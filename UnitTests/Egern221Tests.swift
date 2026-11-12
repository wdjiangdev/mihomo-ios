import XCTest
@testable import Tern

/// feat/egern-2-21: Egern 2.21.0 parity — DNS upstream health, source-IP rules (SRC-IP aliases, IP-SUFFIX,
/// SRC-IP-SUFFIX, SRC-IP-ASN), Egern url_rewrites / header_rewrites / src_ip import, 出站节点 helpers.
final class Egern221Tests: XCTestCase {

    // MARK: - DNS health: query / reply

    func testProbeQueryIsAStandardAQuery() {
        let q = NCDNSHealth.query(id: 0x1234, name: "www.apple.com")
        XCTAssertEqual(Array(q.prefix(12)), [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        let qname: [UInt8] = [3] + Array("www".utf8) + [5] + Array("apple".utf8) + [3] + Array("com".utf8) + [0]
        XCTAssertEqual(Array(q[12..<(12 + qname.count)]), qname)
        XCTAssertEqual(Array(q.suffix(4)), [0x00, 0x01, 0x00, 0x01], "QTYPE A, QCLASS IN")
        let msg = NCDNSMessage.parse(q)
        XCTAssertNotNil(msg, "the shared DNS parser reads the probe")
    }

    private func reply(_ id: UInt16, rcode: UInt8, qr: Bool = true) -> Data {
        var d = NCDNSHealth.query(id: id)
        if qr { d[2] |= 0x80 }
        d[3] = (d[3] & 0xf0) | rcode
        return d
    }

    func testReplyChecks() {
        XCTAssertTrue(NCDNSHealth.check(reply: reply(7, rcode: 0), id: 7).ok, "NOERROR")
        XCTAssertTrue(NCDNSHealth.check(reply: reply(7, rcode: 3), id: 7).ok, "NXDOMAIN still means the server works")
        XCTAssertEqual(NCDNSHealth.check(reply: reply(7, rcode: 2), id: 7).error, "SERVFAIL")
        XCTAssertEqual(NCDNSHealth.check(reply: reply(7, rcode: 5), id: 7).error, "REFUSED")
        XCTAssertEqual(NCDNSHealth.check(reply: reply(7, rcode: 4), id: 7).error, "RCODE 4")
        XCTAssertEqual(NCDNSHealth.check(reply: nil, id: 7).error, "无响应")
        XCTAssertFalse(NCDNSHealth.check(reply: Data([0, 7, 0x81]), id: 7).ok, "too short")
        XCTAssertFalse(NCDNSHealth.check(reply: reply(7, rcode: 0, qr: false), id: 7).ok, "a query echoed back")
        XCTAssertFalse(NCDNSHealth.check(reply: reply(8, rcode: 0), id: 7).ok, "wrong transaction ID")
        XCTAssertTrue(NCDNSHealth.check(reply: reply(0, rcode: 0), id: 7).ok, "DoH replies carry ID 0 (RFC 8484)")
    }

    // MARK: - DNS health: targets / tracker / file

    func testTargetsOrderSkipAndDedupe() {
        let t = NCDNSHealth.targets(nameservers: ["https://223.5.5.5/dns-query", "system", "dhcp://en0", "119.29.29.29"],
                                    fallback: ["tls://dns.google", "119.29.29.29:53"],
                                    bootstrap: ["223.5.5.5"])
        XCTAssertEqual(t.map(\.server), ["https://223.5.5.5/dns-query", "119.29.29.29", "tls://dns.google", "223.5.5.5"])
        XCTAssertEqual(t.map(\.role), ["nameserver", "nameserver", "fallback", "default-nameserver"])
        XCTAssertEqual(t.map { NCDNSHealth.kind(of: $0.upstream) }, ["DoH", "UDP", "DoT", "UDP"])
        let many = NCDNSHealth.targets(nameservers: (1...20).map { "10.0.0.\($0)" }, fallback: [], bootstrap: [])
        XCTAssertEqual(many.count, NCDNSHealth.maxTargets)
    }

    func testTrackerDownAfterTwoFailuresAndRecovers() {
        var tr = NCDNSHealthTracker()
        let targets = NCDNSHealth.targets(nameservers: ["223.5.5.5"], fallback: [], bootstrap: [])
        tr.configure(targets)
        let id = tr.entries[0].id
        XCTAssertNil(tr.record(id: id, ok: false, latencyMs: nil, error: "超时"))
        XCTAssertEqual(tr.entries[0].status, .unknown, "one lost probe is not an outage")
        XCTAssertEqual(tr.record(id: id, ok: false, latencyMs: nil, error: "超时"), .down("223.5.5.5"))
        XCTAssertEqual(tr.entries[0].status, .down)
        XCTAssertNil(tr.record(id: id, ok: false, latencyMs: nil, error: "超时"), "still down: no second transition")
        XCTAssertEqual(tr.entries[0].consecutiveFailures, 3)
        XCTAssertEqual(tr.record(id: id, ok: true, latencyMs: 30, error: nil), .recovered("223.5.5.5"))
        XCTAssertEqual(tr.entries[0].status, .ok)
        XCTAssertEqual(tr.entries[0].latencyMs, 30)
        XCTAssertEqual(tr.entries[0].consecutiveFailures, 0)
        tr.record(id: id, ok: true, latencyMs: NCDNSHealth.slowMs + 1, error: nil)
        XCTAssertEqual(tr.entries[0].status, .slow)
        // A reload with the same DNS keeps the history; a removed server is dropped.
        tr.configure(targets + NCDNSHealth.targets(nameservers: [], fallback: ["1.1.1.1"], bootstrap: []))
        XCTAssertEqual(tr.entries.count, 2)
        XCTAssertEqual(tr.entries[0].status, .slow)
        XCTAssertEqual(tr.entries[1].status, .unknown)
        XCTAssertNil(tr.record(id: "nameserver|nope", ok: false, latencyMs: nil, error: nil))
    }

    func testHealthFileRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("dnshealth-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        var f = NCDNSHealthFile()
        f.updatedAt = Date(timeIntervalSince1970: 1_700_000_000)
        f.entries = [NCDNSHealthEntry(server: "223.5.5.5", role: "nameserver", kind: "UDP", status: .down,
                                      consecutiveFailures: 2, lastError: "超时")]
        f.save(home: dir)
        let back = try XCTUnwrap(NCDNSHealthFile.load(home: dir))
        XCTAssertEqual(back, f)
        XCTAssertEqual(back.downEntries.map(\.server), ["223.5.5.5"])
        XCTAssertNil(NCDNSHealthFile.load(home: dir.appendingPathComponent("missing")))
    }

    func testMonitorNotifiesOnceAndWritesTheFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("dnshealth-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        var notified: [[String]] = []
        let lock = NSLock()
        let monitor = NCDNSHealthMonitor(home: dir, probe: { query, upstream, done in
            // 223.5.5.5 answers NOERROR, 192.0.2.53 never answers anything usable.
            if case .udp(let host, _) = upstream, host == "223.5.5.5" {
                var r = query
                r[2] |= 0x80
                done(r)
            } else {
                done(nil)
            }
        }, notify: { servers in
            lock.lock(); notified.append(servers); lock.unlock()
        })
        monitor.start(NCDNSHealth.targets(nameservers: ["223.5.5.5", "192.0.2.53"], fallback: [], bootstrap: []))
        for _ in 0..<3 { monitor.runRound() }
        let done = expectation(description: "rounds")
        // Rounds complete asynchronously on the monitor queue; poll the snapshot.
        func poll(_ n: Int) {
            monitor.snapshot { entries in
                if entries.last?.consecutiveFailures ?? 0 >= 3 || n > 50 { done.fulfill() } else {
                    DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { poll(n + 1) }
                }
            }
        }
        poll(0)
        wait(for: [done], timeout: 10)
        let snap = expectation(description: "snapshot")
        var entries: [NCDNSHealthEntry] = []
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) {
            monitor.snapshot { entries = $0; snap.fulfill() }
        }
        wait(for: [snap], timeout: 5)
        monitor.stop()
        XCTAssertEqual(entries.map(\.status), [.ok, .down])
        XCTAssertEqual(entries.last?.lastError, "无响应")
        lock.lock(); let n = notified; lock.unlock()
        XCTAssertEqual(n, [["192.0.2.53"]], "one notification on the transition, not every round")
        let file = try XCTUnwrap(NCDNSHealthFile.load(home: dir))
        XCTAssertEqual(file.entries.count, 2)
        XCTAssertEqual(file.downEntries.map(\.server), ["192.0.2.53"])
    }

    // MARK: - Source-IP rules

    func testSourceIPAliasesParse() {
        for spelling in ["SRC-IP", "src-ip", "SRC-IP-CIDR6", "SRC-IP6-CIDR", "SRC-IP6"] {
            let r = NCRule.parse("\(spelling),192.168.1.0/24,DIRECT")
            XCTAssertEqual(r?.kind, "SRC-IP-CIDR", spelling)
            XCTAssertEqual(r?.payload, "192.168.1.0/24", spelling)
        }
        let logic = NCRule.parse("AND,((SRC-IP,192.168.1.10),(DST-PORT,443)),Proxy")
        XCTAssertEqual(logic?.subRules.first?.kind, "SRC-IP-CIDR")
    }

    func testMatcherReadsTheSourceIP() {
        var ctx = NCMatchContext()
        ctx.ip = NCIP("8.8.8.8")
        ctx.srcIP = NCLanShare.sourceIP("::ffff:192.168.1.10")
        XCTAssertEqual(ctx.srcIP, NCIP("192.168.1.10"), "v4-mapped LAN client address")
        let cidr = NCRule.parse("SRC-IP,192.168.1.0/24,DIRECT")!
        XCTAssertTrue(NCRuleMatcher.matches(cidr, ctx))
        let bare = NCRule.parse("SRC-IP,192.168.1.10,DIRECT")!
        XCTAssertTrue(NCRuleMatcher.matches(bare, ctx), "a bare address is a /32")
        XCTAssertFalse(NCRuleMatcher.matches(NCRule.parse("SRC-IP,192.168.2.0/24,DIRECT")!, ctx))
        XCTAssertFalse(NCRuleMatcher.matches(NCRule.parse("IP-CIDR,192.168.1.0/24,DIRECT")!, ctx), "destination is 8.8.8.8")
        var own = NCMatchContext()
        own.ip = NCIP("8.8.8.8")
        XCTAssertFalse(NCRuleMatcher.matches(cidr, own), "no source IP (this device's own traffic) never matches")
    }

    func testIPSuffix() {
        let ip = NCIP("10.1.2.8")!
        XCTAssertTrue(NCRuleMatcher.ipSuffixMatches("0.0.0.8/8", ip))
        XCTAssertTrue(NCRuleMatcher.ipSuffixMatches("9.9.2.8/16", ip))
        XCTAssertFalse(NCRuleMatcher.ipSuffixMatches("0.0.0.9/8", ip))
        XCTAssertTrue(NCRuleMatcher.ipSuffixMatches("0.0.0.0/0", ip), "zero bits match everything")
        XCTAssertTrue(NCRuleMatcher.ipSuffixMatches("0.0.0.0/3", ip), "partial byte: low 3 bits of 8 are 000")
        XCTAssertFalse(NCRuleMatcher.ipSuffixMatches("0.0.0.4/3", ip), "low 3 bits of 4 are 100")
        XCTAssertTrue(NCRuleMatcher.ipSuffixMatches("0.0.0.24/4", ip), "24 = 0001 1000: low 4 bits 1000 like 8")
        XCTAssertFalse(NCRuleMatcher.ipSuffixMatches("::8/8", ip), "family must match")
        XCTAssertFalse(NCRuleMatcher.ipSuffixMatches("0.0.0.8", ip), "bits required")
        XCTAssertFalse(NCRuleMatcher.ipSuffixMatches("0.0.0.8/33", ip))
        XCTAssertTrue(NCRuleMatcher.ipSuffixMatches("::1:8/16", NCIP("2001:db8::8")!))

        var ctx = NCMatchContext()
        ctx.ip = ip
        ctx.srcIP = NCIP("192.168.1.23")
        XCTAssertTrue(NCRuleMatcher.matches(NCRule.parse("IP-SUFFIX,0.0.0.8/8,DIRECT")!, ctx))
        XCTAssertTrue(NCRuleMatcher.matches(NCRule.parse("SRC-IP-SUFFIX,0.0.0.23/8,DIRECT")!, ctx))
        XCTAssertFalse(NCRuleMatcher.matches(NCRule.parse("SRC-IP-SUFFIX,0.0.0.8/8,DIRECT")!, ctx))
        XCTAssertTrue(NCRuleMatcher.ipKinds.contains("IP-SUFFIX"), "IP-SUFFIX reads the destination IP (resolves)")
        XCTAssertTrue(NCRuleMatcher.knownKinds.isSuperset(of: ["IP-SUFFIX", "SRC-IP-SUFFIX", "SRC-IP-ASN"]))
    }

    func testSourceASN() {
        var ctx = NCMatchContext()
        ctx.srcIP = NCIP("192.168.1.23")
        ctx.asnOf = { $0 == NCIP("192.168.1.23") ? 4134 : nil }
        XCTAssertTrue(NCRuleMatcher.matches(NCRule.parse("SRC-IP-ASN,4134,DIRECT")!, ctx))
        XCTAssertTrue(NCRuleMatcher.matches(NCRule.parse("SRC-IP-ASN,AS4134,DIRECT")!, ctx))
        XCTAssertFalse(NCRuleMatcher.matches(NCRule.parse("SRC-IP-ASN,13335,DIRECT")!, ctx))
        XCTAssertEqual(NCRuleMatcher.asnNumber(" as13335 "), 13335)
        XCTAssertNil(NCRuleMatcher.asnNumber("ASX"))
    }

    func testValidatorMapsSourceIPSpellings() throws {
        let a = try XCTUnwrap(NCRuleValidator.convertRuleLine("SRC-IP,192.168.1.10,DIRECT"))
        XCTAssertEqual(a.type, "SRC-IP-CIDR")
        XCTAssertFalse(a.note.isEmpty, "explains it only applies to LAN-sharing clients")
        XCTAssertEqual(try XCTUnwrap(NCRuleValidator.convertRuleLine("SRC-IP-CIDR6,fd00::/8,DIRECT")).type, "SRC-IP-CIDR")
        XCTAssertEqual(try XCTUnwrap(NCRuleValidator.convertRuleLine("SRC-IP-SUFFIX,0.0.0.8/8,DIRECT")).type, "SRC-IP-SUFFIX")
        XCTAssertEqual(try XCTUnwrap(NCRuleValidator.convertRuleLine("IP-SUFFIX,0.0.0.8/8,DIRECT")).type, "IP-SUFFIX")
    }

    func testRuleSetIndexKeepsSourceIPLines() {
        XCTAssertTrue(NCRuleSetIndex.matchableKinds.isSuperset(of: ["IP-SUFFIX", "SRC-IP-SUFFIX", "SRC-IP-ASN", "SRC-IP-CIDR"]))
    }

    func testRuleEditorOffersSourceIP() {
        XCTAssertNotNil(RuleKind.all.first { $0.id == "SRC-IP-CIDR" })
        XCTAssertEqual(RuleKind.aliases["SRC-IP"], "SRC-IP-CIDR")
    }

    // MARK: - Egern import

    private func ruleset(_ text: String) -> NCEngineRuleset {
        let rs = NCEngineRuleset()
        rs.parseText(text, source: "模块", args: [:])
        return rs
    }

    func testEgernURLRewrites() {
        let rs = ruleset("""
        name: rw
        url_rewrites:
          - match: ^https://ad\\.example\\.com/
            location: http://reject-dict/
          - match: ^http://old\\.example\\.com/(.*)
            location: https://new.example.com/$1
            status_code: 301
          - match: ^http://t\\.example\\.com/
            location: https://t2.example.com/
            status_code: 307
          - match: ^https://h\\.example\\.com/
            location: https://h2.example.com/
          - match: ^https://off\\.example\\.com/
            location: http://reject/
            disabled: true
          - match: ^https://bad\\.example\\.com/
            location: https://x.example.com/
            status_code: 404
        mitm:
          hostnames:
            includes:
            - ad.example.com
        """)
        let urls = rs.rules.filter { $0.kind == "url" }
        XCTAssertEqual(urls.map(\.action), ["reject-dict", "302", "307", "header"])
        XCTAssertEqual(urls[1].target, "https://new.example.com/$1")
        XCTAssertEqual(urls[3].target, "https://h2.example.com/")
        XCTAssertFalse(urls.contains { $0.pattern.contains("off") }, "disabled item skipped")
        XCTAssertFalse(rs.unsupported.contains { $0.hasPrefix("egern url_rewrites") }, "\(rs.unsupported)")
        XCTAssertTrue(rs.errors.contains { $0.contains("404") }, "unsupported status code reported: \(rs.errors)")
    }

    func testEgernHeaderRewrites() {
        let rs = ruleset("""
        name: hdr
        header_rewrites:
          - add:
              match: ^https://a\\.example\\.com/
              name: X-Test
              value: "1"
          - replace:
              match: ^https://a\\.example\\.com/
              name: User-Agent
              value: Tern
              type: request
          - delete:
              match: ^https://a\\.example\\.com/
              name: Set-Cookie
              type: response
          - rename:
              match: ^https://a\\.example\\.com/
              name: X
        mitm:
          hostnames:
            includes:
            - a.example.com
        """)
        let h = rs.rules.filter { $0.kind == "header" }
        XCTAssertEqual(h.count, 3)
        XCTAssertEqual(h[0].phase, "request")
        XCTAssertEqual(h[0].headers.map(\.op), ["del", "add"])
        XCTAssertEqual(h[0].headers.last?.value, "1")
        XCTAssertEqual(h[1].headers.last?.name, "User-Agent")
        XCTAssertEqual(h[2].phase, "response")
        XCTAssertEqual(h[2].headers.map(\.op), ["del"])
        XCTAssertTrue(rs.unsupported.contains { $0.hasPrefix("egern header_rewrites") }, "unknown verb listed")
    }

    func testEgernMapLocalsStillListed() {
        let rs = ruleset("""
        name: ml
        map_locals:
          - match: ^https://m\\.example\\.com/
            body: "{}"
        """)
        XCTAssertTrue(rs.unsupported.contains { $0.hasPrefix("egern map_locals") })
    }

    func testEgernSrcIPRule() {
        XCTAssertEqual(NCEngineRuleset.egernCondTypes["src_ip"], "SRC-IP-CIDR")
        let (cond, err) = NCEngineRuleset.egernCond(.object(["src_ip": .object(["match": .string("192.168.1.0/24"),
                                                                                 "policy": .string("DIRECT")])]))
        XCTAssertNil(err)
        XCTAssertEqual(cond, "SRC-IP-CIDR,192.168.1.0/24")
    }

    // MARK: - 出站节点

    func testOutboundNodeName() {
        XCTAssertEqual(OutboundNode.nodeName(["🇯🇵 Tokyo 01", "Proxy"])?.name, "🇯🇵 Tokyo 01")
        let chain = OutboundNode.nodeName(["Relay A -> Exit B"])
        XCTAssertEqual(chain?.name, "Exit B")
        XCTAssertEqual(chain?.hops, ["Relay A", "Exit B"])
        XCTAssertNil(OutboundNode.nodeName(["DIRECT"]))
        XCTAssertNil(OutboundNode.nodeName(["REJECT"]))
        XCTAssertNil(OutboundNode.nodeName([RuleDisplay.engineOutbound]))
        XCTAssertNil(OutboundNode.nodeName([]))
        XCTAssertNil(OutboundNode.nodeName(nil))
    }

    func testOutboundLookupWithoutDatabases() {
        let empty = FileManager.default.temporaryDirectory.appendingPathComponent("outbound-\(UUID().uuidString)")
        let ip = OutboundNode.lookup(OutboundNodeInfo(name: "🇭🇰 Hong Kong 01", server: "192.0.2.3", port: 443), home: empty)
        XCTAssertEqual(ip.serverIP, "192.0.2.3")
        XCTAssertTrue(ip.noGeoDB)
        XCTAssertNil(ip.countryCode)
        XCTAssertEqual(ip.inferredCode, "HK", "region from the name, shown as inferred")
        XCTAssertEqual(ip.serverText, "192.0.2.3:443")
        let dom = OutboundNode.lookup(OutboundNodeInfo(name: "US 02", server: "us2.example.com", port: 8443), home: empty)
        XCTAssertTrue(dom.serverIsDomain)
        XCTAssertNil(dom.serverIP)
        XCTAssertEqual(dom.inferredCode, "US")
        XCTAssertEqual(OutboundNodeInfo(name: "v6", server: "2001:db8::1", port: 443).serverText, "[2001:db8::1]:443")
        XCTAssertEqual(OutboundNodeInfo(name: "a", asn: 2516, asOrg: "KDDI").asnText, "AS2516 · KDDI")
    }
}
