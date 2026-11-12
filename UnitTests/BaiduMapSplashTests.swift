import XCTest
@testable import Tern

/// fix/baidumap-splash: Baidu Maps showed its splash ad on every cold start under Tern while Quantumult X on the
/// same profile blocked it. These tests pin the QX-equivalent pieces end to end, without a device:
/// - the HTTPDNS guard's fixed seed IPs (the SDK dials 180.76.76.x directly, never by name) and that a tunnel
///   stop keeps the persisted table while an explicit off deletes it;
/// - the built-in QX snippet (rewrite + MitM hosts) through the real module parser → rewrite snapshot → native
///   rewrite engine: the no-SNI bare-IP flow is MitM'd by its IP literal (163.177.17.* glob), its URL is built
///   from the Host header, and the splash-config call gets reject-dict;
/// - when the HTTPS layer may join (switch + 重写 + MitM + trusted CA), the DNS-layer rules, the 已拦截 label;
/// - the QX importer keeps a user's own Baidu Maps rewrite with IP / wildcard hostnames.
final class BaiduMapSplashTests: XCTestCase {

    private func ip(_ s: String) -> NCIP { NCIP(s)! }

    private func tempDir() throws -> String {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("bdmap-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: d) }
        return d.path
    }

    // MARK: HTTPDNS guard — fixed seeds (bug A)

    func testSeedIPsHitWithoutAnyResolvedAnswer() {
        let g = NCHTTPDNSGuard()
        g.setEnabled(true)
        // Nothing resolved yet (cold start, upstream down): the hard-coded SDK endpoints are refused anyway.
        XCTAssertEqual(g.ipCount, 0)
        XCTAssertEqual(g.domain(for: ip("180.76.76.112")), "httpdns.baidu.com")
        XCTAssertEqual(g.domain(for: ip("180.76.76.200")), "httpdns.baidubce.com")
        XCTAssertEqual(g.domain(for: ip("180.76.76.220")), "httpdns.baidubce.com")
        // Neighbours (and Baidu's public DNS 180.76.76.76) are not service endpoints.
        XCTAssertNil(g.domain(for: ip("180.76.76.76")))
        XCTAssertNil(g.domain(for: ip("180.76.76.113")))
        // Content servers stay reachable — they are MitM targets, never guard targets.
        XCTAssertNil(g.domain(for: ip("163.177.17.21")))
    }

    func testSeedsFollowTheSwitchAndSurviveRefreshes() {
        let g = NCHTTPDNSGuard()
        XCTAssertNil(g.domain(for: ip("180.76.76.200")), "a guard never enabled passes everything")
        g.setEnabled(true)
        // A completed answer for the seed's own domain replaces the RESOLVED subset only.
        g.refresh(resolver: { d, done in done(d == "httpdns.baidubce.com" ? [NCIP("106.12.0.1")!] : nil) })
        XCTAssertEqual(g.domain(for: ip("106.12.0.1")), "httpdns.baidubce.com")
        XCTAssertEqual(g.domain(for: ip("180.76.76.200")), "httpdns.baidubce.com")
        g.refresh(resolver: { d, done in done(d == "httpdns.baidubce.com" ? [] : nil) })
        XCTAssertNil(g.domain(for: ip("106.12.0.1")))
        XCTAssertEqual(g.domain(for: ip("180.76.76.200")), "httpdns.baidubce.com")
        g.setEnabled(false)
        XCTAssertNil(g.domain(for: ip("180.76.76.200")), "switched off: the seeds stop too")
    }

    func testSeedListIsTheDocumentedEndpoints() {
        XCTAssertEqual(Set(NCHTTPDNSGuard.seedIPs.keys), ["180.76.76.112", "180.76.76.200", "180.76.76.220"])
        for (text, domain) in NCHTTPDNSGuard.seedIPs {
            XCTAssertNotNil(NCIP(text), text)
            XCTAssertTrue(NCHTTPDNSGuard.watchDomains.contains(domain), domain)
        }
    }

    // MARK: HTTPDNS guard — persistence across a tunnel stop (bug B)

    func testStopKeepsTheStoreFileExplicitDisableDeletesIt() throws {
        let file = URL(fileURLWithPath: try tempDir()).appendingPathComponent("nativecore-httpdns-guard.json")
        let a = NCHTTPDNSGuard()
        a.setStoreFile(file)
        a.setEnabled(true)
        a.refresh(resolver: { d, done in done(d == "httpdns.baidu.com" ? [NCIP("110.242.69.16")!] : nil) })
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))

        // Tunnel stop / eviction: disarmed in memory, file kept.
        a.stop()
        XCTAssertFalse(a.isEnabled)
        XCTAssertNil(a.domain(for: ip("110.242.69.16")))
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path), "stop() must keep the persisted table")

        // The next start is armed from the first flow.
        let b = NCHTTPDNSGuard()
        b.setStoreFile(file)
        b.setEnabled(true)
        b.loadPersisted()
        XCTAssertEqual(b.domain(for: ip("110.242.69.16")), "httpdns.baidu.com")

        // The user's explicit off (engine load with the switch off) deletes it.
        b.setEnabled(false)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    // MARK: built-in snippet through the real parser

    func testBuiltinSnippetParsesLikeAQXModule() {
        let sub = NCBaiduMapSplash.parsedModule()
        XCTAssertTrue(sub.errors.isEmpty, "\(sub.errors)")
        XCTAssertEqual(sub.hostnames, NCBaiduMapSplash.mitmHostnames)
        let urls = sub.rules.filter { $0.kind == "url" }
        XCTAssertEqual(urls.count, NCBaiduMapSplash.rewrites.count, "\(sub.rules.map { $0.line })")
        XCTAssertEqual(urls.map { $0.action }, NCBaiduMapSplash.rewrites.map { $0.action })
        XCTAssertEqual(urls.first?.pattern, NCBaiduMapSplash.rewrites.first?.pattern)
        XCTAssertTrue(urls.allSatisfy { $0.source == NCBaiduMapSplash.sourceName })
    }

    func testMergeAppendsAfterTheUsersRulesAndDedupesHosts() {
        let rs = NCEngineRuleset()
        rs.parseText("[rewrite_local]\n^https?:\\/\\/example\\.com\\/ad url reject\n[mitm]\nhostname = example.com, newclient.map.baidu.com\n",
                     source: "mine", args: [:])
        NCBaiduMapSplash.merge(into: rs)
        XCTAssertEqual(rs.rules.first?.source, "mine", "user rules stay first (URL rewrites are first-match)")
        XCTAssertEqual(rs.rules.count, 1 + NCBaiduMapSplash.rewrites.count)
        XCTAssertEqual(rs.hostnames.filter { $0 == "newclient.map.baidu.com" }.count, 1)
        XCTAssertTrue(rs.hostnames.contains("163.177.17.*"))
    }

    /// The built-in rule set as the tunnel loads it: app snapshot builder → JSON → RWSnapshot → engine.
    private func builtinEngine() throws -> NativeRewriteEngine {
        var cfg = NCEngineConfig()
        cfg.enabled = true
        cfg.mitm = true
        let rs = NCEngineRuleset()
        NCBaiduMapSplash.merge(into: rs)
        let (data, hosts) = try NCRewriteSnapshotBuilder.exportData(home: try tempDir(), cfg: cfg, rs: rs)
        XCTAssertEqual(hosts, NCBaiduMapSplash.mitmHostnames.count)
        let snap = try XCTUnwrap(RWSnapshot.decode(String(decoding: data, as: UTF8.self)))
        return NativeRewriteEngine(snapshot: snap)
    }

    private func u16(_ v: Int) -> Data { Data([UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }

    /// Minimal TLS ClientHello record, optionally without SNI (the Baidu SDK's bare-IP dial).
    private func clientHello(sni: String?) -> Data {
        var ext = Data()
        if let sni {
            let n = Data(sni.utf8)
            var list = Data([0x00]) + u16(n.count) + n
            list = u16(list.count) + list
            ext += u16(0x0000) + u16(list.count) + list
        }
        let a = Data("http/1.1".utf8)
        var alpn = Data([UInt8(a.count)]) + a
        alpn = u16(alpn.count) + alpn
        ext += u16(0x0010) + u16(alpn.count) + alpn
        var hs = Data([0x03, 0x03]) + Data(repeating: 7, count: 32)
        hs += Data([0x00])
        hs += u16(2) + Data([0x13, 0x01])
        hs += Data([0x01, 0x00])
        hs += u16(ext.count) + ext
        let msg = Data([0x01, UInt8((hs.count >> 16) & 0xff), UInt8((hs.count >> 8) & 0xff), UInt8(hs.count & 0xff)]) + hs
        return Data([0x16, 0x03, 0x01]) + u16(msg.count) + msg
    }

    func testMitmGatePicksTheIPLiteralHostForANoSNIFlow() throws {
        let engine = try builtinEngine()
        let isMitm: (String, Int) -> Bool = { engine.intercepts(host: $0, port: $1) }
        XCTAssertTrue(isMitm("163.177.17.21", 443), "163.177.17.* glob covers the bare-IP content servers")
        XCTAssertTrue(isMitm("newclient.map.baidu.com", 443))
        XCTAssertFalse(isMitm("163.177.18.21", 443))
        XCTAssertEqual(NCMitmGate.decide(firstBytes: clientHello(sni: nil), knownDomain: nil, dstIP: "163.177.17.21",
                                         port: 443, isMitm: isMitm),
                       .mitm(host: "163.177.17.21", alpn: ["http/1.1"]))
        XCTAssertEqual(NCMitmGate.decide(firstBytes: clientHello(sni: "newclient.map.baidu.com"), knownDomain: nil,
                                         dstIP: "163.177.17.21", port: 443, isMitm: isMitm),
                       .mitm(host: "newclient.map.baidu.com", alpn: ["http/1.1"]))
    }

    private func request(_ target: String, host: String = "newclient.map.baidu.com", connHost: String = "163.177.17.21") -> RewriteRequest {
        RewriteRequest(method: "GET", target: target, host: host, headers: [["Host", host], ["User-Agent", "BaiduMap/20.0"]],
                       length: 0, connHost: connHost, connPort: 443, tls: true)
    }

    func testNoSNIIPFlowRewriteUsesTheHostHeaderAndRejectsTheSplashConfig() throws {
        let engine = try builtinEngine()
        let d = engine.decide(request("/client/phpui2/?qt=ads&sv=20.0.0&os=iphone"))
        guard case .local(let l) = d else { return XCTFail("expected a local reject-dict answer, got \(d)") }
        XCTAssertEqual(l.status, 200)
        XCTAssertEqual(l.log.url, "https://newclient.map.baidu.com/client/phpui2/?qt=ads&sv=20.0.0&os=iphone",
                       "the URL is built from the Host header, not the dialled IP")
        XCTAssertEqual(l.length, 2)
        XCTAssertTrue(l.headers.contains { $0.count == 2 && $0[0] == "Content-Type" && $0[1] == "application/json" }, "\(l.headers)")
        // qt not first in the query works too
        guard case .local = engine.decide(request("/client/phpui2/?sv=20.0.0&qt=ads")) else { return XCTFail("qt=ads later in query") }
    }

    func testOtherRejectsAndUnrelatedCallsPass() throws {
        let engine = try builtinEngine()
        for t in ["/client/crossmarketing/getinfo?x=1", "/client/usersystem/home/dynamic?a=b",
                  "/client/noticebar/get?x=1", "/client/phpui2/?qt=bar", "/client/phpui/?qt=hw&x=1"] {
            guard case .local = engine.decide(request(t)) else { return XCTFail("\(t) not rejected") }
        }
        // The map's real API calls (search, route, tiles) are forwarded untouched.
        for t in ["/client/phpui2/?qt=s&wd=coffee", "/client/phpui2/?qt=adsx", "/client/phpui2/?qt=nav"] {
            if case .local = engine.decide(request(t)) { XCTFail("\(t) must not be rejected") }
        }
        // Another host on the same IP list is untouched.
        if case .local = engine.decide(request("/client/phpui2/?qt=ads", host: "map.baidu.com")) {
            XCTFail("only newclient.map.baidu.com is rewritten")
        }
    }

    func testBlockedRecordRuleTextIsReadable() {
        XCTAssertEqual(NCBaiduMapSplash.blockRule(url: "https://newclient.map.baidu.com/client/phpui2/?qt=ads&sv=1"),
                       "URL-REWRITE,newclient.map.baidu.com/client/phpui2/?qt=ads,REJECT-DICT")
        XCTAssertEqual(NCBaiduMapSplash.blockRule(url: "https://newclient.map.baidu.com/client/crossmarketing/x"),
                       "URL-REWRITE,newclient.map.baidu.com/client/crossmarketing,REJECT")
        XCTAssertNil(NCBaiduMapSplash.blockRule(url: "https://newclient.map.baidu.com/client/phpui2/?qt=s"))
        XCTAssertNil(NCBaiduMapSplash.blockRule(url: "https://www.youtube.com/ads"))
        XCTAssertEqual(NCHTTPDNSGuard.ruleText(for: "httpdns.baidu.com"), "HTTPDNS-GUARD,httpdns.baidu.com,REJECT")
    }

    // MARK: prep decisions

    func testHTTPSLayerNeedsSwitchRewriteMitmAndTrustedCA() {
        var cfg = NCEngineConfig()
        cfg.enabled = true
        cfg.mitm = true
        XCTAssertTrue(NCBaiduMapSplash.httpsLayerEligible(guardOn: true, safeMode: false, cfg: cfg, caTrusted: true))
        XCTAssertFalse(NCBaiduMapSplash.httpsLayerEligible(guardOn: true, safeMode: false, cfg: cfg, caTrusted: false),
                       "no trusted CA: DNS / IP layer only")
        XCTAssertFalse(NCBaiduMapSplash.httpsLayerEligible(guardOn: false, safeMode: false, cfg: cfg, caTrusted: true))
        XCTAssertFalse(NCBaiduMapSplash.httpsLayerEligible(guardOn: true, safeMode: true, cfg: cfg, caTrusted: true))
        XCTAssertFalse(NCBaiduMapSplash.httpsLayerEligible(guardOn: true, safeMode: false, cfg: nil, caTrusted: true))
        var noMitm = cfg
        noMitm.mitm = false
        XCTAssertFalse(NCBaiduMapSplash.httpsLayerEligible(guardOn: true, safeMode: false, cfg: noMitm, caTrusted: true))
        var noRewrite = cfg
        noRewrite.enabled = false
        noRewrite.scriptsEnabled = false
        XCTAssertFalse(NCBaiduMapSplash.httpsLayerEligible(guardOn: true, safeMode: false, cfg: noRewrite, caTrusted: true))
    }

    func testCoreRulesArePrependedOnceAndRejectAtTheDNSLayer() {
        var raw: [String: NCJSONValue] = ["rules": .array([.string("DOMAIN-SUFFIX,baidu.com,DIRECT"), .string("MATCH,Proxy")])]
        NCBaiduMapSplash.prependCoreRules(&raw)
        NCBaiduMapSplash.prependCoreRules(&raw)
        let rules = raw.list("rules").compactMap { v -> String? in if case .string(let s) = v { return s }; return nil }
        XCTAssertEqual(Array(rules.prefix(NCBaiduMapSplash.coreRules.count)), NCBaiduMapSplash.coreRules)
        XCTAssertEqual(rules.count, NCBaiduMapSplash.coreRules.count + 2, "idempotent")
        XCTAssertTrue(rules.contains("DOMAIN,afd.baidu.com,REJECT"))
        XCTAssertTrue(rules.contains("DOMAIN,afdconf.baidu.com,REJECT"))
        XCTAssertTrue(rules.contains("DOMAIN,lc.map.baidu.com,REJECT"))
        // The DNS layer decides these names as REJECT even with the broad DIRECT rule behind them.
        let parsed = rules.compactMap { NCRule.parse($0) }
        XCTAssertEqual(parsed.count, rules.count)
        var ctx = NCMatchContext()
        ctx.domain = "afd.baidu.com"
        XCTAssertEqual(NCRuleMatcher.dnsRejectRule(parsed, ctx)?.raw, "DOMAIN,afd.baidu.com,REJECT")
        ctx.domain = "newclient.map.baidu.com"
        XCTAssertNil(NCRuleMatcher.dnsRejectRule(parsed, ctx), "the API host itself is never DNS-rejected")
    }

    func testSettingsSearchFindsTheSwitchByBaiduMaps() {
        XCTAssertEqual(SettingsSearchIndex.search("百度地图").first?.entry.id, "httpdnsGuard")
        XCTAssertEqual(SettingsSearchIndex.search("开屏").first?.entry.id, "httpdnsGuard")
        XCTAssertEqual(SettingsSearchIndex.search("DNS").first?.entry.id, "dns", "the DNS page still wins its own title")
    }

    // MARK: QX importer keeps a user's own Baidu Maps rewrite (item 5)

    func testQXImportKeepsBaiduMapRewriteWithIPHostnames() {
        let text = """
        [server_local]
        shadowsocks=192.0.2.1:8388, method=aes-128-gcm, password=pw, tag=N1

        [policy]
        static=Main, N1, direct

        [filter_local]
        final, Main

        [rewrite_remote]
        https://raw.githubusercontent.com/RuCu6/QuanX/main/Rewrites/Cube/bdmap.snippet, tag=百度地图, update-interval=172800, opt-parser=false, enabled=true

        [rewrite_local]
        ^https:\\/\\/newclient\\.map\\.baidu\\.com\\/client\\/phpui2.*qt=ads url reject-dict
        ^https:\\/\\/newclient\\.map\\.baidu\\.com\\/client\\/noticebar\\/get? url reject-dict

        [mitm]
        hostname = newclient.map.baidu.com, ugc.map.baidu.com, 163.177.17.*, 180.76.76.112, 180.76.76.200
        """
        let res = NCConfImportPort.importConfResult(text)
        XCTAssertTrue(res.error?.isEmpty ?? true, res.error ?? "")
        XCTAssertTrue(res.rewriteRemotes?.contains { $0.url.hasSuffix("/bdmap.snippet") && $0.enabled } ?? false,
                      "\(String(describing: res.rewriteRemotes))")
        let module = res.module ?? ""
        XCTAssertTrue(module.contains("qt=ads url reject-dict"), module)
        XCTAssertTrue(module.contains("163.177.17.*"), module)
        XCTAssertTrue(module.contains("180.76.76.112"), module)

        let rs = NCEngineRuleset()
        rs.parseText(module, source: "导入", args: [:])
        XCTAssertTrue(rs.hostnames.contains("163.177.17.*"), "\(rs.hostnames)")
        XCTAssertTrue(rs.hostnames.contains("180.76.76.112"), "\(rs.hostnames)")
        XCTAssertTrue(rs.rules.contains { $0.kind == "url" && $0.action == "reject-dict" && $0.pattern.contains("qt=ads") })
        // The tunnel matches an IPv4 glob host entry against a bare destination IP.
        XCTAssertTrue(NativeRewriteEngine.glob("163.177.17.*", "163.177.17.21"))
    }
}
