import XCTest
@testable import Tern

/// fix/qx-dns-records: the Quantumult X DNS behaviours (NCDNSQX.swift) and the session-record persistence
/// (NCSessionArchive resume / rotation, NCStatsSnapshot). Sources are listed in docs/qx-dns-records-audit.md.
final class NCDNSQXTests: XCTestCase {

    private var dir: URL!

    override func setUp() {
        super.setUp()
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("qxdns-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDown() {
        NCSystemDNS.lookupOverride = nil
        NCSystemDNS.fakeRanges = [NCCIDR("198.18.0.0/15")!]
        try? FileManager.default.removeItem(at: dir)
        super.tearDown()
    }

    // MARK: helpers

    private func query(_ name: String = "example.com", type: UInt16 = NCDNSMessage.typeA, id: UInt16 = 0x1234) -> Data {
        var q = NCDNSMessage()
        q.id = id
        q.recursionDesired = true
        q.questions = [NCDNSQuestion(name: name, type: type, klass: NCDNSMessage.classIN)]
        return q.serialized()
    }

    /// A NOERROR reply to `name` carrying `ips` (A or AAAA by address family), TTL 300.
    private func answer(_ ips: [String], name: String = "example.com", type: UInt16 = NCDNSMessage.typeA) -> Data {
        var r = NCDNSMessage()
        r.id = 0x1234
        r.isResponse = true
        r.recursionAvailable = true
        r.questions = [NCDNSQuestion(name: name, type: type, klass: NCDNSMessage.classIN)]
        r.answers = ips.compactMap { NCIP($0) }.map {
            NCDNSRecord(name: name, type: $0.isV4 ? NCDNSMessage.typeA : NCDNSMessage.typeAAAA,
                        klass: NCDNSMessage.classIN, ttl: 300, rdata: Data($0.bytes))
        }
        return r.serialized()
    }

    private func ips(_ wire: Data?) -> [String] {
        (wire.flatMap { NCDNSMessage.parse($0) }?.addressAnswers ?? []).map { $0.0.string }
    }

    private let servers: [NCDNSUpstream] = [.udp(host: "192.0.2.1", port: 53), .udp(host: "192.0.2.2", port: 53),
                                            .udp(host: "192.0.2.3", port: 53)]

    /// Fake upstreams: per index (delay, reply); a missing entry never answers. Records launch times.
    private final class Fake {
        let lock = NSLock()
        let t0 = Date()
        var launched: [Int: TimeInterval] = [:]
        let servers: [NCDNSUpstream]
        let plan: [Int: (TimeInterval, Data?)]
        init(_ servers: [NCDNSUpstream], _ plan: [Int: (TimeInterval, Data?)]) { self.servers = servers; self.plan = plan }
        func exchange(_ u: NCDNSUpstream, _ done: @escaping (Data?) -> Void) {
            let i = servers.firstIndex(of: u)!
            lock.lock(); launched[i] = Date().timeIntervalSince(t0); lock.unlock()
            guard let p = plan[i] else { return }
            DispatchQueue.global().asyncAfter(deadline: .now() + p.0) { done(p.1) }
        }
        var launches: [Int: TimeInterval] { lock.lock(); defer { lock.unlock() }; return launched }
    }

    private func qxRace(_ fake: Fake, accept: ((Data) -> NCDNSCircumvent.Verdict)? = nil,
                        trace: NCDNSAttemptTrace? = nil) -> (Data?, Int?, TimeInterval) {
        let q = DispatchQueue(label: "qx.race.test")
        let exp = expectation(description: "race")
        var out: (Data?, Int?) = (nil, nil)
        var fired = 0
        let t0 = Date()
        NCDNSRace.run(list: servers, start: 0, queue: q, trace: trace, stagger: 0, attemptTimeout: 1.0,
                      overallTimeout: 2.0, maxParallel: min(servers.count, NCDNSRace.qxParallelCap), accept: accept,
                      exchange: { u, done in fake.exchange(u, done) },
                      completion: { r, w in out = (r, w); fired += 1; exp.fulfill() })
        wait(for: [exp], timeout: 4)
        let dt = Date().timeIntervalSince(t0)
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(fired, 1, "completion fires exactly once")
        return (out.0, out.1, dt)
    }

    // MARK: all-at-once race (QX: every server asked concurrently, first answer wins)

    func testQXRaceAsksEveryServerAtOnceAndFastestWins() {
        let fake = Fake(servers, [0: (0.40, answer(["1.1.1.1"])), 1: (0.05, answer(["2.2.2.2"])), 2: (0.20, answer(["3.3.3.3"]))])
        let (r, w, dt) = qxRace(fake)
        XCTAssertEqual(ips(r), ["2.2.2.2"])
        XCTAssertEqual(w, 1)
        XCTAssertLessThan(dt, 0.39, "did not wait for the slow first server")
        let l = fake.launches
        XCTAssertEqual(l.count, 3, "every server launched")
        XCTAssertTrue(l.values.allSatisfy { $0 < 0.2 }, "all launched at once, no 300 ms stagger: \(l)")
    }

    func testQXRaceSkipsSilentServer() {
        let fake = Fake(servers, [2: (0.05, answer(["3.3.3.3"]))])
        let (r, w, _) = qxRace(fake)
        XCTAssertEqual(ips(r), ["3.3.3.3"])
        XCTAssertEqual(w, 2)
    }

    // MARK: circumvent-ipv4-answer / circumvent-ipv6-answer

    func testCircumventJudgePassFilteredAll() {
        let c = NCDNSCircumvent(v4: ["127.0.0.1", "0.0.0.0", "10.10.*"], v6: ["::"])
        XCTAssertEqual(c.judge(answer(["8.8.8.8"])), .pass)
        guard case .filtered(let kept) = c.judge(answer(["127.0.0.1", "8.8.4.4", "10.10.3.4"])) else {
            return XCTFail("partly listed answer should be filtered")
        }
        XCTAssertEqual(ips(kept), ["8.8.4.4"])
        XCTAssertEqual(c.judge(answer(["0.0.0.0", "10.10.1.1"])), .circumvented)
        XCTAssertEqual(c.judge(answer(["0:0::0"], type: NCDNSMessage.typeAAAA)), .circumvented, "parsed-address compare")
        XCTAssertEqual(NCDNSCircumvent().judge(answer(["127.0.0.1"])), .pass, "no lists = pass")
    }

    func testCircumventPatternsParseStringAndArray() {
        XCTAssertEqual(NCDNSCircumvent.patterns(.string("127.0.0.1, 0.0.0.0 ,")), ["127.0.0.1", "0.0.0.0"])
        XCTAssertEqual(NCDNSCircumvent.patterns(.array([.string("1.2.3.4"), .string("5.6.7.*,9.9.9.9")])),
                       ["1.2.3.4", "5.6.7.*", "9.9.9.9"])
        XCTAssertEqual(NCDNSCircumvent.patterns(nil), [])
    }

    func testRaceWaitsPastCircumventedFirstAnswer() {
        let c = NCDNSCircumvent(v4: ["127.0.0.1"], v6: [])
        let fake = Fake(servers, [0: (0.02, answer(["127.0.0.1"])), 1: (0.15, answer(["5.5.5.5"]))])
        let trace = NCDNSAttemptTrace()
        let (r, w, _) = qxRace(fake, accept: { c.judge($0) }, trace: trace)
        XCTAssertEqual(ips(r), ["5.5.5.5"])
        XCTAssertEqual(w, 1)
        XCTAssertTrue(trace.summary.contains("circumvented"), trace.summary)
    }

    func testRaceDeliversFilteredAnswerAtOnce() {
        let c = NCDNSCircumvent(v4: ["127.0.0.1"], v6: [])
        let fake = Fake(servers, [0: (0.02, answer(["127.0.0.1", "6.6.6.6"])), 1: (0.5, answer(["5.5.5.5"]))])
        let (r, w, dt) = qxRace(fake, accept: { c.judge($0) })
        XCTAssertEqual(ips(r), ["6.6.6.6"])
        XCTAssertEqual(w, 0)
        XCTAssertLessThan(dt, 0.4)
    }

    func testRaceFailsWhenEveryAnswerCircumvented() {
        let c = NCDNSCircumvent(v4: ["127.0.0.1"], v6: [])
        let fake = Fake(servers, [0: (0.02, answer(["127.0.0.1"])), 1: (0.04, answer(["127.0.0.1"])),
                                  2: (0.06, answer(["127.0.0.1"]))])
        let (r, w, dt) = qxRace(fake, accept: { c.judge($0) })
        XCTAssertNil(r)
        XCTAssertNil(w)
        XCTAssertLessThan(dt, 1.0, "fails as soon as the last server answered, not at the overall timeout")
    }

    // MARK: system DNS

    func testSystemDNSReplyBuildsAnswersOfAskedFamily() {
        let q = NCDNSMessage.parse(query("sys.example", type: NCDNSMessage.typeA))!
        let r = NCSystemDNS.reply(query: q, ips: [NCIP("93.184.216.34")!, NCIP("2001:db8::1")!, NCIP("93.184.216.34")!])
        let msg = NCDNSMessage.parse(r!)!
        XCTAssertEqual(msg.id, 0x1234)
        XCTAssertTrue(msg.isResponse)
        XCTAssertEqual(ips(r), ["93.184.216.34"], "v6 dropped for an A question, duplicates folded")
        XCTAssertEqual(msg.answers.first?.ttl, NCSystemDNS.ttl)
        XCTAssertNil(NCSystemDNS.reply(query: q, ips: nil), "lookup failure = no answer")
        let empty = NCDNSMessage.parse(NCSystemDNS.reply(query: q, ips: [])!)!
        XCTAssertEqual(empty.rcode, 0)
        XCTAssertTrue(empty.answers.isEmpty, "NOERROR / no data")
    }

    func testSystemDNSDropsFakeIPLoop() {
        NCSystemDNS.fakeRanges = [NCCIDR("198.18.0.0/15")!]
        let q = NCDNSMessage.parse(query("loop.example"))!
        XCTAssertNil(NCSystemDNS.reply(query: q, ips: [NCIP("198.18.0.7")!]), "an answer from our own fake pool is a loop")
        XCTAssertNotNil(NCSystemDNS.reply(query: q, ips: [NCIP("198.20.0.7")!]))
    }

    func testSystemDNSExchangeUsesResolverAndSkipsOtherTypes() {
        NCSystemDNS.lookupOverride = { name, wantV4 in
            name == "sys.example" ? (wantV4 ? [NCIP("203.0.113.9")!] : [NCIP("2001:db8::9")!]) : nil
        }
        let e1 = expectation(description: "A")
        var a: Data?
        NCSystemDNS.exchange(query("sys.example")) { a = $0; e1.fulfill() }
        let e2 = expectation(description: "AAAA")
        var aaaa: Data?
        NCSystemDNS.exchange(query("sys.example", type: NCDNSMessage.typeAAAA)) { aaaa = $0; e2.fulfill() }
        let e3 = expectation(description: "TXT")
        var txt: Data? = Data([1])
        NCSystemDNS.exchange(query("sys.example", type: 16)) { txt = $0; e3.fulfill() }
        wait(for: [e1, e2, e3], timeout: 3)
        XCTAssertEqual(ips(a), ["203.0.113.9"])
        XCTAssertEqual(ips(aaaa), [NCIP("2001:db8::9")!.string])
        XCTAssertNil(txt, "only A / AAAA can be asked through getaddrinfo")
    }

    func testSystemUpstreamJoinsNameserverGroup() {
        let base = NCDNSUpstream.firstUsable([["119.29.29.29"]])
        XCTAssertEqual(NCDNSUpstream.withSystem(base, nameservers: ["119.29.29.29", "system"]),
                       .group([.udp(host: "119.29.29.29", port: 53), .system]))
        XCTAssertEqual(NCDNSUpstream.withSystem(base, nameservers: ["119.29.29.29"]), base, "no-system: unchanged")
        XCTAssertEqual(NCDNSUpstream.withSystem(nil, nameservers: ["system"]), .system)
        XCTAssertEqual(NCDNSUpstream.system.label, "system")
    }

    // MARK: dns_reject_domain_behavior

    private func responder(_ behavior: NCDNSRejectBehavior) -> NCFakeIPResponder {
        let r = NCFakeIPResponder(pool: NCFakeIPPool())
        r.rejectMatcher = { $0 == "ad.example.com" ? "DOMAIN,ad.example.com,REJECT" : nil }
        r.rejectBehavior = behavior
        return r
    }

    func testRejectBehaviourDefaultIsLoopback() {
        XCTAssertEqual(NCDNSRejectBehavior.default, .loopback)
        XCTAssertEqual(NCFakeIPResponder(pool: NCFakeIPPool()).rejectBehavior, .loopback)
        XCTAssertEqual(NCDNSRejectBehavior(raw: " No-Error-No-Answer "), .noErrorNoAnswer)
        XCTAssertEqual(NCDNSRejectBehavior(raw: "NXDOMAIN"), .nxdomain)
        XCTAssertEqual(NCDNSRejectBehavior(raw: "none"), NCDNSRejectBehavior.none)
        XCTAssertNil(NCDNSRejectBehavior(raw: "bogus"))
        XCTAssertNil(NCDNSRejectBehavior(raw: nil))
    }

    func testRejectLoopbackAnswersBothFamiliesTTL10() {
        let r = responder(.loopback)
        let out = r.respondWithOutcome(to: query("ad.example.com"))
        XCTAssertEqual(out.rejection?.host, "ad.example.com")
        let a = NCDNSMessage.parse(out.reply!)!
        XCTAssertEqual(a.rcode, 0)
        XCTAssertEqual(ips(out.reply), ["127.0.0.1"])
        XCTAssertEqual(a.answers.first?.ttl, 10)
        let six = r.respond(to: query("ad.example.com", type: NCDNSMessage.typeAAAA))
        XCTAssertEqual(ips(six), [NCIP("::1")!.string]) // NCIP.string prints v6 uncompressed
        XCTAssertTrue(NCDNSRejectBehavior.isRejectReply(out.reply!))
        XCTAssertTrue(NCDNSRejectBehavior.isRejectReply(six!))
        XCTAssertEqual(NCDNSLogLine.rejected(name: "ad.example.com", type: "A", reply: out.reply!),
                       "[DNS] resolve ad.example.com error: A loopback 127.0.0.1 / ::1 (REJECT rule)")
    }

    func testRejectNoErrorNoAnswerCarriesMarkedSOA() {
        let r = responder(.noErrorNoAnswer)
        let reply = r.respond(to: query("ad.example.com"))!
        let msg = NCDNSMessage.parse(reply)!
        XCTAssertEqual(msg.rcode, 0)
        XCTAssertTrue(msg.answers.isEmpty)
        XCTAssertEqual(reply[reply.startIndex + 8], 0)
        XCTAssertEqual(reply[reply.startIndex + 9], 1, "NSCOUNT = 1 (QX TF 694: 包含 SOA 结果)")
        XCTAssertTrue(NCDNSRejectBehavior.isRejectReply(reply))
        XCTAssertEqual(NCDNSLogLine.rejected(name: "ad.example.com", type: "A", reply: reply),
                       "[DNS] resolve ad.example.com error: A NOERROR no answer (REJECT rule)")
    }

    func testRejectNXDOMAIN() {
        let reply = responder(.nxdomain).respond(to: query("ad.example.com"))!
        XCTAssertEqual(NCDNSMessage.parse(reply)?.rcode, 3)
        XCTAssertTrue(NCDNSRejectBehavior.isRejectReply(reply))
        XCTAssertEqual(NCDNSLogLine.rejected(name: "ad.example.com", type: "A", reply: reply),
                       "[DNS] resolve ad.example.com error: A NXDOMAIN (REJECT rule)")
    }

    func testRejectNoneTurnsDNSLevelRejectOff() {
        let r = responder(NCDNSRejectBehavior.none)
        let out = r.respondWithOutcome(to: query("ad.example.com"))
        XCTAssertNil(out.rejection, "no DNS-level rejection; the connection layer's REJECT still applies")
        let msg = NCDNSMessage.parse(out.reply!)!
        XCTAssertEqual(msg.answers.count, 1)
        XCTAssertEqual(msg.answers.first?.rdata.first, 198, "a fake IP like any other name")
        XCTAssertFalse(NCDNSRejectBehavior.isRejectReply(out.reply!))
    }

    func testRejectClassifierIgnoresOrdinaryLocalAnswers() {
        // A hosts entry pointing at 127.0.0.1 answers with TTL 60 and is not a reject.
        var h = NCDNSMessage.parse(answer(["127.0.0.1"], name: "local.test"))!
        h.answers[0].ttl = 60
        XCTAssertFalse(NCDNSRejectBehavior.isRejectReply(h.serialized()))
        XCTAssertFalse(NCDNSRejectBehavior.isRejectReply(answer(["8.8.8.8"])))
        XCTAssertFalse(NCDNSRejectBehavior.isRejectReply(NCSystemDNS.reply(query: NCDNSMessage.parse(query())!, ips: [])!),
                       "a NODATA without the marked SOA is not a reject")
    }

    // MARK: no-ipv6

    func testNoIPv6ReplyFailsOnlyAAAA() {
        let r = NCDNSPolicy.noIPv6Reply(queryData: query("v6.example", type: NCDNSMessage.typeAAAA))
        let msg = NCDNSMessage.parse(r!)!
        XCTAssertEqual(msg.rcode, 0)
        XCTAssertTrue(msg.answers.isEmpty)
        XCTAssertEqual(msg.id, 0x1234)
        XCTAssertNil(NCDNSPolicy.noIPv6Reply(queryData: query("v6.example", type: NCDNSMessage.typeA)))
        XCTAssertNil(NCDNSPolicy.noIPv6Reply(queryData: query("v6.example", type: NCDNSMessage.typeHTTPS)))
    }

    // MARK: rule-matching resolve cache (serve stale, network change)

    func testResolveCacheFreshStaleMiss() {
        var c = NCResolveCache()
        let t = Date(timeIntervalSince1970: 1_000_000)
        let ip = NCIP("203.0.113.1")!
        XCTAssertEqual(c.lookup("a.example", now: t), .miss)
        c.store("a.example", ip: ip, ttl: 120, now: t)
        XCTAssertEqual(c.lookup("a.example", now: t.addingTimeInterval(60)), .fresh(ip))
        XCTAssertEqual(c.lookup("a.example", now: t.addingTimeInterval(121)), .stale(ip), "expired answer still usable")
        XCTAssertEqual(c.lookup("a.example", now: t.addingTimeInterval(120 + NCResolveCache.staleWindow + 1)), .miss)
    }

    func testResolveCacheFailureKeepsKnownAddress() {
        var c = NCResolveCache()
        let t = Date(timeIntervalSince1970: 1_000_000)
        let ip = NCIP("203.0.113.2")!
        c.store("b.example", ip: ip, ttl: 600, now: t)
        c.store("b.example", ip: nil, ttl: 30, now: t.addingTimeInterval(5))
        XCTAssertEqual(c.lookup("b.example", now: t.addingTimeInterval(6)), .stale(ip), "failed refresh keeps the old answer (stale)")
        c.store("c.example", ip: nil, ttl: 30, now: t)
        XCTAssertEqual(c.lookup("c.example", now: t.addingTimeInterval(10)), .fresh(nil), "failure cached when nothing better known")
        XCTAssertEqual(c.lookup("c.example", now: t.addingTimeInterval(31)), .miss)
    }

    func testResolveCacheNetworkChangeExpiresInsteadOfClearing() {
        var c = NCResolveCache()
        let t = Date(timeIntervalSince1970: 1_000_000)
        let ip = NCIP("203.0.113.3")!
        c.store("d.example", ip: ip, ttl: 3600, now: t)
        c.markAllExpired(now: t.addingTimeInterval(10))
        XCTAssertEqual(c.count, 1, "nothing dropped")
        XCTAssertEqual(c.lookup("d.example", now: t.addingTimeInterval(11)), .stale(ip))
        c.store("d.example", ip: NCIP("203.0.113.4")!, ttl: 60, now: t.addingTimeInterval(12))
        XCTAssertEqual(c.lookup("d.example", now: t.addingTimeInterval(13)), .fresh(NCIP("203.0.113.4")!))
    }

    func testResolveCacheTTLClampAndCapacity() {
        XCTAssertEqual(NCResolveCache.clampTTL(1), 10)
        XCTAssertEqual(NCResolveCache.clampTTL(300), 300)
        XCTAssertEqual(NCResolveCache.clampTTL(86400), 3600)
        var c = NCResolveCache()
        let t = Date(timeIntervalSince1970: 1_000_000)
        for i in 0..<(NCResolveCache.capacity + 10) {
            c.store("h\(i).example", ip: NCIP("10.0.\(i / 256).\(i % 256)")!, ttl: Double(60 + i), now: t)
        }
        XCTAssertLessThanOrEqual(c.count, NCResolveCache.capacity)
        XCTAssertEqual(c.lookup("h\(NCResolveCache.capacity + 9).example", now: t), .fresh(NCIP("10.0.2.9")!), "newest kept")
    }

    // MARK: session archive resume / rotation

    private func rec(_ seq: Int64) -> [String: Any] { ["seq": seq, "v": "r\(seq)"] }
    private func seqs(_ l: [[String: Any]]) -> [Int64?] { l.map { ($0["seq"] as? NSNumber)?.int64Value } }

    func testArchiveResumeContinuesSession() {
        let f = dir.appendingPathComponent("s.jsonl")
        var a: NCSessionArchive? = NCSessionArchive(url: f)
        for i in 1...4 { a?.append(rec(Int64(i))) }
        a = nil
        let b = NCSessionArchive(url: f, resume: true)
        XCTAssertEqual(b.count, 4)
        XCTAssertEqual(b.newestSeq, 4)
        b.append(rec(5))
        XCTAssertEqual(seqs(b.readAll()), [1, 2, 3, 4, 5])
        XCTAssertFalse(FileManager.default.fileExists(atPath: NCSessionArchive.previousURL(f, 1).path), "resume does not rotate")
    }

    func testArchiveResumeDropsTornLastLine() throws {
        let f = dir.appendingPathComponent("torn.jsonl")
        try Data("{\"seq\":1,\"v\":\"a\"}\n{\"seq\":2,\"v\":\"b\"}\n{\"seq\":3,\"v".utf8).write(to: f)
        let a = NCSessionArchive(url: f, resume: true)
        XCTAssertEqual(a.count, 2)
        XCTAssertEqual(a.newestSeq, 2)
        a.append(rec(3))
        XCTAssertEqual(seqs(a.readAll()), [1, 2, 3])
    }

    func testArchiveResumeWithoutFileStartsFresh() {
        let f = dir.appendingPathComponent("none.jsonl")
        let a = NCSessionArchive(url: f, resume: true)
        XCTAssertEqual(a.count, 0)
        a.append(rec(1))
        XCTAssertEqual(a.count, 1)
    }

    func testArchiveNewSessionRotatesPreviousOnes() throws {
        let f = dir.appendingPathComponent("rot.jsonl")
        for s in 1...4 {
            let a = NCSessionArchive(url: f)
            a.append(rec(Int64(s * 10)))
        }
        _ = NCSessionArchive(url: f) // a fifth session: rot.jsonl empty, .1 = session 4, .2 = session 3
        func firstSeq(_ u: URL) -> Int64? {
            NCSessionArchive(url: u, resume: true).readAll().first.flatMap { ($0["seq"] as? NSNumber)?.int64Value }
        }
        XCTAssertEqual(firstSeq(NCSessionArchive.previousURL(f, 1)), 40)
        XCTAssertEqual(firstSeq(NCSessionArchive.previousURL(f, 2)), 30)
        XCTAssertFalse(FileManager.default.fileExists(atPath: NCSessionArchive.previousURL(f, 3).path))
        XCTAssertEqual(NCSessionArchive.previousURL(f, 1).lastPathComponent, "rot.1.jsonl")
    }

    func testArchiveEmptySessionIsNotRotated() {
        let f = dir.appendingPathComponent("empty.jsonl")
        let a = NCSessionArchive(url: f)
        a.append(rec(1))
        _ = NCSessionArchive(url: f)   // session 2, empty
        _ = NCSessionArchive(url: f)   // session 3: the empty session 2 must not push session 1 out of .1
        XCTAssertEqual(NCSessionArchive(url: NCSessionArchive.previousURL(f, 1), resume: true).count, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: NCSessionArchive.previousURL(f, 2).path))
    }

    func testArchiveReadAllCapKeepsNewest() {
        let a = NCSessionArchive(url: dir.appendingPathComponent("cap.jsonl"))
        for i in 1...12 { a.append(rec(Int64(i))) }
        XCTAssertEqual(seqs(a.readAll(limit: 5)), [8, 9, 10, 11, 12])
        XCTAssertEqual(NCSessionArchive.readAllCap, 10_000)
        XCTAssertEqual(NCSessionArchive.fuseBytes, 32 * 1024 * 1024)
    }

    // MARK: counters snapshot

    func testSnapshotRoundTrip() {
        let url = dir.appendingPathComponent("stats.json")
        let s = NCStatsSnapshot(session: 7, since: 1_700_000_000_000, total: 3, seq: 42,
                                policies: [["Proxy", "10", "20"]], hosts: [["a.example", "1", "2"]],
                                rules: [["DOMAIN,a.example", "Proxy", "5"]], rejectStored: 1, rejectedMerged: 2,
                                rejectedOverflow: 0, minutes: [[60, 1, 2, 3, 4, 5]], hours: [[3600, 6, 7, 8, 9, 10]],
                                savedAt: 1_700_000_100)
        XCTAssertTrue(s.save(url))
        XCTAssertEqual(NCStatsSnapshot.load(url), s)
        XCTAssertNil(NCStatsSnapshot.load(dir.appendingPathComponent("missing.json")))
        var old = s
        old.version = 0
        XCTAssertTrue(old.save(url))
        XCTAssertNil(NCStatsSnapshot.load(url), "another shape version starts a new session")
    }

    func testRecorderResumesSavedSession() {
        let closedURL = dir.appendingPathComponent("closed.jsonl")
        let snapURL = dir.appendingPathComponent("session-stats.json")
        let t = Int64(Date().timeIntervalSince1970 * 1000)
        let a = NCStatsRecorder()
        a.enableSessionArchive(closedURL: closedURL, snapshotURL: snapURL, resume: false)
        a.opened(rule: "DOMAIN,a.example", policy: "Proxy")
        a.bytes(policy: "Proxy", host: "a.example", up: 100, down: 200)
        a.closed(NCStatsRecorder.Closed(seq: 0, id: "c1", network: "tcp", srcPort: 50000, dstIP: "203.0.113.1",
                                        dstPort: 443, host: "a.example", remote: "a.example", chains: ["Proxy"],
                                        rule: "DOMAIN,a.example", up: 100, down: 200, start: t, closedAt: t))
        a.persistNow(sync: true)
        let sa = a.statsJSON(session: -1, closedAfter: 0, hostLimit: 0, ruleLimit: 0)

        let b = NCStatsRecorder()
        b.enableSessionArchive(closedURL: closedURL, snapshotURL: snapURL, resume: true)
        XCTAssertTrue(b.resumedSession)
        let sb = b.statsJSON(session: -1, closedAfter: 0, hostLimit: 0, ruleLimit: 0)
        XCTAssertEqual(sb["session"] as? Int64, sa["session"] as? Int64, "same session id: the App keeps its cursor")
        XCTAssertEqual(sb["totalConnections"] as? Int, 1)
        XCTAssertEqual((sb["closed"] as? [[String: Any]])?.count, 1, "archived closed connection still listed")
        XCTAssertEqual(((sb["policies"] as? [[String: Any]])?.first?["down"] as? Int64), 200)
        XCTAssertEqual(((sb["rules"] as? [[String: Any]])?.first?["hits"] as? Int), 1)
        XCTAssertEqual(sb["closedSeq"] as? Int64, sa["closedSeq"] as? Int64)

        // A normal start (no resume) begins a new session and keeps the previous one as .1.
        let c = NCStatsRecorder()
        c.enableSessionArchive(closedURL: closedURL, snapshotURL: snapURL, resume: false)
        XCTAssertFalse(c.resumedSession)
        XCTAssertEqual((c.statsJSON(session: -1, closedAfter: 0, hostLimit: 0, ruleLimit: 0)["totalConnections"] as? Int), 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: NCSessionArchive.previousURL(snapURL, 1).path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: NCSessionArchive.previousURL(closedURL, 1).path))
    }

    func testRecorderResumeWithoutSnapshotStartsFresh() {
        let closedURL = dir.appendingPathComponent("closed2.jsonl")
        let snapURL = dir.appendingPathComponent("stats2.json")
        let a = NCSessionArchive(url: closedURL)
        a.append(["seq": Int64(1), "id": "x"])
        let r = NCStatsRecorder()
        r.enableSessionArchive(closedURL: closedURL, snapshotURL: snapURL, resume: true)
        XCTAssertFalse(r.resumedSession, "no counters on disk: a new session, the stray archive rotated away")
        XCTAssertEqual((r.statsJSON(session: -1, closedAfter: 0, hostLimit: 0, ruleLimit: 0)["closed"] as? [[String: Any]])?.count, 0)
    }
}
