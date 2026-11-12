import XCTest

/// proto5 zhiheng interop: the three remaining kit protocols — OpenConnect, MASQUE-IP
/// (CONNECT-IP) and MASQUE-UDP (CONNECT-UDP) — through their PRODUCTION paths against the real
/// kit servers on zhiheng (45.92.159.155: ocserv 24036, connect-ip-go 24039, masque-go 24040).
/// The kit's group delay test (test99) runs in the App process, where the L3 outbounds have no
/// dialer (PacketTunnel-only lwIP stacks) and CONNECT-UDP cannot carry the TCP test URL at all,
/// so it reports all three as "超时" regardless of health; these tests measure what a user with
/// the tunnel up actually gets, like NCWireGuardZhihengInteropTests does for WireGuard.
///
/// Two client bugs were found and fixed against these servers (both invisible to the loopback
/// suite, whose servers differ in exactly the relevant dimension):
/// - OpenConnect: ocserv 1.1.6 stages plain auth (username form, then a password-only form);
///   the client refused any second form that asked for the password and could never log in.
/// - MASQUE-UDP: the Extended CONNECT :authority was the dial address (45.92.159.155:24040);
///   masque-go validates it against its URI template (tern.test:24040) and answers 400.
/// The MASQUE-IP server side also needed a kit fix (tern-net NOTRACK: the proxy's locally
/// generated raw-socket sends consumed the NAT binding decision before the forwarding pass).
///
/// Runs in proto-loopback.yml job `proto5-zh` (opt-in) with TEST_RUNNER_NC_PROTO5_ZH=1 and
/// TEST_RUNNER_NC_OC_PASS in the environment (the kit node's public test password, also in the
/// UITestSeed); there it FAILS (never skips) when a server is unreachable; elsewhere it skips.
final class NCProto5ZhihengInteropTests: XCTestCase {
    private let env = ProcessInfo.processInfo.environment
    private let q = DispatchQueue(label: "proto5.zh.interop.test")
    private let server = "45.92.159.155"

    override func setUpWithError() throws {
        guard env["NC_PROTO5_ZH"] == "1" else {
            throw XCTSkip("proto5 zhiheng interop: set TEST_RUNNER_NC_PROTO5_ZH=1 with the kit env (proto-loopback.yml proto5-zh)")
        }
        XCTAssertFalse((env["NC_OC_PASS"] ?? "").isEmpty, "NC_OC_PASS missing")
        NCConnector.installOpenConnectDialer()
        NCConnector.installMASQUEIPDialer()
    }

    override func tearDown() {
        NCLwIP.queue.sync {
            NCOCStack.shared.teardownAll()
            NCMQIPStack.shared.teardownAll()
        }
        Thread.sleep(forTimeInterval: 0.5)
        super.tearDown()
    }

    // MARK: nodes (the kit seed nodes, verbatim)

    private func openConnectNode() -> NCProxy {
        NCProxy(name: "Tern-OpenConnect", type: "openconnect", fields: [
            "server": .string(env["NC_OC_SERVER"] ?? server),
            "port": .number(Double(env["NC_OC_PORT"] ?? "") ?? 24036),
            "username": .string(env["NC_OC_USER"] ?? "terndpa3"),
            "password": .string(env["NC_OC_PASS"] ?? ""),
            "dtls": .bool(true), "udp": .bool(true),
            "sni": .string("tern.test"), "skip-cert-verify": .bool(true),
        ])
    }

    private func masqueIPNode() -> NCProxy {
        NCProxy(name: "Tern-MASQUE-IP", type: "masque", fields: [
            "server": .string(server), "port": .number(24039),
            "mode": .string("connect-ip"), "uri": .string("https://proxy:24039/vpn"),
            "sni": .string("proxy"), "mtu": .number(1200),
            "dns": .array([.string("1.1.1.1")]),
            "udp": .bool(true), "skip-cert-verify": .bool(true),
        ])
    }

    private func masqueUDPNode() -> NCProxy {
        NCProxy(name: "Tern-MASQUE-UDP", type: "masque", fields: [
            "server": .string(server), "port": .number(24040),
            "mode": .string("connect-udp"),
            "username": .string("tern"), "password": .string("tern"),
            "uri": .string("https://tern.test:24040/.well-known/masque/udp/{target_host}/{target_port}/"),
            "udp": .bool(true),
            "sni": .string("tern.test"), "skip-cert-verify": .bool(true),
        ])
    }

    // MARK: helpers

    private func dial(_ p: NCProxy, _ host: String, _ port: Int, timeout: TimeInterval = 90) -> (NCRelayStream?, Error?) {
        let exp = expectation(description: "dial \(host):\(port)")
        var out: (NCRelayStream?, Error?) = (nil, nil)
        let t0 = Date()
        NCConnector.connect(target: NCTarget(host: host, port: port), proxy: p, queue: q) { s, e in
            out = (s, e)
            exp.fulfill()
        }
        wait(for: [exp], timeout: timeout)
        NSLog("[proto5-zh] dial %@:%d via %@ in %.2f s -> %@", host, port, p.name,
              Date().timeIntervalSince(t0), out.0 != nil ? "ok" : "\(String(describing: out.1))")
        return out
    }

    /// HTTP/1.0 GET over `s` until the server closes; returns (status line, body).
    private func httpGet(_ s: NCRelayStream, host: String, path: String, timeout: TimeInterval = 120) -> (String, Data) {
        let done = expectation(description: "GET \(path)")
        var raw = Data()
        var finished = false
        func finish() { if !finished { finished = true; done.fulfill() } }
        func read() {
            s.receive { d, _ in
                guard let d, !d.isEmpty else { finish(); return }
                raw.append(d)
                read()
            }
        }
        q.async {
            s.send(Data("GET \(path) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: tern-proto5-zh-probe\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".utf8)) {}
            read()
        }
        wait(for: [done], timeout: timeout)
        let all = q.sync { raw }
        guard let r = all.range(of: Data([13, 10, 13, 10])) else {
            return (String(decoding: all.prefix(200), as: UTF8.self), Data())
        }
        let head = String(decoding: all[all.startIndex..<r.lowerBound], as: UTF8.self)
        var body = Data(all[r.upperBound...])
        if head.lowercased().contains("transfer-encoding: chunked") { body = dechunk(body) }
        return (head.components(separatedBy: "\r\n").first ?? "", body)
    }

    private func dechunk(_ d: Data) -> Data {
        var out = Data()
        var i = d.startIndex
        while let crlf = d[i...].range(of: Data([13, 10])) {
            let sizeLine = String(decoding: d[i..<crlf.lowerBound], as: UTF8.self).split(separator: ";").first ?? ""
            guard let n = Int(sizeLine.trimmingCharacters(in: .whitespaces), radix: 16), n > 0 else { break }
            let start = crlf.upperBound
            guard start + n <= d.endIndex else { out.append(d[start...]); break }
            out.append(d[start..<(start + n)])
            i = min(start + n + 2, d.endIndex)
        }
        return out
    }

    private func dnsQuery(id: UInt16) -> Data {
        var query: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in ["one", "one", "one", "one"] { query.append(UInt8(label.utf8.count)); query += Array(label.utf8) }
        query += [0, 0, 1, 0, 1]
        return Data(query)
    }

    // MARK: OpenConnect

    /// TCP through the OpenConnect tunnel: this dial alone proves the staged auth against
    /// ocserv 1.1.6 completes (username form, then password form) and CSTP comes up; the fetch
    /// proves the data plane — egress must be the zhiheng server itself (tern-net NAT).
    func testOpenConnectHTTPFetchThroughTunnel() throws {
        let p = openConnectNode()
        let (s, err) = dial(p, "www.cloudflare.com", 80)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let (status, body) = httpGet(stream, host: "www.cloudflare.com", path: "/cdn-cgi/trace")
        NSLog("[proto5-zh] OpenConnect GET /cdn-cgi/trace -> %@", status)
        XCTAssertTrue(status.contains(" 200"), status)
        let text = String(decoding: body, as: UTF8.self)
        NSLog("[proto5-zh] OpenConnect trace: %@", text.split(separator: "\n").filter { $0.hasPrefix("ip=") || $0.hasPrefix("colo=") }.joined(separator: " "))
        XCTAssertTrue(text.contains("ip=45.92.159.155"), "egress is not the zhiheng server: \(text)")
    }

    /// UDP DNS through the OpenConnect netif to the pushed resolver (1.1.1.1).
    func testOpenConnectUDPDNSThroughTunnel() throws {
        let p = openConnectNode()
        let session = NCUDPWireGuardSession(proxy: p, queue: q, acquire: { NCOCStack.shared.acquire($0) })
        defer { session.cancel() }
        let qid: UInt16 = 0x5031
        let got = expectation(description: "oc dns answer")
        var answer: [NCIP]?
        var fulfilled = false
        session.onReply = { d in
            guard !fulfilled, let r = NCWGDevice.parseDNS([UInt8](d), id: qid, qtype: 1) else { return }
            fulfilled = true
            answer = r
            got.fulfill()
        }
        let query = dnsQuery(id: qid)
        let timer = DispatchSource.makeTimerSource(queue: q)
        timer.schedule(deadline: .now(), repeating: 2)
        timer.setEventHandler { session.send(query, to: NCTarget(host: "1.1.1.1", port: 53)) }
        timer.resume()
        wait(for: [got], timeout: 90)
        timer.cancel()
        let ips = Set(q.sync { answer?.map { $0.string } ?? [] })
        NSLog("[proto5-zh] OpenConnect DNS one.one.one.one A = %@", ips.sorted().joined(separator: ","))
        XCTAssertFalse(ips.isDisjoint(with: ["1.1.1.1", "1.0.0.1"]), "\(ips)")
    }

    // MARK: MASQUE-IP

    /// TCP through the CONNECT-IP netif (assigned 10.89.0.2, advertised route 0.0.0.0/0):
    /// proves handshake, capsules and the kit's netns + NAT return path end to end.
    func testMASQUEIPHTTPFetchThroughTunnel() throws {
        let p = masqueIPNode()
        let (s, err) = dial(p, "www.cloudflare.com", 80)
        let stream = try XCTUnwrap(s, "dial failed: \(String(describing: err))")
        defer { stream.cancel() }
        let (status, body) = httpGet(stream, host: "www.cloudflare.com", path: "/cdn-cgi/trace")
        NSLog("[proto5-zh] MASQUE-IP GET /cdn-cgi/trace -> %@", status)
        XCTAssertTrue(status.contains(" 200"), status)
        let text = String(decoding: body, as: UTF8.self)
        NSLog("[proto5-zh] MASQUE-IP trace: %@", text.split(separator: "\n").filter { $0.hasPrefix("ip=") || $0.hasPrefix("colo=") }.joined(separator: " "))
        XCTAssertTrue(text.contains("ip=45.92.159.155"), "egress is not the zhiheng server: \(text)")
    }

    // MARK: MASQUE-UDP

    /// DNS over CONNECT-UDP to 1.1.1.1:53: the Extended CONNECT itself is the regression test
    /// for the :authority fix (masque-go rejects a mismatched authority with 400 before any
    /// datagram flows); the parsed answer proves the datagram path both ways.
    func testMASQUEUDPDNSThroughProxy() throws {
        let p = masqueUDPNode()
        let opened = expectation(description: "masque-udp stream open")
        var streamOut: NCRelayStream?
        var openErr: Error?
        NCMASQUERegistry.masqueStream(proxy: p, target: NCTarget(host: "1.1.1.1", port: 53), queue: q) { s, e in
            streamOut = s
            openErr = e
            opened.fulfill()
        }
        wait(for: [opened], timeout: 60)
        let stream = try XCTUnwrap(streamOut, "masqueStream failed: \(String(describing: openErr))")
        defer { stream.cancel() }

        let qid: UInt16 = 0x5032
        let query = dnsQuery(id: qid)
        let matched = expectation(description: "masque-udp dns answer")
        let box = Proto5DNSBox()
        func armReceive() {
            stream.receive { d, _ in
                guard !box.done else { return }
                if let d, let r = NCWGDevice.parseDNS([UInt8](d), id: qid, qtype: 1) {
                    if box.complete(r) { matched.fulfill() }
                    return
                }
                armReceive()
            }
        }
        armReceive()
        let timer = DispatchSource.makeTimerSource(queue: q)
        timer.schedule(deadline: .now(), repeating: 2)
        timer.setEventHandler { if !box.done { stream.send(query) } }
        timer.resume()
        wait(for: [matched], timeout: 90)
        timer.cancel()
        let ips = Set(box.answer?.map { $0.string } ?? [])
        NSLog("[proto5-zh] MASQUE-UDP DNS one.one.one.one A = %@", ips.sorted().joined(separator: ","))
        XCTAssertFalse(ips.isDisjoint(with: ["1.1.1.1", "1.0.0.1"]), "\(ips)")
    }
}

/// Lock-guarded holder for the first parsed DNS answer (receive callbacks and the resend
/// timer touch it from different queues).
private final class Proto5DNSBox {
    private let lock = NSLock()
    private var _answer: [NCIP]?
    private var _done = false

    var done: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _done
    }

    var answer: [NCIP]? {
        lock.lock()
        defer { lock.unlock() }
        return _answer
    }

    /// Records the answer; returns true exactly once (for the first completion).
    func complete(_ r: [NCIP]) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if _done { return false }
        _done = true
        _answer = r
        return true
    }
}
