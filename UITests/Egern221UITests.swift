import XCTest

/// feat/egern-2-21 (Egern 2.21.0 parity): 请求 → connection detail 「出站节点」 (node, server, server region / ASN from
/// the local databases, inferred region, measured exit) and DNS → 「上游状态」 (per-upstream status, red banner).
extension TernUITests {

    // MARK: 102. 连接详情 · 出站节点

    func test102_ConnectionOutboundNode() {
        launch(["-UITestDemoConnections"])
        tab(2)
        XCTAssertTrue(app.element(id: "requests.tcpCount").waitForExistence(timeout: 8), "requests page")

        // Proxied through an IP server: server, region and ASN from the databases (demo values), measured exit.
        let row = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "www.example.com")).firstMatch
        XCTAssertTrue(scrollTo(row), "connection row")
        row.tap()
        let node = app.element(id: "conndetail.node")
        XCTAssertTrue(scrollTo(node), "出站节点 section")
        XCTAssertTrue(fullText(node).contains("Tokyo 01"), "node name: \(fullText(node))")
        XCTAssertTrue(fullText(node).contains("TROJAN"), "node type: \(fullText(node))")
        let server = app.element(id: "conndetail.node.server")
        XCTAssertTrue(server.exists, "server row")
        XCTAssertTrue(fullText(server).contains("192.0.2.1:443"), "server host:port: \(fullText(server))")
        let region = app.element(id: "conndetail.node.region")
        XCTAssertTrue(scrollTo(region), "server region row")
        XCTAssertTrue(fullText(region).contains(L("日本")) || fullText(region).contains("Japan"), "region: \(fullText(region))")
        let asn = app.element(id: "conndetail.node.asn")
        XCTAssertTrue(fullText(asn).contains("AS2516"), "ASN: \(fullText(asn))")
        XCTAssertFalse(app.element(id: "conndetail.node.inferred").exists, "no inferred row when the database answered")
        let exit = app.element(id: "conndetail.node.exit")
        XCTAssertTrue(scrollTo(exit), "exit row")
        XCTAssertTrue(fullText(exit).contains("203.0.113.7"), "measured exit: \(fullText(exit))")
        snap("egern221-outbound-ip")
        back()

        // Domain server: no database lookup, region inferred from the name and labelled so.
        let row3 = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "quic.example.net")).firstMatch
        XCTAssertTrue(scrollTo(row3), "UDP connection row")
        row3.tap()
        let node3 = app.element(id: "conndetail.node")
        XCTAssertTrue(scrollTo(node3), "出站节点 section (domain server)")
        XCTAssertTrue(fullText(node3).contains("San Jose 02"), "node: \(fullText(node3))")
        XCTAssertTrue(fullText(app.element(id: "conndetail.node.server")).contains("us2.example.com:8443"))
        XCTAssertFalse(app.element(id: "conndetail.node.region").exists, "no database region for a domain server")
        let inferred = app.element(id: "conndetail.node.inferred")
        XCTAssertTrue(scrollTo(inferred), "inferred region row")
        XCTAssertTrue(fullText(inferred).contains(L("地区（按名称推断）")), "labelled as inferred: \(fullText(inferred))")
        snap("egern221-outbound-domain")
        back()

        // DIRECT: no 出站节点 section at all.
        let row2 = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "api.example.org")).firstMatch
        XCTAssertTrue(scrollTo(row2), "direct connection row")
        row2.tap()
        XCTAssertTrue(app.element(id: "conndetail.tabs").waitForExistence(timeout: 6))
        XCTAssertFalse(scrollTo(app.element(id: "conndetail.node"), maxSwipes: 4, fail: false), "DIRECT has no node section")
        back()
    }

    // MARK: 103. DNS · 上游状态

    func test103_DNSHealthSection() {
        launch(["-UITestDNSHealth"])
        openMore("DNS")
        let banner = app.element(id: "dns.health.banner")
        XCTAssertTrue(scrollTo(banner), "red banner while an upstream is down")
        XCTAssertTrue(fullText(banner).contains("192.0.2.53"), "banner names the server: \(fullText(banner))")
        let ok = app.element(id: "dns.health.row.nameserver")
        XCTAssertTrue(scrollTo(ok), "nameserver row")
        XCTAssertTrue(fullText(ok).contains("23 ms"), "latency: \(fullText(ok))")
        XCTAssertTrue(fullText(ok).contains("DoH"), "transport subtitle: \(fullText(ok))")
        let slow = app.element(id: "dns.health.row.fallback")
        XCTAssertTrue(fullText(slow).contains("912"), "slow: \(fullText(slow))")
        let down = app.element(id: "dns.health.row.default-nameserver")
        XCTAssertTrue(scrollTo(down), "bootstrap row")
        XCTAssertTrue(fullText(down).contains(L("异常")), "down: \(fullText(down))")
        snap("egern221-dns-health")

        // 更多 → 通知 lists the two new switches.
        back()
        openMore("通知")
        for k in ["dnsUpstream", "tailscaleLogin"] {
            let sw = app.element(id: "notify." + k)
            XCTAssertTrue(scrollTo(sw), "通知 row \(k)")
        }
        snap("egern221-notify-rows")
    }
}
