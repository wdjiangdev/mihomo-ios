import Foundation

// feat/egern-2-21 (Egern 2.21.0 「Proxy server and its location in connection details」): the 出站节点 section of a
// connection's detail page. Everything comes from what Tern already has on the device — the node's server / port
// from the profile, the server IP's country and ASN from the local GeoIP / ASN databases, the exit already measured
// by 出口 IP / 解锁检测. Nothing is sent to an IP lookup service from here.

/// What the 出站节点 section shows for one connection.
struct OutboundNodeInfo: Equatable {
    /// The node the connection left through (the last hop of a proxy chain).
    var name: String
    /// Every hop when the node is a proxy chain (`A -> B`), first hop first; empty for a single node.
    var hops: [String] = []
    var type: String?
    var server: String?
    var port: Int?
    /// The server address used for the database lookup (the server itself when it is an IP).
    var serverIP: String?
    /// From the local GeoIP database.
    var countryCode: String?
    /// From the local ASN database.
    var asn: Int?
    var asOrg: String?
    /// Region read from the node's name (ncDetectRegion) — shown only as 「按名称推断」, never as a lookup result.
    var inferredCode: String?
    /// The exit already measured for this node (ProbeStore); never probed from here.
    var exit: IPInfo?
    var exitDate: Date?
    /// The server is a domain name: the databases need an IP, and the app does not resolve node names itself
    /// (with the VPN on that would go through the tunnel's own DNS and could return a fake IP).
    var serverIsDomain = false
    /// No local GeoIP database file was found.
    var noGeoDB = false

    var serverText: String? {
        guard let s = server, !s.isEmpty else { return nil }
        guard let p = port else { return s }
        return s.contains(":") ? "[\(s)]:\(p)" : "\(s):\(p)"
    }

    var asnText: String? {
        guard let a = asn else { return nil }
        if let o = asOrg, !o.isEmpty { return "AS\(a) · \(o)" }
        return "AS\(a)"
    }
}

enum OutboundNode {
    /// Built-in outbounds that are not nodes.
    static let builtins: Set<String> = ["DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "REJECT-DICT", "REJECT-ARRAY",
                                        "PASS", "COMPATIBLE", "GLOBAL", "MITM", RuleDisplay.engineOutbound]

    /// The node behind a connection's chains (`chains.first` is the node in both the old core's and NativeCore's
    /// format; a proxy chain is one entry `A -> B`). Nil for DIRECT / REJECT / the rewrite engine.
    static func nodeName(_ chains: [String]?) -> (name: String, hops: [String])? {
        guard let first = chains?.first?.trimmingCharacters(in: .whitespaces), !first.isEmpty else { return nil }
        let hops = first.components(separatedBy: " -> ").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard let last = hops.last, !builtins.contains(last.uppercased()), !builtins.contains(last) else { return nil }
        return (last, hops.count > 1 ? hops : [])
    }

    /// Fills the database fields. Pure and synchronous: call it off the main thread (opens / maps the databases).
    static func lookup(_ base: OutboundNodeInfo, home: URL) -> OutboundNodeInfo {
        var info = base
        let code = ncDetectRegion(info.name).code
        info.inferredCode = code.isEmpty ? nil : code
        guard let server = info.server?.trimmingCharacters(in: CharacterSet(charactersIn: "[] ")), !server.isEmpty else { return info }
        guard let ip = NCIP(server) else {
            info.serverIsDomain = true
            return info
        }
        info.serverIP = ip.string
        let dbs = OutboundGeoDB.shared.databases(home: home)
        if let geo = dbs.geo {
            info.countryCode = geo.countryCodes(for: ip).first { $0.count == 2 }?.uppercased()
        } else {
            info.noGeoDB = true
        }
        if let asn = dbs.asn, let rec = asn.lookup(ip)?.object {
            info.asn = rec["autonomous_system_number"]?.int
            info.asOrg = rec["autonomous_system_organization"]?.string
        }
        return info
    }

    /// UI tests (-UITestSeed -UITestDemoConnections): fixed values for the demo connections' nodes (documentation
    /// addresses have no database entry).
    static func demo(name: String, hops: [String]) -> OutboundNodeInfo? {
        switch name {
        case "🇯🇵 Tokyo 01":
            return OutboundNodeInfo(name: name, hops: hops, type: "trojan", server: "192.0.2.1", port: 443, serverIP: "192.0.2.1",
                                    countryCode: "JP", asn: 2516, asOrg: "KDDI CORPORATION", inferredCode: "JP",
                                    exit: IPInfo(ip: "203.0.113.7", countryCode: "JP", country: "Japan", region: "Tokyo", city: "Tokyo",
                                                 asn: "AS2516", org: "KDDI CORPORATION", source: "demo"),
                                    exitDate: Date().addingTimeInterval(-600))
        case "🇺🇸 San Jose 02":
            return OutboundNodeInfo(name: name, hops: hops, type: "vmess", server: "us2.example.com", port: 8443, inferredCode: "US",
                                    serverIsDomain: true)
        default:
            return nil
        }
    }
}

/// The two databases, opened once per file version (mapped, not read into memory). Lock-protected; used from
/// background tasks only.
final class OutboundGeoDB {
    static let shared = OutboundGeoDB()
    private let lock = NSLock()
    private var geoSig = "", asnSig = ""
    private var geo: NCMMDB?, asn: NCMMDB?

    func databases(home: URL) -> (geo: NCMMDB?, asn: NCMMDB?) {
        lock.lock(); defer { lock.unlock() }
        let geoPath = NCGeoStore.findCI(dir: home.path, name: "geoip.metadb")
        let asnPath = NCGeoStore.findCI(dir: home.path, name: "ASN.mmdb")
        let gs = Self.sig(geoPath), asig = Self.sig(asnPath)
        if gs != geoSig { geoSig = gs; geo = gs.isEmpty ? nil : NCMMDB(contentsOfFile: geoPath) }
        if asig != asnSig { asnSig = asig; asn = asig.isEmpty ? nil : NCMMDB(contentsOfFile: asnPath) }
        return (geo, asn)
    }

    private static func sig(_ path: String) -> String {
        guard let a = try? FileManager.default.attributesOfItem(atPath: path), let size = a[.size] as? NSNumber,
              size.intValue > 1024 else { return "" }
        let m = (a[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        return "\(size.intValue):\(m)"
    }
}
