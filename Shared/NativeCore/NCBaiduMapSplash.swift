import Foundation

/// fix/baidumap-splash: the built-in Baidu Maps (百度地图) splash-ad protection — the Quantumult X recipe, built in.
///
/// Why: under Tern build 569 Baidu Maps showed its 开屏 ad on every cold start while Quantumult X on the same
/// profile did not. QX does not win with HTTPDNS blocking alone (V2EX t/1013571: "block http dns 不行，但是把那些
/// IP 都加到 mitm 里就可以了"); what kills the splash in every maintained QX / Loon set is a MitM URL rewrite of the
/// splash-config call on newclient.map.baidu.com plus a few DNS-layer REJECTs:
///   - fmz200/wool_scripts blockAds (Loon plugin, 2026-10-30, 「百度地图」 block): DOMAIN afd / afdconf /
///     httpdns.baidubce / lc.map.baidu.com REJECT, hostname newclient.map.baidu.com, http-response on
///     `^https?://newclient.map.baidu.com/client/phpui2/?qt=ads` (Scripts/baidumap.js pushes splash_screen1040 /
///     *_banner start/end into the past);
///   - RuCu6 bdmap.snippet / V2EX t/1013571 (QX): `phpui2.*qt=ads` / `noticebar/get` / `phpui2.*qt=bar` url
///     reject-dict, hostname adds 163.177.17.*, 180.76.76.112, 180.76.76.200;
///   - blackmatrix7 Advertising / GeQ1an: crossmarketing, usersystem/home/dynamic reject.
/// reject-dict (`{}` with 200) instead of the protobuf script: the client treats an empty answer as "no splash
/// scheduled"; the script needs a 300 KB protobuf runtime per cold start for the same visible result.
///
/// Two layers, both gated by the 「HTTPDNS 守卫」 switch (CoreOverrides.httpdnsGuard, default ON):
///   1. DNS / connection layer — `coreRules`, prepended to the runtime rules by NativeRuntimePrep in every state.
///      Domain-class REJECTs, so the DNS layer refuses the names (NCRuleMatcher.dnsRejectRule) and the records
///      land in 已拦截 with the rule text. The HTTPDNS service's FIXED IPs are the HTTPDNS guard's seeds
///      (NCHTTPDNSGuard.seedIPs), not IP-CIDR rules: the guard refuses them at accept, before MitM or routing.
///   2. HTTPS layer — `moduleText` (a QX snippet: [rewrite_local] + [mitm]) joins the rewrite / MitM rule set like
///      an enabled module, ONLY while the user's 重写 and MitM switches are on AND the Tern CA is trusted
///      (NativeRuntimePrep checks NCCAManager.checkTrust). Without a trusted CA, decrypting newclient would fail
///      every Baidu Maps API call until pinning memory backs off — so it falls back to layer 1 alone.
///
/// Order between the two (documented decision): the HTTPDNS guard runs at TCP accept, before the MitM gate. The
/// seeds are HTTPDNS SERVICE addresses (Baidu Cloud's documented anycast VIP + Baidu's app-family resolver),
/// never content servers, so a guard hit always wins over a MitM host entry for the same IP — the outcome QX
/// reaches by MitM-ing them (the SDK's HTTPDNS call fails) is reached here by refusing it. The app then falls
/// back to the system resolver, newclient.map.baidu.com is dialled by name (or, from a cached answer, by a
/// 163.177.17.x address with no SNI — the MitM gate matches the destination IP against `mitmHostnames`), and the
/// rewrite matches on the request's Host header (NativeRewriteEngine builds the URL from Host, not the IP).
enum NCBaiduMapSplash {
    /// The splash-config / ad hosts refused at the DNS layer (plus the two HTTPDNS service names, so a
    /// system-DNS lookup of them fails fast instead of the guard's accept-time RST).
    static let rejectDomains: [String] = [
        "afd.baidu.com",
        "afdconf.baidu.com",
        "lc.map.baidu.com",
        "httpdns.baidu.com",
        "httpdns.baidubce.com",
    ]

    /// Runtime rule lines (canonical spelling), prepended to the profile's rules while the switch is on.
    static var coreRules: [String] { rejectDomains.map { "DOMAIN,\($0),REJECT" } }

    /// MitM host list of the built-in rewrite (QX hostname syntax: IP literals and IPv4 globs are allowed;
    /// NCHostMatcher / NativeRewriteEngine.glob match them against the destination of a no-SNI flow).
    static let mitmHostnames: [String] = [
        "newclient.map.baidu.com",
        "180.76.76.112",
        "180.76.76.200",
        "163.177.17.*",
    ]

    struct Rewrite {
        /// JS / QX regex (as it appears in the QX line).
        let pattern: String
        /// QX action (reject / reject-dict).
        let action: String
        /// Readable payload for the 已拦截 record (host + path, no user query values).
        let label: String
    }

    static let rewrites: [Rewrite] = [
        Rewrite(pattern: #"^https?:\/\/newclient\.map\.baidu\.com\/client\/phpui2\/\?(.*&)?qt=ads(&|$)"#,
                action: "reject-dict", label: "newclient.map.baidu.com/client/phpui2/?qt=ads"),
        Rewrite(pattern: #"^https?:\/\/newclient\.map\.baidu\.com\/client\/crossmarketing"#,
                action: "reject", label: "newclient.map.baidu.com/client/crossmarketing"),
        Rewrite(pattern: #"^https?:\/\/newclient\.map\.baidu\.com\/client\/usersystem\/home\/dynamic"#,
                action: "reject", label: "newclient.map.baidu.com/client/usersystem/home/dynamic"),
        Rewrite(pattern: #"^https?:\/\/newclient\.map\.baidu\.com\/client\/noticebar\/get"#,
                action: "reject-dict", label: "newclient.map.baidu.com/client/noticebar/get"),
        Rewrite(pattern: #"^https?:\/\/newclient\.map\.baidu\.com\/client\/phpui2?\/\?(.*&)?qt=(bar|hw)(&|$)"#,
                action: "reject-dict", label: "newclient.map.baidu.com/client/phpui2/?qt=bar|hw"),
    ]

    /// Source label of the built-in rules (the rewrite page / logs show it like a module name).
    static let sourceName = "百度地图去开屏（内置）"

    /// The built-in as a Quantumult X snippet — parsed by the same module parser as a user's QX rewrite, so it
    /// cannot drift from what a user would get by importing these lines themselves.
    static var moduleText: String {
        var lines = ["#!name=\(sourceName)", "[rewrite_local]"]
        lines += rewrites.map { "\($0.pattern) url \($0.action)" }
        lines += ["", "[mitm]", "hostname = " + mitmHostnames.joined(separator: ", ")]
        return lines.joined(separator: "\n") + "\n"
    }

    private static let compiled: [(NSRegularExpression, Rewrite)] = rewrites.compactMap { r in
        (try? NSRegularExpression(pattern: r.pattern, options: [])).map { ($0, r) }
    }

    /// The 已拦截 rule text for a rewrite REJECT on `url`, or nil when the URL is not one of the built-in
    /// targets (whoever's rule fired: the built-in or a user's module with the same line). Cheap host test
    /// first — this runs on every rewrite reject in the tunnel.
    static func blockRule(url: String) -> String? {
        guard url.contains("newclient.map.baidu.com") else { return nil }
        let range = NSRange(url.startIndex..., in: url)
        for (re, r) in compiled where re.firstMatch(in: url, options: [], range: range) != nil {
            return "URL-REWRITE,\(r.label),\(r.action.uppercased())"
        }
        return nil
    }
}
