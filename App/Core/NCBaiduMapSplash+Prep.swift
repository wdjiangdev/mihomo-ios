import Foundation

/// fix/baidumap-splash: how NativeRuntimePrep folds the built-in Baidu Maps splash protection (NCBaiduMapSplash)
/// into a generation. Kept apart from the prep body so each decision is a pure, unit-tested function.
extension NCBaiduMapSplash {
    /// Whether the HTTPS layer (MitM rewrite) joins this generation. All of:
    /// - the 「HTTPDNS 守卫」 switch is on (`guardOn`, CoreOverrides.httpdnsGuard) and the prep is not in safe mode;
    /// - the user's 重写 switch is on (`cfg.anyOn`) — the built-in rides along like an enabled module, it never
    ///   turns the rewrite engine on by itself;
    /// - the user's MitM switch is on (`cfg.mitm`) — Tern never starts decrypting on its own;
    /// - the Tern CA is installed AND trusted (`caTrusted`) — otherwise MitM-ing newclient.map.baidu.com would
    ///   break every Baidu Maps API call, so the protection stays on the DNS / IP layer only.
    static func httpsLayerEligible(guardOn: Bool, safeMode: Bool, cfg: NCEngineConfig?, caTrusted: Bool) -> Bool {
        guard guardOn, !safeMode, let cfg, cfg.anyOn, cfg.mitm, caTrusted else { return false }
        return true
    }

    /// The built-in snippet parsed by the regular module parser (QX dialect).
    static func parsedModule() -> NCEngineRuleset {
        let sub = NCEngineRuleset()
        sub.parseText(moduleText, source: sourceName, args: [:])
        return sub
    }

    /// Merge the built-in rewrite rules + MitM hosts into a built rule set, like one more enabled module loaded
    /// LAST: URL rewrites are first-match, so a user's own rule for the same URL keeps precedence.
    static func merge(into rs: NCEngineRuleset) {
        let sub = parsedModule()
        rs.rules.append(contentsOf: sub.rules)
        rs.hostnames = NCMitmBuild.dedupe(rs.hostnames + sub.hostnames)
        for e in sub.errors { rs.errors.append(sourceName + "：" + e) }
    }

    /// Prepend the DNS-layer REJECTs to the runtime rules (before the profile's own rules, so a broad
    /// `DOMAIN-SUFFIX,baidu.com,DIRECT` in the profile cannot shadow them). Idempotent.
    static func prependCoreRules(_ raw: inout [String: NCJSONValue]) {
        let existing = raw.list("rules")
        let have = Set(existing.compactMap { v -> String? in if case .string(let s) = v { return s }; return nil })
        let add = coreRules.filter { !have.contains($0) }
        guard !add.isEmpty else { return }
        raw["rules"] = .array(add.map { NCJSONValue.string($0) } + existing)
    }
}
