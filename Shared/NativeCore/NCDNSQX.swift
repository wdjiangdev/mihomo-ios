import Foundation

// fix/qx-dns-records (user 2026-11-11 「dns解析的查询逻辑……按quanx的来」): the Quantumult X DNS
// behaviours the native core lacked. Sources (quoted in docs/qx-dns-records-audit.md):
//   - QX sample.conf [general]/[dns] comments: https://github.com/crossutility/Quantumult-X/blob/master/sample.conf
//   - QX TestFlight notes (builds 643, 694, 700, 708, 711): https://github.com/AssassinOperation/Profile/blob/master/QX_TestFlight_Update.log
//   - Lᴜᴄʏ's QX wiki, DNS & general: https://wiki.repcz.link/quantumultx/dns/ , https://wiki.repcz.link/quantumultx/general/
//
// Pure logic (plus a getaddrinfo-backed `system` exchange) so the unit tests drive every behaviour.

// MARK: - dns_reject_domain_behavior

/// How a name decided REJECT by a domain-class rule is answered at the DNS layer. QX sample.conf:
/// "By default ("loopback") when a domain rejected at DNS level the loopback IP response will be returned, you can
/// change this behavior by setting dns_reject_domain_behavior to "no-error-no-answer" or "nxdomain" or "none" …
/// it may take at most 10 seconds to take effect (TTL 10)." TF build 694: no-error-no-answer "包含 SOA 结果".
enum NCDNSRejectBehavior: String, Equatable {
    case loopback
    case noErrorNoAnswer = "no-error-no-answer"
    case nxdomain
    case none

    /// QX's default.
    static let `default` = NCDNSRejectBehavior.loopback
    /// TTL of every locally answered reject (QX: "TTL 10").
    static let ttl: UInt32 = 10
    /// SOA owner/mname of the no-error-no-answer authority record — also the marker the data plane's log
    /// classifier keys on (`isRejectReply`).
    static let soaName = "reject.tern.invalid"

    /// Lenient parse of a profile value; unknown / empty → nil (caller keeps the default).
    init?(raw: String?) {
        guard let r = raw?.trimmingCharacters(in: .whitespaces).lowercased(), !r.isEmpty else { return nil }
        switch r {
        case "loopback": self = .loopback
        case "no-error-no-answer", "noerror", "no-error", "nodata": self = .noErrorNoAnswer
        case "nxdomain": self = .nxdomain
        case "none", "off", "disabled": self = NCDNSRejectBehavior.none
        default: return nil
        }
    }

    /// The wire reply for an A / AAAA query of a rejected name; nil for `.none` (no DNS-level rejection: the caller
    /// takes its normal path and the connection layer's REJECT still applies).
    func reply(to query: NCDNSMessage) -> Data? {
        guard self != NCDNSRejectBehavior.none, let q = query.questions.first else { return nil }
        var resp = NCDNSMessage()
        resp.id = query.id
        resp.isResponse = true
        resp.opcode = query.opcode
        resp.recursionDesired = query.recursionDesired
        resp.recursionAvailable = true
        resp.questions = query.questions
        switch self {
        case .loopback:
            if q.type == NCDNSMessage.typeA {
                resp.answers = [NCDNSRecord(name: q.name, type: q.type, klass: q.klass, ttl: Self.ttl, rdata: Data([127, 0, 0, 1]))]
            } else if q.type == NCDNSMessage.typeAAAA {
                resp.answers = [NCDNSRecord(name: q.name, type: q.type, klass: q.klass, ttl: Self.ttl,
                                            rdata: Data([UInt8](repeating: 0, count: 15) + [1]))]
            }
            return resp.serialized()
        case .nxdomain:
            resp.rcode = 3
            return resp.serialized()
        case .noErrorNoAnswer:
            return Self.withSOA(resp.serialized(), zone: q.name)
        case .none:
            return nil
        }
    }

    /// Append one SOA record to the authority section (NSCOUNT = 1) of a serialized answer-less reply.
    static func withSOA(_ wire: Data, zone: String) -> Data {
        var out = wire
        guard out.count >= 12 else { return out }
        out[out.startIndex + 8] = 0
        out[out.startIndex + 9] = 1
        func put16(_ v: UInt16) { out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xff)) }
        func put32(_ v: UInt32) { put16(UInt16(v >> 16)); put16(UInt16(v & 0xffff)) }
        out.append(NCDNSMessage.encodeName(zone))
        put16(6) // SOA
        put16(NCDNSMessage.classIN)
        put32(ttl)
        var rdata = Data()
        rdata.append(NCDNSMessage.encodeName(soaName))           // MNAME (the marker)
        rdata.append(NCDNSMessage.encodeName("hostmaster." + soaName)) // RNAME
        for v in [1, 3600, 600, 86400, ttl] as [UInt32] {             // SERIAL REFRESH RETRY EXPIRE MINIMUM
            rdata.append(contentsOf: [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
        }
        put16(UInt16(rdata.count))
        out.append(rdata)
        return out
    }

    /// Whether a locally answered reply is a DNS-layer reject (for the [DNS] log line): NXDOMAIN (the hosts path
    /// never sets an rcode), loopback answers with the reject TTL (hosts entries answer TTL 60), or the marked SOA.
    static func isRejectReply(_ wire: Data) -> Bool {
        guard let msg = NCDNSMessage.parse(wire) else { return false }
        if msg.rcode == 3 { return true }
        if msg.rcode == 0, !msg.answers.isEmpty, msg.answers.allSatisfy({ $0.ttl == ttl }) {
            let addrs = msg.addressAnswers.map { $0.0 }
            if addrs.count == msg.answers.count,
               addrs.allSatisfy({ $0 == NCIP("127.0.0.1") || $0 == NCIP("::1") }) { return true }
        }
        if msg.rcode == 0, msg.answers.isEmpty, wire.count >= 12, wire[wire.startIndex + 9] == 1 {
            let marker = NCDNSMessage.encodeName(soaName)
            return wire.range(of: marker) != nil
        }
        return false
    }

    /// Short text for the [DNS] reject log line ("127.0.0.1", "NXDOMAIN", "NOERROR/NODATA").
    var logDetail: String {
        switch self {
        case .loopback: return "loopback 127.0.0.1 / ::1"
        case .nxdomain: return "NXDOMAIN"
        case .noErrorNoAnswer: return "NOERROR no answer"
        case .none: return "none"
        }
    }
}

// MARK: - circumvent-ipv4-answer / circumvent-ipv6-answer

/// QX sample.conf: "If the A or AAAA result(IP) from upstream is matched by this field, the result will be ignored and
/// marked as failed. If multiple queries sent to different upstream DNS servers, and the first responded upstream
/// result is matched by this field, Quantumult X Tunnel DNS module will wait for other upstream servers' results.
/// The ? and * can be used." TF build 708 / the wiki add: when the first answer holds at least one record NOT matched,
/// the others are not waited for and the valid result is every record not matched; when every upstream's every
/// record matches, the query fails.
struct NCDNSCircumvent: Equatable {
    var v4: [String] = []
    var v6: [String] = []

    var isEmpty: Bool { v4.isEmpty && v6.isEmpty }

    /// Comma-separated string or array of strings (profile values come in both shapes).
    static func patterns(_ v: NCJSONValue?) -> [String] {
        guard let v else { return [] }
        var raw: [String] = []
        if let s = v.string { raw = s.split(separator: ",").map(String.init) }
        else if let a = v.array { raw = a.compactMap { $0.string }.flatMap { $0.split(separator: ",").map(String.init) } }
        return raw.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
    }

    func matches(_ ip: NCIP) -> Bool {
        let list = ip.isV4 ? v4 : v6
        guard !list.isEmpty else { return false }
        let s = ip.string.lowercased()
        return list.contains { p in
            if !p.contains("*") && !p.contains("?") {
                // exact: compare parsed addresses so "::" == "0:0::0"
                if let pip = NCIP(p) { return pip == ip }
                return p == s
            }
            return NCRuleMatcher.globMatch(pattern: p, s)
        }
    }

    enum Verdict: Equatable {
        /// Nothing matched: deliver as is.
        case pass
        /// Some address records matched, some did not: deliver this rewritten reply (matched records removed).
        case filtered(Data)
        /// Every address record matched: this upstream's answer counts as a failure.
        case circumvented
    }

    func judge(_ wire: Data) -> Verdict {
        guard !isEmpty, let msg = NCDNSMessage.parse(wire) else { return .pass }
        let addrs = msg.addressAnswers
        guard !addrs.isEmpty else { return .pass }
        let hit = addrs.filter { matches($0.0) }
        if hit.isEmpty { return .pass }
        if hit.count == addrs.count { return .circumvented }
        var out = msg
        out.answers = msg.answers.filter { r in
            guard r.type == NCDNSMessage.typeA || r.type == NCDNSMessage.typeAAAA else { return true }
            let ip: NCIP? = r.rdata.count == 4 || r.rdata.count == 16 ? NCIP(bytes: [UInt8](r.rdata)) : nil
            return ip.map { !matches($0) } ?? true
        }
        return .filtered(out.serialized())
    }
}

// MARK: - system DNS ("system" nameserver)

/// QX sample.conf: "The DNS servers fetched from current network(system) will always be used for better performance
/// (you can disable this feature by using "no-system" …)"; `server=/example0.com/system` sends one domain to them.
/// The packet tunnel's own lookups do not go through its tunnel, so the system resolver (getaddrinfo) asks the
/// current network's DNS — the same path the tunnel already uses for node host names. Only A / AAAA can be asked
/// this way (other types get no answer and the race takes the other servers'); TTLs are not exposed by getaddrinfo,
/// so answers carry `ttl`.
enum NCSystemDNS {
    static let ttl: UInt32 = 60
    /// getaddrinfo cannot be cancelled: cap the threads a slow network can pin; over the cap → no answer at once.
    static let maxInFlight = 4
    private static let lock = NSLock()
    private static var inFlight = 0
    private static var loopLogged = false
    private static let queue = DispatchQueue(label: "nc.dns.system", qos: .userInitiated, attributes: .concurrent)

    /// Fake-IP ranges of the running config: an answer inside one means the lookup came back through our own tunnel
    /// (the system resolver is the tunnel's DNS in that case) and is discarded. Set by the engine on load.
    static var fakeRanges: [NCCIDR] {
        get { lock.lock(); defer { lock.unlock() }; return _fakeRanges }
        set { lock.lock(); _fakeRanges = newValue; lock.unlock() }
    }
    private static var _fakeRanges: [NCCIDR] = [NCCIDR("198.18.0.0/15")!]

    /// Test seam: replaces getaddrinfo (name, wantV4) -> addresses or nil (failure).
    static var lookupOverride: ((String, Bool) -> [NCIP]?)?

    /// One query through the system resolver; completion gets a wire reply or nil (no answer / not askable).
    static func exchange(_ queryData: Data, completion: @escaping (Data?) -> Void) {
        guard let query = NCDNSMessage.parse(queryData), query.questions.count == 1 else { completion(nil); return }
        let q = query.questions[0]
        guard q.klass == NCDNSMessage.classIN, q.type == NCDNSMessage.typeA || q.type == NCDNSMessage.typeAAAA,
              !q.name.isEmpty else { completion(nil); return }
        lock.lock()
        guard inFlight < maxInFlight else { lock.unlock(); completion(nil); return }
        inFlight += 1
        lock.unlock()
        queue.async {
            let wantV4 = q.type == NCDNSMessage.typeA
            let ips = (NCSystemDNS.lookupOverride ?? NCSystemDNS.lookup)(q.name, wantV4)
            NCSystemDNS.lock.lock(); NCSystemDNS.inFlight -= 1; NCSystemDNS.lock.unlock()
            completion(NCSystemDNS.reply(query: query, ips: ips))
        }
    }

    /// Build the reply for `ips` (nil = lookup failed → no answer; [] = NOERROR / no data). Answers inside a fake
    /// range are dropped as a tunnel loop.
    static func reply(query: NCDNSMessage, ips: [NCIP]?) -> Data? {
        guard let ips, let q = query.questions.first else { return nil }
        let ranges = fakeRanges
        if ips.contains(where: { ip in ranges.contains { $0.contains(ip) } }) {
            lock.lock()
            let first = !loopLogged
            loopLogged = true
            lock.unlock()
            if first { StartupLog.write("DNS: system resolver answered from the tunnel's fake-IP range — system DNS ignored for such answers") }
            return nil
        }
        var resp = NCDNSMessage()
        resp.id = query.id
        resp.isResponse = true
        resp.opcode = query.opcode
        resp.recursionDesired = query.recursionDesired
        resp.recursionAvailable = true
        resp.questions = query.questions
        let wantV4 = q.type == NCDNSMessage.typeA
        var seen: [NCIP] = []
        for ip in ips where ip.isV4 == wantV4 && !seen.contains(ip) { seen.append(ip) }
        resp.answers = seen.prefix(16).map { NCDNSRecord(name: q.name, type: q.type, klass: q.klass, ttl: ttl, rdata: Data($0.bytes)) }
        return resp.serialized()
    }

    private static func lookup(_ name: String, _ wantV4: Bool) -> [NCIP]? {
        var hints = addrinfo()
        hints.ai_family = wantV4 ? AF_INET : AF_INET6
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(name, nil, &hints, &res)
        defer { if let res { freeaddrinfo(res) } }
        if rc == EAI_NONAME { return [] }
        guard rc == 0 else { return nil }
        var out: [NCIP] = []
        var p = res
        while let ai = p {
            if let sa = ai.pointee.ai_addr {
                if ai.pointee.ai_family == AF_INET {
                    let a = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
                    let b = withUnsafeBytes(of: a) { [UInt8]($0) }
                    if let ip = NCIP(bytes: b) { out.append(ip) }
                } else if ai.pointee.ai_family == AF_INET6 {
                    let a = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                    let b = withUnsafeBytes(of: a) { [UInt8]($0) }
                    if let ip = NCIP(bytes: b) { out.append(ip) }
                }
            }
            p = ai.pointee.ai_next
        }
        return out
    }
}

// MARK: - no-ipv6

extension NCDNSPolicy {
    /// QX `no-ipv6`: an AAAA question is answered NOERROR with no data (any other question → nil, keep going).
    static func noIPv6Reply(queryData: Data) -> Data? {
        guard let query = NCDNSMessage.parse(queryData), query.questions.count == 1,
              query.questions[0].type == NCDNSMessage.typeAAAA, query.questions[0].klass == NCDNSMessage.classIN else { return nil }
        var resp = NCDNSMessage()
        resp.id = query.id
        resp.isResponse = true
        resp.opcode = query.opcode
        resp.recursionDesired = query.recursionDesired
        resp.recursionAvailable = true
        resp.questions = query.questions
        return resp.serialized()
    }
}

// MARK: - rule-matching resolve cache (QX: expired results are still used while a new query runs)

/// QX TF build 643: "一直以来 Quantumult X 都会“尽可能”的使用给所有 DNS 缓存打上过期标识的机制而不是主动清空所有缓存的机制，
/// 在命中过期结果时会尝试使用过期结果进行连接并同时触发新的 DNS 查询" (also on a network change). The engine's rule-matching
/// lookup cache follows that: a fresh entry answers; an expired entry with an address answers at once AND starts a
/// refresh; a network change marks everything expired instead of clearing. Bounded (512 names) and the stale use is
/// capped at `staleWindow` (sources are silent on a limit; Tern's choice).
struct NCResolveCache {
    struct Entry { var ip: NCIP?; var expires: Date }
    enum Lookup: Equatable { case fresh(NCIP?), stale(NCIP), miss }

    static let capacity = 512
    static let staleWindow: TimeInterval = 3600
    static let failureTTL: TimeInterval = 30
    /// Answer TTL clamp (seconds): honour short TTLs (QX does) but not below 10 s, keep at most an hour.
    static func clampTTL(_ ttl: Double) -> Double { min(max(ttl, 10), 3600) }

    private(set) var entries: [String: Entry] = [:]

    var count: Int { entries.count }

    func lookup(_ host: String, now: Date = Date()) -> Lookup {
        guard let e = entries[host] else { return .miss }
        if e.expires > now { return .fresh(e.ip) }
        if let ip = e.ip, now.timeIntervalSince(e.expires) < Self.staleWindow { return .stale(ip) }
        return .miss
    }

    /// Store a lookup result. A failure never overwrites a known address (it stays usable as a stale answer until
    /// the stale window runs out); it is cached as a failure only when nothing better is known.
    mutating func store(_ host: String, ip: NCIP?, ttl: Double, now: Date = Date()) {
        if ip == nil, let old = entries[host], old.ip != nil {
            entries[host] = Entry(ip: old.ip, expires: min(old.expires, now))
            return
        }
        if entries[host] == nil, entries.count >= Self.capacity {
            // Drop what can no longer answer at all, then the soonest-expired eighth.
            entries = entries.filter { $0.value.ip != nil && now.timeIntervalSince($0.value.expires) < Self.staleWindow }
            if entries.count >= Self.capacity {
                let victims = entries.sorted { $0.value.expires < $1.value.expires }.prefix(Self.capacity / 8).map(\.key)
                for k in victims { entries.removeValue(forKey: k) }
            }
        }
        entries[host] = Entry(ip: ip, expires: now.addingTimeInterval(ip == nil ? Self.failureTTL : Self.clampTTL(ttl)))
    }

    /// Network change (QX): everything expires now, nothing is dropped.
    mutating func markAllExpired(now: Date = Date()) {
        for k in Array(entries.keys) { entries[k]?.expires = min(entries[k]!.expires, now) }
    }

    mutating func removeAll() { entries.removeAll() }
}
