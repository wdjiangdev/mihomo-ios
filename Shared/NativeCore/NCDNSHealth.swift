import Foundation
import UserNotifications

// feat/egern-2-21 (Egern 2.21.0 「DNS upstream health monitoring with failure notifications」):
// the tunnel probes every configured upstream DNS server on a slow timer and writes what it saw to
// <home>/dns-health.json; the app's DNS page reads that file (no live connection to the tunnel, no
// observed store) and a system notification goes out when an upstream stops answering.
//
// Kept apart from the DNS query path on purpose: the probes use their own NCDNSForwarder (same transport
// code as real queries, so a DoH / DoT / DoQ server is tested the way it is used), never the coalescing
// cache, never the fake-IP responder. Memory: a handful of small structs; one round every 60 s.

/// One upstream as the DNS page shows it.
struct NCDNSHealthEntry: Codable, Equatable, Identifiable {
    enum Status: String, Codable { case unknown, ok, slow, down }

    /// The server as configured (`https://1.1.1.1/dns-query`, `223.5.5.5`, `tls://dns.google`).
    var server: String
    /// Where it comes from in the DNS config: nameserver / fallback / default-nameserver.
    var role: String
    /// Transport: UDP / TCP / DoH / DoT / DoQ.
    var kind: String
    var status: Status = .unknown
    /// Last successful round trip.
    var latencyMs: Int?
    var consecutiveFailures: Int = 0
    var lastCheck: Date?
    var lastOK: Date?
    var lastError: String?

    var id: String { role + "|" + server }
}

struct NCDNSHealthFile: Codable, Equatable {
    var version = 1
    var updatedAt: Date?
    /// Seconds between rounds.
    var interval: Int = Int(NCDNSHealth.interval)
    /// The name each probe asks for (A record).
    var probeName: String = NCDNSHealth.probeName
    var entries: [NCDNSHealthEntry] = []

    var downEntries: [NCDNSHealthEntry] { entries.filter { $0.status == .down } }

    static func url(home: URL) -> URL { home.appendingPathComponent("dns-health.json") }

    static func load(home: URL) -> NCDNSHealthFile? {
        guard let d = try? Data(contentsOf: url(home: home)) else { return nil }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .secondsSince1970
        return try? dec.decode(NCDNSHealthFile.self, from: d)
    }

    func save(home: URL) {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .secondsSince1970
        enc.outputFormatting = [.sortedKeys]
        if let d = try? enc.encode(self) { try? d.write(to: Self.url(home: home), options: .atomic) }
    }
}

enum NCDNSHealth {
    /// One round per minute; the first one shortly after the core starts.
    static let interval: TimeInterval = 60
    static let firstDelay: TimeInterval = 5
    /// Per-probe deadline. A real query waits about as long before the next server is tried.
    static let timeout: TimeInterval = 5
    /// An upstream counts as down after this many failed rounds in a row (one lost UDP packet is not an outage).
    static let downAfter = 2
    /// A successful answer slower than this is shown as slow (amber), not as a failure.
    static let slowMs = 800
    /// At most this many upstreams are probed (a profile with a long nameserver-policy list stays cheap).
    static let maxTargets = 8
    /// A name every resolver answers; the probe asks for its A record.
    static let probeName = "www.apple.com"

    struct Target: Equatable {
        var server: String
        var role: String
        var upstream: NCDNSUpstream
    }

    /// Probe targets from the effective DNS config, in the order the page lists them: nameserver, fallback,
    /// default-nameserver. `system` / `dhcp://` entries are skipped (iOS resolves those; nothing to probe);
    /// the same server listed twice is probed once, under its first role.
    static func targets(nameservers: [String], fallback: [String], bootstrap: [String]) -> [Target] {
        var out: [Target] = []
        for (role, list) in [("nameserver", nameservers), ("fallback", fallback), ("default-nameserver", bootstrap)] {
            for raw in list {
                let server = raw.trimmingCharacters(in: .whitespaces)
                guard let up = NCDNSUpstream.parse(server) else { continue }
                if out.contains(where: { $0.upstream == up }) { continue }
                out.append(Target(server: server, role: role, upstream: up))
                if out.count >= maxTargets { return out }
            }
        }
        return out
    }

    static func kind(of u: NCDNSUpstream) -> String {
        switch u {
        case .udp: return "UDP"
        case .tcp: return "TCP"
        case .dot: return "DoT"
        case .doh: return "DoH"
        case .doq: return "DoQ"
        case .group: return "—"
        }
    }

    /// A standard recursive A query for `name` with the given transaction ID.
    static func query(id: UInt16, name: String = probeName) -> Data {
        var d = Data([UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in name.split(separator: ".") where !label.isEmpty {
            let bytes = Array(label.utf8.prefix(63))
            d.append(UInt8(bytes.count))
            d.append(contentsOf: bytes)
        }
        d.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01])
        return d
    }

    /// Whether `reply` is a usable answer to the probe: a response (QR) with RCODE NOERROR or NXDOMAIN — the server
    /// is working either way. SERVFAIL / REFUSED / a garbled packet count as a failure, with the reason.
    /// DoH replies carry ID 0 (RFC 8484), so the ID is checked only when it is non-zero on both sides.
    static func check(reply: Data?, id: UInt16) -> (ok: Bool, error: String?) {
        guard let r = reply else { return (false, "无响应") }
        guard r.count >= 12 else { return (false, "回复无效") }
        let rid = UInt16(r[0]) << 8 | UInt16(r[1])
        if rid != 0, id != 0, rid != id { return (false, "回复无效") }
        guard r[2] & 0x80 != 0 else { return (false, "回复无效") }
        switch r[3] & 0x0f {
        case 0, 3: return (true, nil)
        case 2: return (false, "SERVFAIL")
        case 5: return (false, "REFUSED")
        default: return (false, "RCODE \(r[3] & 0x0f)")
        }
    }
}

/// Status bookkeeping, pure (unit-tested): feed one probe result per upstream, get back the upstreams that just went
/// down or came back.
struct NCDNSHealthTracker {
    private(set) var entries: [NCDNSHealthEntry] = []

    /// Keep what is known about servers that are still configured (a reload with the same DNS keeps its history).
    mutating func configure(_ targets: [NCDNSHealth.Target]) {
        let old = Dictionary(entries.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        entries = targets.map { t in
            let fresh = NCDNSHealthEntry(server: t.server, role: t.role, kind: NCDNSHealth.kind(of: t.upstream))
            return old[fresh.id] ?? fresh
        }
    }

    enum Transition: Equatable { case down(String), recovered(String) }

    /// Records one probe; returns the transition it caused, if any.
    @discardableResult
    mutating func record(id: String, ok: Bool, latencyMs: Int?, error: String?, now: Date = Date()) -> Transition? {
        guard let i = entries.firstIndex(where: { $0.id == id }) else { return nil }
        var e = entries[i]
        let wasDown = e.status == .down
        e.lastCheck = now
        if ok {
            e.consecutiveFailures = 0
            e.latencyMs = latencyMs
            e.lastOK = now
            e.lastError = nil
            e.status = (latencyMs ?? 0) > NCDNSHealth.slowMs ? .slow : .ok
        } else {
            e.consecutiveFailures += 1
            e.lastError = error
            if e.consecutiveFailures >= NCDNSHealth.downAfter {
                e.status = .down
            } else if e.status == .unknown {
                // first failure of a never-seen server: not an outage yet, not ok either
                e.status = .unknown
            }
        }
        entries[i] = e
        if !wasDown && e.status == .down { return .down(e.server) }
        if wasDown && e.status != .down { return .recovered(e.server) }
        return nil
    }
}

/// The tunnel-side loop. Probes run on `queue`; `probe` sends one query to one upstream (the engine passes its
/// NCDNSForwarder), `notify` gets the servers that just went down. Start / stop are idempotent.
final class NCDNSHealthMonitor {
    typealias Probe = (_ query: Data, _ upstream: NCDNSUpstream, _ completion: @escaping (Data?) -> Void) -> Void

    private let queue: DispatchQueue
    private let home: URL
    private let probe: Probe
    private let notify: ([String]) -> Void
    private var tracker = NCDNSHealthTracker()
    private var targets: [NCDNSHealth.Target] = []
    private var timer: DispatchSourceTimer?
    private var generation = 0
    private var nextID: UInt16 = UInt16.random(in: 1...0xfff0)

    init(home: URL, queue: DispatchQueue = DispatchQueue(label: "nc.dns-health"),
         probe: @escaping Probe, notify: @escaping ([String]) -> Void = NCDNSHealthNotice.post) {
        self.home = home
        self.queue = queue
        self.probe = probe
        self.notify = notify
    }

    /// (Re)arm for these targets. Empty → stopped, and the file says there is nothing to check.
    func start(_ newTargets: [NCDNSHealth.Target]) {
        queue.async {
            self.generation += 1
            self.targets = newTargets
            self.tracker.configure(newTargets)
            self.timer?.cancel()
            self.timer = nil
            self.write()
            guard !newTargets.isEmpty else { return }
            let t = DispatchSource.makeTimerSource(queue: self.queue)
            t.schedule(deadline: .now() + NCDNSHealth.firstDelay, repeating: NCDNSHealth.interval, leeway: .seconds(5))
            let gen = self.generation
            t.setEventHandler { [weak self] in self?.round(gen) }
            t.resume()
            self.timer = t
        }
    }

    func stop() {
        queue.async {
            self.generation += 1
            self.timer?.cancel()
            self.timer = nil
        }
    }

    /// One round now (tests, and the first round after start through the timer).
    func runRound() { queue.async { self.round(self.generation) } }

    private func round(_ gen: Int) {
        guard gen == generation, !targets.isEmpty else { return }
        let group = DispatchGroup()
        var down: [String] = []
        for t in targets {
            let id = t.role + "|" + t.server
            nextID = nextID &+ 1
            if nextID == 0 { nextID = 1 }
            let qid = nextID
            let start = DispatchTime.now()
            var finished = false
            group.enter()
            let finish: (Data?, Bool) -> Void = { [weak self] reply, timedOut in
                guard let self else { return }
                self.queue.async {
                    guard !finished else { return }
                    finished = true
                    if gen == self.generation {
                        let ms = Int((DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000)
                        let (ok, err) = NCDNSHealth.check(reply: reply, id: qid)
                        if case .down(let s)? = self.tracker.record(id: id, ok: ok, latencyMs: ok ? ms : nil,
                                                                     error: timedOut ? "超时" : err) {
                            down.append(s)
                        }
                    }
                    group.leave()
                }
            }
            queue.asyncAfter(deadline: .now() + NCDNSHealth.timeout) { finish(nil, true) }
            probe(NCDNSHealth.query(id: qid), t.upstream) { reply in finish(reply, false) }
        }
        group.notify(queue: queue) { [weak self] in
            guard let self, gen == self.generation else { return }
            self.write()
            if !down.isEmpty { self.notify(down) }
        }
    }

    private func write() {
        var f = NCDNSHealthFile()
        f.updatedAt = Date()
        f.entries = tracker.entries
        f.save(home: home)
    }

    /// Snapshot for tests.
    func snapshot(_ done: @escaping ([NCDNSHealthEntry]) -> Void) { queue.async { done(self.tracker.entries) } }
}

/// The failure notification (更多 → 通知 → DNS 上游异常). Posted from the tunnel; text is catalog keys localized by
/// iOS at display time, like TunnelNotice (the extension carries no string catalog).
enum NCDNSHealthNotice {
    static func post(_ servers: [String]) {
        guard NotifyPrefs.allows(.dnsUpstream), let first = servers.first else { return }
        let content = UNMutableNotificationContent()
        content.title = NotifyText.loc("DNS 上游异常")
        content.body = servers.count == 1
            ? NotifyText.loc("「%@」连续 2 次没有正常回复，域名解析可能变慢或失败。", [first])
            : NotifyText.loc("%@ 等 %@ 个 DNS 上游连续 2 次没有正常回复。", [first, String(servers.count)])
        content.sound = .default
        content.threadIdentifier = "tern." + NotifyKind.dnsUpstream.rawValue
        let req = UNNotificationRequest(identifier: "tern.dnsUpstream." + UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { _ in }
    }
}
