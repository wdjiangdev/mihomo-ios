import Foundation

/// fix/qx-dns-records: the connection session's counters on disk (rule hits, policy / host bytes, totals, minute /
/// hour speed rows, reject aggregation counters), so a tunnel that iOS relaunched after jetsam / a crash continues
/// the session instead of zeroing it (NCStatsRecorder.enableSessionArchive(resume:)). Plain Codable; rows are
/// strings / Int64 arrays so the file stays readable and decoding never depends on the recorder's private types.
/// Bounded by the recorder's own caps (policyCap / hostCap / ruleCap / minCap / hourCap): a few hundred KB at most.
struct NCStatsSnapshot: Codable, Equatable {
    /// Bumped when the shape changes; a snapshot of another version is ignored (new session).
    static let currentVersion = 1

    var version: Int = NCStatsSnapshot.currentVersion
    var session: Int64
    var since: Int64
    var total: Int
    var seq: Int64
    /// [name, up, down]
    var policies: [[String]]
    /// [name, up, down]
    var hosts: [[String]]
    /// [rule, policy, hits]
    var rules: [[String]]
    var rejectStored: Int
    var rejectedMerged: Int
    var rejectedOverflow: Int
    /// NCStatsRecorder.Ring rows (width 6).
    var minutes: [[Int64]]
    var hours: [[Int64]]
    /// Unix seconds of the save.
    var savedAt: Double

    init(session: Int64, since: Int64, total: Int, seq: Int64, policies: [[String]], hosts: [[String]],
         rules: [[String]], rejectStored: Int, rejectedMerged: Int, rejectedOverflow: Int,
         minutes: [[Int64]], hours: [[Int64]], savedAt: Double) {
        self.session = session
        self.since = since
        self.total = total
        self.seq = seq
        self.policies = policies
        self.hosts = hosts
        self.rules = rules
        self.rejectStored = rejectStored
        self.rejectedMerged = rejectedMerged
        self.rejectedOverflow = rejectedOverflow
        self.minutes = minutes
        self.hours = hours
        self.savedAt = savedAt
    }

    /// The saved snapshot, or nil (missing, unreadable, other version, or larger than `maxBytes`).
    static let maxBytes = 4 * 1024 * 1024
    static func load(_ url: URL) -> NCStatsSnapshot? {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = (attrs[.size] as? NSNumber)?.intValue, size > 0, size <= maxBytes,
              let data = try? Data(contentsOf: url),
              let snap = try? JSONDecoder().decode(NCStatsSnapshot.self, from: data),
              snap.version == currentVersion else { return nil }
        return snap
    }

    /// Atomic replace (temp file + rename), creating the directory when needed. Returns false on failure.
    @discardableResult
    func save(_ url: URL) -> Bool {
        guard let data = try? JSONEncoder().encode(self) else { return false }
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        return (try? data.write(to: url, options: .atomic)) != nil
    }
}
