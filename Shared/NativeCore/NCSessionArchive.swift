import Foundation

/// feat/session-records (user 2026-10-29: 「连接/拦截记录、DNS 解析记录，单次连接一直保留待查，
/// 重连后才会归0」): an append-only JSONL archive for ONE connection session. The in-memory
/// rings (NCStatsRecorder's 300 closed connections, NativeLogRing's 400 lines) rotate within
/// minutes on a busy session, which made session totals outlive their own records (a rule's
/// hit count stayed while every connection behind it had rotated out of the drill-in list).
/// The archive keeps every record on disk for the whole session instead; it is truncated
/// only when a new session starts (fresh tunnel process / provider start, or the user's
/// 清零 reset) — reconnecting is what zeroes the records, exactly as specified.
///
/// One JSON object per line; every object carries its `seq` (Int64). An in-memory offset
/// index makes `read(afterSeq:)` a seek, not a scan. A hard size fuse stops appending on a
/// pathological session rather than filling the disk; the live rings still serve recent
/// records in that case.
final class NCSessionArchive {
    private let url: URL
    private let lock = NSLock()
    private var handle: FileHandle?
    private var offsets: [Int64] = [] // byte offset of each line, in append order
    private var endOffset: Int64 = 0
    private var lastSeq: Int64 = 0
    /// Size fuse per session file. fix/qx-dns-records: 256 MB → 32 MB (bounded, and a resumed session rebuilds its
    /// line index from the file — 32 MB is ~200k records / ~1.7 MB of index at most).
    static let fuseBytes: Int64 = 32 * 1024 * 1024
    /// fix/qx-dns-records: QX keeps the records of the last few VPN connections (traffic statistics: "最近几次 VPN 连接",
    /// TF 741; script records: a new record per VPN start, older ones kept, TF 502/506). A new session moves the
    /// previous session's file to `<name>.1.jsonl` (and `.1` to `.2`) instead of deleting it.
    static let keptPrevious = 2
    /// fix/qx-dns-records: `readAll` (the DNS history endpoint) returns at most the newest this many records, so one
    /// long session cannot build a response bigger than the tunnel can hold.
    static let readAllCap = 10_000
    /// fix/qx-dns-records: set by the tunnel at start before the archives open — true when the previous tunnel
    /// process ended without stopTunnel (jetsam / crash, relaunched by iOS) and its session continues.
    static var resumeOnOpen = false

    /// Creating an archive starts a fresh session (the previous session's file is rotated to `.1`), unless `resume`
    /// is set and the file exists: then the session continues — the index is rebuilt and appends go on after it.
    init(url: URL, resume: Bool = false) {
        self.url = url
        if resume, FileManager.default.fileExists(atPath: url.path) {
            reopen()
        } else {
            Self.rotate(url)
            reset()
        }
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return offsets.count }
    var newestSeq: Int64 { lock.lock(); defer { lock.unlock() }; return lastSeq }

    /// `<dir>/<name>.<n>.<ext>` — the n-th previous session's file (n ≥ 1).
    static func previousURL(_ url: URL, _ n: Int) -> URL {
        let ext = url.pathExtension
        let base = url.deletingPathExtension().lastPathComponent
        return url.deletingLastPathComponent().appendingPathComponent("\(base).\(n)" + (ext.isEmpty ? "" : ".\(ext)"))
    }

    /// Shift previous sessions down one slot (dropping the oldest) and move a non-empty current file to `.1`.
    static func rotate(_ url: URL) {
        let fm = FileManager.default
        guard let size = (try? fm.attributesOfItem(atPath: url.path))?[.size] as? NSNumber, size.int64Value > 0 else { return }
        guard keptPrevious > 0 else { try? fm.removeItem(at: url); return }
        try? fm.removeItem(at: previousURL(url, keptPrevious))
        if keptPrevious > 1 {
            for n in stride(from: keptPrevious - 1, through: 1, by: -1) {
                let from = previousURL(url, n)
                if fm.fileExists(atPath: from.path) { try? fm.moveItem(at: from, to: previousURL(url, n + 1)) }
            }
        }
        try? fm.moveItem(at: url, to: previousURL(url, 1))
    }

    /// Start over (new session / user reset): truncate the file and the index.
    func reset() {
        lock.lock(); defer { lock.unlock() }
        handle?.closeFile()
        handle = nil
        offsets = []
        endOffset = 0
        lastSeq = 0
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: url.path, contents: nil)
        handle = try? FileHandle(forWritingTo: url)
        handle?.seekToEndOfFile()
    }

    /// Resume: rebuild the line index by streaming the file (64 KB at a time, never the whole file in memory), drop
    /// a torn last line (the process died mid-write), take the newest seq from the last complete line.
    private func reopen() {
        lock.lock(); defer { lock.unlock() }
        offsets = []
        endOffset = 0
        lastSeq = 0
        if let r = try? FileHandle(forReadingFrom: url) {
            var lineStart: Int64 = 0
            var pos: Int64 = 0
            while true {
                let chunk = r.readData(ofLength: 64 * 1024)
                if chunk.isEmpty { break }
                for (i, b) in chunk.enumerated() where b == 0x0A {
                    let end = pos + Int64(i) + 1
                    if end - lineStart > 1 { offsets.append(lineStart) }
                    lineStart = end
                }
                pos += Int64(chunk.count)
            }
            endOffset = lineStart // anything after the last newline is a torn record: overwritten by the next append
            if let last = offsets.last {
                r.seek(toFileOffset: UInt64(last))
                let data = r.readData(ofLength: Int(endOffset - last))
                if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    lastSeq = (obj["seq"] as? NSNumber)?.int64Value ?? 0
                }
            }
            r.closeFile()
        }
        handle = try? FileHandle(forWritingTo: url)
        handle?.truncateFile(atOffset: UInt64(endOffset))
        handle?.seek(toFileOffset: UInt64(endOffset))
    }

    /// Append one record. The record's `seq` must be non-decreasing across appends.
    func append(_ dict: [String: Any]) {
        guard let seq = (dict["seq"] as? NSNumber)?.int64Value,
              let data = try? JSONSerialization.data(withJSONObject: dict) else { return }
        lock.lock(); defer { lock.unlock() }
        guard let h = handle, endOffset < Self.fuseBytes else { return }
        var line = data
        line.append(0x0A)
        offsets.append(endOffset)
        h.write(line)
        endOffset += Int64(line.count)
        lastSeq = seq
    }

    /// Records with `seq > afterSeq`, NEWEST first, at most `limit`.
    func read(afterSeq: Int64, limit: Int) -> [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        guard limit > 0, let h = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { h.closeFile() }
        var out: [[String: Any]] = []
        var i = offsets.count - 1
        while i >= 0, out.count < limit {
            let start = offsets[i]
            let end = (i + 1 < offsets.count) ? offsets[i + 1] : endOffset
            guard end > start else { i -= 1; continue }
            h.seek(toFileOffset: UInt64(start))
            let data = h.readData(ofLength: Int(end - start))
            if let obj = try? JSONSerialization.jsonObject(with: data), let dict = obj as? [String: Any] {
                let seq = (dict["seq"] as? NSNumber)?.int64Value ?? 0
                if seq <= afterSeq { break } // lines are seq-ordered: everything older is out too
                out.append(dict)
            }
            i -= 1
        }
        return out
    }

    /// The session's records, OLDEST first (session history endpoints) — the newest `limit` of them.
    func readAll(limit: Int = NCSessionArchive.readAllCap) -> [[String: Any]] {
        read(afterSeq: 0, limit: limit).reversed()
    }
}
