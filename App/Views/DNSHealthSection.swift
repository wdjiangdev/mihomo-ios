import SwiftUI

// feat/egern-2-21 (Egern 2.21.0 「DNS upstream health monitoring」): 上游状态 on the DNS page. The tunnel's
// NCDNSHealthMonitor writes <home>/dns-health.json once a minute; this section reads that file off the main thread
// every 10 s while it is on screen. It observes no store (the DNS page is a root-reachable list) and talks to no one.

struct DNSHealthSection: View {
    @State private var file: NCDNSHealthFile?
    @State private var loaded = false

    /// UI tests (-UITestSeed -UITestDNSHealth): a fixed file with one healthy, one slow and one down upstream.
    static var demo: Bool { UITestSeed.enabled && UITestSeed.args.contains("-UITestDNSHealth") }
    static let refresh: UInt64 = 10_000_000_000

    var body: some View {
        Section {
            if let f = file, !f.entries.isEmpty {
                let down = f.downEntries
                if !down.isEmpty {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.white)
                        Text(down.count == 1
                             ? String(localized: "「\(down[0].server)」连续 2 次没有正常回复，域名解析可能变慢或失败。")
                             : String(localized: "\(down.count) 个 DNS 上游连续 2 次没有正常回复。"))
                            .font(.footnote.weight(.semibold)).foregroundStyle(.white)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.vertical, 2)
                    .listRowBackground(Theme.bad)
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("dns.health.banner")
                }
                ForEach(f.entries) { e in
                    DNSHealthRow(e: e)
                }
            } else {
                Text(LocalizedStringKey(loaded ? "连接 VPN 后每 60 秒检测一次。" : "读取中…"))
                    .font(.footnote).foregroundStyle(.secondary)
                    .accessibilityIdentifier("dns.health.none")
            }
        } header: {
            Text("上游状态")
        } footer: {
            if let f = file, let at = f.updatedAt {
                Text("每 \(f.interval) 秒向每个上游查询一次 \(f.probeName)，连续 2 次失败算异常。上次检测：\(at.formatted(date: .omitted, time: .standard))")
            }
        }
        .listRowBackground(Theme.card)
        .task {
            while !Task.isCancelled {
                let f: NCDNSHealthFile?
                if Self.demo {
                    f = Self.demoFile()
                } else {
                    let home = AppShared.homeURL
                    f = await Task.detached(priority: .utility) { NCDNSHealthFile.load(home: home) }.value
                }
                if f != file { file = f }
                loaded = true
                try? await Task.sleep(nanoseconds: Self.refresh)
            }
        }
    }

    static func demoFile() -> NCDNSHealthFile {
        let now = Date()
        var f = NCDNSHealthFile()
        f.updatedAt = now
        f.entries = [
            NCDNSHealthEntry(server: "https://223.5.5.5/dns-query", role: "nameserver", kind: "DoH", status: .ok, latencyMs: 23,
                             consecutiveFailures: 0, lastCheck: now, lastOK: now),
            NCDNSHealthEntry(server: "tls://dns.google", role: "fallback", kind: "DoT", status: .slow, latencyMs: 912,
                             consecutiveFailures: 0, lastCheck: now, lastOK: now),
            NCDNSHealthEntry(server: "192.0.2.53", role: "default-nameserver", kind: "UDP", status: .down,
                             consecutiveFailures: 3, lastCheck: now, lastOK: now.addingTimeInterval(-600), lastError: "超时"),
        ]
        return f
    }
}

/// Plain title (the server) with the role and transport as subtitle; status and latency on the right.
struct DNSHealthRow: View {
    let e: NCDNSHealthEntry

    var roleText: String {
        switch e.role {
        case "nameserver": return String(localized: "主 DNS")
        case "fallback": return String(localized: "回落 DNS")
        case "default-nameserver": return String(localized: "引导 DNS")
        default: return e.role
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(color).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: e.server).font(.callout).lineLimit(1).truncationMode(.middle)
                Text(verbatim: "\(roleText) · \(e.kind)").font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 2) {
                Text(statusText).font(.callout.monospacedDigit()).foregroundStyle(color)
                if e.status == .down, let err = e.lastError, !err.isEmpty {
                    Text(LocalizedStringKey(err)).font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("dns.health.row.\(e.role)")
    }

    var color: Color {
        switch e.status {
        case .ok: return Theme.good
        case .slow: return Theme.warn
        case .down: return Theme.bad
        case .unknown: return .secondary
        }
    }

    var statusText: String {
        switch e.status {
        case .ok: return "\(e.latencyMs ?? 0) ms"
        case .slow: return String(localized: "较慢 \(e.latencyMs ?? 0) ms")
        case .down: return String(localized: "异常")
        case .unknown: return e.consecutiveFailures > 0 ? String(localized: "未回复") : String(localized: "等待检测")
        }
    }
}
