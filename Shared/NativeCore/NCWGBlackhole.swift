import Foundation

/// fix/wg-endpoint-blackhole: the recreate decision for a WireGuard peer's endpoint connection.
///
/// A UDP NWConnection whose route silently dies (the interface it was bound or routed through went
/// away, a NAT mapping expired into a black hole, …) never reports an error: it stays `.ready` and
/// sends are fire-and-forget, so a handshake attempt retransmits into the void until it gives up —
/// invisibly in every environment except the real packet-tunnel extension, where the core's sockets
/// interact with the tunnel's own routes and interface bindings. When an attempt has really tried
/// (≥ 4 initiations, one per rekey timeout), has heard absolutely nothing back, and has been running
/// ≥ 20 s, the connection itself is the prime suspect: drop it and let the next retransmit open a
/// fresh one. Rate-limited to one recreate per 20 s so a genuinely unreachable endpoint cannot churn.
enum NCWGBlackhole {
    static func shouldRecreate(sentOnAttempt: Int, receivedOnAttempt: Int,
                               attemptAge: TimeInterval, sinceLastRecreate: TimeInterval) -> Bool {
        sentOnAttempt >= 4 && receivedOnAttempt == 0 && attemptAge >= 20 && sinceLastRecreate >= 20
    }
}
