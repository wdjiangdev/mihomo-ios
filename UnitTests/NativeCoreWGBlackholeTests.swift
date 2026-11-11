import Network
import XCTest
@testable import Tern

/// fix/wg-endpoint-blackhole: the two halves of the WireGuard endpoint fix —
/// NCWGBlackhole.shouldRecreate (the pure recreate decision NCWGPeer.tick consults) and
/// NCOutboundBinding's pinInterface: false shaping (a long-lived connection must not be pinned
/// to a creation-time interface snapshot, but must still be kept off the tunnel).
final class NativeCoreWGBlackholeTests: XCTestCase {

    override func tearDown() {
        NCOutboundBinding.start(includeAllNetworks: false) // restore the shared static state
        super.tearDown()
    }

    // MARK: - Recreate decision

    func testRecreateWhenAttemptBlackholed() {
        XCTAssertTrue(NCWGBlackhole.shouldRecreate(sentOnAttempt: 4, receivedOnAttempt: 0,
                                                   attemptAge: 20, sinceLastRecreate: .greatestFiniteMagnitude))
        XCTAssertTrue(NCWGBlackhole.shouldRecreate(sentOnAttempt: 9, receivedOnAttempt: 0,
                                                   attemptAge: 85, sinceLastRecreate: 20))
    }

    func testNoRecreateBelowThresholds() {
        // Too few initiations: the attempt has not really tried on this connection yet.
        XCTAssertFalse(NCWGBlackhole.shouldRecreate(sentOnAttempt: 3, receivedOnAttempt: 0,
                                                    attemptAge: 60, sinceLastRecreate: .greatestFiniteMagnitude))
        // Something came back: the route works, the peer is at fault — recreating cannot help.
        XCTAssertFalse(NCWGBlackhole.shouldRecreate(sentOnAttempt: 6, receivedOnAttempt: 1,
                                                    attemptAge: 60, sinceLastRecreate: .greatestFiniteMagnitude))
        // Too young: still inside the first retransmit cycles.
        XCTAssertFalse(NCWGBlackhole.shouldRecreate(sentOnAttempt: 4, receivedOnAttempt: 0,
                                                    attemptAge: 19, sinceLastRecreate: .greatestFiniteMagnitude))
        // Rate limit: a recreate just happened; an unreachable endpoint must not churn connections.
        XCTAssertFalse(NCWGBlackhole.shouldRecreate(sentOnAttempt: 8, receivedOnAttempt: 0,
                                                    attemptAge: 60, sinceLastRecreate: 19))
    }

    // MARK: - Outbound binding shaping

    func testUnpinnedParamsProhibitTunnelButPinNothing() {
        NCOutboundBinding.start(includeAllNetworks: true)
        let p = NCOutboundBinding.params(.udp, host: "203.0.113.9", pinInterface: false)
        XCTAssertTrue(p.prohibitedInterfaceTypes.contains(.other),
                      "the tunnel interface stays prohibited (no loop into the tunnel)")
        XCTAssertNil(p.requiredInterface,
                     "no pin: the connection must follow route changes instead of a stale snapshot")
    }

    func testDefaultParamsStillProhibitTunnel() {
        NCOutboundBinding.start(includeAllNetworks: true)
        let p = NCOutboundBinding.params(.udp, host: "203.0.113.9")
        XCTAssertTrue(p.prohibitedInterfaceTypes.contains(.other))
    }

    func testBindingOffLeavesParamsUntouched() {
        NCOutboundBinding.start(includeAllNetworks: false)
        let p = NCOutboundBinding.params(.udp, host: "203.0.113.9", pinInterface: false)
        XCTAssertFalse(p.prohibitedInterfaceTypes.contains(.other))
        XCTAssertNil(p.requiredInterface)
    }
}
