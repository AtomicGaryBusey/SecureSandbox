import Darwin

public enum NativeBrokerPeerIdentity {
    public static func requireRoot(_ descriptor: Int32) throws {
        try validate(descriptor, expectedUID: 0, expectedGID: 0)
    }

    public static func validate(
        _ descriptor: Int32,
        expectedUID: uid_t,
        expectedGID: gid_t
    ) throws {
        guard descriptor >= 0 else {
            throw NativeSessionProtocolError.rejected(
                "native_broker_peer_descriptor_invalid"
            )
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(descriptor, &uid, &gid) == 0,
              uid == expectedUID, gid == expectedGID else {
            throw NativeSessionProtocolError.rejected(
                "native_broker_peer_identity_invalid"
            )
        }
    }
}
