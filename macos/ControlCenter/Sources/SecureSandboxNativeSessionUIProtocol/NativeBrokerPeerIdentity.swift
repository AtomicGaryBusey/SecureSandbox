import Darwin
import Foundation

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

public enum NativeDescriptorBorrow {
    public static func duplicateCloseOnExec(_ descriptor: Int32) throws -> Int32 {
        guard descriptor >= 0 else {
            throw NativeSessionProtocolError.rejected(
                "native_broker_descriptor_invalid"
            )
        }
        let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0 else {
            throw NativeSessionProtocolError.rejected(
                "native_broker_descriptor_borrow_failed"
            )
        }
        return duplicate
    }
}

public enum NativeDescriptorInheritanceGate {
    private static let lock = NSLock()

    public static func makeUnixStreamSocket() throws -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw NativeSessionProtocolError.rejected(
                "native_broker_socket_unavailable"
            )
        }
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0,
              fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0 else {
            Darwin.close(descriptor)
            throw NativeSessionProtocolError.rejected(
                "native_broker_socket_cloexec_failed"
            )
        }
        return descriptor
    }

    /// Foundation Process can fork while another thread creates a descriptor.
    /// Serialize every Control Center launch with the socket creation/F_SETFD
    /// window; after publication FD_CLOEXEC itself protects all later execs.
    public static func run(_ process: Process) throws {
        lock.lock()
        defer { lock.unlock() }
        try process.run()
    }
}
