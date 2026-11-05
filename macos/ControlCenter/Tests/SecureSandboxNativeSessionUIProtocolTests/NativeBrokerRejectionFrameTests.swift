import Foundation
import Testing
@testable import SecureSandboxNativeSessionUIProtocol

private func appendBigEndian(_ value: UInt32, to data: inout Data) {
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func rejectionFrame(
    status: UInt32 = 1,
    stdout: Data = Data(),
    stderr: Data
) -> Data {
    var result = Data("SSAR".utf8)
    appendBigEndian(status, to: &result)
    appendBigEndian(UInt32(stdout.count), to: &result)
    appendBigEndian(UInt32(stderr.count), to: &result)
    result.append(stdout)
    result.append(stderr)
    return result
}

private func canonicalRejection(
    error: String = "control_center_live_identity_invalid",
    schema: String = "secure-sandbox-touchid-approval-v1",
    status: String = "rejected"
) throws -> Data {
    try CanonicalNativeJSON.encodeLine([
        "error": error,
        "schema": schema,
        "status": status,
    ])
}

@Suite struct NativeBrokerRejectionFrameTests {
    @Test func admitsOnlyExactContentFreeRejectedFrame() throws {
        let value = rejectionFrame(stderr: try canonicalRejection())
        #expect(NativeBrokerRejectionFrame.hasMagic(value))
        #expect(
            try NativeBrokerRejectionFrame.decodeRejectedError(value)
                == "control_center_live_identity_invalid"
        )
        #expect(!NativeBrokerRejectionFrame.hasMagic(Data("{}\n".utf8)))
    }

    @Test func rejectsSuccessOutputAndMalformedBinaryFrames() throws {
        let error = try canonicalRejection()
        let valid = rejectionFrame(stderr: error)
        let variants = [
            rejectionFrame(status: 0, stderr: error),
            rejectionFrame(stdout: Data("ok\n".utf8), stderr: error),
            valid + Data([0]),
            Data("SSAR".utf8),
        ]
        for value in variants {
            #expect(throws: NativeSessionProtocolError.self) {
                try NativeBrokerRejectionFrame.decodeRejectedError(value)
            }
        }
    }

    @Test func rejectsNoncanonicalOrUnsafeErrorPayloads() throws {
        let variants = [
            Data(#"{"error":"control_center_live_identity_invalid", "schema":"secure-sandbox-touchid-approval-v1","status":"rejected"}"#.utf8)
                + Data([0x0a]),
            try canonicalRejection(error: "ControlCenter/invalid"),
            try canonicalRejection(error: "control_center_invalid\n"),
            try canonicalRejection(error: "contrôle_center_invalid"),
            try canonicalRejection(schema: "secure-sandbox-other-v1"),
            try canonicalRejection(status: "approved"),
            try CanonicalNativeJSON.encodeLine([
                "error": "control_center_live_identity_invalid",
                "extra": true,
                "schema": "secure-sandbox-touchid-approval-v1",
                "status": "rejected",
            ]),
        ]
        for payload in variants {
            #expect(throws: NativeSessionProtocolError.self) {
                try NativeBrokerRejectionFrame.decodeRejectedError(
                    rejectionFrame(stderr: payload)
                )
            }
        }
    }

    @Test func enforcesIndependentErrorSizeCeiling() throws {
        let payload = try canonicalRejection()
        #expect(throws: NativeSessionProtocolError.self) {
            try NativeBrokerRejectionFrame.decodeRejectedError(
                rejectionFrame(stderr: payload),
                maximumErrorBytes: payload.count - 1
            )
        }
    }
}
