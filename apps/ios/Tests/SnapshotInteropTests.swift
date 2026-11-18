import XCTest
@testable import SottoAuthenticatorSpike

final class SnapshotInteropTests: XCTestCase {
    func testDecryptsSharedVectorProducedByAndroidBinding() throws {
        let envelope = try XCTUnwrap(Data(base64Encoded: Self.sharedEnvelope))
        XCTAssertEqual(
            try decryptTestSnapshot(key: Self.testKey, envelope: envelope),
            Self.snapshotJSON,
        )
    }

    func testEncryptsTheSameVectorAsAndroidBinding() throws {
        let envelope = try encryptTestSnapshot(
            key: Self.testKey,
            nonce: Self.testNonce,
            snapshotJson: Self.snapshotJSON,
        )
        XCTAssertEqual(envelope.base64EncodedString(), Self.sharedEnvelope)
    }

    func testRejectsModifiedCiphertextAndUnsupportedVersion() throws {
        let envelope = try XCTUnwrap(Data(base64Encoded: Self.sharedEnvelope))

        var modifiedCiphertext = envelope
        modifiedCiphertext[modifiedCiphertext.index(before: modifiedCiphertext.endIndex)] ^= 1
        XCTAssertThrowsError(try decryptTestSnapshot(key: Self.testKey, envelope: modifiedCiphertext))

        var unsupportedVersion = envelope
        unsupportedVersion[4] = 2
        XCTAssertThrowsError(try decryptTestSnapshot(key: Self.testKey, envelope: unsupportedVersion))
    }

    private static let testKey = Data(repeating: 0x11, count: 32) // gitleaks:allow -- public synthetic interoperability fixture only
    private static let testNonce = Data(repeating: 0x22, count: 12) // gitleaks:allow -- public synthetic interoperability fixture only
    private static let snapshotJSON = #"{"formatVersion":1,"project":"synthetic-project","instance":"synthetic-instance","label":"Synthetic test entry"}"#
    private static let sharedEnvelope = "U09UMQEAIiIiIiIiIiIiIiIibNVhJrKi/iuzWqxPIcmH9yWi4cAa88MhNyx+yjPDFnorC8NnJ8Ga8z4qgkeDOz0Xn/D3DOYGG5DXEcjDwBiW3AzkeUw45nx7hRJC8HmKmy7Jn89fYYu3cWMjgtNQ1mmx/CgwPg0y+Dp8+YNjBiK9WDFhOaPPYO0z7/+PPTYi1dw="
}
