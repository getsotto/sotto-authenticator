import Foundation
import authenticator_bridgeFFI

@MainActor
final class SnapshotInteropExperiment: ObservableObject {
    @Published var envelopeBase64 = ""
    @Published private(set) var status = "No snapshot operation has run."

    private let key = Data(repeating: 0x11, count: 32) // gitleaks:allow -- public synthetic interoperability fixture only
    private let nonce = Data(repeating: 0x22, count: 12) // gitleaks:allow -- public synthetic interoperability fixture only
    private let snapshot = #"{"formatVersion":1,"project":"synthetic-project","instance":"synthetic-instance","label":"Synthetic test entry"}"#

    func encryptFixture() {
        do {
            let envelope = try encryptTestSnapshot(key: key, nonce: nonce, snapshotJson: snapshot)
            envelopeBase64 = envelope.base64EncodedString()
            status = "Synthetic snapshot encrypted. Copy this envelope to Android and decrypt it there."
        } catch {
            status = "Synthetic snapshot encryption failed."
        }
    }

    func decryptPastedEnvelope() {
        guard let envelope = Data(base64Encoded: envelopeBase64) else {
            status = "Envelope must be valid Base64."
            return
        }
        do {
            let plaintext = try decryptTestSnapshot(key: key, envelope: envelope)
            status = plaintext == snapshot
                ? "Cross-platform synthetic snapshot decrypted and matched."
                : "Decrypted snapshot did not match the expected synthetic fixture."
        } catch {
            status = "Synthetic snapshot was rejected."
        }
    }
}
