import Foundation
import authenticator_bridgeFFI

@main
struct SwiftBridgeSmoke {
    static func main() {
        let key = Data(repeating: 0x11, count: 32)
        let nonce = Data(repeating: 0x22, count: 12)
        let fixture = #"{"formatVersion":1,"project":"synthetic-project","instance":"synthetic-instance","label":"Synthetic test entry"}"#
        let expectedEnvelopeBase64 = "U09UMQEAIiIiIiIiIiIiIiIibNVhJrKi/iuzWqxPIcmH9yWi4cAa88MhNyx+yjPDFnorC8NnJ8Ga8z4qgkeDOz0Xn/D3DOYGG5DXEcjDwBiW3AzkeUw45nx7hRJC8HmKmy7Jn89fYYu3cWMjgtNQ1mmx/CgwPg0y+Dp8+YNjBiK9WDFhOaPPYO0z7/+PPTYi1dw="
        do {
            let envelope: Data
            if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--decrypt-base64" {
                guard let supplied = Data(base64Encoded: CommandLine.arguments[2]) else {
                    fatalError("Supplied synthetic envelope was not valid Base64.")
                }
                envelope = supplied
            } else {
                envelope = try encryptTestSnapshot(key: key, nonce: nonce, snapshotJson: fixture)
                precondition(
                    envelope.base64EncodedString() == expectedEnvelopeBase64,
                    "Swift bridge did not produce the shared synthetic vector.",
                )
            }
            let plaintext = try decryptTestSnapshot(key: key, envelope: envelope)
            precondition(plaintext == fixture, "Swift bridge returned a different synthetic snapshot.")
            print("Swift bridge encrypted and decrypted the synthetic snapshot.")
            print("ENVELOPE_BASE64=\(envelope.base64EncodedString())")
        } catch {
            fatalError("Swift bridge snapshot operation failed.")
        }
    }
}
