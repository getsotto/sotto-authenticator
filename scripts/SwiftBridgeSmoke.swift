import Foundation
import authenticator_bridgeFFI

@main
struct SwiftBridgeSmoke {
    static func main() {
        let key = Data(repeating: 0x11, count: 32)
        let nonce = Data(repeating: 0x22, count: 12)
        let fixture = #"{"formatVersion":1,"project":"synthetic-project","instance":"synthetic-instance","label":"Synthetic test entry"}"#
        do {
            let envelope = try encryptTestSnapshot(key: key, nonce: nonce, snapshotJson: fixture)
            let plaintext = try decryptTestSnapshot(key: key, envelope: envelope)
            precondition(plaintext == fixture, "Swift bridge returned a different synthetic snapshot.")
            print("Swift bridge encrypted and decrypted the synthetic snapshot.")
        } catch {
            fatalError("Swift bridge snapshot operation failed.")
        }
    }
}
