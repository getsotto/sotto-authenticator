import CryptoKit
import Foundation
import LocalAuthentication
import Security

@MainActor
final class VaultKeyExperiment: ObservableObject {
    @Published private(set) var hasTestKey: Bool
    @Published private(set) var hasEnvelope = false
    @Published private(set) var status = "No synthetic vault operation has run."

    private static let service = "dev.getsotto.authenticator.vault-key-spike"
    private static let account = "synthetic-aes-key"
    private static let markerKey = "ios-vault-key-experiment-exists"
    private static let fixture = Data("synthetic local vault fixture v1".utf8)
    private var envelope: Data?

    init() {
        hasTestKey = UserDefaults.standard.bool(forKey: Self.markerKey)
    }

    func createTestKey() {
        guard deleteExistingKeyIfPresent() else { return }

        var keyBytes = Data(count: 32)
        guard keyBytes.withUnsafeMutableBytes({ bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!) == errSecSuccess
        }) else {
            status = "Synthetic key generation failed."
            return
        }
        defer { keyBytes.resetBytes(in: 0..<keyBytes.count) }

        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.userPresence],
            &accessError
        ) else {
            _ = accessError?.takeRetainedValue()
            status = "Protected Keychain storage is unavailable on this device."
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecAttrAccessControl as String: accessControl,
            kSecValueData as String: keyBytes,
        ]
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            status = "Protected Keychain key creation failed."
            return
        }

        UserDefaults.standard.set(true, forKey: Self.markerKey)
        hasTestKey = true
        hasEnvelope = false
        envelope = nil
        status = "Synthetic AES key created in protected Keychain storage."
    }

    func encryptFixture() {
        guard var keyBytes = retrieveKey(reason: "Authenticate to encrypt the synthetic fixture.") else { return }
        defer { Self.clear(&keyBytes) }
        do {
            let key = SymmetricKey(data: keyBytes)
            guard let sealed = try AES.GCM.seal(Self.fixture, using: key).combined else {
                status = "Synthetic encryption failed."
                return
            }
            envelope = sealed
            hasEnvelope = true
            status = "Protected encrypt succeeded; synthetic envelope remains in memory only."
        } catch {
            status = "Synthetic encryption failed."
        }
    }

    func decryptFixture(tampered: Bool = false) {
        guard let envelope else {
            status = "Encrypt the synthetic fixture first."
            return
        }
        guard var keyBytes = retrieveKey(reason: "Authenticate to decrypt the synthetic fixture.") else { return }
        defer { Self.clear(&keyBytes) }
        do {
            let key = SymmetricKey(data: keyBytes)
            var candidate = envelope
            if tampered, !candidate.isEmpty {
                candidate[candidate.index(before: candidate.endIndex)] ^= 1
            }
            let sealed = try AES.GCM.SealedBox(combined: candidate)
            let plaintext = try AES.GCM.open(sealed, using: key)
            status = tampered
                ? "Unexpectedly accepted the modified synthetic envelope."
                : plaintext == Self.fixture
                    ? "Protected decrypt succeeded; synthetic fixture matched."
                    : "Decrypted fixture did not match the expected synthetic value."
        } catch {
            status = tampered
                ? "Modified synthetic fixture rejected by AES-GCM authentication."
                : "Synthetic decryption failed or authentication was unavailable."
        }
    }

    func deleteTestKey() {
        let deleteStatus = SecItemDelete(keyQuery as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            status = "Synthetic Keychain key cleanup failed."
            return
        }
        UserDefaults.standard.removeObject(forKey: Self.markerKey)
        hasTestKey = false
        hasEnvelope = false
        envelope = nil
        status = "Synthetic AES key deleted; in-memory fixture discarded."
    }

    private func retrieveKey(reason: String) -> Data? {
        guard hasTestKey else {
            status = "Create the synthetic AES key first."
            return nil
        }
        let context = LAContext()
        defer { context.invalidate() }
        context.localizedReason = reason
        var query = keyQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let lookupStatus = SecItemCopyMatching(query as CFDictionary, &result)
        guard lookupStatus == errSecSuccess, let keyBytes = result as? Data else {
            if lookupStatus == errSecItemNotFound {
                UserDefaults.standard.removeObject(forKey: Self.markerKey)
                hasTestKey = false
                status = "Synthetic Keychain key is missing; create a new key."
            } else {
                status = "System authentication did not authorize the key operation."
            }
            return nil
        }
        return keyBytes
    }

    private func deleteExistingKeyIfPresent() -> Bool {
        let deleteStatus = SecItemDelete(keyQuery as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            status = "Existing synthetic Keychain key cleanup failed; no new key was created."
            return false
        }
        UserDefaults.standard.removeObject(forKey: Self.markerKey)
        hasTestKey = false
        hasEnvelope = false
        envelope = nil
        return true
    }

    private var keyQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
        ]
    }

    private static func clear(_ data: inout Data) {
        data.resetBytes(in: 0..<data.count)
    }
}
