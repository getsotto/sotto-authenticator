import Foundation
import LocalAuthentication
import Security

@MainActor
final class ProtectedKeyExperiment: ObservableObject {
    @Published private(set) var hasTestKey: Bool
    @Published private(set) var status = "No synthetic key exists."

    private static let tagDefaultsKey = "ios-protected-key-experiment-tag"
    private static let challenge = Data("sotto ios protected key test challenge".utf8)

    init() {
        hasTestKey = UserDefaults.standard.string(forKey: Self.tagDefaultsKey) != nil
    }

    func createTestKey() {
        guard deleteExistingKeyIfPresent() else { return }

        let applicationTag = Data(UUID().uuidString.utf8)
        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessError
        ) else {
            _ = accessError?.takeRetainedValue()
            status = "Protected key setup is unavailable on this device."
            hasTestKey = false
            return
        }

        let privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrAccessControl as String: accessControl,
        ]
        let keyAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttributes,
        ]

        var keyError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(keyAttributes as CFDictionary, &keyError) != nil else {
            _ = keyError?.takeRetainedValue()
            status = "Secure Enclave key creation failed. No fallback key was created."
            hasTestKey = false
            return
        }

        UserDefaults.standard.set(applicationTag.base64EncodedString(), forKey: Self.tagDefaultsKey)
        hasTestKey = true
        status = "Synthetic Secure Enclave key created. Authenticate to sign the test challenge."
    }

    func signTestChallenge() {
        guard let tagValue = UserDefaults.standard.string(forKey: Self.tagDefaultsKey),
              let applicationTag = Data(base64Encoded: tagValue) else {
            hasTestKey = false
            status = "No synthetic key is available."
            return
        }

        let context = LAContext()
        defer { context.invalidate() }
        context.localizedReason = "Authenticate to use the synthetic signing key."
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]

        var result: CFTypeRef?
        let lookupStatus = SecItemCopyMatching(query as CFDictionary, &result)
        guard lookupStatus != errSecItemNotFound else {
            UserDefaults.standard.removeObject(forKey: Self.tagDefaultsKey)
            hasTestKey = false
            status = "No synthetic key is available."
            return
        }
        guard lookupStatus == errSecSuccess else {
            status = "Authentication did not authorize the synthetic key operation."
            return
        }
        guard let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
            status = "The protected key reference is invalid."
            return
        }
        // SecItemCopyMatching returns CFTypeRef; verify its concrete type before bridging.
        let privateKey = unsafeDowncast(result, to: SecKey.self)

        var signingError: Unmanaged<CFError>?
        guard SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            Self.challenge as CFData,
            &signingError
        ) != nil else {
            _ = signingError?.takeRetainedValue()
            status = "The protected signing operation failed."
            return
        }

        status = "Protected signing succeeded. Signature output was discarded."
    }

    func deleteTestKey() {
        guard let tagValue = UserDefaults.standard.string(forKey: Self.tagDefaultsKey),
              let applicationTag = Data(base64Encoded: tagValue) else {
            hasTestKey = false
            status = "No synthetic key is available to delete."
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
        ]
        let deleteStatus = SecItemDelete(query as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            status = "Synthetic key cleanup failed."
            return
        }

        UserDefaults.standard.removeObject(forKey: Self.tagDefaultsKey)
        hasTestKey = false
        status = "Synthetic key deleted."
    }

    private func deleteExistingKeyIfPresent() -> Bool {
        guard let tagValue = UserDefaults.standard.string(forKey: Self.tagDefaultsKey) else {
            return true
        }
        guard let applicationTag = Data(base64Encoded: tagValue) else {
            status = "Stored synthetic key reference is invalid; cleanup is required."
            return false
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag,
        ]
        let deleteStatus = SecItemDelete(query as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            status = "Existing synthetic key cleanup failed; no new key was created."
            return false
        }

        UserDefaults.standard.removeObject(forKey: Self.tagDefaultsKey)
        hasTestKey = false
        return true
    }
}
