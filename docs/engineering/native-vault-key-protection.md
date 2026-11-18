# Native vault-key protection spike

**Status:** synthetic local experiment only. It does not select a production
credential-storage or recovery design.

## Scope

This spike exercises native AES-GCM with a synthetic AES-256 key on each
platform. It encrypts one fixed public fixture, decrypts it after system
authentication, rejects a modified ciphertext, and provides explicit cleanup.
The encrypted fixture is held in memory only and is discarded on process
restart. No real seed, account data, network transfer, backup, or analytics is
used.

The fixture envelope is temporary. On Android it is `SVK1 || 12-byte IV ||
ciphertext || 16-byte GCM tag`; the test header is checked before decryption.
On iOS, CryptoKit's combined AES-GCM representation is held in memory. Neither
representation is approved for stored user data.

## Platform implementation and evidence

Tested 18 November 2026:

| Platform | Key and authentication boundary | Observed result | Environment limit |
| --- | --- | --- | --- |
| iOS | Random 256-bit key stored as a generic-password Keychain item with `WhenPasscodeSetThisDeviceOnly` and `userPresence`. Retrieval returns key bytes to the app process before CryptoKit performs AES-GCM. | On iPhone 17 Pro Simulator, iOS 26.3.1, key creation, synthetic encrypt/decrypt, modified-ciphertext rejection, and deletion succeeded. | The simulator result did not visibly characterize the authentication prompt, physical-device Keychain behavior, or hardware backing. This key is not a Secure Enclave key and is exportable to the app process after access is granted. |
| Android, per-operation biometric | Android Keystore AES-256-GCM key with authentication required for each operation and `BIOMETRIC_STRONG`; the `Cipher` is authorized with `BiometricPrompt.CryptoObject`. | On API 37 Android 17 emulator, simulated fingerprint authorized encrypt/decrypt; modified ciphertext was rejected; canceling the prompt did not produce an authorized result. | Key reported **software** backing. A pre-authentication no-prompt AES probe was denied. No physical Android device was available. |
| Android, biometric or device credential | Android Keystore AES-256-GCM key with a five-second authentication window and `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`. The app authenticates, then initializes the cipher. | On the API 37 emulator, device PIN authorized encrypt/decrypt; modified ciphertext was rejected. A direct AES operation was denied before authentication, permitted immediately after PIN authentication without a second prompt, then denied again after the window expired. The key reported **software** backing. | This demonstrates the configured five-second reuse window on this emulator only. No physical-device or vendor-specific behavior was characterized. |

The Android emulator used `sdk_gphone16k_arm64` (`emu64a16k`). Its temporary
PIN and virtual fingerprint were test setup and were cleared after the run.
Both Android policies used Android Keystore; the result does not establish
StrongBox or Trusted Environment protection.

## Key and plaintext boundaries

- iOS Keychain stores the key bytes protected by the configured access
  control. After authentication, `SecItemCopyMatching` returns those bytes to
  the app. Swift `Data`, CryptoKit, and allocator copies cannot be guaranteed
  erased; the experiment clears its mutable local buffer on a best-effort
  basis.
- Android Keystore does not export the generated key through the API. The
  emulator reported software backing, so the experiment makes no hardware
  security claim. The synthetic plaintext still enters the app process for the
  fixture operation.
- Both clients display only operation status. They do not display fixture
  plaintext, key bytes, IVs, tags, or ciphertext. No values are sent over the
  network or written to app logs.
- Android's five-second setting is an experiment parameter, not an accepted
  app-unlock policy. Authentication gating alone does not define auto-lock,
  process lifecycle, screenshots, accessibility, invalidation, or recovery.

## What this establishes

The native platforms can exercise AES-GCM with synthetic fixtures behind
native key access controls in the tested environments. Modified ciphertext
fails authentication. The Android emulator supports the two tested
authentication policies for AES operations and reports their key backing.

## What remains undecided or untested

- Production key hierarchy, key wrapping, recovery key, recovery-kit format,
  portable migration, and cross-platform key handoff.
- Whether a production design stores a random local vault key in native secure
  storage, how it is backed up, and what happens after loss, reinstall,
  passcode changes, or biometric changes.
- Physical Android key security levels, representative vendors and API 26–36.
- iOS physical-device symmetric-Keychain lifecycle and explicit canceled
  authentication behavior. Simulator success is not hardware evidence.
- Process death, app backgrounding, screen capture, accessibility, backup and
  restore behavior for real credential data.
- Production envelope versioning, nonce policy, metadata privacy,
  corruption/rollback policy, import bounds, and deletion semantics.

Do not use this harness for real credentials. Do not interpret these results as
an audit, production approval, or evidence that platform key protection alone
solves device loss or compromised-app risks.

## Platform references

- Apple: [Keychain items protected by Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- Apple: [passcode-set, device-only Keychain accessibility](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly)
- Apple: [CryptoKit AES-GCM](https://developer.apple.com/documentation/cryptokit/aes/gcm)
- Android: [Keystore system and key security levels](https://developer.android.com/privacy-and-security/keystore)
- Android: [Keystore key authentication and GCM parameters](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)
- Android: [Biometric authentication and device credentials](https://developer.android.com/identity/sign-in/biometric-auth)
