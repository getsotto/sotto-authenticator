# Android device-bound key access spike

Status: implementation in progress.

This spike checks whether Android Keystore can enforce system authentication at
the point a synthetic cryptographic operation is performed. It uses a fixed
test challenge and temporary P-256 signing keys. It does not accept or store
TOTP seeds, account data, tokens, or other user credentials.

## Experiment boundary

- All signing keys are generated locally in Android Keystore under
  experiment-only aliases and have an explicit delete action.
- The test signs a fixed public challenge, discards the signature, and shows
  only an outcome message. It never exports a private key.
- The app does not store an authentication-success Boolean. Key authorization
  is enforced by Android Keystore.
- No key material, signature, challenge, device identifier, or authentication
  result is sent over a network or written to logs or analytics.
- No production key format, account schema, backup, recovery, synchronization,
  device attestation, or release support promise is selected here.

## Questions this spike measures

1. Can a per-operation Keystore signature be authorized by a strong biometric
   through `BiometricPrompt.CryptoObject`?
2. Can a short-lived Keystore authorization window preserve biometric and
   device-credential fallback while still making Keystore, rather than app UI
   state, the gate for the signature?
3. What happens when the secure lock screen or biometric enrollment changes,
   the app is backgrounded, or the process is restarted?
4. What key security level does the tested emulator or device report?

Android does not support every prompt authenticator combination on every API
level. A `CryptoObject` flow is restricted to strong biometrics, while
device-credential combinations have separate API-level support limits. The
spike therefore records the exact flow and API level for each result instead
of describing all Android unlock paths as equivalent.

## Cleanup

Use **Delete synthetic keys** in the app to remove the experiment aliases.
Uninstalling the app also removes its Android Keystore entries. Emulator PIN,
pattern, and biometric configuration is test setup only and must be reset
before the emulator is reused for unrelated work.

## Evidence

Implementation and test results will be recorded here after the experiment is
run. Emulator results do not establish physical-device or hardware-backed
behavior. Hardware claims require a named physical test device and reported
Keystore security level.
