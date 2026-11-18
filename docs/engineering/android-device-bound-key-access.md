# Android device-bound key access spike

Status: emulator spike implemented; physical-device characterization deferred.

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
of describing all Android unlock paths as equivalent. See the official
[BiometricPrompt guide](https://developer.android.com/identity/sign-in/biometric-auth),
[BiometricPrompt API reference](https://developer.android.com/reference/androidx/biometric/BiometricPrompt.PromptInfo.Builder),
and [Keystore key authorization reference](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder).

The harness compares two policies. The biometric-only key requires per-use
strong biometric authorization and signs through a `CryptoObject`. The
biometric-or-device-credential key has a five-second Keystore authorization
window; the prompt has no `CryptoObject`, so the app initializes and uses the
signature only after the system prompt succeeds. A no-prompt probe attempts the
actual Keystore operation directly, without checking app UI state.

## Observed results

Tested 18 November 2026 on the API 37 Android 17 emulator
(`sdk_gphone16k_arm64`, `emu64a16k`). Both keys reported **software** backing.
No physical Android device was connected.

Review decision: emulator evidence is accepted for this spike. Results establish
the software-backed emulator flow only; physical-device hardware backing and
vendor-specific behavior remain unverified and are not claims of this PR.

| Check | Result |
| --- | --- |
| Key generation without a secure screen lock | Rejected by Android Keystore. |
| Key creation with emulator PIN and enrolled virtual fingerprint | Both policies created keys. |
| Strong biometric plus `CryptoObject` signing | Succeeded; the signature was discarded. |
| Strong biometric with the five-second fallback policy | Succeeded; the signature was discarded. |
| Device PIN fallback with the five-second policy | Succeeded; the signature was discarded. |
| Fallback key operation without a prompt, before authentication | Keystore rejected it as unauthenticated. |
| Fallback key operation without a prompt after the authorization window elapsed | Keystore rejected it as unauthenticated. |
| App background and foreground after the authorization window elapsed | Keystore rejected a no-prompt operation after returning to the app. |
| Process force-stop and relaunch | The alias remained; a no-prompt operation was still rejected. |
| Change the device PIN | An immediate no-prompt probe signed once; after waiting seven seconds, Keystore rejected it. The test did not isolate whether the system PIN-change flow itself refreshed the auth window. |
| Remove the secure screen lock | The fallback alias was no longer available; the app required creating a new test key. |

The five-second policy makes credential fallback available while retaining a
Keystore-enforced authorization boundary, but it allows repeated key use
during that short window. That differs from the per-operation biometric key.
Product policy must decide whether this usability/security tradeoff is
acceptable; this spike does not choose a production timeout.

Not tested: API 26–36 device behavior, physical-device hardware backing, or
biometric enrollment changes. PIN change and secure-lock removal were tested
only on this API 37 emulator; device-specific results may differ. Physical
device characterization is deferred until hardware is available. The code
gates combined biometric and device-credential prompts to API 30 and later
because earlier platform versions do not support that combination. The
biometric-only mode remains available from the app's current minimum API level,
26.

## Cleanup

Use **Delete synthetic keys** in the app to remove the experiment aliases.
Uninstalling the app also removes its Android Keystore entries. Emulator PIN,
pattern, and biometric configuration is test setup only and must be reset
before the emulator is reused for unrelated work.

## Evidence

Implementation and API 37 emulator results are recorded in the Observed results
section above. The emulator reported software-backed keys. Physical-device and
hardware-backed behavior remain unverified; emulator results do not establish
those properties.
