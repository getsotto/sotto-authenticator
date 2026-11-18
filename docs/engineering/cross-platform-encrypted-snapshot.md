# Cross-platform encrypted snapshot spike

**Status:** temporary engineering experiment; not a production format.

This document records a synthetic snapshot envelope used to exercise the Rust
core through the iOS and Android bindings. It does not establish a backup,
recovery, migration, or key management design. Do not use this format for user
data.

## Fixture and envelope v1

The plaintext fixture is UTF-8 JSON with exactly these fields:

```json
{"formatVersion":1,"project":"synthetic-project","instance":"synthetic-instance","label":"Synthetic test entry"}
```

The JSON object is validated before encryption and after decryption. Unknown or
missing fields and a version other than `1` are rejected.

The binary envelope is concatenated as follows:

| Field | Size | Meaning |
| --- | ---: | --- |
| Magic | 4 bytes | ASCII `SOT1` |
| Version | 1 byte | `1` |
| Reserved | 1 byte | Must be zero |
| Nonce | 12 bytes | AES-GCM nonce |
| Ciphertext and tag | variable | AES-256-GCM ciphertext with 16-byte tag |

The six-byte header is authenticated as AES-GCM associated data. The accepted
key is exactly 32 bytes. Plaintext is limited to 64 KiB. The decoder rejects
unknown header versions, nonzero reserved bytes, incomplete envelopes,
oversize input, authentication failures, invalid UTF-8/JSON, and invalid JSON
shape. It never attempts plaintext or alternate-format decoding.

The Rust implementation uses `aes-gcm` 0.10.3 with AES-256-GCM, a 96-bit
nonce, and a 128-bit authentication tag. Rust-owned key and plaintext buffers
are zeroized on drop where supported. Copies in callers, FFI, the cipher, or
compiler may remain; zeroization is best-effort and does not guarantee process
memory erasure. See the [RustCrypto AES-GCM crate](https://docs.rs/aes-gcm/0.10.3/aes_gcm/)
and [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116.html) for the primitive
and nonce requirements.

The native harness uses a public synthetic key and nonce fixture so both apps
can reproduce the same test vector. These bytes are intentionally not secret
and provide no confidentiality. Reusing a nonce with a real key would be
unsafe; production nonce creation and key distribution are out of scope.

## Key boundary and test evidence

The iOS Secure Enclave and Android Keystore keys characterized in the earlier
spikes are P-256 signing keys. This experiment does not turn either signing
key into an encryption key and does not export or bypass either platform key.
The native harness passes only the explicitly public test key and nonce to the
Rust core. Therefore reciprocal results demonstrate that both generated
bindings call the same Rust envelope implementation; they do not demonstrate
platform-protected snapshot-key handoff.

### Recorded checks

Executed 18 November 2026:

| Environment | Check | Result |
| --- | --- | --- |
| Rust host | `cargo test -p authenticator-bridge` | 12 passed, including invalid keys, invalid JSON, wrong key, modified header/ciphertext, truncation, unsupported version, and size bounds |
| iOS Simulator | iPhone 17 Pro, iOS 26.3.1, `xcodebuild test` | 3 passed: decrypt shared golden vector, produce matching vector, reject modified ciphertext/version |
| Android Emulator | API 37 / Android 17, `connectedAndroidTest` | 3 passed: decrypt shared golden vector, produce matching vector, reject modified ciphertext/version |
| macOS Swift bridge smoke | Generated Swift binding with the host Rust library | Encrypted/decrypted the fixture and matched the shared vector |
| Runtime producer/consumer exchange | `scripts/smoke-cross-platform-snapshot.sh` with Android API 37 emulator | Passed in both directions: Swift-generated output was decrypted by the Android app; Android-app output was decrypted by the Swift binding |

The XCTest and Android instrumentation suites use the same public deterministic
golden vector. The separate runtime exchange script goes further: it captures
an envelope emitted by the Swift binding, supplies it to the Android app, and
checks the app's decrypted status. It then captures an envelope emitted by the
Android app and passes it to the Swift binding for decryption. The Swift
producer/consumer runs on the macOS host with the generated Swift binding and
host Rust library; the Android producer/consumer runs in the API 37 emulator.
This demonstrates runtime envelope exchange through both generated bindings,
not protected key exchange between real devices. No physical Android device
was available for this spike.

### Negative cases exercised

- Wrong key and invalid key or nonce size.
- Unknown version, invalid magic/reserved header, and truncated envelope.
- Modified authenticated ciphertext/tag.
- Invalid JSON, unsupported payload version, and invalid snapshot fields.
- Oversized envelope or plaintext.
- No path falls back to plaintext or another version.

## Unresolved production decisions

- Snapshot schema, canonical serialization, compatibility, and migration.
- Key hierarchy, derivation, wrapping, recovery, device enrollment, and loss.
- Nonce generation and collision policy for each encryption key.
- Resource bounds based on real account/project data and streaming needs.
- Independent security review, platform threat models, and audit requirements.
- Whether snapshots need authenticated identity, rollback protection, or
  metadata privacy.

Passing these spike tests is not a security audit or production approval.
