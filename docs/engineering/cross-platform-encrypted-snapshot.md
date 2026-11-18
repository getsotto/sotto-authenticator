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

## Unresolved production decisions

- Snapshot schema, canonical serialization, compatibility, and migration.
- Key hierarchy, derivation, wrapping, recovery, device enrollment, and loss.
- Nonce generation and collision policy for each encryption key.
- Resource bounds based on real account/project data and streaming needs.
- Independent security review, platform threat models, and audit requirements.
- Whether snapshots need authenticated identity, rollback protection, or
  metadata privacy.

Passing these spike tests is not a security audit or production approval.
