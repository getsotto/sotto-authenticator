# Local vault key hierarchy and recovery options

**Status:** proposal for maintainer review. No production key hierarchy or recovery format has been approved.

## Decision to make

The authenticator needs a local vault that can be unlocked on a device and moved to another supported platform. The initial implementation should add no hosted service or recurring infrastructure. Migration must not depend on copying a device-bound key.

[PR 12](https://github.com/getsotto/sotto-authenticator/pull/12) characterised synthetic AES key access on iOS and Android. It did not test durable credentials, portable recovery, or a shared production key hierarchy. Its platform findings are recorded in [native vault-key protection](native-vault-key-protection.md).

The design must separate these questions:

1. How is data protected during ordinary use on one device?
2. How can an authorised user move or recover the vault on another device?
3. Which code performs encryption, decryption, and key handling across the native and Rust boundary?

## Options

| Option | Local device protection | Cross-platform migration | Main cost or risk | Assessment |
| --- | --- | --- | --- | --- |
| Device-bound key only | Native Keychain or Keystore protects the only vault key. | No portable recovery path. A device change can make the vault unusable. | Simple local unlock, but conflicts with the product requirement to support migration. | Reject as the sole key path. It may protect a local copy in a design with a separate recovery route. |
| User-chosen passphrase directly encrypts the vault | A passphrase-derived key is required to unlock every vault. | Portable if every client implements the same derivation and format. | Weak or reused passphrases need careful protection against guessing. Forgotten passphrases cannot be reset without a separate recovery mechanism. The app must choose and tune a password KDF. | Keep as a candidate, not the default. Requires a deliberate UX and cryptographic review. |
| Random vault key with separate local and portable protection | A random vault key is protected for local use by platform-native storage and authentication. | A user-controlled recovery secret can unlock an export on iOS, Android, and future desktop or CLI clients. | More key-management states and an explicit recovery experience. Loss of both the device access path and recovery material means loss of the vault. | Recommended architecture direction. Decide the recovery secret representation and cryptographic details in follow-up decisions. |
| Hosted recovery or synchronisation | A service stores or brokers encrypted vault data or key material. | Can support multiple devices, subject to service design. | Adds recurring infrastructure, account and service threat models, operational recovery, and support obligations. | Out of scope for this stage. Revisit only after a separate product and cost decision. |

## Proposed direction

Keep ordinary local unlock and portable recovery as separate paths:

```text
vault records
    encrypted with a random vault data key

random vault data key
    protected for local unlock by the platform adapter
    protected separately for a user-controlled export

portable export
    user initiated, versioned, and usable without a Sotto service
```

This direction avoids making an OS-specific key the only way to recover data. It also keeps local authentication native and leaves a portable export possible without accounts, email, object storage, or sync. The export is a user-held file or transfer payload, not a backup that Sotto can recover.

The following choices remain open and must not be inferred from this proposal:

- Whether portable recovery uses a generated high-entropy secret, a user-chosen passphrase, or another reviewed mechanism.
- Whether the secret is shown as words, grouped characters, or another format, and how the user confirms that it was saved.
- Which KDF, encryption construction, parameters, nonce rules, envelope fields, and import limits are selected.
- Whether native adapters or the shared Rust core perform each cryptographic operation. The choice must account for Android non-exportable keys, iOS Keychain access, FFI copies, and consistent cross-platform files.
- How export metadata is minimised and whether project, instance, issuer, and account labels are encrypted.
- Whether import replaces or merges entries, and how duplicates and partial failures are presented.
- What lock, background, timeout, backup, restore, invalidation, deletion, and reinstall behaviour is supported.

## User and recovery consequences

- Local device authentication is a convenience and protection boundary for a local copy. It does not by itself make that key portable.
- A recovery secret controlled by the user has no server-side reset. The product must explain that loss of the recovery secret can make an export unrecoverable.
- A local vault can remain accessible on an enrolled device when the user has lost the recovery secret. A new device cannot recover from that local copy unless the user can still export it.
- A device-bound key must never be described as the user's backup or migration key.
- No Sotto service is required by the proposed direction. Initial recurring infrastructure cost remains zero, excluding existing developer programme or test-device costs.
- Desktop and CLI clients are future compatibility targets. The portable format must be specified independently of the first mobile UI, while support claims must match clients actually released.

## Required design gates

Before implementing durable vault data, maintainers must approve:

1. The local and portable key hierarchy, including the recovery-secret model.
2. The portable envelope and cryptographic choices, with test vectors and failure behaviour.
3. The boundary between native platform code and Rust for key operations and plaintext.
4. The user journey for creating, confirming, exporting, importing, replacing, and deleting recovery material.
5. Lifecycle and backup policy for supported platforms.

All experiments before those gates use synthetic data only. No real TOTP seed, account record, or user export is in scope.

## References

- [ADR 0002: local vault design gate](../decisions/0002-local-vault-design-gate.md)
- [Step 1 threat model and architecture gate](step-1-threat-model-and-architecture-gate.md)
- [Native vault-key protection findings](native-vault-key-protection.md)
- [Cross-platform encrypted snapshot experiment](cross-platform-encrypted-snapshot.md)
