# ADR 0004: recovery factor and portable vault journey

- Status: accepted
- Date: 2026-11-19
- Depends on: [ADR 0003: local vault key hierarchy and portable recovery](0003-local-vault-key-hierarchy.md)
- Evidence: [native vault-key protection findings](../engineering/native-vault-key-protection.md)

## Context

ADR 0003 accepts separate local-unlock and portable-recovery paths. It leaves
the recovery factor and user journey open. This decision proposes the product
contract needed before the portable format and cryptographic parameters are
specified in Step 2 PR 03.

The product must support migration across platforms without a Sotto account,
hosted recovery, or sync service. Project and instance groupings are core to the
authenticator's user experience and must survive migration.

## Proposed decision

- Use a generated, high-entropy recovery secret, separate from the device
  passcode and local unlock. Do not use a user-chosen passphrase as the only
  portable recovery factor.
- Require recovery setup and confirmation before the first real credential is
  stored. The user must understand that Sotto cannot retrieve or reset the
  secret.
- Make the first export an explicit user-managed file containing the whole
  vault, preserving project and instance groupings. Keep the recovery secret
  separate from the file. Do not upload either to Sotto.
- Import requires both the file and recovery secret. Validate the complete
  input before changing the active vault. Exact preview and replace or merge
  behaviour remain for the format and implementation reviews.
- On an enrolled device, a user who has lost recovery material can
  reauthenticate, create a new secret, confirm it, and create a fresh export.
  Existing exports remain protected by their original secret and cannot be
  revoked by rotating the current secret.
- If the user loses both access to the enrolled device and the recovery
  material, the vault is unrecoverable. No support or service-side reset is
  provided.
- The first release targets iOS and Android. Keep the portable contract
  independent of platform key stores so future desktop and CLI clients can
  implement it. Do not claim those clients are supported before they ship.

## Consequences

Recovery setup adds work before the first real credential can be stored. This
reduces the chance that a device-bound local copy is mistaken for a portable
backup. Users must keep recovery material safe, and old exports retain their
original recovery requirement. Sotto cannot reset a lost secret.

The journey requires no hosted account, email, sync, or object storage, so it
adds no recurring infrastructure cost. The exact recovery-secret encoding,
format, cryptographic construction, and error limits remain unselected.

## Deferred decisions

Step 2 PR 03 must decide and review:

- recovery-secret entropy length, encoding, checksum, and confirmation details;
- key derivation or wrapping and authenticated-encryption construction;
- envelope versioning, nonce rules, authenticated fields, metadata privacy,
  and import bounds;
- wrong-secret and corrupted-file error behaviour without leaking information;
- whether import replaces or merges, how duplicates are handled, and the
  atomicity guarantee.

## Review trigger

Before implementation, product and maintainers must accept or revise this
journey. Do not accept real credentials until the portable format, platform
lifecycle, native/Rust boundary, and readiness gate have also been reviewed.
