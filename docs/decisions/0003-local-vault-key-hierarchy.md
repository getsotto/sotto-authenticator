# ADR 0003: local vault key hierarchy and portable recovery

- Status: accepted for design direction; implementation details remain open
- Date: 2026-11-19
- Evidence: [native vault-key protection findings](../engineering/native-vault-key-protection.md)

## Context

ADR 0002 requires a separately reviewed key hierarchy and recovery design
before persistent credentials are implemented. PR 12 characterised synthetic
native AES key access, but did not establish a portable recovery mechanism or
production key format.

The product direction is mobile first, project aware, and intended to support
migration across platforms. The initial vault must not require a hosted service
or recurring infrastructure. A device-bound key alone cannot meet migration
and recovery needs.

## Decision

- Separate ordinary local unlock from portable recovery.
- Use a random vault data key as the basis for protecting vault records.
- Protect the local copy through native platform facilities and authentication.
- Provide a distinct, user-controlled recovery path for a portable export that
  does not depend on an Sotto service or device-bound key.
- Keep the portable format independent of the native key store so future
  desktop and CLI clients can implement it.
- Keep the recovery-secret format, derivation and encryption parameters,
  envelope schema, and native/Rust cryptographic boundary undecided until
  their own reviewed design gates.
- Use synthetic data only until the key hierarchy, portable envelope,
  lifecycle policy, and recovery journey have been approved.

## Consequences

Local access can continue through a device's native protection, while migration
uses a separate user-held recovery path. There is no server-side reset. If a
user loses both the enrolled device access and recovery material, the vault may
be unrecoverable. The product must make this consequence clear before creating
real credentials.

The design does not require hosted accounts, sync, email, or object storage, so
the initial recurring infrastructure cost remains zero. Implementations still
need to account for platform-specific key behaviour and copies across native
and Rust memory boundaries.

## Deferred decisions

1. Should the portable recovery factor be generated for the user or chosen by
   the user? Step 2 PR 02 compares these journeys.
2. Should the first portable export be an explicit user-managed file, with
   sync remaining out of scope?
3. Which desktop and CLI clients are compatibility targets for the first
   portable format, even if those clients ship later?

## Review trigger

This decision accepts only the direction above. It does not approve the
recovery-factor experience, portable envelope, cryptographic parameters,
platform lifecycle, or native/Rust boundary. Record and review those details
before implementing persistent real credentials.
