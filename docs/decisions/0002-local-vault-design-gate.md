# ADR 0002: proceed to a local vault design gate

- Status: accepted for bounded synthetic key-protection characterization
- Date: 2026-11-18
- Evidence: [Step 1 threat model and architecture gate](../engineering/step-1-threat-model-and-architecture-gate.md)
- Follow-up evidence: [native vault-key protection spike](../engineering/native-vault-key-protection.md)

## Context

The first engineering stage validated a native iOS and Android shell with a
shared Rust core, TOTP vectors, platform-authenticated synthetic signing keys,
and runtime exchange of a temporary encrypted test envelope. It did not
implement credential persistence, key wrapping, recovery, or migration.

The platform key spikes use P-256 signing keys. The cross-platform envelope
uses a public synthetic AES key and nonce. Neither result demonstrates a
production vault key hierarchy. Android evidence is emulator-only and
software-backed; the iOS hardware test did not characterize key invalidation
or recovery lifecycle.

The product direction is mobile first, native, project-aware, and open source.
The first implementation should keep recurring infrastructure cost close to
zero. Cross-platform migration is a product requirement, so a device-bound key
cannot be the only way to recover credential data.

## Decision

- Proceed to a bounded design and local-only credential-storage spike.
- Retain native iOS/Android clients, a shared Rust domain core, and the UniFFI
  boundary from ADR 0001.
- Keep platform key storage and local authentication in native adapters; keep
  shared TOTP behavior in Rust.
- Require a separately reviewed key hierarchy and recovery/migration design
  before storing real credentials.
- Do not reuse the P-256 signing keys or PR 10 test envelope as vault
  encryption design.
- Keep hosted services, sync, and object storage out of the next stage. The
  local-only stage requires no recurring infrastructure.

## Consequences

The bounded characterization spike in PR 12 exercises native AES-GCM keys with
synthetic fixtures. Further design work may compare storage and recovery
approaches using synthetic fixtures. No stage is allowed to accept real
account secrets or claim production security. The design must address device loss,
passcode knowledge, lifecycle invalidation, cross-platform import/export,
plaintext copies, diagnostics, deletion, and backup/restore.

This decision leaves the encryption-key hierarchy, portable recovery method,
sync model, production file format, and platform support matrix open. It also
leaves independent review scope and release controls for a later gate.

## Rejected for now

- Use the device-bound P-256 signing key directly as a vault key: the spikes
  only establish signing behavior and do not show suitable symmetric
  encryption or portable recovery.
- Adopt the PR 10 envelope as a user-data format: it uses public deterministic
  test material and has no production key distribution, nonce policy, recovery,
  or migration contract.
- Add a hosted service now: current evidence does not require one, while it
  would add recurring cost and a separate service threat model before local
  storage is understood.

## Review trigger

Revisit this ADR after the key hierarchy and recovery options are compared,
before any persistent credential storage is implemented. Revisit the
service/cost boundary only if product scope adds synchronization, hosted
recovery, or accounts.
