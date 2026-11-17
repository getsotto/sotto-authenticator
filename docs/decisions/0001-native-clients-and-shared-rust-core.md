# ADR 0001: Native clients with a shared Rust core

- Status: Accepted for the first implementation stage
- Date: 2026-11-16

## Context

Sotto Authenticator is intended to make managing MFA across work and personal projects feel clearer while remaining a functional authenticator. It should begin on mobile, use native platform capabilities, and leave room to expand to desktop and CLI clients. Early engineering must keep the infrastructure bill close to zero.

The first technical risk is whether native iOS and Android clients can use one shared implementation without compromising native app development or locking desktop and CLI clients out of the core.

## Decision

- Build separate native iOS and Android clients.
- Put shared authentication and domain logic in a Rust library.
- Use UniFFI-generated Swift and Kotlin bindings at the platform boundary.
- Keep UI, lifecycle, secure storage, and platform-specific integrations native to each OS.
- Validate the boundary with a no-secret proof function before implementing authentication behavior.
- Start without a backend dependency. The proof stage requires no hosted infrastructure.

## Consequences

This creates a reusable core for future desktop and CLI clients and keeps native APIs available for platform UX and secure storage. It also adds Rust FFI and native build tooling to each mobile build. UniFFI/JNA and generated artifacts must be reviewed as the integration matures; this proof does not decide storage, sync, recovery, backup, cryptography, or server architecture.

## Rejected for this stage

- A cross-platform UI framework: it would add a second platform abstraction before validating whether the shared domain core is sufficient.
- Separate authentication logic per mobile app: that would create behavior drift and duplicate security-sensitive implementation.
- A hosted service: no account or synchronization requirement is being implemented in this stage, and a service would create recurring cost without validating the core risk.

## Review trigger

Revisit this decision if the Rust boundary makes native accessibility, platform security, app delivery, or future desktop/CLI support materially harder than expected.
