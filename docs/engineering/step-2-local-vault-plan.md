# Step 2: local vault design and synthetic implementation plan

**Status:** proposed sequence. The key hierarchy and recovery decisions remain subject to maintainer review.

## Goal

Design a local-only vault that supports native mobile unlock and a portable
recovery path across supported platforms, without relying on hosted
infrastructure. Validate the design with synthetic fixtures before considering
real credentials.

Step 1 established the native iOS and Android clients, shared Rust core, and
initial platform behaviour. PR 12 characterised synthetic AES key protection.
Neither stage approved a production vault format, recovery scheme, or persistent
credential storage.

## Guardrails

- No real seeds, account records, project labels, or user exports in design
  spikes.
- No hosted service, sync, object storage, account system, or recurring
  infrastructure in this step.
- A device-bound key must not be the sole recovery path.
- Native code owns platform authentication and secure-storage APIs.
- The native/Rust boundary and the lifetime of plaintext and key copies must be
  specified before implementation.
- Future desktop and CLI compatibility must inform the portable format. Do not
  claim support for clients that have not shipped.
- Each PR should leave the app buildable and the synthetic test path usable.

## Pull request sequence

### Step 2 PR 01: key hierarchy and recovery direction

**This PR.** Propose separate paths for local device
unlock and user-controlled portable recovery. Compare device-only keys,
passphrase-derived vault keys, a random vault key with separate local and
portable protection, and hosted recovery. Record the product questions that
must be answered before detailed cryptographic or UX decisions.

**Exit criteria:** ADR 0003 has maintainer approval or concrete requested
changes. No implementation or real data is introduced.

### Step 2 PR 02: recovery factor and user journey

Decide how the user creates, confirms, stores, uses, replaces, and loses
portable recovery material. Compare a generated high-entropy secret with a
user-chosen passphrase. Define recovery failure messages and whether the first
export is an explicit user-managed file. Do not select KDF parameters here
unless the cryptographic design is reviewed with them.

**Exit criteria:** the recovery factor and its user-visible consequences are
approved; loss and replacement cases have acceptance criteria.

### Step 2 PR 03: portable envelope and cryptographic contract

Specify a versioned portable file that can be read independently of the
platform key store. Decide algorithms, derivation parameters where applicable,
nonce generation, authenticated fields, metadata visibility, import bounds,
duplicate handling, and error behaviour. Add synthetic test vectors and
negative cases before connecting persistent storage.

**Exit criteria:** independent review can verify the format and vectors from
the specification; no production credentials are used.

### Step 2 PR 04: shared vault domain boundary

Define the Rust/UniFFI operations for synthetic vault records and portable
envelopes. Keep platform authentication in native code. Document which key
operations happen natively or in Rust, every key/plaintext crossing, buffer
lifetimes, error mapping, and best-effort clearing. Keep project and instance
metadata private by default in examples.

**Exit criteria:** narrow APIs and ownership rules are documented and covered
by Rust-level synthetic tests. The interfaces do not accept an unbounded
payload or expose secret material in display strings or errors.

### Step 2 PR 05: iOS local-key adapter

Exercise the approved local protection model on iOS using synthetic keys.
Cover creation, unlock, cancellation, app relaunch, passcode and biometric
lifecycle where safe, and deletion. Keep unsupported simulator or hardware
behaviour explicit.

**Exit criteria:** supported iOS behaviour and known limitations are recorded;
the adapter does not silently fall back to unprotected storage.

### Step 2 PR 06: Android local-key adapter

Exercise the approved local protection model on Android using synthetic keys.
Cover configured authenticator policy, timeout, invalidation, backup/restore,
security level, and representative API/vendor behaviour where hardware is
available. Keep emulator-only evidence distinct from physical-device results.

**Exit criteria:** supported Android behaviour and API constraints are
recorded; the adapter does not silently fall back to unprotected storage.

### Step 2 PR 07: synthetic local vault persistence

Connect the approved domain boundary and native adapters to persist a small
synthetic vault. Exercise restart, unlock, wrong recovery material, modified
data, deletion, and migration without real seeds.

**Exit criteria:** records survive the intended local lifecycle, failures do
not produce partial or misleading success, and cleanup removes both stored
data and keys where the platform permits.

### Step 2 PR 08: cross-platform export and import

Implement explicit user-controlled export and import using synthetic records.
Test iOS-to-Android and Android-to-iOS interchange. Confirm that project,
instance, issuer, and account metadata follow the approved privacy rules.

**Exit criteria:** both clients consume each other's versioned export; malformed,
oversized, modified, and unsupported files fail without partial import.

### Step 2 PR 09: lifecycle and recovery review

Review lock and foreground behaviour, device loss, reinstall, passcode and
biometric changes, deletion, OS backup and restore, and recovery-material loss.
Update the threat model and record any support limits.

**Exit criteria:** every supported lifecycle has a test or explicit documented
limit, with no unresolved data-loss behaviour hidden behind a success state.

### Step 2 PR 10: real-credential readiness gate

Prepare a separate proposal for accepting real credentials. Include the
approved key and recovery decisions, privacy and diagnostics review, platform
coverage, migration and deletion behaviour, release controls, and independent
security review recommendation.

**Exit criteria:** maintainer approval is recorded before any implementation
accepts real TOTP seeds or account records. Passing this gate does not itself
claim an audit or production security.

## Sequence dependencies

```text
PR 01 key direction
  -> PR 02 recovery journey
  -> PR 03 portable crypto contract
  -> PR 04 Rust boundary
  -> PR 05 iOS adapter ----\
  -> PR 06 Android adapter --+-> PR 07 synthetic persistence
                                  -> PR 08 cross-platform export/import
                                  -> PR 09 lifecycle review
                                  -> PR 10 real-credential gate
```

The platform adapters can be developed in parallel only after PRs 01 to 04
settle the shared contracts. If the crypto review changes the format or key
boundary, update the plan before implementation proceeds.

## Current decision blockers

- Product must choose or direct investigation of the recovery factor and the
  consequences of losing it.
- Maintainers must approve the proposed separation of local unlock from
  portable recovery.
- The initial desktop and CLI compatibility targets are not specified.
- The native/Rust cryptographic boundary is not selected.
- No portable vault format, production key hierarchy, backup policy, or
  lifecycle policy is approved.

Until these blockers are resolved, implementation remains synthetic and local.
