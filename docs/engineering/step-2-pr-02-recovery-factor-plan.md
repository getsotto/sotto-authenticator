# Step 2 PR 02: recovery factor and user journey plan

**Status:** proposed decision work. This plan depends on maintainer review of
[ADR 0003](../decisions/0003-local-vault-key-hierarchy.md) and the PR 14
separation of local unlock from portable recovery.

## Objective

Resolve the product contract for portable recovery before selecting
cryptographic parameters or implementing a recovery flow. Record a reviewable
recommendation for the recovery factor, setup requirement, export scope, and
loss and replacement behaviour.

## Inputs

- [Step 2 PR 02 specification](step-2-pr-02-recovery-factor-spec.md)
- [ADR 0003: local vault key hierarchy and portable recovery](../decisions/0003-local-vault-key-hierarchy.md)
- [Local vault key hierarchy and recovery options](local-vault-key-hierarchy-options.md)
- Existing product direction: native mobile first, project aware, migration
  across platforms, future desktop and CLI support, and no hosted infrastructure
  in the initial local vault stage.

## Work sequence

### 1. Confirm the dependency

- Review the PR 14 direction: separate local device unlock from portable
  recovery.
- Do not treat ADR 0003 as accepted until maintainers record their decision.
- If the hierarchy direction changes, revise this specification before
  selecting a recovery journey.

### 2. Compare and select the recovery factor

- Compare a generated high-entropy recovery secret with a user-chosen
  passphrase.
- Record user effort, risk from weak or reused secrets, support for future
  clients, loss behaviour, and whether a password KDF is required.
- Record the selected factor as a proposed decision until product and
  maintainers approve it.
- Leave secret encoding, KDF choice and parameters, checksum, encryption
  construction, and file format for Step 2 PR 03.

### 3. Decide setup and export scope

- Decide whether recovery setup is mandatory before the first real credential
  is stored, or can be deferred with a clear warning.
- Decide whether the first user-controlled export contains the whole vault or
  supports project or instance selection.
- Preserve the user's project and instance groupings in either case.
- Record the reason for each choice and its user-facing consequence.

### 4. Finalise the recovery journeys

- Specify first-time creation and confirmation of recovery material.
- Specify local authentication before export and recovery rotation.
- Specify import on a new device and successful setup of a new local unlock
  path.
- Specify forgotten recovery material while an enrolled device is available.
- Specify total loss of device access and recovery material, including that no
  service-side reset exists.
- Specify the warning that existing exports remain protected by their original
  recovery material after rotation.

### 5. Record the decision and prepare the next gate

- Update the recovery-factor specification with accepted decisions and clearly
  labelled unresolved items.
- Record the accepted product contract in ADR 0003 or a small follow-up ADR.
- Update the Step 2 sequence so PR 03 starts only after the recovery factor and
  user journey are approved.
- Keep the PR docs-only. Do not add a key derivation, portable envelope,
  persistent store, or user credential handling.

## Acceptance criteria

- Product and maintainers approve the recovery-factor direction.
- The decision says whether setup is required before the first real credential
  and whether initial export is whole-vault or project scoped.
- All five journeys in the spec have an agreed outcome: setup, export, import,
  replacement, and total loss.
- It is clear that recovery material is separate from local authentication and
  that Sotto cannot reset it.
- The behaviour is usable by iOS and Android and does not depend on a service.
- Future desktop and CLI compatibility requirements are recorded without
  claiming those clients already exist.
- The spec names cryptographic choices reserved for PR 03.
- No application code, real credentials, or infrastructure changes are
  included.

## Review and verification

- Ask product reviewers to challenge the recovery and loss journey.
- Ask platform reviewers to challenge whether the proposed flows are
  implementable on iOS and Android.
- Ask a cryptography reviewer to identify any recovery-factor constraint that
  must be decided before PR 03.
- Run local Markdown link validation, `git diff --check`, and a secret scan.
- No application tests are expected for this documentation-only decision PR.

## Out of scope

Implementation of the recovery UI, KDF tuning, cryptographic test vectors,
portable file encoding, vault persistence, OS backup behaviour, and accepting
real TOTP credentials. These require later decisions and separately reviewable
PRs.
