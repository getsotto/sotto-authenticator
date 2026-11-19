# Step 2 PR 02: recovery factor and user journey specification

**Status:** draft for product and maintainer review. Depends on acceptance of the proposed direction in [ADR 0003](../decisions/0003-local-vault-key-hierarchy.md).

## Purpose

Choose a user-controlled recovery factor and define how a user creates, confirms,
uses, replaces, and loses it. The result should support portable migration
without a Sotto account or hosted recovery service.

This specification covers the product contract. It does not approve a
cryptographic format or permit persistent real credentials.

## Product context

Sotto Authenticator is project aware. A user's vault may contain entries across
several projects and instances, such as work and personal environments. The
portable recovery path must preserve those groupings and work across supported
mobile platforms. Future desktop and CLI clients should be able to implement
the same recovery contract.

The local unlock path and portable recovery path have different jobs:

- Local unlock uses the enrolled device and its native authentication and key
  storage.
- Portable recovery makes a user-managed export usable on another device or
  supported client.
- Neither path depends on a Sotto server, email account, or sync service.

## Requirements

1. Recovery must not rely on copying an iOS Keychain item or Android Keystore
   key to another device.
2. Recovery material must be separate from the device passcode, app unlock
   setting, TOTP seed, project name, and instance name.
3. An export and its recovery material must remain useful without access to a
   Sotto service.
4. The recovery factor must be usable on iOS, Android, and future desktop or
   CLI clients that support the portable format.
5. The app must explain that Sotto cannot reset lost recovery material.
6. Recovery material must not appear in application logs, crash reports,
   analytics, or status messages.
7. The app must distinguish a local vault from an exported recovery copy. A
   recovery factor by itself is not a backup of the vault.
8. The design must explain what happens when a user has lost recovery material
   but still has access to an enrolled device, and when both are lost.
9. The first supported export scope must be explicit. It must not silently
   omit project or instance groups.
10. All PR 02 examples and validation use synthetic data only.

## Recovery factor options

| Factor | Benefits | Costs and risks | Recommendation for review |
| --- | --- | --- | --- |
| Generated high-entropy recovery secret | Avoids relying on a user-created password and does not require a password KDF to compensate for low entropy. Can be generated consistently across platforms. | The user must store it safely. It cannot be recovered by Sotto. A representation that is easy to write and enter needs a reviewed encoding and error detection. | Preferred direction. Generate it from a cryptographically secure random source. Select the exact encoding and confirmation interaction in a later format and UX decision. |
| User-chosen passphrase | Familiar to many users and can be re-entered without storing a separate code. | Human-chosen phrases can be weak or reused. A stolen export can permit offline guessing, so a password KDF, parameters, and resource limits must be reviewed. Forgotten phrases cannot be reset without another recovery path. | Keep as an alternative if user research shows that a generated secret is too difficult to use. Do not treat an ordinary app password as an adequate export key. |
| Device credential or device-bound key only | Simple local unlock on one enrolled device. | Does not provide portable recovery to a different device or platform. | Reject as the sole recovery factor. |

### Proposed recommendation

Use a generated, high-entropy recovery secret as the portable recovery factor,
separate from native local unlock. The user supplies that secret when importing
an export on a new device. The active local vault remains protected by its
platform adapter.

This is a product recommendation, not an approved cryptographic design. The
secret's length, encoding, checksum, derivation, wrapping construction, and
envelope representation remain for Step 2 PR 03 and independent review.

## User journeys

### Create a vault and prepare recovery

1. The user creates a local vault. The native client establishes the approved
   local unlock path.
2. The app explains that device protection does not make the vault portable.
3. The app creates the proposed recovery material and explains that Sotto
   cannot retrieve or reset it.
4. The user records the recovery material outside the app.
5. The app asks the user to confirm that they can reproduce it. The exact
   confirmation interaction is still to be selected.
6. The app reports whether recovery setup is complete. It must not imply that
   the recovery material contains or backs up vault data.

**Decision required:** whether completing recovery setup is required before
the first credential can be added, or whether the user can defer it with a
clear warning. The recommendation is to require setup before storing the first
real credential, because otherwise the app accepts data without the portable
recovery capability that the product requires.

### Export the vault

1. The user authenticates locally and chooses an explicit export action.
2. The app creates a portable file protected by the recovery factor.
3. The app tells the user where the file was saved and that the recovery
   material must be kept separately from the file.
4. The user can transfer the file using their chosen method. Sotto does not
   upload or retain it.

**Decision required:** whether the first release exports the entire vault or
allows a selected project or instance. The recommendation is a whole-vault
export that preserves project and instance groupings. Partial export can be
considered later after its effect on references and user expectations is
specified.

### Import on another device or platform

1. The user chooses an import action and selects a portable export.
2. The app requests the recovery material separately.
3. The app validates and decrypts the export before changing the active vault.
4. The app sets up a new local unlock path for the destination device.
5. The app reports success only after the imported vault is available under the
   new local unlock path.

The file format, preview contents, duplicate handling, merge or replace
behaviour, and atomicity rules are assigned to Step 2 PR 03 and later
implementation planning.

### Replace lost recovery material on an enrolled device

1. The user authenticates to the existing local vault.
2. The app creates new recovery material and requires the user to confirm it.
3. The user creates a fresh export protected by the new recovery material.
4. The app explains that older exports still require the old recovery material.

This does not revoke or re-protect files the user exported previously. A later
format decision must define whether rotation changes any local key wrappers or
only creates a new portable export.

### Lose both the enrolled device and recovery material

The user cannot recover the vault through Sotto. The app, help desk, or
maintainers must not imply that support can reset the recovery factor. This
consequence must be presented before the user stores real credentials.

## Required messages and states

The user journey must provide distinct, non-secret-bearing states for:

- recovery setup required;
- recovery material displayed and awaiting confirmation;
- recovery setup complete;
- local authentication required before export or recovery rotation;
- export created and saved;
- recovery material rejected or export unable to be opened;
- import completed;
- import failed without changing the active vault;
- recovery material replaced, with a reminder about older exports;
- recovery cannot be reset when no enrolled device or recovery material is
  available.

Messages must not disclose whether a particular recovery secret is correct
before authenticated validation of the export. They must not include the
secret, key, plaintext record, or encrypted payload in logs or diagnostics.

## Out of scope for PR 02

- Selecting a concrete KDF, cipher, parameters, envelope schema, nonce format,
  checksum, or recovery-secret encoding.
- Implementing a vault, export, import, recovery factor, or account database.
- Deciding the Rust and native cryptographic operation boundary.
- Cloud sync, accounts, email delivery, remote reset, or hosted recovery.
- Import merging, conflict resolution, and partial project export mechanics.
- Accepting real TOTP seeds or account metadata.

## Acceptance criteria for the decision

- Maintainers accept or revise the recovery factor recommendation.
- The product decision records whether recovery setup is required before the
  first real credential is stored.
- The product decision records whole-vault or scoped export for the first
  release.
- Creation, confirmation, export, import, rotation, and total-loss journeys
  have an agreed outcome and user-facing consequence.
- The recovery secret is distinct from local device authentication, and no
  service-side reset is promised.
- The selected recovery factor remains implementable by iOS, Android, and
  future desktop or CLI clients.
- Cryptographic parameters and the portable format remain gated on Step 2 PR
  03 review.
- No implementation accepts real credentials as part of this decision.

## References

- [ADR 0003: local vault key hierarchy and portable recovery](../decisions/0003-local-vault-key-hierarchy.md)
- [Local vault key hierarchy and recovery options](local-vault-key-hierarchy-options.md)
- [Step 2 local vault plan](step-2-local-vault-plan.md)
