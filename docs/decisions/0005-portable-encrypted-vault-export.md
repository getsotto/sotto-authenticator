# ADR 0005: portable encrypted vault export

- Status: revised proposal pending cryptographic and platform review
- Date: 2026-11-19
- Depends on: [ADR 0003: local vault key hierarchy and portable recovery](0003-local-vault-key-hierarchy.md), [ADR 0004: recovery factor and portable vault journey](0004-recovery-factor-and-portable-vault-journey.md)

## Context

The accepted recovery journey requires a user-managed export that can move a
whole project-aware vault between supported platforms without a Sotto account
or service. Local device keys cannot provide that portability. The export
format must also remain implementable by future desktop and CLI clients.

The existing `SOT1` snapshot is an interoperability spike for synthetic test
data. It accepts a caller-supplied key and nonce and is explicitly not a
production backup format. This proposal does not promote that test API.

## Proposed direction

- Represent the generated 256-bit recovery secret as a 24-word English BIP-39
  mnemonic. Use the mnemonic's encoded entropy bytes as the secret input and
  the mnemonic checksum to detect transcription errors. Do not apply BIP-39's
  wallet seed derivation to this application key hierarchy.
- Generate a fresh 256-bit data encryption key for each export. Derive a
  separate wrapping key using HKDF-SHA-256. Extract uses the fresh random salt
  and the generated recovery entropy. Expand uses a context assigned to
  wrapping. Reserve a distinct context for each key purpose.
- Wrap the data key with AES-256-GCM and authenticate the header and salt.
  Encrypt the complete vault with AES-256-GCM under the data key and
  authenticate the header, salt and complete wrapping record, including its
  nonce and tag. Use independently generated 96-bit nonces and full tags
  for both operations.
- Select a complete cryptographic suite by the envelope version and suite
  pair. Reject unknown pairs without fallback. Generate the recovery entropy,
  salt, data key and nonces internally using the operating system's secure
  random source. Restrict fixed inputs to synthetic fixtures.
- Use strict UTF-8 JSON with duplicate member rejection and schema validation.
  Version the payload schema independently of the envelope. Keep all vault
  records and metadata encrypted. Leave the envelope unpadded for the first
  format, which exposes the format identifier and encoded vault size.
- Treat an invalid mnemonic checksum, wrong recovery secret, or failed AEAD
  authentication as import failure. Authenticate and validate the entire
  export before preview or replacement.
- Include a vault identifier, export counter and issue date in the encrypted
  payload. Show the date and counter at preview. Require explicit confirmation
  before replacing a vault and warn if the counter is at or below the
  highest previously observed counter for that vault. Store the replacement
  and counter together. A fresh device has no local history for comparison,
  and disconnected devices can produce divergent export histories.

The byte layout, payload schema, parser bounds and client integration remain
subject to review before the format is final.

## Consequences

The format remains independent of Apple Keychain and Android Keystore and
requires no hosted service. Separating the wrapping and data keys separates
the two encryption operations. Binding the wrapping record to the payload
makes a substituted wrapper fail authentication, even if it unwraps to the
same data key. Recovery rotation therefore produces a fresh export with new
random inputs. Existing files still require their original recovery phrase.

The envelope has one wrapping record. Supporting additional recovery factors
would require a separate format decision. AES-GCM requires nonce uniqueness
per key. The implementation must document its randomness and invocation
limits. HKDF assumes the recovery material was generated with high entropy.
A future human-chosen passphrase would require its own password KDF decision.

## Decisions requested

Independent cryptographic and platform reviewers should assess:

1. The authenticated fields and the key and nonce lifecycle for both
   encryption operations, including after a failed export.
2. The payload schema, parser bounds and failure behaviour on supported clients.
3. The local counter lifecycle across restore, concurrent exports, and
   divergent export histories.

Do not implement this candidate as production export or accept real
credentials until the review is resolved, the normative format is published,
and cross-implementation vectors pass.

## References

- [BIP-39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) describes computer-generated entropy encoding and a mnemonic checksum. Sotto proposes to use the entropy encoding only, not the BIP-39 seed derivation.
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html) defines HMAC-based extract-and-expand key derivation and its context input.
- [RFC 5116: Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc5116.html) defines the AEAD interface and nonce uniqueness requirement.
