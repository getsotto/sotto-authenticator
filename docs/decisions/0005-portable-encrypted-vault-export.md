# ADR 0005: portable encrypted vault export

- Status: proposed; independent cryptographic review required
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
- Derive a 256-bit export key from the recovery entropy and a fresh 256-bit
  random salt using HKDF-SHA-256 with fixed Sotto-specific context. The
  recovery entropy has high entropy, so this is not a password-hardening
  design. User-chosen passphrases are not supported as the sole recovery
  factor.
- Encrypt the complete canonical vault payload with AES-256-GCM. Generate a
  fresh 96-bit nonce for each export. Put the fixed header and public salt in
  authenticated associated data. Keep project and instance names, labels,
  and all vault records encrypted.
- Use a compact, versioned binary envelope with a fixed header, salt, nonce,
  and ciphertext including the authentication tag. Reject unknown versions,
  unsupported suites, malformed input, and inputs beyond reviewed limits.
- Generate recovery entropy, salt, and nonce only with an operating-system
  cryptographically secure random source. Do not use caller-provided values
  outside deterministic synthetic test vectors.
- Treat an invalid mnemonic checksum, wrong recovery secret, or failed AEAD
  authentication as import failure. Do not return partial plaintext or mutate
  the active vault before the entire export has been authenticated and
  validated.

This is a candidate, not an accepted production protocol. The exact byte
layout, canonical payload encoding, bounds, import error mapping, and random
number API remain open until reviewed. The public format and deterministic
synthetic vectors must be published before another client is expected to
interoperate.

## Consequences

The format remains independent of Apple Keychain and Android Keystore. A
separate salt gives each export a distinct derived key with overwhelming
probability, while a fresh nonce is used for the AEAD operation. The design
adds no hosted service or recurring infrastructure cost. A 24-word secret
requires careful setup and confirmation UX; a lost secret cannot be reset.

AES-GCM requires that a nonce not repeat for a given key. The implementation
must use a reviewed CSPRNG and document the relevant limits. Because the
recovery secret is generated rather than user chosen, HKDF is used for key
separation and extraction, not to slow offline guesses. If the product later
allows a human-chosen passphrase, it requires a separate decision and a
password KDF designed for that threat.

## Decisions requested

Independent cryptographic and platform reviewers should assess:

1. Whether BIP-39 entropy encoding is suitable for Sotto recovery material,
   given that the application will not use its wallet seed derivation.
2. Whether HKDF-SHA-256 with a random salt and fixed context is appropriate
   for the generated high-entropy recovery input.
3. Whether AES-256-GCM with random 96-bit nonces is appropriate for this
   bounded, single-payload export and how its invocation limits should be
   expressed.
4. Whether the proposed single-key envelope is preferable to a wrapped
   per-export data key for the supported rotation and recovery journeys.
5. What canonical payload encoding, parser bounds, and failure behaviour are
   required before a format can be implemented.

Do not implement this candidate as production export or accept real
credentials until the review is resolved, the normative format is published,
and cross-implementation vectors pass.

## References

- [BIP-39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) describes computer-generated entropy encoding and a mnemonic checksum. Sotto proposes to use the entropy encoding only, not the BIP-39 seed derivation.
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html) defines HMAC-based extract-and-expand key derivation and its context input.
- [RFC 5116: Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc5116.html) defines the AEAD interface and nonce uniqueness requirement.
