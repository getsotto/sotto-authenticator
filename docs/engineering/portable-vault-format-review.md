# Portable vault format review evidence

The candidate export would let users move a project-aware vault between
devices using a file and a recovery phrase. The evidence below comes from
synthetic fixtures. The export format is provisional pending independent
cryptographic and platform review. [ADR 0005](../decisions/0005-portable-encrypted-vault-export.md)

## Evidence available

- **Interoperability.** A standalone Node.js writer and Python reader agreed
  on all 53 synthetic cases. These included empty and populated vaults, size
  limits, malformed authenticated JSON and an alternate wrapping record for
  the same data key. The public Rust suite reproduces one empty and one
  populated envelope byte for byte and tests rejection of the alternate
  wrapper. The populated fixture uses the same ID across record types and
  includes an escaped label with a multibyte character.
  [Envelope and payload tests](../../crates/authenticator-bridge/src/portable_vault/tests.rs)
- **Bounded restore reads.** The Rust preview accepts a valid envelope at the
  provisional limit. It stops after the first byte over the limit and
  rejects read failures even after receiving a valid envelope prefix.
  [Restore reader tests](../../crates/authenticator-bridge/src/portable_vault/tests.rs)
- **Recovery and failed exports.** Rust matches a public BIP-39 fixture
  and reopens an export using a re-entered phrase. The host SQLite fixture
  injects a partial failure at each of the four random reads. Each fails
  the export and keeps the reservation, and the next successful export opens
  with a new counter. [Phrase tests](../../crates/authenticator-bridge/src/portable_vault/recovery_phrase.rs) · [Durability tests](../../crates/authenticator-bridge/src/portable_vault/durability.rs)
- **Recovery rotation.** A host test seals a second export with a different
  phrase. Each file opens with its own phrase. After restoring the newer
  export, the older file still requires rollback acknowledgement and
  restoring it preserves the highest counter.
  [Restore tests](../../crates/authenticator-bridge/src/portable_vault/tests.rs)
- **Save retry.** A host test stages an export beside its destination. A
  partial write leaves the previous file intact. Retrying the same sealed
  bytes after reopening the counter store preserves the original counter.
  Mobile file providers and power-loss behaviour still need evidence.
  [Durability tests](../../crates/authenticator-bridge/src/portable_vault/durability.rs)
- **Restore consistency.** The host fixture preserves the highest observed
  counter after a deliberate rollback, rejects stale previews and recovers
  the previous vault and counter after an uncommitted writer exits.
  [Durability tests](../../crates/authenticator-bridge/src/portable_vault/durability.rs)
- **Release boundary.** The mobile artefact and binding checks showed that
  the portable vault prototype stayed in Rust tests. The existing native
  snapshot and TOTP bindings provide source evidence of where keys and
  plaintext can be copied. [Release boundary findings](portable-vault-release-boundary.md)
- **Decoded record text.** The prototype wraps owned, decoded project and
  instance names and entry labels in clearing buffers. Those allocations
  clear on drop, including when a preview is discarded. The decoder checks
  the UTF-8 byte limit before allocating the owned record text. JSON escape
  decoding can still use parser scratch space. Scratch buffers, identifiers
  and native copies still need review.
  [Payload types](../../crates/authenticator-bridge/src/portable_vault/payload.rs)
- **Decoded identifiers.** The parser checks the existing identifier syntax
  before creating an owned identifier. It checks sibling uniqueness during
  vault validation. Preview and counter history still retain their own
  copies of vault identifiers.
  [Payload types](../../crates/authenticator-bridge/src/portable_vault/payload.rs)

Run the published Rust checks from the repository root. The interrupted-write
test starts its own child fixture.

```sh
cargo test -p authenticator-bridge --locked portable_vault
```

## Nonce collision estimate for review

Count two 96-bit nonce draws per sealing attempt across all installations
in the workload under review. Count retries that seal again, including
attempts that fail before delivery. Copying an already sealed file adds no
draws. The estimate assumes independent, uniform random draws.
[Proposed key usage and retry policy](../decisions/0005-portable-encrypted-vault-export.md#proposed-key-usage-and-retry-policy)

With `m` draws there are `m * (m - 1) / 2` pairs. Each pair has probability
`2^-96` of repeating a nonce, so the sum bounds the chance of any repeat.
For an illustrative workload of `2^31` attempts, the bound for `2^32`
draws is strictly below `2^-33`. Counting all nonce repeats makes this
conservative even if the same encryption key appears in multiple attempts.
The GCM requirement concerns repeating a nonce with the same key for
distinct input data. [NIST SP 800-38D, sections 8 and 8.3](https://csrc.nist.gov/pubs/sp/800/38/d/final)

Reviewers still need to assess the workload over the supported lifetime
and the random-source assumptions across supported platforms, including
after backup and restore. The example leaves the lifetime limit open.

## Questions for independent review

1. Do the authenticated fields bind the complete wrapping record to the
   payload as intended? Are the one-use policy and collision assumptions
   appropriate across devices and repeated exports? [Nonce collision estimate](#nonce-collision-estimate-for-review)
2. Which schema and size limits are appropriate for supported mobile
   devices? How should mobile file pickers apply those limits before
   buffering, and how should clients report authenticated payload errors?
3. What should users see when local history is missing, stale or divergent?
   What mobile storage evidence is needed for atomic replacement and
   interrupted writes?
4. How should clients display and accept recovery words, and who owns each
   copy of the recovery material and decrypted records across the native
   boundary? Which clearing guarantees can each layer support?

The [production gates in ADR 0005](../decisions/0005-portable-encrypted-vault-export.md#decisions-requested)
require independent review, a published normative format and passing
cross-implementation vectors.
