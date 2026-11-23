# Portable vault format review evidence

The candidate export would let users move a project-aware vault between
devices using a file and a recovery phrase. The evidence below comes from
synthetic fixtures. The export format is provisional pending independent
cryptographic and platform review. [ADR 0005](../decisions/0005-portable-encrypted-vault-export.md)

## Evidence available

- **Interoperability.** A standalone Node.js writer and Python reader agreed
  on all 52 synthetic cases. These included empty and populated vaults, size
  limits, malformed authenticated JSON and an alternate wrapping record for
  the same data key. The public Rust suite reproduces the empty-vault
  envelope byte for byte and tests populated round trips and rejection of
  the alternate wrapper. [Envelope and payload tests](../../crates/authenticator-bridge/src/portable_vault/tests.rs)
- **Recovery and failed exports.** Rust matches a public BIP-39 fixture
  and reopens an export using a re-entered phrase. The host SQLite fixture
  injects a partial failure at each of the four random reads. Each fails
  the export and keeps the reservation, and the next successful export opens
  with a new counter. [Phrase tests](../../crates/authenticator-bridge/src/portable_vault/recovery_phrase.rs) · [Durability tests](../../crates/authenticator-bridge/src/portable_vault/durability.rs)
- **Restore consistency.** The host fixture preserves the highest observed
  counter after a deliberate rollback, rejects stale previews and recovers
  the previous vault and counter after an uncommitted writer exits.
  [Durability tests](../../crates/authenticator-bridge/src/portable_vault/durability.rs)
- **Release boundary.** The mobile artefact and binding checks showed that
  the portable vault prototype stayed in Rust tests. The existing native
  snapshot and TOTP bindings provide source evidence of where keys and
  plaintext can be copied. [Release boundary findings](portable-vault-release-boundary.md)

Run the published Rust checks from the repository root. The interrupted-write
test starts its own child fixture.

```sh
cargo test -p authenticator-bridge --locked portable_vault
```

## Questions for independent review

1. Do the authenticated fields bind the complete wrapping record to the
   payload as intended? What key and nonce usage limits should apply across
   repeated exports and retries?
2. Which schema and size limits are appropriate for supported mobile
   devices? How should clients reject an oversized file before buffering it
   and report authenticated payload errors?
3. What should users see when local history is missing, stale or divergent?
   What mobile storage evidence is needed for atomic replacement and
   interrupted writes?
4. How should clients display and accept recovery words, and who owns each
   copy of the recovery material and decrypted records across the native
   boundary? Which clearing guarantees can each layer support?

The [production gates in ADR 0005](../decisions/0005-portable-encrypted-vault-export.md#decisions-requested)
require independent review, a published normative format and passing
cross-implementation vectors.
