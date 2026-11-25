# Portable vault release boundary

The provisional portable vault in [ADR 0005](../decisions/0005-portable-encrypted-vault-export.md)
includes recovery phrases, deterministic test inputs and a host SQLite
transaction fixture. The mobile builds exclude these Rust test modules.
The earlier [SOT1 snapshot experiment](cross-platform-encrypted-snapshot.md)
still runs through the native apps with public synthetic data. Its two
entry points remain alongside the TOTP function and the bridge smoke function.

## Reproduce the boundary check

```sh
./scripts/generate-bindings.sh
./scripts/build-rust-ios.sh
./scripts/build-rust-android.sh
./scripts/check-portable-vault-release.sh
```

The check reads Cargo's recorded source inputs and normal dependency graph for
each mobile target. The bridge's direct `tempfile` dependency is test-only.
UniFFI also depends on `tempfile` transitively. The check also rejects
test-only features on shared dependencies. These are the `zeroize` features
on AES, AES-GCM and SHA-2, `rc` on Serde and `serde` on Zeroize.

The check compares the UniFFI entry points in each packaged iOS static
archive and Android shared library with those in the generated Swift, C and
Kotlin bindings. Update the expected entry points when the bridge interface
changes deliberately.

## Buffer ownership at the current boundary

Swift encodes strings as UTF-8 and copies them into a Rust buffer. Kotlin
encodes strings into a byte buffer and copies the bytes into a Rust buffer.
Both bindings serialise the SOT1 key bytes before UniFFI lifts them into a
Rust vector. The SOT1 functions wrap that vector in `Zeroizing`. The
decryption path copies the validated plaintext into the returned string.
The bindings lift that string into the caller and free the Rust return buffer
without explicitly clearing it.
The original native inputs, the serialised key copies and the returned
plaintext are outside the lifetime of the Rust wrappers.

The TOTP function wraps its Base32 string when decoding starts and wraps the
decoded seed on success. Timestamp and parameter validation precede decoding.
Native copies and HMAC working state sit outside those wrappers. A future
portable vault interface needs an ownership and clearing strategy for
recovery material and decrypted records across the full native call. These
observations come from tracing the source and generated bindings.
