# Deterministic TOTP core

PR 02 adds an RFC 6238 code generator to the shared Rust library. Native callers
provide the Base32 seed, Unix timestamp, and all TOTP parameters. The core does
not read the system clock or choose implicit defaults.

## Supported inputs

- HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512.
- 6, 7, or 8 decimal digits.
- Any non-zero period representable by `u32`, in seconds.
- Unix timestamps from zero through `i64::MAX` seconds.
- RFC 4648 Base32 secrets, upper or lower case, with or without canonical
  padding; decoded secrets must contain 1–128 bytes.

Malformed input returns a typed, generic error. Error text does not include the
seed. The parameter record contains no secret, and the secret is passed as a
separate function argument.

## Secret lifetime and limits

The owned encoded string and decoded byte buffer are zeroized on drop where
supported by the Rust `zeroize` crate. Copies or temporary buffers inside the
caller, FFI layer, Base32 decoder, compiler, or HMAC implementation are outside
this guarantee. Short keys are accepted for interoperability with existing
authenticator seeds; RFC 6238 recommends a key whose length matches the HMAC
output. This API note and passing published vectors do not certify account
storage, backups, device security, or the product as a whole.

## Interoperability evidence

Unit tests use all six timestamp/code examples from RFC 6238 Appendix B for
each supported algorithm. The vectors establish deterministic algorithm
compatibility; they are not a security audit.
