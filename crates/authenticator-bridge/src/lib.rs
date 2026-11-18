use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

const MAX_SECRET_BYTES: usize = 128;
const MAX_BASE32_BYTES: usize = 208;
const SNAPSHOT_MAGIC: &[u8; 4] = b"SOT1";
const SNAPSHOT_VERSION: u8 = 1;
const SNAPSHOT_HEADER_LEN: usize = 6;
const SNAPSHOT_NONCE_LEN: usize = 12;
const SNAPSHOT_KEY_LEN: usize = 32;
const MAX_SNAPSHOT_PLAINTEXT_BYTES: usize = 64 * 1024;
const MAX_SNAPSHOT_ENVELOPE_BYTES: usize =
    SNAPSHOT_HEADER_LEN + SNAPSHOT_NONCE_LEN + MAX_SNAPSHOT_PLAINTEXT_BYTES + 16;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestSnapshot {
    #[serde(rename = "formatVersion")]
    format_version: u8,
    project: String,
    instance: String,
    label: String,
}

/// Errors from the temporary encrypted snapshot interoperability spike.
///
/// These APIs and the envelope are test-only. They are not suitable for
/// protecting user backup data or establishing a production key hierarchy.
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum TestSnapshotError {
    #[error("test key must be exactly 32 bytes")]
    InvalidKey,
    #[error("test nonce must be exactly 12 bytes")]
    InvalidNonce,
    #[error("snapshot envelope is malformed")]
    InvalidEnvelope,
    #[error("snapshot envelope version is unsupported")]
    UnsupportedVersion,
    #[error("snapshot authentication failed")]
    AuthenticationFailed,
    #[error("snapshot JSON is invalid or exceeds the supported size")]
    InvalidSnapshot,
}

/// Encrypt a test snapshot JSON string into the temporary v1 envelope.
///
/// The caller supplies key and nonce to make cross-platform vectors
/// reproducible. Use only explicitly public synthetic fixtures here. This is
/// not a production backup API; nonce uniqueness for real keys is not provided.
#[uniffi::export]
pub fn encrypt_test_snapshot(
    key: Vec<u8>,
    nonce: Vec<u8>,
    snapshot_json: String,
) -> Result<Vec<u8>, TestSnapshotError> {
    if key.len() != SNAPSHOT_KEY_LEN {
        return Err(TestSnapshotError::InvalidKey);
    }
    if nonce.len() != SNAPSHOT_NONCE_LEN {
        return Err(TestSnapshotError::InvalidNonce);
    }
    let plaintext = Zeroizing::new(snapshot_json.into_bytes());
    validate_snapshot(&plaintext)?;

    let header = snapshot_header();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| TestSnapshotError::InvalidSnapshot)?;

    let mut envelope = Vec::with_capacity(header.len() + nonce.len() + ciphertext.len());
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Decrypt and validate a temporary v1 test snapshot envelope.
///
/// No plaintext, alternate version, or weaker-format fallback is attempted.
/// The returned JSON string is owned by the caller and must be handled as
/// sensitive data in real applications; this spike uses synthetic data only.
#[uniffi::export]
pub fn decrypt_test_snapshot(key: Vec<u8>, envelope: Vec<u8>) -> Result<String, TestSnapshotError> {
    if key.len() != SNAPSHOT_KEY_LEN {
        return Err(TestSnapshotError::InvalidKey);
    }
    if envelope.len() < SNAPSHOT_HEADER_LEN + SNAPSHOT_NONCE_LEN + 16
        || envelope.len() > MAX_SNAPSHOT_ENVELOPE_BYTES
    {
        return Err(TestSnapshotError::InvalidEnvelope);
    }
    if &envelope[..4] != SNAPSHOT_MAGIC {
        return Err(TestSnapshotError::InvalidEnvelope);
    }
    if envelope[4] != SNAPSHOT_VERSION {
        return Err(TestSnapshotError::UnsupportedVersion);
    }
    if envelope[5] != 0 {
        return Err(TestSnapshotError::InvalidEnvelope);
    }

    let header = &envelope[..SNAPSHOT_HEADER_LEN];
    let nonce = &envelope[SNAPSHOT_HEADER_LEN..SNAPSHOT_HEADER_LEN + SNAPSHOT_NONCE_LEN];
    let ciphertext = &envelope[SNAPSHOT_HEADER_LEN + SNAPSHOT_NONCE_LEN..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| TestSnapshotError::AuthenticationFailed)?,
    );
    validate_snapshot(&plaintext)?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| TestSnapshotError::InvalidSnapshot)
}

fn snapshot_header() -> [u8; SNAPSHOT_HEADER_LEN] {
    [
        SNAPSHOT_MAGIC[0],
        SNAPSHOT_MAGIC[1],
        SNAPSHOT_MAGIC[2],
        SNAPSHOT_MAGIC[3],
        SNAPSHOT_VERSION,
        0,
    ]
}

fn validate_snapshot(plaintext: &[u8]) -> Result<(), TestSnapshotError> {
    if plaintext.is_empty() || plaintext.len() > MAX_SNAPSHOT_PLAINTEXT_BYTES {
        return Err(TestSnapshotError::InvalidSnapshot);
    }
    let snapshot: TestSnapshot =
        serde_json::from_slice(plaintext).map_err(|_| TestSnapshotError::InvalidSnapshot)?;
    if snapshot.format_version != 1
        || snapshot.project.is_empty()
        || snapshot.instance.is_empty()
        || snapshot.label.is_empty()
    {
        return Err(TestSnapshotError::InvalidSnapshot);
    }
    Ok(())
}

#[cfg(test)]
mod snapshot_tests {
    use super::{
        decrypt_test_snapshot, encrypt_test_snapshot, snapshot_header, Aes256Gcm, Key, Nonce,
        Payload, TestSnapshotError, SNAPSHOT_HEADER_LEN, SNAPSHOT_NONCE_LEN,
    };
    use aes_gcm::aead::Aead;
    use aes_gcm::KeyInit;

    const KEY: [u8; 32] = [0x11; 32];
    const NONCE: [u8; 12] = [0x22; 12];
    const FIXTURE: &str = r#"{"formatVersion":1,"project":"synthetic-project","instance":"synthetic-instance","label":"Synthetic test entry"}"#;

    #[test]
    fn round_trips_synthetic_snapshot() {
        let envelope = encrypt_test_snapshot(KEY.to_vec(), NONCE.to_vec(), FIXTURE.to_owned())
            .expect("synthetic snapshot encrypts");
        assert_eq!(
            decrypt_test_snapshot(KEY.to_vec(), envelope),
            Ok(FIXTURE.to_owned())
        );
    }

    #[test]
    fn rejects_wrong_key_and_changed_ciphertext() {
        let envelope = encrypt_test_snapshot(KEY.to_vec(), NONCE.to_vec(), FIXTURE.to_owned())
            .expect("synthetic snapshot encrypts");
        assert_eq!(
            decrypt_test_snapshot(vec![0x33; 32], envelope.clone()),
            Err(TestSnapshotError::AuthenticationFailed)
        );

        let mut changed = envelope;
        *changed.last_mut().expect("tag exists") ^= 1;
        assert_eq!(
            decrypt_test_snapshot(KEY.to_vec(), changed),
            Err(TestSnapshotError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_unknown_or_modified_header_and_truncation() {
        let envelope = encrypt_test_snapshot(KEY.to_vec(), NONCE.to_vec(), FIXTURE.to_owned())
            .expect("synthetic snapshot encrypts");

        let mut unknown_version = envelope.clone();
        unknown_version[4] = 2;
        assert_eq!(
            decrypt_test_snapshot(KEY.to_vec(), unknown_version),
            Err(TestSnapshotError::UnsupportedVersion)
        );

        let mut changed_header = envelope.clone();
        changed_header[5] = 1;
        assert_eq!(
            decrypt_test_snapshot(KEY.to_vec(), changed_header),
            Err(TestSnapshotError::InvalidEnvelope)
        );

        for truncated in [
            Vec::new(),
            envelope[..SNAPSHOT_HEADER_LEN + SNAPSHOT_NONCE_LEN + 15].to_vec(),
        ] {
            assert_eq!(
                decrypt_test_snapshot(KEY.to_vec(), truncated),
                Err(TestSnapshotError::InvalidEnvelope)
            );
        }
    }

    #[test]
    fn rejects_invalid_keys_nonces_json_and_snapshot_shapes() {
        assert_eq!(
            encrypt_test_snapshot(vec![1; 31], NONCE.to_vec(), FIXTURE.to_owned()),
            Err(TestSnapshotError::InvalidKey)
        );
        assert_eq!(
            encrypt_test_snapshot(KEY.to_vec(), vec![2; 11], FIXTURE.to_owned()),
            Err(TestSnapshotError::InvalidNonce)
        );
        assert_eq!(
            encrypt_test_snapshot(KEY.to_vec(), NONCE.to_vec(), "not json".to_owned()),
            Err(TestSnapshotError::InvalidSnapshot)
        );
        assert_eq!(
            encrypt_test_snapshot(
                KEY.to_vec(),
                NONCE.to_vec(),
                FIXTURE.replace("\"formatVersion\":1", "\"formatVersion\":2"),
            ),
            Err(TestSnapshotError::InvalidSnapshot)
        );
        assert_eq!(
            decrypt_test_snapshot(vec![1; 31], Vec::new()),
            Err(TestSnapshotError::InvalidKey)
        );
    }

    #[test]
    fn rejects_authenticated_invalid_json_and_oversized_envelopes() {
        let header = snapshot_header();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&KEY));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&NONCE),
                Payload {
                    msg: b"not json",
                    aad: &header,
                },
            )
            .expect("test cipher encrypts");
        let mut invalid_json_envelope = header.to_vec();
        invalid_json_envelope.extend_from_slice(&NONCE);
        invalid_json_envelope.extend_from_slice(&ciphertext);
        assert_eq!(
            decrypt_test_snapshot(KEY.to_vec(), invalid_json_envelope),
            Err(TestSnapshotError::InvalidSnapshot)
        );

        assert_eq!(
            decrypt_test_snapshot(KEY.to_vec(), vec![0; 6 + 12 + 64 * 1024 + 17]),
            Err(TestSnapshotError::InvalidEnvelope)
        );
        assert_eq!(SNAPSHOT_NONCE_LEN, NONCE.len());
    }
}

macro_rules! hmac_calculator {
    ($digest:ty, $secret:expr, $counter:expr) => {{
        let mut mac =
            Hmac::<$digest>::new_from_slice($secret).expect("HMAC accepts keys of any length");
        mac.update($counter);
        mac.finalize().into_bytes().to_vec()
    }};
}

/// HMAC algorithm used to generate a time-based one-time password.
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1, the interoperable RFC 6238 baseline.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

/// Parameters for deterministic TOTP generation.
#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct TotpParameters {
    /// Length of the decimal code. Supported values are 6, 7, and 8.
    pub digits: u8,
    /// Duration of a time step in seconds. Must be greater than zero.
    pub period_seconds: u32,
    /// HMAC algorithm to use.
    pub algorithm: TotpAlgorithm,
}

/// Input validation failures from TOTP generation.
///
/// Error messages are deliberately generic and never include secret material.
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum TotpError {
    #[error("timestamp must be non-negative")]
    InvalidTimestamp,
    #[error("period must be greater than zero")]
    InvalidPeriod,
    #[error("digits must be 6, 7, or 8")]
    InvalidDigits,
    #[error("secret must not be empty")]
    EmptySecret,
    #[error("secret exceeds the supported size")]
    SecretTooLong,
    #[error("secret must be valid Base32")]
    InvalidSecretEncoding,
}

/// Generate a TOTP code for the supplied Unix timestamp.
///
/// The caller controls time; this function never reads a system clock. The
/// secret must be Base32-encoded and is accepted with or without RFC 4648
/// padding, in either case. Decoded secrets are limited to 128 bytes.
///
/// Secret buffers owned here are zeroized on drop where supported. Copies
/// made by the caller, FFI layer, compiler, or HMAC implementation may remain;
/// zeroization is best-effort and is not a guarantee about process memory.
#[uniffi::export]
pub fn generate_totp_code(
    secret_base32: String,
    unix_time_seconds: i64,
    parameters: TotpParameters,
) -> Result<String, TotpError> {
    if unix_time_seconds < 0 {
        return Err(TotpError::InvalidTimestamp);
    }
    if parameters.period_seconds == 0 {
        return Err(TotpError::InvalidPeriod);
    }
    if !(6..=8).contains(&parameters.digits) {
        return Err(TotpError::InvalidDigits);
    }

    let secret = decode_secret(secret_base32)?;
    let counter = (unix_time_seconds as u64) / u64::from(parameters.period_seconds);
    let counter_bytes = counter.to_be_bytes();
    let digest = match parameters.algorithm {
        TotpAlgorithm::Sha1 => hmac_calculator!(Sha1, &secret, &counter_bytes),
        TotpAlgorithm::Sha256 => hmac_calculator!(Sha256, &secret, &counter_bytes),
        TotpAlgorithm::Sha512 => hmac_calculator!(Sha512, &secret, &counter_bytes),
    };

    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.pow(u32::from(parameters.digits));
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = usize::from(parameters.digits)
    ))
}

fn decode_secret(secret_base32: String) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut normalized = Zeroizing::new(secret_base32);
    if normalized.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if normalized.len() > MAX_BASE32_BYTES {
        return Err(TotpError::SecretTooLong);
    }

    normalized.make_ascii_uppercase();
    let decoder = if normalized.as_bytes().contains(&b'=') {
        &BASE32
    } else {
        &BASE32_NOPAD
    };
    let decoded = Zeroizing::new(
        decoder
            .decode(normalized.as_bytes())
            .map_err(|_| TotpError::InvalidSecretEncoding)?,
    );
    if decoded.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if decoded.len() > MAX_SECRET_BYTES {
        return Err(TotpError::SecretTooLong);
    }
    Ok(decoded)
}

/// Returns a fixed message so native clients can prove they called this Rust library.
#[uniffi::export]
pub fn platform_message() -> String {
    "Hello from the shared Rust authenticator core".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{generate_totp_code, platform_message, TotpAlgorithm, TotpError, TotpParameters};
    use data_encoding::{BASE32, BASE32_NOPAD};

    fn parameters(algorithm: TotpAlgorithm, digits: u8) -> TotpParameters {
        TotpParameters {
            digits,
            period_seconds: 30,
            algorithm,
        }
    }

    fn base32(bytes: &[u8]) -> String {
        BASE32_NOPAD.encode(bytes)
    }

    #[test]
    fn returns_the_native_bridge_proof_message() {
        assert_eq!(
            platform_message(),
            "Hello from the shared Rust authenticator core"
        );
    }

    #[test]
    fn matches_rfc_6238_appendix_b_vectors() {
        let sha1_seed = b"12345678901234567890";
        let sha256_seed = b"12345678901234567890123456789012";
        let sha512_seed = b"1234567890123456789012345678901234567890123456789012345678901234";
        let vectors = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];

        for (timestamp, sha1, sha256, sha512) in vectors {
            assert_eq!(
                generate_totp_code(
                    base32(sha1_seed),
                    timestamp,
                    parameters(TotpAlgorithm::Sha1, 8)
                ),
                Ok(sha1.to_owned())
            );
            assert_eq!(
                generate_totp_code(
                    base32(sha256_seed),
                    timestamp,
                    parameters(TotpAlgorithm::Sha256, 8)
                ),
                Ok(sha256.to_owned())
            );
            assert_eq!(
                generate_totp_code(
                    base32(sha512_seed),
                    timestamp,
                    parameters(TotpAlgorithm::Sha512, 8)
                ),
                Ok(sha512.to_owned())
            );
        }
    }

    #[test]
    fn accepts_lowercase_unpadded_and_padded_base32() {
        let lower = base32(b"12345678901234567890").to_lowercase();
        assert_eq!(
            generate_totp_code(lower, 59, parameters(TotpAlgorithm::Sha1, 8)),
            Ok("94287082".to_owned())
        );

        let raw_seed = b"123456789012345678901";
        let padded = BASE32.encode(raw_seed);
        let unpadded = BASE32_NOPAD.encode(raw_seed);
        assert!(padded.ends_with('='));
        assert_eq!(
            generate_totp_code(padded, 59, parameters(TotpAlgorithm::Sha1, 8)),
            Ok("76798304".to_owned())
        );
        assert_eq!(
            generate_totp_code(unpadded, 59, parameters(TotpAlgorithm::Sha1, 8)),
            Ok("76798304".to_owned())
        );
    }

    #[test]
    fn enforces_digits_and_preserves_leading_zeroes() {
        let secret = base32(b"12345678901234567890");
        assert_eq!(
            generate_totp_code(secret.clone(), 59, parameters(TotpAlgorithm::Sha1, 6)),
            Ok("287082".to_owned())
        );
        assert_eq!(
            generate_totp_code(secret, 59, parameters(TotpAlgorithm::Sha1, 7)),
            Ok("4287082".to_owned())
        );
        assert_eq!(
            generate_totp_code(
                base32(b"12345678901234567890"),
                1_111_111_109,
                parameters(TotpAlgorithm::Sha1, 8)
            ),
            Ok("07081804".to_owned())
        );
    }

    #[test]
    fn uses_explicit_timestamp_and_handles_bounds() {
        let secret = base32(b"12345678901234567890");
        let params = parameters(TotpAlgorithm::Sha1, 8);
        assert_eq!(
            generate_totp_code(secret.clone(), 30, params),
            generate_totp_code(secret.clone(), 59, params)
        );
        assert_ne!(
            generate_totp_code(secret.clone(), 59, params),
            generate_totp_code(secret.clone(), 60, params)
        );
        assert!(generate_totp_code(secret.clone(), 0, params).is_ok());
        assert_eq!(
            generate_totp_code(secret.clone(), -1, params),
            Err(TotpError::InvalidTimestamp)
        );
        assert_eq!(
            generate_totp_code(secret.clone(), i64::MAX, params)
                .unwrap()
                .len(),
            8
        );
        assert_eq!(
            generate_totp_code(
                secret,
                0,
                TotpParameters {
                    period_seconds: u32::MAX,
                    ..params
                }
            )
            .unwrap()
            .len(),
            8
        );
    }

    #[test]
    fn rejects_invalid_parameters_and_secret_encodings_without_echoing_seed() {
        let params = parameters(TotpAlgorithm::Sha1, 8);
        assert_eq!(
            generate_totp_code(
                "A".to_owned(),
                0,
                TotpParameters {
                    period_seconds: 0,
                    ..params
                }
            ),
            Err(TotpError::InvalidPeriod)
        );
        for digits in [5, 9] {
            assert_eq!(
                generate_totp_code("A".to_owned(), 0, parameters(TotpAlgorithm::Sha1, digits)),
                Err(TotpError::InvalidDigits)
            );
        }
        assert_eq!(
            generate_totp_code(String::new(), 0, params),
            Err(TotpError::EmptySecret)
        );
        assert_eq!(
            generate_totp_code("SENSITIVE-SEED".to_owned(), 0, params),
            Err(TotpError::InvalidSecretEncoding)
        );
        assert_eq!(
            generate_totp_code("A=======".to_owned(), 0, params),
            Err(TotpError::InvalidSecretEncoding)
        );
        assert_eq!(
            TotpError::InvalidSecretEncoding.to_string(),
            "secret must be valid Base32"
        );
        assert!(!format!("{:?}", TotpError::InvalidSecretEncoding).contains("SENSITIVE-SEED"));
    }

    #[test]
    fn rejects_secrets_over_the_decoded_size_limit() {
        let oversized = base32(&[0x5a; 129]);
        assert_eq!(
            generate_totp_code(oversized, 0, parameters(TotpAlgorithm::Sha1, 6)),
            Err(TotpError::SecretTooLong)
        );
    }
}
