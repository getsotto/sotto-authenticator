use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

const MAX_SECRET_BYTES: usize = 128;
const MAX_BASE32_BYTES: usize = 208;

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
