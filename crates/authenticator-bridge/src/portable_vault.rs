//! Synthetic implementation of the provisional portable vault envelope in ADR 0005.
//! This module is compiled for Rust tests only, with no native bridge entry point.

use aes_gcm::aead::{rand_core::RngCore, AeadInPlace, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;

use payload::SyntheticVault;
use zeroize::{Zeroize, Zeroizing};

const HEADER: &[u8; 8] = b"SOTV\x01\x01\x00\x00";
const WRAPPING_CONTEXT: &[u8] = b"org.getsotto.sotto-authenticator/portable-vault/v1/kek";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const SALT_END: usize = HEADER.len() + KEY_BYTES;
const WRAP_NONCE_END: usize = SALT_END + NONCE_BYTES;
const WRAPPED_KEY_END: usize = WRAP_NONCE_END + KEY_BYTES;
const WRAP_END: usize = WRAPPED_KEY_END + TAG_BYTES;
const PAYLOAD_START: usize = WRAP_END + NONCE_BYTES;
const OVERHEAD: usize = PAYLOAD_START + TAG_BYTES;
const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = OVERHEAD + MAX_PLAINTEXT_BYTES;

type SecretKey = Zeroizing<[u8; KEY_BYTES]>;

#[derive(Debug, PartialEq, Eq)]
enum ExportError {
    InvalidSize,
    InvalidHeader,
    UnsupportedSuite,
    AuthenticationFailed,
    InvalidPayload,
    RandomnessUnavailable,
    EncryptionFailed,
}

struct ExportRandomness {
    salt: [u8; KEY_BYTES],
    wrap_nonce: [u8; NONCE_BYTES],
    data_key: SecretKey,
    payload_nonce: [u8; NONCE_BYTES],
}

impl ExportRandomness {
    fn generate() -> Result<Self, ExportError> {
        let mut inputs = Self {
            salt: [0; KEY_BYTES],
            wrap_nonce: [0; NONCE_BYTES],
            data_key: Zeroizing::new([0; KEY_BYTES]),
            payload_nonce: [0; NONCE_BYTES],
        };
        for bytes in [
            &mut inputs.salt[..],
            &mut inputs.wrap_nonce[..],
            &mut inputs.data_key[..],
            &mut inputs.payload_nonce[..],
        ] {
            OsRng
                .try_fill_bytes(bytes)
                .map_err(|_| ExportError::RandomnessUnavailable)?;
        }
        Ok(inputs)
    }
}

fn export(vault: &SyntheticVault, entropy: &SecretKey) -> Result<Vec<u8>, ExportError> {
    let mut payload = vault.to_bytes(MAX_PLAINTEXT_BYTES)?;
    seal(&mut payload, entropy, ExportRandomness::generate()?)
}

fn seal(
    payload: &mut [u8],
    entropy: &SecretKey,
    randomness: ExportRandomness,
) -> Result<Vec<u8>, ExportError> {
    if payload.len() > MAX_PLAINTEXT_BYTES {
        return Err(ExportError::InvalidSize);
    }

    let mut envelope = Vec::with_capacity(OVERHEAD + payload.len());
    envelope.extend_from_slice(HEADER);
    envelope.extend_from_slice(&randomness.salt);
    let prk = extract(&randomness.salt, entropy);
    let wrapping_key = expand(&prk);
    let mut wrapped_key = randomness.data_key.clone();
    let wrap_tag = cipher(&wrapping_key)
        .encrypt_in_place_detached(
            Nonce::from_slice(&randomness.wrap_nonce),
            &envelope,
            &mut wrapped_key[..],
        )
        .map_err(|_| ExportError::EncryptionFailed)?;
    envelope.extend_from_slice(&randomness.wrap_nonce);
    envelope.extend_from_slice(&wrapped_key[..]);
    envelope.extend_from_slice(&wrap_tag);

    let payload_tag = cipher(&randomness.data_key)
        .encrypt_in_place_detached(
            Nonce::from_slice(&randomness.payload_nonce),
            &envelope,
            payload,
        )
        .map_err(|_| ExportError::EncryptionFailed)?;
    envelope.extend_from_slice(&randomness.payload_nonce);
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(&payload_tag);
    Ok(envelope)
}

fn open(envelope: &[u8], entropy: &SecretKey) -> Result<SyntheticVault, ExportError> {
    // Only the fixed fields and tags determine the minimum. The authenticated
    // JSON schema determines which plaintext lengths can actually be valid.
    if !(OVERHEAD..=MAX_ENVELOPE_BYTES).contains(&envelope.len()) {
        return Err(ExportError::InvalidSize);
    }
    if envelope[..4] != HEADER[..4] || envelope[6..8] != HEADER[6..8] {
        return Err(ExportError::InvalidHeader);
    }
    if envelope[4..6] != HEADER[4..6] {
        return Err(ExportError::UnsupportedSuite);
    }

    let prk = extract(&envelope[HEADER.len()..SALT_END], entropy);
    let wrapping_key = expand(&prk);
    let mut data_key = Zeroizing::new([0; KEY_BYTES]);
    data_key.copy_from_slice(&envelope[WRAP_NONCE_END..WRAPPED_KEY_END]);
    cipher(&wrapping_key)
        .decrypt_in_place_detached(
            Nonce::from_slice(&envelope[SALT_END..WRAP_NONCE_END]),
            &envelope[..SALT_END],
            &mut data_key[..],
            Tag::from_slice(&envelope[WRAPPED_KEY_END..WRAP_END]),
        )
        .map_err(|_| ExportError::AuthenticationFailed)?;

    let tag_start = envelope.len() - TAG_BYTES;
    let mut payload = Zeroizing::new(envelope[PAYLOAD_START..tag_start].to_vec());
    // Include the complete wrapping record so even a second valid wrap of this
    // same data key cannot authenticate the original payload.
    cipher(&data_key)
        .decrypt_in_place_detached(
            Nonce::from_slice(&envelope[WRAP_END..PAYLOAD_START]),
            &envelope[..WRAP_END],
            &mut payload,
            Tag::from_slice(&envelope[tag_start..]),
        )
        .map_err(|_| ExportError::AuthenticationFailed)?;

    SyntheticVault::from_bytes(&payload)
}

fn cipher(key: &SecretKey) -> Aes256Gcm {
    Aes256Gcm::new((&**key).into())
}

fn extract(salt: &[u8], entropy: &SecretKey) -> SecretKey {
    hmac_sha256(salt, &[&entropy[..]])
}

fn expand(prk: &SecretKey) -> SecretKey {
    // RFC 5869 Expand needs only its first block for a 32-byte SHA-256 output.
    hmac_sha256(&prk[..], &[WRAPPING_CONTEXT, &[1]])
}

fn hmac_sha256(key: &[u8], chunks: &[&[u8]]) -> SecretKey {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(key).expect("HMAC accepts any key size");
    for chunk in chunks {
        mac.update(chunk);
    }
    let mut block = mac.finalize().into_bytes();
    let mut secret = Zeroizing::new([0; KEY_BYTES]);
    secret.copy_from_slice(&block);
    block.as_mut_slice().zeroize();
    secret
}

mod payload;
mod recovery_phrase;
mod tests;
