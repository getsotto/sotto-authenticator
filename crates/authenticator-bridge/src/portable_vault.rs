//! Synthetic implementation of the provisional portable vault envelope in ADR 0005.
//! This module is compiled for Rust tests only, with no native bridge entry point.

use aes_gcm::aead::{
    rand_core::{Error as RandomError, RngCore},
    AeadInPlace, KeyInit, OsRng,
};
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
        let mut rng = OsRng;
        Self::from_source(|bytes| rng.try_fill_bytes(bytes))
    }

    fn from_source(
        mut fill: impl FnMut(&mut [u8]) -> Result<(), RandomError>,
    ) -> Result<Self, ExportError> {
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
            fill(bytes).map_err(|_| ExportError::RandomnessUnavailable)?;
        }
        Ok(inputs)
    }
}

fn export(vault: &SyntheticVault, entropy: &SecretKey) -> Result<Vec<u8>, ExportError> {
    export_with_randomness(vault, entropy, ExportRandomness::generate)
}

fn export_with_randomness(
    vault: &SyntheticVault,
    entropy: &SecretKey,
    generate: impl FnOnce() -> Result<ExportRandomness, ExportError>,
) -> Result<Vec<u8>, ExportError> {
    let envelope = vault.encode(MAX_PLAINTEXT_BYTES, PAYLOAD_START, TAG_BYTES)?;
    seal_encoded(envelope, entropy, generate()?)
}

fn seal(
    payload: &[u8],
    entropy: &SecretKey,
    randomness: ExportRandomness,
) -> Result<Vec<u8>, ExportError> {
    if payload.len() > MAX_PLAINTEXT_BYTES {
        return Err(ExportError::InvalidSize);
    }

    let mut envelope = Zeroizing::new(vec![0; OVERHEAD + payload.len()]);
    envelope[PAYLOAD_START..PAYLOAD_START + payload.len()].copy_from_slice(payload);
    seal_encoded(envelope, entropy, randomness)
}

fn seal_encoded(
    mut envelope: Zeroizing<Vec<u8>>,
    entropy: &SecretKey,
    randomness: ExportRandomness,
) -> Result<Vec<u8>, ExportError> {
    let (prefix, body) = envelope.split_at_mut(PAYLOAD_START);
    let (payload, tag) = body.split_at_mut(body.len() - TAG_BYTES);
    prefix[..HEADER.len()].copy_from_slice(HEADER);
    prefix[HEADER.len()..SALT_END].copy_from_slice(&randomness.salt);
    let mut wrapped_key = randomness.data_key.clone();
    let wrap_tag = {
        let wrapping_key = expand(&extract(&randomness.salt, entropy));
        cipher(&wrapping_key)
            .encrypt_in_place_detached(
                Nonce::from_slice(&randomness.wrap_nonce),
                &prefix[..SALT_END],
                &mut wrapped_key[..],
            )
            .map_err(|_| ExportError::EncryptionFailed)?
    };
    prefix[SALT_END..WRAP_NONCE_END].copy_from_slice(&randomness.wrap_nonce);
    prefix[WRAP_NONCE_END..WRAPPED_KEY_END].copy_from_slice(&wrapped_key[..]);
    prefix[WRAPPED_KEY_END..WRAP_END].copy_from_slice(&wrap_tag);
    prefix[WRAP_END..].copy_from_slice(&randomness.payload_nonce);

    let payload_tag = cipher(&randomness.data_key)
        .encrypt_in_place_detached(
            Nonce::from_slice(&randomness.payload_nonce),
            &prefix[..WRAP_END],
            payload,
        )
        .map_err(|_| ExportError::EncryptionFailed)?;
    tag.copy_from_slice(&payload_tag);
    // The envelope now contains only ciphertext and public framing.
    Ok(std::mem::take(&mut *envelope))
}

fn open(envelope: &[u8], entropy: &SecretKey) -> Result<SyntheticVault, ExportError> {
    FramedEnvelope::validate(envelope)?;
    FramedEnvelope(Zeroizing::new(envelope.to_vec())).decode(entropy)
}

// The read buffer holds plaintext after the payload tag verifies.
struct FramedEnvelope(Zeroizing<Vec<u8>>);

impl FramedEnvelope {
    fn parse(envelope: Vec<u8>) -> Result<Self, ExportError> {
        Self::validate(&envelope)?;
        Ok(Self(Zeroizing::new(envelope)))
    }

    fn decode(mut self, entropy: &SecretKey) -> Result<SyntheticVault, ExportError> {
        SyntheticVault::from_bytes(self.decrypt(entropy)?, MAX_PLAINTEXT_BYTES)
    }

    fn validate(envelope: &[u8]) -> Result<(), ExportError> {
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
        Ok(())
    }

    fn decrypt(&mut self, entropy: &SecretKey) -> Result<&[u8], ExportError> {
        let envelope = &mut self.0;
        let mut data_key = Zeroizing::new([0; KEY_BYTES]);
        data_key.copy_from_slice(&envelope[WRAP_NONCE_END..WRAPPED_KEY_END]);
        {
            let wrapping_key = expand(&extract(&envelope[HEADER.len()..SALT_END], entropy));
            cipher(&wrapping_key)
                .decrypt_in_place_detached(
                    Nonce::from_slice(&envelope[SALT_END..WRAP_NONCE_END]),
                    &envelope[..SALT_END],
                    &mut data_key[..],
                    Tag::from_slice(&envelope[WRAPPED_KEY_END..WRAP_END]),
                )
                .map_err(|_| ExportError::AuthenticationFailed)?;
        }

        let (prefix, body) = envelope.split_at_mut(PAYLOAD_START);
        let (payload, tag) = body.split_at_mut(body.len() - TAG_BYTES);
        // Include the complete wrapping record so even a second valid wrap of this
        // same data key cannot authenticate the original payload.
        cipher(&data_key)
            .decrypt_in_place_detached(
                Nonce::from_slice(&prefix[WRAP_END..]),
                &prefix[..WRAP_END],
                payload,
                Tag::from_slice(tag),
            )
            .map_err(|_| ExportError::AuthenticationFailed)?;

        Ok(payload)
    }
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

#[cfg(test)]
mod durability;
mod payload;
mod recovery_phrase;
mod restore;
mod tests;
