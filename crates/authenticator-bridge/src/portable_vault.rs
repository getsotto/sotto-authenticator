//! Synthetic implementation of the provisional portable vault envelope in ADR 0005.
//! This module is compiled for Rust tests only, with no native bridge entry point.

use aes_gcm::aead::{rand_core::RngCore, AeadInPlace, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
const MIN_PAYLOAD_BYTES: usize = 109;
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_JSON_INTEGER: u64 = (1 << 53) - 1;

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

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SyntheticVault {
    format_version: u8,
    vault_id: String,
    export_counter: u64,
    issued_at: u64,
    // Nested records need a separately agreed schema before they can be restored.
    projects: [(); 0],
}

impl SyntheticVault {
    fn validate(&self) -> Result<(), ExportError> {
        if self.format_version != 1
            || self.vault_id.len() != 32
            || !self
                .vault_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(1..=MAX_JSON_INTEGER).contains(&self.export_counter)
            || self.issued_at > MAX_JSON_INTEGER
        {
            return Err(ExportError::InvalidPayload);
        }
        Ok(())
    }
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
    vault.validate()?;
    let mut payload = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *payload, vault).map_err(|_| ExportError::InvalidPayload)?;
    seal(&mut payload, entropy, ExportRandomness::generate()?)
}

fn seal(
    payload: &mut [u8],
    entropy: &SecretKey,
    randomness: ExportRandomness,
) -> Result<Vec<u8>, ExportError> {
    if !(MIN_PAYLOAD_BYTES..=MAX_PAYLOAD_BYTES).contains(&payload.len()) {
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
    if !(OVERHEAD + MIN_PAYLOAD_BYTES..=OVERHEAD + MAX_PAYLOAD_BYTES).contains(&envelope.len()) {
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

    let vault: SyntheticVault =
        serde_json::from_slice(&payload).map_err(|_| ExportError::InvalidPayload)?;
    vault.validate()?;
    Ok(vault)
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

#[test]
fn exports_same_synthetic_vault_with_fresh_randomness() {
    let vault = SyntheticVault {
        format_version: 1,
        vault_id: "0".repeat(32),
        export_counter: 1,
        issued_at: 0,
        projects: [],
    };
    let entropy = Zeroizing::new([0x23; KEY_BYTES]);
    let first = export(&vault, &entropy).expect("first export");
    let second = export(&vault, &entropy).expect("second export");
    assert_ne!(first, second);
    for envelope in [first, second] {
        let restored = open(&envelope, &entropy).expect("open synthetic vault");
        assert!(restored == vault);
    }
}
