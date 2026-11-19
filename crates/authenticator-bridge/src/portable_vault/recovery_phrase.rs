use aes_gcm::aead::{rand_core::RngCore, OsRng};
use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use super::{SecretKey, KEY_BYTES};

const WORD_COUNT: usize = 24;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RecoveryPhraseError {
    InvalidPhrase,
    RandomnessUnavailable,
}

// Keep the phrase as word indices in a zeroise-on-drop Mnemonic. Avoid
// exposing Debug, Clone or an owned string representation of the phrase.
pub(super) struct RecoveryPhrase(Mnemonic);

impl RecoveryPhrase {
    pub(super) fn generate() -> Result<Self, RecoveryPhraseError> {
        let mut entropy = Zeroizing::new([0; KEY_BYTES]);
        OsRng
            .try_fill_bytes(&mut entropy[..])
            .map_err(|_| RecoveryPhraseError::RandomnessUnavailable)?;
        Ok(Self::from_entropy(&entropy))
    }

    fn from_entropy(entropy: &SecretKey) -> Self {
        Self(
            Mnemonic::from_entropy_in(Language::English, &entropy[..])
                .expect("32 bytes encode as an English BIP-39 phrase"),
        )
    }

    pub(super) fn parse(input: &str) -> Result<Self, RecoveryPhraseError> {
        // The library accepts broader whitespace and other word counts. Check
        // Sotto's ASCII grammar before the library can interpret the input.
        if !input
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b' ' | b'\t' | b'\r' | b'\n'))
            || input.split_ascii_whitespace().take(WORD_COUNT + 1).count() != WORD_COUNT
        {
            return Err(RecoveryPhraseError::InvalidPhrase);
        }
        Mnemonic::parse_in_normalized(Language::English, input)
            .map(Self)
            .map_err(|_| RecoveryPhraseError::InvalidPhrase)
    }

    pub(super) fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.words()
    }

    pub(super) fn entropy(&self) -> Result<SecretKey, RecoveryPhraseError> {
        // The vault KDF consumes the encoded entropy, excluding the checksum.
        // BIP-39's separate wallet seed derivation is outside this path.
        let (bytes, len) = self.0.to_entropy_array();
        let bytes = Zeroizing::new(bytes);
        if len != KEY_BYTES {
            return Err(RecoveryPhraseError::InvalidPhrase);
        }
        let mut entropy = Zeroizing::new([0; KEY_BYTES]);
        entropy.copy_from_slice(&bytes[..KEY_BYTES]);
        Ok(entropy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_entropy_phrase() -> String {
        // Public 256-bit zero entropy vector from Trezor's BIP-39 fixtures.
        format!("{}art", "abandon ".repeat(23))
    }

    #[test]
    fn matches_the_public_bip39_vector_in_both_directions() {
        let entropy = Zeroizing::new([0; KEY_BYTES]);
        let phrase = RecoveryPhrase::from_entropy(&entropy);
        let expected = zero_entropy_phrase();
        assert!(phrase.words().eq(expected.split(' ')));
        let parsed = RecoveryPhrase::parse(&expected).unwrap();
        assert_eq!(&parsed.entropy().unwrap()[..], &entropy[..]);
    }

    #[test]
    fn generates_24_words_with_fresh_entropy() {
        let first = RecoveryPhrase::generate().unwrap();
        let second = RecoveryPhrase::generate().unwrap();
        assert_eq!(first.words().count(), WORD_COUNT);
        assert_eq!(second.words().count(), WORD_COUNT);
        assert!(first.entropy().unwrap() != second.entropy().unwrap());
    }

    #[test]
    fn rejects_unexpected_entropy_length_before_returning_key_material() {
        // Deliberately bypass the parser's word-count invariant.
        let phrase = RecoveryPhrase(Mnemonic::from_entropy(&[0; 16]).unwrap());
        assert_eq!(
            phrase.entropy().err(),
            Some(RecoveryPhraseError::InvalidPhrase)
        );
    }

    #[test]
    fn accepts_the_four_ascii_separators_and_leading_or_trailing_space() {
        let expected = zero_entropy_phrase();
        let mixed = format!("\r\n{} \t", expected.replace(' ', " \t\r\n"));
        let parsed = RecoveryPhrase::parse(&mixed).unwrap();
        assert!(parsed.words().eq(expected.split(' ')));
    }

    #[test]
    fn rejects_wrong_counts_bad_checksum_and_nonconforming_input() {
        let valid = zero_entropy_phrase();
        let other_valid_bip39_length = format!("{}about", "abandon ".repeat(11));
        for input in [
            other_valid_bip39_length,
            "abandon ".repeat(24).trim_end().to_owned(),
            format!("{valid} abandon"),
            valid.replacen("abandon", "Abandon", 1),
            valid.replacen("abandon", "aban", 1),
            valid.replacen("abandon", "notaword", 1),
            valid.replacen(' ', "\u{a0}", 1),
            valid.replacen(' ', "\u{b}", 1),
            valid.replacen(' ', "\u{c}", 1),
        ] {
            assert_eq!(
                RecoveryPhrase::parse(&input).err(),
                Some(RecoveryPhraseError::InvalidPhrase)
            );
        }
    }
}
