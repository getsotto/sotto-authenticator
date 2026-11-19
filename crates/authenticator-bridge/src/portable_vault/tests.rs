use super::*;
use data_encoding::HEXLOWER;

const EMPTY_VAULT: &str = r#"{"formatVersion":1,"vaultId":"00000000000000000000000000000000","exportCounter":1,"issuedAt":0,"projects":[]}"#;
// Public synthetic values from the independent Node writer and Python reader.
const NODE_ENVELOPE: &str = concat!(
    "534f5456010100000101010101010101010101010101010101010101010101010101010101010101",
    "111111111111111111111111",
    "f02ac1fb4f5d3415ce542dfc048e1ccef59e1a501f7da9e7d5919368fa6afed9ff623dcdec746e7f0907bdcc6d1b046e",
    "313131313131313131313131",
    "a03ba98bba6fe1aaa43ff804ba0724b5b3c6062880ac6da2fa8f3f5dc10545872f52dba3f0a9a3ddb7febe099eb3d51f9",
    "838c2ebd899570a0602dc3a097f961042fe9907a559c6dd57ed19ed086aaf839289cdcfe2dfbf46f8ea5c69003a720599",
    "01a468cda4e879aa7c377ad63157f8c4f97dfa58426869cbdec8240a",
);

fn node_entropy() -> SecretKey {
    Zeroizing::new(std::array::from_fn(|i| i as u8))
}

#[test]
fn matches_independent_envelope_and_key_derivation() {
    let expected = HEXLOWER.decode(NODE_ENVELOPE.as_bytes()).unwrap();
    let entropy = node_entropy();
    let prk = extract(&[1; KEY_BYTES], &entropy);
    assert_eq!(
        HEXLOWER.encode(&prk[..]),
        "41aba2df421ea8784e1b1c7b8cee5db547932361bae337615b237f8dea79e059"
    );
    assert_eq!(
        HEXLOWER.encode(&expand(&prk)[..]),
        "989a4b0d05dfe2191e9b66ff575929549a3cd2e5563850966ed69576e21b2283"
    );
    let inputs = ExportRandomness {
        salt: [1; KEY_BYTES],
        wrap_nonce: [0x11; NONCE_BYTES],
        data_key: Zeroizing::new([0x21; KEY_BYTES]),
        payload_nonce: [0x31; NONCE_BYTES],
    };
    assert_eq!(
        seal(&mut EMPTY_VAULT.as_bytes().to_vec(), &entropy, inputs).unwrap(),
        expected
    );
    let vault = open(&expected, &entropy).unwrap();
    assert_eq!(serde_json::to_string(&vault).unwrap(), EMPTY_VAULT);
}

#[test]
fn rejects_a_valid_replacement_wrapper_for_the_same_data_key() {
    let entropy = node_entropy();
    let data_key_bytes = [0x21; KEY_BYTES];
    let mut envelope = seal(
        &mut EMPTY_VAULT.as_bytes().to_vec(),
        &entropy,
        ExportRandomness {
            salt: [2; KEY_BYTES],
            wrap_nonce: [0x12; NONCE_BYTES],
            data_key: Zeroizing::new(data_key_bytes),
            payload_nonce: [0x32; NONCE_BYTES],
        },
    )
    .unwrap();
    assert!(open(&envelope, &entropy).is_ok());
    let kek = expand(&extract(&envelope[HEADER.len()..SALT_END], &entropy));
    let alternate_nonce = [0xf0; NONCE_BYTES];
    let mut same_key = data_key_bytes;
    let alternate_tag = cipher(&kek)
        .encrypt_in_place_detached(
            Nonce::from_slice(&alternate_nonce),
            &envelope[..SALT_END],
            &mut same_key,
        )
        .unwrap();

    envelope[SALT_END..WRAP_NONCE_END].copy_from_slice(&alternate_nonce);
    envelope[WRAP_NONCE_END..WRAPPED_KEY_END].copy_from_slice(&same_key);
    envelope[WRAPPED_KEY_END..WRAP_END].copy_from_slice(&alternate_tag);
    assert_eq!(
        open(&envelope, &entropy).err(),
        Some(ExportError::AuthenticationFailed)
    );
}

#[test]
fn rejects_incomplete_unsupported_and_altered_envelopes() {
    let entropy = node_entropy();
    let envelope = HEXLOWER.decode(NODE_ENVELOPE.as_bytes()).unwrap();
    for end in 0..envelope.len() {
        let error = if end < OVERHEAD {
            ExportError::InvalidSize
        } else {
            ExportError::AuthenticationFailed
        };
        assert_eq!(
            open(&envelope[..end], &entropy).err(),
            Some(error),
            "truncated to {end} bytes"
        );
    }
    for (offset, error) in [
        (0, ExportError::InvalidHeader),
        (4, ExportError::UnsupportedSuite),
        (5, ExportError::UnsupportedSuite),
        (7, ExportError::InvalidHeader),
        (HEADER.len(), ExportError::AuthenticationFailed),
        (SALT_END, ExportError::AuthenticationFailed),
        (WRAP_NONCE_END, ExportError::AuthenticationFailed),
        (WRAPPED_KEY_END, ExportError::AuthenticationFailed),
        (WRAP_END, ExportError::AuthenticationFailed),
        (PAYLOAD_START, ExportError::AuthenticationFailed),
        (envelope.len() - 1, ExportError::AuthenticationFailed),
    ] {
        let mut changed = envelope.clone();
        changed[offset] ^= 1;
        assert_eq!(open(&changed, &entropy).err(), Some(error), "byte {offset}");
    }
    assert_eq!(
        open(&envelope, &Zeroizing::new([0xff; KEY_BYTES])).err(),
        Some(ExportError::AuthenticationFailed)
    );
    let mut trailing = envelope;
    trailing.push(0);
    assert_eq!(
        open(&trailing, &entropy).err(),
        Some(ExportError::AuthenticationFailed)
    );
}

#[test]
fn validates_authenticated_json_before_returning_a_vault() {
    let entropy = node_entropy();
    for json in [
        EMPTY_VAULT.replace(r#""projects":[]"#, r#""projects":[],"projec\u0074s":[]"#),
        EMPTY_VAULT.replace(r#""projects":[]"#, r#""projects":[{}]"#),
        EMPTY_VAULT.replace(r#""projects":[]"#, r#""projects":null"#),
        EMPTY_VAULT.replace(r#""formatVersion":1"#, r#""formatVersion":2"#),
        EMPTY_VAULT.replace(r#""exportCounter":1"#, r#""exportCounter":0"#),
        EMPTY_VAULT.replace(r#""issuedAt":0"#, r#""issuedAt":9007199254740992"#),
        format!("{EMPTY_VAULT}{{}}"),
    ] {
        let envelope = seal(
            &mut json.into_bytes(),
            &entropy,
            ExportRandomness::generate().unwrap(),
        )
        .unwrap();
        assert_eq!(
            open(&envelope, &entropy).err(),
            Some(ExportError::InvalidPayload)
        );
    }
}

#[test]
fn rejects_an_authenticated_array_of_positional_fields() {
    // Match the object fixture's size so this case reaches JSON validation.
    let mut payload = br#"[1,"00000000000000000000000000000000",1,0,[]]"#.to_vec();
    payload.resize(EMPTY_VAULT.len(), b' ');
    let entropy = node_entropy();
    let envelope = seal(
        &mut payload,
        &entropy,
        ExportRandomness::generate().unwrap(),
    )
    .unwrap();
    assert_eq!(
        open(&envelope, &entropy).err(),
        Some(ExportError::InvalidPayload)
    );
}

#[test]
fn validates_short_authenticated_payloads_at_the_json_boundary() {
    let entropy = node_entropy();
    for mut payload in [Vec::new(), b"{}".to_vec()] {
        let envelope = seal(
            &mut payload,
            &entropy,
            ExportRandomness::generate().unwrap(),
        )
        .unwrap();
        assert_eq!(envelope.len(), OVERHEAD + payload.len());
        assert_eq!(
            open(&envelope, &entropy).err(),
            Some(ExportError::InvalidPayload)
        );
    }
}

#[test]
fn bounds_the_payload_at_one_mebibyte() {
    let entropy = node_entropy();
    let mut bytes = EMPTY_VAULT.as_bytes().to_vec();
    bytes.resize(MAX_PAYLOAD_BYTES, b' ');
    let mut envelope = seal(&mut bytes, &entropy, ExportRandomness::generate().unwrap()).unwrap();
    assert_eq!(envelope.len(), OVERHEAD + MAX_PAYLOAD_BYTES);
    assert!(open(&envelope, &entropy).is_ok());

    envelope.push(0);
    assert_eq!(
        open(&envelope, &entropy).err(),
        Some(ExportError::InvalidSize)
    );
    bytes.push(b' ');
    assert_eq!(
        seal(&mut bytes, &entropy, ExportRandomness::generate().unwrap()).err(),
        Some(ExportError::InvalidSize)
    );
}
