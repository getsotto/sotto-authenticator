use super::*;
use data_encoding::HEXLOWER;
use recovery_phrase::RecoveryPhrase;

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
fn exports_same_synthetic_vault_with_fresh_randomness() {
    let vault = SyntheticVault::from_bytes(EMPTY_VAULT.as_bytes()).unwrap();
    let entropy = Zeroizing::new([0x23; KEY_BYTES]);
    let first = export(&vault, &entropy).expect("first export");
    let second = export(&vault, &entropy).expect("second export");
    assert_ne!(first, second);
    for envelope in [first, second] {
        let restored = open(&envelope, &entropy).expect("open synthetic vault");
        assert!(restored == vault);
    }
}

#[test]
fn a_reentered_recovery_phrase_opens_a_synthetic_export() {
    let vault = SyntheticVault::from_bytes(EMPTY_VAULT.as_bytes()).unwrap();
    let (envelope, written_words) = {
        let phrase = RecoveryPhrase::generate().unwrap();
        let envelope = export(&vault, &phrase.entropy().unwrap()).unwrap();
        // Keep this simulated copy of the phrase within the test.
        let mut written_words = Zeroizing::new(String::with_capacity(24 * 9));
        for (index, word) in phrase.words().enumerate() {
            if index != 0 {
                written_words.push(' ');
            }
            written_words.push_str(word);
        }
        (envelope, written_words)
    };
    let restored_phrase = RecoveryPhrase::parse(&written_words).unwrap();
    assert!(open(&envelope, &restored_phrase.entropy().unwrap()).unwrap() == vault);

    let wrong_phrase = RecoveryPhrase::generate().unwrap();
    assert_eq!(
        open(&envelope, &wrong_phrase.entropy().unwrap()).err(),
        Some(ExportError::AuthenticationFailed)
    );
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
fn accepts_json_whitespace_and_checks_the_provisional_metadata_rules() {
    let entropy = node_entropy();
    let vault_id = "abcdef0123456789abcdef0123456789";
    let json = EMPTY_VAULT.replace(&"0".repeat(32), vault_id);
    let mut padded = format!(" \t\r\n{json}\n").into_bytes();
    let envelope = seal(&mut padded, &entropy, ExportRandomness::generate().unwrap()).unwrap();
    let vault = open(&envelope, &entropy).unwrap();
    assert_eq!(vault.vault_id, vault_id);
    assert_eq!(vault.export_counter, 1);
    assert_eq!(vault.issued_at, 0);

    for mut payload in [
        json.replace(vault_id, &vault_id.to_ascii_uppercase())
            .into_bytes(),
        format!("\u{feff}{json}").into_bytes(),
    ] {
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
}

#[test]
fn rejects_an_authenticated_array_of_positional_fields() {
    let mut payload = br#"[1,"00000000000000000000000000000000",1,0,[]]"#.to_vec();
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

fn populated_payload(projects: usize, instances: usize, entries: usize) -> serde_json::Value {
    use serde_json::json;

    let mut next_id = 0;
    let mut id = || {
        next_id += 1;
        format!("{next_id:032x}")
    };
    let projects: Vec<_> = (0..projects)
        .map(|_| {
            let instances: Vec<_> = (0..instances)
                .map(|_| {
                    let entries: Vec<_> = (0..entries)
                        .map(|_| json!({"id": id(), "label": "synthetic café"}))
                        .collect();
                    json!({"id": id(), "name": "synthetic staging", "entries": entries})
                })
                .collect();
            json!({"id": id(), "name": "synthetic project", "instances": instances})
        })
        .collect();
    let mut vault: serde_json::Value = serde_json::from_str(EMPTY_VAULT).unwrap();
    vault["projects"] = json!(projects);
    vault
}

#[test]
fn round_trips_nested_projects_instances_and_entries() {
    let original = populated_payload(2, 2, 3);
    let vault = SyntheticVault::from_bytes(original.to_string().as_bytes()).unwrap();
    let entropy = node_entropy();
    let envelope = export(&vault, &entropy).unwrap();
    let restored = open(&envelope, &entropy).unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&restored.to_bytes().unwrap()).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn rejects_authenticated_invalid_nested_records() {
    let original = populated_payload(2, 1, 1);
    let mut cases = Vec::new();

    let mut duplicate = original.clone();
    duplicate["projects"][1]["instances"][0]["entries"][0]["id"] =
        original["projects"][0]["id"].clone();
    cases.push((
        "duplicate across record types and projects",
        duplicate.to_string(),
    ));

    let mut positional = original.clone();
    let project = &original["projects"][0];
    positional["projects"][0] =
        serde_json::json!([project["id"], project["name"], project["instances"]]);
    cases.push(("positional project", positional.to_string()));

    let mut positional_instance = original.clone();
    let instance = &original["projects"][0]["instances"][0];
    positional_instance["projects"][0]["instances"][0] =
        serde_json::json!([instance["id"], instance["name"], instance["entries"]]);
    cases.push(("positional instance", positional_instance.to_string()));

    let mut positional_entry = original.clone();
    let entry = &original["projects"][0]["instances"][0]["entries"][0];
    positional_entry["projects"][0]["instances"][0]["entries"][0] =
        serde_json::json!([entry["id"], entry["label"]]);
    cases.push(("positional entry", positional_entry.to_string()));

    for (case, field, value) in [
        ("credential field", "seed", serde_json::Value::Null),
        (
            "external parent reference",
            "instanceId",
            original["projects"][0]["id"].clone(),
        ),
        ("oversized UTF-8 label", "label", "é".repeat(65).into()),
        ("blank label", "label", " ".into()),
        (
            "control character in label",
            "label",
            "synthetic\nlabel".into(),
        ),
        ("invalid identity", "id", "not-a-record-id".into()),
    ] {
        let mut invalid = original.clone();
        invalid["projects"][0]["instances"][0]["entries"][0][field] = value;
        cases.push((case, invalid.to_string()));
    }
    cases.push((
        "duplicate escaped nested field",
        original.to_string().replacen(
            r#""label":"synthetic café""#,
            r#""label":"synthetic café","labe\u006c":"duplicate""#,
            1,
        ),
    ));

    let entropy = node_entropy();
    for (case, json) in cases {
        let envelope = seal(
            &mut json.into_bytes(),
            &entropy,
            ExportRandomness::generate().unwrap(),
        )
        .unwrap();
        assert_eq!(
            open(&envelope, &entropy).err(),
            Some(ExportError::InvalidPayload),
            "{case}"
        );
    }
}

#[test]
fn accepts_each_collection_limit_and_rejects_one_more_item() {
    for (accepted, rejected) in [
        ((32, 0, 0), (33, 0, 0)),
        ((1, 16, 0), (1, 17, 0)),
        ((1, 1, 64), (1, 1, 65)),
    ] {
        let (projects, instances, entries) = accepted;
        let valid = populated_payload(projects, instances, entries).to_string();
        assert!(SyntheticVault::from_bytes(valid.as_bytes()).is_ok());
        let (projects, instances, entries) = rejected;
        let too_many = populated_payload(projects, instances, entries).to_string();
        assert_eq!(
            SyntheticVault::from_bytes(too_many.as_bytes()).err(),
            Some(ExportError::InvalidPayload)
        );
    }
}

#[test]
fn rejects_a_valid_record_tree_above_the_total_size_cap() {
    let mut large = populated_payload(16, 16, 64);
    for project in large["projects"].as_array_mut().unwrap() {
        for instance in project["instances"].as_array_mut().unwrap() {
            for entry in instance["entries"].as_array_mut().unwrap() {
                entry["label"] = "e".repeat(128).into();
            }
        }
    }
    // Individually valid collections and labels can still exceed the envelope cap.
    let vault: SyntheticVault = serde_json::from_value(large).unwrap();
    assert_eq!(
        export(&vault, &node_entropy()).err(),
        Some(ExportError::InvalidSize)
    );
}
