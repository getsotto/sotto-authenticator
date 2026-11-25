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

pub(super) fn node_entropy() -> SecretKey {
    Zeroizing::new(std::array::from_fn(|i| i as u8))
}

#[test]
fn aes_round_keys_use_clearing_on_drop() {
    use aes_gcm::{aead::consts::U12, AesGcm};

    fn requires_clearing_on_drop<Aes: zeroize::ZeroizeOnDrop>(_: &AesGcm<Aes, U12>) {}

    requires_clearing_on_drop(&cipher(&node_entropy()));
}

#[test]
fn hkdf_hash_state_uses_clearing_on_drop() {
    fn requires_clearing_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    requires_clearing_on_drop::<Sha256>();
}

#[test]
fn exports_same_synthetic_vault_with_fresh_randomness() {
    let vault = SyntheticVault::from_bytes(EMPTY_VAULT.as_bytes(), MAX_PLAINTEXT_BYTES).unwrap();
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
    let vault = SyntheticVault::from_bytes(EMPTY_VAULT.as_bytes(), MAX_PLAINTEXT_BYTES).unwrap();
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
fn matches_the_independent_populated_vault_envelope() {
    // The same ID appears in all three record types. The label includes a
    // multibyte character and JSON escapes to exercise the encoded bytes.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        entropy_hex: String,
        plaintext: String,
        envelope_hex: String,
        replacement_wrapping_record_hex: String,
    }

    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/populated-vault.json")).unwrap();
    let expected = HEXLOWER.decode(fixture.envelope_hex.as_bytes()).unwrap();
    let entropy = SecretKey::new(
        HEXLOWER
            .decode(fixture.entropy_hex.as_bytes())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let json = fixture.plaintext;
    let vault = SyntheticVault::from_bytes(json.as_bytes(), MAX_PLAINTEXT_BYTES).unwrap();
    let mut payload = vault.to_bytes(MAX_PLAINTEXT_BYTES).unwrap();
    assert_eq!(&payload[..], json.as_bytes());

    // Public fixed inputs used by the independent Node.js and Python fixture.
    let randomness = ExportRandomness {
        salt: [0x11; KEY_BYTES],
        wrap_nonce: [0x21; NONCE_BYTES],
        data_key: Zeroizing::new([0x31; KEY_BYTES]),
        payload_nonce: [0x41; NONCE_BYTES],
    };
    assert_eq!(seal(&mut payload, &entropy, randomness).unwrap(), expected);
    assert!(open(&expected, &entropy).unwrap() == vault);

    let mut replaced = expected;
    let replacement_record = HEXLOWER
        .decode(fixture.replacement_wrapping_record_hex.as_bytes())
        .unwrap();
    replaced[SALT_END..WRAP_END].copy_from_slice(&replacement_record);
    assert_eq!(
        open(&replaced, &entropy).err(),
        Some(ExportError::AuthenticationFailed)
    );
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
    bytes.resize(MAX_PLAINTEXT_BYTES, b' ');
    let mut envelope = seal(&mut bytes, &entropy, ExportRandomness::generate().unwrap()).unwrap();
    assert_eq!(OVERHEAD, 128);
    assert_eq!(envelope.len(), OVERHEAD + MAX_PLAINTEXT_BYTES);
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
    let mut original = populated_payload(2, 2, 3);
    let repeated_id = original["projects"][0]["id"].clone();
    // The same text can identify a project and its child records. A
    // different project can also have an instance with that local ID.
    original["projects"][0]["instances"][0]["id"] = repeated_id.clone();
    original["projects"][0]["instances"][0]["entries"][0]["id"] = repeated_id.clone();
    original["projects"][0]["instances"][1]["entries"][0]["id"] = repeated_id.clone();
    original["projects"][1]["instances"][0]["id"] = repeated_id;
    let vault =
        SyntheticVault::from_bytes(original.to_string().as_bytes(), MAX_PLAINTEXT_BYTES).unwrap();
    let entropy = node_entropy();
    let envelope = export(&vault, &entropy).unwrap();
    let restored = open(&envelope, &entropy).unwrap();
    let decoded: serde_json::Value =
        serde_json::from_slice(&restored.to_bytes(MAX_PLAINTEXT_BYTES).unwrap()).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn preserves_label_text_within_the_utf8_byte_limit() {
    let mut original = populated_payload(1, 1, 4);
    let project = &mut original["projects"][0];
    project["name"] = "".into();
    project["instances"][0]["name"] = " \t".into();
    let entries = project["instances"][0]["entries"].as_array_mut().unwrap();
    for (entry, label) in entries.iter_mut().zip([
        String::new(),
        String::from("  "),
        String::from("synthetic\nline\u{0}"),
        "é".repeat(64),
    ]) {
        entry["label"] = label.into();
    }
    let vault =
        SyntheticVault::from_bytes(original.to_string().as_bytes(), MAX_PLAINTEXT_BYTES).unwrap();
    let entropy = node_entropy();
    let restored = open(&export(&vault, &entropy).unwrap(), &entropy).unwrap();
    let decoded: serde_json::Value =
        serde_json::from_slice(&restored.to_bytes(MAX_PLAINTEXT_BYTES).unwrap()).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn rejects_authenticated_invalid_nested_records() {
    let original = populated_payload(2, 2, 2);
    let mut cases = Vec::new();

    let mut duplicate_project = original.clone();
    duplicate_project["projects"][1]["id"] = original["projects"][0]["id"].clone();
    cases.push(("duplicate projects", duplicate_project.to_string()));
    let mut duplicate_instance = original.clone();
    duplicate_instance["projects"][0]["instances"][1]["id"] =
        original["projects"][0]["instances"][0]["id"].clone();
    cases.push((
        "duplicate instances in one project",
        duplicate_instance.to_string(),
    ));
    let mut duplicate_entry = original.clone();
    duplicate_entry["projects"][0]["instances"][0]["entries"][1]["id"] =
        original["projects"][0]["instances"][0]["entries"][0]["id"].clone();
    cases.push((
        "duplicate entries in one instance",
        duplicate_entry.to_string(),
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
        assert!(SyntheticVault::from_bytes(valid.as_bytes(), MAX_PLAINTEXT_BYTES).is_ok());
        let (projects, instances, entries) = rejected;
        let too_many = populated_payload(projects, instances, entries).to_string();
        assert_eq!(
            SyntheticVault::from_bytes(too_many.as_bytes(), MAX_PLAINTEXT_BYTES).err(),
            Some(ExportError::InvalidPayload)
        );
    }
}

#[test]
fn applies_export_size_policy_separately_from_schema_validation() {
    let mut large = populated_payload(16, 16, 64);
    for project in large["projects"].as_array_mut().unwrap() {
        for instance in project["instances"].as_array_mut().unwrap() {
            for entry in instance["entries"].as_array_mut().unwrap() {
                entry["label"] = "e".repeat(128).into();
            }
        }
    }
    let plaintext = large.to_string();
    assert!(plaintext.len() > MAX_PLAINTEXT_BYTES);
    assert_eq!(
        SyntheticVault::from_bytes(plaintext.as_bytes(), MAX_PLAINTEXT_BYTES).err(),
        Some(ExportError::InvalidSize)
    );
    let vault = SyntheticVault::from_bytes(plaintext.as_bytes(), plaintext.len()).unwrap();
    assert_eq!(
        export(&vault, &node_entropy()).err(),
        Some(ExportError::InvalidSize)
    );
}

pub(super) fn synthetic_recovery_phrase(entropy: &SecretKey) -> String {
    // This helper is only for the public, deterministic test entropy.
    bip39::Mnemonic::from_entropy(&entropy[..])
        .unwrap()
        .words()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn previews_authenticated_metadata_against_history_for_the_same_vault() {
    use restore::{RestoreHistory, RestoreState};
    use std::collections::BTreeMap;

    let vault_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let other_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut original = populated_payload(2, 2, 1);
    original["vaultId"] = vault_id.into();
    original["issuedAt"] = 1_700_000_000_u64.into();
    original["exportCounter"] = 7.into();
    let vault =
        SyntheticVault::from_bytes(original.to_string().as_bytes(), MAX_PLAINTEXT_BYTES).unwrap();
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let envelope = export(&vault, &entropy).unwrap();

    for (known_counter, expected) in [
        (None, RestoreHistory::NoLocalHistory),
        (Some(6), RestoreHistory::HigherCounterFreshnessUnknown),
        (Some(7), RestoreHistory::OlderOrEqual),
        (Some(8), RestoreHistory::OlderOrEqual),
    ] {
        let mut history = BTreeMap::from([(other_id.to_owned(), 200)]);
        if let Some(counter) = known_counter {
            history.insert(vault_id.to_owned(), counter);
        }
        let state = RestoreState::new(None, history);
        let pending = state.prepare_restore(envelope.as_slice(), &phrase).unwrap();
        let preview = pending.preview();
        assert_eq!(preview.history, expected);
        assert_eq!(preview.vault_id, vault_id);
        assert_eq!(preview.issued_at, 1_700_000_000);
        assert_eq!(preview.export_counter, 7);
        // Opening or discarding a preview does not advance either counter.
        drop(pending);
        assert!(state.active().is_none());
        assert_eq!(state.highest_counter(vault_id), known_counter);
        assert_eq!(state.highest_counter(other_id), Some(200));
    }
}

#[test]
fn restore_reader_stops_at_the_first_byte_over_the_limit() {
    use restore::{PreviewError, RestoreState};
    use std::io::{self, Read};

    let state = RestoreState::new(None, Default::default());
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let mut payload = EMPTY_VAULT.as_bytes().to_vec();
    payload.resize(MAX_PLAINTEXT_BYTES, b' ');
    let envelope = seal(
        &mut payload,
        &entropy,
        ExportRandomness::generate().unwrap(),
    )
    .unwrap();
    assert_eq!(envelope.len(), MAX_ENVELOPE_BYTES);

    let pending = state.prepare_restore(envelope.as_slice(), &phrase).unwrap();
    assert_eq!(pending.preview().export_counter, 1);

    let mut trailing = io::repeat(0).take(64);
    let oversized = envelope.as_slice().chain(&mut trailing);
    assert_eq!(
        state.prepare_restore(oversized, &phrase).err(),
        Some(PreviewError::InvalidFile)
    );
    assert_eq!(trailing.limit(), 63);
}

#[test]
fn restore_reader_returns_no_preview_when_the_stream_fails_before_eof() {
    use restore::{PreviewError, RestoreState};
    use std::io::{self, Read};

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic read failure"))
        }
    }

    let active = restore_fixture("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 7, 1);
    let state = RestoreState::new(Some(active.clone()), Default::default());
    let phrase = synthetic_recovery_phrase(&node_entropy());
    let envelope = HEXLOWER.decode(NODE_ENVELOPE.as_bytes()).unwrap();
    // A complete authentic envelope still needs EOF before it can be previewed.
    let reader = envelope.as_slice().chain(FailingReader);

    assert_eq!(
        state.prepare_restore(reader, &phrase).err(),
        Some(PreviewError::ReadFailed)
    );
    assert!(state.active() == Some(&active));
    assert_eq!(state.highest_counter(&active.vault_id), Some(7));
}

#[test]
fn rejects_invalid_phrase_or_export_before_returning_any_preview() {
    use restore::{PreviewError, RestoreState};
    use std::collections::BTreeMap;

    let state = RestoreState::new(None, BTreeMap::new());
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let wrong_phrase = synthetic_recovery_phrase(&Zeroizing::new([0xff; KEY_BYTES]));
    let vault = SyntheticVault::from_bytes(EMPTY_VAULT.as_bytes(), MAX_PLAINTEXT_BYTES).unwrap();
    let envelope = export(&vault, &entropy).unwrap();
    let mut unread = std::io::Cursor::new(envelope.as_slice());
    assert_eq!(
        state.prepare_restore(&mut unread, "invalid phrase").err(),
        Some(PreviewError::InvalidPhrase)
    );
    assert_eq!(unread.position(), 0);
    assert_eq!(
        state
            .prepare_restore(envelope.as_slice(), &wrong_phrase)
            .err(),
        Some(PreviewError::CannotOpen)
    );
    for offset in [WRAPPED_KEY_END, envelope.len() - 1] {
        let mut tampered = envelope.clone();
        tampered[offset] ^= 1;
        assert_eq!(
            state.prepare_restore(tampered.as_slice(), &phrase).err(),
            Some(PreviewError::CannotOpen)
        );
    }
    let invalid_payload = seal(
        &mut b"{}".to_vec(),
        &entropy,
        ExportRandomness::generate().unwrap(),
    )
    .unwrap();
    assert_eq!(
        state
            .prepare_restore(invalid_payload.as_slice(), &phrase)
            .err(),
        Some(PreviewError::InvalidFile)
    );
}

pub(super) fn restore_fixture(vault_id: &str, counter: u64, projects: usize) -> SyntheticVault {
    let mut json = populated_payload(projects, 1, 2);
    json["vaultId"] = vault_id.into();
    json["exportCounter"] = counter.into();
    SyntheticVault::from_bytes(json.to_string().as_bytes(), MAX_PLAINTEXT_BYTES).unwrap()
}

#[test]
fn recovery_rotation_preserves_old_exports_and_local_history() {
    use restore::{ConfirmError, PreviewError, RestoreConfirmation, RestoreHistory, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let original = restore_fixture(id, 6, 1);
    let mut source = RestoreState::new(Some(original.clone()), Default::default());
    let old_entropy = node_entropy();
    let new_entropy = Zeroizing::new([0xff; KEY_BYTES]);
    let old_phrase = synthetic_recovery_phrase(&old_entropy);
    let new_phrase = synthetic_recovery_phrase(&new_entropy);
    let old_export = source
        .reserve_export(1)
        .unwrap()
        .seal(&old_entropy)
        .unwrap();
    let new_export = source
        .reserve_export(2)
        .unwrap()
        .seal(&new_entropy)
        .unwrap();

    let mut destination = RestoreState::new(None, Default::default());
    for (envelope, wrong_phrase) in [(&old_export, &new_phrase), (&new_export, &old_phrase)] {
        assert_eq!(
            destination
                .prepare_restore(envelope.as_slice(), wrong_phrase)
                .err(),
            Some(PreviewError::CannotOpen)
        );
    }
    assert!(destination.active().is_none());
    assert_eq!(destination.highest_counter(id), None);

    let pending = destination
        .prepare_restore(new_export.as_slice(), &new_phrase)
        .unwrap();
    assert_eq!(pending.preview().history, RestoreHistory::NoLocalHistory);
    pending
        .confirm(&mut destination, RestoreConfirmation::Replace)
        .unwrap();
    let mut expected = original;
    expected.export_counter = 8;
    expected.issued_at = 2;
    assert!(destination.active() == Some(&expected));
    assert_eq!(destination.highest_counter(id), Some(8));

    let older = destination
        .prepare_restore(old_export.as_slice(), &old_phrase)
        .unwrap();
    assert_eq!(older.preview().export_counter, 7);
    assert_eq!(older.preview().history, RestoreHistory::OlderOrEqual);
    assert_eq!(
        older.confirm(&mut destination, RestoreConfirmation::Replace),
        Err(ConfirmError::RollbackAcknowledgementRequired)
    );
    assert!(destination.active() == Some(&expected));
    destination
        .prepare_restore(old_export.as_slice(), &old_phrase)
        .unwrap()
        .confirm(&mut destination, RestoreConfirmation::ReplaceOlderOrEqual)
        .unwrap();
    expected.export_counter = 7;
    expected.issued_at = 1;
    assert!(destination.active() == Some(&expected));
    assert_eq!(destination.highest_counter(id), Some(8));
}

#[test]
fn confirms_a_replacement_and_records_its_counter() {
    use restore::{RestoreConfirmation, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let other_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let current = restore_fixture(other_id, 55, 1);
    let mut state = RestoreState::new(Some(current), Default::default());
    let incoming = restore_fixture(id, 7, 2);
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let envelope = export(&incoming, &entropy).unwrap();
    let pending = state.prepare_restore(envelope.as_slice(), &phrase).unwrap();
    assert_eq!(state.active().unwrap().vault_id, other_id);
    assert_eq!(state.highest_counter(id), None);

    pending
        .confirm(&mut state, RestoreConfirmation::Replace)
        .unwrap();
    assert!(state.active() == Some(&incoming));
    assert_eq!(state.highest_counter(id), Some(7));
    assert_eq!(state.highest_counter(other_id), Some(55));
}

#[test]
fn cancelling_a_restore_leaves_an_existing_vault_and_counters_intact() {
    use restore::RestoreState;

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut state = RestoreState::new(Some(restore_fixture(id, 11, 1)), Default::default());
    let original = restore_fixture(id, 11, 1);
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let envelope = export(&restore_fixture(id, 12, 2), &entropy).unwrap();

    // Dropping the prepared restore is the cancellation path.
    drop(state.prepare_restore(envelope.as_slice(), &phrase).unwrap());
    assert!(state.active() == Some(&original));
    assert_eq!(state.highest_counter(id), Some(11));

    // A later confirmation still works against the same untouched state.
    use restore::RestoreConfirmation;
    state
        .prepare_restore(envelope.as_slice(), &phrase)
        .unwrap()
        .confirm(&mut state, RestoreConfirmation::Replace)
        .unwrap();
    assert_eq!(state.highest_counter(id), Some(12));
}

#[test]
fn requires_acknowledgement_for_older_and_equal_restores_and_keeps_the_highest_counter() {
    use restore::{ConfirmError, RestoreConfirmation, RestoreHistory, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    for counter in [9, 10] {
        let original = restore_fixture(id, 10, 1);
        let mut state = RestoreState::new(Some(restore_fixture(id, 10, 1)), Default::default());
        let incoming = restore_fixture(id, counter, 2);
        let envelope = export(&incoming, &entropy).unwrap();

        let pending = state.prepare_restore(envelope.as_slice(), &phrase).unwrap();
        assert_eq!(pending.preview().history, RestoreHistory::OlderOrEqual);
        assert_eq!(
            pending.confirm(&mut state, RestoreConfirmation::Replace),
            Err(ConfirmError::RollbackAcknowledgementRequired)
        );
        assert!(state.active() == Some(&original));
        assert_eq!(state.highest_counter(id), Some(10));

        let pending = state.prepare_restore(envelope.as_slice(), &phrase).unwrap();
        pending
            .confirm(&mut state, RestoreConfirmation::ReplaceOlderOrEqual)
            .unwrap();
        assert!(state.active() == Some(&incoming));
        assert_eq!(state.highest_counter(id), Some(10));
    }
}

#[test]
fn invalidates_an_open_preview_after_a_different_replacement_with_the_same_counter() {
    use restore::{ConfirmError, RestoreConfirmation, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut state = RestoreState::new(Some(restore_fixture(id, 7, 0)), Default::default());
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let first = export(&restore_fixture(id, 7, 1), &entropy).unwrap();
    let replacement = restore_fixture(id, 7, 2);
    let second = export(&replacement, &entropy).unwrap();

    let stale = state.prepare_restore(first.as_slice(), &phrase).unwrap();
    state
        .prepare_restore(second.as_slice(), &phrase)
        .unwrap()
        .confirm(&mut state, RestoreConfirmation::ReplaceOlderOrEqual)
        .unwrap();

    assert_eq!(
        stale.confirm(&mut state, RestoreConfirmation::ReplaceOlderOrEqual),
        Err(ConfirmError::PreviewChanged)
    );
    assert!(state.active() == Some(&replacement));
    assert_eq!(state.highest_counter(id), Some(7));
}

#[test]
fn a_preview_cannot_confirm_against_a_different_restore_state() {
    use restore::{ConfirmError, RestoreConfirmation, RestoreState};

    let from = RestoreState::new(None, Default::default());
    let mut to = RestoreState::new(None, Default::default());
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let envelope = export(&restore_fixture(id, 12, 1), &entropy).unwrap();
    let pending = from.prepare_restore(envelope.as_slice(), &phrase).unwrap();
    assert_eq!(
        pending.confirm(&mut to, RestoreConfirmation::Replace),
        Err(ConfirmError::PreviewChanged)
    );
    assert!(to.active().is_none());
    assert_eq!(to.highest_counter(id), None);
}

#[test]
fn concurrent_exports_reserve_distinct_counters_for_the_same_vault() {
    use restore::RestoreState;
    use std::sync::{Barrier, Mutex};
    use std::thread;

    const WORKERS: usize = 8;
    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let state = Mutex::new(RestoreState::new(
        Some(restore_fixture(id, 6, 1)),
        Default::default(),
    ));
    let start = Barrier::new(WORKERS);
    let mut counters = thread::scope(|scope| {
        let mut workers = Vec::new();
        for worker in 0..WORKERS {
            let state = &state;
            let start = &start;
            workers.push(scope.spawn(move || {
                let issued_at = 1_700_000_000 + worker as u64;
                start.wait();
                let reservation = state.lock().unwrap().reserve_export(issued_at).unwrap();
                let entropy = node_entropy();
                let envelope = reservation.seal(&entropy).unwrap();
                let reopened = open(&envelope, &entropy).unwrap();
                assert_eq!(reopened.vault_id, id);
                assert_eq!(reopened.issued_at, issued_at);
                reopened.export_counter
            }));
        }
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    counters.sort_unstable();
    assert_eq!(counters, (7..=14).collect::<Vec<_>>());
    let state = state.into_inner().unwrap();
    assert_eq!(state.highest_counter(id), Some(14));
    assert_eq!(state.active().unwrap().export_counter, 6);
}

#[test]
fn export_after_rollback_uses_the_highest_counter_and_keeps_abandoned_gaps() {
    use restore::{RestoreConfirmation, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let mut state = RestoreState::new(Some(restore_fixture(id, 10, 1)), Default::default());
    let mut restored = restore_fixture(id, 7, 2);
    let older = export(&restored, &entropy).unwrap();
    state
        .prepare_restore(older.as_slice(), &phrase)
        .unwrap()
        .confirm(&mut state, RestoreConfirmation::ReplaceOlderOrEqual)
        .unwrap();

    drop(state.reserve_export(101).unwrap());
    assert_eq!(state.highest_counter(id), Some(11));
    let next = state.reserve_export(102).unwrap();
    assert!(state.active() == Some(&restored));

    restored.export_counter = 12;
    restored.issued_at = 102;
    let envelope = next.seal(&entropy).unwrap();
    assert!(open(&envelope, &entropy).unwrap() == restored);
    assert_eq!(state.highest_counter(id), Some(12));
}

#[test]
fn reservation_keeps_the_selected_contents_across_a_later_replacement() {
    use restore::{RestoreConfirmation, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let mut original = restore_fixture(id, 10, 1);
    let mut state = RestoreState::new(Some(original.clone()), Default::default());
    let reserved = state.reserve_export(101).unwrap();

    let replacement = restore_fixture(id, 12, 2);
    let incoming = export(&replacement, &entropy).unwrap();
    state
        .prepare_restore(incoming.as_slice(), &phrase)
        .unwrap()
        .confirm(&mut state, RestoreConfirmation::Replace)
        .unwrap();

    original.export_counter = 11;
    original.issued_at = 101;
    let envelope = reserved.seal(&entropy).unwrap();
    assert!(open(&envelope, &entropy).unwrap() == original);
    assert!(state.active() == Some(&replacement));
    assert_eq!(state.highest_counter(id), Some(12));
}

#[test]
fn stops_reservations_after_the_largest_json_counter() {
    use payload::MAX_JSON_INTEGER;
    use restore::{ReserveExportError, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut state = RestoreState::new(
        Some(restore_fixture(id, MAX_JSON_INTEGER - 1, 1)),
        Default::default(),
    );
    let entropy = node_entropy();
    let last = state.reserve_export(0).unwrap().seal(&entropy).unwrap();
    assert_eq!(
        open(&last, &entropy).unwrap().export_counter,
        MAX_JSON_INTEGER
    );
    assert_eq!(
        state.reserve_export(0).err(),
        Some(ReserveExportError::CounterExhausted)
    );
    assert_eq!(state.highest_counter(id), Some(MAX_JSON_INTEGER));
}

#[test]
fn invalid_export_requests_leave_counter_history_intact() {
    use payload::MAX_JSON_INTEGER;
    use restore::{ReserveExportError, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut empty = RestoreState::new(None, Default::default());
    assert_eq!(
        empty.reserve_export(0).err(),
        Some(ReserveExportError::NoActiveVault)
    );
    assert_eq!(empty.highest_counter(id), None);

    let mut state = RestoreState::new(Some(restore_fixture(id, 6, 1)), Default::default());
    assert_eq!(
        state.reserve_export(MAX_JSON_INTEGER + 1).err(),
        Some(ReserveExportError::InvalidIssueDate)
    );
    assert_eq!(state.highest_counter(id), Some(6));
}

#[test]
fn disconnected_export_histories_can_diverge_at_the_same_counter() {
    use restore::{RestoreHistory, RestoreState};

    let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let mut first = RestoreState::new(Some(restore_fixture(id, 6, 1)), Default::default());
    let mut second = RestoreState::new(Some(restore_fixture(id, 6, 2)), Default::default());
    let first_export = first.reserve_export(101).unwrap().seal(&entropy).unwrap();
    let second_export = second.reserve_export(101).unwrap().seal(&entropy).unwrap();

    let first_vault = open(&first_export, &entropy).unwrap();
    let second_vault = open(&second_export, &entropy).unwrap();
    assert_eq!(first_vault.export_counter, 7);
    assert_eq!(second_vault.export_counter, 7);
    // With equal counters and issue dates, the difference is in the contents.
    assert!(first_vault != second_vault);
    let pending = first
        .prepare_restore(second_export.as_slice(), &phrase)
        .unwrap();
    assert_eq!(pending.preview().history, RestoreHistory::OlderOrEqual);
    assert_eq!(pending.preview().issued_at, 101);
}
