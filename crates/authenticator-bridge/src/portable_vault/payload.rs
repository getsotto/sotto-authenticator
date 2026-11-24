use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};
use std::marker::PhantomData;

use serde::de::{
    self, value::MapAccessDeserializer, DeserializeSeed, MapAccess, SeqAccess, Visitor,
};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use super::ExportError;

const MAX_PROJECTS: usize = 32;
const MAX_INSTANCES_PER_PROJECT: usize = 16;
const MAX_ENTRIES_PER_INSTANCE: usize = 64;
const MAX_LABEL_BYTES: usize = 128;
pub(super) const MAX_JSON_INTEGER: u64 = (1 << 53) - 1;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct SyntheticVault {
    format_version: u8,
    pub(super) vault_id: String,
    pub(super) export_counter: u64,
    pub(super) issued_at: u64,
    projects: Records<Project, MAX_PROJECTS>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Project {
    id: String,
    name: RecordText,
    instances: Records<Instance, MAX_INSTANCES_PER_PROJECT>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Instance {
    id: String,
    name: RecordText,
    entries: Records<Entry, MAX_ENTRIES_PER_INSTANCE>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    label: RecordText,
}

// Wrap each string as it is decoded so completed fields are cleared even if
// a later field prevents the record from being constructed.
#[derive(Clone, Serialize)]
#[serde(transparent)]
struct RecordText(Zeroizing<String>);

impl<'de> Deserialize<'de> for RecordText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RecordTextVisitor;

        impl Visitor<'_> for RecordTextVisitor {
            type Value = RecordText;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string up to {MAX_LABEL_BYTES} UTF-8 bytes")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<RecordText, E> {
                if text.len() > MAX_LABEL_BYTES {
                    return Err(E::custom("record text exceeds the UTF-8 byte limit"));
                }
                Ok(RecordText(Zeroizing::new(text.to_owned())))
            }
        }

        deserializer.deserialize_str(RecordTextVisitor)
    }
}

impl PartialEq for RecordText {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl Eq for RecordText {}

#[test]
fn record_text_checks_the_decoded_byte_limit_before_owning_the_string() {
    for character in ["é", r"\u00e9"] {
        let at_limit = format!("\"{}\"", character.repeat(MAX_LABEL_BYTES / 2));
        let decoded: RecordText = serde_json::from_str(&at_limit).unwrap();
        assert_eq!(decoded.0.len(), MAX_LABEL_BYTES);
        let over_limit = format!("\"{}\"", character.repeat(MAX_LABEL_BYTES / 2 + 1));
        assert!(serde_json::from_str::<RecordText>(&over_limit).is_err());
    }
}

#[test]
fn decoded_names_and_labels_use_clearing_buffers() {
    use super::tests::restore_fixture;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    fn check_buffer(text: &mut (impl Zeroize + ZeroizeOnDrop + AsRef<str>)) {
        assert!(!text.as_ref().is_empty());
        text.zeroize();
        assert!(text.as_ref().is_empty());
    }

    let mut vault = restore_fixture("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, 1);
    let project = &mut vault.projects.0[0];
    check_buffer(&mut project.name.0);
    let instance = &mut project.instances.0[0];
    check_buffer(&mut instance.name.0);
    check_buffer(&mut instance.entries.0[0].label.0);
}

impl SyntheticVault {
    pub(super) fn from_bytes(bytes: &[u8], limit: usize) -> Result<Self, ExportError> {
        if bytes.len() > limit {
            return Err(ExportError::InvalidSize);
        }
        let JsonObject(vault): JsonObject<Self> =
            serde_json::from_slice(bytes).map_err(|_| ExportError::InvalidPayload)?;
        vault.validate()?;
        Ok(vault)
    }

    pub(super) fn to_bytes(&self, limit: usize) -> Result<Zeroizing<Vec<u8>>, ExportError> {
        self.validate()?;
        let mut size = PayloadSize { bytes: 0, limit };
        serde_json::to_writer(&mut size, self).map_err(|error| {
            // The writer's only I/O error is exceeding the payload cap.
            if error.is_io() {
                ExportError::InvalidSize
            } else {
                ExportError::InvalidPayload
            }
        })?;
        // Allocate the complete buffer once so growth does not leave earlier
        // plaintext allocations outside the Zeroizing buffer.
        let mut output = Zeroizing::new(Vec::with_capacity(size.bytes));
        serde_json::to_writer(&mut *output, self).map_err(|_| ExportError::InvalidPayload)?;
        Ok(output)
    }

    fn validate(&self) -> Result<(), ExportError> {
        if self.format_version != 1
            || !valid_id(&self.vault_id)
            || !(1..=MAX_JSON_INTEGER).contains(&self.export_counter)
            || self.issued_at > MAX_JSON_INTEGER
        {
            return Err(ExportError::InvalidPayload);
        }

        let mut project_ids = BTreeSet::new();
        for project in &self.projects.0 {
            validate_record_id(&mut project_ids, &project.id)?;
            let mut instance_ids = BTreeSet::new();
            for instance in &project.instances.0 {
                validate_record_id(&mut instance_ids, &instance.id)?;
                let mut entry_ids = BTreeSet::new();
                for entry in &instance.entries.0 {
                    validate_record_id(&mut entry_ids, &entry.id)?;
                }
            }
        }
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_record_id<'a>(ids: &mut BTreeSet<&'a str>, id: &'a str) -> Result<(), ExportError> {
    if !valid_id(id) || !ids.insert(id) {
        return Err(ExportError::InvalidPayload);
    }
    Ok(())
}

struct PayloadSize {
    bytes: usize,
    limit: usize,
}

impl Write for PayloadSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes {
            return Err(io::Error::other("payload exceeds size limit"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Derived struct deserialisation also accepts positional arrays. Force maps
// at every record level while preserving Serde's duplicate-field checks.
struct JsonObject<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = JsonObject<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a vault object with named fields")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(JsonObject)
            }
        }

        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(transparent)]
struct Records<T, const LIMIT: usize>(Vec<T>);

impl<'de, T: Deserialize<'de>, const LIMIT: usize> Deserialize<'de> for Records<T, LIMIT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RecordsVisitor<T, const LIMIT: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for RecordsVisitor<T, LIMIT> {
            type Value = Records<T, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array of at most {LIMIT} vault objects")
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let mut records = Vec::new();
                while records.len() < LIMIT {
                    let Some(JsonObject(record)) = seq.next_element()? else {
                        return Ok(Records(records));
                    };
                    records.push(record);
                }
                // The seed runs only if another element exists, and rejects it
                // before Serde parses or allocates anything for that element.
                seq.next_element_seed(RejectExtraRecord)?;
                Ok(Records(records))
            }
        }

        deserializer.deserialize_seq(RecordsVisitor(PhantomData))
    }
}

struct RejectExtraRecord;

impl<'de> DeserializeSeed<'de> for RejectExtraRecord {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, _deserializer: D) -> Result<(), D::Error> {
        Err(de::Error::custom("too many vault records"))
    }
}
