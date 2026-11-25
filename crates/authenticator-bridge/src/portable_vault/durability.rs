//! Host-only transaction harness. The stored envelope uses a public fixture
//! key. SQLite and this schema are here to exercise interruption semantics.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::payload::MAX_JSON_INTEGER;
use super::restore::{
    AuthenticatedExport, ConfirmError, PendingRestore, PreviewError, ReserveExportError,
    ReservedExport, RestoreConfirmation, RestorePreview, RestoreState,
};
use super::tests::{node_entropy, restore_fixture, synthetic_recovery_phrase};
use super::{
    export, open, ExportError, ExportRandomness, RandomError, SecretKey, SyntheticVault, KEY_BYTES,
    NONCE_BYTES,
};

const FIXTURE_VAULT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHILD_DATABASE: &str = "SOTTO_DURABILITY_TEST_CHILD_DATABASE";
const INTERRUPTED_EXIT: i32 = 83;

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error("fixture database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("fixture envelope operation failed: {0:?}")]
    Envelope(ExportError),
    #[error("fixture preview failed: {0:?}")]
    Preview(PreviewError),
    #[error("fixture confirmation failed: {0:?}")]
    Confirm(ConfirmError),
    #[error("fixture export reservation failed: {0:?}")]
    Reserve(ReserveExportError),
    #[error("fixture counter is outside the supported range")]
    InvalidCounter,
}

fn open_database(path: &Path) -> rusqlite::Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(Duration::from_secs(10))?;
    db.pragma_update(None, "synchronous", "EXTRA")?;
    Ok(db)
}

fn fixture_key() -> SecretKey {
    SecretKey::new([0xee; 32])
}

fn initialise_database(path: &Path) -> rusqlite::Result<Connection> {
    let db = open_database(path)?;
    db.execute_batch(
        "PRAGMA journal_mode = DELETE;
         CREATE TABLE active_vault (
             slot INTEGER PRIMARY KEY CHECK (slot = 1),
             envelope BLOB NOT NULL
         );
         CREATE TABLE export_history (
             vault_id TEXT PRIMARY KEY,
             highest INTEGER NOT NULL CHECK (highest BETWEEN 1 AND 9007199254740991)
         );
         CREATE TABLE fixture_identity (
             slot INTEGER PRIMARY KEY CHECK (slot = 1),
             store_id BLOB NOT NULL,
             revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision >= 0)
         );
         INSERT INTO fixture_identity (slot, store_id, revision) VALUES (1, randomblob(16), 0);",
    )?;
    Ok(db)
}

fn seed_database(path: &Path, active: &SyntheticVault) -> Result<(), FixtureError> {
    let mut db = initialise_database(path)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    write_replacement(&tx, active, active.export_counter)?;
    tx.commit()?;
    Ok(())
}

fn load_state(db: &Connection) -> Result<RestoreState, FixtureError> {
    let envelope: Option<Vec<u8>> = db
        .query_row(
            "SELECT envelope FROM active_vault WHERE slot = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let active = envelope
        .map(|bytes| open(&bytes, &fixture_key()))
        .transpose()
        .map_err(FixtureError::Envelope)?;
    let mut query = db.prepare("SELECT vault_id, highest FROM export_history")?;
    let rows = query.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut highest_counters = BTreeMap::new();
    for row in rows {
        let (id, counter) = row?;
        let counter = u64::try_from(counter).map_err(|_| FixtureError::InvalidCounter)?;
        if !(1..=MAX_JSON_INTEGER).contains(&counter) {
            return Err(FixtureError::InvalidCounter);
        }
        highest_counters.insert(id, counter);
    }
    Ok(RestoreState::new(active, highest_counters))
}

fn write_counter(tx: &Transaction<'_>, vault_id: &str, highest: u64) -> Result<(), FixtureError> {
    let highest = i64::try_from(highest).map_err(|_| FixtureError::InvalidCounter)?;
    tx.execute(
        "INSERT INTO export_history (vault_id, highest) VALUES (?1, ?2)
         ON CONFLICT(vault_id) DO UPDATE SET highest = max(highest, excluded.highest)",
        params![vault_id, highest],
    )?;
    Ok(())
}

fn persisted_counter(db: &Connection, vault_id: &str) -> i64 {
    db.query_row(
        "SELECT highest FROM export_history WHERE vault_id = ?1",
        [vault_id],
        |row| row.get(0),
    )
    .unwrap()
}

fn write_replacement(
    tx: &Transaction<'_>,
    vault: &SyntheticVault,
    highest: u64,
) -> Result<(), FixtureError> {
    let encrypted = export(vault, &fixture_key()).map_err(FixtureError::Envelope)?;
    tx.execute(
        "INSERT INTO active_vault (slot, envelope) VALUES (1, ?1)
         ON CONFLICT(slot) DO UPDATE SET envelope = excluded.envelope",
        [encrypted],
    )?;
    write_counter(tx, &vault.vault_id, highest)?;
    tx.execute(
        "UPDATE fixture_identity SET revision = revision + 1 WHERE slot = 1",
        [],
    )?;
    Ok(())
}

fn reserve_durably(db: &mut Connection, issued_at: u64) -> Result<ReservedExport, FixtureError> {
    // Take the write lock before reading the counter so two connections cannot
    // reserve the same value. Return the snapshot only after commit succeeds.
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut state = load_state(&tx)?;
    let reservation = state
        .reserve_export(issued_at)
        .map_err(FixtureError::Reserve)?;
    let active = state
        .active()
        .expect("reservation requires an active vault");
    let highest = state
        .highest_counter(&active.vault_id)
        .expect("reservation records its counter");
    write_counter(&tx, &active.vault_id, highest)?;
    tx.commit()?;
    Ok(reservation)
}

#[derive(PartialEq, Eq)]
struct StoreStamp {
    id: Vec<u8>,
    revision: i64,
    incoming_counter: Option<i64>,
}

fn store_stamp(tx: &Transaction<'_>, incoming_id: &str) -> rusqlite::Result<StoreStamp> {
    tx.query_row(
        "SELECT store_id, revision, (SELECT highest FROM export_history WHERE vault_id = ?1)
         FROM fixture_identity WHERE slot = 1",
        [incoming_id],
        |row| {
            Ok(StoreStamp {
                id: row.get(0)?,
                revision: row.get(1)?,
                incoming_counter: row.get(2)?,
            })
        },
    )
}

struct PendingFixtureRestore {
    stamp: StoreStamp,
    state: RestoreState,
    pending: PendingRestore,
}

impl PendingFixtureRestore {
    fn prepare(db: &mut Connection, incoming: &SyntheticVault) -> Result<Self, FixtureError> {
        let entropy = node_entropy();
        let phrase = synthetic_recovery_phrase(&entropy);
        let envelope = export(incoming, &entropy).map_err(FixtureError::Envelope)?;
        Self::prepare_from_reader(db, envelope.as_slice(), &phrase)
    }

    fn prepare_from_reader(
        db: &mut Connection,
        reader: impl Read,
        phrase: &str,
    ) -> Result<Self, FixtureError> {
        // File I/O and authentication can run before taking a database snapshot.
        let incoming = AuthenticatedExport::read(reader, phrase).map_err(FixtureError::Preview)?;
        // Read the preview's active vault and the stamp from the same snapshot.
        let tx = db.transaction()?;
        let state = load_state(&tx)?;
        let pending = state.prepare_authenticated_restore(incoming);
        let stamp = store_stamp(&tx, &pending.preview().vault_id)?;
        tx.commit()?;
        Ok(Self {
            stamp,
            state,
            pending,
        })
    }

    fn preview(&self) -> &RestorePreview {
        self.pending.preview()
    }

    fn confirm(
        self,
        db: &mut Connection,
        confirmation: RestoreConfirmation,
    ) -> Result<(), FixtureError> {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.stage(&tx, confirmation)?;
        tx.commit()?;
        Ok(())
    }

    // The caller holds the write transaction from the recheck through commit.
    // Keep staging separate so the interrupted-writer test can exit before commit.
    fn stage(
        mut self,
        tx: &Transaction<'_>,
        confirmation: RestoreConfirmation,
    ) -> Result<(), FixtureError> {
        if store_stamp(tx, &self.preview().vault_id)? != self.stamp {
            return Err(FixtureError::Confirm(ConfirmError::PreviewChanged));
        }
        self.pending
            .confirm(&mut self.state, confirmation)
            .map_err(FixtureError::Confirm)?;
        let active = self.state.active().expect("confirmation installs a vault");
        let highest = self
            .state
            .highest_counter(&active.vault_id)
            .expect("confirmation records its counter");
        write_replacement(tx, active, highest)
    }
}

#[test]
fn committed_reservations_survive_reopen_even_when_the_snapshot_is_abandoned() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 1);
    seed_database(&path, &original).unwrap();

    drop(reserve_durably(&mut open_database(&path).unwrap(), 1).unwrap());

    let mut db = open_database(&path).unwrap();
    let reopened = load_state(&db).unwrap();
    assert!(reopened.active() == Some(&original));
    assert_eq!(reopened.highest_counter(FIXTURE_VAULT_ID), Some(7));
    let entropy = node_entropy();
    let envelope = reserve_durably(&mut db, 2).unwrap().seal(&entropy).unwrap();
    assert_eq!(open(&envelope, &entropy).unwrap().export_counter, 8);
}

#[test]
fn failed_random_reads_keep_reserved_counters_after_reopen() {
    use std::num::NonZeroU32;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 1);
    seed_database(&path, &original).unwrap();
    let entropy = node_entropy();
    let read_lengths = [KEY_BYTES, NONCE_BYTES, KEY_BYTES, NONCE_BYTES];

    for failed_read in 0..read_lengths.len() {
        let mut db = open_database(&path).unwrap();
        let reserved = reserve_durably(&mut db, 2).unwrap();
        let mut reads = Vec::new();
        let failed = reserved.seal_with_randomness(&entropy, || {
            ExportRandomness::from_source(|bytes| {
                let current_read = reads.len();
                reads.push(bytes.len());
                if current_read == failed_read {
                    // A random source can write part of a buffer before failing.
                    bytes[0] = 0xff;
                    return Err(NonZeroU32::new(RandomError::CUSTOM_START).unwrap().into());
                }
                bytes.fill(0x42);
                Ok(())
            })
        });
        assert_eq!(failed, Err(ExportError::RandomnessUnavailable));
        assert_eq!(reads, read_lengths[..=failed_read]);
        drop(db);

        let reopened = load_state(&open_database(&path).unwrap()).unwrap();
        assert!(reopened.active() == Some(&original));
        assert_eq!(
            reopened.highest_counter(FIXTURE_VAULT_ID),
            Some(7 + failed_read as u64)
        );
    }

    let mut db = open_database(&path).unwrap();
    let retry = reserve_durably(&mut db, 3).unwrap().seal(&entropy).unwrap();
    let mut expected = original;
    expected.export_counter = 11;
    expected.issued_at = 3;
    assert!(open(&retry, &entropy).unwrap() == expected);
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 11);
}

fn save_fixture_export(
    directory: &Path,
    destination: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let mut staging = tempfile::NamedTempFile::new_in(directory)?;
    write(staging.as_file_mut())?;
    staging.persist(destination).map_err(|error| error.error)?;
    Ok(())
}

#[test]
fn retrying_a_partial_save_keeps_the_sealed_bytes_and_counter() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("vault.sqlite");
    let destination = directory.path().join("vault.sotv");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 1);
    seed_database(&database, &original).unwrap();
    let entropy = node_entropy();
    let previous = export(&original, &entropy).unwrap();
    save_fixture_export(directory.path(), &destination, |file| {
        file.write_all(&previous)
    })
    .unwrap();

    let mut db = open_database(&database).unwrap();
    let sealed = reserve_durably(&mut db, 2).unwrap().seal(&entropy).unwrap();
    drop(db);

    let failure = save_fixture_export(directory.path(), &destination, |file| {
        file.write_all(&sealed[..sealed.len() / 2])?;
        Err(io::Error::other("synthetic partial save failure"))
    });
    assert!(failure.is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), previous);

    // Retry the write with the same envelope, even after reopening the store.
    let mut db = open_database(&database).unwrap();
    save_fixture_export(directory.path(), &destination, |file| {
        file.write_all(&sealed)
    })
    .unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), sealed);
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 7);
    let state = load_state(&db).unwrap();
    let phrase = synthetic_recovery_phrase(&entropy);
    let preview = state
        .prepare_restore(File::open(&destination).unwrap(), &phrase)
        .unwrap();
    assert_eq!(preview.preview().export_counter, 7);
    assert!(state.active() == Some(&original));

    let next = reserve_durably(&mut db, 3).unwrap().seal(&entropy).unwrap();
    assert_eq!(open(&next, &entropy).unwrap().export_counter, 8);
}

#[test]
fn saved_export_restores_into_a_fresh_database_after_confirmation() {
    use super::restore::RestoreHistory;

    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.sqlite");
    let destination = directory.path().join("destination.sqlite");
    let file = directory.path().join("vault.sotv");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 2);
    seed_database(&source, &original).unwrap();
    initialise_database(&destination).unwrap();

    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let sealed = reserve_durably(&mut open_database(&source).unwrap(), 42)
        .unwrap()
        .seal(&entropy)
        .unwrap();
    save_fixture_export(directory.path(), &file, |writer| writer.write_all(&sealed)).unwrap();

    let mut db = open_database(&destination).unwrap();
    let pending =
        PendingFixtureRestore::prepare_from_reader(&mut db, File::open(&file).unwrap(), &phrase)
            .unwrap();
    assert_eq!(pending.preview().history, RestoreHistory::NoLocalHistory);
    assert_eq!(pending.preview().export_counter, 7);
    let before = load_state(&db).unwrap();
    assert!(before.active().is_none());
    assert_eq!(before.highest_counter(FIXTURE_VAULT_ID), None);

    pending
        .confirm(&mut db, RestoreConfirmation::Replace)
        .unwrap();
    drop(db);
    let db = open_database(&destination).unwrap();
    let restored = load_state(&db).unwrap();
    let mut expected = original;
    expected.export_counter = 7;
    expected.issued_at = 42;
    assert!(restored.active() == Some(&expected));
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 7);
}

#[test]
fn preview_uses_counter_committed_during_file_read() {
    use super::restore::RestoreHistory;

    struct ReserveOnFirstRead<'a> {
        envelope: &'a [u8],
        writer: Option<Connection>,
    }

    impl Read for ReserveOnFirstRead<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if let Some(mut writer) = self.writer.take() {
                reserve_durably(&mut writer, 1)
                    .expect("reservation should commit during a file read");
            }
            self.envelope.read(buffer)
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("vault.sqlite");
    seed_database(&database, &restore_fixture(FIXTURE_VAULT_ID, 6, 1)).unwrap();
    let mut db = open_database(&database).unwrap();
    let writer = open_database(&database).unwrap();
    writer.busy_timeout(Duration::ZERO).unwrap();
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let incoming = restore_fixture(FIXTURE_VAULT_ID, 7, 2);
    let sealed = export(&incoming, &entropy).unwrap();
    let reader = ReserveOnFirstRead {
        envelope: &sealed,
        writer: Some(writer),
    };

    let pending = PendingFixtureRestore::prepare_from_reader(&mut db, reader, &phrase).unwrap();
    assert_eq!(pending.preview().history, RestoreHistory::OlderOrEqual);
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 7);
    pending
        .confirm(&mut db, RestoreConfirmation::ReplaceOlderOrEqual)
        .unwrap();
    assert!(load_state(&db).unwrap().active() == Some(&incoming));
}

#[test]
fn rejected_file_imports_preserve_the_stored_vault_and_history() {
    use super::{seal, MAX_ENVELOPE_BYTES};

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("vault.sqlite");
    let file = directory.path().join("incoming.sotv");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 1);
    seed_database(&database, &original).unwrap();
    let mut db = open_database(&database).unwrap();
    let reservation = reserve_durably(&mut db, 1).unwrap();
    drop(reservation);
    let tx = db.transaction().unwrap();
    let before = store_stamp(&tx, FIXTURE_VAULT_ID).unwrap();
    tx.commit().unwrap();
    drop(db);

    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let wrong_phrase = synthetic_recovery_phrase(&SecretKey::new([0xff; KEY_BYTES]));
    let incoming = restore_fixture(FIXTURE_VAULT_ID, 9, 2);
    let sealed = export(&incoming, &entropy).unwrap();
    let mut modified = sealed.clone();
    *modified.last_mut().unwrap() ^= 1;
    let mut unsupported = sealed.clone();
    unsupported[4] ^= 1;
    let mut malformed = sealed.clone();
    malformed[0] ^= 1;
    let invalid_payload = seal(
        &mut b"{}".to_vec(),
        &entropy,
        ExportRandomness::generate().unwrap(),
    )
    .unwrap();

    for (bytes, recovery_phrase, expected_error) in [
        (Vec::new(), &phrase, PreviewError::InvalidFile),
        (
            vec![0; MAX_ENVELOPE_BYTES + 1],
            &phrase,
            PreviewError::InvalidFile,
        ),
        (unsupported, &phrase, PreviewError::UnsupportedFormat),
        (malformed, &phrase, PreviewError::InvalidFile),
        (modified, &phrase, PreviewError::CannotOpen),
        (sealed, &wrong_phrase, PreviewError::CannotOpen),
        (invalid_payload, &phrase, PreviewError::InvalidFile),
    ] {
        std::fs::write(&file, bytes).unwrap();
        let mut db = open_database(&database).unwrap();
        let failure = PendingFixtureRestore::prepare_from_reader(
            &mut db,
            File::open(&file).unwrap(),
            recovery_phrase,
        )
        .err();
        assert!(
            matches!(
                &failure,
                Some(FixtureError::Preview(error)) if *error == expected_error
            ),
            "expected {expected_error:?}, got {failure:?}"
        );
        drop(db);

        let mut reopened = open_database(&database).unwrap();
        let state = load_state(&reopened).unwrap();
        assert!(state.active() == Some(&original));
        assert_eq!(persisted_counter(&reopened, FIXTURE_VAULT_ID), 7);
        let tx = reopened.transaction().unwrap();
        assert!(store_stamp(&tx, FIXTURE_VAULT_ID).unwrap() == before);
    }
}

#[test]
fn independent_database_connections_reserve_distinct_counters() {
    use std::sync::Barrier;
    use std::thread;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    seed_database(&path, &restore_fixture(FIXTURE_VAULT_ID, 6, 1)).unwrap();
    let start = Barrier::new(4);

    let mut counters = thread::scope(|scope| {
        let threads: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let connection = open_database(&path);
                    start.wait();
                    let mut db = connection.unwrap();
                    let entropy = node_entropy();
                    let envelope = reserve_durably(&mut db, 1).unwrap().seal(&entropy).unwrap();
                    open(&envelope, &entropy).unwrap().export_counter
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    counters.sort_unstable();
    assert_eq!(counters, [7, 8, 9, 10]);
    let reopened = load_state(&open_database(&path).unwrap()).unwrap();
    assert_eq!(reopened.highest_counter(FIXTURE_VAULT_ID), Some(10));
}

#[test]
fn fresh_store_and_an_unrelated_vault_have_independent_history() {
    use super::restore::RestoreHistory;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    let other_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let first = restore_fixture(FIXTURE_VAULT_ID, 9, 1);
    let second = restore_fixture(other_id, 3, 2);
    let mut db = initialise_database(&path).unwrap();
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);

    for incoming in [&first, &second] {
        let pending = PendingFixtureRestore::prepare(&mut db, incoming).unwrap();
        assert_eq!(pending.preview().history, RestoreHistory::NoLocalHistory);
        pending
            .confirm(&mut db, RestoreConfirmation::Replace)
            .unwrap();
    }
    drop(db);

    let db = open_database(&path).unwrap();
    let reopened = load_state(&db).unwrap();
    assert!(reopened.active() == Some(&second));
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 9);
    assert_eq!(persisted_counter(&db, other_id), 3);
    let envelope = export(&first, &entropy).unwrap();
    let pending = reopened
        .prepare_restore(envelope.as_slice(), &phrase)
        .unwrap();
    assert_eq!(pending.preview().history, RestoreHistory::OlderOrEqual);
}

#[test]
fn interrupted_replacement_recovers_both_vault_and_counter_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 1);
    seed_database(&path, &original).unwrap();
    let incoming = restore_fixture(FIXTURE_VAULT_ID, 9, 2);
    let mut db = open_database(&path).unwrap();
    let pending = PendingFixtureRestore::prepare(&mut db, &incoming).unwrap();
    drop(db);

    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "portable_vault::durability::interrupt_fixture_writer",
        ])
        .env(CHILD_DATABASE, &path)
        .output()
        .unwrap();
    assert_eq!(
        child.status.code(),
        Some(INTERRUPTED_EXIT),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    let journal = path.with_extension("sqlite-journal");
    assert!(
        journal.is_file(),
        "the interrupted writer must leave a rollback journal"
    );

    let mut db = open_database(&path).unwrap();
    let reopened = load_state(&db).unwrap();
    assert!(reopened.active() == Some(&original));
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 6);

    // The interrupted write also rolled back the revision. The preview still
    // identifies the same database state after reopening.
    pending
        .confirm(&mut db, RestoreConfirmation::Replace)
        .unwrap();
    drop(db);

    let db = open_database(&path).unwrap();
    let reopened = load_state(&db).unwrap();
    assert!(reopened.active() == Some(&incoming));
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 9);
}

#[test]
fn committed_rollback_keeps_the_highest_counter_on_disk() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    seed_database(&path, &restore_fixture(FIXTURE_VAULT_ID, 10, 1)).unwrap();
    let older = restore_fixture(FIXTURE_VAULT_ID, 7, 2);

    let mut db = open_database(&path).unwrap();
    PendingFixtureRestore::prepare(&mut db, &older)
        .unwrap()
        .confirm(&mut db, RestoreConfirmation::ReplaceOlderOrEqual)
        .unwrap();
    drop(db);

    let mut db = open_database(&path).unwrap();
    assert!(load_state(&db).unwrap().active() == Some(&older));
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 10);
    let entropy = node_entropy();
    let next = reserve_durably(&mut db, 1).unwrap().seal(&entropy).unwrap();
    assert_eq!(open(&next, &entropy).unwrap().export_counter, 11);
}

#[test]
#[ignore = "child process for the interrupted replacement test"]
fn interrupt_fixture_writer() {
    let path = PathBuf::from(std::env::var_os(CHILD_DATABASE).expect("fixture database path"));
    let mut db = open_database(&path).unwrap();
    let pending =
        PendingFixtureRestore::prepare(&mut db, &restore_fixture(FIXTURE_VAULT_ID, 9, 2)).unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    pending.stage(&tx, RestoreConfirmation::Replace).unwrap();
    tx.cache_flush().unwrap();
    // Exit without running Rust or SQLite destructors and without committing.
    std::process::exit(INTERRUPTED_EXIT);
}

#[test]
fn a_committed_same_counter_replacement_requires_a_new_durable_preview() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    seed_database(&path, &restore_fixture(FIXTURE_VAULT_ID, 7, 1)).unwrap();
    let mut db = open_database(&path).unwrap();
    let stale =
        PendingFixtureRestore::prepare(&mut db, &restore_fixture(FIXTURE_VAULT_ID, 7, 2)).unwrap();

    let replacement = restore_fixture(FIXTURE_VAULT_ID, 7, 3);
    let mut writer = open_database(&path).unwrap();
    PendingFixtureRestore::prepare(&mut writer, &replacement)
        .unwrap()
        .confirm(&mut writer, RestoreConfirmation::ReplaceOlderOrEqual)
        .unwrap();

    assert!(matches!(
        stale.confirm(&mut db, RestoreConfirmation::ReplaceOlderOrEqual),
        Err(FixtureError::Confirm(ConfirmError::PreviewChanged))
    ));
    assert!(load_state(&db).unwrap().active() == Some(&replacement));
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 7);
}

#[test]
fn a_committed_reservation_requires_a_new_durable_preview_for_that_vault() {
    use super::restore::RestoreHistory;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 1);
    seed_database(&path, &original).unwrap();
    let mut db = open_database(&path).unwrap();
    let incoming = restore_fixture(FIXTURE_VAULT_ID, 7, 2);
    let stale = PendingFixtureRestore::prepare(&mut db, &incoming).unwrap();
    assert_eq!(
        stale.preview().history,
        RestoreHistory::HigherCounterFreshnessUnknown
    );

    let mut writer = open_database(&path).unwrap();
    drop(reserve_durably(&mut writer, 1).unwrap());

    assert!(matches!(
        stale.confirm(&mut db, RestoreConfirmation::Replace),
        Err(FixtureError::Confirm(ConfirmError::PreviewChanged))
    ));
    let fresh = PendingFixtureRestore::prepare(&mut db, &incoming).unwrap();
    assert_eq!(fresh.preview().history, RestoreHistory::OlderOrEqual);
    assert!(matches!(
        fresh.confirm(&mut db, RestoreConfirmation::Replace),
        Err(FixtureError::Confirm(
            ConfirmError::RollbackAcknowledgementRequired
        ))
    ));
    assert!(load_state(&db).unwrap().active() == Some(&original));
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 7);
}

#[test]
fn durable_preview_cannot_authorise_a_different_database_with_the_same_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.sqlite");
    let other = directory.path().join("other.sqlite");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 1);
    seed_database(&first, &original).unwrap();
    seed_database(&other, &original).unwrap();
    let mut db = open_database(&first).unwrap();
    let mut other = open_database(&other).unwrap();
    let pending =
        PendingFixtureRestore::prepare(&mut db, &restore_fixture(FIXTURE_VAULT_ID, 7, 2)).unwrap();

    assert!(matches!(
        pending.confirm(&mut other, RestoreConfirmation::Replace),
        Err(FixtureError::Confirm(ConfirmError::PreviewChanged))
    ));
    assert!(load_state(&other).unwrap().active() == Some(&original));
    assert_eq!(persisted_counter(&other, FIXTURE_VAULT_ID), 6);
}
