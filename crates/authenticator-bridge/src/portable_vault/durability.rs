//! Host-only transaction harness. The stored envelope uses a public fixture
//! key. SQLite and this schema are here to exercise interruption semantics.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::payload::MAX_JSON_INTEGER;
use super::restore::{
    ConfirmError, PreviewError, ReserveExportError, ReservedExport, RestoreConfirmation,
    RestoreState,
};
use super::tests::{node_entropy, restore_fixture, synthetic_recovery_phrase};
use super::{export, open, ExportError, SecretKey, SyntheticVault};

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
         );",
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

fn stage_confirmed_restore(
    tx: &Transaction<'_>,
    incoming: &SyntheticVault,
    confirmation: RestoreConfirmation,
) -> Result<(), FixtureError> {
    // Exercise the Rust confirmation rules inside this fixture transaction.
    // Handling a preview displayed before the write transaction is client work.
    let entropy = node_entropy();
    let phrase = synthetic_recovery_phrase(&entropy);
    let envelope = export(incoming, &entropy).map_err(FixtureError::Envelope)?;
    let mut state = load_state(tx)?;
    let pending = state
        .prepare_restore(&envelope, &phrase)
        .map_err(FixtureError::Preview)?;
    pending
        .confirm(&mut state, confirmation)
        .map_err(FixtureError::Confirm)?;
    let active = state.active().expect("confirmation installs a vault");
    let highest = state
        .highest_counter(&active.vault_id)
        .expect("confirmation records its counter");
    write_replacement(tx, active, highest)
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
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let state = load_state(&tx).unwrap();
        let envelope = export(incoming, &entropy).unwrap();
        let pending = state.prepare_restore(&envelope, &phrase).unwrap();
        assert_eq!(pending.preview().history, RestoreHistory::NoLocalHistory);
        stage_confirmed_restore(&tx, incoming, RestoreConfirmation::Replace).unwrap();
        tx.commit().unwrap();
    }
    drop(db);

    let db = open_database(&path).unwrap();
    let reopened = load_state(&db).unwrap();
    assert!(reopened.active() == Some(&second));
    assert_eq!(persisted_counter(&db, FIXTURE_VAULT_ID), 9);
    assert_eq!(persisted_counter(&db, other_id), 3);
    let envelope = export(&first, &entropy).unwrap();
    let pending = reopened.prepare_restore(&envelope, &phrase).unwrap();
    assert_eq!(pending.preview().history, RestoreHistory::OlderOrEqual);
}

#[test]
fn interrupted_replacement_recovers_both_vault_and_counter_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.sqlite");
    let original = restore_fixture(FIXTURE_VAULT_ID, 6, 1);
    seed_database(&path, &original).unwrap();

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

    let incoming = restore_fixture(FIXTURE_VAULT_ID, 9, 2);
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    stage_confirmed_restore(&tx, &incoming, RestoreConfirmation::Replace).unwrap();
    tx.commit().unwrap();
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
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    stage_confirmed_restore(&tx, &older, RestoreConfirmation::ReplaceOlderOrEqual).unwrap();
    tx.commit().unwrap();
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
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    stage_confirmed_restore(
        &tx,
        &restore_fixture(FIXTURE_VAULT_ID, 9, 2),
        RestoreConfirmation::Replace,
    )
    .unwrap();
    tx.cache_flush().unwrap();
    // Exit without running Rust or SQLite destructors and without committing.
    std::process::exit(INTERRUPTED_EXIT);
}
