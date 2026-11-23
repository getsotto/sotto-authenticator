use std::collections::BTreeMap;
use std::sync::Arc;

use super::payload::{SyntheticVault, MAX_JSON_INTEGER};
use super::recovery_phrase::RecoveryPhrase;
use super::{export_with_randomness, open, ExportError, ExportRandomness, SecretKey};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RestoreHistory {
    NoLocalHistory,
    OlderOrEqual,
    /// The counter exceeds local history, which cannot rule out an offline fork.
    HigherCounterFreshnessUnknown,
}

pub(super) struct RestorePreview {
    pub(super) vault_id: String,
    pub(super) issued_at: u64,
    pub(super) export_counter: u64,
    pub(super) history: RestoreHistory,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PreviewError {
    InvalidPhrase,
    InvalidExport(ExportError),
}

#[derive(PartialEq, Eq)]
pub(super) enum RestoreConfirmation {
    Replace,
    ReplaceOlderOrEqual,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ConfirmError {
    PreviewChanged,
    RollbackAcknowledgementRequired,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReserveExportError {
    NoActiveVault,
    InvalidIssueDate,
    CounterExhausted,
}

/// A snapshot with a counter already recorded in local history. Dropping it
/// or failing to encrypt it leaves a gap, so a retry always gets a new counter.
pub(super) struct ReservedExport(SyntheticVault);

impl ReservedExport {
    pub(super) fn seal(self, entropy: &SecretKey) -> Result<Vec<u8>, ExportError> {
        self.seal_with_randomness(entropy, ExportRandomness::generate)
    }

    pub(super) fn seal_with_randomness(
        self,
        entropy: &SecretKey,
        generate: impl FnOnce() -> Result<ExportRandomness, ExportError>,
    ) -> Result<Vec<u8>, ExportError> {
        export_with_randomness(&self.0, entropy, generate)
    }
}

pub(super) struct RestoreState {
    active: Option<SyntheticVault>,
    highest_counters: BTreeMap<String, u64>,
    // A private generation ties the preview to this state and invalidates it
    // after a replacement, even if the replacement has the same ID and counter.
    active_generation: Arc<()>,
}

impl RestoreState {
    pub(super) fn new(
        active: Option<SyntheticVault>,
        mut highest_counters: BTreeMap<String, u64>,
    ) -> Self {
        if let Some(vault) = &active {
            record_counter(&mut highest_counters, vault);
        }
        Self {
            active,
            highest_counters,
            active_generation: Arc::new(()),
        }
    }

    pub(super) fn active(&self) -> Option<&SyntheticVault> {
        self.active.as_ref()
    }

    pub(super) fn highest_counter(&self, vault_id: &str) -> Option<u64> {
        self.highest_counters.get(vault_id).copied()
    }

    /// Reserve and snapshot under exclusive access. Encryption can happen
    /// after the caller releases that access.
    pub(super) fn reserve_export(
        &mut self,
        issued_at: u64,
    ) -> Result<ReservedExport, ReserveExportError> {
        let active = self
            .active
            .as_ref()
            .ok_or(ReserveExportError::NoActiveVault)?;
        if issued_at > MAX_JSON_INTEGER {
            return Err(ReserveExportError::InvalidIssueDate);
        }

        let counter = self
            .highest_counter(&active.vault_id)
            .unwrap_or(active.export_counter)
            .checked_add(1)
            .filter(|&counter| counter <= MAX_JSON_INTEGER)
            .ok_or(ReserveExportError::CounterExhausted)?;
        let mut snapshot = active.clone();
        snapshot.export_counter = counter;
        snapshot.issued_at = issued_at;
        record_counter(&mut self.highest_counters, &snapshot);
        Ok(ReservedExport(snapshot))
    }

    pub(super) fn prepare_restore(
        &self,
        envelope: &[u8],
        phrase: &str,
    ) -> Result<PendingRestore, PreviewError> {
        let phrase = RecoveryPhrase::parse(phrase).map_err(|_| PreviewError::InvalidPhrase)?;
        let entropy = phrase.entropy().map_err(|_| PreviewError::InvalidPhrase)?;
        let vault = open(envelope, &entropy).map_err(PreviewError::InvalidExport)?;
        let known_counter = self.highest_counter(&vault.vault_id);
        let history = match known_counter {
            None => RestoreHistory::NoLocalHistory,
            Some(counter) if vault.export_counter <= counter => RestoreHistory::OlderOrEqual,
            Some(_) => RestoreHistory::HigherCounterFreshnessUnknown,
        };
        let preview = RestorePreview {
            vault_id: vault.vault_id.clone(),
            issued_at: vault.issued_at,
            export_counter: vault.export_counter,
            history,
        };
        Ok(PendingRestore {
            vault,
            preview,
            known_counter,
            active_generation: Arc::clone(&self.active_generation),
        })
    }
}

/// Owns the authenticated vault until confirmation. Dropping it cancels the
/// restore and leaves the active vault and counter history untouched.
pub(super) struct PendingRestore {
    vault: SyntheticVault,
    preview: RestorePreview,
    known_counter: Option<u64>,
    active_generation: Arc<()>,
}

impl PendingRestore {
    pub(super) fn preview(&self) -> &RestorePreview {
        &self.preview
    }

    /// Consume the preview. A changed state or missing acknowledgement requires
    /// the caller to prepare a fresh preview before trying again.
    pub(super) fn confirm(
        self,
        state: &mut RestoreState,
        confirmation: RestoreConfirmation,
    ) -> Result<(), ConfirmError> {
        if !Arc::ptr_eq(&state.active_generation, &self.active_generation)
            || state.highest_counter(&self.vault.vault_id) != self.known_counter
        {
            return Err(ConfirmError::PreviewChanged);
        }
        if self.preview.history == RestoreHistory::OlderOrEqual
            && confirmation != RestoreConfirmation::ReplaceOlderOrEqual
        {
            return Err(ConfirmError::RollbackAcknowledgementRequired);
        }

        // Exclusive access makes this one in-memory transition. A persistent
        // implementation must commit the vault and counter in one transaction.
        record_counter(&mut state.highest_counters, &self.vault);
        state.active = Some(self.vault);
        state.active_generation = Arc::new(());
        Ok(())
    }
}

fn record_counter(counters: &mut BTreeMap<String, u64>, vault: &SyntheticVault) {
    let highest = counters.entry(vault.vault_id.clone()).or_default();
    *highest = (*highest).max(vault.export_counter);
}

#[test]
fn requires_a_new_preview_when_counter_history_changes_without_a_replacement() {
    use super::{export, MAX_PLAINTEXT_BYTES};
    use zeroize::Zeroizing;

    let json = br#"{"formatVersion":1,"vaultId":"00000000000000000000000000000000","exportCounter":7,"issuedAt":0,"projects":[]}"#;
    let vault = SyntheticVault::from_bytes(json, MAX_PLAINTEXT_BYTES).unwrap();
    let entropy = Zeroizing::new([0; 32]);
    let envelope = export(&vault, &entropy).unwrap();
    // Public BIP-39 fixture for the all-zero entropy above.
    let phrase = format!("{}art", "abandon ".repeat(23));
    let mut active = vault.clone();
    active.export_counter = 6;
    let mut state = RestoreState::new(Some(active.clone()), BTreeMap::new());
    let pending = state.prepare_restore(&envelope, &phrase).unwrap();

    drop(state.reserve_export(1).unwrap());
    assert_eq!(
        pending.confirm(&mut state, RestoreConfirmation::Replace),
        Err(ConfirmError::PreviewChanged)
    );
    assert!(state.active() == Some(&active));
    assert_eq!(state.highest_counter(&vault.vault_id), Some(7));
}
