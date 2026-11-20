use std::collections::BTreeMap;

use super::recovery_phrase::RecoveryPhrase;
use super::{open, ExportError};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RestoreHistory {
    NoLocalHistory,
    OlderOrEqual,
    NewerThanLocal,
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

/// Prepare a read-only preview from authenticated, validated export data.
///
/// The caller supplies the highest locally issued or accepted counter for each
/// vault. A preview does not add to that history. A later confirmation step
/// must check current history again before installing the vault.
pub(super) fn preview_restore(
    envelope: &[u8],
    phrase: &str,
    local_counters: &BTreeMap<String, u64>,
) -> Result<RestorePreview, PreviewError> {
    let phrase = RecoveryPhrase::parse(phrase).map_err(|_| PreviewError::InvalidPhrase)?;
    let entropy = phrase.entropy().map_err(|_| PreviewError::InvalidPhrase)?;
    let vault = open(envelope, &entropy).map_err(PreviewError::InvalidExport)?;
    let history = match local_counters.get(&vault.vault_id) {
        None => RestoreHistory::NoLocalHistory,
        Some(&counter) if vault.export_counter <= counter => RestoreHistory::OlderOrEqual,
        Some(_) => RestoreHistory::NewerThanLocal,
    };
    Ok(RestorePreview {
        vault_id: vault.vault_id,
        issued_at: vault.issued_at,
        export_counter: vault.export_counter,
        history,
    })
}
