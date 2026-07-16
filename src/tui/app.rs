use std::path::PathBuf;

use chrono::Utc;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::clipboard::{ClearOutcome, PendingClipboard};
use crate::crypto::{normalize_mnemonic, validate_mnemonic, CryptoError};
use crate::model::Entry;
use crate::validation::{
    validate_entry, validate_vault, MAX_NAME_CHARS, MAX_NOTES_CHARS, MAX_PASSWORD_CHARS,
    MAX_TAG_INPUT_CHARS, MAX_URL_CHARS, MAX_USERNAME_CHARS,
};
use crate::vault::{UnlockedVault, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Setup,
    Unlock,
    Main,
    Add,
    Edit,
    ConfirmDelete,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusKind {
    #[default]
    Info,
    Success,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputField {
    #[default]
    Name,
    Username,
    Password,
    Url,
    Notes,
    Tags,
}

impl InputField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Username,
            Self::Username => Self::Password,
            Self::Password => Self::Url,
            Self::Url => Self::Notes,
            Self::Notes => Self::Tags,
            Self::Tags => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::Tags,
            Self::Username => Self::Name,
            Self::Password => Self::Username,
            Self::Url => Self::Password,
            Self::Notes => Self::Url,
            Self::Tags => Self::Notes,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FormState {
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: String,
    pub field: InputField,
    pub edit_id: Option<Uuid>,
}

pub struct App {
    pub path: PathBuf,
    pub screen: Screen,
    pub seed_input: String,
    pub show_seed: bool,
    pub unlock_error: Option<String>,
    /// Set by Enter; main loop draws "Unlocking…" then calls `finish_unlock`.
    pub unlocking: bool,
    pub vault: Option<UnlockedVault>,
    pub filter: String,
    pub filtering: bool,
    pub selected: usize,
    pub show_password: bool,
    pub status: String,
    pub status_kind: StatusKind,
    pub form: FormState,
    pub filtered_indices: Vec<usize>,
    delete_target: Option<Uuid>,
    clipboard_copy: Option<PendingClipboard>,
}

impl App {
    pub fn new(path: PathBuf) -> Self {
        let exists = path.exists();
        Self {
            path,
            screen: if exists {
                Screen::Unlock
            } else {
                Screen::Setup
            },
            seed_input: String::new(),
            show_seed: false,
            unlock_error: None,
            unlocking: false,
            vault: None,
            filter: String::new(),
            filtering: false,
            selected: 0,
            show_password: false,
            status: if exists {
                "Enter seed phrase and press Enter".into()
            } else {
                "No vault yet — create one to get started".into()
            },
            status_kind: StatusKind::Info,
            form: FormState::default(),
            filtered_indices: Vec::new(),
            delete_target: None,
            clipboard_copy: None,
        }
    }

    pub fn set_status(&mut self, msg: impl Into<String>, kind: StatusKind) {
        self.status = msg.into();
        self.status_kind = kind;
    }

    pub fn info(&mut self, msg: impl Into<String>) {
        self.set_status(msg, StatusKind::Info);
    }

    pub fn success(&mut self, msg: impl Into<String>) {
        self.set_status(msg, StatusKind::Success);
    }

    pub fn error_status(&mut self, msg: impl Into<String>) {
        self.set_status(msg, StatusKind::Error);
    }

    pub fn recompute_filter(&mut self) {
        let Some(vault) = self.vault.as_ref() else {
            self.filtered_indices.clear();
            return;
        };
        if self.filter.is_empty() {
            self.filtered_indices = (0..vault.data.entries.len()).collect();
        } else {
            let matcher = SkimMatcherV2::default();
            let mut scored: Vec<(i64, usize)> = vault
                .data
                .entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| {
                    let hay = format!(
                        "{} {} {} {}",
                        e.name,
                        e.username,
                        e.url,
                        e.tags.join(" ")
                    );
                    matcher
                        .fuzzy_match(&hay, &self.filter)
                        .map(|score| (score, i))
                })
                .collect();
            scored.sort_by(|a, b| b.0.cmp(&a.0));
            self.filtered_indices = scored.into_iter().map(|(_, i)| i).collect();
        }
        if self.selected >= self.filtered_indices.len() && !self.filtered_indices.is_empty() {
            self.selected = self.filtered_indices.len() - 1;
        }
        if self.filtered_indices.is_empty() {
            self.selected = 0;
        }
    }

    pub fn selected_entry_index(&self) -> Option<usize> {
        self.filtered_indices.get(self.selected).copied()
    }

    pub fn seed_word_count(&self) -> usize {
        self.seed_input.split_whitespace().count()
    }

    pub fn seed_display(&self) -> String {
        if self.show_seed {
            self.seed_input.clone()
        } else {
            self.seed_input
                .split_whitespace()
                .map(|_| "••••")
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    /// Validate the phrase and queue unlock so the UI can show a busy state first.
    pub fn start_unlock(&mut self) {
        if self.unlocking {
            return;
        }
        let phrase = normalize_mnemonic(&self.seed_input);
        if let Err(e) = validate_mnemonic(&phrase) {
            self.unlock_error = Some(format_crypto_error(&e));
            self.show_seed = false;
            self.info("Fix the phrase and press Enter");
            return;
        }
        self.unlock_error = None;
        self.unlocking = true;
        self.info("Unlocking…");
    }

    /// Run after a redraw with `unlocking == true`.
    pub fn finish_unlock(&mut self) {
        let phrase = Zeroizing::new(normalize_mnemonic(&self.seed_input));
        match UnlockedVault::unlock(&self.path, &phrase) {
            Ok(vault) => {
                self.vault = Some(vault);
                self.seed_input.zeroize();
                self.show_seed = false;
                self.unlock_error = None;
                self.unlocking = false;
                self.screen = Screen::Main;
                self.success(
                    "Unlocked. / filter  a add  e edit  d delete  c copy  r reveal  q quit",
                );
                self.recompute_filter();
            }
            Err(e) => {
                let (msg, clear_seed) = format_unlock_error(&e);
                self.unlock_error = Some(msg);
                if clear_seed {
                    self.seed_input.zeroize();
                }
                self.show_seed = false;
                self.unlocking = false;
                self.error_status("Unlock failed");
            }
        }
    }

    pub fn move_selection(&mut self, delta: isize) {
        let len = self.filtered_indices.len();
        if len == 0 {
            return;
        }
        let cur = self.selected as isize + delta;
        self.selected = cur.rem_euclid(len as isize) as usize;
        self.show_password = false;
    }

    pub fn open_add(&mut self) {
        self.form = FormState {
            field: InputField::Name,
            ..FormState::default()
        };
        self.screen = Screen::Add;
        self.info("Tab next field  Enter save  Esc cancel");
    }

    pub fn open_edit(&mut self) {
        let Some(idx) = self.selected_entry_index() else {
            self.error_status("No entry selected");
            return;
        };
        let entry = &self.vault.as_ref().unwrap().data.entries[idx];
        self.form = FormState {
            name: entry.name.clone(),
            username: entry.username.clone(),
            password: entry.password.clone(),
            url: entry.url.clone(),
            notes: entry.notes.clone(),
            tags: entry.tags.join(", "),
            field: InputField::Name,
            edit_id: Some(entry.id),
        };
        self.screen = Screen::Edit;
        self.info("Tab next field  Enter save  Esc cancel");
    }

    pub fn save_form(&mut self) {
        let tags: Vec<String> = self
            .form
            .tags
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let entry = Entry {
            id: self.form.edit_id.unwrap_or_else(Uuid::new_v4),
            name: self.form.name.clone(),
            username: self.form.username.clone(),
            password: self.form.password.clone(),
            url: self.form.url.clone(),
            notes: self.form.notes.clone(),
            tags,
            updated_at: Utc::now(),
        };
        if let Err(error) = validate_entry(&entry) {
            self.error_status(error.to_string());
            return;
        }

        let vault = self.vault.as_mut().unwrap();
        let mut next_data = vault.data.clone();
        if let Some(id) = self.form.edit_id {
            if let Some(existing) = next_data
                .entries
                .iter_mut()
                .find(|candidate| candidate.id == id)
            {
                *existing = entry;
            }
        } else {
            next_data.entries.push(entry);
        }
        if let Err(error) = validate_vault(&next_data) {
            self.error_status(error.to_string());
            return;
        }

        let previous_data = std::mem::replace(&mut vault.data, next_data);
        let editing = self.form.edit_id.is_some();
        if let Err(error) = vault.persist() {
            vault.data = previous_data;
            self.error_status(format!("Save failed: {error}"));
            return;
        }
        if editing {
            self.success("Entry updated");
        } else {
            self.success("Entry added");
        }
        self.form = FormState::default();
        self.screen = Screen::Main;
        self.recompute_filter();
    }

    pub fn request_delete(&mut self) {
        let Some(index) = self.selected_entry_index() else {
            self.error_status("No entry selected");
            return;
        };
        let (id, name) = {
            let entry = &self.vault.as_ref().unwrap().data.entries[index];
            (entry.id, entry.name.clone())
        };
        self.delete_target = Some(id);
        self.screen = Screen::ConfirmDelete;
        self.info(format!("Delete '{name}'? y/n"));
    }

    pub fn confirm_delete(&mut self, yes: bool) {
        if yes {
            if let Some(id) = self.delete_target {
                let vault = self.vault.as_mut().unwrap();
                if let Some(index) = vault.data.entries.iter().position(|entry| entry.id == id) {
                    let name = vault.data.entries[index].name.clone();
                    vault.data.entries.remove(index);
                    if let Err(e) = vault.persist() {
                        self.error_status(format!("Save failed: {e}"));
                    } else {
                        self.success(format!("Deleted '{name}'"));
                    }
                }
            }
        } else {
            self.info("Delete cancelled");
        }
        self.delete_target = None;
        self.screen = Screen::Main;
        self.recompute_filter();
    }

    pub fn delete_target_name(&self) -> Option<&str> {
        let id = self.delete_target?;
        self.vault
            .as_ref()?
            .data
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.name.as_str())
    }

    pub fn copy_password(&mut self) {
        let Some(idx) = self.selected_entry_index() else {
            self.error_status("No entry selected");
            return;
        };
        let password = self.vault.as_ref().unwrap().data.entries[idx]
            .password
            .clone();
        match PendingClipboard::copy(&password) {
            Ok(copy) => {
                self.clipboard_copy = Some(copy);
                self.success("Password copied");
            }
            Err(e) => self.error_status(format!("Clipboard error: {e}")),
        }
    }

    pub fn tick_clipboard(&mut self) {
        let expired = self
            .clipboard_copy
            .as_ref()
            .is_some_and(PendingClipboard::is_expired);
        if !expired {
            return;
        }

        let copy = self.clipboard_copy.take().unwrap();
        match copy.clear_if_unchanged() {
            Ok(ClearOutcome::Cleared) => self.info("Clipboard cleared"),
            Ok(ClearOutcome::Changed) => self.info("Clipboard changed; clear skipped"),
            Err(error) => self.error_status(format!("Clipboard clear failed: {error}")),
        }
    }

    pub fn status_line(&self) -> String {
        match &self.clipboard_copy {
            Some(copy) => format!(
                "{} · clipboard clears in {}s",
                self.status,
                copy.remaining_seconds()
            ),
            None => self.status.clone(),
        }
    }

    pub fn form_password_display(&self) -> &'static str {
        if self.form.password.is_empty() {
            ""
        } else {
            "••••••••"
        }
    }

    pub fn list_empty_message(&self) -> Option<String> {
        let vault = self.vault.as_ref()?;
        if vault.data.entries.is_empty() {
            return Some("Vault is empty. Press 'a' to add an entry.".into());
        }
        if self.filtered_indices.is_empty() && !self.filter.is_empty() {
            return Some(format!(
                "No matches for '{}'. Press Esc to clear the filter.",
                self.filter
            ));
        }
        None
    }

    pub fn push_form_char(&mut self, character: char) {
        let (field, max) = match self.form.field {
            InputField::Name => ("Name", MAX_NAME_CHARS),
            InputField::Username => ("Username", MAX_USERNAME_CHARS),
            InputField::Password => ("Password", MAX_PASSWORD_CHARS),
            InputField::Url => ("URL", MAX_URL_CHARS),
            InputField::Notes => ("Notes", MAX_NOTES_CHARS),
            InputField::Tags => ("Tags", MAX_TAG_INPUT_CHARS),
        };
        if self.active_form_value_mut().chars().count() >= max {
            self.error_status(format!("{field} is limited to {max} characters"));
            return;
        }
        self.active_form_value_mut().push(character);
    }

    pub fn active_form_value_mut(&mut self) -> &mut String {
        match self.form.field {
            InputField::Name => &mut self.form.name,
            InputField::Username => &mut self.form.username,
            InputField::Password => &mut self.form.password,
            InputField::Url => &mut self.form.url,
            InputField::Notes => &mut self.form.notes,
            InputField::Tags => &mut self.form.tags,
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.seed_input.zeroize();
        if let Some(copy) = self.clipboard_copy.take() {
            let _ = copy.clear_if_unchanged();
        }
    }
}

fn format_crypto_error(err: &CryptoError) -> String {
    match err {
        CryptoError::InvalidMnemonic(detail) => format!("Invalid seed phrase: {detail}"),
        other => other.to_string(),
    }
}

/// Returns (message, clear_seed). Clear seed only when the phrase itself was wrong.
fn format_unlock_error(err: &VaultError) -> (String, bool) {
    match err {
        VaultError::Crypto(CryptoError::Decrypt) => ("Wrong seed phrase".into(), true),
        VaultError::Crypto(CryptoError::InvalidMnemonic(detail)) => {
            (format!("Invalid seed phrase: {detail}"), false)
        }
        VaultError::Crypto(other) => (other.to_string(), false),
        VaultError::Invalid(reason) => (format!("Corrupted vault: {reason}"), false),
        VaultError::Json(_) => ("Corrupted vault: invalid data".into(), false),
        VaultError::NotFound(path) => (
            format!(
                "Vault not found at {}. Run `credman init` or `credman restore` first.",
                path.display()
            ),
            false,
        ),
        other => (other.to_string(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    fn unlocked_app() -> (TempDir, App) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let phrase = crate::crypto::generate_mnemonic().unwrap();
        let vault = UnlockedVault::create(&path, &phrase).unwrap();
        let mut app = App::new(path);
        app.vault = Some(vault);
        app.screen = Screen::Main;
        app.recompute_filter();
        (dir, app)
    }

    fn test_entry(name: &str) -> Entry {
        Entry {
            id: Uuid::new_v4(),
            name: name.into(),
            username: String::new(),
            password: "secret".into(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn seed_display_masks_words_without_revealing_lengths() {
        let mut app = App::new(PathBuf::from("vault"));
        app.seed_input = "short exceptionallylong".into();

        assert_eq!(app.seed_word_count(), 2);
        assert_eq!(app.seed_display(), "•••• ••••");

        app.show_seed = true;
        assert_eq!(app.seed_display(), "short exceptionallylong");
    }

    #[test]
    fn failed_unlock_preserves_masked_seed_for_correction() {
        let dir = tempdir().unwrap();
        let mut app = App::new(dir.path().join("missing-vault"));
        app.seed_input = "one two three".into();
        app.show_seed = true;

        app.start_unlock();

        assert_eq!(app.seed_input, "one two three");
        assert!(!app.show_seed);
        assert!(!app.unlocking);
        assert!(app.unlock_error.is_some());
    }

    #[test]
    fn form_password_mask_does_not_reveal_length() {
        let mut app = App::new(PathBuf::from("vault"));
        app.form.password = "short".into();
        assert_eq!(app.form_password_display(), "••••••••");
        app.form.password = "a much longer password".into();
        assert_eq!(app.form_password_display(), "••••••••");
    }

    #[test]
    fn delete_confirmation_tracks_entry_by_id() {
        let (_dir, mut app) = unlocked_app();
        app.vault
            .as_mut()
            .unwrap()
            .data
            .entries
            .push(test_entry("Production"));
        app.recompute_filter();

        app.request_delete();

        assert_eq!(app.delete_target_name(), Some("Production"));
        assert!(app.status.contains("Production"));
        app.confirm_delete(false);
        assert_eq!(app.vault.as_ref().unwrap().data.entries.len(), 1);
        assert_eq!(app.delete_target_name(), None);
    }

    #[test]
    fn empty_vault_and_empty_filter_results_have_distinct_messages() {
        let (_dir, mut app) = unlocked_app();
        assert!(app.list_empty_message().unwrap().contains("Vault is empty"));

        app.vault
            .as_mut()
            .unwrap()
            .data
            .entries
            .push(test_entry("GitHub"));
        app.filter = "missing".into();
        app.recompute_filter();

        let message = app.list_empty_message().unwrap();
        assert!(message.contains("No matches"));
        assert!(message.contains("missing"));
    }

    #[test]
    fn form_input_stops_at_field_limit() {
        let mut app = App::new(PathBuf::from("vault"));
        app.form.field = InputField::Name;
        app.form.name = "a".repeat(MAX_NAME_CHARS);

        app.push_form_char('b');

        assert_eq!(app.form.name.chars().count(), MAX_NAME_CHARS);
        assert!(app.status.contains("limited"));
    }
}
