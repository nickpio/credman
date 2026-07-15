use std::path::PathBuf;

use chrono::Utc;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::normalize_mnemonic;
use crate::model::Entry;
use crate::vault::UnlockedVault;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    Main,
    Add,
    Edit,
    ConfirmDelete,
    Quit,
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
    pub vault: Option<UnlockedVault>,
    pub filter: String,
    pub filtering: bool,
    pub selected: usize,
    pub show_password: bool,
    pub status: String,
    pub form: FormState,
    pub filtered_indices: Vec<usize>,
}

impl App {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            screen: Screen::Unlock,
            seed_input: String::new(),
            show_seed: false,
            unlock_error: None,
            vault: None,
            filter: String::new(),
            filtering: false,
            selected: 0,
            show_password: false,
            status: "Enter seed phrase and press Enter".into(),
            form: FormState::default(),
            filtered_indices: Vec::new(),
        }
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

    pub fn try_unlock(&mut self) {
        let phrase = Zeroizing::new(normalize_mnemonic(&self.seed_input));
        match UnlockedVault::unlock(&self.path, &phrase) {
            Ok(vault) => {
                self.vault = Some(vault);
                self.seed_input.zeroize();
                self.show_seed = false;
                self.unlock_error = None;
                self.screen = Screen::Main;
                self.status = "Unlocked. / filter  a add  e edit  d delete  c copy  r reveal  q quit"
                    .into();
                self.recompute_filter();
            }
            Err(_) => {
                self.unlock_error = Some("Wrong seed phrase or corrupted vault".into());
                self.show_seed = false;
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
        self.status = "Tab next field  Enter save  Esc cancel".into();
    }

    pub fn open_edit(&mut self) {
        let Some(idx) = self.selected_entry_index() else {
            self.status = "No entry selected".into();
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
        self.status = "Tab next field  Enter save  Esc cancel".into();
    }

    pub fn save_form(&mut self) {
        if self.form.name.trim().is_empty() {
            self.status = "Name is required".into();
            return;
        }
        let tags: Vec<String> = self
            .form
            .tags
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let vault = self.vault.as_mut().unwrap();
        if let Some(id) = self.form.edit_id {
            if let Some(entry) = vault.data.entries.iter_mut().find(|e| e.id == id) {
                entry.name = self.form.name.clone();
                entry.username = self.form.username.clone();
                entry.password = self.form.password.clone();
                entry.url = self.form.url.clone();
                entry.notes = self.form.notes.clone();
                entry.tags = tags;
                entry.updated_at = Utc::now();
            }
            self.status = "Entry updated".into();
        } else {
            vault.data.entries.push(Entry {
                id: Uuid::new_v4(),
                name: self.form.name.clone(),
                username: self.form.username.clone(),
                password: self.form.password.clone(),
                url: self.form.url.clone(),
                notes: self.form.notes.clone(),
                tags,
                updated_at: Utc::now(),
            });
            self.status = "Entry added".into();
        }
        if let Err(e) = vault.persist() {
            self.status = format!("Save failed: {e}");
        }
        self.form = FormState::default();
        self.screen = Screen::Main;
        self.recompute_filter();
    }

    pub fn request_delete(&mut self) {
        if self.selected_entry_index().is_none() {
            self.status = "No entry selected".into();
            return;
        }
        self.screen = Screen::ConfirmDelete;
        self.status = "Delete selected entry? y/n".into();
    }

    pub fn confirm_delete(&mut self, yes: bool) {
        if yes {
            if let Some(idx) = self.selected_entry_index() {
                let vault = self.vault.as_mut().unwrap();
                let name = vault.data.entries[idx].name.clone();
                vault.data.entries.remove(idx);
                if let Err(e) = vault.persist() {
                    self.status = format!("Save failed: {e}");
                } else {
                    self.status = format!("Deleted '{name}'");
                }
            }
        } else {
            self.status = "Delete cancelled".into();
        }
        self.screen = Screen::Main;
        self.recompute_filter();
    }

    pub fn copy_password(&mut self) {
        let Some(idx) = self.selected_entry_index() else {
            self.status = "No entry selected".into();
            return;
        };
        let password = self.vault.as_ref().unwrap().data.entries[idx]
            .password
            .clone();
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(password)) {
            Ok(()) => self.status = "Password copied".into(),
            Err(e) => self.status = format!("Clipboard error: {e}"),
        }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut app = App::new(PathBuf::from("missing-vault"));
        app.seed_input = "one two three".into();
        app.show_seed = true;

        app.try_unlock();

        assert_eq!(app.seed_input, "one two three");
        assert!(!app.show_seed);
        assert!(app.unlock_error.is_some());
    }
}
