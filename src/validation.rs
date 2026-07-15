use thiserror::Error;

use crate::model::{Entry, VaultData};

pub const MIN_GENERATED_PASSWORD_LEN: usize = 8;
pub const MAX_GENERATED_PASSWORD_LEN: usize = 128;
pub const MAX_ENTRIES: usize = 10_000;
pub const MAX_NAME_CHARS: usize = 256;
pub const MAX_USERNAME_CHARS: usize = 256;
pub const MAX_PASSWORD_CHARS: usize = 4_096;
pub const MAX_URL_CHARS: usize = 2_048;
pub const MAX_NOTES_CHARS: usize = 8_192;
pub const MAX_TAG_CHARS: usize = 64;
pub const MAX_TAGS_PER_ENTRY: usize = 32;
pub const MAX_TAG_INPUT_CHARS: usize = MAX_TAGS_PER_ENTRY * (MAX_TAG_CHARS + 2);
pub const MAX_VAULT_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_VAULT_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("{field} is required")]
    Required { field: &'static str },
    #[error("{field} is too long ({actual} characters; maximum {max})")]
    TooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    #[error("too many {item} ({actual}; maximum {max})")]
    TooMany {
        item: &'static str,
        max: usize,
        actual: usize,
    },
    #[error("generated password length {actual} is outside the allowed range {min}..={max}")]
    GeneratedPasswordLength {
        min: usize,
        max: usize,
        actual: usize,
    },
    #[error("vault content is too large ({actual} bytes; maximum {max})")]
    VaultContentTooLarge { max: usize, actual: usize },
    #[error("vault file is too large ({actual} bytes; maximum {max})")]
    VaultFileTooLarge { max: u64, actual: u64 },
}

pub fn validate_generated_password_length(length: usize) -> Result<(), ValidationError> {
    if !(MIN_GENERATED_PASSWORD_LEN..=MAX_GENERATED_PASSWORD_LEN).contains(&length) {
        return Err(ValidationError::GeneratedPasswordLength {
            min: MIN_GENERATED_PASSWORD_LEN,
            max: MAX_GENERATED_PASSWORD_LEN,
            actual: length,
        });
    }
    Ok(())
}

pub fn validate_entry(entry: &Entry) -> Result<(), ValidationError> {
    validate_text("name", &entry.name, MAX_NAME_CHARS, true)?;
    validate_text("username", &entry.username, MAX_USERNAME_CHARS, false)?;
    validate_text("password", &entry.password, MAX_PASSWORD_CHARS, false)?;
    validate_text("URL", &entry.url, MAX_URL_CHARS, false)?;
    validate_text("notes", &entry.notes, MAX_NOTES_CHARS, false)?;
    if entry.tags.len() > MAX_TAGS_PER_ENTRY {
        return Err(ValidationError::TooMany {
            item: "tags",
            max: MAX_TAGS_PER_ENTRY,
            actual: entry.tags.len(),
        });
    }
    for tag in &entry.tags {
        validate_text("tag", tag, MAX_TAG_CHARS, false)?;
    }
    Ok(())
}

pub fn validate_vault(data: &VaultData) -> Result<(), ValidationError> {
    if data.entries.len() > MAX_ENTRIES {
        return Err(ValidationError::TooMany {
            item: "entries",
            max: MAX_ENTRIES,
            actual: data.entries.len(),
        });
    }

    let mut content_bytes = 0usize;
    for entry in &data.entries {
        validate_entry(entry)?;
        for value in [
            &entry.name,
            &entry.username,
            &entry.password,
            &entry.url,
            &entry.notes,
        ] {
            content_bytes = content_bytes.saturating_add(value.len());
        }
        for tag in &entry.tags {
            content_bytes = content_bytes.saturating_add(tag.len());
        }
        if content_bytes > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(ValidationError::VaultContentTooLarge {
                max: MAX_VAULT_PLAINTEXT_BYTES,
                actual: content_bytes,
            });
        }
    }
    Ok(())
}

pub fn validate_plaintext_size(size: usize) -> Result<(), ValidationError> {
    if size > MAX_VAULT_PLAINTEXT_BYTES {
        return Err(ValidationError::VaultContentTooLarge {
            max: MAX_VAULT_PLAINTEXT_BYTES,
            actual: size,
        });
    }
    Ok(())
}

pub fn validate_vault_file_size(size: u64) -> Result<(), ValidationError> {
    if size > MAX_VAULT_FILE_BYTES {
        return Err(ValidationError::VaultFileTooLarge {
            max: MAX_VAULT_FILE_BYTES,
            actual: size,
        });
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    max: usize,
    required: bool,
) -> Result<(), ValidationError> {
    if required && value.trim().is_empty() {
        return Err(ValidationError::Required { field });
    }
    let actual = value.chars().count();
    if actual > max {
        return Err(ValidationError::TooLong { field, max, actual });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    fn valid_entry() -> Entry {
        Entry {
            id: Uuid::new_v4(),
            name: "Example".into(),
            username: "user".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: String::new(),
            tags: vec!["work".into()],
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn generated_password_length_has_safe_bounds() {
        assert!(validate_generated_password_length(8).is_ok());
        assert!(validate_generated_password_length(128).is_ok());
        assert!(validate_generated_password_length(7).is_err());
        assert!(validate_generated_password_length(129).is_err());
    }

    #[test]
    fn entry_requires_a_nonblank_name() {
        let mut entry = valid_entry();
        entry.name = "  ".into();
        assert_eq!(
            validate_entry(&entry),
            Err(ValidationError::Required { field: "name" })
        );
    }

    #[test]
    fn entry_limits_use_character_count() {
        let mut entry = valid_entry();
        entry.name = "é".repeat(MAX_NAME_CHARS);
        assert!(validate_entry(&entry).is_ok());
        entry.name.push('é');
        assert!(matches!(
            validate_entry(&entry),
            Err(ValidationError::TooLong { field: "name", .. })
        ));
    }

    #[test]
    fn entry_limits_tags() {
        let mut entry = valid_entry();
        entry.tags = vec!["tag".into(); MAX_TAGS_PER_ENTRY + 1];
        assert!(matches!(
            validate_entry(&entry),
            Err(ValidationError::TooMany { item: "tags", .. })
        ));
    }

    #[test]
    fn vault_limits_entry_count() {
        let mut data = VaultData::new();
        data.entries = (0..=MAX_ENTRIES).map(|_| valid_entry()).collect();
        assert!(matches!(
            validate_vault(&data),
            Err(ValidationError::TooMany {
                item: "entries",
                ..
            })
        ));
    }

    #[test]
    fn vault_file_size_is_capped() {
        assert!(validate_vault_file_size(MAX_VAULT_FILE_BYTES).is_ok());
        assert!(validate_vault_file_size(MAX_VAULT_FILE_BYTES + 1).is_err());
    }
}
