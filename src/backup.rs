use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{
    self, decrypt, derive_key_from_secret, encrypt, normalize_mnemonic, random_nonce, random_salt,
    validate_mnemonic, ARGON2_M_KIB, ARGON2_P_COST, ARGON2_T_COST, NONCE_LEN, SALT_LEN,
};
use crate::model::VaultData;
use crate::validation::{
    validate_plaintext_size, validate_vault, validate_vault_file_size, ValidationError,
};

pub const FORMAT_NAME: &str = "credman-backup";
pub const FORMAT_VERSION: u32 = 1;
pub const MIN_PASSPHRASE_CHARS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupSecretKind {
    Seed,
    Passphrase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupKdf {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBackup {
    pub format: String,
    pub version: u32,
    pub secret: BackupSecretKind,
    pub kdf: BackupKdf,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("invalid backup file: {0}")]
    Invalid(String),
    #[error("passphrase must be at least {MIN_PASSPHRASE_CHARS} characters")]
    PassphraseTooShort,
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

impl EncryptedBackup {
    pub fn encrypt_with_seed(data: &VaultData, mnemonic: &str) -> Result<Self, BackupError> {
        validate_mnemonic(mnemonic)?;
        let normalized = Zeroizing::new(normalize_mnemonic(mnemonic));
        Self::encrypt_inner(data, BackupSecretKind::Seed, normalized.as_bytes())
    }

    pub fn encrypt_with_passphrase(data: &VaultData, passphrase: &str) -> Result<Self, BackupError> {
        validate_passphrase(passphrase)?;
        Self::encrypt_inner(data, BackupSecretKind::Passphrase, passphrase.as_bytes())
    }

    fn encrypt_inner(
        data: &VaultData,
        secret_kind: BackupSecretKind,
        secret: &[u8],
    ) -> Result<Self, BackupError> {
        validate_vault(data)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(data)?);
        validate_plaintext_size(plaintext.len())?;
        let salt = random_salt();
        let nonce = random_nonce();
        let key = derive_key_from_secret(secret, &salt)?;
        let ciphertext = encrypt(&key, &nonce, &plaintext)?;
        Ok(Self {
            format: FORMAT_NAME.into(),
            version: FORMAT_VERSION,
            secret: secret_kind,
            kdf: BackupKdf {
                alg: "argon2id".into(),
                m_kib: ARGON2_M_KIB,
                t: ARGON2_T_COST,
                p: ARGON2_P_COST,
            },
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(ciphertext),
        })
    }

    pub fn decrypt_with_seed(&self, mnemonic: &str) -> Result<VaultData, BackupError> {
        if self.secret != BackupSecretKind::Seed {
            return Err(BackupError::Invalid(
                "backup was encrypted with a passphrase; use --passphrase".into(),
            ));
        }
        validate_mnemonic(mnemonic)?;
        let normalized = Zeroizing::new(normalize_mnemonic(mnemonic));
        self.decrypt_inner(normalized.as_bytes())
    }

    pub fn decrypt_with_passphrase(&self, passphrase: &str) -> Result<VaultData, BackupError> {
        if self.secret != BackupSecretKind::Passphrase {
            return Err(BackupError::Invalid(
                "backup was encrypted with the seed phrase; omit --passphrase".into(),
            ));
        }
        validate_passphrase(passphrase)?;
        self.decrypt_inner(passphrase.as_bytes())
    }

    fn decrypt_inner(&self, secret: &[u8]) -> Result<VaultData, BackupError> {
        self.validate_header()?;
        let salt = decode_fixed::<SALT_LEN>(&self.salt_b64, "salt")?;
        let nonce = decode_fixed::<NONCE_LEN>(&self.nonce_b64, "nonce")?;
        let ciphertext = B64.decode(&self.ciphertext_b64)?;
        validate_vault_file_size(ciphertext.len() as u64)?;
        let key = derive_key_from_secret(secret, &salt)?;
        let plaintext = Zeroizing::new(decrypt(&key, &nonce, &ciphertext)?);
        validate_plaintext_size(plaintext.len())?;
        let data: VaultData = serde_json::from_slice(&plaintext)?;
        validate_vault(&data)?;
        Ok(data)
    }

    fn validate_header(&self) -> Result<(), BackupError> {
        if self.format != FORMAT_NAME {
            return Err(BackupError::Invalid(format!(
                "unknown format {:?}",
                self.format
            )));
        }
        if self.version != FORMAT_VERSION {
            return Err(BackupError::Invalid(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.kdf.alg != "argon2id" {
            return Err(BackupError::Invalid(format!(
                "unsupported kdf {}",
                self.kdf.alg
            )));
        }
        // v1 always derives with compile-time defaults; reject mismatched params early.
        if self.kdf.m_kib != ARGON2_M_KIB
            || self.kdf.t != ARGON2_T_COST
            || self.kdf.p != ARGON2_P_COST
        {
            return Err(BackupError::Invalid(
                "unsupported Argon2 parameters".into(),
            ));
        }
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<(), BackupError> {
        let json = serde_json::to_vec_pretty(self)?;
        validate_vault_file_size(json.len() as u64)?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&json)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, BackupError> {
        if !path.exists() {
            return Err(BackupError::Invalid(format!(
                "file not found: {}",
                path.display()
            )));
        }
        validate_vault_file_size(fs::metadata(path)?.len())?;
        let bytes = fs::read(path)?;
        let backup: Self = serde_json::from_slice(&bytes)?;
        backup.validate_header()?;
        Ok(backup)
    }
}

pub fn validate_passphrase(passphrase: &str) -> Result<(), BackupError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(BackupError::PassphraseTooShort);
    }
    Ok(())
}

/// Merge imported entries into `target`. Matching IDs are replaced by the import.
pub fn merge_entries(target: &mut VaultData, mut imported: VaultData) {
    for entry in std::mem::take(&mut imported.entries) {
        if let Some(existing) = target.entries.iter_mut().find(|e| e.id == entry.id) {
            *existing = entry;
        } else {
            target.entries.push(entry);
        }
    }
}

fn decode_fixed<const N: usize>(b64: &str, field: &str) -> Result<[u8; N], BackupError> {
    let bytes = B64.decode(b64)?;
    bytes.try_into().map_err(|_| {
        BackupError::Invalid(format!(
            "{field} has wrong length (expected {N} bytes)"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_mnemonic;
    use crate::model::Entry;
    use chrono::Utc;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn sample_data(password: &str) -> VaultData {
        let mut data = VaultData::new();
        data.entries.push(Entry {
            id: Uuid::from_u128(1),
            name: "Example".into(),
            username: "user".into(),
            password: password.into(),
            url: String::new(),
            notes: String::new(),
            tags: vec!["a".into()],
            updated_at: Utc::now(),
        });
        data
    }

    #[test]
    fn seed_backup_roundtrip() {
        let phrase = generate_mnemonic().unwrap();
        let data = sample_data("s3cret");
        let backup = EncryptedBackup::encrypt_with_seed(&data, &phrase).unwrap();
        assert_eq!(backup.secret, BackupSecretKind::Seed);
        let restored = backup.decrypt_with_seed(&phrase).unwrap();
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].password, "s3cret");
    }

    #[test]
    fn passphrase_backup_roundtrip() {
        let data = sample_data("s3cret");
        let backup = EncryptedBackup::encrypt_with_passphrase(&data, "backup-pass").unwrap();
        assert_eq!(backup.secret, BackupSecretKind::Passphrase);
        let restored = backup.decrypt_with_passphrase("backup-pass").unwrap();
        assert_eq!(restored.entries[0].password, "s3cret");
    }

    #[test]
    fn wrong_seed_fails() {
        let phrase = generate_mnemonic().unwrap();
        let other = generate_mnemonic().unwrap();
        let backup = EncryptedBackup::encrypt_with_seed(&sample_data("x"), &phrase).unwrap();
        assert!(backup.decrypt_with_seed(&other).is_err());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let backup =
            EncryptedBackup::encrypt_with_passphrase(&sample_data("x"), "correct!!").unwrap();
        assert!(backup.decrypt_with_passphrase("wrong!!!!").is_err());
    }

    #[test]
    fn secret_kind_mismatch_is_rejected() {
        let phrase = generate_mnemonic().unwrap();
        let seed_backup = EncryptedBackup::encrypt_with_seed(&sample_data("x"), &phrase).unwrap();
        assert!(seed_backup.decrypt_with_passphrase("passphrase").is_err());

        let pass_backup =
            EncryptedBackup::encrypt_with_passphrase(&sample_data("x"), "passphrase").unwrap();
        assert!(pass_backup.decrypt_with_seed(&phrase).is_err());
    }

    #[test]
    fn rejects_short_passphrase() {
        assert!(matches!(
            EncryptedBackup::encrypt_with_passphrase(&sample_data("x"), "short"),
            Err(BackupError::PassphraseTooShort)
        ));
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.backup.json");
        let phrase = generate_mnemonic().unwrap();
        let backup = EncryptedBackup::encrypt_with_seed(&sample_data("pw"), &phrase).unwrap();
        backup.save(&path).unwrap();
        let loaded = EncryptedBackup::load(&path).unwrap();
        let data = loaded.decrypt_with_seed(&phrase).unwrap();
        assert_eq!(data.entries[0].password, "pw");
    }

    #[test]
    fn merge_entries_replaces_by_id() {
        let mut target = sample_data("old");
        target.entries.push(Entry {
            id: Uuid::from_u128(2),
            name: "Keep".into(),
            username: String::new(),
            password: "keep".into(),
            url: String::new(),
            notes: String::new(),
            tags: vec![],
            updated_at: Utc::now(),
        });
        let mut imported = VaultData::new();
        imported.entries.push(Entry {
            id: Uuid::from_u128(1),
            name: "Example".into(),
            username: "user".into(),
            password: "new".into(),
            url: String::new(),
            notes: String::new(),
            tags: vec![],
            updated_at: Utc::now(),
        });
        imported.entries.push(Entry {
            id: Uuid::from_u128(3),
            name: "Added".into(),
            username: String::new(),
            password: "added".into(),
            url: String::new(),
            notes: String::new(),
            tags: vec![],
            updated_at: Utc::now(),
        });
        merge_entries(&mut target, imported);
        assert_eq!(target.entries.len(), 3);
        assert_eq!(target.entries[0].password, "new");
        assert_eq!(target.entries[1].password, "keep");
        assert_eq!(target.entries[2].name, "Added");
    }
}
