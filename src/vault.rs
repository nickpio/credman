use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use fs2::FileExt;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{
    self, decrypt, derive_key, encrypt, random_nonce, random_salt, VaultKey, ARGON2_M_KIB,
    ARGON2_P_COST, ARGON2_T_COST, NONCE_LEN, SALT_LEN,
};
use crate::model::VaultData;
use crate::validation::{
    validate_plaintext_size, validate_vault, validate_vault_file_size, ValidationError,
};

const MAGIC: &[u8; 8] = b"CREDMAN\0";
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("vault not found at {0}")]
    NotFound(PathBuf),
    #[error("vault is in use by another credman process: {0}")]
    InUse(PathBuf),
    #[error("invalid vault file: {0}")]
    Invalid(String),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

/// On-disk header layout (little-endian):
/// magic[8] | version u32 | m_kib u32 | t_cost u32 | p_cost u32 | salt[16] | nonce[12] | ct_len u64 | ciphertext
pub struct VaultFile {
    pub path: PathBuf,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub ciphertext: Vec<u8>,
}

impl VaultFile {
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("CREDMAN_VAULT") {
            return PathBuf::from(p);
        }
        dirs_fallback_home().join(".credman").join("vault")
    }
}

fn dirs_fallback_home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

fn ensure_secure_parent(path: &Path) -> Result<(), VaultError> {
    let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) else {
        return Ok(());
    };
    #[cfg(unix)]
    let created = !parent.exists();
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    if created || is_default_vault_path(path) {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn is_default_vault_path(path: &Path) -> bool {
    dirs::home_dir().is_some_and(|home| path == home.join(".credman").join("vault"))
}

fn harden_file_permissions(_path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

struct VaultLock {
    file: File,
}

fn lock_path_for(vault_path: &Path) -> PathBuf {
    let mut path = vault_path.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

impl VaultLock {
    fn acquire(vault_path: &Path) -> Result<Self, VaultError> {
        ensure_secure_parent(vault_path)?;
        let lock_path = lock_path_for(vault_path);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&lock_path)?;
        harden_file_permissions(&lock_path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self { file }),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Err(VaultError::InUse(vault_path.to_path_buf()))
            }
            Err(error) => Err(VaultError::Io(error)),
        }
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn read_u32(buf: &[u8], off: &mut usize) -> Result<u32, VaultError> {
    if *off + 4 > buf.len() {
        return Err(VaultError::Invalid("truncated header".into()));
    }
    let v = u32::from_le_bytes(buf[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn read_u64(buf: &[u8], off: &mut usize) -> Result<u64, VaultError> {
    if *off + 8 > buf.len() {
        return Err(VaultError::Invalid("truncated header".into()));
    }
    let v = u64::from_le_bytes(buf[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

impl VaultFile {
    pub fn load(path: &Path) -> Result<Self, VaultError> {
        if !path.exists() {
            return Err(VaultError::NotFound(path.to_path_buf()));
        }
        ensure_secure_parent(path)?;
        harden_file_permissions(path)?;
        validate_vault_file_size(fs::metadata(path)?.len())?;
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        if buf.len() < 8 + 4 * 4 + SALT_LEN + NONCE_LEN + 8 {
            return Err(VaultError::Invalid("file too small".into()));
        }
        if &buf[0..8] != MAGIC {
            return Err(VaultError::Invalid("bad magic".into()));
        }
        let mut off = 8;
        let version = read_u32(&buf, &mut off)?;
        if version != FORMAT_VERSION {
            return Err(VaultError::Invalid(format!("unsupported version {version}")));
        }
        let m_kib = read_u32(&buf, &mut off)?;
        let t_cost = read_u32(&buf, &mut off)?;
        let p_cost = read_u32(&buf, &mut off)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[off..off + SALT_LEN]);
        off += SALT_LEN;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[off..off + NONCE_LEN]);
        off += NONCE_LEN;
        let ct_len_raw = read_u64(&buf, &mut off)?;
        validate_vault_file_size(ct_len_raw)?;
        let ct_len = ct_len_raw as usize;
        if off + ct_len != buf.len() {
            return Err(VaultError::Invalid("ciphertext length mismatch".into()));
        }
        let ciphertext = buf[off..].to_vec();
        Ok(Self {
            path: path.to_path_buf(),
            salt,
            nonce,
            m_kib,
            t_cost,
            p_cost,
            ciphertext,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.m_kib.to_le_bytes());
        out.extend_from_slice(&self.t_cost.to_le_bytes());
        out.extend_from_slice(&self.p_cost.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn save(&self) -> Result<(), VaultError> {
        ensure_secure_parent(&self.path)?;
        let data = self.serialize();
        let tmp = self.path.with_extension("tmp");
        {
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut f = options.open(&tmp)?;
            harden_file_permissions(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

pub struct UnlockedVault {
    pub path: PathBuf,
    pub key: VaultKey,
    pub salt: [u8; SALT_LEN],
    pub data: VaultData,
    _lock: VaultLock,
}

impl UnlockedVault {
    pub fn create(path: &Path, mnemonic: &str) -> Result<Self, VaultError> {
        let lock = VaultLock::acquire(path)?;
        Self::create_with_lock(path, mnemonic, lock)
    }

    pub fn replace(path: &Path, mnemonic: &str) -> Result<Self, VaultError> {
        let lock = VaultLock::acquire(path)?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Self::create_with_lock(path, mnemonic, lock)
    }

    fn create_with_lock(path: &Path, mnemonic: &str, lock: VaultLock) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.to_path_buf()));
        }
        ensure_secure_parent(path)?;
        let salt = random_salt();
        let key = derive_key(mnemonic, &salt)?;
        let data = VaultData::new();
        let mut vault = Self {
            path: path.to_path_buf(),
            key,
            salt,
            data,
            _lock: lock,
        };
        vault.persist()?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, mnemonic: &str) -> Result<Self, VaultError> {
        let lock = VaultLock::acquire(path)?;
        let file = VaultFile::load(path)?;
        // Header stores Argon2 params for future flexibility; v1 always uses compile-time defaults
        // matching what we write. Derive with stored salt.
        let _ = (file.m_kib, file.t_cost, file.p_cost);
        let key = derive_key(mnemonic, &file.salt)?;
        let plaintext = Zeroizing::new(decrypt(&key, &file.nonce, &file.ciphertext)?);
        validate_plaintext_size(plaintext.len())?;
        let data: VaultData = serde_json::from_slice(&plaintext)?;
        validate_vault(&data)?;
        Ok(Self {
            path: path.to_path_buf(),
            key,
            salt: file.salt,
            data,
            _lock: lock,
        })
    }

    pub fn persist(&mut self) -> Result<(), VaultError> {
        validate_vault(&self.data)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.data)?);
        validate_plaintext_size(plaintext.len())?;
        let nonce = random_nonce();
        let ciphertext = encrypt(&self.key, &nonce, &plaintext)?;
        let file = VaultFile {
            path: self.path.clone(),
            salt: self.salt,
            nonce,
            m_kib: ARGON2_M_KIB,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            ciphertext,
        };
        file.save()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_mnemonic;
    use crate::model::Entry;
    use chrono::Utc;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn create_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let phrase = generate_mnemonic().unwrap();
        {
            let mut v = UnlockedVault::create(&path, &phrase).unwrap();
            v.data.entries.push(Entry {
                id: Uuid::new_v4(),
                name: "Test".into(),
                username: "user".into(),
                password: "s3cret".into(),
                url: String::new(),
                notes: String::new(),
                tags: vec!["a".into()],
                updated_at: Utc::now(),
            });
            v.persist().unwrap();
        }
        let unlocked = UnlockedVault::unlock(&path, &phrase).unwrap();
        assert_eq!(unlocked.data.entries.len(), 1);
        assert_eq!(unlocked.data.entries[0].password, "s3cret");
    }

    #[test]
    fn wrong_phrase_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let phrase = generate_mnemonic().unwrap();
        let other = generate_mnemonic().unwrap();
        UnlockedVault::create(&path, &phrase).unwrap();
        assert!(UnlockedVault::unlock(&path, &other).is_err());
    }

    #[test]
    fn vault_lock_fails_fast_and_releases_on_drop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");

        let first = VaultLock::acquire(&path).unwrap();
        assert!(matches!(
            VaultLock::acquire(&path),
            Err(VaultError::InUse(locked_path)) if locked_path == path
        ));

        drop(first);
        VaultLock::acquire(&path).unwrap();
    }

    #[test]
    fn lock_path_appends_without_replacing_vault_extension() {
        assert_eq!(
            lock_path_for(Path::new("credentials.prod")),
            PathBuf::from("credentials.prod.lock")
        );
    }

    #[test]
    fn oversized_vault_file_is_rejected_before_reading() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let file = File::create(&path).unwrap();
        file.set_len(crate::validation::MAX_VAULT_FILE_BYTES + 1)
            .unwrap();

        assert!(matches!(
            VaultFile::load(&path),
            Err(VaultError::Validation(
                ValidationError::VaultFileTooLarge { .. }
            ))
        ));
    }

    #[test]
    fn persist_rejects_invalid_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let phrase = generate_mnemonic().unwrap();
        let mut vault = UnlockedVault::create(&path, &phrase).unwrap();
        vault.data.entries.push(Entry {
            id: Uuid::new_v4(),
            name: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            updated_at: Utc::now(),
        });

        assert!(matches!(
            vault.persist(),
            Err(VaultError::Validation(ValidationError::Required {
                field: "name"
            }))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vault_directory_and_file_use_private_permissions() {
        let dir = tempdir().unwrap();
        let vault_dir = dir.path().join(".credman");
        let path = vault_dir.join("vault");
        let phrase = generate_mnemonic().unwrap();

        UnlockedVault::create(&path, &phrase).unwrap();

        assert_eq!(
            fs::metadata(&vault_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(lock_path_for(&path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        VaultFile::load(&path).unwrap();

        assert_eq!(
            fs::metadata(&vault_dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn load_missing_returns_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing-vault");
        match VaultFile::load(&path) {
            Err(VaultError::NotFound(p)) => assert_eq!(p, path),
            Err(e) => panic!("expected NotFound, got {e}"),
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
    }

    #[test]
    fn unlock_missing_returns_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing-vault");
        let phrase = generate_mnemonic().unwrap();
        match UnlockedVault::unlock(&path, &phrase) {
            Err(VaultError::NotFound(p)) => assert_eq!(p, path),
            Err(e) => panic!("expected NotFound, got {e}"),
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
    }

    #[test]
    fn restore_create_when_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let phrase = generate_mnemonic().unwrap();
        assert!(!path.exists());
        UnlockedVault::create(&path, &phrase).unwrap();
        let unlocked = UnlockedVault::unlock(&path, &phrase).unwrap();
        assert!(unlocked.data.entries.is_empty());
    }

    #[test]
    fn restore_replace_overwrites_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault");
        let phrase = generate_mnemonic().unwrap();
        let other = generate_mnemonic().unwrap();
        {
            let mut v = UnlockedVault::create(&path, &phrase).unwrap();
            v.data.entries.push(Entry {
                id: Uuid::new_v4(),
                name: "old".into(),
                username: String::new(),
                password: "gone".into(),
                url: String::new(),
                notes: String::new(),
                tags: vec![],
                updated_at: Utc::now(),
            });
            v.persist().unwrap();
        }
        UnlockedVault::replace(&path, &other).unwrap();
        let unlocked = UnlockedVault::unlock(&path, &other).unwrap();
        assert!(unlocked.data.entries.is_empty());
        assert!(UnlockedVault::unlock(&path, &phrase).is_err());
    }
}
