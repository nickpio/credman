use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{
    self, decrypt, derive_key, encrypt, random_nonce, random_salt, VaultKey, ARGON2_M_KIB,
    ARGON2_P_COST, ARGON2_T_COST, NONCE_LEN, SALT_LEN,
};
use crate::model::VaultData;

const MAGIC: &[u8; 8] = b"CREDMAN\0";
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("vault not found at {0}")]
    NotFound(PathBuf),
    #[error("invalid vault file: {0}")]
    Invalid(String),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
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
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h);
    }
    PathBuf::from(".")
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
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .is_some_and(|home| path == home.join(".credman").join("vault"))
}

fn harden_file_permissions(_path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    Ok(())
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
        let ct_len = read_u64(&buf, &mut off)? as usize;
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
}

impl UnlockedVault {
    pub fn create(path: &Path, mnemonic: &str) -> Result<Self, VaultError> {
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
        };
        vault.persist()?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, mnemonic: &str) -> Result<Self, VaultError> {
        let file = VaultFile::load(path)?;
        // Header stores Argon2 params for future flexibility; v1 always uses compile-time defaults
        // matching what we write. Derive with stored salt.
        let _ = (file.m_kib, file.t_cost, file.p_cost);
        let key = derive_key(mnemonic, &file.salt)?;
        let plaintext = Zeroizing::new(decrypt(&key, &file.nonce, &file.ciphertext)?);
        let data: VaultData = serde_json::from_slice(&plaintext)?;
        Ok(Self {
            path: path.to_path_buf(),
            key,
            salt: file.salt,
            data,
        })
    }

    pub fn persist(&mut self) -> Result<(), VaultError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.data)?);
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
}
