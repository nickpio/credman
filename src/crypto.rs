use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// Argon2id params tuned for ~0.5–1s interactive unlock on a typical laptop.
/// New vaults/backups are written with these; unlock always uses params from the file.
pub const ARGON2_M_KIB: u32 = 64 * 1024;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

/// Sanity bounds for Argon2 params read from vault/backup headers (DoS / malformed files).
pub const ARGON2_M_KIB_MIN: u32 = 8;
pub const ARGON2_M_KIB_MAX: u32 = 1024 * 1024; // 1 GiB
pub const ARGON2_T_COST_MIN: u32 = 1;
pub const ARGON2_T_COST_MAX: u32 = 100;
pub const ARGON2_P_COST_MIN: u32 = 1;
pub const ARGON2_P_COST_MAX: u32 = 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("key derivation failed")]
    Kdf,
    #[error("unsupported Argon2 parameters")]
    UnsupportedParams,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong seed phrase or corrupted vault)")]
    Decrypt,
    #[error("invalid nonce length")]
    BadNonce,
}

/// Argon2id parameters used for key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Parameters written by the current build when creating a vault or backup.
    pub const fn current() -> Self {
        Self {
            m_kib: ARGON2_M_KIB,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }

    /// Validate params from an on-disk header before deriving.
    pub fn validated(m_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self, CryptoError> {
        if !(ARGON2_M_KIB_MIN..=ARGON2_M_KIB_MAX).contains(&m_kib)
            || !(ARGON2_T_COST_MIN..=ARGON2_T_COST_MAX).contains(&t_cost)
            || !(ARGON2_P_COST_MIN..=ARGON2_P_COST_MAX).contains(&p_cost)
            || m_kib < p_cost.saturating_mul(8)
        {
            return Err(CryptoError::UnsupportedParams);
        }
        // Ensure the argon2 crate accepts them as well.
        let _ = Params::new(m_kib, t_cost, p_cost, Some(KEY_LEN))
            .map_err(|_| CryptoError::UnsupportedParams)?;
        Ok(Self {
            m_kib,
            t_cost,
            p_cost,
        })
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey {
    key: [u8; KEY_LEN],
}

impl VaultKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

/// Generate a BIP39 12-word English mnemonic (128-bit entropy).
pub fn generate_mnemonic() -> Result<String, CryptoError> {
    let mut entropy = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;
    entropy.zeroize();
    Ok(mnemonic.to_string())
}

pub fn validate_mnemonic(phrase: &str) -> Result<(), CryptoError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;
    if mnemonic.word_count() != 12 {
        return Err(CryptoError::InvalidMnemonic(
            "seed phrase must be exactly 12 BIP39 words".into(),
        ));
    }
    Ok(())
}

pub fn normalize_mnemonic(phrase: &str) -> String {
    phrase.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Short non-secret check value for an offline seed backup.
///
/// First 4 hex characters of SHA-256 over the normalized BIP39 phrase.
/// Never stored by credman — purely advisory for the user.
pub fn seed_fingerprint(phrase: &str) -> Result<String, CryptoError> {
    validate_mnemonic(phrase)?;
    let normalized = Zeroizing::new(normalize_mnemonic(phrase));
    let digest = Sha256::digest(normalized.as_bytes());
    Ok(format!("{:02x}{:02x}", digest[0], digest[1]))
}

pub fn derive_key(
    mnemonic: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<VaultKey, CryptoError> {
    validate_mnemonic(mnemonic)?;
    let normalized = Zeroizing::new(normalize_mnemonic(mnemonic));
    derive_key_from_secret(normalized.as_bytes(), salt, params)
}

/// Derive a vault key from an arbitrary secret (seed bytes or backup passphrase).
pub fn derive_key_from_secret(
    secret: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<VaultKey, CryptoError> {
    let argon_params = Params::new(params.m_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::UnsupportedParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(secret, salt, &mut key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(VaultKey { key })
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt(key: &VaultKey, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)
}

pub fn decrypt(key: &VaultKey, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadNonce);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_roundtrip_validate() {
        let phrase = generate_mnemonic().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
        validate_mnemonic(&phrase).unwrap();
    }

    #[test]
    fn rejects_non_twelve_word_phrase() {
        // Valid BIP39 24-word mnemonic must still be rejected by credman.
        let mut entropy = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        let long = Mnemonic::from_entropy_in(Language::English, &entropy)
            .unwrap()
            .to_string();
        assert_eq!(long.split_whitespace().count(), 24);
        let err = validate_mnemonic(&long).unwrap_err();
        assert!(err.to_string().contains("12"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let phrase = generate_mnemonic().unwrap();
        let salt = random_salt();
        let params = KdfParams::current();
        let key = derive_key(&phrase, &salt, &params).unwrap();
        let nonce = random_nonce();
        let pt = b"hello vault";
        let ct = encrypt(&key, &nonce, pt).unwrap();
        let out = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn wrong_seed_fails() {
        let phrase = generate_mnemonic().unwrap();
        let other = generate_mnemonic().unwrap();
        let salt = random_salt();
        let params = KdfParams::current();
        let key = derive_key(&phrase, &salt, &params).unwrap();
        let bad = derive_key(&other, &salt, &params).unwrap();
        let nonce = random_nonce();
        let ct = encrypt(&key, &nonce, b"secret").unwrap();
        assert!(decrypt(&bad, &nonce, &ct).is_err());
    }

    #[test]
    fn derive_uses_explicit_params() {
        let phrase = generate_mnemonic().unwrap();
        let salt = random_salt();
        let a = KdfParams {
            m_kib: 16,
            t_cost: 1,
            p_cost: 1,
        };
        let b = KdfParams {
            m_kib: 32,
            t_cost: 1,
            p_cost: 1,
        };
        let ka = derive_key(&phrase, &salt, &a).unwrap();
        let kb = derive_key(&phrase, &salt, &b).unwrap();
        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn rejects_out_of_bounds_params() {
        assert!(matches!(
            KdfParams::validated(4, 1, 1),
            Err(CryptoError::UnsupportedParams)
        ));
        assert!(matches!(
            KdfParams::validated(ARGON2_M_KIB_MAX + 1, 1, 1),
            Err(CryptoError::UnsupportedParams)
        ));
        assert!(matches!(
            KdfParams::validated(64, ARGON2_T_COST_MAX + 1, 1),
            Err(CryptoError::UnsupportedParams)
        ));
        assert!(matches!(
            KdfParams::validated(64, 1, ARGON2_P_COST_MAX + 1),
            Err(CryptoError::UnsupportedParams)
        ));
        assert!(KdfParams::validated(ARGON2_M_KIB, ARGON2_T_COST, ARGON2_P_COST).is_ok());
    }

    #[test]
    fn seed_fingerprint_is_stable_and_short() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let a = seed_fingerprint(phrase).unwrap();
        let b = seed_fingerprint(&format!("  {phrase}  ")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 4);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn seed_fingerprint_differs_for_different_phrases() {
        let a = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let b = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_ne!(seed_fingerprint(a).unwrap(), seed_fingerprint(b).unwrap());
    }

    #[test]
    fn passphrase_secret_derives_distinct_key() {
        let salt = random_salt();
        let params = KdfParams::current();
        let a = derive_key_from_secret(b"passphrase-one", &salt, &params).unwrap();
        let b = derive_key_from_secret(b"passphrase-two", &salt, &params).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
