use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use rand::RngCore;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// Argon2id params tuned for ~0.5–1s interactive unlock on a typical laptop.
pub const ARGON2_M_KIB: u32 = 64 * 1024;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("key derivation failed")]
    Kdf,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong seed phrase or corrupted vault)")]
    Decrypt,
    #[error("invalid nonce length")]
    BadNonce,
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

pub fn derive_key(mnemonic: &str, salt: &[u8]) -> Result<VaultKey, CryptoError> {
    validate_mnemonic(mnemonic)?;
    let normalized = Zeroizing::new(normalize_mnemonic(mnemonic));
    let params = Params::new(ARGON2_M_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|_| CryptoError::Kdf)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(normalized.as_bytes(), salt, &mut key)
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
        let key = derive_key(&phrase, &salt).unwrap();
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
        let key = derive_key(&phrase, &salt).unwrap();
        let bad = derive_key(&other, &salt).unwrap();
        let nonce = random_nonce();
        let ct = encrypt(&key, &nonce, b"secret").unwrap();
        assert!(decrypt(&bad, &nonce, &ct).is_err());
    }
}
