//! Distinct authenticated v2 backup envelope. No plaintext backup/export or path writer.
use super::*;

pub(super) fn admin_scope(app: &Application, admin: &AuthenticatedContext) -> Result<(), Error> {
    if !admin.admin || app.tasks.values().any(|t| t.owner != admin.owner || t.workspace != admin.workspace)
        || app.records.values().any(|r| r.owner != admin.owner || r.workspace != admin.workspace)
    { Err(Error::Denied) } else { Ok(()) }
}

fn prepare_restored(app: &mut Application, admin: &AuthenticatedContext, now: Time) -> Result<(), Error> {
    admin_scope(app, admin)?;
    app.generation = app.generation.checked_add(1).ok_or(Error::Capacity)?;
    app.revoked_tasks.extend(app.tasks.keys().copied());
    for grant in app.grants.values_mut() { grant.revoked = true; }
    for record in app.records.values_mut() { record.restored = true; }
    for delivery in app.deliveries.values_mut().filter(|d| d.status.is_none()) {
        delivery.status = Some(DeliveryStatus::Unknown);
        if delivery.action != PrivateAction::Use {
            app.records.get_mut(&delivery.record).ok_or(Error::InvalidStorage)?.signup = SignupState::Unknown;
        }
    }
    // Copying preserves the existing clock freeze and high-water.
    app.last_time = Some(app.last_time.map_or(now, |previous| previous.max(now)));
    snapshot::validate(app)
}

const BACKUP_MAGIC: &[u8; 8] = b"CMABAK02";

/// Deliberately no Debug/Serialize. This is a trusted-human input, not an agent request field.
#[derive(Clone, Copy)]
pub(crate) enum BackupSecret<'a> { Seed(&'a str), Passphrase(&'a str) }
impl BackupSecret<'_> {
    fn kind(self) -> u32 { match self { Self::Seed(_) => 1, Self::Passphrase(_) => 2 } }
    fn derive(self, salt: &[u8; SALT_LEN], kdf: &KdfParams) -> Result<VaultKey, Error> {
        match self {
            Self::Seed(seed) => crypto::derive_key(seed, salt, kdf).map_err(|_| Error::InvalidStorage),
            Self::Passphrase(passphrase) => {
                if passphrase.chars().count() < 16 || passphrase.len() > 4096 || passphrase.trim().is_empty() { return Err(Error::InvalidStorage); }
                crypto::derive_key_from_secret(passphrase.as_bytes(), salt, kdf).map_err(|_| Error::InvalidStorage)
            }
        }
    }
}

fn encrypt_backup(app: &Application, secret: BackupSecret<'_>) -> Result<Vec<u8>, Error> {
    let snapshot = snapshot::encode(app)?;
    encrypt_snapshot(&snapshot, secret)
}

fn encrypt_snapshot(snapshot: &[u8], secret: BackupSecret<'_>) -> Result<Vec<u8>, Error> {
    if snapshot.len() > snapshot::MAX_PLAINTEXT { return Err(Error::Capacity); }
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let kdf = KdfParams::current();
    let key = secret.derive(&salt, &kdf)?;
    let mut bytes = BACKUP_MAGIC.to_vec();
    for word in [2, secret.kind(), kdf.m_kib, kdf.t_cost, kdf.p_cost] { bytes.extend_from_slice(&word.to_be_bytes()); }
    bytes.extend_from_slice(&salt);
    // Bind envelope version/kind/KDF/salt inside authenticated plaintext without changing shared crypto APIs.
    let mut plaintext = Zeroizing::new(bytes.clone());
    plaintext.extend_from_slice(snapshot);
    let ciphertext = crypto::encrypt(&key, &nonce, &plaintext).map_err(|_| Error::InvalidStorage)?;
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&ciphertext);
    if bytes.len() > MAX_IMAGE { return Err(Error::Capacity); }
    Ok(bytes)
}

fn decrypt_backup(bytes: &[u8], secret: BackupSecret<'_>) -> Result<Application, Error> {
    if bytes.len() > MAX_IMAGE { return Err(Error::InvalidStorage); }
    fn array<const N: usize>(reader: &mut Cursor<&[u8]>) -> Result<[u8; N], Error> {
        let mut bytes = [0; N];
        reader.read_exact(&mut bytes).map_err(|_| Error::InvalidStorage)?;
        Ok(bytes)
    }
    let mut reader = Cursor::new(bytes);
    if &array::<8>(&mut reader)? != BACKUP_MAGIC || u32::from_be_bytes(array(&mut reader)?) != 2
        || u32::from_be_bytes(array(&mut reader)?) != secret.kind() { return Err(Error::InvalidStorage); }
    let kdf = KdfParams::validated(u32::from_be_bytes(array(&mut reader)?), u32::from_be_bytes(array(&mut reader)?),
        u32::from_be_bytes(array(&mut reader)?)).map_err(|_| Error::InvalidStorage)?;
    // Backup input is untrusted; never accept costs above the reviewed new-backup defaults.
    let ceiling = KdfParams::current();
    if kdf.m_kib > ceiling.m_kib || kdf.t_cost > ceiling.t_cost || kdf.p_cost > ceiling.p_cost { return Err(Error::InvalidStorage); }
    let salt = array::<SALT_LEN>(&mut reader)?;
    let prefix_len = reader.position() as usize;
    let nonce = array::<NONCE_LEN>(&mut reader)?;
    let length = u64::from_be_bytes(array(&mut reader)?);
    let offset = reader.position() as usize;
    if length != (bytes.len() - offset) as u64 { return Err(Error::InvalidStorage); }
    let key = secret.derive(&salt, &kdf)?;
    let plaintext = Zeroizing::new(crypto::decrypt(&key, &nonce, &bytes[offset..]).map_err(|_| Error::InvalidStorage)?);
    if plaintext.len() < prefix_len || plaintext[..prefix_len] != bytes[..prefix_len] { return Err(Error::InvalidStorage); }
    snapshot::decode(&plaintext[prefix_len..])
}

impl DurableVault {
    pub(crate) fn export_backup(&self, admin: &AuthenticatedContext, secret: BackupSecret<'_>) -> Result<Vec<u8>, Error> {
        self.ready()?;
        admin_scope(&self.app, admin)?;
        if self.app.clock_frozen { return Err(Error::ClockRecoveryRequired); }
        encrypt_backup(&self.app, secret)
    }

    /// Explicit copy only. Destination seed is independent of either backup secret kind.
    pub(crate) fn restore_backup(path: &Path, destination_seed: &str, admin: &AuthenticatedContext,
        bytes: &[u8], secret: BackupSecret<'_>, now: Time) -> Result<Self, Error> {
        if !admin.admin { return Err(Error::Denied); }
        let mut app = decrypt_backup(bytes, secret)?;
        prepare_restored(&mut app, admin, now)?;
        Self::create_from_app(path, destination_seed, app)
    }
}

#[cfg(test)]
mod tests;
