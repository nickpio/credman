//! Linux local-filesystem storage. All filenames are anchored to a private no-follow directory FD.
//! An uncleared pending intent is an explicit recovery gate, never automatic replay permission.
use super::*;
use crate::crypto::{self, KdfParams, VaultKey, NONCE_LEN, SALT_LEN};
use fs2::FileExt;
use std::ffi::CString;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

const MAGIC: &[u8; 8] = b"CMAGENT2";
const INTENT_MAGIC: &[u8; 8] = b"CMPEND02";
const STATE: &str = "state.v2";
const PENDING: &str = "pending.v2";
const RECOVERY: &str = "recovery.v2";
const MAX_IMAGE: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FaultPoint { TempWrite, AfterIntent, AfterRename, DirectorySync, RecoveryBeforeRename, RecoveryAfterRename }

#[cfg(test)]
thread_local! {
    static INITIAL_PUBLICATION_FAULT: std::cell::Cell<Option<FaultPoint>> = const { std::cell::Cell::new(None) };
}

/// No Debug: this retains keys, current encrypted evidence and staged plaintext state.
pub(crate) struct DurableVault {
    app: Application,
    store: Store,
    frozen: bool,
}

struct Store {
    dir: File,
    _lock: File,
    key: VaultKey,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    current_image: Option<Vec<u8>>,
    blocked: bool,
    #[cfg(test)]
    fault: Option<FaultPoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Publication { NotPublished, Durable, Unknown }

fn cstring(bytes: &[u8]) -> Result<CString, Error> {
    CString::new(bytes).map_err(|_| Error::InvalidStorage)
}

fn directory(path: &Path) -> Result<File, Error> {
    if !path.is_absolute() { return Err(Error::InvalidStorage); }
    let root = cstring(b"/")?;
    // SAFETY: a valid NUL-terminated path is passed; ownership of a successful FD is transferred once.
    let fd = unsafe { libc::open(root.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
    if fd < 0 { return Err(Error::InvalidStorage); }
    // SAFETY: open returned an owned live descriptor.
    let mut dir = unsafe { File::from_raw_fd(fd) };
    for component in path.components() {
        match component {
            Component::RootDir => {},
            Component::Normal(name) => {
                let name = cstring(name.as_bytes())?;
                // SAFETY: dir is live, flags require a directory, and name is NUL terminated.
                let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
                if fd < 0 { return Err(Error::InvalidStorage); }
                // SAFETY: openat returned an owned live descriptor.
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => return Err(Error::InvalidStorage),
        }
    }
    let m = dir.metadata().map_err(|_| Error::InvalidStorage)?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if m.uid() != uid || m.mode() & 0o7777 != 0o700 { return Err(Error::InvalidStorage); }
    Ok(dir)
}

fn open_file(dir: &File, name: &str, flags: i32) -> std::io::Result<File> {
    let name = CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: directory FD and C string are live. Mode is supplied for O_CREAT; no symlinks are followed.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(),
        flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o600 as libc::mode_t) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    // SAFETY: openat returned a unique owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !m.is_file() || m.uid() != uid || m.nlink() != 1 || m.mode() & 0o7777 != 0o600 {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    Ok(file)
}

fn read_image(dir: &File, name: &str) -> Result<Option<Vec<u8>>, Error> {
    let file = match open_file(dir, name, libc::O_RDONLY) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::InvalidStorage),
    };
    let mut bytes = Vec::new();
    file.take((MAX_IMAGE + 1) as u64).read_to_end(&mut bytes).map_err(|_| Error::InvalidStorage)?;
    if bytes.len() > MAX_IMAGE { return Err(Error::InvalidStorage); }
    Ok(Some(bytes))
}

fn pending_exists(dir: &File) -> Result<bool, Error> {
    Ok(gate_exists(dir, PENDING)? || gate_exists(dir, RECOVERY)?)
}

fn gate_exists(dir: &File, name: &str) -> Result<bool, Error> {
    let name = cstring(name.as_bytes())?;
    // Opening is deliberately not required: malformed/unreadable/symlinked intent must still gate restart.
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid output allocation, directory and C string; fstatat initializes stat on success.
    let rc = unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 { return Ok(true); }
    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound { Ok(false) }
    else { Err(Error::RecoveryRequired) }
}

fn unlink(dir: &File, name: &str) -> std::io::Result<()> {
    let name = CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: live directory FD and NUL-terminated relative name, no output pointers.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        Err(std::io::Error::last_os_error())
    } else { Ok(()) }
}

fn rename(dir: &File, from: &str, to: &str, create_only: bool) -> std::io::Result<()> {
    let from = CString::new(from).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let to = CString::new(to).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: both relative names and their common directory FD are valid for the syscall.
    let rc = unsafe { libc::renameat2(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr(),
        if create_only { libc::RENAME_NOREPLACE } else { 0 }) };
    if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

fn seal(app: &Application, key: &VaultKey, salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<Vec<u8>, Error> {
    let plaintext = snapshot::encode(app)?;
    seal_plaintext(&plaintext, key, salt, kdf)
}

fn seal_plaintext(plaintext: &[u8], key: &VaultKey, salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<Vec<u8>, Error> {
    if plaintext.len() > snapshot::MAX_PLAINTEXT { return Err(Error::Capacity); }
    let nonce = crypto::random_nonce();
    let ciphertext = crypto::encrypt(key, &nonce, plaintext).map_err(|_| Error::InvalidStorage)?;
    let mut image = Vec::new();
    image.extend_from_slice(MAGIC);
    for word in [2, kdf.m_kib, kdf.t_cost, kdf.p_cost] { image.extend_from_slice(&word.to_be_bytes()); }
    image.extend_from_slice(salt);
    image.extend_from_slice(&nonce);
    image.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    image.extend_from_slice(&ciphertext);
    Ok(image)
}

fn unseal(image: &[u8], mnemonic: &str) -> Result<(Application, VaultKey, [u8; SALT_LEN], KdfParams), Error> {
    if image.len() > MAX_IMAGE { return Err(Error::InvalidStorage); }
    let mut reader = Cursor::new(image);
    fn array<const N: usize>(reader: &mut Cursor<&[u8]>) -> Result<[u8; N], Error> {
        let mut bytes = [0; N];
        reader.read_exact(&mut bytes).map_err(|_| Error::InvalidStorage)?;
        Ok(bytes)
    }
    if &array::<8>(&mut reader)? != MAGIC || u32::from_be_bytes(array(&mut reader)?) != 2 { return Err(Error::InvalidStorage); }
    let kdf = KdfParams::validated(u32::from_be_bytes(array(&mut reader)?),
        u32::from_be_bytes(array(&mut reader)?), u32::from_be_bytes(array(&mut reader)?)).map_err(|_| Error::InvalidStorage)?;
    let salt = array::<SALT_LEN>(&mut reader)?;
    let nonce = array::<NONCE_LEN>(&mut reader)?;
    let length = u64::from_be_bytes(array(&mut reader)?);
    let offset = usize::try_from(reader.position()).map_err(|_| Error::InvalidStorage)?;
    if length != (image.len() - offset) as u64 { return Err(Error::InvalidStorage); }
    let key = crypto::derive_key(mnemonic, &salt, &kdf).map_err(|_| Error::InvalidStorage)?;
    let plaintext = Zeroizing::new(crypto::decrypt(&key, &nonce, &image[offset..]).map_err(|_| Error::InvalidStorage)?);
    let app = snapshot::decode(&plaintext)?;
    Ok((app, key, salt, kdf))
}

impl Store {
    fn acquire(path: &Path) -> Result<(File, File), Error> {
        let (dir, lock) = Self::acquire_recovery(path)?;
        if pending_exists(&dir)? { return Err(Error::RecoveryRequired); }
        Ok((dir, lock))
    }

    fn acquire_recovery(path: &Path) -> Result<(File, File), Error> {
        let dir = directory(path)?;
        let lock = open_file(&dir, "owner.lock", libc::O_RDWR | libc::O_CREAT).map_err(|_| Error::InvalidStorage)?;
        lock.try_lock_exclusive().map_err(|e| if e.kind() == std::io::ErrorKind::WouldBlock { Error::InUse } else { Error::InvalidStorage })?;
        Ok((dir, lock))
    }

    fn fault(&mut self, point: FaultPoint) -> bool {
        #[cfg(test)]
        if self.fault == Some(point) { self.fault = None; return true; }
        let _ = point;
        false
    }

    fn publish(&mut self, app: &Application) -> Publication {
        if self.blocked || pending_exists(&self.dir) != Ok(false) {
            self.blocked = true;
            return Publication::Unknown;
        }
        let image = match seal(app, &self.key, &self.salt, self.kdf) {
            Ok(bytes) => bytes, Err(_) => return Publication::NotPublished,
        };
        let temp = format!("candidate-{}.v2", Uuid::new_v4());
        // Test-only read-only opening causes a real EBADF write failure, before intent/publication.
        let access = if self.fault(FaultPoint::TempWrite) { libc::O_RDONLY } else { libc::O_WRONLY };
        let written = (|| {
            let mut file = open_file(&self.dir, &temp, access | libc::O_CREAT | libc::O_EXCL)?;
            file.write_all(&image)?;
            file.sync_all()
        })();
        if written.is_err() {
            let _ = unlink(&self.dir, &temp);
            return Publication::NotPublished;
        }
        // Both reconciliation images are encrypted. No plaintext sidecar, request body or key is written.
        let intent_written = (|| {
            let mut intent = open_file(&self.dir, PENDING, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
            intent.write_all(INTENT_MAGIC)?;
            let previous = self.current_image.as_deref().unwrap_or(&[]);
            intent.write_all(&(previous.len() as u64).to_be_bytes())?;
            intent.write_all(&(image.len() as u64).to_be_bytes())?;
            intent.write_all(previous)?;
            intent.write_all(&image)?;
            intent.sync_all()?;
            self.dir.sync_all()
        })();
        if intent_written.is_err() {
            self.blocked = true;
            return Publication::Unknown;
        }
        if self.fault(FaultPoint::AfterIntent) {
            self.blocked = true;
            return Publication::Unknown;
        }
        if rename(&self.dir, &temp, STATE, self.current_image.is_none()).is_err()
            || self.fault(FaultPoint::AfterRename) || self.fault(FaultPoint::DirectorySync)
            || self.dir.sync_all().is_err()
        {
            // A rename error, including EIO, is not assumed to leave the old path unchanged.
            self.blocked = true;
            return Publication::Unknown;
        }
        self.current_image = Some(image);
        // Main image is already confirmed durable. Cleanup failure cannot undo that fact.
        // Freeze this owner for maintenance; a retained intent also gates restart.
        if unlink(&self.dir, PENDING).is_err() || self.dir.sync_all().is_err() { self.blocked = true; }
        Publication::Durable
    }
}

impl DurableVault {
    /// Uses an existing dedicated directory owned by the user with mode 0700.
    pub(crate) fn create(path: &Path, mnemonic: &str) -> Result<Self, Error> {
        Self::create_from_app(path, mnemonic, Application { generation: 1, ..Application::default() })
    }

    fn create_from_app(path: &Path, mnemonic: &str, app: Application) -> Result<Self, Error> {
        // Validate and size-check the complete copy before acquiring/touching a destination.
        snapshot::encode(&app)?;
        let (dir, lock) = Store::acquire(path)?;
        if read_image(&dir, STATE)?.is_some() { return Err(Error::Conflict); }
        let salt = crypto::random_salt();
        let kdf = KdfParams::current();
        let key = crypto::derive_key(mnemonic, &salt, &kdf).map_err(|_| Error::InvalidStorage)?;
        let mut owner = Self { app, frozen: false,
            store: Store { dir, _lock: lock, key, salt, kdf, current_image: None, blocked: false,
                #[cfg(test)] fault: INITIAL_PUBLICATION_FAULT.with(|fault| fault.take()) } };
        match owner.store.publish(&owner.app) {
            Publication::Durable => { owner.frozen = owner.store.blocked; Ok(owner) },
            Publication::NotPublished => Err(Error::NotPublished),
            Publication::Unknown => Err(Error::RecoveryRequired),
        }
    }

    pub(crate) fn open(path: &Path, mnemonic: &str) -> Result<Self, Error> {
        let (dir, lock) = Store::acquire(path)?;
        let image = read_image(&dir, STATE)?.ok_or(Error::InvalidStorage)?;
        let (app, key, salt, kdf) = unseal(&image, mnemonic)?;
        if app.deliveries.values().any(|attempt| attempt.status.is_none()) { return Err(Error::RecoveryRequired); }
        Ok(Self { frozen: false, app, store: Store { dir, _lock: lock, key, salt, kdf,
            current_image: Some(image), blocked: false, #[cfg(test)] fault: None } })
    }

    fn ready(&self) -> Result<(), Error> {
        if self.frozen || self.store.blocked { Err(Error::RecoveryRequired) } else { Ok(()) }
    }

    fn commit(&mut self, mut candidate: Application) -> Result<(), Error> {
        self.ready()?;
        candidate.generation = self.app.generation.checked_add(1).ok_or(Error::Capacity)?;
        // Invalid staging must fail before any file operation; never publish an unchecked image.
        snapshot::validate(&candidate)?;
        match self.store.publish(&candidate) {
            Publication::NotPublished => Err(Error::NotPublished),
            Publication::Unknown => { self.frozen = true; Err(Error::RecoveryRequired) },
            Publication::Durable => { self.app = candidate; self.frozen = self.store.blocked; Ok(()) },
        }
    }

    fn apply<R>(&mut self, operation: impl FnOnce(&mut Application) -> Result<R, Error>) -> Result<R, Error> {
        self.ready()?;
        let mut candidate = self.app.clone();
        let result = operation(&mut candidate);
        // Persist trusted clock high-water/freeze even when authorization fails.
        self.commit(candidate)?;
        result
    }

    pub(crate) fn approve_task(&mut self, ctx: &AuthenticatedContext, task: TaskApproval, now: Time) -> Result<(), Error> {
        self.apply(|app| app.approve_task(ctx, task, now))
    }
    pub(crate) fn revoke_task(&mut self, ctx: &AuthenticatedContext, task: Uuid, now: Time) -> Result<(), Error> {
        self.apply(|app| app.revoke_task(ctx, task, now))
    }
    pub(crate) fn mutate(&mut self, ctx: &AuthenticatedContext, task: Uuid, request: Uuid, op: Mutation, now: Time) -> Result<Receipt, Error> {
        self.apply(|app| app.mutate(ctx, task, request, op, now))
    }
    pub(crate) fn metadata(&mut self, ctx: &AuthenticatedContext, task: Uuid, record: Uuid, fields: Fields, now: Time) -> Result<MetadataView, Error> {
        self.apply(|app| app.metadata(ctx, task, record, fields, now))
    }
    #[cfg(test)]
    pub(crate) fn read_secret(&mut self, ctx: &AuthenticatedContext, task: Uuid, record: Uuid, fields: Fields, now: Time) -> Result<Disclosure, Error> {
        self.apply(|app| app.read_secret(ctx, task, record, fields, now))
    }

    /// Trusted consumer configuration preflight only. Final SecretUse authorization remains in use_secret.
    pub(crate) fn validate_consumer(&self, ctx: &AuthenticatedContext, task: Uuid, service: &str, origin: &str, now: i64) -> Result<(), Error> {
        self.ready()?;
        let now = self.app.effective_time(now)?;
        let approved = self.app.task(ctx, task, now)?;
        if approved.service != service || approved.origin != origin { return Err(Error::Denied); }
        Ok(())
    }

    /// Private human import only. The approved task, never caller-supplied identity, owns the record.
    pub(crate) fn import_for_task(&mut self, admin: &AuthenticatedContext, task: Uuid, request: Uuid,
        kind: CredentialKind, values: SecretInput, now: i64) -> Result<Receipt, Error> {
        self.apply(|app| {
            let now = app.clock(now)?;
            let ctx = app.trusted_task_context(admin, task, now)?;
            app.mutate(&ctx, task, request, Mutation::Create { kind, values }, now)
        })
    }

    /// Private human export/test oracle only. Administration does not bypass task policy or grants.
    pub(crate) fn read_for_task(&mut self, admin: &AuthenticatedContext, task: Uuid, record: Uuid,
        fields: Fields, now: i64) -> Result<Disclosure, Error> {
        self.apply(|app| {
            let now = app.clock(now)?;
            let ctx = app.trusted_task_context(admin, task, now)?;
            app.read_secret(&ctx, task, record, fields, now)
        })
    }
    pub(crate) fn audit_events(&self, ctx: &AuthenticatedContext) -> Result<Vec<AuditEvent>, Error> {
        self.ready()?;
        self.app.audit_events(ctx)
    }

    pub(in crate::agent) fn admin_app(&self) -> &Application { &self.app }
    pub(in crate::agent) fn admin_frozen(&self) -> bool { self.frozen || self.store.blocked }
}

mod workflow;
mod recovery;
mod backup;
pub(crate) use backup::BackupSecret;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod workflow_tests;
#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod reviewed_repairs_tests;

#[cfg(test)]
mod final_review_tests;

#[cfg(test)]
mod private_generation_tests;

#[cfg(test)]
mod session_expiry_tests;
