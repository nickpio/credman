//! Offline trusted-human copy administration. No workload RPC or plaintext export.
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;

use chrono::Utc;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::agent::{AuthenticatedContext, BackupSecret, DurableVault, Error};
use crate::agent_broker::{harden, open_fd, read_fd};

pub(crate) struct Options {
    pub(crate) directory: PathBuf,
    pub(crate) seed_fd: RawFd,
    pub(crate) identity_fd: RawFd,
    pub(crate) operation: Operation,
}

pub(crate) enum Operation {
    Backup { secret_fd: RawFd, passphrase: bool, output_fd: RawFd },
    Restore { secret_fd: RawFd, passphrase: bool, backup_fd: RawFd },
    Recover,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity { owner: String, principal: String, workspace: String }

fn text(fd: RawFd) -> Result<Zeroizing<String>, Error> {
    let bytes = read_fd(fd, 4096)?;
    Ok(Zeroizing::new(std::str::from_utf8(&bytes).map_err(|_| Error::Invalid)?.to_owned()))
}

fn output(fd: RawFd, inputs: &[RawFd]) -> Result<File, Error> {
    open_fd(fd)?;
    // SAFETY: the caller transferred this already-validated, unique live descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata().map_err(|_| Error::Invalid)?;
    // SAFETY: geteuid has no preconditions, and F_GETFL has no pointer arguments.
    let uid = unsafe { libc::geteuid() };
    let access = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if access < 0 || access & libc::O_ACCMODE == libc::O_RDONLY || m.uid() != uid
        || m.mode() & 0o077 != 0 || m.nlink() > 1 { return Err(Error::Invalid); }
    if m.is_file() {
        // A caller opens a new private output. Never truncate or append to an existing payload.
        if m.len() != 0 || unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) } != 0 {
            return Err(Error::Invalid);
        }
    } else if !m.file_type().is_fifo() { return Err(Error::Invalid); }
    for input in inputs {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: metadata is a valid output allocation and the input is live.
        if unsafe { libc::fstat(*input, metadata.as_mut_ptr()) } < 0 { return Err(Error::Invalid); }
        // SAFETY: successful fstat initialized metadata.
        let other = unsafe { metadata.assume_init() };
        if m.dev() == other.st_dev && m.ino() == other.st_ino { return Err(Error::Invalid); }
    }
    Ok(file)
}

fn write_output(mut file: File, bytes: &[u8]) -> Result<(), Error> {
    file.write_all(bytes).map_err(|_| Error::InteractionRequired)?;
    if file.metadata().map_err(|_| Error::InteractionRequired)?.is_file() {
        file.sync_all().map_err(|_| Error::InteractionRequired)?;
    }
    Ok(())
}

/// Identity/configuration is supplied by a trusted human supervisor, not authenticated by JSON syntax.
pub(crate) fn run(options: Options) -> Result<(), Error> {
    harden()?;
    let mut inputs = vec![options.seed_fd, options.identity_fd];
    let output_fd = match &options.operation {
        Operation::Backup { secret_fd, output_fd, .. } => { inputs.push(*secret_fd); Some(*output_fd) }
        Operation::Restore { secret_fd, backup_fd, .. } => { inputs.extend([*secret_fd, *backup_fd]); None }
        Operation::Recover => None,
    };
    let mut unique = BTreeSet::new();
    for fd in inputs.iter().copied().chain(output_fd) {
        open_fd(fd)?;
        if !unique.insert(fd) { return Err(Error::Invalid); }
    }
    // Validate output before reading/closing inputs or changing any vault state.
    let destination = output_fd.map(|fd| output(fd, &inputs)).transpose()?;
    let identity_bytes = read_fd(options.identity_fd, 65536)?;
    let identity: Identity = serde_json::from_slice(&identity_bytes).map_err(|_| Error::Invalid)?;
    if [&identity.owner, &identity.principal, &identity.workspace].iter()
        .any(|s| s.trim().is_empty() || s.len() > 2048) { return Err(Error::Invalid); }
    let context = AuthenticatedContext::from_authenticated_admin(identity.owner, identity.principal, identity.workspace);
    let seed = text(options.seed_fd)?;
    match options.operation {
        Operation::Backup { secret_fd, passphrase, .. } => {
            let secret = text(secret_fd)?;
            let kind = if passphrase { BackupSecret::Passphrase(&secret) } else { BackupSecret::Seed(&secret) };
            let owner = DurableVault::open(&options.directory, &seed)?;
            let bytes = owner.export_backup(&context, kind)?;
            write_output(destination.ok_or(Error::Invalid)?, &bytes)
        }
        Operation::Restore { secret_fd, passphrase, backup_fd } => {
            let secret = text(secret_fd)?;
            let bytes = read_fd(backup_fd, 32 * 1024 * 1024)?;
            let kind = if passphrase { BackupSecret::Passphrase(&secret) } else { BackupSecret::Seed(&secret) };
            let _owner = DurableVault::restore_backup(&options.directory, &seed, &context, &bytes, kind, Utc::now().timestamp())?;
            Ok(())
        }
        Operation::Recover => {
            let mut clock = || Utc::now().timestamp();
            let _owner = DurableVault::recover(&options.directory, &seed, &context, &mut clock)?;
            Ok(())
        }
    }
}
