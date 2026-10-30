//! Private, bounded admission. A session UUID identifies a revocable attachment, not authority.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::agent::{AuthenticatedContext, Error};
use crate::agent_ipc::{strict_json, FramedChannel};

const CAPACITY: usize = 32;
const MAX_TASKS: usize = 64;

pub(crate) struct Sessions {
    entries: BTreeMap<Uuid, Session>,
    owner: String,
    workspace: String,
    admin: String,
    socket: Option<PathBuf>,
    deadline: i64,
}
struct Session {
    digest: Option<[u8; 32]>,
    principal: String,
    tasks: BTreeSet<Uuid>,
    expires_at: i64,
}
impl Sessions {
    pub(crate) fn new(owner: String, workspace: String, admin: String, socket: Option<PathBuf>, deadline: i64) -> Self {
        Self { entries: BTreeMap::new(), owner, workspace, admin, socket, deadline }
    }
    pub(crate) fn issue(&mut self, principal: String, tasks: Vec<Uuid>, expires_at: i64, now: i64) -> Result<Value, Error> {
        self.entries.retain(|_, s| s.expires_at > now);
        let allowed: BTreeSet<_> = tasks.iter().copied().collect();
        if principal.trim().is_empty() || principal.len() > 2048 || principal == self.admin
            || tasks.is_empty() || tasks.len() > MAX_TASKS || allowed.len() != tasks.len()
            || allowed.contains(&Uuid::nil()) || expires_at <= now || expires_at > self.deadline {
            return Err(Error::Invalid);
        }
        let socket = self.socket.as_ref().ok_or(Error::InteractionRequired)?;
        if self.entries.len() >= CAPACITY { return Err(Error::Capacity); }
        let mut random = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(random.as_mut()).map_err(|_| Error::InteractionRequired)?;
        let token = Zeroizing::new(random.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let digest = Sha256::digest(token.as_bytes()).into();
        let id = Uuid::new_v4();
        self.entries.insert(id, Session { digest: Some(digest), principal, tasks: allowed, expires_at });
        Ok(json!({"ok":true,"session":{"id":id,"socket":socket,"token":token.as_str(),"expires_at":expires_at}}))
    }
    pub(crate) fn revoke(&mut self, id: Uuid) { self.entries.remove(&id); }
    pub(crate) fn live(&self, id: Uuid, now: i64) -> bool {
        self.entries.get(&id).is_some_and(|s| s.expires_at > now && s.digest.is_none())
    }
    pub(crate) fn permits(&self, id: Uuid, task: Uuid, now: i64) -> bool {
        self.live(id, now) && self.entries.get(&id).is_some_and(|s| s.tasks.contains(&task))
    }
    fn attach(&mut self, token: &str, now: i64) -> Result<(Uuid, AuthenticatedContext), Error> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            return Err(Error::Denied);
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let (id, session) = self.entries.iter_mut().find(|(_, s)| s.expires_at > now && s.digest.is_some_and(|expected| {
            expected.iter().zip(digest).fold(0u8, |difference, (a, b)| difference | (a ^ b)) == 0
        }))
            .ok_or(Error::Denied)?;
        session.digest = None;
        Ok((*id, AuthenticatedContext::from_authenticated_session(
            self.owner.clone(), session.principal.clone(), self.workspace.clone(), session.expires_at)))
    }
    pub(crate) fn admit(&mut self, stream: UnixStream, now: i64) -> Result<(Uuid, AuthenticatedContext, FramedChannel), Error> {
        check_uid(&stream)?;
        let mut channel = FramedChannel::new(stream, Duration::from_secs(1), Duration::from_secs(1))
            .map_err(|_| Error::Denied)?;
        let result = channel.receive().map_err(|_| Error::Denied).and_then(|value| {
            let attach: Attach = serde_json::from_value(value).map_err(|_| Error::Denied)?;
            if attach.op != "attach" { return Err(Error::Denied); }
            self.attach(&attach.token, now.max(chrono::Utc::now().timestamp()))
        });
        match result {
            Ok((id, context)) => {
                if channel.send(&json!({"ok":true})).is_err() { self.revoke(id); return Err(Error::Denied); }
                Ok((id, context, channel))
            }
            Err(error) => { let _ = channel.send(&json!({"ok":false,"error":"access denied"})); Err(error) }
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attach { op: String, #[serde(deserialize_with = "secret")] token: Zeroizing<String> }
fn secret<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(decoder).map(Zeroizing::new)
}

pub(crate) fn check_uid(stream: &UnixStream) -> Result<(), Error> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and size are valid output allocations for SO_PEERCRED.
    if unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
        cred.as_mut_ptr().cast(), &mut size) } < 0 { return Err(Error::Denied); }
    // SAFETY: successful SO_PEERCRED initialized cred; geteuid has no preconditions.
    if size as usize != std::mem::size_of::<libc::ucred>() || unsafe { cred.assume_init().uid != libc::geteuid() } {
        return Err(Error::Denied);
    }
    Ok(())
}

// Walk every directory through nofollow descriptors. Only the immediate parent must be private.
fn parent(path: &Path) -> Result<(File, CString), Error> {
    if !path.is_absolute() || path.to_str().is_none() { return Err(Error::Invalid); }
    let parts: Vec<_> = path.components().collect();
    let name = match parts.last() { Some(Component::Normal(name)) => CString::new(name.as_encoded_bytes()).map_err(|_| Error::Invalid)?, _ => return Err(Error::Invalid) };
    let mut directory = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/").map_err(|_| Error::Invalid)?;
    for part in &parts[1..parts.len()-1] {
        let Component::Normal(part) = part else { return Err(Error::Invalid); };
        let part = CString::new(part.as_encoded_bytes()).map_err(|_| Error::Invalid)?;
        // SAFETY: the directory and NUL-terminated component remain live; openat returns a new descriptor.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), part.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 { return Err(Error::Invalid); }
        // SAFETY: fd is a fresh owned descriptor from openat.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let metadata = directory.metadata().map_err(|_| Error::Invalid)?;
    // SAFETY: geteuid has no preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700 { return Err(Error::Invalid); }
    Ok((directory, name))
}
fn anchored(directory: &File, name: &CString) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{}", directory.as_raw_fd(), name.to_string_lossy()))
}
fn stat_at(directory: &File, name: &CString) -> Result<libc::stat, Error> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat is a valid output and the directory/name remain live.
    if unsafe { libc::fstatat(directory.as_raw_fd(), name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } < 0 { return Err(Error::Invalid); }
    // SAFETY: successful fstatat initialized stat.
    Ok(unsafe { stat.assume_init() })
}
pub(crate) struct Listener {
    pub(crate) socket: UnixListener,
    directory: File,
    name: CString,
    identity: (u64, u64),
}
impl Listener {
    pub(crate) fn bind(path: &Path) -> Result<Self, Error> {
        let (directory, name) = parent(path)?;
        // bind is exclusive and never removes an existing path, including dangling symlinks.
        // SAFETY: umask changes this single-threaded process only and has no pointer arguments.
        let mask = unsafe { libc::umask(0o177) };
        let bound = UnixListener::bind(anchored(&directory, &name));
        unsafe { libc::umask(mask); }
        let socket = bound.map_err(|_| Error::Invalid)?;
        let stat = stat_at(&directory, &name)?;
        let listener = Self { socket, directory, name, identity: (stat.st_dev, stat.st_ino) };
        if stat.st_mode & 0o7777 != 0o600 { return Err(Error::Invalid); }
        // SAFETY: listen changes the backlog of this owned socket, without pointer arguments.
        if unsafe { libc::listen(listener.socket.as_raw_fd(), CAPACITY as i32) } < 0 { return Err(Error::Invalid); }
        listener.socket.set_nonblocking(true).map_err(|_| Error::Invalid)?;
        crate::agent_broker::open_fd(listener.socket.as_raw_fd())?;
        Ok(listener)
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if let Ok(stat) = stat_at(&self.directory, &self.name) {
            if (stat.st_dev, stat.st_ino) == self.identity && stat.st_mode & libc::S_IFMT == libc::S_IFSOCK {
                // SAFETY: unlinkat is scoped to our retained parent and verified socket inode. No directories are removed.
                unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0); }
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionFile { id: Uuid, socket: PathBuf, #[serde(deserialize_with = "secret")] token: Zeroizing<String>, expires_at: i64 }
pub(crate) fn connect(path: &Path, now: i64) -> Result<FramedChannel, Error> {
    let (directory, name) = parent(path)?;
    // O_NONBLOCK prevents a malicious FIFO from blocking before the regular-file check.
    // SAFETY: directory/name remain live; openat returns a fresh descriptor.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if fd < 0 { return Err(Error::Invalid); }
    // SAFETY: fd is a fresh owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let stat = file.metadata().map_err(|_| Error::Invalid)?;
    if !stat.is_file() || stat.mode() & 0o7777 != 0o600 || stat.nlink() != 1
        || stat.uid() != unsafe { libc::geteuid() } || stat.len() > 4096 { return Err(Error::Invalid); }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(4097).read_to_end(&mut bytes).map_err(|_| Error::Invalid)?;
    if bytes.len() > 4096 { return Err(Error::Invalid); }
    let session: SessionFile = serde_json::from_value(strict_json(&bytes).map_err(|_| Error::Invalid)?)
        .map_err(|_| Error::Invalid)?;
    if session.id.is_nil() || session.expires_at <= now { return Err(Error::Denied); }
    let (directory, name) = parent(&session.socket)?;
    let stat = stat_at(&directory, &name)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_mode & 0o7777 != 0o600
        || stat.st_uid != unsafe { libc::geteuid() } { return Err(Error::Denied); }
    let stream = connect_bounded(&anchored(&directory, &name))?;
    check_uid(&stream)?;
    let mut channel = FramedChannel::new(stream, Duration::from_secs(5), Duration::from_secs(5)).map_err(|_| Error::Denied)?;
    channel.send(&json!({"op":"attach","token":session.token.as_str()})).map_err(|_| Error::Denied)?;
    if channel.receive().map_err(|_| Error::Denied)? != json!({"ok":true}) { return Err(Error::Denied); }
    Ok(channel)
}
fn connect_bounded(path: &Path) -> Result<UnixStream, Error> {
    let bytes = path.as_os_str().as_encoded_bytes();
    // SAFETY: zero is a valid sockaddr_un representation before filling the family and path.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() { return Err(Error::Invalid); }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) { *target = *source as libc::c_char; }
    // SAFETY: socket has no pointer parameters and returns a fresh descriptor.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 { return Err(Error::Denied); }
    // SAFETY: fd is a fresh AF_UNIX stream descriptor.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    // SAFETY: address is a valid initialized sockaddr_un of the supplied size.
    let result = unsafe { libc::connect(fd, (&address as *const libc::sockaddr_un).cast(), std::mem::size_of_val(&address) as libc::socklen_t) };
    if result < 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) { return Err(Error::Denied); }
        let mut poll = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        // SAFETY: poll is an initialized single-element allocation.
        if unsafe { libc::poll(&mut poll, 1, 1000) } <= 0 || stream.take_error().map_err(|_| Error::Denied)?.is_some() { return Err(Error::Denied); }
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sessions() -> Sessions {
        Sessions::new("owner".into(), "workspace".into(), "human".into(), Some("/private/bridge.sock".into()), 400)
    }
    #[test]
    fn session_token_is_single_use_and_scope_survives_attach() {
        let mut sessions = sessions();
        let task = Uuid::new_v4();
        let issued = sessions.issue("agent".into(), vec![task], 200, 100).unwrap();
        let token = issued["session"]["token"].as_str().unwrap();
        let id: Uuid = serde_json::from_value(issued["session"]["id"].clone()).unwrap();
        assert_eq!(token.len(), 64);
        assert!(!sessions.live(id, 100));
        assert!(sessions.attach(&id.to_string(), 100).is_err());
        assert!(sessions.attach(token, 100).is_ok());
        assert!(sessions.attach(token, 100).is_err());
        assert!(sessions.permits(id, task, 100));
        assert!(!sessions.permits(id, Uuid::new_v4(), 100));
        assert!(!sessions.permits(id, task, 200));
        sessions.revoke(id);
        assert!(!sessions.live(id, 100));
    }
    #[test]
    fn issuance_is_bounded_and_cannot_mint_admin_or_approve_tasks() {
        let mut sessions = sessions();
        let task = Uuid::new_v4();
        for (principal, tasks, expiry) in [
            ("human", vec![task], 200), ("", vec![task], 200), ("agent", vec![], 200),
            ("agent", vec![task, task], 200), ("agent", vec![Uuid::nil()], 200),
            ("agent", vec![task], 100), ("agent", vec![task], 401),
        ] { assert!(sessions.issue(principal.into(), tasks, expiry, 100).is_err()); }
        for _ in 0..CAPACITY { sessions.issue("agent".into(), vec![task], 200, 100).unwrap(); }
        assert!(matches!(sessions.issue("agent".into(), vec![task], 200, 100), Err(Error::Capacity)));
        assert!(sessions.issue("agent".into(), vec![task], 300, 200).is_ok());
    }
}
