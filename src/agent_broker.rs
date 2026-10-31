//! Bounded trusted-supervisor entrypoint. Workload identity is bound to an owned socket, never JSON.
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::agent::{AuthenticatedContext, CredentialKind, DurableVault, Error, Field, Fields,
    GenerationPolicy, Mutation, Permission, PrivateAction, PrivateUse, SecretInput, TaskApproval};
use crate::agent_https::{Destination, PreparedHttps};
use crate::agent_ipc::{fits_frame, strict_json, FramedChannel};
use crate::agent_bridge::{Listener, Sessions};

pub(crate) struct RunOptions {
    pub(crate) directory: PathBuf,
    pub(crate) seed_fd: RawFd,
    pub(crate) config_fd: RawFd,
    pub(crate) admin_fd: RawFd,
    pub(crate) create: bool,
    pub(crate) bridge_socket: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorConfig {
    owner: String,
    workspace: String,
    admin_principal: String,
    peers: Vec<PeerConfig>,
    #[serde(default)]
    destinations: Vec<Destination>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerConfig { fd: RawFd, principal: String }

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkRequest {
    Generate { task: Uuid, request: Uuid, kind: CredentialKind, #[serde(default)] username: Option<String>,
        #[serde(default)] policy: Option<GenerationPolicy> },
    Mutate { task: Uuid, request: Uuid, mutation: Mutation },
    Metadata { task: Uuid, record: Uuid, fields: Fields },
    Use { task: Uuid, usage: PrivateUse },
}
impl WorkRequest {
    fn task(&self) -> Uuid {
        match self { Self::Generate { task, .. } | Self::Mutate { task, .. } | Self::Metadata { task, .. }
            | Self::Use { task, .. } => *task }
    }

    pub(crate) fn validate_agent(&self) -> Result<(), Error> {
        match self {
            Self::Mutate { mutation, .. } => match mutation {
                Mutation::Create { .. } | Mutation::Generate { .. } => Err(Error::Denied),
                Mutation::Patch { values, .. } if !values.metadata_only() => Err(Error::Denied),
                Mutation::Share { grant, .. } if grant.permissions.contains(&Permission::SecretRead) => Err(Error::Denied),
                _ => Ok(()),
            },
            Self::Metadata { fields, .. } if fields.iter().any(|field| matches!(field, Field::Password | Field::ApiKey)) => Err(Error::Denied),
            Self::Generate { policy, .. } if policy.is_some_and(|policy| !policy.valid()) => Err(Error::Invalid),
            Self::Generate { kind, username, .. } => match (kind, username.as_deref()) {
                (CredentialKind::Login, Some(name)) if !name.is_empty() && name.len() <= 2048 => Ok(()),
                (CredentialKind::ApiKey, None) => Ok(()),
                _ => Err(Error::Invalid),
            },
            Self::Use { usage, .. } if usage.action != PrivateAction::Use => Err(Error::InteractionRequired),
            _ => Ok(()),
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum AdminControl {
    ImportSecret { task: Uuid, request: Uuid, kind: CredentialKind, values: SecretInput },
    ReadSecret { task: Uuid, record: Uuid, fields: Fields },
    Status,
    Approve { approval: Box<TaskApproval> },
    RevokeTask { task: Uuid },
    IssueSession { principal: String, tasks: Vec<Uuid>, expires_at: i64 },
    RevokeSession { session: Uuid },
    Audit { #[serde(default)] offset: usize },
    Shutdown,
}
enum AdminRequest { Control(AdminControl), Work(WorkRequest) }
impl AdminRequest {
    fn parse(value: Value) -> Result<Self, Error> {
        match value.get("op").and_then(Value::as_str) {
            Some("generate" | "mutate" | "metadata" | "use") =>
                serde_json::from_value(value).map(Self::Work).map_err(|_| Error::Invalid),
            _ => serde_json::from_value(value).map(Self::Control).map_err(|_| Error::Invalid),
        }
    }
}

struct Peer {
    fd: RawFd,
    channel: FramedChannel,
    context: AuthenticatedContext,
    session: Option<Uuid>,
    admin: bool,
    active: bool,
}

fn now() -> i64 { Utc::now().timestamp() }
fn identifier(value: &str) -> bool { !value.is_empty() && value.len() <= 2048 }
fn failure(error: Error) -> Value { json!({"ok": false, "error": error.to_string()}) }

pub(crate) fn open_fd(fd: RawFd) -> Result<(), Error> {
    // SAFETY: F_GETFD has no pointer arguments and cannot transfer descriptor ownership.
    if fd < 3 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 { return Err(Error::Invalid); }
    // SAFETY: the previous check established a live descriptor in this single-threaded entrypoint.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 { return Err(Error::Invalid); }
    Ok(())
}

pub(crate) fn read_fd(fd: RawFd, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    open_fd(fd)?;
    // SAFETY: the supervisor transfers this validated unique descriptor to the broker.
    let file = unsafe { File::from_raw_fd(fd) };
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limit + 1) as u64).read_to_end(&mut bytes).map_err(|_| Error::Invalid)?;
    if bytes.len() > limit { return Err(Error::Invalid); }
    Ok(bytes)
}

pub(crate) fn close_unlisted(keep: &BTreeSet<RawFd>) -> Result<(), Error> {
    let mut descriptors = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(|_| Error::Invalid)? {
        let entry = entry.map_err(|_| Error::Invalid)?;
        let fd: RawFd = entry.file_name().to_str().ok_or(Error::Invalid)?.parse().map_err(|_| Error::Invalid)?;
        if fd > 2 && !keep.contains(&fd) { descriptors.push(fd); }
    }
    for fd in descriptors {
        // SAFETY: closing an integer descriptor has no memory-safety preconditions. The proc iterator is gone.
        if unsafe { libc::close(fd) } < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

fn socket(fd: RawFd) -> Result<UnixStream, Error> {
    open_fd(fd)?;
    for (option, expected) in [(libc::SO_DOMAIN, libc::AF_UNIX), (libc::SO_TYPE, libc::SOCK_STREAM)] {
        let mut value: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: value and size are valid output allocations for the specified integer socket options.
        let result = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, option,
            (&mut value as *mut libc::c_int).cast(), &mut size) };
        if result < 0 || value != expected { return Err(Error::Invalid); }
    }
    // SAFETY: fd is an exclusively transferred, validated AF_UNIX stream descriptor.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.peer_addr().map_err(|_| Error::Invalid)?;
    Ok(stream)
}

fn distinct_sockets(fds: impl Iterator<Item = RawFd>) -> Result<(), Error> {
    let mut identities = BTreeSet::new();
    for fd in fds {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: metadata is a valid output allocation and fd was checked before this call.
        if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } < 0 { return Err(Error::Invalid); }
        // SAFETY: successful fstat initialized the complete structure.
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
            || !identities.insert((metadata.st_dev, metadata.st_ino)) { return Err(Error::Invalid); }
    }
    Ok(())
}

fn peer(fd: RawFd, context: AuthenticatedContext, admin: bool) -> Result<Peer, Error> {
    let stream = socket(fd)?;
    let raw = stream.as_raw_fd();
    let channel = FramedChannel::new(stream, Duration::from_secs(5), Duration::from_secs(5))
        .map_err(|_| Error::Invalid)?;
    Ok(Peer { fd: raw, channel, context, session: None, admin, active: true })
}

fn work(owner: &mut DurableVault, ctx: &AuthenticatedContext, request: WorkRequest,
    destinations: &[Destination]) -> Result<Value, Error> {
    request.validate_agent()?;
    match request {
        WorkRequest::Generate { task, request, kind, username, policy } => {
            let receipt = owner.mutate(ctx, task, request, Mutation::Generate { kind, username, policy }, now())?;
            Ok(json!({"ok": true, "receipt": receipt}))
        }
        WorkRequest::Mutate { task, request, mutation } => {
            let receipt = owner.mutate(ctx, task, request, mutation, now())?;
            Ok(json!({"ok": true, "receipt": receipt}))
        }
        WorkRequest::Metadata { task, record, fields } => {
            let metadata = owner.metadata(ctx, task, record, fields, now())?;
            Ok(json!({"ok": true, "revision": metadata.revision, "signup": metadata.signup, "fields": metadata.fields}))
        }
        WorkRequest::Use { task, usage } => {
            let destination = destinations.iter().find(|destination| destination.id == usage.destination)
                .ok_or(Error::Denied)?;
            if usage.fields != destination.fields() { return Err(Error::Denied); }
            owner.validate_consumer(ctx, task, &destination.service, &destination.origin, now())?;
            let prepared = PreparedHttps::prepare(destination)?;
            let receipt = owner.use_secret(ctx, task, usage, &mut now, move |values| prepared.deliver(values))?;
            Ok(json!({"ok": true, "receipt": receipt}))
        }
    }
}

fn admin(owner: &mut DurableVault, ctx: &AuthenticatedContext, request: AdminRequest,
    sessions: &mut Sessions, destinations: &[Destination]) -> Result<(Value, bool), Error> {
    match request {
        // Human-issued grants may include SecretRead. The core still checks the
        // human task's scope; workload peers always pass validate_agent below.
        AdminRequest::Work(WorkRequest::Mutate { task, request, mutation: mutation @ Mutation::Share { .. } }) => {
            let receipt = owner.mutate(ctx, task, request, mutation, now())?;
            Ok((json!({"ok": true, "receipt": receipt}), false))
        }
        AdminRequest::Work(request) => Ok((work(owner, ctx, request, destinations)?, false)),
        AdminRequest::Control(control) => match control {
            AdminControl::ImportSecret { task, request, kind, values } => {
                let receipt = owner.import_for_task(ctx, task, request, kind, values, now())?;
                Ok((json!({"ok": true, "receipt": receipt}), false))
            }
            AdminControl::ReadSecret { task, record, fields } => {
                let disclosure = owner.read_for_task(ctx, task, record, fields, now())?;
                Ok((json!({"ok": true, "permission": "secret.read", "fields": disclosure.expose()}), false))
            }
            AdminControl::Status => {
                owner.audit_events(ctx)?;
                Ok((json!({"ok": true}), false))
            }
            AdminControl::Shutdown => Ok((json!({"ok": true}), true)),
            AdminControl::Approve { approval } => {
                owner.approve_task(ctx, *approval, now())?;
                Ok((json!({"ok": true}), false))
            }
            AdminControl::RevokeTask { task } => {
                owner.revoke_task(ctx, task, now())?;
                Ok((json!({"ok": true}), false))
            }
            AdminControl::IssueSession { principal, tasks, expires_at } =>
                Ok((sessions.issue(principal, tasks, expires_at, now())?, false)),
            AdminControl::RevokeSession { session } => {
                sessions.revoke(session);
                Ok((json!({"ok":true}), false))
            }
            AdminControl::Audit { offset } => {
                let all = owner.audit_events(ctx)?;
                let total = all.len();
                let events: Vec<_> = all.into_iter().skip(offset).take(100).collect();
                let has_more = offset.saturating_add(events.len()) < total;
                Ok((json!({"ok": true, "events": events, "total": total, "has_more": has_more}), false))
            }
        },
    }
}

/// This is a trusted supervisor protocol, not authentication of arbitrary same-UID callers.
/// The supervisor must close transferred endpoint duplicates and provide private stdout/stderr.
pub(crate) fn harden() -> Result<(), Error> {
    // SAFETY: prctl integer options do not dereference pointers; limits affect this child only.
    let hardened = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
        && libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 };
    if !hardened { return Err(Error::Invalid); }
    Ok(())
}

pub(crate) fn run(options: RunOptions) -> Result<(), Error> {
    harden()?;
    let mut keep = BTreeSet::new();
    for fd in [options.seed_fd, options.config_fd, options.admin_fd] {
        open_fd(fd)?;
        if !keep.insert(fd) { return Err(Error::Invalid); }
    }
    let config_bytes = read_fd(options.config_fd, 65536)?;
    let config: SupervisorConfig = serde_json::from_value(strict_json(&config_bytes).map_err(|_| Error::Invalid)?)
        .map_err(|_| Error::Invalid)?;
    if !identifier(&config.owner) || !identifier(&config.workspace) || !identifier(&config.admin_principal)
        || (config.peers.is_empty() && options.bridge_socket.is_none()) || config.peers.len() > 16 {
        return Err(Error::Invalid);
    }
    if config.destinations.len() > 16 { return Err(Error::Invalid); }
    let mut destination_ids = BTreeSet::new();
    for destination in &config.destinations {
        destination.validate()?;
        if !destination_ids.insert(&destination.id) { return Err(Error::Invalid); }
    }
    let mut principals = BTreeSet::from([config.admin_principal.clone()]);
    for p in &config.peers {
        open_fd(p.fd)?;
        if !identifier(&p.principal) || !principals.insert(p.principal.clone()) || !keep.insert(p.fd) {
            return Err(Error::Invalid);
        }
    }
    distinct_sockets(std::iter::once(options.admin_fd).chain(config.peers.iter().map(|p| p.fd)))?;
    close_unlisted(&keep)?;
    let listener = options.bridge_socket.as_ref().map(|path| Listener::bind(path)).transpose()?;
    let session_admin = config.admin_principal.clone();
    let admin_ctx = AuthenticatedContext::from_authenticated_admin(config.owner.clone(), config.admin_principal, config.workspace.clone());
    let mut peers = vec![peer(options.admin_fd, admin_ctx, true)?];
    for p in config.peers {
        let ctx = AuthenticatedContext::from_authenticated_peer(config.owner.clone(), p.principal, config.workspace.clone());
        peers.push(peer(p.fd, ctx, false)?);
    }
    let seed_bytes = read_fd(options.seed_fd, 4096)?;
    let seed = Zeroizing::new(std::str::from_utf8(&seed_bytes).map_err(|_| Error::Invalid)?.to_owned());
    let mut owner = if options.create { DurableVault::create(&options.directory, &seed)? }
        else { DurableVault::open(&options.directory, &seed)? };
    drop(seed);
    drop(seed_bytes);
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut sessions = Sessions::new(config.owner, config.workspace, session_admin, options.bridge_socket, now() + 300);
    loop {
        if Instant::now() >= deadline { return Ok(()); }
        for p in &mut peers {
            if p.session.is_some_and(|id| !sessions.live(id, now())) { p.active = false; }
        }
        peers.retain(|p| {
            if !p.active { if let Some(id) = p.session { sessions.revoke(id); } }
            p.active
        });
        let mut polls: Vec<_> = peers.iter().map(|p| libc::pollfd {
            fd: if p.active { p.fd } else { -1 }, events: libc::POLLIN, revents: 0,
        }).collect();
        if let Some(listener) = &listener {
            polls.push(libc::pollfd { fd: listener.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        // SAFETY: polls is an initialized contiguous allocation of the supplied count.
        let ready = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 1000) };
        if ready < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
            return Err(Error::InteractionRequired);
        }
        let admission_ready = listener.is_some() && polls.last().is_some_and(|p| p.revents & libc::POLLIN != 0);
        for (p, readiness) in peers.iter_mut().zip(polls) {
            if Instant::now() >= deadline { return Ok(()); }
            if !p.active || readiness.revents == 0 { continue; }
            if p.session.is_some_and(|id| !sessions.live(id, now())) { p.active = false; continue; }
            let value = match p.channel.receive() {
                Ok(value) => value,
                Err(_) => { p.active = false; if p.admin { return Err(Error::InteractionRequired); } continue; }
            };
            if Instant::now() >= deadline { return Ok(()); }
            let ctx = &p.context;
            let result = if p.admin {
                AdminRequest::parse(value)
                    .and_then(|r| admin(&mut owner, ctx, r, &mut sessions, &config.destinations))
            } else {
                serde_json::from_value::<WorkRequest>(value).map_err(|_| Error::Invalid)
                    .and_then(|r| {
                        if p.session.is_some_and(|id| !sessions.permits(id, r.task(), now())) { return Err(Error::Denied); }
                        work(&mut owner, ctx, r, &config.destinations)
                    }).map(|v| (v, false))
            };
            let (response, stop) = result.unwrap_or_else(|error| (failure(error), false));
            // Local response rejection must not poison an otherwise healthy capability.
            let response = if fits_frame(&response) { response } else { failure(Error::Capacity) };
            if p.channel.send(&response).is_err() {
                p.active = false;
                if p.admin && !stop { return Err(Error::InteractionRequired); }
            }
            if stop { return Ok(()); }
        }
        if admission_ready {
            if Instant::now() >= deadline { return Ok(()); }
            if let Some(listener) = &listener {
                if let Ok((stream, _)) = listener.socket.accept() {
                    let fd = stream.as_raw_fd();
                    open_fd(fd)?;
                    if let Ok((id, context, channel)) = sessions.admit(stream, now()) {
                        peers.push(Peer { fd, context, channel, session: Some(id), admin: false, active: true });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(mut value: Value) -> WorkRequest {
        value["task"] = json!(Uuid::from_u128(1));
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn raw_workloads_cannot_cross_the_plaintext_or_grant_boundary() {
        let id = Uuid::from_u128(2);
        assert!(serde_json::from_value::<WorkRequest>(json!({"op":"read", "task":id,
            "record":id,"fields":["Password"]})).is_err());
        for value in [
            json!({"op":"metadata","record":id,"fields":["Password"]}),
            json!({"op":"metadata","record":id,"fields":["ApiKey"]}),
            json!({"op":"mutate","request":id,"mutation":{"Create":{"kind":"ApiKey","values":{"ApiKey":"synthetic"}}}}),
            json!({"op":"mutate","request":id,"mutation":{"Generate":{"kind":"ApiKey","username":null}}}),
            json!({"op":"mutate","request":id,"mutation":{"Patch":{"record":id,"expected":1,"values":{"Label":"allowed","Password":"synthetic"}}}}),
            json!({"op":"mutate","request":id,"mutation":{"Share":{"record":id,"expected":1,"grant":{
                "recipient":"peer","fields":["Password"],"permissions":["SecretUse","SecretRead"],
                "destinations":["fixture"],"expires_at":100,"follow_active":false}}}}),
        ] {
            assert_eq!(request(value).validate_agent(), Err(Error::Denied));
        }
        for action in ["Register", "Login"] {
            assert_eq!(request(json!({"op":"use","usage":{"request":id,"record":id,"fields":["Username","Password"],
                "destination":"fixture","action":action}})).validate_agent(), Err(Error::InteractionRequired));
        }
        for value in [
            json!({"op":"metadata","record":id,"fields":["Username","Label","Notes"]}),
            json!({"op":"mutate","request":id,"mutation":{"Patch":{"record":id,"expected":1,"values":{"Label":"allowed","Username":"allowed","Notes":"allowed"}}}}),
            json!({"op":"mutate","request":id,"mutation":{"Share":{"record":id,"expected":1,"grant":{
                "recipient":"peer","fields":["Password"],"permissions":["SecretUse"],
                "destinations":["fixture"],"expires_at":100,"follow_active":false}}}}),
        ] {
            assert_eq!(request(value).validate_agent(), Ok(()));
        }
    }

    #[test]
    fn generation_wire_requires_kind_appropriate_nonsecret_input() {
        let id = Uuid::from_u128(2);
        for value in [
            json!({"op":"generate","request":id,"kind":"Login","username":"synthetic-user"}),
            json!({"op":"generate","request":id,"kind":"ApiKey"}),
        ] {
            let request = request(value);
            assert_eq!(request.task(), Uuid::from_u128(1));
            assert_eq!(request.validate_agent(), Ok(()));
        }
        for value in [
            json!({"op":"generate","request":id,"kind":"Login"}),
            json!({"op":"generate","request":id,"kind":"Login","username":""}),
            json!({"op":"generate","request":id,"kind":"ApiKey","username":"not-absent"}),
            json!({"op":"generate","request":id,"kind":"ApiKey","policy":{"length":15,"symbols":false,"require_classes":false}}),
            json!({"op":"generate","request":id,"kind":"ApiKey","policy":{"length":129,"symbols":true,"require_classes":true}}),
        ] {
            assert_eq!(request(value).validate_agent(), Err(Error::Invalid));
        }
        let specified = request(json!({"op":"generate","request":id,"kind":"Login","username":"synthetic-user",
            "policy":{"length":32,"symbols":true,"require_classes":true}}));
        assert_eq!(specified.validate_agent(), Ok(()));
        assert!(serde_json::from_value::<WorkRequest>(json!({"op":"generate","task":id,"request":id,"kind":"ApiKey",
            "policy":{"length":32,"symbols":false,"require_classes":false,"extra":true}})).is_err());
    }

    #[test]
    fn private_admin_operations_have_no_workload_or_fallthrough_route() {
        let id = Uuid::from_u128(1);
        for value in [
            json!({"op":"import_secret","task":id,"request":id,"kind":"ApiKey","values":{"ApiKey":"synthetic"}}),
            json!({"op":"read_secret","task":id,"record":id,"fields":["ApiKey"]}),
        ] {
            assert!(serde_json::from_value::<WorkRequest>(value.clone()).is_err());
            assert!(matches!(AdminRequest::parse(value.clone()), Ok(AdminRequest::Control(_))));
            let mut forged = value;
            forged["admin"] = json!(true);
            assert!(AdminRequest::parse(forged).is_err());
        }
        assert!(AdminRequest::parse(json!({"op":"read_secret","task":id,"record":id,"fields":["ApiKey"],"mutation":{}})).is_err());
    }
}
