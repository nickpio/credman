//! Agent policy core. Sibling callers use DurableVault, never the private staging application.
//! Contexts, approvals, clock values and use callbacks come from trusted integration.

mod snapshot;
#[cfg(target_os = "linux")]
mod storage;
#[cfg(target_os = "linux")]
pub(crate) use storage::DurableVault;
#[cfg(target_os = "linux")]
pub(crate) use storage::BackupSecret;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) type Time = i64;
/// Backward steps at or below this many seconds keep the high-water mark and do not freeze the vault.
pub(crate) const CLOCK_SKEW_TOLERANCE: Time = 5;
pub(crate) type Fields = BTreeSet<Field>;
pub(crate) type Permissions = BTreeSet<Permission>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Field { Label, Username, Password, ApiKey, Notes }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Permission { MetadataRead, SecretUse, SecretRead, SecretWrite, AccessGrant, EntryDelete }

impl Field {
    fn secret(self) -> bool { matches!(self, Self::Password | Self::ApiKey) }
}

/// Never deserialize identity or administration authority from an agent request.
#[derive(Clone)]
pub(crate) struct AuthenticatedContext {
    owner: String,
    principal: String,
    workspace: String,
    admin: bool,
    session_deadline: Option<Time>,
}

impl AuthenticatedContext {
    /// Trusted transport/admin integration only. Not an authentication mechanism itself.
    pub(crate) fn from_authenticated_peer(owner: String, principal: String, workspace: String) -> Self {
        Self { owner, principal, workspace, admin: false, session_deadline: None }
    }

    /// Trusted session attachment only. Deadline comes from matched server-held session state.
    pub(crate) fn from_authenticated_session(owner: String, principal: String, workspace: String, deadline: Time) -> Self {
        Self { owner, principal, workspace, admin: false, session_deadline: Some(deadline) }
    }

    /// Trusted, separately authenticated human control path only.
    pub(crate) fn from_authenticated_admin(owner: String, principal: String, workspace: String) -> Self {
        Self { owner, principal, workspace, admin: true, session_deadline: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShareBounds {
    pub(crate) recipients: BTreeSet<String>,
    pub(crate) fields: Fields,
    pub(crate) permissions: Permissions,
    pub(crate) destinations: BTreeSet<String>,
    pub(crate) expires_at: Time,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskApproval {
    pub(crate) id: Uuid,
    pub(crate) owner: String,
    pub(crate) principal: String,
    pub(crate) workspace: String,
    pub(crate) service: String,
    pub(crate) origin: String,
    pub(crate) fields: Fields,
    pub(crate) permissions: Permissions,
    pub(crate) destinations: BTreeSet<String>,
    pub(crate) expires_at: Time,
    pub(crate) share: Option<ShareBounds>,
}

/// Intentionally no Debug. Serialization is used only for internal request fingerprints.
#[derive(Clone)]
pub(crate) struct SecretInput(BTreeMap<Field, Zeroizing<String>>);

impl Serialize for SecretInput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let values: BTreeMap<Field, &str> = self.0.iter().map(|(f, v)| (*f, v.as_str())).collect();
        values.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueFields;
        impl<'de> serde::de::Visitor<'de> for UniqueFields {
            type Value = SecretInput;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("unique credential fields")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = BTreeMap::new();
                while let Some(field) = map.next_key::<Field>()? {
                    if fields.contains_key(&field) {
                        return Err(serde::de::Error::custom("duplicate credential field"));
                    }
                    let value = Zeroizing::new(map.next_value::<String>()?);
                    fields.insert(field, value);
                }
                Ok(SecretInput(fields))
            }
        }
        deserializer.deserialize_map(UniqueFields)
    }
}

impl SecretInput {
    pub(crate) fn metadata_only(&self) -> bool { self.0.keys().all(|field| !field.secret()) }
    #[cfg(test)]
    pub(crate) fn new(fields: BTreeMap<Field, String>) -> Self {
        Self(fields.into_iter().map(|(field, value)| (field, Zeroizing::new(value))).collect())
    }
    fn fields(&self) -> Fields { self.0.keys().copied().collect() }
    fn valid(&self) -> bool {
        !self.0.is_empty() && self.0.len() <= 5
            && self.0.iter().all(|(field, value)| value.len() <= 8192 && (!field.secret() || !value.is_empty()))
    }
}

/// No plaintext Debug or implicit serialization on access results.
pub(crate) struct Disclosure(SecretInput);
impl Disclosure {
    /// Explicit disclosure boundary. The caller must label this as secret.read.
    pub(crate) fn expose(&self) -> BTreeMap<Field, &str> {
        self.0.0.iter().map(|(f, v)| (*f, v.as_str())).collect()
    }
}
impl fmt::Debug for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Disclosure([REDACTED])") }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum CredentialKind { Login, ApiKey }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SignupState { Pending, Submitted, ReportedSuccess, VerifiedLogin, Rejected, HumanRequired, Unknown }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: Uuid,
    owner: String,
    workspace: String,
    created_by: String,
    task: Uuid,
    service: String,
    origin: String,
    kind: CredentialKind,
    revision: u64,
    secret_version: u64,
    values: SecretInput,
    signup: SignupState,
    deleted: bool,
    restored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantSpec {
    pub(crate) recipient: String,
    pub(crate) fields: Fields,
    pub(crate) permissions: Permissions,
    pub(crate) destinations: BTreeSet<String>,
    pub(crate) expires_at: Time,
    /// When true, later secret versions stay authorized. Pinned grants match the issued version.
    pub(crate) follow_active: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant { record: Uuid, spec: GrantSpec, revoked: bool, version: u64, issuer_task: Uuid, admin_issued: bool }

/// Bounds for privately generated secrets. Absent on the wire for policy-less requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationPolicy {
    pub(crate) length: u8,
    pub(crate) symbols: bool,
    pub(crate) require_classes: bool,
}
impl GenerationPolicy {
    pub(crate) fn valid(self) -> bool { (16..=128).contains(&self.length) }
}

/// Caller input contains no owner, creator, origin mutation or authentication fields.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Mutation {
    Create { kind: CredentialKind, values: SecretInput },
    Generate {
        kind: CredentialKind,
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<GenerationPolicy>,
    },
    Patch { record: Uuid, expected: u64, values: SecretInput },
    Delete { record: Uuid, expected: u64 },
    Share { record: Uuid, expected: u64, grant: GrantSpec },
    Revoke { record: Uuid, expected: u64, grant: Uuid },
    ReportOutcome { record: Uuid, expected: u64, state: SignupState },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub(crate) record: Uuid,
    pub(crate) revision: u64,
    pub(crate) grant: Option<Uuid>,
}

/// Nonsecret record view. `fields` contains only the requested metadata fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetadataView {
    pub(crate) revision: u64,
    pub(crate) signup: SignupState,
    pub(crate) fields: BTreeMap<Field, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    #[error("access denied")]
    Denied,
    #[error("invalid request")]
    Invalid,
    #[error("revision conflict")]
    Conflict,
    #[error("request identifier reused with different input")]
    ReplayConflict,
    #[error("trusted clock recovery required")]
    ClockRecoveryRequired,
    #[error("capacity reached")]
    Capacity,
    #[error("private delivery unavailable")]
    InteractionRequired,
    #[error("private credential generation unavailable")]
    GenerationUnavailable,
    #[error("storage publication did not occur")]
    NotPublished,
    #[error("validated storage recovery required")]
    RecoveryRequired,
    #[error("invalid encrypted agent vault")]
    InvalidStorage,
    #[error("agent vault is in use")]
    InUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DeliveryStatus { Accepted, Rejected, HumanRequired, Unknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PrivateAction { Use, Register, Login }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateUse {
    pub(crate) request: Uuid,
    pub(crate) record: Uuid,
    pub(crate) fields: Fields,
    pub(crate) destination: String,
    pub(crate) action: PrivateAction,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DeliveryReceipt { pub(crate) attempt: Uuid, pub(crate) status: DeliveryStatus }

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestKey { owner: String, principal: String, task: Uuid, id: Uuid }
#[derive(Clone, Copy, Serialize, Deserialize)]
enum CachedKind { Create, Patch, MetadataPatch, Delete, Share, Revoke, ReportOutcome }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Remembered { fingerprint: [u8; 32], result: Receipt, kind: CachedKind }

fn generation_fields(kind: CredentialKind, username: Option<&str>) -> Result<Fields, Error> {
    match (kind, username) {
        (CredentialKind::Login, Some(name)) if !name.is_empty() && name.len() <= 2048 =>
            Ok([Field::Username, Field::Password].into_iter().collect()),
        (CredentialKind::ApiKey, None) => Ok([Field::ApiKey].into_iter().collect()),
        _ => Err(Error::Invalid),
    }
}

#[cfg(test)]
thread_local! {
    static GENERATION_DRAWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static GENERATION_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

const GENERATION_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const GENERATION_SYMBOLS: &[u8] = b"!@#$%^&*+=?";

/// Rejection sampling: bytes at or above the largest multiple of `span` in `0..256` are discarded.
fn generation_index(byte: u8, span: usize) -> Option<usize> {
    if span == 0 || span > 256 { return None; }
    let limit = (256 / span) * span;
    let value = byte as usize;
    (value < limit).then_some(value % span)
}

fn sample_secret(alphabet: &[u8], length: usize) -> Result<Zeroizing<String>, Error> {
    let mut secret = Zeroizing::new(String::with_capacity(length));
    let mut random = Zeroizing::new([0u8; 128]);
    while secret.len() < length {
        OsRng.try_fill_bytes(random.as_mut()).map_err(|_| Error::GenerationUnavailable)?;
        for &byte in random.iter() {
            if secret.len() == length { break; }
            if let Some(index) = generation_index(byte, alphabet.len()) {
                secret.push(alphabet[index] as char);
            }
        }
    }
    Ok(secret)
}

fn classes_present(secret: &str, symbols: bool) -> bool {
    let (mut upper, mut lower, mut digit, mut symbol) = (false, false, false, !symbols);
    for byte in secret.bytes() {
        match byte {
            b'A'..=b'Z' => upper = true,
            b'a'..=b'z' => lower = true,
            b'0'..=b'9' => digit = true,
            _ if symbols && GENERATION_SYMBOLS.contains(&byte) => symbol = true,
            _ => {}
        }
    }
    upper && lower && digit && symbol
}

fn generate_secret(policy: Option<GenerationPolicy>) -> Result<Zeroizing<String>, Error> {
    #[cfg(test)]
    {
        GENERATION_DRAWS.with(|draws| draws.set(draws.get() + 1));
        if GENERATION_FAIL.with(|fail| fail.replace(false)) { return Err(Error::GenerationUnavailable); }
    }
    let Some(policy) = policy else {
        let mut random = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(random.as_mut()).map_err(|_| Error::GenerationUnavailable)?;
        let mut secret = Zeroizing::new(String::with_capacity(32));
        // A power-of-two alphabet gives uniform characters without modulo bias.
        for byte in random.iter() { secret.push(GENERATION_ALPHABET[(byte & 63) as usize] as char); }
        return Ok(secret);
    };
    if !policy.valid() { return Err(Error::Invalid); }
    let mut alphabet = GENERATION_ALPHABET.to_vec();
    if policy.symbols { alphabet.extend_from_slice(GENERATION_SYMBOLS); }
    // Whole-value retries keep required classes from pinning positions.
    for _ in 0..128 {
        let secret = sample_secret(&alphabet, policy.length as usize)?;
        if !policy.require_classes || classes_present(&secret, policy.symbols) { return Ok(secret); }
    }
    Err(Error::GenerationUnavailable)
}

fn generate_values(kind: CredentialKind, username: Option<String>, policy: Option<GenerationPolicy>) -> Result<SecretInput, Error> {
    let secret = generate_secret(policy)?;
    let mut values = BTreeMap::new();
    match kind {
        CredentialKind::Login => {
            values.insert(Field::Username, Zeroizing::new(username.ok_or(Error::Invalid)?));
            values.insert(Field::Password, secret);
        }
        CredentialKind::ApiKey => { values.insert(Field::ApiKey, secret); }
    }
    Ok(SecretInput(values))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryAttempt {
    task: Uuid, record: Uuid, version: u64, destination: String, fields: Fields,
    status: Option<DeliveryStatus>,
    key: RequestKey,
    fingerprint: [u8; 32],
    action: PrivateAction,
    dispatched: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AuditAction { Mutation, MetadataRead, SecretRead, SecretUse }

/// Safe successful-transition events only. Bounded, volatile, not an authoritative audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditEvent {
    pub(crate) task: Uuid,
    pub(crate) record: Uuid,
    pub(crate) request: Option<Uuid>,
    pub(crate) action: AuditAction,
    /// Zero when decoded from a snapshot written before this field existed.
    #[serde(default)]
    pub(crate) at: Time,
    /// Empty when decoded from a snapshot written before this field existed.
    #[serde(default)]
    pub(crate) principal: String,
}

/// Private staging state. Only the durable owner is reachable by sibling modules.
#[derive(Default, Clone)]
struct Application {
    tasks: BTreeMap<Uuid, TaskApproval>,
    records: BTreeMap<Uuid, Record>,
    grants: BTreeMap<Uuid, Grant>,
    requests: BTreeMap<RequestKey, Remembered>,
    audit: VecDeque<AuditEvent>,
    last_time: Option<Time>,
    clock_frozen: bool,
    generation: u64,
    revoked_tasks: BTreeSet<Uuid>,
    deliveries: BTreeMap<Uuid, DeliveryAttempt>,
}

impl Application {
    fn audit(&mut self, event: AuditEvent) {
        if self.audit.len() == 10_000 { self.audit.pop_front(); }
        self.audit.push_back(event);
    }

    /// Administration only. Agent metadata/disclosure paths never expose this stream.
    pub(crate) fn audit_events(&self, admin: &AuthenticatedContext) -> Result<Vec<AuditEvent>, Error> {
        if !admin.admin { return Err(Error::Denied); }
        Ok(self.audit.iter().filter(|event| self.tasks.get(&event.task).is_some_and(|task|
            task.owner == admin.owner && task.workspace == admin.workspace)).cloned().collect())
    }

    fn effective_time(&self, now: Time) -> Result<Time, Error> {
        if self.clock_frozen { return Err(Error::ClockRecoveryRequired); }
        match self.last_time {
            Some(last) if now < last => {
                if last.saturating_sub(now) <= CLOCK_SKEW_TOLERANCE { Ok(last) } else { Err(Error::ClockRecoveryRequired) }
            }
            _ => Ok(now),
        }
    }

    /// Effective time for expiry checks. Within-tolerance rollback does not move the high-water mark.
    fn clock(&mut self, now: Time) -> Result<Time, Error> {
        let effective = match self.effective_time(now) {
            Ok(effective) => effective,
            Err(error) => { self.clock_frozen = true; return Err(error); }
        };
        if self.last_time.is_none_or(|high| now > high) { self.last_time = Some(now); }
        Ok(effective)
    }

    pub(crate) fn approve_task(&mut self, admin: &AuthenticatedContext, task: TaskApproval, now: Time) -> Result<(), Error> {
        let now = self.clock(now)?;
        if !admin.admin || admin.owner != task.owner || admin.workspace != task.workspace { return Err(Error::Denied); }
        // Retained immutable tasks bind this dedicated vault even after revocation/deletion.
        if self.tasks.values().any(|retained| retained.owner != task.owner || retained.workspace != task.workspace) {
            return Err(Error::Denied);
        }
        if task.id.is_nil() || task.expires_at <= now || task.fields.is_empty() || task.permissions.is_empty()
            || task.owner.is_empty() || task.principal.is_empty() || task.workspace.is_empty() || task.service.is_empty() || task.origin.is_empty()
            || [&task.owner, &task.principal, &task.workspace, &task.service, &task.origin].iter().any(|s| s.len() > 2048)
            || task.destinations.len() > 32 || task.destinations.iter().any(|s| s.is_empty() || s.len() > 2048)
        { return Err(Error::Invalid); }
        if let Some(bounds) = &task.share {
            if bounds.recipients.is_empty() || bounds.recipients.len() > 32
                || bounds.recipients.iter().any(|s| s.is_empty() || s.len() > 2048)
                || !bounds.fields.is_subset(&task.fields) || !bounds.permissions.is_subset(&task.permissions)
                || !bounds.destinations.is_subset(&task.destinations) || bounds.expires_at > task.expires_at
                || bounds.expires_at <= now || bounds.permissions.contains(&Permission::AccessGrant)
            { return Err(Error::Invalid); }
        }
        if self.tasks.contains_key(&task.id) { return Err(Error::Conflict); }
        if self.tasks.len() >= 10_000 { return Err(Error::Capacity); }
        self.tasks.insert(task.id, task);
        Ok(())
    }

    pub(crate) fn revoke_task(&mut self, admin: &AuthenticatedContext, id: Uuid, now: Time) -> Result<(), Error> {
        self.clock(now)?;
        let task = self.tasks.get(&id).ok_or(Error::Denied)?;
        if !admin.admin || admin.owner != task.owner || admin.workspace != task.workspace { return Err(Error::Denied); }
        self.revoked_tasks.insert(id);
        Ok(())
    }

    fn task(&self, ctx: &AuthenticatedContext, id: Uuid, now: Time) -> Result<&TaskApproval, Error> {
        let t = self.tasks.get(&id).ok_or(Error::Denied)?;
        if t.owner != ctx.owner || t.workspace != ctx.workspace || t.principal != ctx.principal
            || now >= t.expires_at || self.revoked_tasks.contains(&id)
            || ctx.session_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(Error::Denied);
        }
        Ok(t)
    }

    fn trusted_task_context(&self, admin: &AuthenticatedContext, id: Uuid, now: Time) -> Result<AuthenticatedContext, Error> {
        if !admin.admin { return Err(Error::Denied); }
        let t = self.tasks.get(&id).ok_or(Error::Denied)?;
        if t.owner != admin.owner || t.workspace != admin.workspace { return Err(Error::Denied); }
        let ctx = AuthenticatedContext::from_authenticated_peer(t.owner.clone(), t.principal.clone(), t.workspace.clone());
        self.task(&ctx, id, now)?;
        Ok(ctx)
    }

    fn record(&self, ctx: &AuthenticatedContext, id: Uuid) -> Result<&Record, Error> {
        let r = self.records.get(&id).ok_or(Error::Denied)?;
        if r.owner != ctx.owner || r.workspace != ctx.workspace || r.deleted { return Err(Error::Denied); }
        Ok(r)
    }

    #[expect(clippy::too_many_arguments, reason = "Keep explicit authorization dimensions at each check")]
    fn can(&self, ctx: &AuthenticatedContext, t: &TaskApproval, r: &Record,
           permission: Permission, fields: &Fields, destination: Option<&str>, now: Time) -> bool {
        if r.service != t.service || r.origin != t.origin || !t.permissions.contains(&permission)
            || !fields.is_subset(&t.fields) || destination.is_some_and(|d| !t.destinations.contains(d))
        { return false; }
        if r.created_by == ctx.principal && r.task == t.id { return true; }
        self.grants.values().any(|g| g.record == r.id && !g.revoked && now < g.spec.expires_at
            && (if g.spec.follow_active { r.secret_version >= g.version } else { g.version == r.secret_version })
            && !self.revoked_tasks.contains(&g.issuer_task)
            && self.tasks.get(&g.issuer_task).is_some_and(|issuer| now < issuer.expires_at)
            && g.spec.recipient == ctx.principal && g.spec.permissions.contains(&permission)
            && fields.is_subset(&g.spec.fields)
            && destination.is_none_or(|d| g.spec.destinations.contains(d)))
    }

    fn authorize(&self, ctx: &AuthenticatedContext, t: &TaskApproval, op: &Mutation, now: Time, retry: bool) -> Result<(), Error> {
        use Permission::*;
        if let Mutation::Generate { kind, username, policy } = op {
            if policy.is_some_and(|policy| !policy.valid()) { return Err(Error::Invalid); }
            let fields = generation_fields(*kind, username.as_deref())?;
            if !t.permissions.contains(&SecretWrite) || !fields.is_subset(&t.fields) { return Err(Error::Denied); }
            return Ok(());
        }
        if let Mutation::Create { kind, values } = op {
            if !values.valid() { return Err(Error::Invalid); }
            if !t.permissions.contains(&SecretWrite) || !values.fields().is_subset(&t.fields) { return Err(Error::Denied); }
            if (*kind == CredentialKind::Login && (!values.0.contains_key(&Field::Password) || values.0.contains_key(&Field::ApiKey)))
                || (*kind == CredentialKind::ApiKey && (!values.0.contains_key(&Field::ApiKey) || values.0.contains_key(&Field::Password)))
            { return Err(Error::Invalid); }
            return Ok(());
        }
        let (id, expected) = match op {
            Mutation::Patch { record, expected, .. } | Mutation::Delete { record, expected }
            | Mutation::Share { record, expected, .. } | Mutation::Revoke { record, expected, .. }
            | Mutation::ReportOutcome { record, expected, .. } => (*record, *expected),
            Mutation::Create { .. } | Mutation::Generate { .. } => unreachable!(),
        };
        // Deleted records still permit only an authorized identical deletion receipt retry.
        let r = self.records.get(&id).ok_or(Error::Denied)?;
        if r.owner != ctx.owner || r.workspace != ctx.workspace || (r.deleted && !(retry && matches!(op, Mutation::Delete { .. }))) {
            return Err(Error::Denied);
        }
        match op {
            Mutation::Patch { values, .. } => {
                if !values.valid() { return Err(Error::Invalid); }
                if !self.can(ctx, t, r, SecretWrite, &values.fields(), None, now) { return Err(Error::Denied); }
                if (r.kind == CredentialKind::Login && values.0.contains_key(&Field::ApiKey))
                    || (r.kind == CredentialKind::ApiKey && values.0.contains_key(&Field::Password))
                { return Err(Error::Invalid); }
            }
            Mutation::Delete { .. } => {
                if !ctx.admin && !self.can(ctx, t, r, EntryDelete, &r.values.fields(), None, now) { return Err(Error::Denied); }
            }
            Mutation::Share { grant, .. } => {
                if grant.fields.is_empty() || grant.permissions.is_empty() || grant.expires_at <= now
                    || grant.recipient.is_empty() || grant.recipient.len() > 2048
                    || grant.permissions.contains(&AccessGrant) || !grant.fields.is_subset(&r.values.fields())
                    || grant.destinations.len() > 32 || grant.destinations.iter().any(|s| s.is_empty() || s.len() > 2048)
                    || (grant.permissions.contains(&SecretUse) && grant.destinations.is_empty())
                { return Err(Error::Invalid); }
                if !ctx.admin {
                    let bounds = t.share.as_ref().ok_or(Error::Denied)?;
                    if !self.can(ctx, t, r, AccessGrant, &grant.fields, None, now)
                        || !bounds.recipients.contains(&grant.recipient) || !grant.fields.is_subset(&bounds.fields)
                        || !grant.permissions.is_subset(&bounds.permissions) || !grant.destinations.is_subset(&bounds.destinations)
                        || grant.expires_at > bounds.expires_at
                    { return Err(Error::Denied); }
                    for permission in &grant.permissions {
                        if !self.can(ctx, t, r, *permission, &grant.fields, None, now) { return Err(Error::Denied); }
                    }
                } else if r.service != t.service || r.origin != t.origin || !grant.fields.is_subset(&t.fields)
                    || !grant.permissions.is_subset(&t.permissions) || !grant.destinations.is_subset(&t.destinations)
                    || grant.expires_at > t.expires_at
                { return Err(Error::Denied); }
            }
            Mutation::Revoke { grant, .. } => {
                let g = self.grants.get(grant).ok_or(Error::Denied)?;
                if g.record != id || (!ctx.admin && !self.can(ctx, t, r, AccessGrant, &g.spec.fields, None, now)) {
                    return Err(Error::Denied);
                }
            }
            Mutation::ReportOutcome { state, .. } => {
                // Agent reports cannot promote themselves to verified adapter evidence.
                if *state == SignupState::VerifiedLogin || !self.can(ctx, t, r, SecretWrite, &Fields::new(), None, now) {
                    return Err(Error::Denied);
                }
            }
            Mutation::Create { .. } | Mutation::Generate { .. } => unreachable!(),
        }
        if !retry && r.revision != expected { return Err(Error::Conflict); }
        if !retry && r.revision == u64::MAX { return Err(Error::Capacity); }
        Ok(())
    }

    pub(crate) fn mutate(&mut self, ctx: &AuthenticatedContext, task: Uuid, request: Uuid,
                         op: Mutation, now: Time) -> Result<Receipt, Error> {
        let now = self.clock(now)?;
        if request.is_nil() { return Err(Error::Invalid); }
        let t = self.task(ctx, task, now)?.clone();
        self.authorize(ctx, &t, &op, now, true)?;
        let key = RequestKey { owner: ctx.owner.clone(), principal: ctx.principal.clone(), task, id: request };
        if self.deliveries.values().any(|delivery| delivery.key == key) { return Err(Error::ReplayConflict); }
        let bytes = Zeroizing::new(serde_json::to_vec(&op).map_err(|_| Error::Invalid)?);
        if bytes.len() > 65536 { return Err(Error::Invalid); }
        let fingerprint: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        if let Some(previous) = self.requests.get(&key) {
            // No cached result is a capability, even if request ID and input match.
            if previous.fingerprint != fingerprint { return Err(Error::ReplayConflict); }
            if matches!(&op, Mutation::Create { .. } | Mutation::Generate { .. }) { self.record(ctx, previous.result.record)?; }
            return Ok(previous.result.clone());
        }
        self.authorize(ctx, &t, &op, now, false)?;
        if self.requests.len() >= 10_000 { return Err(Error::Capacity); }
        let kind = match &op {
            Mutation::Create { .. } | Mutation::Generate { .. } => CachedKind::Create,
            Mutation::Patch { values, .. } if values.metadata_only() => CachedKind::MetadataPatch,
            Mutation::Patch { .. } => CachedKind::Patch,
            Mutation::Delete { .. } => CachedKind::Delete, Mutation::Share { .. } => CachedKind::Share,
            Mutation::Revoke { .. } => CachedKind::Revoke, Mutation::ReportOutcome { .. } => CachedKind::ReportOutcome,
        };
        // Fingerprint and cache checks above must use the nonsecret Generate specification.
        let op = match op {
            Mutation::Generate { kind, username, policy } => {
                if self.records.len() >= 10_000 { return Err(Error::Capacity); }
                Mutation::Create { kind, values: generate_values(kind, username, policy)? }
            }
            other => other,
        };
        let receipt = match op {
            Mutation::Generate { .. } => unreachable!(),
            Mutation::Create { kind, values } => {
                if self.records.len() >= 10_000 { return Err(Error::Capacity); }
                let id = Uuid::new_v4();
                self.records.insert(id, Record {
                    id, owner: ctx.owner.clone(), workspace: ctx.workspace.clone(), created_by: ctx.principal.clone(),
                    task, service: t.service, origin: t.origin, kind, revision: 1, secret_version: 1,
                    values, signup: SignupState::Pending, deleted: false, restored: false,
                });
                Receipt { record: id, revision: 1, grant: None }
            }
            Mutation::Patch { record, values, .. } => {
                let secret = !values.metadata_only();
                let r = self.records.get_mut(&record).ok_or(Error::Denied)?;
                if secret {
                    if r.secret_version == u64::MAX { return Err(Error::Capacity); }
                    r.secret_version += 1;
                    r.signup = SignupState::Pending;
                }
                r.values.0.extend(values.0);
                r.revision += 1;
                Receipt { record, revision: r.revision, grant: None }
            }
            Mutation::Share { record, grant, .. } => {
                if self.grants.len() >= 10_000 { return Err(Error::Capacity); }
                let id = Uuid::new_v4();
                let version = self.records.get(&record).ok_or(Error::Denied)?.secret_version;
                self.grants.insert(id, Grant { record, spec: grant, revoked: false, version, issuer_task: task, admin_issued: ctx.admin });
                let r = self.records.get_mut(&record).ok_or(Error::Denied)?;
                r.revision += 1;
                Receipt { record, revision: r.revision, grant: Some(id) }
            }
            Mutation::Revoke { record, grant, .. } => {
                self.grants.get_mut(&grant).ok_or(Error::Denied)?.revoked = true;
                let r = self.records.get_mut(&record).ok_or(Error::Denied)?;
                r.revision += 1;
                Receipt { record, revision: r.revision, grant: Some(grant) }
            }
            Mutation::Delete { record, .. } => {
                let r = self.records.get_mut(&record).ok_or(Error::Denied)?;
                r.deleted = true;
                r.values.0.clear();
                r.revision += 1;
                for g in self.grants.values_mut().filter(|g| g.record == record) { g.revoked = true; }
                Receipt { record, revision: r.revision, grant: None }
            }
            Mutation::ReportOutcome { record, state, .. } => {
                let r = self.records.get_mut(&record).ok_or(Error::Denied)?;
                r.signup = state;
                r.revision += 1;
                Receipt { record, revision: r.revision, grant: None }
            }
        };
        self.requests.insert(key, Remembered { fingerprint, result: receipt.clone(), kind });
        self.audit(AuditEvent { task, record: receipt.record, request: Some(request), action: AuditAction::Mutation,
            at: now, principal: ctx.principal.clone() });
        Ok(receipt)
    }

    #[expect(clippy::too_many_arguments, reason = "Keep explicit authorization dimensions at each check")]
    fn select(&self, ctx: &AuthenticatedContext, task: Uuid, record: Uuid,
              fields: &Fields, permission: Permission, destination: Option<&str>, now: Time) -> Result<SecretInput, Error> {
        if fields.is_empty() { return Err(Error::Invalid); }
        if permission == Permission::MetadataRead && fields.iter().any(|f| f.secret()) { return Err(Error::Denied); }
        let t = self.task(ctx, task, now)?;
        let r = self.record(ctx, record)?;
        if !self.can(ctx, t, r, permission, fields, destination, now) { return Err(Error::Denied); }
        let mut values = BTreeMap::new();
        for field in fields { values.insert(*field, r.values.0.get(field).ok_or(Error::Denied)?.clone()); }
        Ok(SecretInput(values))
    }

    pub(crate) fn read_secret(&mut self, ctx: &AuthenticatedContext, task: Uuid, record: Uuid,
                              fields: Fields, now: Time) -> Result<Disclosure, Error> {
        let now = self.clock(now)?;
        let result = self.select(ctx, task, record, &fields, Permission::SecretRead, None, now)?;
        self.audit(AuditEvent { task, record, request: None, action: AuditAction::SecretRead,
            at: now, principal: ctx.principal.clone() });
        Ok(Disclosure(result))
    }

    pub(crate) fn metadata(&mut self, ctx: &AuthenticatedContext, task: Uuid, record: Uuid,
                           fields: Fields, now: Time) -> Result<MetadataView, Error> {
        let now = self.clock(now)?;
        let values = self.select(ctx, task, record, &fields, Permission::MetadataRead, None, now)?;
        let record_state = self.record(ctx, record)?;
        let view = MetadataView {
            revision: record_state.revision,
            signup: record_state.signup,
            fields: values.0.into_iter().map(|(f, v)| (f, v.to_string())).collect(),
        };
        self.audit(AuditEvent { task, record, request: None, action: AuditAction::MetadataRead,
            at: now, principal: ctx.principal.clone() });
        Ok(view)
    }

    /// The callback is trusted integration, never a model-controlled destination or ordinary tool response.
    /// Synchronous exclusive ownership orders dispatch before/after revoke. No persistence or replay is claimed.
    #[cfg(test)]
    #[expect(clippy::too_many_arguments, reason = "Test-only synchronous policy oracle")]
    pub(crate) fn use_secret<F>(&mut self, ctx: &AuthenticatedContext, task: Uuid, record: Uuid,
                                fields: Fields, destination: &str, now: Time, deliver: F) -> Result<DeliveryReceipt, Error>
    where F: FnOnce(&BTreeMap<Field, &str>) -> Result<DeliveryStatus, Error> {
        let now = self.clock(now)?;
        let values = self.select(ctx, task, record, &fields, Permission::SecretUse, Some(destination), now)?;
        let private = values.0.iter().map(|(f, v)| (*f, v.as_str())).collect();
        let status = deliver(&private)?;
        self.audit(AuditEvent { task, record, request: None, action: AuditAction::SecretUse,
            at: now, principal: ctx.principal.clone() });
        Ok(DeliveryReceipt { attempt: Uuid::new_v4(), status })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod private_generation_tests;
