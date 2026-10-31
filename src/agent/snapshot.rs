//! Private encrypted-payload codec. Never an agent response or plaintext export surface.
use super::*;

pub(super) const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;
const LIMIT: usize = 10_000;
const COMPACT_AT: usize = 8_000;
/// Cached mutation receipts and completed deliveries stay idempotent for this long.
/// A pruned request id is not a saved authorization: the retry is a new operation and current policy is checked again.
/// Untimestamped entries inherit the snapshot clock high-water on decode.
pub(super) const RETRY_WINDOW: Time = 24 * 60 * 60;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u32,
    generation: u64,
    tasks: Vec<TaskApproval>,
    records: Vec<Record>,
    grants: Vec<(Uuid, Grant)>,
    requests: Vec<(RequestKey, Remembered)>,
    revoked_tasks: Vec<Uuid>,
    deliveries: Vec<(Uuid, DeliveryAttempt)>,
    audit: Vec<AuditEvent>,
    last_time: Option<Time>,
    clock_frozen: bool,
    /// Per-record account of revisions whose receipts were compacted. Absent on schema 2.
    #[serde(default)]
    baselines: Vec<(Uuid, RecordBaseline)>,
    /// SHA-256 of the previous ciphertext when this image replaced the salt or seed.
    #[serde(default)]
    predecessor: Option<[u8; 32]>,
}

pub(super) fn encode(app: &Application) -> Result<Zeroizing<Vec<u8>>, Error> {
    validate(app)?;
    let snapshot = Snapshot {
        schema: 3, generation: app.generation,
        tasks: app.tasks.values().cloned().collect(), records: app.records.values().cloned().collect(),
        grants: app.grants.iter().map(|(k, v)| (*k, v.clone())).collect(),
        requests: app.requests.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        revoked_tasks: app.revoked_tasks.iter().copied().collect(),
        deliveries: app.deliveries.iter().map(|(k, v)| (*k, v.clone())).collect(),
        audit: app.audit.iter().cloned().collect(), last_time: app.last_time, clock_frozen: app.clock_frozen,
        baselines: app.baselines.iter().map(|(k, v)| (*k, v.clone())).collect(),
        predecessor: app.predecessor,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&snapshot).map_err(|_| Error::InvalidStorage)?);
    if bytes.len() > MAX_PLAINTEXT { return Err(Error::Capacity); }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Application, Error> {
    if bytes.len() > MAX_PLAINTEXT { return Err(Error::InvalidStorage); }
    let s: Snapshot = serde_json::from_slice(bytes).map_err(|_| Error::InvalidStorage)?;
    if (s.schema != 2 && s.schema != 3) || s.generation == 0 || [s.tasks.len(), s.records.len(), s.grants.len(),
        s.requests.len(), s.revoked_tasks.len(), s.deliveries.len(), s.audit.len(), s.baselines.len()].iter().any(|n| *n > LIMIT)
    { return Err(Error::InvalidStorage); }
    let mut app = Application { generation: s.generation, last_time: s.last_time,
        clock_frozen: s.clock_frozen, predecessor: s.predecessor, ..Application::default() };
    for t in s.tasks {
        if app.tasks.insert(t.id, t).is_some() { return Err(Error::InvalidStorage); }
    }
    for r in s.records {
        if app.records.insert(r.id, r).is_some() { return Err(Error::InvalidStorage); }
    }
    for (id, g) in s.grants {
        if app.grants.insert(id, g).is_some() { return Err(Error::InvalidStorage); }
    }
    for (id, mut r) in s.requests {
        if r.at.is_none() { r.at = app.last_time; }
        if app.requests.insert(id, r).is_some() { return Err(Error::InvalidStorage); }
    }
    for id in s.revoked_tasks {
        if !app.revoked_tasks.insert(id) { return Err(Error::InvalidStorage); }
    }
    for (id, mut d) in s.deliveries {
        if d.at.is_none() { d.at = app.last_time; }
        if app.deliveries.insert(id, d).is_some() { return Err(Error::InvalidStorage); }
    }
    for (id, baseline) in s.baselines {
        if app.baselines.insert(id, baseline).is_some() { return Err(Error::InvalidStorage); }
    }
    app.audit = s.audit.into();
    validate(&app)?;
    Ok(app)
}

fn ensure(ok: bool) -> Result<(), Error> { if ok { Ok(()) } else { Err(Error::InvalidStorage) } }

fn same_scope(task: &TaskApproval, record: &Record) -> bool {
    task.owner == record.owner && task.workspace == record.workspace
        && task.origin == record.origin && task.service == record.service
}

pub(super) fn validate(app: &Application) -> Result<(), Error> {
    ensure(app.generation > 0 && (!app.clock_frozen || app.last_time.is_some()))?;
    ensure([app.tasks.len(), app.records.len(), app.grants.len(), app.requests.len(),
        app.revoked_tasks.len(), app.deliveries.len(), app.audit.len(), app.baselines.len()].iter().all(|n| *n <= LIMIT))?;
    // Reuse authoritative task-bound validation without treating expired/revoked approvals as invalid history.
    let mut checker = Application::default();
    for (id, task) in &app.tasks {
        ensure(!id.is_nil() && *id == task.id && !task.workspace.is_empty())?;
        let admin = AuthenticatedContext::from_authenticated_admin(task.owner.clone(), "snapshot-validation".into(), task.workspace.clone());
        checker.approve_task(&admin, task.clone(), Time::MIN).map_err(|_| Error::InvalidStorage)?;
    }
    for id in &app.revoked_tasks { ensure(app.tasks.contains_key(id))?; }
    for (id, r) in &app.records {
        let t = app.tasks.get(&r.task).ok_or(Error::InvalidStorage)?;
        ensure(!id.is_nil() && *id == r.id && same_scope(t, r) && t.principal == r.created_by
            && r.revision > 0 && r.secret_version > 0 && r.secret_version <= r.revision
            && t.permissions.contains(&Permission::SecretWrite))?;
        if r.deleted { ensure(r.values.0.is_empty())?; }
        else {
            ensure(r.values.valid() && r.values.fields().is_subset(&t.fields))?;
            ensure((r.kind == CredentialKind::Login && r.values.0.contains_key(&Field::Password)
                && !r.values.0.contains_key(&Field::ApiKey))
                || (r.kind == CredentialKind::ApiKey && r.values.0.contains_key(&Field::ApiKey)
                && !r.values.0.contains_key(&Field::Password)))?;
        }
    }
    for (id, g) in &app.grants {
        let r = app.records.get(&g.record).ok_or(Error::InvalidStorage)?;
        let t = app.tasks.get(&g.issuer_task).ok_or(Error::InvalidStorage)?;
        let spec = &g.spec;
        ensure(!id.is_nil() && same_scope(t, r) && g.version > 0 && g.version <= r.secret_version
            && (!r.deleted || g.revoked) && !spec.fields.is_empty()
            && !spec.permissions.is_empty() && !spec.permissions.contains(&Permission::AccessGrant)
            && !spec.recipient.is_empty() && spec.recipient.len() <= 2048
            && spec.fields.is_subset(&t.fields) && spec.permissions.is_subset(&t.permissions)
            && spec.destinations.is_subset(&t.destinations) && spec.expires_at > Time::MIN && spec.expires_at <= t.expires_at
            && (!spec.permissions.contains(&Permission::SecretUse) || !spec.destinations.is_empty())
            && (r.deleted || spec.fields.is_subset(&r.values.fields())))?;
        if !g.admin_issued {
            let bounds = t.share.as_ref().ok_or(Error::InvalidStorage)?;
            ensure(t.principal == r.created_by && t.id == r.task
                && t.permissions.contains(&Permission::AccessGrant)
                && (!spec.follow_active || bounds.allow_follow_active)
                && bounds.recipients.contains(&spec.recipient) && spec.fields.is_subset(&bounds.fields)
                && spec.permissions.is_subset(&bounds.permissions)
                && spec.destinations.is_subset(&bounds.destinations) && spec.expires_at <= bounds.expires_at)?;
        }
    }
    let mut revisions: BTreeMap<Uuid, BTreeSet<u64>> = BTreeMap::new();
    let mut creates = BTreeSet::new();
    let mut shares = BTreeSet::new();
    let mut deletes = BTreeSet::new();
    let mut patches: BTreeMap<Uuid, BTreeSet<u64>> = BTreeMap::new();
    for (key, cached) in &app.requests {
        let t = app.tasks.get(&key.task).ok_or(Error::InvalidStorage)?;
        let r = app.records.get(&cached.result.record).ok_or(Error::InvalidStorage)?;
        let through = app.baselines.get(&r.id).map(|base| base.through).unwrap_or(0);
        ensure(!key.id.is_nil() && key.owner == t.owner && key.principal == t.principal && same_scope(t, r)
            && cached.result.revision > through && cached.result.revision <= r.revision)?;
        ensure(revisions.entry(r.id).or_default().insert(cached.result.revision))?;
        match cached.kind {
            CachedKind::Create => {
                ensure(r.task == key.task && r.created_by == key.principal && cached.result.revision == 1
                    && cached.result.grant.is_none() && creates.insert(r.id))?;
            }
            CachedKind::Share | CachedKind::Revoke => {
                let id = cached.result.grant.ok_or(Error::InvalidStorage)?;
                let g = app.grants.get(&id).ok_or(Error::InvalidStorage)?;
                ensure(g.record == r.id)?;
                if matches!(cached.kind, CachedKind::Share) {
                    ensure(g.issuer_task == key.task && shares.insert(id))?;
                } else { ensure(g.revoked)?; }
            }
            CachedKind::Delete => {
                ensure(r.deleted && cached.result.grant.is_none())?;
                deletes.insert(r.id);
            }
            CachedKind::Patch | CachedKind::MetadataPatch => {
                ensure(cached.result.grant.is_none())?;
                if matches!(cached.kind, CachedKind::Patch) {
                    patches.entry(r.id).or_default().insert(cached.result.revision);
                }
            }
            CachedKind::ReportOutcome => ensure(cached.result.grant.is_none())?,
        }
    }
    let mut accounted_grants = BTreeSet::new();
    for (id, base) in &app.baselines {
        let record = app.records.get(id).ok_or(Error::InvalidStorage)?;
        ensure(base.through <= record.revision)?;
        ensure(base.through > 0 || (base.secret_version == 0 && !base.delete_pruned && base.pruned_grants.is_empty()))?;
        ensure(base.through == 0 || base.secret_version >= 1)?;
        ensure(base.pruned_grants.windows(2).all(|pair| pair[0] < pair[1]))?;
        if base.verified_login { ensure(record.signup == SignupState::VerifiedLogin)?; }
        for gid in &base.pruned_grants {
            let grant = app.grants.get(gid).ok_or(Error::InvalidStorage)?;
            ensure(grant.record == *id && accounted_grants.insert(*gid))?;
            ensure(!app.requests.values().any(|cached| cached.kind == CachedKind::Share && cached.result.grant == Some(*gid)))?;
        }
    }
    for (id, r) in &app.records {
        let base = app.baselines.get(id);
        let through = base.map(|item| item.through).unwrap_or(0);
        let versions = revisions.get(id);
        let patch_count = patches.get(id).map_or(0, |items| items.len() as u64);
        if r.deleted {
            if through == 0 { ensure(deletes.contains(id))?; }
            else { ensure(base.is_some_and(|item| item.delete_pruned) ^ deletes.contains(id))?; }
        } else {
            ensure(!deletes.contains(id) && !base.is_some_and(|item| item.delete_pruned))?;
        }
        if through == r.revision {
            ensure(through > 0 && versions.is_none() && !creates.contains(id)
                && base.is_some_and(|item| item.secret_version == r.secret_version))?;
        } else {
            let versions = versions.ok_or(Error::InvalidStorage)?;
            let start = through + 1;
            ensure(versions.len() as u64 == r.revision - through && versions.first() == Some(&start)
                && versions.last() == Some(&r.revision) && versions.iter().copied().eq(start..=r.revision))?;
            if through == 0 {
                ensure(creates.contains(id) && r.secret_version == 1 + patch_count)?;
            } else {
                ensure(!creates.contains(id) && base.is_some_and(|item| r.secret_version == item.secret_version + patch_count))?;
            }
        }
    }
    ensure(shares.len() + accounted_grants.len() == app.grants.len() && shares.is_disjoint(&accounted_grants))?;
    let mut delivery_keys = BTreeSet::new();
    let mut registrations = BTreeSet::new();
    for (id, d) in &app.deliveries {
        let t = app.tasks.get(&d.task).ok_or(Error::InvalidStorage)?;
        let r = app.records.get(&d.record).ok_or(Error::InvalidStorage)?;
        ensure(!id.is_nil() && same_scope(t, r) && d.version > 0 && d.version <= r.secret_version
            && !d.fields.is_empty() && d.fields.is_subset(&t.fields)
            && t.permissions.contains(&Permission::SecretUse) && t.destinations.contains(&d.destination)
            && d.key.task == d.task && d.key.owner == t.owner && d.key.principal == t.principal
            && !d.key.id.is_nil() && !app.requests.contains_key(&d.key) && delivery_keys.insert(d.key.clone())
            && (d.dispatched || d.status == Some(DeliveryStatus::Rejected)))?;
        let request = PrivateUse { request: d.key.id, record: d.record, fields: d.fields.clone(),
            destination: d.destination.clone(), action: d.action };
        let bytes = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| Error::InvalidStorage)?);
        let fingerprint: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        ensure(d.fingerprint == fingerprint)?;
        if d.action != PrivateAction::Use {
            ensure(r.kind == CredentialKind::Login && d.fields.contains(&Field::Username) && d.fields.contains(&Field::Password))?;
        }
        if d.action == PrivateAction::Register && d.dispatched { ensure(registrations.insert(d.record))?; }
    }
    for r in app.records.values().filter(|r| r.signup == SignupState::VerifiedLogin) {
        let sealed = app.baselines.get(&r.id).is_some_and(|base| base.verified_login);
        ensure(sealed || app.deliveries.values().any(|d| d.record == r.id && d.version == r.secret_version
            && d.action == PrivateAction::Login && d.dispatched && d.status == Some(DeliveryStatus::Accepted)))?;
    }
    for event in &app.audit {
        let t = app.tasks.get(&event.task).ok_or(Error::InvalidStorage)?;
        let r = app.records.get(&event.record).ok_or(Error::InvalidStorage)?;
        ensure(same_scope(t, r))?;
        let legacy = event.at == 0 && event.principal.is_empty();
        if !legacy {
            ensure(event.principal == t.principal)?;
            ensure(app.last_time.is_some_and(|last| (0..=last).contains(&event.at)))?;
        }
        if let Some(request) = event.request {
            let key = RequestKey { owner: t.owner.clone(), principal: t.principal.clone(), task: t.id, id: request };
            ensure(app.requests.get(&key).is_some_and(|entry| entry.result.record == event.record))?;
        }
    }
    Ok(())
}

fn stale(at: Option<Time>, now: Option<Time>) -> bool {
    match at {
        None => false,
        Some(stored) => now.is_some_and(|now| now.saturating_sub(stored) >= RETRY_WINDOW),
    }
}

pub(super) fn should_compact(app: &Application) -> bool {
    let hot = [app.tasks.len(), app.records.len(), app.grants.len(), app.requests.len(),
        app.revoked_tasks.len(), app.deliveries.len()].into_iter().any(|len| len >= COMPACT_AT);
    let periodic = app.generation >= 32 && app.generation.is_multiple_of(32);
    hot || periodic || app.requests.values().any(|cached| stale(cached.at, app.last_time))
        || app.deliveries.values().any(|delivery| delivery.status.is_some() && stale(delivery.at, app.last_time))
}

/// Drop history that the retry window no longer needs. Deterministic, and `validate` still has to pass before publication.
pub(super) fn compact(app: &mut Application) {
    let record_ids: Vec<Uuid> = app.records.keys().copied().collect();
    for id in record_ids {
        let mut revisions: Vec<(u64, RequestKey)> = app.requests.iter()
            .filter(|(_, cached)| cached.result.record == id)
            .map(|(key, cached)| (cached.result.revision, key.clone())).collect();
        revisions.sort_by_key(|(revision, _)| *revision);
        let through = app.baselines.get(&id).map(|base| base.through).unwrap_or(0);
        let mut next_revision = through + 1;
        let mut folded = Vec::new();
        for (revision, key) in &revisions {
            if *revision <= through { continue; }
            let cached = &app.requests[key];
            if !stale(cached.at, app.last_time) || *revision != next_revision { break; }
            folded.push((key.clone(), cached.clone()));
            next_revision += 1;
        }
        if folded.is_empty() { continue; }
        for (key, _) in &folded { app.requests.remove(key); }
        let base = app.baselines.entry(id).or_default();
        for (_, cached) in folded {
            base.through = cached.result.revision;
            match cached.kind {
                CachedKind::Create => base.secret_version = 1,
                CachedKind::Patch => base.secret_version = base.secret_version.saturating_add(1),
                CachedKind::Delete => base.delete_pruned = true,
                CachedKind::Share => {
                    if let Some(grant) = cached.result.grant {
                        if !base.pruned_grants.contains(&grant) { base.pruned_grants.push(grant); }
                    }
                }
                CachedKind::MetadataPatch | CachedKind::Revoke | CachedKind::ReportOutcome => {}
            }
        }
        base.pruned_grants.sort();
    }
    let grant_ids: Vec<Uuid> = app.grants.keys().copied().collect();
    for gid in grant_ids {
        let Some(grant) = app.grants.get(&gid) else { continue };
        let expired = app.last_time.is_some_and(|now| grant.spec.expires_at <= now);
        let record = grant.record;
        if !grant.revoked && !expired { continue; }
        if app.requests.values().any(|cached| cached.result.grant == Some(gid)) { continue; }
        app.grants.remove(&gid);
        if let Some(base) = app.baselines.get_mut(&record) { base.pruned_grants.retain(|id| *id != gid); }
    }
    let delivery_ids: Vec<Uuid> = app.deliveries.keys().copied().collect();
    for id in delivery_ids {
        let Some(delivery) = app.deliveries.get(&id).cloned() else { continue };
        if delivery.status.is_none() || !stale(delivery.at, app.last_time) { continue; }
        let seal_register = delivery.action == PrivateAction::Register && delivery.dispatched
            && app.records.contains_key(&delivery.record);
        let seal_login = app.records.get(&delivery.record).is_some_and(|record|
            delivery.action == PrivateAction::Login && delivery.dispatched
                && delivery.status == Some(DeliveryStatus::Accepted)
                && record.signup == SignupState::VerifiedLogin && delivery.version == record.secret_version);
        if seal_register || seal_login {
            let base = app.baselines.entry(delivery.record).or_default();
            if seal_register { base.registration_dispatched = true; }
            if seal_login { base.verified_login = true; }
        }
        app.deliveries.remove(&id);
    }
    let dropped_records: Vec<Uuid> = app.records.iter().filter(|(id, record)| record.deleted
        && app.grants.values().all(|grant| grant.record != **id)
        && app.deliveries.values().all(|delivery| delivery.record != **id)
        && app.requests.values().all(|cached| cached.result.record != **id)).map(|(id, _)| *id).collect();
    for id in dropped_records {
        app.records.remove(&id);
        app.baselines.remove(&id);
    }
    let referenced = |id: Uuid| app.records.values().any(|record| record.task == id)
        || app.grants.values().any(|grant| grant.issuer_task == id)
        || app.deliveries.values().any(|delivery| delivery.task == id || delivery.key.task == id)
        || app.requests.keys().any(|key| key.task == id);
    let mut remove_tasks: Vec<Uuid> = app.tasks.iter().filter(|(id, task)| !referenced(**id)
        && (app.revoked_tasks.contains(id) || app.last_time.is_some_and(|now| task.expires_at <= now)))
        .map(|(id, _)| *id).collect();
    if !app.tasks.is_empty() && remove_tasks.len() == app.tasks.len() {
        if let Some(keep) = app.tasks.values().max_by_key(|task| (task.expires_at, task.id)).map(|task| task.id) {
            remove_tasks.retain(|id| *id != keep);
        }
    }
    for id in remove_tasks {
        app.tasks.remove(&id);
        app.revoked_tasks.remove(&id);
    }
    app.revoked_tasks.retain(|id| app.tasks.contains_key(id));
    app.audit.retain(|event| {
        let Some(task) = app.tasks.get(&event.task) else { return false };
        if !app.records.contains_key(&event.record) { return false; }
        match event.request {
            None => true,
            Some(request) => {
                let key = RequestKey { owner: task.owner.clone(), principal: task.principal.clone(), task: task.id, id: request };
                app.requests.get(&key).is_some_and(|entry| entry.result.record == event.record)
            }
        }
    });
    for (id, base) in &mut app.baselines {
        if app.records.get(id).is_some_and(|record| record.signup != SignupState::VerifiedLogin) {
            base.verified_login = false;
        }
        base.pruned_grants.sort();
        base.pruned_grants.dedup();
    }
    app.baselines.retain(|id, base| app.records.contains_key(id) && (base.through > 0 || base.delete_pruned
        || base.registration_dispatched || base.verified_login || !base.pruned_grants.is_empty()));
}

pub(super) fn clock_only_difference(current: &Application, candidate: &Application) -> Result<bool, Error> {
    // Encode through zeroizing buffers; do not materialize secrets in a serde_json::Value.
    let mut left = current.clone();
    let mut right = candidate.clone();
    let high = left.last_time.max(right.last_time);
    left.last_time = high;
    right.last_time = high;
    left.generation = 1;
    right.generation = 1;
    Ok(*encode(&left)? == *encode(&right)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::setup;

    fn fixture() -> Application { let (mut app, _, _, _) = setup(); app.generation = 1; app }

    #[test]
    fn private_snapshot_roundtrip_and_schema_guard() {
        let app = fixture();
        let bytes = encode(&app).unwrap();
        let restored = decode(&bytes).unwrap();
        assert_eq!(restored.records.len(), app.records.len());
        assert_eq!(restored.requests.len(), app.requests.len());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["schema"] = 99.into();
        assert!(matches!(decode(&serde_json::to_vec(&value).unwrap()), Err(Error::InvalidStorage)));
    }

    #[test]
    fn unknown_record_fields_and_missing_restore_guard_fail_closed() {
        let bytes = encode(&fixture()).unwrap();
        for damage in 0..5 {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let record = value["records"][0].as_object_mut().unwrap();
            match damage {
                0 => { record.insert("extra_object".into(), serde_json::json!({"value": null})); }
                1 => { record.insert("extra_array".into(), serde_json::json!(["synthetic"])); }
                2 => { record.insert("extra_text".into(), "synthetic".into()); }
                3 => { record.remove("restored"); }
                _ => { record.insert("restored".into(), "false".into()); }
            }
            assert!(matches!(decode(&serde_json::to_vec(&value).unwrap()), Err(Error::InvalidStorage)));
        }
    }

    #[test]
    fn duplicate_ids_bad_scope_and_cache_correspondence_are_rejected() {
        let bytes = encode(&fixture()).unwrap();
        for damage in 0..4 {
            let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            match damage {
                0 => { let r = v["records"][0].clone(); v["records"].as_array_mut().unwrap().push(r); }
                1 => v["records"][0]["owner"] = "another-user".into(),
                2 => v["requests"][0][1]["result"]["revision"] = 999.into(),
                _ => { v["requests"] = serde_json::json!([]); }
            }
            assert!(matches!(decode(&serde_json::to_vec(&v).unwrap()), Err(Error::InvalidStorage)));
        }
    }

    #[test]
    fn legacy_audit_events_decode_and_inconsistent_new_fields_fail() {
        let bytes = encode(&fixture()).unwrap();
        let mut legacy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for event in legacy["audit"].as_array_mut().unwrap() {
            let event = event.as_object_mut().unwrap();
            event.remove("at");
            event.remove("principal");
        }
        let restored = decode(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(restored.audit.iter().all(|event| event.at == 0 && event.principal.is_empty()));
        for (field, value) in [("principal", serde_json::Value::from("other")), ("at", serde_json::json!(1_000_000))] {
            let mut damaged: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            damaged["audit"][0][field] = value;
            assert!(matches!(decode(&serde_json::to_vec(&damaged).unwrap()), Err(Error::InvalidStorage)));
        }
    }

    #[test]
    fn schema_2_without_baselines_or_timestamps_decodes() {
        let bytes = encode(&fixture()).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["schema"] = 2.into();
        value.as_object_mut().unwrap().remove("baselines");
        value.as_object_mut().unwrap().remove("predecessor");
        for request in value["requests"].as_array_mut().unwrap() {
            request[1].as_object_mut().unwrap().remove("at");
        }
        let legacy = serde_json::to_vec(&value).unwrap();
        let app = decode(&legacy).unwrap();
        assert!(app.requests.values().all(|cached| cached.at == app.last_time));
        let mut retained = app.clone();
        compact(&mut retained);
        assert_eq!(retained.requests.len(), app.requests.len());
        retained.last_time = retained.last_time.map(|now| now + RETRY_WINDOW);
        compact(&mut retained);
        assert!(retained.requests.is_empty());
        assert!(app.baselines.is_empty());
        let again = decode(&encode(&app).unwrap()).unwrap();
        assert_eq!(again.records.len(), app.records.len());
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&encode(&again).unwrap()).unwrap()["schema"], 3);
    }

    #[test]
    fn compaction_accounts_for_metadata_patches_without_rotating_values() {
        use super::super::tests::{agent, input};
        let (mut app, ta, _, receipt) = super::super::tests::setup();
        app.generation = 1;
        app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Patch {
            record: receipt.record, expected: 1, values: input(&[(Field::Label, "new-label")]),
        }, 3).unwrap();
        for cached in app.requests.values_mut() { cached.at = Some(3 - RETRY_WINDOW); }
        compact(&mut app);
        assert_eq!(app.baselines[&receipt.record].through, 2);
        assert_eq!(app.baselines[&receipt.record].secret_version, 1);
        assert_eq!(app.records[&receipt.record].secret_version, 1);
        validate(&app).unwrap();
        assert!(decode(&encode(&app).unwrap()).is_ok());
    }

    #[test]
    fn compaction_collapses_aged_history_and_replays_do_not_bypass_authorization() {
        use super::super::tests::{admin, agent, input};
        let (mut app, ta, _, receipt) = super::super::tests::setup();
        app.generation = 1;
        let request = Uuid::new_v4();
        let create = Mutation::Create { kind: CredentialKind::Login, values: input(&[(Field::Username, "aged-user"), (Field::Password, "aged-secret")]) };
        let first = app.mutate(&agent("a"), ta, request, create.clone(), 2).unwrap();
        assert_eq!(app.mutate(&agent("a"), ta, request, create.clone(), 3).unwrap(), first);
        let mut expected = receipt.revision;
        for _ in 0..9_000 {
            expected = app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::ReportOutcome {
                record: receipt.record, expected, state: SignupState::Pending,
            }, 3).unwrap().revision;
        }
        assert!(app.requests.len() >= COMPACT_AT && should_compact(&app));
        for cached in app.requests.values_mut() { cached.at = Some(3 - RETRY_WINDOW); }
        compact(&mut app);
        validate(&app).unwrap();
        assert!(app.requests.len() < 100);
        assert!(app.baselines.get(&receipt.record).is_some_and(|base| base.through == expected));
        let continued = app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::ReportOutcome {
            record: receipt.record, expected, state: SignupState::Pending,
        }, 4).unwrap();
        validate(&app).unwrap();
        let restored = decode(&encode(&app).unwrap()).unwrap();
        assert_eq!(restored.records[&receipt.record].revision, continued.revision);
        assert_eq!(restored.baselines[&receipt.record].through, expected);
        app.revoke_task(&admin(), ta, 4).unwrap();
        let records = app.records.len();
        assert_eq!(app.mutate(&agent("a"), ta, request, create, 4).unwrap_err(), Error::Denied);
        assert_eq!(app.records.len(), records);
        let mut deleted = setup_deleted();
        for cached in deleted.requests.values_mut() { cached.at = Some(2 - RETRY_WINDOW); }
        compact(&mut deleted);
        validate(&deleted).unwrap();
        assert!(deleted.records.is_empty());
    }

    fn setup_deleted() -> Application {
        use super::super::tests::agent;
        let (mut app, ta, _, receipt) = super::super::tests::setup();
        app.generation = 1;
        app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Delete {
            record: receipt.record, expected: receipt.revision,
        }, 2).unwrap();
        app
    }
}
