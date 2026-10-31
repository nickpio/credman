//! Private encrypted-payload codec. Never an agent response or plaintext export surface.
use super::*;

pub(super) const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;
const LIMIT: usize = 10_000;

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
}

pub(super) fn encode(app: &Application) -> Result<Zeroizing<Vec<u8>>, Error> {
    validate(app)?;
    let snapshot = Snapshot {
        schema: 2, generation: app.generation,
        tasks: app.tasks.values().cloned().collect(), records: app.records.values().cloned().collect(),
        grants: app.grants.iter().map(|(k, v)| (*k, v.clone())).collect(),
        requests: app.requests.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        revoked_tasks: app.revoked_tasks.iter().copied().collect(),
        deliveries: app.deliveries.iter().map(|(k, v)| (*k, v.clone())).collect(),
        audit: app.audit.iter().cloned().collect(), last_time: app.last_time, clock_frozen: app.clock_frozen,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&snapshot).map_err(|_| Error::InvalidStorage)?);
    if bytes.len() > MAX_PLAINTEXT { return Err(Error::Capacity); }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Application, Error> {
    if bytes.len() > MAX_PLAINTEXT { return Err(Error::InvalidStorage); }
    let s: Snapshot = serde_json::from_slice(bytes).map_err(|_| Error::InvalidStorage)?;
    if s.schema != 2 || s.generation == 0 || [s.tasks.len(), s.records.len(), s.grants.len(),
        s.requests.len(), s.revoked_tasks.len(), s.deliveries.len(), s.audit.len()].iter().any(|n| *n > LIMIT)
    { return Err(Error::InvalidStorage); }
    let mut app = Application { generation: s.generation, last_time: s.last_time,
        clock_frozen: s.clock_frozen, ..Application::default() };
    for t in s.tasks {
        if app.tasks.insert(t.id, t).is_some() { return Err(Error::InvalidStorage); }
    }
    for r in s.records {
        if app.records.insert(r.id, r).is_some() { return Err(Error::InvalidStorage); }
    }
    for (id, g) in s.grants {
        if app.grants.insert(id, g).is_some() { return Err(Error::InvalidStorage); }
    }
    for (id, r) in s.requests {
        if app.requests.insert(id, r).is_some() { return Err(Error::InvalidStorage); }
    }
    for id in s.revoked_tasks {
        if !app.revoked_tasks.insert(id) { return Err(Error::InvalidStorage); }
    }
    for (id, d) in s.deliveries {
        if app.deliveries.insert(id, d).is_some() { return Err(Error::InvalidStorage); }
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
        app.revoked_tasks.len(), app.deliveries.len(), app.audit.len()].iter().all(|n| *n <= LIMIT))?;
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
        ensure(!key.id.is_nil() && key.owner == t.owner && key.principal == t.principal && same_scope(t, r)
            && cached.result.revision > 0 && cached.result.revision <= r.revision)?;
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
    for (id, r) in &app.records {
        let versions = revisions.get(id).ok_or(Error::InvalidStorage)?;
        // Every revision has exactly one corresponding successful request result.
        ensure(creates.contains(id) && (!r.deleted || deletes.contains(id))
            && versions.len() as u64 == r.revision && versions.first() == Some(&1)
            && versions.last() == Some(&r.revision)
            && r.secret_version == 1 + patches.get(id).map_or(0, |p| p.len() as u64))?;
    }
    ensure(shares.len() == app.grants.len())?;
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
        ensure(app.deliveries.values().any(|d| d.record == r.id && d.version == r.secret_version
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
}
