//! Explicit trusted-human reconciliation. Neither seed possession nor an agent request grants this authority.
use super::*;

fn read_gate(dir: &File, name: &str) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let file = open_file(dir, name, libc::O_RDONLY).map_err(|_| Error::RecoveryRequired)?;
    let limit = MAX_IMAGE.checked_mul(2).and_then(|n| n.checked_add(24)).ok_or(Error::RecoveryRequired)?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes).map_err(|_| Error::RecoveryRequired)?;
    if bytes.len() < 24 || bytes.len() > limit || &bytes[..8] != INTENT_MAGIC { return Err(Error::RecoveryRequired); }
    let old_len = usize::try_from(u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| Error::RecoveryRequired)?)).map_err(|_| Error::RecoveryRequired)?;
    let new_len = usize::try_from(u64::from_be_bytes(bytes[16..24].try_into().map_err(|_| Error::RecoveryRequired)?)).map_err(|_| Error::RecoveryRequired)?;
    if old_len > MAX_IMAGE || new_len > MAX_IMAGE || new_len == 0
        || old_len.checked_add(new_len).and_then(|n| n.checked_add(24)) != Some(bytes.len())
    { return Err(Error::RecoveryRequired); }
    Ok((bytes[24..24 + old_len].to_vec(), bytes[24 + old_len..].to_vec()))
}

fn equal<T: Serialize>(a: &T, b: &T) -> Result<bool, Error> {
    let left = Zeroizing::new(serde_json::to_vec(a).map_err(|_| Error::RecoveryRequired)?);
    let right = Zeroizing::new(serde_json::to_vec(b).map_err(|_| Error::RecoveryRequired)?);
    Ok(*left == *right)
}

fn transition(old: &Application, next: &Application) -> Result<(), Error> {
    if old.generation.checked_add(1) != Some(next.generation) || !old.revoked_tasks.is_subset(&next.revoked_tasks) {
        return Err(Error::RecoveryRequired);
    }
    for (id, t) in &old.tasks {
        if !equal(t, next.tasks.get(id).ok_or(Error::RecoveryRequired)?)? { return Err(Error::RecoveryRequired); }
    }
    for (id, r) in &old.records {
        let n = next.records.get(id).ok_or(Error::RecoveryRequired)?;
        if r.owner != n.owner || r.workspace != n.workspace || r.created_by != n.created_by || r.task != n.task
            || r.service != n.service || r.origin != n.origin || r.kind != n.kind || r.revision > n.revision
            || r.secret_version > n.secret_version || (r.deleted && !n.deleted)
            || r.restored != n.restored
        { return Err(Error::RecoveryRequired); }
    }
    for (id, g) in &old.grants {
        let n = next.grants.get(id).ok_or(Error::RecoveryRequired)?;
        if g.record != n.record || g.version != n.version || g.issuer_task != n.issuer_task || g.admin_issued != n.admin_issued
            || (g.revoked && !n.revoked) || !equal(&g.spec, &n.spec)? { return Err(Error::RecoveryRequired); }
    }
    for (key, cached) in &old.requests {
        if !equal(cached, next.requests.get(key).ok_or(Error::RecoveryRequired)?)? { return Err(Error::RecoveryRequired); }
    }
    for (id, d) in &old.deliveries {
        let n = next.deliveries.get(id).ok_or(Error::RecoveryRequired)?;
        let mut expected = d.clone();
        if d.status.is_none() { expected.status = n.status; expected.dispatched = n.dispatched; }
        if !equal(&expected, n)? { return Err(Error::RecoveryRequired); }
    }
    Ok(())
}

fn sanitize(app: &mut Application, now: Time) -> Result<(), Error> {
    app.generation = app.generation.checked_add(1).ok_or(Error::RecoveryRequired)?;
    app.revoked_tasks.extend(app.tasks.keys().copied());
    for grant in app.grants.values_mut() { grant.revoked = true; }
    for d in app.deliveries.values_mut().filter(|d| d.status.is_none()) {
        d.status = Some(DeliveryStatus::Unknown);
        if d.action != PrivateAction::Use {
            app.records.get_mut(&d.record).ok_or(Error::RecoveryRequired)?.signup = SignupState::Unknown;
        }
    }
    app.clock_frozen = false;
    app.last_time = Some(now);
    snapshot::validate(app).map_err(|_| Error::RecoveryRequired)
}

fn scope(app: &Application, ctx: &AuthenticatedContext) -> Result<(), Error> {
    if !ctx.admin || app.tasks.values().any(|t| t.owner != ctx.owner || t.workspace != ctx.workspace)
        || app.records.values().any(|r| r.owner != ctx.owner || r.workspace != ctx.workspace)
    { Err(Error::Denied) } else { Ok(()) }
}

fn empty_initial(app: &Application) -> bool {
    app.generation == 1 && app.tasks.is_empty() && app.records.is_empty() && app.grants.is_empty()
        && app.requests.is_empty() && app.revoked_tasks.is_empty() && app.deliveries.is_empty()
        && app.audit.is_empty() && app.last_time.is_none() && !app.clock_frozen
}

fn safe_initial_publication(app: &Application) -> bool {
    empty_initial(app) || (app.records.values().all(|record| record.restored)
        && app.tasks.keys().all(|id| app.revoked_tasks.contains(id))
        && app.grants.values().all(|grant| grant.revoked)
        && app.deliveries.values().all(|attempt| attempt.status.is_some()))
}

fn absent_initial_image(dir: &File, mnemonic: &str) -> Result<Vec<u8>, Error> {
    let (previous, candidate) = read_gate(dir, PENDING)?;
    if !previous.is_empty() { return Err(Error::RecoveryRequired); }
    let (app, _, _, _) = unseal(&candidate, mnemonic).map_err(|_| Error::RecoveryRequired)?;
    if !safe_initial_publication(&app) { return Err(Error::RecoveryRequired); }
    Ok(candidate)
}

fn validate_pending(dir: &File, mnemonic: &str, visible: &[u8]) -> Result<(), Error> {
    let (old, next) = read_gate(dir, PENDING)?;
    let (candidate, _, salt, kdf) = unseal(&next, mnemonic).map_err(|_| Error::RecoveryRequired)?;
    if old.is_empty() {
        if !safe_initial_publication(&candidate) { return Err(Error::RecoveryRequired); }
    } else {
        let (previous, _, old_salt, old_kdf) = unseal(&old, mnemonic).map_err(|_| Error::RecoveryRequired)?;
        if salt != old_salt || kdf != old_kdf { return Err(Error::RecoveryRequired); }
        transition(&previous, &candidate)?;
    }
    if visible != next && visible != old { return Err(Error::RecoveryRequired); }
    Ok(())
}

fn write_pair(dir: &File, target: &str, old: &[u8], next: &[u8]) -> Result<(), Error> {
    let temp = format!("recovery-plan-{}.v2", Uuid::new_v4());
    let mut file = open_file(dir, &temp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).map_err(|_| Error::RecoveryRequired)?;
    file.write_all(INTENT_MAGIC).and_then(|()| file.write_all(&(old.len() as u64).to_be_bytes()))
        .and_then(|()| file.write_all(&(next.len() as u64).to_be_bytes()))
        .and_then(|()| file.write_all(old)).and_then(|()| file.write_all(next))
        .and_then(|()| file.sync_all()).map_err(|_| Error::RecoveryRequired)?;
    rename(dir, &temp, target, true).map_err(|_| Error::RecoveryRequired)?;
    dir.sync_all().map_err(|_| Error::RecoveryRequired)
}

impl DurableVault {
    /// Trusted human integration only. Scope and seed are checked independently. Never dispatches externally.
    pub(crate) fn recover(path: &Path, mnemonic: &str, admin: &AuthenticatedContext,
        clock: &mut impl FnMut() -> Time) -> Result<Self, Error> {
        recover_at(path, mnemonic, admin, clock, None)
    }
}

pub(super) fn recover_at(path: &Path, mnemonic: &str, admin: &AuthenticatedContext,
    clock: &mut impl FnMut() -> Time, fault: Option<FaultPoint>) -> Result<DurableVault, Error> {
    if !admin.admin { return Err(Error::Denied); }
    let (dir, lock) = Store::acquire_recovery(path)?;
    let on_disk = read_image(&dir, STATE)?;
    let missing_state = on_disk.is_none();
    // Initial copies must already carry revoked authority and registration-blocked records.
    let visible = match on_disk { Some(image) => image, None => absent_initial_image(&dir, mnemonic)? };
    let (mut app, key, salt, kdf) = unseal(&visible, mnemonic).map_err(|_| Error::RecoveryRequired)?;
    scope(&app, admin)?;
    let plan_exists = gate_exists(&dir, RECOVERY)?;
    let has_pending = gate_exists(&dir, PENDING)?;
    let image;
    if plan_exists {
        let (base, planned) = read_gate(&dir, RECOVERY)?;
        let (previous, _, base_salt, base_kdf) = unseal(&base, mnemonic).map_err(|_| Error::RecoveryRequired)?;
        let (target, _, target_salt, target_kdf) = unseal(&planned, mnemonic).map_err(|_| Error::RecoveryRequired)?;
        scope(&previous, admin)?; scope(&target, admin)?;
        if salt != base_salt || salt != target_salt || kdf != base_kdf || kdf != target_kdf
            || (visible != base && visible != planned) { return Err(Error::RecoveryRequired); }
        let mut expected = previous;
        sanitize(&mut expected, target.last_time.ok_or(Error::RecoveryRequired)?)?;
        if !equal(&*snapshot::encode(&expected)?, &*snapshot::encode(&target)?)? { return Err(Error::RecoveryRequired); }
        if has_pending { validate_pending(&dir, mnemonic, &base)?; }
        app = target;
        image = planned;
    } else {
        if !has_pending && !app.clock_frozen && !app.deliveries.values().any(|d| d.status.is_none()) {
            return Err(Error::Invalid);
        }
        if has_pending { validate_pending(&dir, mnemonic, &visible)?; }
        sanitize(&mut app, clock())?;
        image = seal(&app, &key, &salt, kdf)?;
        // Publish the recovery gate durably before replacing state or clearing the original gate.
        write_pair(&dir, RECOVERY, &visible, &image)?;
    }
    let temp = format!("recovered-{}.v2", Uuid::new_v4());
    let mut file = open_file(&dir, &temp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).map_err(|_| Error::RecoveryRequired)?;
    file.write_all(&image).and_then(|()| file.sync_all()).map_err(|_| Error::RecoveryRequired)?;
    if fault == Some(FaultPoint::RecoveryBeforeRename) { return Err(Error::RecoveryRequired); }
    rename(&dir, &temp, STATE, missing_state).map_err(|_| Error::RecoveryRequired)?;
    if fault == Some(FaultPoint::RecoveryAfterRename) { return Err(Error::RecoveryRequired); }
    dir.sync_all().map_err(|_| Error::RecoveryRequired)?;
    if has_pending { unlink(&dir, PENDING).map_err(|_| Error::RecoveryRequired)?; dir.sync_all().map_err(|_| Error::RecoveryRequired)?; }
    unlink(&dir, RECOVERY).map_err(|_| Error::RecoveryRequired)?;
    dir.sync_all().map_err(|_| Error::RecoveryRequired)?;
    Ok(DurableVault { app, frozen: false, store: Store { dir, _lock: lock, key, salt, kdf,
        current_image: Some(image), blocked: false, #[cfg(test)] fault: None } })
}
