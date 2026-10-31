//! Explicit trusted-human reconciliation. Neither seed possession nor an agent request grants this authority.
use super::*;
use sha2::{Digest, Sha256};

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

fn referenced_task(app: &Application, id: Uuid) -> bool {
    app.records.values().any(|record| record.task == id)
        || app.grants.values().any(|grant| grant.issuer_task == id)
        || app.deliveries.values().any(|delivery| delivery.task == id || delivery.key.task == id)
        || app.requests.keys().any(|key| key.task == id)
}

fn transition(old: &Application, next: &Application) -> Result<(), Error> {
    if old.generation.checked_add(1) != Some(next.generation) || (old.tasks.is_empty() != next.tasks.is_empty() && next.tasks.is_empty()) {
        return Err(Error::RecoveryRequired);
    }
    for id in &old.revoked_tasks {
        if next.tasks.contains_key(id) && !next.revoked_tasks.contains(id) { return Err(Error::RecoveryRequired); }
    }
    for (id, task) in &old.tasks {
        if let Some(retained) = next.tasks.get(id) {
            if !equal(task, retained)? { return Err(Error::RecoveryRequired); }
        } else {
            let expired = next.last_time.or(old.last_time).is_some_and(|now| task.expires_at <= now);
            if (!expired && !old.revoked_tasks.contains(id)) || referenced_task(next, *id) {
                return Err(Error::RecoveryRequired);
            }
        }
    }
    for (id, r) in &old.records {
        if let Some(n) = next.records.get(id) {
            if r.owner != n.owner || r.workspace != n.workspace || r.created_by != n.created_by || r.task != n.task
                || r.service != n.service || r.origin != n.origin || r.kind != n.kind || r.revision > n.revision
                || r.secret_version > n.secret_version || (r.deleted && !n.deleted)
                || r.restored != n.restored
                || (r.revision == n.revision && (r.secret_version != n.secret_version || r.deleted != n.deleted
                    || !equal(&r.values, &n.values)?))
            { return Err(Error::RecoveryRequired); }
        } else if !r.deleted || next.grants.values().any(|grant| grant.record == *id)
            || next.deliveries.values().any(|delivery| delivery.record == *id)
            || next.requests.values().any(|cached| cached.result.record == *id)
        { return Err(Error::RecoveryRequired); }
    }
    for (id, g) in &old.grants {
        if let Some(n) = next.grants.get(id) {
            if g.record != n.record || g.version != n.version || g.issuer_task != n.issuer_task || g.admin_issued != n.admin_issued
                || (g.revoked && !n.revoked) || !equal(&g.spec, &n.spec)? { return Err(Error::RecoveryRequired); }
        } else {
            let expired = next.last_time.or(old.last_time).is_some_and(|now| g.spec.expires_at <= now);
            if (!g.revoked && !expired) || next.requests.values().any(|cached| cached.result.grant == Some(*id)) {
                return Err(Error::RecoveryRequired);
            }
        }
    }
    for (key, cached) in &old.requests {
        if let Some(retained) = next.requests.get(key) {
            if !equal(cached, retained)? { return Err(Error::RecoveryRequired); }
        } else {
            let through = next.baselines.get(&cached.result.record).map(|base| base.through).unwrap_or(0);
            let old_revision = old.records.get(&cached.result.record).map(|record| record.revision).unwrap_or(0);
            let covered = cached.result.revision <= through && through <= old_revision;
            let record_removed = !next.records.contains_key(&cached.result.record)
                && old.records.get(&cached.result.record).is_some_and(|record| record.deleted);
            if !covered && !record_removed { return Err(Error::RecoveryRequired); }
        }
    }
    for (id, d) in &old.deliveries {
        if let Some(n) = next.deliveries.get(id) {
            let mut expected = d.clone();
            if d.status.is_none() { expected.status = n.status; expected.dispatched = n.dispatched; }
            if !equal(&expected, n)? { return Err(Error::RecoveryRequired); }
        } else if d.status.is_none()
            || d.action == PrivateAction::Register && d.dispatched && next.records.contains_key(&d.record)
                && !next.baselines.get(&d.record).is_some_and(|base| base.registration_dispatched)
        {
            return Err(Error::RecoveryRequired);
        } else if d.action == PrivateAction::Login && d.dispatched && d.status == Some(DeliveryStatus::Accepted) {
            if let Some(record) = next.records.get(&d.record) {
                let still = record.signup == SignupState::VerifiedLogin && record.secret_version == d.version;
                let sealed = next.baselines.get(&d.record).is_some_and(|base| base.verified_login);
                let retained = next.deliveries.values().any(|delivery| delivery.record == d.record
                    && delivery.action == PrivateAction::Login && delivery.dispatched
                    && delivery.status == Some(DeliveryStatus::Accepted) && delivery.version == record.secret_version);
                if still && !sealed && !retained { return Err(Error::RecoveryRequired); }
            }
        }
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
    app.predecessor = None;
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
        match unseal(&old, mnemonic) {
            Ok((previous, _, old_salt, old_kdf)) => {
                if salt != old_salt || kdf != old_kdf {
                    let hash: [u8; 32] = Sha256::digest(&old).into();
                    if candidate.predecessor != Some(hash) { return Err(Error::RecoveryRequired); }
                }
                transition(&previous, &candidate)?;
            }
            // The previous image is bound by the hash inside the new seed's ciphertext.
            Err(_) => {
                let hash: [u8; 32] = Sha256::digest(&old).into();
                if candidate.predecessor != Some(hash) { return Err(Error::RecoveryRequired); }
            }
        }
    }
    if visible != next.as_slice() && visible != old.as_slice() { return Err(Error::RecoveryRequired); }
    Ok(())
}

/// Install a re-keyed image when the visible file still decrypts only with the previous seed.
fn adopt_rekeyed(dir: &File, mnemonic: &str, admin: &AuthenticatedContext, visible: &[u8]) -> Result<(), Error> {
    if !gate_exists(dir, PENDING)? { return Err(Error::RecoveryRequired); }
    let (old, next) = read_gate(dir, PENDING)?;
    if visible != old.as_slice() && visible != next.as_slice() { return Err(Error::RecoveryRequired); }
    let (app, _, _, _) = unseal(&next, mnemonic).map_err(|_| Error::RecoveryRequired)?;
    scope(&app, admin)?;
    let hash: [u8; 32] = Sha256::digest(&old).into();
    if app.predecessor != Some(hash) { return Err(Error::RecoveryRequired); }
    if visible == next.as_slice() { return Ok(()); }
    let temp = format!("rekey-adopt-{}.v2", Uuid::new_v4());
    let mut file = open_file(dir, &temp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).map_err(|_| Error::RecoveryRequired)?;
    file.write_all(&next).and_then(|()| file.sync_all()).map_err(|_| Error::RecoveryRequired)?;
    rename(dir, &temp, STATE, false).map_err(|_| Error::RecoveryRequired)?;
    dir.sync_all().map_err(|_| Error::RecoveryRequired)
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
    let mut on_disk = read_image(&dir, STATE)?;
    if let Some(image) = on_disk.as_ref() {
        if unseal(image, mnemonic).is_err() {
            adopt_rekeyed(&dir, mnemonic, admin, image)?;
            on_disk = read_image(&dir, STATE)?;
        }
    }
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
    let persisted_last_time = app.last_time;
    let persisted_frozen = app.clock_frozen;
    Ok(DurableVault { app, frozen: false, store: Store { dir, _lock: lock, key, salt, kdf,
        current_image: Some(image), blocked: false, persisted_last_time, persisted_frozen,
        #[cfg(test)] fault: None } })
}
