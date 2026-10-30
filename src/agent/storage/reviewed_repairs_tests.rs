use super::*;
use super::tests::fixture;
use super::tests::destination;
use super::workflow_tests::request;
use super::super::tests::{admin, agent, approval, input};
use std::cell::Cell;
use tempfile::TempDir;
use std::fs;

fn initial_evidence() -> (TempDir, String) {
    let dir = destination();
    let seed = crypto::generate_mnemonic().unwrap();
    let (directory, lock) = Store::acquire(dir.path()).unwrap();
    let salt = crypto::random_salt(); let kdf = KdfParams::current();
    let key = crypto::derive_key(&seed, &salt, &kdf).unwrap();
    let mut store = Store { dir: directory, _lock: lock, key, salt, kdf, current_image: None,
        blocked: false, fault: Some(FaultPoint::AfterIntent) };
    let empty = Application { generation: 1, ..Application::default() };
    assert_eq!(store.publish(&empty), Publication::Unknown);
    assert!(!dir.path().join(STATE).exists() && dir.path().join(PENDING).exists());
    drop(store);
    (dir, seed)
}

#[test]
fn registration_guard_survives_metadata_and_secret_patches_after_restart() {
    for (status, field) in [(DeliveryStatus::Unknown, Field::Notes), (DeliveryStatus::Accepted, Field::Password)] {
        let mut f = fixture();
        let calls = Cell::new(0);
        let first = f.owner.use_secret(&agent("a"), f.ta, request(f.receipt.record, PrivateAction::Register), &mut || 3, |_| {
            calls.set(calls.get() + 1);
            if status == DeliveryStatus::Unknown { Err(Error::InteractionRequired) } else { Ok(status) }
        });
        assert!(first.is_ok() || matches!(first, Err(Error::InteractionRequired)));
        let value = f.owner.app.records[&f.receipt.record].values.0.get(&field)
            .map(|value| value.to_string()).unwrap_or_else(|| "synthetic metadata patch".into());
        f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Patch { record: f.receipt.record,
            expected: 1, values: SecretInput::new([(field, value)].into_iter().collect()) }, 4).unwrap();
        drop(f.owner);
        let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
        let result = owner.use_secret(&agent("a"), f.ta, request(f.receipt.record, PrivateAction::Register), &mut || 5, |_| {
            calls.set(calls.get() + 1); Ok(DeliveryStatus::Accepted)
        });
        assert_eq!(result.unwrap_err(), Error::Conflict, "ordinary patch must retain record-level registration guard");
        assert_eq!(calls.get(), 1);
        owner.use_secret(&agent("a"), f.ta, request(f.receipt.record, PrivateAction::Login), &mut || 5,
            |_| Ok(DeliveryStatus::Accepted)).unwrap();
    }
}

#[test]
fn validated_missing_initial_state_is_recoverable_only_by_explicit_human() {
    let (dir, seed) = initial_evidence();
    assert!(matches!(DurableVault::open(dir.path(), &seed), Err(Error::RecoveryRequired)));
    assert!(matches!(DurableVault::create(dir.path(), &seed), Err(Error::RecoveryRequired)));
    assert!(matches!(DurableVault::recover(dir.path(), &seed, &agent("a"), &mut || 2), Err(Error::Denied)));
    let owner = DurableVault::recover(dir.path(), &seed, &admin(), &mut || 2).expect("validated empty creation must recover");
    assert!(owner.app.records.is_empty() && owner.app.tasks.is_empty());
    drop(owner);
    assert!(DurableVault::open(dir.path(), &seed).is_ok());
}

#[test]
fn retained_scope_rejects_different_workspace_or_owner_admission() {
    for (owner, workspace) in [("user", "another-project"), ("another-user", "project")] {
        let mut f = fixture();
        let mut other = approval("other"); other.owner = owner.into(); other.workspace = workspace.into();
        let other_admin = AuthenticatedContext::from_authenticated_admin(owner.into(), "human".into(), workspace.into());
        let count = f.owner.app.tasks.len();
        assert_eq!(f.owner.approve_task(&other_admin, other.clone(), 3).unwrap_err(), Error::Denied);
        assert_eq!(f.owner.app.tasks.len(), count);
        f.owner.app.tasks.insert(other.id, other);
        assert!(matches!(snapshot::encode(&f.owner.app), Err(Error::InvalidStorage)));
    }
}

#[test]
fn initial_recovery_interruption_before_or_after_rename_resumes_without_clearing_gate_early() {
    for fault in [FaultPoint::RecoveryBeforeRename, FaultPoint::RecoveryAfterRename] {
        let (dir, seed) = initial_evidence();
        assert!(matches!(recovery::recover_at(dir.path(), &seed, &admin(), &mut || 2, Some(fault)), Err(Error::RecoveryRequired)));
        assert!(dir.path().join(PENDING).exists() && dir.path().join(RECOVERY).exists());
        assert_eq!(dir.path().join(STATE).exists(), fault == FaultPoint::RecoveryAfterRename);
        assert!(matches!(DurableVault::open(dir.path(), &seed), Err(Error::RecoveryRequired)));
        let owner = DurableVault::recover(dir.path(), &seed, &admin(), &mut || 3).unwrap();
        assert!(owner.app.records.is_empty() && owner.app.tasks.is_empty());
        assert!(!dir.path().join(PENDING).exists() && !dir.path().join(RECOVERY).exists());
        drop(owner);
        assert!(DurableVault::open(dir.path(), &seed).is_ok());
    }
}

#[test]
fn missing_initial_recovery_rejects_wrong_seed_malformed_nonempty_and_symlinked_evidence() {
    for case in 0..5 {
        let (dir, seed) = initial_evidence();
        let path = dir.path().join(PENDING);
        let initial = fs::read(&path).unwrap();
        let candidate = initial[24..].to_vec();
        let mut supplied = seed.clone();
        match case {
            0 => supplied = crypto::generate_mnemonic().unwrap(),
            1 => { let mut corrupt = initial; *corrupt.last_mut().unwrap() ^= 1; fs::write(&path, corrupt).unwrap(); }
            2 => {
                let mut noninitial = INTENT_MAGIC.to_vec();
                for _ in 0..2 { noninitial.extend_from_slice(&(candidate.len() as u64).to_be_bytes()); }
                noninitial.extend_from_slice(&candidate); noninitial.extend_from_slice(&candidate);
                fs::write(&path, noninitial).unwrap();
            }
            3 => {
                let (mut app, key, salt, kdf) = unseal(&candidate, &seed).unwrap();
                app.approve_task(&admin(), approval("a"), 1).unwrap();
                let nonempty = seal(&app, &key, &salt, kdf).unwrap();
                let mut evidence = INTENT_MAGIC.to_vec();
                evidence.extend_from_slice(&0u64.to_be_bytes());
                evidence.extend_from_slice(&(nonempty.len() as u64).to_be_bytes()); evidence.extend_from_slice(&nonempty);
                fs::write(&path, evidence).unwrap();
            }
            _ => {
                fs::rename(&path, dir.path().join("kept-initial-evidence")).unwrap();
                std::os::unix::fs::symlink("kept-initial-evidence", &path).unwrap();
            }
        }
        let retained = fs::read(&path).unwrap();
        assert!(matches!(DurableVault::recover(dir.path(), &supplied, &admin(), &mut || 2), Err(Error::RecoveryRequired)));
        assert!(!dir.path().join(STATE).exists());
        assert!(fs::read(&path).unwrap() == retained);
    }
}

#[test]
fn missing_state_for_noninitial_mutation_remains_gated() {
    let mut f = fixture();
    f.owner.store.fault = Some(FaultPoint::AfterIntent);
    assert_eq!(f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Patch {
        record: f.receipt.record, expected: 1, values: input(&[(Field::Notes, "synthetic metadata")]),
    }, 3).unwrap_err(), Error::RecoveryRequired);
    drop(f.owner);
    fs::remove_file(f.dir.path().join(STATE)).unwrap();
    assert!(matches!(DurableVault::recover(f.dir.path(), &f.seed, &admin(), &mut || 4), Err(Error::RecoveryRequired)));
    assert!(f.dir.path().join(PENDING).exists());
}

#[test]
fn duplicate_dispatched_registrations_across_versions_fail_snapshot_validation() {
    let mut f = fixture();
    f.owner.use_secret(&agent("a"), f.ta, request(f.receipt.record, PrivateAction::Register), &mut || 3,
        |_| Ok(DeliveryStatus::Accepted)).unwrap();
    f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Patch {
        record: f.receipt.record, expected: 1, values: input(&[(Field::Notes, "synthetic metadata")]),
    }, 4).unwrap();
    let mut duplicate = f.owner.app.deliveries.values().next().unwrap().clone();
    duplicate.version = 2; duplicate.key.id = Uuid::new_v4();
    let body = PrivateUse { request: duplicate.key.id, record: duplicate.record, fields: duplicate.fields.clone(),
        destination: duplicate.destination.clone(), action: duplicate.action };
    let encoded = Zeroizing::new(serde_json::to_vec(&body).unwrap());
    duplicate.fingerprint = Sha256::digest(encoded.as_slice()).into();
    f.owner.app.deliveries.insert(Uuid::new_v4(), duplicate);
    assert!(matches!(snapshot::encode(&f.owner.app), Err(Error::InvalidStorage)));
}

#[test]
fn definitely_cancelled_registration_does_not_claim_an_external_dispatch() {
    let mut f = fixture();
    let mut grant = super::super::tests::grant(); grant.expires_at = 4;
    f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Share {
        record: f.receipt.record, expected: 1, grant,
    }, 3).unwrap();
    let mut samples = [3, 4].into_iter();
    assert_eq!(f.owner.use_secret(&agent("b"), f.tb, request(f.receipt.record, PrivateAction::Register),
        &mut || samples.next().unwrap(), |_| panic!("cancelled dispatch reached callback")).unwrap_err(), Error::Denied);
    f.owner.use_secret(&agent("a"), f.ta, request(f.receipt.record, PrivateAction::Register), &mut || 5,
        |_| Ok(DeliveryStatus::Accepted)).unwrap();
    assert_eq!(f.owner.app.deliveries.values().filter(|d| d.action == PrivateAction::Register && d.dispatched).count(), 1);
}

#[test]
fn rejected_other_scope_leaves_original_scope_recoverable_after_revocation() {
    let mut f = fixture();
    f.owner.revoke_task(&admin(), f.ta, 3).unwrap();
    f.owner.revoke_task(&admin(), f.tb, 3).unwrap();
    let mut foreign = approval("other"); foreign.workspace = "another-project".into();
    let foreign_admin = AuthenticatedContext::from_authenticated_admin("user".into(), "human".into(), "another-project".into());
    assert_eq!(f.owner.approve_task(&foreign_admin, foreign, 3).unwrap_err(), Error::Denied);
    f.owner.store.fault = Some(FaultPoint::AfterRename);
    assert_eq!(f.owner.approve_task(&admin(), approval("human"), 4).unwrap_err(), Error::RecoveryRequired);
    drop(f.owner);
    assert!(matches!(DurableVault::recover(f.dir.path(), &f.seed, &foreign_admin, &mut || 5), Err(Error::Denied)));
    let mut owner = DurableVault::recover(f.dir.path(), &f.seed, &admin(), &mut || 5).unwrap();
    let ta = super::tests::reapprove(&mut owner, f.receipt.record, 6);
    owner.use_secret(&agent("a"), ta, request(f.receipt.record, PrivateAction::Login), &mut || 6,
        |_| Ok(DeliveryStatus::Accepted)).unwrap();
    assert_eq!(owner.app.records[&f.receipt.record].signup, SignupState::VerifiedLogin);
}
