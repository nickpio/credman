use super::*;
use super::tests::{fixture, Fixture};
use super::workflow_tests::request;
use super::super::tests::{admin, agent, approval, fields, input};
use std::fs;

fn uncertain() -> Fixture {
    let mut f = fixture();
    f.owner.store.fault = Some(FaultPoint::AfterRename);
    assert_eq!(f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Patch {
        record: f.receipt.record, expected: 1, values: input(&[(Field::Username, "changed-synthetic-user")]),
    }, 3).unwrap_err(), Error::RecoveryRequired);
    f
}

#[test]
fn human_recovery_selects_visible_valid_image_and_revokes_authority_without_losing_provenance() {
    let f = uncertain();
    assert!(matches!(DurableVault::recover(f.dir.path(), &f.seed, &admin(), &mut || 4), Err(Error::InUse)));
    drop(f.owner);
    assert!(matches!(DurableVault::recover(f.dir.path(), &f.seed, &agent("a"), &mut || 4), Err(Error::Denied)));
    let mut owner = DurableVault::recover(f.dir.path(), &f.seed, &admin(), &mut || 4).unwrap();
    let record = &owner.app.records[&f.receipt.record];
    assert_eq!(record.created_by, "a");
    assert_eq!(record.task, f.ta);
    assert_eq!(record.secret_version, 2);
    assert!(record.values.0.get(&Field::Username).is_some_and(|v| v.as_str() == "changed-synthetic-user"));
    assert!(record.values.0.contains_key(&Field::Password));
    assert_eq!(owner.app.revoked_tasks.len(), owner.app.tasks.len());
    assert!(owner.app.grants.values().all(|g| g.revoked));
    assert!(!f.dir.path().join(PENDING).exists() && !f.dir.path().join(RECOVERY).exists());
    assert_eq!(owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), 5).unwrap_err(), Error::Denied);
    drop(owner);
    assert!(DurableVault::open(f.dir.path(), &f.seed).is_ok());
}

#[test]
fn wrong_seed_tampered_evidence_and_mismatched_visible_image_remain_gated() {
    for damage in 0..3 {
        let f = uncertain();
        drop(f.owner);
        let seed = if damage == 0 { crypto::generate_mnemonic().unwrap() } else { f.seed.clone() };
        if damage == 1 {
            let mut intent = fs::read(f.dir.path().join(PENDING)).unwrap();
            *intent.last_mut().unwrap() ^= 1;
            fs::write(f.dir.path().join(PENDING), intent).unwrap();
        }
        if damage == 2 {
            let mut visible = fs::read(f.dir.path().join(STATE)).unwrap();
            *visible.last_mut().unwrap() ^= 1;
            fs::write(f.dir.path().join(STATE), visible).unwrap();
        }
        assert!(matches!(DurableVault::recover(f.dir.path(), &seed, &admin(), &mut || 4), Err(Error::RecoveryRequired)));
        assert!(f.dir.path().join(PENDING).exists());
        assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::RecoveryRequired)));
    }
}

#[test]
fn interrupted_recovery_stays_gated_and_explicit_resume_is_idempotent() {
    let f = uncertain();
    drop(f.owner);
    assert!(matches!(recovery::recover_at(f.dir.path(), &f.seed, &admin(), &mut || 4,
        Some(FaultPoint::RecoveryAfterRename)), Err(Error::RecoveryRequired)));
    assert!(f.dir.path().join(RECOVERY).exists());
    assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::RecoveryRequired)));
    let owner = DurableVault::recover(f.dir.path(), &f.seed, &admin(), &mut || 5).unwrap();
    assert!(owner.app.tasks.keys().all(|id| owner.app.revoked_tasks.contains(id)));
    assert!(owner.app.records[&f.receipt.record].values.0.contains_key(&Field::Password));
    drop(owner);
    assert!(DurableVault::open(f.dir.path(), &f.seed).is_ok());
}

#[test]
fn unfinished_registration_recovers_unknown_never_reregisters_and_fresh_approval_can_login() {
    let mut f = fixture();
    let register = request(f.receipt.record, PrivateAction::Register);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = f.owner.use_secret(&agent("a"), f.ta, register, &mut || 3,
            |_| -> Result<DeliveryStatus, Error> { panic!("synthetic interrupted registration") });
    }));
    assert!(interrupted.is_err());
    drop(f.owner);
    let mut owner = DurableVault::recover(f.dir.path(), &f.seed, &admin(), &mut || 4).unwrap();
    assert_eq!(owner.app.records[&f.receipt.record].signup, SignupState::Unknown);
    assert!(owner.app.deliveries.values().all(|d| d.status == Some(DeliveryStatus::Unknown)));
    let human = approval("human"); let th = human.id;
    let approved = approval("a"); let ta = approved.id;
    owner.approve_task(&admin(), human, 5).unwrap();
    owner.approve_task(&admin(), approved, 5).unwrap();
    owner.mutate(&admin(), th, Uuid::new_v4(), Mutation::Share { record: f.receipt.record, expected: 1,
        grant: GrantSpec { recipient: "a".into(), fields: fields(&[Field::Username, Field::Password]),
            permissions: [Permission::SecretUse].into_iter().collect(), destinations: ["test-service".into()].into_iter().collect(),
            expires_at: 100, follow_active: false } }, 5).unwrap();
    assert_eq!(owner.use_secret(&agent("a"), ta, request(f.receipt.record, PrivateAction::Register), &mut || 6,
        |_| panic!("recovery reset the registration guard")).unwrap_err(), Error::Conflict);
    owner.use_secret(&agent("a"), ta, request(f.receipt.record, PrivateAction::Login), &mut || 6,
        |_| Ok(DeliveryStatus::Accepted)).unwrap();
    assert_eq!(owner.app.records[&f.receipt.record].signup, SignupState::VerifiedLogin);
}
