use super::*;
use super::super::tests::fixture;
use super::super::tests::{destination, reapprove};
use super::super::workflow_tests::request;
use super::super::super::tests::{admin, agent, grant};
use std::fs;

const PASSPHRASE: &str = "synthetic backup fixture phrase only";

#[test]
fn both_secret_kinds_preserve_full_snapshot_and_restore_without_live_authority() {
    let mut f = fixture();
    f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Share {
        record: f.receipt.record, expected: 1, grant: grant(),
    }, 3).unwrap();
    f.owner.use_secret(&agent("a"), f.ta, request(f.receipt.record, PrivateAction::Login), &mut || 3,
        |_| Ok(DeliveryStatus::Accepted)).unwrap();
    let before = snapshot::encode(&f.owner.app).unwrap();
    for secret in [BackupSecret::Seed(&f.seed), BackupSecret::Passphrase(PASSPHRASE)] {
        let bytes = f.owner.export_backup(&admin(), secret).unwrap();
        assert_eq!(&bytes[..8], BACKUP_MAGIC);
        let decoded = decrypt_backup(&bytes, secret).unwrap();
        assert!(*snapshot::encode(&decoded).unwrap() == *before);
        let dir = destination(); let seed = crypto::generate_mnemonic().unwrap();
        let mut restored = DurableVault::restore_backup(dir.path(), &seed, &admin(), &bytes, secret, 4).unwrap();
        assert!(restored.app.grants.values().all(|g| g.revoked));
        assert!(restored.app.tasks.keys().all(|id| restored.app.revoked_tasks.contains(id)));
        assert!(restored.app.records[&f.receipt.record].restored);
        assert_eq!(restored.app.records[&f.receipt.record].signup, SignupState::VerifiedLogin);
        assert_eq!(restored.app.requests.len(), f.owner.app.requests.len());
        assert_eq!(restored.app.deliveries.len(), f.owner.app.deliveries.len());
        let ta = reapprove(&mut restored, f.receipt.record, 5);
        assert_eq!(restored.use_secret(&agent("a"), ta, request(f.receipt.record, PrivateAction::Register), &mut || 5,
            |_| panic!("restored data invited registration")).unwrap_err(), Error::Conflict);
        restored.use_secret(&agent("a"), ta, request(f.receipt.record, PrivateAction::Login), &mut || 5,
            |_| Ok(DeliveryStatus::Accepted)).unwrap();
    }
}

#[test]
fn restored_pre_registration_backup_stays_blocked_after_patch_reopen_and_recovery() {
    let f = fixture();
    let record = f.receipt.record;
    assert!(!f.owner.app.records[&record].restored);
    assert_eq!(f.owner.app.records[&record].signup, SignupState::Pending);
    assert!(f.owner.app.deliveries.is_empty());
    let bytes = f.owner.export_backup(&admin(), BackupSecret::Passphrase(PASSPHRASE)).unwrap();
    let target = destination(); let seed = crypto::generate_mnemonic().unwrap();
    let mut restored = DurableVault::restore_backup(target.path(), &seed, &admin(), &bytes, BackupSecret::Passphrase(PASSPHRASE), 3).unwrap();
    let original = &f.owner.app.records[&record];
    let copied = &restored.app.records[&record];
    assert_eq!(copied.created_by, original.created_by);
    assert_eq!(copied.task, original.task);
    assert_eq!(copied.origin, original.origin);
    assert!(serde_json::to_vec(&copied.values).unwrap() == serde_json::to_vec(&original.values).unwrap());
    let ta = reapprove(&mut restored, record, 4);
    let expected = restored.app.records[&record].revision;
    restored.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Patch { record, expected,
        values: super::super::super::tests::input(&[(Field::Username, "changed-synthetic-user")]) }, 4).unwrap();
    drop(restored);
    let mut restored = DurableVault::open(target.path(), &seed).unwrap();
    let ta = reapprove(&mut restored, record, 5);
    assert_eq!(restored.use_secret(&agent("a"), ta, request(record, PrivateAction::Register), &mut || 5,
        |_| panic!("patch or reopen reset restored guard")).unwrap_err(), Error::Conflict);
    restored.store.fault = Some(FaultPoint::AfterIntent);
    let expected = restored.app.records[&record].revision;
    assert_eq!(restored.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Patch { record, expected,
        values: super::super::super::tests::input(&[(Field::Username, "unpublished-synthetic-user")]) }, 6).unwrap_err(), Error::RecoveryRequired);
    drop(restored);
    let mut recovered = DurableVault::recover(target.path(), &seed, &admin(), &mut || 7).unwrap();
    assert!(recovered.app.records[&record].restored);
    assert_eq!(recovered.app.records[&record].values.0[&Field::Username].as_str(), "changed-synthetic-user");
    let ta = reapprove(&mut recovered, record, 8);
    assert_eq!(recovered.use_secret(&agent("a"), ta, request(record, PrivateAction::Register), &mut || 8,
        |_| panic!("recovery reset restored guard")).unwrap_err(), Error::Conflict);
    recovered.use_secret(&agent("a"), ta, request(record, PrivateAction::Login), &mut || 8,
        |_| Ok(DeliveryStatus::Accepted)).unwrap();
}

#[test]
fn wrong_secret_kind_version_cost_corruption_and_invalid_inner_snapshot_are_rejected() {
    let f = fixture();
    let secret = BackupSecret::Passphrase(PASSPHRASE);
    let valid = f.owner.export_backup(&admin(), secret).unwrap();
    assert!(decrypt_backup(&valid, BackupSecret::Passphrase("different synthetic fixture phrase")).is_err());
    assert!(decrypt_backup(&valid, BackupSecret::Seed(&f.seed)).is_err());
    for case in 0..5 {
        let mut damaged = valid.clone();
        match case {
            0 => damaged[8..12].copy_from_slice(&99u32.to_be_bytes()),
            1 => damaged[16..20].copy_from_slice(&u32::MAX.to_be_bytes()),
            2 => { *damaged.last_mut().unwrap() ^= 1; },
            3 => { damaged.truncate(12); },
            _ => { damaged[12..16].copy_from_slice(&1u32.to_be_bytes()); },
        }
        assert!(matches!(decrypt_backup(&damaged, secret), Err(Error::InvalidStorage)));
    }
    let inner = encrypt_snapshot(br#"{"schema":99}"#, secret).unwrap();
    assert!(matches!(decrypt_backup(&inner, secret), Err(Error::InvalidStorage)));
    assert!(f.owner.export_backup(&admin(), BackupSecret::Passphrase("short")).is_err());
    assert!(f.owner.export_backup(&admin(), BackupSecret::Seed("invalid synthetic phrase")).is_err());
}

#[test]
fn export_requires_admin_ready_owner_and_restore_never_overwrites_existing_destination() {
    let f = fixture(); let secret = BackupSecret::Passphrase(PASSPHRASE);
    assert!(matches!(f.owner.export_backup(&agent("a"), secret), Err(Error::Denied)));
    let before = fs::read(f.dir.path().join(STATE)).unwrap();
    let bytes = f.owner.export_backup(&admin(), secret).unwrap();
    assert!(matches!(DurableVault::restore_backup(f.dir.path(), &f.seed, &admin(), &bytes, secret, 3), Err(Error::InUse)));
    drop(f.owner);
    assert!(matches!(DurableVault::restore_backup(f.dir.path(), &f.seed, &admin(), &bytes, secret, 3), Err(Error::Conflict)));
    assert!(fs::read(f.dir.path().join(STATE)).unwrap() == before);
    let dir = destination();
    assert!(matches!(DurableVault::restore_backup(dir.path(), &f.seed, &agent("a"), &bytes, secret, 3), Err(Error::Denied)));
    assert!(!dir.path().join(STATE).exists());
}

#[test]
fn restore_preparation_preserves_clock_gate_history_and_settles_unfinished_delivery() {
    let mut f = fixture();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = f.owner.use_secret(&agent("a"), f.ta, request(f.receipt.record, PrivateAction::Register), &mut || 10,
            |_| -> Result<DeliveryStatus, Error> { panic!("synthetic interrupted registration") });
    }));
    assert!(interrupted.is_err());
    let mut app = f.owner.app.clone();
    app.clock_frozen = true;
    let generation = app.generation;
    let requests = app.requests.len();
    let audit = app.audit.len();
    prepare_restored(&mut app, &admin(), 5).unwrap();
    assert_eq!(app.generation, generation + 1);
    assert!(app.clock_frozen);
    assert_eq!(app.last_time, Some(10));
    assert!(app.records[&f.receipt.record].restored);
    assert_eq!(app.records[&f.receipt.record].signup, SignupState::Unknown);
    assert!(app.deliveries.values().all(|d| d.status == Some(DeliveryStatus::Unknown)));
    assert!(app.tasks.keys().all(|id| app.revoked_tasks.contains(id)));
    assert_eq!(app.requests.len(), requests);
    assert_eq!(app.audit.len(), audit);
    assert!(snapshot::decode(&snapshot::encode(&app).unwrap()).unwrap().clock_frozen);
}

#[test]
fn authenticated_unknown_record_fields_refuse_restore_before_publication() {
    let f = fixture();
    let snapshot = snapshot::encode(&f.owner.app).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    value["records"][0]["extra_object"] = serde_json::json!({"value": "synthetic"});
    let plaintext = Zeroizing::new(serde_json::to_vec(&value).unwrap());
    let bytes = encrypt_snapshot(&plaintext, BackupSecret::Seed(&f.seed)).unwrap();
    let target = destination();
    assert!(matches!(DurableVault::restore_backup(target.path(), &f.seed, &admin(), &bytes,
        BackupSecret::Seed(&f.seed), 3), Err(Error::InvalidStorage)));
    assert!(!target.path().join(STATE).exists() && !target.path().join(PENDING).exists());
}

#[test]
fn authenticated_duplicate_secret_fields_refuse_restore_before_publication() {
    let f = fixture();
    let snapshot = snapshot::encode(&f.owner.app).unwrap();
    let text = Zeroizing::new(String::from_utf8(snapshot.to_vec()).unwrap());
    let original_values = Zeroizing::new(serde_json::to_string(&f.owner.app.records[&f.receipt.record].values).unwrap());
    let needle = Zeroizing::new(format!("\"values\":{}", original_values.as_str()));
    for key in [r#""Password""#, r#""\u0050assword""#] {
        for value in ["synthetic-first", "synthetic-second"] {
            let replacement = Zeroizing::new(format!("\"values\":{{\"Username\":\"fixture-user\",\"Password\":\"synthetic-first\",{key}:\"{value}\"}}"));
            let malformed = Zeroizing::new(text.replacen(needle.as_str(), replacement.as_str(), 1));
            assert!(malformed.as_str() != text.as_str());
            let bytes = encrypt_snapshot(malformed.as_bytes(), BackupSecret::Seed(&f.seed)).unwrap();
            let target = destination();
            assert!(matches!(DurableVault::restore_backup(target.path(), &f.seed, &admin(), &bytes,
                BackupSecret::Seed(&f.seed), 3), Err(Error::InvalidStorage)), "authenticated duplicate field was restored");
            assert!(!target.path().join(STATE).exists() && !target.path().join(PENDING).exists());
        }
    }
}
