use super::*;
use super::tests::{destination, fixture};
use super::super::tests::{admin, agent, grant};
use std::fs;

fn interrupt_initial<R>(operation: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset { fn drop(&mut self) { INITIAL_PUBLICATION_FAULT.with(|fault| fault.set(None)); } }
    INITIAL_PUBLICATION_FAULT.with(|fault| { assert!(fault.replace(Some(FaultPoint::AfterIntent)).is_none()); });
    let _reset = Reset;
    operation()
}

#[test]
fn initial_native_restore_recovery_preserves_data_and_resumes_after_interruption() {
    let mut f = fixture();
    let record = f.receipt.record;
    f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Share {
        record, expected: 1, grant: grant(),
    }, 3).unwrap();
    let source_before = snapshot::encode(&f.owner.app).unwrap();
    let source_image = fs::read(f.dir.path().join(STATE)).unwrap();
    for secret in [BackupSecret::Seed(&f.seed), BackupSecret::Passphrase("synthetic initial restore phrase")] {
        let backup = f.owner.export_backup(&admin(), secret).unwrap();
        let target = destination(); let seed = crypto::generate_mnemonic().unwrap();
        let result = interrupt_initial(|| {
            DurableVault::restore_backup(target.path(), &seed, &admin(), &backup, secret, 4).map(|_| ())
        });
        assert!(matches!(result, Err(Error::RecoveryRequired)));
        assert!(!target.path().join(STATE).exists() && target.path().join(PENDING).exists());
        assert!(matches!(DurableVault::open(target.path(), &seed), Err(Error::RecoveryRequired)));
        assert!(matches!(DurableVault::recover(target.path(), &seed, &agent("a"), &mut || 5), Err(Error::Denied)));
        let foreign = AuthenticatedContext::from_authenticated_admin("user".into(), "human".into(), "foreign-project".into());
        assert!(matches!(DurableVault::recover(target.path(), &seed, &foreign, &mut || 5), Err(Error::Denied)));
        let wrong = crypto::generate_mnemonic().unwrap();
        assert!(matches!(DurableVault::recover(target.path(), &wrong, &admin(), &mut || 5), Err(Error::RecoveryRequired)));
        assert!(matches!(recovery::recover_at(target.path(), &seed, &admin(), &mut || 5,
            Some(FaultPoint::RecoveryBeforeRename)), Err(Error::RecoveryRequired)));
        assert!(!target.path().join(STATE).exists());
        assert!(target.path().join(PENDING).exists() && target.path().join(RECOVERY).exists());
        assert!(matches!(DurableVault::open(target.path(), &seed), Err(Error::RecoveryRequired)));
        let recovered = DurableVault::recover(target.path(), &seed, &admin(), &mut || 6).unwrap();
        assert_eq!(recovered.app.records.len(), 1);
        assert!(recovered.app.records[&record].restored);
        assert!(recovered.app.tasks.keys().all(|id| recovered.app.revoked_tasks.contains(id)));
        assert!(recovered.app.grants.values().all(|grant| grant.revoked));
        assert!(recovered.app.generation > f.owner.app.generation);
        let original = &f.owner.app.records[&record]; let copied = &recovered.app.records[&record];
        assert!(serde_json::to_vec(&copied.values).unwrap() == serde_json::to_vec(&original.values).unwrap());
        assert_eq!(copied.created_by, original.created_by);
        assert_eq!(copied.task, original.task);
        assert_eq!(recovered.app.requests.len(), f.owner.app.requests.len());
        assert_eq!(recovered.app.audit.len(), f.owner.app.audit.len());
        drop(recovered);
        assert!(DurableVault::open(target.path(), &seed).unwrap().app.records[&record].restored);
        assert!(!target.path().join(PENDING).exists() && !target.path().join(RECOVERY).exists());
    }
    assert!(*source_before == *snapshot::encode(&f.owner.app).unwrap());
    assert!(source_image == fs::read(f.dir.path().join(STATE)).unwrap());
}
