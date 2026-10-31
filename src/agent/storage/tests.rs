use super::*;
use super::super::tests::{admin, agent, approval, fields, grant, input};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use tempfile::{tempdir, TempDir};

pub(super) fn destination() -> TempDir {
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

pub(super) fn reapprove(owner: &mut DurableVault, record: Uuid, now: Time) -> Uuid {
    let human = approval("human"); let th = human.id;
    let task = approval("a"); let ta = task.id;
    owner.approve_task(&admin(), human, now).unwrap();
    owner.approve_task(&admin(), task, now).unwrap();
    let expected = owner.app.records[&record].revision;
    owner.mutate(&admin(), th, Uuid::new_v4(), Mutation::Share { record, expected, grant: GrantSpec {
        recipient: "a".into(), fields: fields(&[Field::Username, Field::Password]),
        permissions: [Permission::SecretUse, Permission::SecretWrite].into_iter().collect(),
        destinations: ["test-service".into()].into_iter().collect(), expires_at: 100, follow_active: false,
    } }, now).unwrap();
    ta
}

pub(super) struct Fixture {
    pub(super) dir: TempDir,
    pub(super) seed: String,
    pub(super) owner: DurableVault,
    pub(super) ta: Uuid,
    pub(super) tb: Uuid,
    pub(super) receipt: Receipt,
    pub(super) request: Uuid,
    pub(super) create: Mutation,
}

impl DurableVault {
    #[expect(clippy::too_many_arguments, reason = "Test fixture supplies a fixed clock and request")]
    fn use_fixed<F>(&mut self, ctx: &AuthenticatedContext, task: Uuid, record: Uuid,
        fields: Fields, destination: &str, now: Time, deliver: F) -> Result<DeliveryReceipt, Error>
    where F: FnOnce(&BTreeMap<Field, &str>) -> Result<DeliveryStatus, Error> {
        self.use_secret(ctx, task, PrivateUse { request: Uuid::new_v4(), record, fields,
            destination: destination.into(), action: PrivateAction::Use }, &mut || now, deliver)
    }
}

pub(super) fn fixture() -> Fixture {
    fixture_with_approvals(approval("a"), approval("b"))
}

pub(super) fn fixture_with_approvals(a: TaskApproval, b: TaskApproval) -> Fixture {
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let seed = crypto::generate_mnemonic().unwrap();
    let mut owner = DurableVault::create(dir.path(), &seed).unwrap();
    let (ta, tb) = (a.id, b.id);
    owner.approve_task(&admin(), a, 1).unwrap();
    owner.approve_task(&admin(), b, 1).unwrap();
    let request = Uuid::new_v4();
    let create = Mutation::Create { kind: CredentialKind::Login,
        values: input(&[(Field::Username, "fixture-user"), (Field::Password, "FAKE-canary-password")]) };
    let receipt = owner.mutate(&agent("a"), ta, request, create.clone(), 2).unwrap();
    Fixture { dir, seed, owner, ta, tb, receipt, request, create }
}

#[test]
fn encrypted_roundtrip_reopen_and_idempotent_create() {
    let f = fixture();
    let bytes = fs::read(f.dir.path().join(STATE)).unwrap();
    assert_eq!(&bytes[..8], MAGIC);
    assert_ne!(&bytes[..8], b"CREDMAN\0");
    assert!(!bytes.windows(b"FAKE-canary-password".len()).any(|part| part == b"FAKE-canary-password"));
    assert_eq!(fs::metadata(f.dir.path().join(STATE)).unwrap().mode() & 0o7777, 0o600);
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    let retry = owner.mutate(&agent("a"), f.ta, f.request, f.create, 3).unwrap();
    assert_eq!(retry, f.receipt);
    assert_eq!(owner.app.records.len(), 1);
    let disclosed = owner.read_secret(&agent("a"), f.ta, retry.record, fields(&[Field::Password]), 3).unwrap();
    assert_eq!(disclosed.expose()[&Field::Password], "FAKE-canary-password");
    assert!(!f.dir.path().join(PENDING).exists());
}

#[test]
fn wrong_seed_corrupt_ciphertext_and_encrypted_unknown_schema_are_rejected() {
    let f = fixture();
    let image = fs::read(f.dir.path().join(STATE)).unwrap();
    let wrong = crypto::generate_mnemonic().unwrap();
    assert!(matches!(unseal(&image, &wrong), Err(Error::InvalidStorage)));
    let mut corrupt = image.clone();
    let last = corrupt.last_mut().unwrap(); *last ^= 1;
    assert!(matches!(unseal(&corrupt, &f.seed), Err(Error::InvalidStorage)));
    let bytes = snapshot::encode(&f.owner.app).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["schema"] = 999.into();
    let invalid = Zeroizing::new(serde_json::to_vec(&value).unwrap());
    let sealed = seal_plaintext(&invalid, &f.owner.store.key, &f.owner.store.salt, f.owner.store.kdf).unwrap();
    assert!(matches!(unseal(&sealed, &f.seed), Err(Error::InvalidStorage)));
}

#[test]
fn lock_exclusion_and_create_only_preserve_existing_image() {
    let f = fixture();
    assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::InUse)));
    let original = fs::read(f.dir.path().join(STATE)).unwrap();
    drop(f.owner);
    assert!(matches!(DurableVault::create(f.dir.path(), &f.seed), Err(Error::Conflict)));
    assert_eq!(fs::read(f.dir.path().join(STATE)).unwrap(), original);
}

#[test]
fn actual_pre_intent_write_failure_preserves_disk_memory_and_request_state() {
    let mut f = fixture();
    let original = fs::read(f.dir.path().join(STATE)).unwrap();
    let requests = f.owner.app.requests.len();
    let generation = f.owner.app.generation;
    f.owner.store.fault = Some(FaultPoint::TempWrite);
    let result = f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Patch {
        record: f.receipt.record, expected: 1, values: input(&[(Field::Password, "never-published-fake")]),
    }, 3);
    assert_eq!(result.unwrap_err(), Error::NotPublished);
    assert_eq!(fs::read(f.dir.path().join(STATE)).unwrap(), original);
    assert_eq!(f.owner.app.generation, generation);
    assert_eq!(f.owner.app.requests.len(), requests);
    assert!(!f.dir.path().join(PENDING).exists());
    assert_eq!(f.owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), 3)
        .unwrap().expose()[&Field::Password], "FAKE-canary-password");
}

#[test]
fn after_rename_and_directory_sync_uncertainty_freeze_and_gate_restart() {
    for point in [FaultPoint::AfterRename, FaultPoint::DirectorySync] {
        let mut f = fixture();
        let original = fs::read(f.dir.path().join(STATE)).unwrap();
        let request = Uuid::new_v4();
        f.owner.store.fault = Some(point);
        let result = f.owner.mutate(&agent("a"), f.ta, request, Mutation::Share {
            record: f.receipt.record, expected: 1, grant: grant(),
        }, 3);
        assert_eq!(result.unwrap_err(), Error::RecoveryRequired);
        assert!(f.dir.path().join(PENDING).exists());
        let pending = fs::read(f.dir.path().join(PENDING)).unwrap();
        assert_eq!(&pending[..8], INTENT_MAGIC);
        assert!(pending.windows(original.len()).any(|part| part == original));
        assert!(!pending.windows(b"FAKE-canary-password".len()).any(|part| part == b"FAKE-canary-password"));
        let current = fs::read(f.dir.path().join(STATE)).unwrap();
        let (published, _, _, _) = unseal(&current, &f.seed).unwrap();
        assert_eq!(published.grants.len(), 1);
        assert!(published.requests.keys().any(|key| key.id == request));
        // Stale staging state is not published to memory, and cannot be used as fallback authority.
        assert!(f.owner.app.grants.is_empty());
        assert_eq!(f.owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), 4).unwrap_err(), Error::RecoveryRequired);
        assert_eq!(f.owner.revoke_task(&admin(), f.ta, 4).unwrap_err(), Error::RecoveryRequired);
        assert!(matches!(f.owner.audit_events(&admin()), Err(Error::RecoveryRequired)));
        drop(f.owner);
        assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::RecoveryRequired)));
    }
}

#[test]
fn share_request_and_issuer_revocation_remain_atomic_after_reopen() {
    let mut f = fixture();
    let request = Uuid::new_v4();
    let share = Mutation::Share { record: f.receipt.record, expected: 1, grant: grant() };
    let shared = f.owner.mutate(&agent("a"), f.ta, request, share.clone(), 3).unwrap();
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.mutate(&agent("a"), f.ta, request, share.clone(), 4).unwrap(), shared);
    assert_eq!(owner.app.grants.len(), 1);
    owner.use_fixed(&agent("b"), f.tb, f.receipt.record, fields(&[Field::Password]), "test-service", 4,
        |_| Ok(DeliveryStatus::Accepted)).unwrap();
    owner.revoke_task(&admin(), f.ta, 5).unwrap();
    drop(owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.use_fixed(&agent("b"), f.tb, f.receipt.record, fields(&[Field::Password]), "test-service", 6,
        |_| panic!("revoked issuer task reached adapter after restart")).unwrap_err(), Error::Denied);
    assert_eq!(owner.mutate(&agent("a"), f.ta, request, share, 6).unwrap_err(), Error::Denied);
}

#[test]
fn unfinished_private_handoff_freezes_on_unwind_and_gates_restart() {
    let mut f = fixture();
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = f.owner.use_fixed(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), "test-service", 3,
            |_| -> Result<DeliveryStatus, Error> { panic!("synthetic adapter interruption") });
    }));
    assert!(crashed.is_err());
    assert!(f.owner.app.deliveries.values().any(|d| d.status.is_none()));
    assert_eq!(f.owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), 4).unwrap_err(), Error::RecoveryRequired);
    drop(f.owner);
    assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::RecoveryRequired)));
}

#[test]
fn terminal_private_outcomes_are_persisted_without_plaintext_responses() {
    let mut f = fixture();
    for status in [DeliveryStatus::Rejected, DeliveryStatus::HumanRequired, DeliveryStatus::Unknown] {
        let receipt = f.owner.use_fixed(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), "test-service", 3,
            |_| Ok(status)).unwrap();
        assert_eq!(receipt.status, status);
        assert!(!serde_json::to_string(&receipt).unwrap().contains("FAKE-canary"));
        assert_eq!(f.owner.app.deliveries[&receipt.attempt].status, Some(status));
    }
    drop(f.owner);
    let owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.app.deliveries.len(), 3);
    assert!(owner.app.deliveries.values().all(|d| d.status.is_some()));
}

#[test]
fn symlinked_parent_lock_or_state_and_unsafe_directory_are_rejected() {
    let f = fixture();
    let alias_dir = tempdir().unwrap();
    let alias = alias_dir.path().join("alias");
    symlink(f.dir.path(), &alias).unwrap();
    assert!(matches!(DurableVault::open(&alias, &f.seed), Err(Error::InvalidStorage)));
    drop(f.owner);
    let original = f.dir.path().join("kept-encrypted");
    fs::rename(f.dir.path().join(STATE), &original).unwrap();
    symlink(&original, f.dir.path().join(STATE)).unwrap();
    assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::InvalidStorage)));
    fs::remove_file(f.dir.path().join(STATE)).unwrap();
    fs::rename(original, f.dir.path().join(STATE)).unwrap();
    fs::remove_file(f.dir.path().join("owner.lock")).unwrap();
    symlink(f.dir.path().join(STATE), f.dir.path().join("owner.lock")).unwrap();
    assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::InvalidStorage)));
    fs::set_permissions(f.dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::InvalidStorage)));
}

#[test]
fn final_handoff_resamples_expiry_after_intent_publication() {
    let mut f = fixture();
    let request = PrivateUse { request: Uuid::new_v4(), record: f.receipt.record,
        fields: fields(&[Field::Password]), destination: "test-service".into(), action: PrivateAction::Use };
    let mut samples = [3, 1000].into_iter();
    let mut called = false;
    let result = f.owner.use_secret(&agent("a"), f.ta, request,
        &mut || samples.next().expect("unexpected clock sample"), |_| { called = true; Ok(DeliveryStatus::Accepted) });
    assert!(!called, "expired task must not dispatch after slow publication");
    assert_eq!(result.unwrap_err(), Error::Denied);
}

#[test]
fn clock_only_updates_skip_publication_until_the_persist_interval() {
    let mut f = fixture();
    let before = fs::read(f.dir.path().join(STATE)).unwrap();
    let persisted = f.owner.app.last_time.unwrap();
    assert_eq!(f.owner.read_secret(&agent("a"), f.ta, Uuid::nil(), fields(&[Field::Password]), persisted + 1).unwrap_err(), Error::Denied);
    assert_eq!(f.owner.app.last_time, Some(persisted + 1));
    assert_eq!(fs::read(f.dir.path().join(STATE)).unwrap(), before);
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.app.last_time, Some(persisted));
    let due = persisted + CLOCK_PERSIST_INTERVAL;
    assert_eq!(owner.read_secret(&agent("a"), f.ta, Uuid::nil(), fields(&[Field::Password]), due).unwrap_err(), Error::Denied);
    drop(owner);
    let owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.app.last_time, Some(due));
}

#[test]
fn clock_freeze_publishes_immediately() {
    let mut f = fixture();
    let persisted = f.owner.app.last_time.unwrap();
    assert_eq!(f.owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), persisted - CLOCK_SKEW_TOLERANCE - 1).unwrap_err(),
        Error::ClockRecoveryRequired);
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert!(owner.app.clock_frozen);
    assert_eq!(owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), persisted).unwrap_err(),
        Error::ClockRecoveryRequired);
}

#[test]
fn version_2_header_opens_and_the_next_write_uses_associated_data() {
    let f = fixture();
    let plaintext = snapshot::encode(&f.owner.app).unwrap();
    let legacy = seal_version(&plaintext, &f.owner.store.key, &f.owner.store.salt, f.owner.store.kdf, HEADER_V2).unwrap();
    assert_eq!(u32::from_be_bytes(legacy[8..12].try_into().unwrap()), HEADER_V2);
    let _ = unseal(&legacy, &f.seed).unwrap();
    let mut low_memory = legacy.clone();
    low_memory[12..16].copy_from_slice(&(8u32 * 1024).to_be_bytes());
    assert!(unseal(&low_memory, &f.seed).is_err());
    drop(f.owner);
    fs::write(f.dir.path().join(STATE), &legacy).unwrap();
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Patch {
        record: f.receipt.record, expected: 1, values: input(&[(Field::Username, "republished-user")]),
    }, 3).unwrap();
    drop(owner);
    let image = fs::read(f.dir.path().join(STATE)).unwrap();
    assert_eq!(u32::from_be_bytes(image[8..12].try_into().unwrap()), HEADER_V3);
    let mut flipped = image.clone();
    flipped[24] ^= 0x5a;
    assert!(unseal(&flipped, &f.seed).is_err());
    assert!(unseal(&image, &f.seed).is_ok());
}

#[test]
fn aged_receipts_compact_during_commit_and_later_work_survives_restart() {
    let mut f = fixture();
    let now = f.owner.app.last_time.unwrap();
    for cached in f.owner.app.requests.values_mut() { cached.at = Some(now - snapshot::RETRY_WINDOW); }
    assert_eq!(f.owner.read_secret(&agent("a"), f.ta, Uuid::nil(), fields(&[Field::Password]), now).unwrap_err(), Error::Denied);
    assert!(f.owner.app.baselines.contains_key(&f.receipt.record));
    assert!(f.owner.app.requests.values().all(|cached| cached.result.record != f.receipt.record));
    let created = f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Create {
        kind: CredentialKind::Login, values: input(&[(Field::Username, "after-compact"), (Field::Password, "after-compact-secret")]),
    }, now).unwrap();
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert!(owner.app.records.contains_key(&created.record));
    assert!(owner.app.baselines.contains_key(&f.receipt.record));
    assert_eq!(owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), now).unwrap().expose()[&Field::Password],
        "FAKE-canary-password");
}

#[test]
fn pruned_delivery_rechecks_authority_and_registration_stays_sealed() {
    let mut f = fixture();
    let req = PrivateUse { request: Uuid::new_v4(), record: f.receipt.record, fields: fields(&[Field::Password]),
        destination: "test-service".into(), action: PrivateAction::Use };
    f.owner.use_secret(&agent("a"), f.ta, req.clone(), &mut || 3, |_| Ok(DeliveryStatus::Accepted)).unwrap();
    f.owner.revoke_task(&admin(), f.ta, 4).unwrap();
    for delivery in f.owner.app.deliveries.values_mut() { delivery.at = Some(3 - snapshot::RETRY_WINDOW); }
    let mut called = false;
    assert_eq!(f.owner.use_secret(&agent("a"), f.ta, req, &mut || 4, |_| { called = true; Ok(DeliveryStatus::Accepted) }).unwrap_err(), Error::Denied);
    assert!(!called);
    drop(f.owner);

    let mut f = fixture();
    let register = PrivateUse { request: Uuid::new_v4(), record: f.receipt.record, fields: fields(&[Field::Username, Field::Password]),
        destination: "test-service".into(), action: PrivateAction::Register };
    f.owner.use_secret(&agent("a"), f.ta, register, &mut || 3, |_| Ok(DeliveryStatus::Accepted)).unwrap();
    for delivery in f.owner.app.deliveries.values_mut() { delivery.at = Some(3 - snapshot::RETRY_WINDOW); }
    let again = PrivateUse { request: Uuid::new_v4(), record: f.receipt.record, fields: fields(&[Field::Username, Field::Password]),
        destination: "test-service".into(), action: PrivateAction::Register };
    let mut called = false;
    assert_eq!(f.owner.use_secret(&agent("a"), f.ta, again, &mut || 4, |_| { called = true; Ok(DeliveryStatus::Accepted) }).unwrap_err(), Error::Conflict);
    assert!(!called);
}

#[test]
fn rekey_replaces_the_seed_and_interruption_stays_recoverable() {
    let mut f = fixture();
    let new_seed = crypto::generate_mnemonic().unwrap();
    let generation = f.owner.app.generation;
    f.owner.rekey(&admin(), &new_seed).unwrap();
    assert_eq!(f.owner.app.generation, generation + 1);
    assert!(f.owner.app.predecessor.is_some());
    drop(f.owner);
    assert!(DurableVault::open(f.dir.path(), &f.seed).is_err());
    let mut owner = DurableVault::open(f.dir.path(), &new_seed).unwrap();
    assert_eq!(owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), 3).unwrap().expose()[&Field::Password],
        "FAKE-canary-password");
    let image = fs::read(f.dir.path().join(STATE)).unwrap();
    assert!(!image.windows(b"FAKE-canary-password".len()).any(|part| part == b"FAKE-canary-password"));
    assert_eq!(u32::from_be_bytes(image[8..12].try_into().unwrap()), HEADER_V3);
    drop(owner);

    let mut f = fixture();
    let new_seed = crypto::generate_mnemonic().unwrap();
    f.owner.store.fault = Some(FaultPoint::TempWrite);
    assert_eq!(f.owner.rekey(&admin(), &new_seed).unwrap_err(), Error::NotPublished);
    drop(f.owner);
    assert!(DurableVault::open(f.dir.path(), &f.seed).is_ok());

    let mut f = fixture();
    let new_seed = crypto::generate_mnemonic().unwrap();
    f.owner.store.fault = Some(FaultPoint::AfterIntent);
    assert_eq!(f.owner.rekey(&admin(), &new_seed).unwrap_err(), Error::RecoveryRequired);
    let pending = fs::read(f.dir.path().join(PENDING)).unwrap();
    assert_eq!(&pending[..8], INTENT_MAGIC);
    assert!(!pending.windows(b"FAKE-canary-password".len()).any(|part| part == b"FAKE-canary-password"));
    drop(f.owner);
    assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::RecoveryRequired)));
    assert!(matches!(DurableVault::open(f.dir.path(), &new_seed), Err(Error::RecoveryRequired)));
    let owner = DurableVault::recover(f.dir.path(), &new_seed, &admin(), &mut || 4).unwrap();
    assert_eq!(owner.app.records[&f.receipt.record].values.0[&Field::Password].as_str(), "FAKE-canary-password");
    assert!(owner.app.tasks.keys().all(|id| owner.app.revoked_tasks.contains(id)));
    drop(owner);
    assert!(DurableVault::open(f.dir.path(), &f.seed).is_err());
    assert!(DurableVault::open(f.dir.path(), &new_seed).is_ok());
}
