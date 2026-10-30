use super::*;
use super::tests::{fixture, fixture_with_approvals};
use super::super::tests::{admin, agent, approval, fields, grant, input};
use std::fs;

fn login() -> Mutation {
    Mutation::Generate { kind: CredentialKind::Login, username: Some("public-generated-user".into()) }
}
fn api_key() -> Mutation { Mutation::Generate { kind: CredentialKind::ApiKey, username: None } }
fn draws() -> usize { GENERATION_DRAWS.with(|draws| draws.get()) }

#[test]
fn private_generation_durable_restart_preserves_record_secret_receipt_and_fingerprint() {
    let mut f = fixture();
    let request = Uuid::new_v4();
    let receipt = f.owner.mutate(&agent("a"), f.ta, request, login(), 3).unwrap();
    let original = f.owner.read_for_task(&admin(), f.ta, receipt.record, fields(&[Field::Password]), 3).unwrap();
    let image = fs::read(f.dir.path().join(STATE)).unwrap();
    assert!(!image.windows(32).any(|part| part == original.expose()[&Field::Password].as_bytes()));
    assert!(!f.dir.path().join(PENDING).exists());
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    let before = draws();
    assert_eq!(owner.mutate(&agent("a"), f.ta, request, login(), 4).unwrap(), receipt);
    assert_eq!(draws(), before);
    assert_eq!(owner.app.records.len(), 2);
    assert_eq!(owner.app.records[&receipt.record].revision, 1);
    let recovered = owner.read_for_task(&admin(), f.ta, receipt.record, fields(&[Field::Password]), 4).unwrap();
    assert!(original.expose()[&Field::Password] == recovered.expose()[&Field::Password]);
    let key = RequestKey { owner: "user".into(), principal: "a".into(), task: f.ta, id: request };
    assert!(matches!(owner.app.requests[&key].kind, CachedKind::Create));
    let spec = serde_json::to_vec(&login()).unwrap();
    assert_eq!(owner.app.requests[&key].fingerprint, <[u8; 32]>::from(Sha256::digest(spec)));
    assert_eq!(owner.mutate(&agent("a"), f.ta, request, api_key(), 4).unwrap_err(), Error::ReplayConflict);
    owner.revoke_task(&admin(), f.ta, 5).unwrap();
    drop(owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.mutate(&agent("a"), f.ta, request, login(), 6).unwrap_err(), Error::Denied);
    assert_eq!(draws(), before);
}

#[test]
fn private_generation_publication_failure_never_splits_record_and_receipt() {
    for fault in [FaultPoint::TempWrite, FaultPoint::AfterIntent, FaultPoint::AfterRename] {
        let mut f = fixture();
        let original = fs::read(f.dir.path().join(STATE)).unwrap();
        let request = Uuid::new_v4();
        f.owner.store.fault = Some(fault);
        let error = f.owner.mutate(&agent("a"), f.ta, request, api_key(), 3).unwrap_err();
        assert_eq!(f.owner.app.records.len(), 1);
        assert!(!f.owner.app.requests.keys().any(|key| key.id == request));
        if fault == FaultPoint::TempWrite {
            assert_eq!(error, Error::NotPublished);
            assert_eq!(fs::read(f.dir.path().join(STATE)).unwrap(), original);
            let receipt = f.owner.mutate(&agent("a"), f.ta, request, api_key(), 3).unwrap();
            assert!(f.owner.app.records.contains_key(&receipt.record));
            assert_eq!(f.owner.app.records.len(), 2);
        } else {
            assert_eq!(error, Error::RecoveryRequired);
            let pending = fs::read(f.dir.path().join(PENDING)).unwrap();
            let previous_len = u64::from_be_bytes(pending[8..16].try_into().unwrap()) as usize;
            let (staged, _, _, _) = unseal(&pending[24 + previous_len..], &f.seed).unwrap();
            let cached = staged.requests.iter().find(|(key, _)| key.id == request).unwrap().1;
            assert!(staged.records.contains_key(&cached.result.record));
            assert_eq!(staged.records.len(), 2);
            let before = draws();
            assert_eq!(f.owner.mutate(&agent("a"), f.ta, request, api_key(), 4).unwrap_err(), Error::RecoveryRequired);
            assert_eq!(draws(), before);
            drop(f.owner);
            assert!(matches!(DurableVault::open(f.dir.path(), &f.seed), Err(Error::RecoveryRequired)));
        }
    }
}

#[test]
fn private_generation_import_admin_scope_task_and_idempotency_are_enforced() {
    let mut f = fixture();
    let request = Uuid::new_v4();
    let values = || input(&[(Field::ApiKey, "synthetic-private-import")]);
    let mut foreign_owner = admin(); foreign_owner.owner = "other".into();
    let mut foreign_workspace = admin(); foreign_workspace.workspace = "other".into();
    for ctx in [agent("a"), foreign_owner, foreign_workspace] {
        assert_eq!(f.owner.import_for_task(&ctx, f.ta, request, CredentialKind::ApiKey, values(), 3)
            .unwrap_err(), Error::Denied);
        assert_eq!(f.owner.read_for_task(&ctx, f.ta, f.receipt.record, fields(&[Field::Password]), 3)
            .unwrap_err(), Error::Denied);
    }
    assert_eq!(f.owner.import_for_task(&admin(), Uuid::new_v4(), request, CredentialKind::ApiKey, values(), 3)
        .unwrap_err(), Error::Denied);
    assert_eq!(f.owner.import_for_task(&admin(), f.ta, Uuid::nil(), CredentialKind::ApiKey, values(), 3)
        .unwrap_err(), Error::Invalid);
    let imported = f.owner.import_for_task(&admin(), f.ta, request, CredentialKind::ApiKey, values(), 3).unwrap();
    assert_eq!(f.owner.app.records[&imported.record].created_by, "a");
    assert_eq!(f.owner.app.records[&imported.record].task, f.ta);
    assert_eq!(f.owner.app.records[&imported.record].owner, "user");
    assert_eq!(f.owner.import_for_task(&admin(), f.ta, request, CredentialKind::ApiKey, values(), 3).unwrap(), imported);
    assert_eq!(f.owner.import_for_task(&admin(), f.ta, request, CredentialKind::ApiKey,
        input(&[(Field::ApiKey, "changed-synthetic-import")]), 3).unwrap_err(), Error::ReplayConflict);
    let before = draws();
    assert_eq!(f.owner.mutate(&agent("a"), f.ta, request, api_key(), 3).unwrap_err(), Error::ReplayConflict);
    assert_eq!(draws(), before);
    let disclosure = f.owner.read_for_task(&admin(), f.ta, imported.record, fields(&[Field::ApiKey]), 3).unwrap();
    assert!(disclosure.expose()[&Field::ApiKey] == "synthetic-private-import");
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.import_for_task(&admin(), f.ta, request, CredentialKind::ApiKey, values(), 4).unwrap(), imported);
    let audit = owner.audit_events(&admin()).unwrap();
    assert!(audit.iter().any(|event| event.record == imported.record && event.task == f.ta && event.action == AuditAction::SecretRead));
    assert!(!serde_json::to_string(&audit).unwrap().contains("synthetic-private-import"));
    owner.revoke_task(&admin(), f.ta, 5).unwrap();
    assert_eq!(owner.import_for_task(&admin(), f.ta, request, CredentialKind::ApiKey, values(), 5).unwrap_err(), Error::Denied);
    assert_eq!(owner.read_for_task(&admin(), f.ta, imported.record, fields(&[Field::ApiKey]), 5).unwrap_err(), Error::Denied);
    owner.frozen = true;
    assert_eq!(owner.import_for_task(&admin(), f.ta, Uuid::new_v4(), CredentialKind::ApiKey, values(), 5)
        .unwrap_err(), Error::RecoveryRequired);
    assert_eq!(owner.read_for_task(&admin(), f.ta, imported.record, fields(&[Field::ApiKey]), 5)
        .unwrap_err(), Error::RecoveryRequired);
}

#[test]
fn private_generation_import_and_export_do_not_bypass_task_permissions_or_expiry() {
    let mut a = approval("a");
    a.permissions.remove(&Permission::SecretRead);
    a.permissions.remove(&Permission::SecretWrite);
    a.share = None;
    let mut f = fixture_with_approvals(approval("a"), a);
    let limited = f.tb;
    assert_eq!(f.owner.import_for_task(&admin(), limited, Uuid::new_v4(), CredentialKind::ApiKey,
        input(&[(Field::ApiKey, "synthetic-private-import")]), 3).unwrap_err(), Error::Denied);
    assert_eq!(f.owner.read_for_task(&admin(), limited, f.receipt.record, fields(&[Field::Password]), 3)
        .unwrap_err(), Error::Denied);
    let mut scoped = approval("a"); scoped.fields.remove(&Field::ApiKey); scoped.share = None;
    let scoped_id = scoped.id;
    f.owner.approve_task(&admin(), scoped, 3).unwrap();
    assert_eq!(f.owner.import_for_task(&admin(), scoped_id, Uuid::new_v4(), CredentialKind::ApiKey,
        input(&[(Field::ApiKey, "synthetic-private-import")]), 3).unwrap_err(), Error::Denied);
    assert_eq!(f.owner.import_for_task(&admin(), f.ta, Uuid::new_v4(), CredentialKind::ApiKey,
        input(&[(Field::ApiKey, "synthetic-private-import")]), 1000).unwrap_err(), Error::Denied);
    assert_eq!(f.owner.read_for_task(&admin(), f.ta, f.receipt.record, fields(&[Field::Password]), 1000)
        .unwrap_err(), Error::Denied);
}

#[test]
fn private_generation_export_requires_admin_and_current_secret_read_grant() {
    let mut f = fixture();
    assert_eq!(f.owner.read_for_task(&admin(), f.tb, f.receipt.record, fields(&[Field::Password]), 3)
        .unwrap_err(), Error::Denied);
    let first = f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Share {
        record: f.receipt.record, expected: 1, grant: grant(),
    }, 3).unwrap();
    assert_eq!(f.owner.read_for_task(&admin(), f.tb, f.receipt.record, fields(&[Field::Password]), 3)
        .unwrap_err(), Error::Denied);
    let mut read_grant = grant(); read_grant.permissions.insert(Permission::SecretRead);
    let shared = f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Share {
        record: f.receipt.record, expected: first.revision, grant: read_grant,
    }, 3).unwrap();
    assert_eq!(f.owner.read_for_task(&agent("b"), f.tb, f.receipt.record, fields(&[Field::Password]), 3)
        .unwrap_err(), Error::Denied);
    let exported = f.owner.read_for_task(&admin(), f.tb, f.receipt.record, fields(&[Field::Password]), 3).unwrap();
    assert!(exported.expose()[&Field::Password] == "FAKE-canary-password");
    assert_eq!(f.owner.read_for_task(&admin(), f.tb, f.receipt.record, fields(&[Field::Notes]), 3)
        .unwrap_err(), Error::Denied);
    f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Revoke {
        record: f.receipt.record, expected: shared.revision, grant: shared.grant.unwrap(),
    }, 4).unwrap();
    assert_eq!(f.owner.read_for_task(&admin(), f.tb, f.receipt.record, fields(&[Field::Password]), 4)
        .unwrap_err(), Error::Denied);
    drop(f.owner);
    let owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert!(owner.audit_events(&admin()).unwrap().iter().any(|event|
        event.task == f.tb && event.record == f.receipt.record && event.action == AuditAction::SecretRead));
}

#[test]
fn private_generation_consumer_preflight_checks_exact_binding_without_disclosure() {
    let mut a = approval("a"); a.origin = "https://fixture.invalid:9443".into();
    let mut b = approval("b"); b.origin = a.origin.clone();
    let mut f = fixture_with_approvals(a, b);
    let service = "test-service";
    let origin = "https://fixture.invalid:9443";
    assert_eq!(f.owner.validate_consumer(&agent("a"), f.ta, service, origin, 3), Ok(()));
    for (ctx, task, service, origin) in [
        (agent("b"), f.ta, service, origin),
        (agent("a"), Uuid::new_v4(), service, origin),
        (agent("a"), f.ta, "wrong-service", origin),
        (agent("a"), f.ta, service, "https://fixture.invalid"),
        (agent("a"), f.ta, service, "https://fixture.invalid:9443/"),
        (AuthenticatedContext::from_authenticated_peer("other".into(), "a".into(), "project".into()), f.ta, service, origin),
        (AuthenticatedContext::from_authenticated_peer("user".into(), "a".into(), "other".into()), f.ta, service, origin),
    ] {
        assert_eq!(f.owner.validate_consumer(&ctx, task, service, origin, 3), Err(Error::Denied));
    }
    assert_eq!(f.owner.validate_consumer(&agent("a"), f.ta, service, origin, 1000), Err(Error::Denied));
    assert_eq!(f.owner.validate_consumer(&agent("a"), f.ta, service, origin, 1), Err(Error::ClockRecoveryRequired));
    f.owner.revoke_task(&admin(), f.ta, 4).unwrap();
    assert_eq!(f.owner.validate_consumer(&agent("a"), f.ta, service, origin, 4), Err(Error::Denied));
    f.owner.app.clock_frozen = true;
    assert_eq!(f.owner.validate_consumer(&agent("b"), f.tb, service, origin, 4), Err(Error::ClockRecoveryRequired));
    f.owner.frozen = true;
    assert_eq!(f.owner.validate_consumer(&agent("b"), f.tb, service, origin, 4), Err(Error::RecoveryRequired));
}

#[test]
fn private_generation_delegated_use_retains_private_handoff_and_revocation_guards() {
    let mut f = fixture();
    let generated = f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), login(), 3).unwrap();
    let oracle = f.owner.read_for_task(&admin(), f.ta, generated.record, fields(&[Field::Password]), 3).unwrap();
    let shared = f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Share {
        record: generated.record, expected: 1, grant: grant(),
    }, 3).unwrap();
    let usage = PrivateUse { request: Uuid::new_v4(), record: generated.record,
        fields: fields(&[Field::Username, Field::Password]), destination: "test-service".into(), action: PrivateAction::Use };
    let mut called = false;
    let delivered = f.owner.use_secret(&agent("b"), f.tb, usage.clone(), &mut || 4, |values| {
        called = true;
        assert!(values[&Field::Password] == oracle.expose()[&Field::Password]);
        Ok(DeliveryStatus::Accepted)
    }).unwrap();
    assert!(called);
    assert_eq!(f.owner.app.records[&generated.record].signup, SignupState::Pending);
    assert!(!serde_json::to_string(&delivered).unwrap().contains(oracle.expose()[&Field::Password]));
    assert_eq!(f.owner.read_for_task(&admin(), f.tb, generated.record, fields(&[Field::Password]), 4)
        .unwrap_err(), Error::Denied);
    f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Revoke {
        record: generated.record, expected: shared.revision, grant: shared.grant.unwrap(),
    }, 5).unwrap();
    for request in [usage.clone(), PrivateUse { request: Uuid::new_v4(), ..usage }] {
        assert_eq!(f.owner.use_secret(&agent("b"), f.tb, request, &mut || 5,
            |_| panic!("revoked generated credential reached callback")).unwrap_err(), Error::Denied);
    }
}
