use super::*;
use super::tests::{admin, agent, approval, fields, setup};

fn login(name: &str) -> Mutation {
    Mutation::Generate { kind: CredentialKind::Login, username: Some(name.into()) }
}
fn api_key() -> Mutation { Mutation::Generate { kind: CredentialKind::ApiKey, username: None } }
fn draws() -> usize { GENERATION_DRAWS.with(|draws| draws.get()) }

#[test]
fn private_generation_formats_public_metadata_and_nonsecret_fingerprint() {
    let (mut app, ta, _, _) = setup();
    let before = draws();
    for (op, secret_field) in [(login("public-fixture-user"), Field::Password), (api_key(), Field::ApiKey)] {
        let request = Uuid::new_v4();
        let specification = serde_json::to_vec(&op).unwrap();
        let receipt = app.mutate(&agent("a"), ta, request, op, 3).unwrap();
        let record = &app.records[&receipt.record];
        let secret = &record.values.0[&secret_field];
        assert!(secret.len() == 32);
        assert!(secret.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
        assert_eq!(record.values.fields(), if secret_field == Field::Password {
            fields(&[Field::Username, Field::Password])
        } else { fields(&[Field::ApiKey]) });
        let key = RequestKey { owner: "user".into(), principal: "a".into(), task: ta, id: request };
        let cached = &app.requests[&key];
        assert!(matches!(cached.kind, CachedKind::Create));
        assert_eq!(cached.fingerprint, <[u8; 32]>::from(Sha256::digest(&specification)));
        assert_eq!(receipt.revision, 1);
        assert_eq!(receipt.grant, None);
        for output in [serde_json::to_string(&receipt).unwrap(), format!("{receipt:?}"),
            serde_json::to_string(&app.audit_events(&admin()).unwrap()).unwrap()] {
            assert!(!output.contains(secret.as_str()));
            assert!(!output.contains("public-fixture-user"));
        }
    }
    assert_eq!(draws() - before, 2);
    let receipt = app.mutate(&agent("a"), ta, Uuid::new_v4(), login("public-fixture-user"), 3).unwrap();
    assert_eq!(app.metadata(&agent("a"), ta, receipt.record, fields(&[Field::Username]), 3)
        .unwrap()[&Field::Username], "public-fixture-user");
    assert_eq!(app.metadata(&agent("a"), ta, receipt.record, fields(&[Field::Password]), 3)
        .unwrap_err(), Error::Denied);
}

#[test]
fn private_generation_invalid_specs_and_authority_never_draw_randomness() {
    let (mut app, ta, _, _) = setup();
    let before = draws();
    for op in [Mutation::Generate { kind: CredentialKind::Login, username: None }, login(""), login(&"x".repeat(2049)),
        Mutation::Generate { kind: CredentialKind::ApiKey, username: Some("public-user".into()) },
        Mutation::Generate { kind: CredentialKind::ApiKey, username: Some(String::new()) }] {
        assert_eq!(app.mutate(&agent("a"), ta, Uuid::new_v4(), op, 3).unwrap_err(), Error::Invalid);
    }
    for ctx in [agent("b"), AuthenticatedContext::from_authenticated_peer("other".into(), "a".into(), "project".into()),
        AuthenticatedContext::from_authenticated_peer("user".into(), "a".into(), "other".into())] {
        assert_eq!(app.mutate(&ctx, ta, Uuid::new_v4(), api_key(), 3).unwrap_err(), Error::Denied);
    }
    assert_eq!(app.mutate(&agent("a"), ta, Uuid::nil(), api_key(), 3).unwrap_err(), Error::Invalid);
    assert_eq!(app.mutate(&agent("a"), Uuid::new_v4(), Uuid::new_v4(), api_key(), 3).unwrap_err(), Error::Denied);
    for missing_write in [true, false] {
        let mut task = approval("a");
        task.share = None;
        if missing_write { task.permissions.remove(&Permission::SecretWrite); }
        else { task.fields.remove(&Field::Username); }
        let id = task.id;
        app.approve_task(&admin(), task, 3).unwrap();
        assert_eq!(app.mutate(&agent("a"), id, Uuid::new_v4(), login("public-user"), 3).unwrap_err(), Error::Denied);
    }
    assert_eq!(draws(), before);
    assert_eq!(app.records.len(), 1);
    for forged in [r#"{"Generate":{"kind":"Login","username":"public","values":{"Password":"fake"}}}"#,
        r#"{"Generate":{"kind":"ApiKey","username":null,"principal":"b"}}"#] {
        assert!(serde_json::from_str::<Mutation>(forged).is_err());
    }
}

#[test]
fn private_generation_cache_reauthorization_deleted_record_and_conflicts_precede_randomness() {
    let (mut app, ta, _, _) = setup();
    let request = Uuid::new_v4();
    let receipt = app.mutate(&agent("a"), ta, request, login("public-user"), 3).unwrap();
    let before = draws();
    assert_eq!(app.mutate(&agent("a"), ta, request, login("public-user"), 3).unwrap(), receipt);
    for changed in [login("different-public-user"), api_key(), Mutation::Create {
        kind: CredentialKind::Login, values: app.records[&receipt.record].values.clone(),
    }] {
        assert_eq!(app.mutate(&agent("a"), ta, request, changed, 3).unwrap_err(), Error::ReplayConflict);
    }
    app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Delete { record: receipt.record, expected: 1 }, 4).unwrap();
    assert_eq!(app.mutate(&agent("a"), ta, request, login("public-user"), 4).unwrap_err(), Error::Denied);
    let request = Uuid::new_v4();
    app.mutate(&agent("a"), ta, request, api_key(), 4).unwrap();
    let after_create = draws();
    app.revoke_task(&admin(), ta, 5).unwrap();
    assert_eq!(app.mutate(&agent("a"), ta, request, api_key(), 5).unwrap_err(), Error::Denied);
    assert_eq!(draws(), after_create);
    assert_eq!(after_create - before, 1);
}

#[test]
fn private_generation_expiry_clock_and_capacity_precede_randomness() {
    let (mut app, ta, _, existing) = setup();
    let request = Uuid::new_v4();
    let receipt = app.mutate(&agent("a"), ta, request, api_key(), 3).unwrap();
    let before = draws();
    let mut full_requests = app.clone();
    let key = RequestKey { owner: "user".into(), principal: "a".into(), task: ta, id: request };
    let remembered = full_requests.requests[&key].clone();
    while full_requests.requests.len() < 10_000 {
        let mut key = key.clone(); key.id = Uuid::new_v4();
        full_requests.requests.insert(key, remembered.clone());
    }
    assert_eq!(full_requests.mutate(&agent("a"), ta, request, api_key(), 3).unwrap(), receipt);
    assert_eq!(full_requests.mutate(&agent("a"), ta, Uuid::new_v4(), api_key(), 3).unwrap_err(), Error::Capacity);
    let mut full_records = app.clone();
    let record = app.records[&existing.record].clone();
    while full_records.records.len() < 10_000 {
        let mut record = record.clone(); record.id = Uuid::new_v4();
        full_records.records.insert(record.id, record);
    }
    assert_eq!(full_records.mutate(&agent("a"), ta, Uuid::new_v4(), api_key(), 3).unwrap_err(), Error::Capacity);
    assert_eq!(app.mutate(&agent("a"), ta, request, api_key(), 1000).unwrap_err(), Error::Denied);
    assert_eq!(app.mutate(&agent("a"), ta, request, api_key(), 999).unwrap_err(), Error::ClockRecoveryRequired);
    assert_eq!(app.mutate(&agent("a"), ta, request, api_key(), 1001).unwrap_err(), Error::ClockRecoveryRequired);
    assert_eq!(draws(), before);
}

#[test]
fn private_generation_fallible_rng_does_not_leave_a_record_or_receipt() {
    let (mut app, ta, _, _) = setup();
    let request = Uuid::new_v4();
    let counts = (app.records.len(), app.requests.len(), app.audit.len());
    GENERATION_FAIL.with(|fail| fail.set(true));
    assert_eq!(app.mutate(&agent("a"), ta, request, api_key(), 3).unwrap_err(), Error::GenerationUnavailable);
    assert_eq!((app.records.len(), app.requests.len(), app.audit.len()), counts);
    let receipt = app.mutate(&agent("a"), ta, request, api_key(), 3).unwrap();
    assert!(app.records.contains_key(&receipt.record));
}
