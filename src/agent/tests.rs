use super::*;

pub(super) fn fields(items: &[Field]) -> Fields { items.iter().copied().collect() }
fn permissions(items: &[Permission]) -> Permissions { items.iter().copied().collect() }
fn strings(items: &[&str]) -> BTreeSet<String> { items.iter().map(|s| s.to_string()).collect() }
pub(super) fn input(items: &[(Field, &str)]) -> SecretInput {
    SecretInput::new(items.iter().map(|(f, v)| (*f, v.to_string())).collect())
}
pub(super) fn agent(name: &str) -> AuthenticatedContext {
    AuthenticatedContext::from_authenticated_peer("user".into(), name.into(), "project".into())
}
pub(super) fn admin() -> AuthenticatedContext {
    AuthenticatedContext::from_authenticated_admin("user".into(), "human".into(), "project".into())
}
pub(super) fn approval(name: &str) -> TaskApproval {
    TaskApproval {
        id: Uuid::new_v4(), owner: "user".into(), principal: name.into(), workspace: "project".into(),
        service: "test-service".into(), origin: "https://service.example.invalid".into(),
        fields: fields(&[Field::Label, Field::Username, Field::Password, Field::ApiKey, Field::Notes]),
        permissions: permissions(&[Permission::MetadataRead, Permission::SecretUse, Permission::SecretRead,
            Permission::SecretWrite, Permission::AccessGrant, Permission::EntryDelete]),
        destinations: strings(&["test-service"]), expires_at: 1000, share: Some(ShareBounds {
            recipients: strings(&["b"]), fields: fields(&[Field::Username, Field::Password]),
            permissions: permissions(&[Permission::SecretUse, Permission::SecretRead, Permission::MetadataRead]),
            destinations: strings(&["test-service"]), expires_at: 500,
        }),
    }
}
pub(super) fn setup() -> (Application, Uuid, Uuid, Receipt) {
    let mut app = Application::default();
    let a = approval("a");
    let b = approval("b");
    let (ta, tb) = (a.id, b.id);
    app.approve_task(&admin(), a, 1).unwrap();
    app.approve_task(&admin(), b, 1).unwrap();
    let result = app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Create {
        kind: CredentialKind::Login,
        values: input(&[(Field::Label, "synthetic"), (Field::Username, "fixture-user"),
            (Field::Password, "FAKE-canary-password"), (Field::Notes, "fixture-note")]),
    }, 2).unwrap();
    (app, ta, tb, result)
}
pub(super) fn grant() -> GrantSpec {
    GrantSpec { recipient: "b".into(), fields: fields(&[Field::Username, Field::Password]),
        permissions: permissions(&[Permission::SecretUse]), destinations: strings(&["test-service"]),
        expires_at: 100, follow_active: false }
}
fn share(app: &mut Application, ta: Uuid, record: Uuid, spec: GrantSpec) -> Receipt {
    app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Share { record, expected: 1, grant: spec }, 3).unwrap()
}

#[test]
fn create_returns_reference_and_immutable_user_provenance() {
    let (app, ta, _, receipt) = setup();
    let r = app.records.get(&receipt.record).unwrap();
    assert_eq!(r.owner, "user");
    assert_eq!(r.created_by, "a");
    assert_eq!(r.task, ta);
    assert_eq!(r.service, "test-service");
    assert_eq!(r.origin, "https://service.example.invalid");
    assert_eq!(r.kind, CredentialKind::Login);
    assert_eq!(r.signup, SignupState::Pending);
    assert!(!r.restored);
    assert_eq!(receipt.revision, 1);
    let output = serde_json::to_string(&receipt).unwrap();
    assert!(!output.contains("FAKE-canary"));
    assert!(!output.contains("fixture-user"));
    assert!(!output.contains("fixture-note"));
}

#[test]
fn unshared_record_and_guessed_reference_are_denied() {
    let (mut app, _, tb, receipt) = setup();
    for id in [receipt.record, Uuid::new_v4()] {
        assert_eq!(app.read_secret(&agent("b"), tb, id, fields(&[Field::Password]), 3).unwrap_err(), Error::Denied);
        assert_eq!(app.metadata(&agent("b"), tb, id, fields(&[Field::Label]), 3).unwrap_err(), Error::Denied);
    }
    // Naming another task does not change the internally bound principal.
    let ta = app.records[&receipt.record].task;
    assert_eq!(app.read_secret(&agent("b"), ta, receipt.record, fields(&[Field::Password]), 3).unwrap_err(), Error::Denied);
}

#[test]
fn use_grant_is_not_read_metadata_write_delete_or_reshare_permission() {
    let (mut app, ta, tb, r) = setup();
    share(&mut app, ta, r.record, grant());
    let result = app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Username, Field::Password]),
        "test-service", 4, |values| {
            assert_eq!(values[&Field::Password], "FAKE-canary-password");
            assert_eq!(values.len(), 2);
            Ok(DeliveryStatus::Accepted)
        }).unwrap();
    assert_eq!(result.status, DeliveryStatus::Accepted);
    assert!(!serde_json::to_string(&result).unwrap().contains("FAKE-canary"));
    assert_eq!(app.read_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), 4).unwrap_err(), Error::Denied);
    assert_eq!(app.metadata(&agent("b"), tb, r.record, fields(&[Field::Username]), 4).unwrap_err(), Error::Denied);
    assert_eq!(app.mutate(&agent("b"), tb, Uuid::new_v4(), Mutation::Patch { record: r.record, expected: 2,
        values: input(&[(Field::Password, "different-fake")]) }, 4).unwrap_err(), Error::Denied);
    assert_eq!(app.mutate(&agent("b"), tb, Uuid::new_v4(), Mutation::Delete { record: r.record, expected: 2 }, 4).unwrap_err(), Error::Denied);
    assert_eq!(app.mutate(&agent("b"), tb, Uuid::new_v4(), Mutation::Share { record: r.record, expected: 2,
        grant: grant() }, 4).unwrap_err(), Error::Denied);
}

#[test]
fn private_use_checks_fields_destination_and_never_falls_back() {
    let (mut app, ta, tb, r) = setup();
    share(&mut app, ta, r.record, grant());
    assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Notes]), "test-service", 4,
        |_| panic!("unauthorized field reached adapter")).unwrap_err(), Error::Denied);
    assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "evil", 4,
        |_| panic!("unauthorized destination reached adapter")).unwrap_err(), Error::Denied);
    assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 4,
        |_| Err(Error::InteractionRequired)).unwrap_err(), Error::InteractionRequired);
}

#[test]
fn explicit_read_and_metadata_are_field_scoped_and_debug_is_redacted() {
    let (mut app, ta, tb, r) = setup();
    let mut spec = grant();
    spec.permissions = permissions(&[Permission::SecretRead, Permission::MetadataRead]);
    share(&mut app, ta, r.record, spec);
    let disclosed = app.read_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), 4).unwrap();
    assert_eq!(disclosed.expose()[&Field::Password], "FAKE-canary-password");
    assert_eq!(format!("{disclosed:?}"), "Disclosure([REDACTED])");
    assert_eq!(app.metadata(&agent("b"), tb, r.record, fields(&[Field::Username]), 4).unwrap()[&Field::Username], "fixture-user");
    assert_eq!(app.metadata(&agent("b"), tb, r.record, fields(&[Field::Password]), 4).unwrap_err(), Error::Denied);
    assert_eq!(app.read_secret(&agent("b"), tb, r.record, fields(&[Field::Notes]), 4).unwrap_err(), Error::Denied);
}

#[test]
fn revocation_and_exact_expiry_boundary_block_future_access() {
    let (mut app, ta, tb, r) = setup();
    let shared = share(&mut app, ta, r.record, grant());
    let revoked = app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Revoke {
        record: r.record, expected: 2, grant: shared.grant.unwrap(),
    }, 4).unwrap();
    assert_eq!(revoked.revision, 3);
    assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 4,
        |_| panic!("revoked grant reached adapter")).unwrap_err(), Error::Denied);
    let (mut app, ta, tb, r) = setup();
    share(&mut app, ta, r.record, grant());
    app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 99,
        |_| Ok(DeliveryStatus::Accepted)).unwrap();
    assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 100,
        |_| panic!("expired grant reached adapter")).unwrap_err(), Error::Denied);
}

#[test]
fn share_bounds_prevent_permission_recipient_expiry_destination_and_field_widening() {
    let (mut app, ta, _, r) = setup();
    let mut variants = Vec::new();
    let mut s = grant(); s.recipient = "other".into(); variants.push(s);
    let mut s = grant(); s.expires_at = 501; variants.push(s);
    let mut s = grant(); s.fields.insert(Field::Notes); variants.push(s);
    let mut s = grant(); s.permissions.insert(Permission::SecretWrite); variants.push(s);
    let mut s = grant(); s.destinations.insert("evil".into()); variants.push(s);
    for spec in variants {
        assert_eq!(app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Share {
            record: r.record, expected: 1, grant: spec }, 3).unwrap_err(), Error::Denied);
    }
    let mut spec = grant(); spec.permissions.insert(Permission::AccessGrant);
    assert_eq!(app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Share {
        record: r.record, expected: 1, grant: spec }, 3).unwrap_err(), Error::Invalid);
    assert_eq!(app.records[&r.record].revision, 1);
    assert!(app.grants.is_empty());
}

#[test]
fn patches_cannot_widen_policy_and_stale_updates_do_not_mutate() {
    let (mut app, ta, tb, r) = setup();
    share(&mut app, ta, r.record, grant());
    assert_eq!(app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Patch {
        record: r.record, expected: 1, values: input(&[(Field::Password, "stale-fake")]),
    }, 4).unwrap_err(), Error::Conflict);
    let updated = app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Patch {
        record: r.record, expected: 2, values: input(&[(Field::Password, "new-fake-password")]),
    }, 4).unwrap();
    assert_eq!(updated.revision, 3);
    let stored = &app.records[&r.record];
    assert_eq!(stored.created_by, "a");
    assert_eq!(stored.task, ta);
    assert_eq!(stored.origin, "https://service.example.invalid");
    assert_eq!(stored.secret_version, 2);
    assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 5,
        |_| panic!("rotation must invalidate pinned grant")).unwrap_err(), Error::Denied);
    assert_eq!(app.read_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), 5).unwrap_err(), Error::Denied);
}

#[test]
fn create_and_patch_retries_are_scoped_and_changed_inputs_conflict() {
    let (mut app, ta, _, r) = setup();
    let request = Uuid::new_v4();
    let operation = Mutation::Create { kind: CredentialKind::ApiKey, values: input(&[(Field::ApiKey, "fake-api-key")]) };
    let first = app.mutate(&agent("a"), ta, request, operation.clone(), 3).unwrap();
    assert_eq!(app.mutate(&agent("a"), ta, request, operation, 3).unwrap(), first);
    assert_eq!(app.records.len(), 2);
    let changed = Mutation::Create { kind: CredentialKind::ApiKey, values: input(&[(Field::ApiKey, "different-fake-key")]) };
    assert_eq!(app.mutate(&agent("a"), ta, request, changed, 3).unwrap_err(), Error::ReplayConflict);
    let request = Uuid::new_v4();
    let patch = Mutation::Patch { record: r.record, expected: 1, values: input(&[(Field::Notes, "new-note")]) };
    let first = app.mutate(&agent("a"), ta, request, patch.clone(), 4).unwrap();
    assert_eq!(app.mutate(&agent("a"), ta, request, patch, 4).unwrap(), first);
    assert_eq!(app.records[&r.record].revision, 2);
    app.revoke_task(&admin(), ta, 5).unwrap();
    let patch = Mutation::Patch { record: r.record, expected: 1, values: input(&[(Field::Notes, "new-note")]) };
    assert_eq!(app.mutate(&agent("a"), ta, request, patch, 5).unwrap_err(), Error::Denied);
}

#[test]
fn grant_revocation_cannot_be_bypassed_by_write_retry() {
    let (mut app, ta, tb, r) = setup();
    // Human approval, not A's bounded sharing, permits this explicit write grant.
    let human = approval("human");
    let th = human.id;
    app.approve_task(&admin(), human, 3).unwrap();
    let mut spec = grant();
    spec.permissions = permissions(&[Permission::SecretWrite]);
    let shared = app.mutate(&admin(), th, Uuid::new_v4(), Mutation::Share {
        record: r.record, expected: 1, grant: spec,
    }, 3).unwrap();
    let request = Uuid::new_v4();
    let patch = Mutation::Patch { record: r.record, expected: 2, values: input(&[(Field::Password, "b-fake-password")]) };
    app.mutate(&agent("b"), tb, request, patch.clone(), 4).unwrap();
    app.mutate(&admin(), th, Uuid::new_v4(), Mutation::Revoke {
        record: r.record, expected: 3, grant: shared.grant.unwrap(),
    }, 5).unwrap();
    assert_eq!(app.mutate(&agent("b"), tb, request, patch, 5).unwrap_err(), Error::Denied);
    assert_eq!(app.records[&r.record].revision, 4);
    assert_eq!(app.records[&r.record].created_by, "a");
    assert_eq!(app.records[&r.record].task, ta);
}

#[test]
fn delete_erases_fields_and_retries_without_double_revision() {
    let (mut app, ta, tb, r) = setup();
    share(&mut app, ta, r.record, grant());
    let request = Uuid::new_v4();
    let op = Mutation::Delete { record: r.record, expected: 2 };
    let deleted = app.mutate(&agent("a"), ta, request, op.clone(), 4).unwrap();
    assert_eq!(deleted.revision, 3);
    assert_eq!(app.mutate(&agent("a"), ta, request, op, 4).unwrap(), deleted);
    assert!(app.records[&r.record].values.0.is_empty());
    assert_eq!(app.read_secret(&agent("a"), ta, r.record, fields(&[Field::Password]), 4).unwrap_err(), Error::Denied);
    assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 4,
        |_| panic!("deleted record reached adapter")).unwrap_err(), Error::Denied);
}

#[test]
fn ownership_workspace_and_admin_approval_do_not_come_from_agent_input() {
    let (mut app, ta, _, r) = setup();
    assert_eq!(app.approve_task(&agent("a"), approval("b"), 3).unwrap_err(), Error::Denied);
    let mut foreign = agent("a"); foreign.owner = "another-user".into();
    assert_eq!(app.read_secret(&foreign, ta, r.record, fields(&[Field::Password]), 3).unwrap_err(), Error::Denied);
    let mut foreign = agent("a"); foreign.workspace = "other-project".into();
    assert_eq!(app.read_secret(&foreign, ta, r.record, fields(&[Field::Password]), 3).unwrap_err(), Error::Denied);
    // AuthenticatedContext intentionally has no Deserialize implementation.
}

#[test]
fn expiry_and_clock_rollback_fail_closed_even_after_time_catches_up() {
    let (mut app, ta, _, r) = setup();
    assert_eq!(app.read_secret(&agent("a"), ta, r.record, fields(&[Field::Password]), 1000).unwrap_err(), Error::Denied);
    let (mut app, ta, _, r) = setup();
    app.read_secret(&agent("a"), ta, r.record, fields(&[Field::Password]), 20).unwrap();
    assert_eq!(app.read_secret(&agent("a"), ta, r.record, fields(&[Field::Password]), 19).unwrap_err(), Error::ClockRecoveryRequired);
    assert_eq!(app.read_secret(&agent("a"), ta, r.record, fields(&[Field::Password]), 21).unwrap_err(), Error::ClockRecoveryRequired);
}

#[test]
fn outcome_reports_cannot_claim_verified_adapter_evidence_and_unknown_keeps_secret() {
    let (mut app, ta, _, r) = setup();
    assert_eq!(app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::ReportOutcome {
        record: r.record, expected: 1, state: SignupState::VerifiedLogin,
    }, 3).unwrap_err(), Error::Denied);
    app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::ReportOutcome {
        record: r.record, expected: 1, state: SignupState::Unknown,
    }, 3).unwrap();
    assert_eq!(app.records[&r.record].signup, SignupState::Unknown);
    assert_eq!(app.read_secret(&agent("a"), ta, r.record, fields(&[Field::Password]), 4).unwrap().expose()[&Field::Password], "FAKE-canary-password");
}

#[test]
fn metadata_only_task_cannot_read_use_write_or_create() {
    let (mut app, ta, _, r) = setup();
    let mut limited = approval("a");
    limited.fields = fields(&[Field::Label]);
    limited.permissions = permissions(&[Permission::MetadataRead]);
    limited.share = None;
    let tl = limited.id;
    app.approve_task(&admin(), limited, 3).unwrap();
    assert_eq!(app.mutate(&agent("a"), tl, Uuid::new_v4(), Mutation::Create {
        kind: CredentialKind::Login, values: input(&[(Field::Label, "fake-label")]),
    }, 3).unwrap_err(), Error::Denied);
    assert_eq!(app.read_secret(&agent("a"), tl, r.record, fields(&[Field::Password]), 3).unwrap_err(), Error::Denied);
    assert!(app.read_secret(&agent("a"), ta, r.record, fields(&[Field::Password]), 3).is_ok());
}

#[test]
fn audit_and_error_output_have_no_credential_content() {
    let (mut app, ta, tb, r) = setup();
    share(&mut app, ta, r.record, grant());
    app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 4,
        |_| Ok(DeliveryStatus::Unknown)).unwrap();
    let events = app.audit_events(&admin()).unwrap();
    assert!(events.iter().any(|e| e.action == AuditAction::SecretUse));
    let encoded = serde_json::to_string(&events).unwrap();
    let debug = format!("{events:?}");
    for output in [encoded, debug] {
        for private in ["FAKE-canary-password", "fixture-user", "fixture-note", "synthetic"] {
            assert!(!output.contains(private));
        }
    }
    assert!(matches!(app.audit_events(&agent("b")), Err(Error::Denied)));
    let error = app.read_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), 4).unwrap_err();
    assert_eq!(error.to_string(), "access denied");
    assert!(!format!("{error:?}").contains("FAKE-canary"));
}

#[test]
fn forged_request_authority_and_policy_fields_are_rejected() {
    let forged = r#"{"Create":{"kind":"Login","values":{"Password":"fake"},"admin":true}}"#;
    assert!(serde_json::from_str::<Mutation>(forged).is_err());
    let forged = r#"{"Patch":{"record":"00000000-0000-0000-0000-000000000001","expected":1,"values":{"Password":"fake"},"owner":"other"}}"#;
    assert!(serde_json::from_str::<Mutation>(forged).is_err());
}

#[test]
fn share_revision_and_invalid_empty_requests_preserve_state() {
    let (mut app, ta, _, r) = setup();
    share(&mut app, ta, r.record, grant());
    assert_eq!(app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Share {
        record: r.record, expected: 1, grant: grant(),
    }, 4).unwrap_err(), Error::Conflict);
    assert_eq!(app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Patch {
        record: r.record, expected: 2, values: input(&[]),
    }, 4).unwrap_err(), Error::Invalid);
    assert_eq!(app.records[&r.record].revision, 2);
    assert_eq!(app.grants.len(), 1);
}

#[test]
fn username_patch_invalidates_entire_pinned_grant_and_follow_active_is_rejected() {
    let (mut app, ta, tb, r) = setup();
    let mut following = grant(); following.follow_active = true;
    assert_eq!(app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Share {
        record: r.record, expected: 1, grant: following,
    }, 3).unwrap_err(), Error::Invalid);
    share(&mut app, ta, r.record, grant());
    app.mutate(&agent("a"), ta, Uuid::new_v4(), Mutation::Patch {
        record: r.record, expected: 2, values: input(&[(Field::Username, "changed-fixture-user")]),
    }, 4).unwrap();
    assert_eq!(app.records[&r.record].secret_version, 2);
    assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 5,
        |_| panic!("username rotation must invalidate the whole grant")).unwrap_err(), Error::Denied);
}

#[test]
fn issuer_task_revocation_and_expiry_invalidate_grants_and_cached_retries() {
    for revoke in [true, false] {
        let (mut app, ta, tb, r) = setup();
        let request = Uuid::new_v4();
        let op = Mutation::Share { record: r.record, expected: 1, grant: grant() };
        app.mutate(&agent("a"), ta, request, op.clone(), 3).unwrap();
        if revoke { app.revoke_task(&admin(), ta, 4).unwrap(); }
        else { app.tasks.get_mut(&ta).unwrap().expires_at = 4; }
        assert_eq!(app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 4,
            |_| panic!("inactive issuer task reached private delivery")).unwrap_err(), Error::Denied);
        assert_eq!(app.mutate(&agent("a"), ta, request, op, 4).unwrap_err(), Error::Denied);
    }
}

#[test]
fn write_retry_is_denied_after_its_own_pinned_version_is_replaced() {
    let (mut app, _, tb, r) = setup();
    let human = approval("human"); let th = human.id;
    app.approve_task(&admin(), human, 3).unwrap();
    let mut spec = grant(); spec.permissions = permissions(&[Permission::SecretWrite]);
    app.mutate(&admin(), th, Uuid::new_v4(), Mutation::Share { record: r.record, expected: 1, grant: spec }, 3).unwrap();
    let request = Uuid::new_v4();
    let op = Mutation::Patch { record: r.record, expected: 2, values: input(&[(Field::Username, "new-synthetic-user")]) };
    app.mutate(&agent("b"), tb, request, op.clone(), 4).unwrap();
    assert_eq!(app.mutate(&agent("b"), tb, request, op, 4).unwrap_err(), Error::Denied);
}

#[test]
fn rejected_and_human_required_delivery_statuses_are_safe() {
    for status in [DeliveryStatus::Rejected, DeliveryStatus::HumanRequired] {
        let (mut app, ta, tb, r) = setup();
        share(&mut app, ta, r.record, grant());
        let result = app.use_secret(&agent("b"), tb, r.record, fields(&[Field::Password]), "test-service", 4,
            |_| Ok(status)).unwrap();
        assert_eq!(result.status, status);
        assert!(!serde_json::to_string(&result).unwrap().contains("FAKE-canary"));
    }
}
