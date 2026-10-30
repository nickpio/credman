use super::*;
use super::tests::{fixture, fixture_with_approvals};
use super::super::tests::{admin, agent, approval, fields, grant};

#[test]
fn copied_record_cannot_register_even_without_a_prior_delivery_journal() {
    let mut f = fixture();
    f.owner.apply(|app| {
        app.records.get_mut(&f.receipt.record).unwrap().restored = true;
        Ok(())
    }).unwrap();
    let req = request(f.receipt.record, PrivateAction::Register);
    let mut dispatched = false;
    let result = f.owner.use_secret(&agent("a"), f.ta, req, &mut || 3, |_| {
        dispatched = true;
        Ok(DeliveryStatus::Accepted)
    });
    assert!(!dispatched, "copied credentials must not invite a fresh registration");
    assert_eq!(result.unwrap_err(), Error::Conflict);
}

pub(super) fn request(record: Uuid, action: PrivateAction) -> PrivateUse {
    PrivateUse { request: Uuid::new_v4(), record, fields: fields(&[Field::Username, Field::Password]),
        destination: "fake-app".into(), action }
}

#[test]
fn private_request_retry_after_restart_is_once_only_and_changed_input_conflicts() {
    let mut f = fixture();
    let req = request(f.receipt.record, PrivateAction::Use);
    let first = f.owner.use_secret(&agent("a"), f.ta, req.clone(), &mut || 3, |_| Ok(DeliveryStatus::Accepted)).unwrap();
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    let retry = owner.use_secret(&agent("a"), f.ta, req.clone(), &mut || 4, |_| panic!("duplicate dispatch")).unwrap();
    assert_eq!(retry, first);
    assert_eq!(owner.app.deliveries.len(), 1);
    let mut changed = req.clone(); changed.action = PrivateAction::Login;
    assert_eq!(owner.use_secret(&agent("a"), f.ta, changed, &mut || 4,
        |_| panic!("changed request dispatched")).unwrap_err(), Error::ReplayConflict);
    owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Patch { record: req.record, expected: 1,
        values: super::super::tests::input(&[(Field::Username, "rotated-synthetic-user")]) }, 4).unwrap();
    assert_eq!(owner.use_secret(&agent("a"), f.ta, req, &mut || 4,
        |_| panic!("old-version request dispatched")).unwrap_err(), Error::Denied);
}

#[test]
fn unknown_registration_cannot_be_replayed_by_new_id_report_or_restart_and_login_reconciles() {
    let mut f = fixture();
    let register = request(f.receipt.record, PrivateAction::Register);
    assert_eq!(f.owner.use_secret(&agent("a"), f.ta, register.clone(), &mut || 3,
        |_| Err(Error::InteractionRequired)).unwrap_err(), Error::InteractionRequired);
    assert_eq!(f.owner.app.records[&register.record].signup, SignupState::Unknown);
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    let prior = owner.use_secret(&agent("a"), f.ta, register.clone(), &mut || 4,
        |_| panic!("unknown registration replayed")).unwrap();
    assert_eq!(prior.status, DeliveryStatus::Unknown);
    owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::ReportOutcome {
        record: register.record, expected: 1, state: SignupState::Pending,
    }, 4).unwrap();
    let duplicate = request(register.record, PrivateAction::Register);
    assert_eq!(owner.use_secret(&agent("a"), f.ta, duplicate, &mut || 4,
        |_| panic!("new request bypassed registration guard")).unwrap_err(), Error::Conflict);
    let login = request(register.record, PrivateAction::Login);
    owner.use_secret(&agent("a"), f.ta, login, &mut || 4, |values| {
        assert!(values.contains_key(&Field::Password) && values.contains_key(&Field::Username));
        Ok(DeliveryStatus::Accepted)
    }).unwrap();
    assert_eq!(owner.app.records[&register.record].signup, SignupState::VerifiedLogin);
    drop(owner);
    let owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.app.records[&register.record].signup, SignupState::VerifiedLogin);
}

#[test]
fn final_clock_rollback_cancels_dispatch_and_persists_clock_gate() {
    let mut f = fixture();
    let req = request(f.receipt.record, PrivateAction::Register);
    let mut samples = [4, 3].into_iter();
    assert_eq!(f.owner.use_secret(&agent("a"), f.ta, req, &mut || samples.next().unwrap(),
        |_| panic!("rollback dispatched")).unwrap_err(), Error::ClockRecoveryRequired);
    assert!(f.owner.app.clock_frozen);
    assert!(f.owner.app.deliveries.values().all(|d| !d.dispatched && d.status == Some(DeliveryStatus::Rejected)));
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    assert_eq!(owner.read_secret(&agent("a"), f.ta, f.receipt.record, fields(&[Field::Password]), 5).unwrap_err(), Error::ClockRecoveryRequired);
}


#[test]
fn request_namespaces_and_untrusted_verified_status_fail_closed() {
    let mut f = fixture();
    let req = request(f.receipt.record, PrivateAction::Use);
    f.owner.use_secret(&agent("a"), f.ta, req.clone(), &mut || 3, |_| Ok(DeliveryStatus::Accepted)).unwrap();
    assert_eq!(f.owner.mutate(&agent("a"), f.ta, req.request, Mutation::ReportOutcome {
        record: req.record, expected: 1, state: SignupState::Pending,
    }, 3).unwrap_err(), Error::ReplayConflict);
    assert_eq!(f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::ReportOutcome {
        record: req.record, expected: 1, state: SignupState::VerifiedLogin,
    }, 3).unwrap_err(), Error::Denied);
    let mut invalid = f.owner.app.clone();
    invalid.records.get_mut(&req.record).unwrap().signup = SignupState::VerifiedLogin;
    assert!(matches!(snapshot::encode(&invalid), Err(Error::InvalidStorage)));
}

#[test]
fn adapter_error_cannot_claim_storage_nonpublication_after_dispatch() {
    let mut f = fixture();
    let req = request(f.receipt.record, PrivateAction::Register);
    let mut called = false;
    let result = f.owner.use_secret(&agent("a"), f.ta, req.clone(), &mut || 3, |_| {
        called = true;
        Err(Error::NotPublished)
    });
    assert!(called);
    assert_eq!(result.unwrap_err(), Error::InteractionRequired);
    drop(f.owner);
    let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
    let replay = owner.use_secret(&agent("a"), f.ta, req, &mut || 4,
        |_| panic!("failed external action was replayed")).unwrap();
    assert_eq!(replay.status, DeliveryStatus::Unknown);
}

#[test]
fn delegated_handoff_rechecks_grant_recipient_and_issuer_expiry_and_resolves_intent() {
    for (case, issuer_expiry, recipient_expiry, grant_expiry, handoff) in [
        ("grant", 1000, 1000, 100, 100),
        ("recipient", 1000, 50, 100, 50),
        // Grant attenuation also caps its expiry at the issuer task's deadline.
        ("issuer_and_attenuated_grant", 50, 1000, 50, 50),
    ] {
        let mut issuer = approval("a");
        let mut recipient = approval("b");
        for (task, expiry) in [(&mut issuer, issuer_expiry), (&mut recipient, recipient_expiry)] {
            task.expires_at = expiry;
            if let Some(bounds) = &mut task.share { bounds.expires_at = bounds.expires_at.min(expiry); }
        }
        let mut f = fixture_with_approvals(issuer, recipient);
        let mut spec = grant();
        spec.expires_at = grant_expiry;
        f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Share {
            record: f.receipt.record, expected: 1, grant: spec,
        }, 3).unwrap();
        let req = request(f.receipt.record, PrivateAction::Use);
        let mut samples = [4, handoff].into_iter();
        let result = f.owner.use_secret(&agent("b"), f.tb, req.clone(),
            &mut || samples.next().expect("unexpected clock sample"),
            |_| panic!("expired delegated authority reached adapter"));
        assert_eq!(result.unwrap_err(), Error::Denied, "{case}");
        assert_eq!(f.owner.app.deliveries.len(), 1);
        assert!(f.owner.app.deliveries.values().all(|d|
            !d.dispatched && d.status == Some(DeliveryStatus::Rejected)), "{case}");
        drop(f.owner);
        let mut owner = DurableVault::open(f.dir.path(), &f.seed).unwrap();
        assert!(owner.app.deliveries.values().all(|d|
            !d.dispatched && d.status == Some(DeliveryStatus::Rejected)), "{case}");
        assert_eq!(owner.use_secret(&agent("b"), f.tb, req, &mut || handoff,
            |_| panic!("expired retry dispatched")).unwrap_err(), Error::Denied, "{case}");
        assert!(owner.audit_events(&admin()).is_ok());
    }
}
