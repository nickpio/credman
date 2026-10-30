use super::*;
use super::tests::fixture_with_approvals;
use super::super::tests::{admin, agent, approval, fields, grant};
use crate::agent_bridge::Sessions;
use crate::agent_ipc::FramedChannel;
use serde_json::json;
use std::cell::Cell;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn attach(sessions: &mut Sessions, task: Uuid, now: Time, expiry: Time)
    -> (Uuid, AuthenticatedContext, [FramedChannel<()>; 2]) {
    let issued = sessions.issue("b".into(), vec![task], expiry, now)
        .expect("session issuance must succeed");
    let token = issued["session"]["token"].as_str().expect("issued token missing");
    let (server, client) = UnixStream::pair().expect("private attachment pair unavailable");
    let mut client = FramedChannel::new(client, (), Duration::from_secs(2), Duration::from_secs(2))
        .expect("attachment framing unavailable");
    client.send(&json!({"op":"attach", "token":token})).expect("attachment request failed");
    let (session, context, server) = sessions.admit(server, now)
        .expect("real one-use token admission must succeed");
    assert!(client.receive().expect("attachment acknowledgement missing") == json!({"ok":true}));
    (session, context, [client, server])
}

fn successful_uses(owner: &DurableVault) -> usize {
    owner.audit_events(&admin()).expect("trusted audit unavailable").iter()
        .filter(|event| event.action == AuditAction::SecretUse).count()
}

#[test]
fn attached_session_expiry_cancels_final_handoff_and_live_retry() {
    let base = chrono::Utc::now().timestamp();
    let task_expiry = base + 3600;
    let grant_expiry = base + 1800;
    let mut a = approval("a");
    let mut b = approval("b");
    for task in [&mut a, &mut b] {
        task.expires_at = task_expiry;
        task.share.as_mut().unwrap().expires_at = task_expiry;
    }
    let mut f = fixture_with_approvals(a, b);
    let retained_directory = f.dir.keep();
    let mut spec = grant();
    spec.expires_at = grant_expiry;
    let shared = f.owner.mutate(&agent("a"), f.ta, Uuid::new_v4(), Mutation::Share {
        record: f.receipt.record, expected: 1, grant: spec,
    }, 3).expect("delegation must succeed");
    let grant_id = shared.grant.expect("grant reference missing");

    let admitted_at = chrono::Utc::now().timestamp();
    let session_expiry = admitted_at + 30;
    assert!(session_expiry < task_expiry && session_expiry < grant_expiry);
    let mut sessions = Sessions::new("user".into(), "project".into(), "human".into(),
        Some("/synthetic/session-expiry.sock".into()), task_expiry);
    let (session, context, _channels) = attach(&mut sessions, f.tb, admitted_at, session_expiry);
    assert!(sessions.permits(session, f.tb, admitted_at));
    assert!(!sessions.permits(session, f.tb, session_expiry));
    assert!(f.owner.app.tasks[&f.tb].expires_at > session_expiry);
    assert!(f.owner.app.tasks[&f.ta].expires_at > session_expiry);
    assert!(f.owner.app.grants[&grant_id].spec.expires_at > session_expiry);
    assert!(!f.owner.app.grants[&grant_id].revoked);
    f.owner.validate_consumer(&context, f.tb, "fake-app", "unix:fake-app", admitted_at)
        .expect("consumer task preflight must remain valid");

    let request = |id| PrivateUse { request: id, record: f.receipt.record,
        fields: fields(&[Field::Username, Field::Password]), destination: "fake-app".into(),
        action: PrivateAction::Use };
    let live_calls = Cell::new(0usize);
    let live = f.owner.use_secret(&context, f.tb, request(Uuid::new_v4()), &mut || admitted_at, |values| {
        assert!(values.len() == 2 && values.contains_key(&Field::Username) && values.contains_key(&Field::Password));
        live_calls.set(live_calls.get() + 1);
        Ok(DeliveryStatus::Accepted)
    }).expect("live-session control must deliver");
    assert!(live.status == DeliveryStatus::Accepted && live_calls.get() == 1);
    let audit_before = successful_uses(&f.owner);
    assert!(audit_before == 1);

    assert!(sessions.permits(session, f.tb, admitted_at));
    let expired_request = Uuid::new_v4();
    let expired_calls = Cell::new(0usize);
    let mut samples = [admitted_at, session_expiry].into_iter();
    let outcome = f.owner.use_secret(&context, f.tb, request(expired_request),
        &mut || samples.next().expect("unexpected trusted clock sample"), |_| {
            expired_calls.set(expired_calls.get() + 1);
            Ok(DeliveryStatus::Accepted)
        });
    assert!(samples.next().is_none());
    assert!(expired_calls.get() == 0, "expired session must not reach private callback");
    assert!(matches!(outcome, Err(Error::Denied)));
    let journal = f.owner.app.deliveries.values().find(|d| d.key.id == expired_request)
        .expect("delivery intent must exist");
    assert!(!journal.dispatched && journal.status == Some(DeliveryStatus::Rejected));
    assert!(!retained_directory.join(PENDING).exists());
    assert!(successful_uses(&f.owner) == audit_before);

    drop(f.owner);
    let mut owner = DurableVault::open(&retained_directory, &f.seed)
        .expect("cancelled delivery must reopen safely");
    let journal = owner.app.deliveries.values().find(|d| d.key.id == expired_request)
        .expect("cancelled journal must survive reopen");
    assert!(!journal.dispatched && journal.status == Some(DeliveryStatus::Rejected));
    assert!(successful_uses(&owner) == audit_before);

    let retry_at = session_expiry + 1;
    let (renewed_session, renewed_context, _renewed_channels) =
        attach(&mut sessions, f.tb, retry_at, session_expiry + 60);
    assert!(sessions.permits(renewed_session, f.tb, retry_at));
    assert!(owner.app.select(&renewed_context, f.tb, f.receipt.record,
        &fields(&[Field::Username, Field::Password]), Permission::SecretUse, Some("fake-app"), retry_at).is_ok(),
        "newly attached live context must otherwise authorize this private use");
    let retry_calls = Cell::new(0usize);
    let retry = owner.use_secret(&renewed_context, f.tb, request(expired_request), &mut || retry_at, |_| {
        retry_calls.set(retry_calls.get() + 1);
        Ok(DeliveryStatus::Accepted)
    });
    assert!(matches!(retry, Err(Error::Denied)));
    assert!(retry_calls.get() == 0, "cancelled request must not redispatch under renewed authority");
    let journal = owner.app.deliveries.values().find(|d| d.key.id == expired_request).unwrap();
    assert!(!journal.dispatched && journal.status == Some(DeliveryStatus::Rejected));
    assert!(!retained_directory.join(PENDING).exists());
    assert!(successful_uses(&owner) == audit_before);
}
