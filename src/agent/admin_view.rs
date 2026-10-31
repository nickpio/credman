//! Read-only administration projections. Metadata and secret values stay on the task-scoped path.
use serde_json::{json, Map, Value};

use super::*;

const CAPACITY: usize = 10_000;
const PAGE: usize = 100;

impl AuthenticatedContext {
    pub(crate) fn owner(&self) -> &str { &self.owner }
    pub(crate) fn workspace(&self) -> &str { &self.workspace }
}

fn readable(ctx: &AuthenticatedContext, frozen: bool) -> Result<(), Error> {
    if !ctx.admin { return Err(Error::Denied); }
    if frozen { return Err(Error::RecoveryRequired); }
    Ok(())
}

fn count_of(count: usize) -> Value { json!({"count": count, "capacity": CAPACITY}) }

fn status_value(app: &Application, ctx: &AuthenticatedContext, frozen: bool) -> Result<Value, Error> {
    if !ctx.admin { return Err(Error::Denied); }
    let owner = ctx.owner();
    let workspace = ctx.workspace();
    let (live, deleted) = record_counts(app, owner, workspace);
    Ok(json!({
        "tasks": count_of(app.tasks.values().filter(|task| task.owner == owner && task.workspace == workspace).count()),
        "records": {"live": live, "deleted": deleted, "capacity": CAPACITY},
        "grants": count_of(scoped_grants(app, owner, workspace).count()),
        "requests": count_of(app.requests.keys().filter(|key| key.owner == owner && task_in_scope(app, key.task, owner, workspace)).count()),
        "deliveries": count_of(app.deliveries.values().filter(|delivery| delivery.key.owner == owner && task_in_scope(app, delivery.task, owner, workspace)).count()),
        "audit": count_of(app.audit.iter().filter(|event| task_in_scope(app, event.task, owner, workspace)).count()),
        "frozen": frozen,
        "clock_frozen": app.clock_frozen,
    }))
}

fn validate_session_tasks(app: &Application, ctx: &AuthenticatedContext, principal: &str,
    tasks: &[Uuid], now: Time, frozen: bool) -> Result<(), Error> {
    if !ctx.admin { return Err(Error::Denied); }
    if frozen { return Err(Error::RecoveryRequired); }
    if app.clock_frozen { return Err(Error::ClockRecoveryRequired); }
    if tasks.is_empty() || tasks.iter().any(|id| app.tasks.get(id).is_none_or(|task|
        task.owner != ctx.owner() || task.workspace != ctx.workspace() || task.principal != principal
        || now >= task.expires_at || app.revoked_tasks.contains(id)))
    { return Err(Error::Invalid); }
    Ok(())
}

fn tasks_page(app: &Application, ctx: &AuthenticatedContext, offset: usize, frozen: bool) -> Result<Value, Error> {
    readable(ctx, frozen)?;
    let owner = ctx.owner();
    let workspace = ctx.workspace();
    let items = app.tasks.values().filter(|task| task.owner == owner && task.workspace == workspace)
        .map(|task| task_view(task, app.revoked_tasks.contains(&task.id))).collect();
    bounded_page("tasks", items, offset)
}

fn records_page(app: &Application, ctx: &AuthenticatedContext, offset: usize, frozen: bool) -> Result<Value, Error> {
    readable(ctx, frozen)?;
    let items = app.records.values().filter(|record| record.owner == ctx.owner() && record.workspace == ctx.workspace())
        .map(record_view).collect();
    bounded_page("records", items, offset)
}

fn grants_page(app: &Application, ctx: &AuthenticatedContext, offset: usize,
    record: Option<Uuid>, frozen: bool) -> Result<Value, Error> {
    readable(ctx, frozen)?;
    let owner = ctx.owner();
    let workspace = ctx.workspace();
    let items = scoped_grants(app, owner, workspace).filter(|(_, grant)| record.is_none_or(|id| grant.record == id))
        .map(|(id, grant)| grant_view(*id, grant)).collect();
    bounded_page("grants", items, offset)
}

fn task_in_scope(app: &Application, id: Uuid, owner: &str, workspace: &str) -> bool {
    app.tasks.get(&id).is_some_and(|task| task.owner == owner && task.workspace == workspace)
}

fn record_counts(app: &Application, owner: &str, workspace: &str) -> (usize, usize) {
    app.records.values().filter(|record| record.owner == owner && record.workspace == workspace)
        .fold((0, 0), |(live, deleted), record| if record.deleted { (live, deleted + 1) } else { (live + 1, deleted) })
}

fn scoped_grants<'a>(app: &'a Application, owner: &'a str, workspace: &'a str) -> impl Iterator<Item = (&'a Uuid, &'a Grant)> + 'a {
    app.grants.iter().filter(move |(_, grant)| app.records.get(&grant.record)
        .is_some_and(|record| record.owner == owner && record.workspace == workspace))
}

fn task_view(task: &TaskApproval, revoked: bool) -> Value {
    json!({
        "id": task.id, "owner": task.owner, "principal": task.principal, "workspace": task.workspace,
        "service": task.service, "origin": task.origin, "fields": task.fields, "permissions": task.permissions,
        "destinations": task.destinations, "expires_at": task.expires_at, "share": task.share, "revoked": revoked,
    })
}

/// Record values, including metadata, are intentionally absent.
fn record_view(record: &Record) -> Value {
    json!({
        "id": record.id, "service": record.service, "origin": record.origin, "kind": record.kind,
        "revision": record.revision, "secret_version": record.secret_version, "deleted": record.deleted,
        "signup": record.signup, "created_by": record.created_by, "task": record.task,
    })
}

fn grant_view(id: Uuid, grant: &Grant) -> Value {
    json!({
        "id": id, "record": grant.record, "recipient": grant.spec.recipient, "fields": grant.spec.fields,
        "permissions": grant.spec.permissions, "destinations": grant.spec.destinations,
        "expires_at": grant.spec.expires_at, "revoked": grant.revoked, "version": grant.version,
        "issuer_task": grant.issuer_task,
    })
}

fn page_value(key: &str, items: &[Value], total: usize, has_more: bool) -> Value {
    let mut response = Map::new();
    response.insert("ok".into(), json!(true));
    response.insert(key.into(), Value::Array(items.to_vec()));
    response.insert("total".into(), json!(total));
    response.insert("has_more".into(), json!(has_more));
    Value::Object(response)
}

/// At most 100 entries. A shorter page is returned when that is what fits in one frame.
pub(crate) fn bounded_page(key: &str, items: Vec<Value>, offset: usize) -> Result<Value, Error> {
    let total = items.len();
    let rest: Vec<_> = items.into_iter().skip(offset).take(PAGE).collect();
    if rest.is_empty() { return Ok(page_value(key, &[], total, false)); }
    let mut count = rest.len();
    loop {
        let has_more = offset.saturating_add(count) < total;
        let response = page_value(key, &rest[..count], total, has_more);
        if crate::agent_ipc::fits_frame(&response) { return Ok(response); }
        count -= 1;
        if count == 0 { return Err(Error::Capacity); }
    }
}

#[cfg(target_os = "linux")]
impl super::storage::DurableVault {
    pub(crate) fn operational_status(&self, ctx: &AuthenticatedContext) -> Result<Value, Error> {
        status_value(self.admin_app(), ctx, self.admin_frozen())
    }
    pub(crate) fn list_tasks(&self, ctx: &AuthenticatedContext, offset: usize) -> Result<Value, Error> {
        tasks_page(self.admin_app(), ctx, offset, self.admin_frozen())
    }
    pub(crate) fn list_records(&self, ctx: &AuthenticatedContext, offset: usize) -> Result<Value, Error> {
        records_page(self.admin_app(), ctx, offset, self.admin_frozen())
    }
    pub(crate) fn list_grants(&self, ctx: &AuthenticatedContext, offset: usize, record: Option<Uuid>) -> Result<Value, Error> {
        grants_page(self.admin_app(), ctx, offset, record, self.admin_frozen())
    }
    pub(crate) fn validate_session_tasks(&self, ctx: &AuthenticatedContext, principal: &str, tasks: &[Uuid], now: Time) -> Result<(), Error> {
        validate_session_tasks(self.admin_app(), ctx, principal, tasks, now, self.admin_frozen())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::tests::{admin, agent as peer, approval, grant, setup};
    use crate::agent_ipc::fits_frame;
    use std::collections::BTreeSet;

    const CANARIES: [&str; 4] = ["FAKE-canary-password", "fixture-user", "fixture-note", "synthetic"];

    fn encoded_clean(value: &Value) {
        let encoded = serde_json::to_string(value).unwrap();
        for canary in CANARIES { assert!(!encoded.contains(canary), "{canary} in {encoded}"); }
        assert!(fits_frame(value));
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    }

    #[test]
    fn status_and_lists_omit_secret_and_metadata_values() {
        let (mut app, ta, _, receipt) = setup();
        let status = status_value(&app, &admin(), false).unwrap();
        encoded_clean(&status);
        assert_eq!(status["tasks"]["count"], 2);
        assert_eq!(status["tasks"]["capacity"], CAPACITY);
        assert_eq!(status["records"], json!({"live": 1, "deleted": 0, "capacity": CAPACITY}));
        assert_eq!(status["grants"]["count"], 0);
        assert_eq!(status["requests"]["count"], 1);
        assert_eq!(status["deliveries"]["count"], 0);
        assert_eq!(status["audit"]["count"], 1);
        assert_eq!(status["frozen"], false);
        assert_eq!(status["clock_frozen"], false);
        assert_eq!(keys(&status), ["audit", "clock_frozen", "deliveries", "frozen", "grants", "records", "requests", "tasks"]
            .into_iter().map(str::to_owned).collect());

        let records = records_page(&app, &admin(), 0, false).unwrap();
        encoded_clean(&records);
        assert_eq!(records["total"], 1);
        assert_eq!(records["has_more"], false);
        let record = &records["records"][0];
        assert_eq!(record["id"], json!(receipt.record));
        assert_eq!(record["service"], "test-service");
        assert_eq!(record["origin"], "https://service.example.invalid");
        assert_eq!(record["kind"], "Login");
        assert_eq!(record["revision"], 1);
        assert_eq!(record["secret_version"], 1);
        assert_eq!(record["deleted"], false);
        assert_eq!(record["signup"], "Pending");
        assert_eq!(record["created_by"], "a");
        assert_eq!(record["task"], json!(ta));
        assert_eq!(keys(record), ["created_by", "deleted", "id", "kind", "origin", "revision", "secret_version", "service", "signup", "task"]
            .into_iter().map(str::to_owned).collect());

        let shared = app.mutate(&peer("a"), ta, Uuid::new_v4(), Mutation::Share {
            record: receipt.record, expected: 1, grant: grant(),
        }, 3).unwrap();
        let grants = grants_page(&app, &admin(), 0, None, false).unwrap();
        encoded_clean(&grants);
        assert_eq!(grants["total"], 1);
        let listed = &grants["grants"][0];
        assert_eq!(listed["id"], json!(shared.grant.unwrap()));
        assert_eq!(listed["record"], json!(receipt.record));
        assert_eq!(listed["recipient"], "b");
        assert_eq!(listed["revoked"], false);
        assert_eq!(listed["version"], 1);
        assert_eq!(listed["issuer_task"], json!(ta));
        assert_eq!(listed["expires_at"], 100);
        assert!(listed.get("values").is_none() && listed.get("follow_active").is_none());
        assert_eq!(grants_page(&app, &admin(), 0, Some(receipt.record), false).unwrap()["total"], 1);
        assert_eq!(grants_page(&app, &admin(), 0, Some(Uuid::new_v4()), false).unwrap()["total"], 0);

        app.mutate(&peer("a"), ta, Uuid::new_v4(), Mutation::Delete { record: receipt.record, expected: 2 }, 4).unwrap();
        let deleted = records_page(&app, &admin(), 0, false).unwrap();
        encoded_clean(&deleted);
        assert_eq!(deleted["records"][0]["deleted"], true);
        assert_eq!(grants_page(&app, &admin(), 0, Some(receipt.record), false).unwrap()["grants"][0]["revoked"], true);
        let after = status_value(&app, &admin(), true).unwrap();
        encoded_clean(&after);
        assert_eq!(after["records"], json!({"live": 0, "deleted": 1, "capacity": CAPACITY}));
        assert_eq!(after["grants"]["count"], 1);
        assert_eq!(after["requests"]["count"], 3);
        assert_eq!(after["frozen"], true);

        let other = AuthenticatedContext::from_authenticated_admin("user".into(), "human".into(), "elsewhere".into());
        assert_eq!(records_page(&app, &other, 0, false).unwrap()["total"], 0);
        assert_eq!(status_value(&app, &other, false).unwrap()["tasks"]["count"], 0);
        assert_eq!(status_value(&app, &peer("a"), false).unwrap_err(), Error::Denied);
        assert_eq!(records_page(&app, &admin(), 0, true).unwrap_err(), Error::RecoveryRequired);
        assert_eq!(tasks_page(&app, &admin(), 0, true).unwrap_err(), Error::RecoveryRequired);
        assert_eq!(grants_page(&app, &admin(), 0, None, true).unwrap_err(), Error::RecoveryRequired);
    }

    #[test]
    fn task_lists_are_paged_without_crossing_the_frame() {
        let mut app = Application::default();
        for _ in 0..101 {
            let task = approval("a");
            app.approve_task(&admin(), task, 1).unwrap();
        }
        let mut seen = 0usize;
        let mut offset = 0usize;
        loop {
            let page = tasks_page(&app, &admin(), offset, false).unwrap();
            encoded_clean(&page);
            let count = page["tasks"].as_array().unwrap().len();
            assert!(count <= PAGE && (page["has_more"] == true || count > 0 || offset >= 101));
            assert_eq!(page["total"], 101);
            assert!(page["tasks"].as_array().unwrap().iter().all(|task| task.get("values").is_none()));
            seen += count;
            if page["has_more"] != true { break; }
            assert!(count > 0);
            offset += count;
        }
        assert_eq!(seen, 101);
        assert_eq!(tasks_page(&app, &admin(), 101, false).unwrap()["tasks"].as_array().unwrap().len(), 0);

        let fat = "x".repeat(40_000);
        let items = vec![json!(fat.clone()), json!(fat), json!("tail")];
        let first = bounded_page("records", items.clone(), 0).unwrap();
        assert_eq!(first["records"].as_array().unwrap().len(), 1);
        assert_eq!(first["has_more"], true);
        assert!(fits_frame(&first));
        assert_eq!(bounded_page("records", items, 2).unwrap()["records"][0], "tail");
        assert_eq!(bounded_page("records", vec![json!("y".repeat(70_000))], 0).unwrap_err(), Error::Capacity);
    }

    #[test]
    fn session_tasks_must_exist_for_the_principal_and_stay_usable() {
        let (mut app, ta, tb, _) = setup();
        assert!(validate_session_tasks(&app, &admin(), "a", &[ta], 10, false).is_ok());
        assert_eq!(validate_session_tasks(&app, &admin(), "b", &[ta], 10, false), Err(Error::Invalid));
        assert_eq!(validate_session_tasks(&app, &admin(), "a", &[tb], 10, false), Err(Error::Invalid));
        assert_eq!(validate_session_tasks(&app, &admin(), "a", &[Uuid::new_v4()], 10, false), Err(Error::Invalid));
        assert_eq!(validate_session_tasks(&app, &admin(), "a", &[ta, tb], 10, false), Err(Error::Invalid));
        assert_eq!(validate_session_tasks(&app, &admin(), "a", &[], 10, false), Err(Error::Invalid));
        assert_eq!(validate_session_tasks(&app, &admin(), "a", &[ta], 1000, false), Err(Error::Invalid));
        assert!(validate_session_tasks(&app, &admin(), "a", &[ta], 999, false).is_ok());
        let elsewhere = AuthenticatedContext::from_authenticated_admin("user".into(), "human".into(), "elsewhere".into());
        assert_eq!(validate_session_tasks(&app, &elsewhere, "a", &[ta], 10, false), Err(Error::Invalid));
        assert_eq!(validate_session_tasks(&app, &peer("a"), "a", &[ta], 10, false), Err(Error::Denied));
        assert_eq!(validate_session_tasks(&app, &admin(), "a", &[ta], 10, true), Err(Error::RecoveryRequired));
        app.revoke_task(&admin(), ta, 3).unwrap();
        assert_eq!(validate_session_tasks(&app, &admin(), "a", &[ta], 4, false), Err(Error::Invalid));
        app.clock_frozen = true;
        assert_eq!(validate_session_tasks(&app, &admin(), "b", &[tb], 4, false), Err(Error::ClockRecoveryRequired));
    }
}
