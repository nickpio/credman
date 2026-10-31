//! Model-facing credential references and private delivery. No plaintext secret reads.
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::agent::Error;
use crate::agent_broker::WorkRequest;
use crate::agent_ipc::{fits_frame, strict_json, FramedChannel, MAX_FRAME_BYTES};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Initialize {
    protocol_version: String,
    capabilities: Map<String, Value>,
    client_info: ClientInfo,
}
#[derive(Deserialize)]
struct ClientInfo { name: String, version: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call { name: String, arguments: Map<String, Value> }
#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Initialize, Initialized, Ready }

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn result(id: Value, value: Value) -> Value { json!({"jsonrpc":"2.0","id":id,"result":value}) }
fn empty(params: &Option<Value>) -> bool { params.as_ref().is_none_or(|p| p.as_object().is_some_and(|p| p.is_empty())) }
fn first_page(params: &Option<Value>) -> bool {
    params.as_ref().is_none_or(|p| p.as_object().is_some_and(|p|
        p.keys().all(|key| key == "cursor") && p.get("cursor").is_none_or(Value::is_null)))
}

fn dispatch(value: Value, state: &mut State, channel: &mut FramedChannel) -> Option<Value> {
    let Some(object) = value.as_object() else { return Some(error(Value::Null, -32600, "Invalid Request")); };
    let notification = !object.contains_key("id");
    let id = object.get("id").cloned().unwrap_or(Value::Null);
    let valid_id = notification || id.as_str().is_some_and(|s| s.len() <= 256)
        || id.as_i64().is_some() || id.as_u64().is_some();
    let valid = object.get("jsonrpc") == Some(&json!("2.0")) && valid_id
        && object.get("method").and_then(Value::as_str).is_some_and(|s| !s.is_empty() && s.len() <= 128)
        && object.keys().all(|k| ["jsonrpc", "id", "method", "params"].contains(&k.as_str()))
        && object.get("params").is_none_or(Value::is_object);
    if !valid { return if notification { None } else { Some(error(Value::Null, -32600, "Invalid Request")) }; }
    let method = object["method"].as_str().unwrap();
    let mut params = object.get("params").cloned();
    // Only transport-level metadata is discarded. Tool arguments remain intact and typed.
    if let Some(meta) = params.as_mut().and_then(Value::as_object_mut).and_then(|p| p.remove("_meta")) {
        if !meta.as_object().is_some_and(|m|
            m.get("progressToken").is_none_or(|token| token.is_string() || token.is_number())) {
            return if notification { None } else { Some(error(id, -32602, "Invalid params")) };
        }
    }
    if notification {
        if method == "notifications/initialized" && *state == State::Initialized && empty(&params) { *state = State::Ready; }
        return None;
    }
    let response = match method {
        "ping" if empty(&params) => result(id, json!({})),
        "initialize" if *state == State::Initialize => {
            let parsed = params.and_then(|p| serde_json::from_value::<Initialize>(p).ok());
            match parsed {
                Some(p) if !p.protocol_version.is_empty() && p.protocol_version.len() <= 128
                    && !p.client_info.name.is_empty() && p.client_info.name.len() <= 2048
                    && p.client_info.version.len() <= 2048 => {
                    let _ = p.capabilities;
                    let version = if p.protocol_version == "2024-11-05" { "2024-11-05" } else { "2025-11-25" };
                    *state = State::Initialized;
                    result(id, json!({"protocolVersion":version,"capabilities":{"tools":{}},
                        "serverInfo":{"name":"credman","version":env!("CARGO_PKG_VERSION")},
                        "instructions":"Trusted supervisor session identity applies to this entire process. Generate credentials privately and share scoped record references. Secrets cannot be read through MCP. Private use is limited to human-configured HTTPS GET destinations, not registration or verified login."}))
                }
                _ => error(id, -32602, "Invalid params"),
            }
        }
        "tools/list" if *state == State::Ready && first_page(&params) => result(id, json!({"tools":tools()})),
        "tools/call" if *state == State::Ready => {
            let call = params.and_then(|p| serde_json::from_value::<Call>(p).ok());
            match call.and_then(work_request) {
                Some(request) => {
                    let response = if !fits_frame(&request) { json!({"ok":false,"error":"invalid request"}) }
                        else {
                            // A lost reply may follow a committed mutation. Never retry or infer denial.
                            channel.send(&request).and_then(|()| channel.receive()).unwrap_or_else(|_|
                                json!({"ok":false,"error":"owner transport unavailable","outcome":"unknown"}))
                        };
                    let text = serde_json::to_string(&response).unwrap_or_else(|_| "{\"ok\":false}".into());
                    result(id, json!({"content":[{"type":"text","text":text}],
                        "isError":response.get("ok") != Some(&Value::Bool(true)),"structuredContent":response}))
                }
                None => error(id, -32602, "Invalid params"),
            }
        }
        "initialize" | "tools/list" | "tools/call" | "ping" => error(id, -32602, "Invalid params"),
        _ => error(id, -32601, "Method not found"),
    };
    Some(response)
}
fn work_request(call: Call) -> Option<Value> {
    let op = match call.name.as_str() {
        "credman_generate" => "generate", "credman_mutate" => "mutate", "credman_metadata" => "metadata", "credman_use" => "use", _ => return None,
    };
    let mut args = call.arguments;
    // The operation is fixed by the tool name. It cannot be supplied through arguments.
    if args.contains_key("op") { return None; }
    args.insert("op".into(), json!(op));
    let value = Value::Object(args);
    serde_json::from_value::<WorkRequest>(value.clone()).ok()?;
    Some(value)
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
fn tools() -> Value {
    let uuid = json!({"type":"string","format":"uuid"});
    let fields = json!({"type":"array","items":{"enum":["Label","Username","Password","ApiKey","Notes"]},"uniqueItems":true,"minItems":1,"maxItems":5});
    let metadata_fields = json!({"type":"array","items":{"enum":["Label","Username","Notes"]},"uniqueItems":true,"minItems":1,"maxItems":3});
    let values = object(json!({
        "Label":{"type":"string","maxLength":8192},"Username":{"type":"string","maxLength":8192},
        "Notes":{"type":"string","maxLength":8192}}), &[]);
    let mut values = values.as_object().unwrap().clone();
    values.insert("minProperties".into(), json!(1));
    let values = Value::Object(values);
    let grant = object(json!({"recipient":{"type":"string"},"fields":fields,
        "permissions":{"type":"array","items":{"enum":["MetadataRead","SecretUse","SecretWrite","AccessGrant","EntryDelete"]},"uniqueItems":true},
        "destinations":{"type":"array","items":{"type":"string"},"uniqueItems":true},
        "expires_at":{"type":"integer"},"follow_active":{"type":"boolean"}}),
        &["recipient","fields","permissions","destinations","expires_at","follow_active"]);
    let expected = json!({"type":"integer","minimum":0,"maximum":u64::MAX});
    let variants = [
        ("Patch", object(json!({"record":uuid,"expected":expected,"values":values}), &["record","expected","values"])),
        ("Delete", object(json!({"record":uuid,"expected":expected}), &["record","expected"])),
        ("Share", object(json!({"record":uuid,"expected":expected,"grant":grant}), &["record","expected","grant"])),
        ("Revoke", object(json!({"record":uuid,"expected":expected,"grant":uuid}), &["record","expected","grant"])),
        ("ReportOutcome", object(json!({"record":uuid,"expected":expected,"state":{"enum":["Pending","Submitted","ReportedSuccess","Rejected","HumanRequired","Unknown"]}}), &["record","expected","state"])),
    ];
    let mutations: Vec<_> = variants.into_iter().map(|(name, schema)| {
        let mut props = Map::new(); props.insert(name.into(), schema);
        object(Value::Object(props), &[name])
    }).collect();
    let mutate = object(json!({"task":uuid,"request":uuid,"mutation":{"oneOf":mutations}}), &["task","request","mutation"]);
    let metadata = object(json!({"task":uuid,"record":uuid,"fields":metadata_fields}), &["task","record","fields"]);
    let policy = object(json!({"length":{"type":"integer","minimum":16,"maximum":128},
        "symbols":{"type":"boolean"},"require_classes":{"type":"boolean"}}),
        &["length","symbols","require_classes"]);
    let mut generate = object(json!({"task":uuid,"request":uuid,"kind":{"enum":["Login","ApiKey"]},
        "username":{"type":"string","minLength":1,"maxLength":2048},"policy":policy}), &["task","request","kind"]);
    generate["oneOf"] = json!([
        {"properties":{"kind":{"const":"Login"}},"required":["username"]},
        {"properties":{"kind":{"const":"ApiKey"}},"not":{"required":["username"]}}
    ]);
    let usage = object(json!({"request":uuid,"record":uuid,"fields":fields,"destination":{"type":"string"},"action":{"enum":["Use"]}}),
        &["request","record","fields","destination","action"]);
    let usage = object(json!({"task":uuid,"usage":usage}), &["task","usage"]);
    json!([
        {"name":"credman_generate","description":"Privately generate a Login password with the supplied username, or an ApiKey without username. Returns only an idempotent record receipt, never the generated secret.","inputSchema":generate},
        {"name":"credman_mutate","description":"Apply approved metadata-only patches, bounded sharing/revocation, deletion, or outcome reports. Plaintext Create, secret patches and SecretRead grants are forbidden. Does not register accounts or contact services.","inputSchema":mutate},
        {"name":"credman_metadata","description":"Read approved nonsecret record fields.","inputSchema":metadata},
        {"name":"credman_use","description":"Privately authenticate a fixed HTTPS GET to a human-configured destination ID. Fields must exactly match that destination. Returns a delivery receipt only. HTTP acceptance is not verified login or account registration.","inputSchema":usage}
    ])
}

fn line(reader: &mut BufReader<File>, deadline: Instant) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut frame_deadline = deadline;
    loop {
        if reader.buffer().is_empty() { ready(reader.get_ref().as_raw_fd(), libc::POLLIN, frame_deadline)?; }
        let buffer = reader.fill_buf().map_err(|_| Error::Invalid)?;
        if buffer.is_empty() { return if bytes.is_empty() { Ok(None) } else { Err(Error::Invalid) }; }
        if bytes.is_empty() { frame_deadline = deadline.min(Instant::now() + Duration::from_secs(5)); }
        let count = buffer.iter().position(|b| *b == b'\n').map(|n| n + 1).unwrap_or(buffer.len());
        if bytes.len() + count > MAX_FRAME_BYTES + 1 { return Err(Error::Invalid); }
        let complete = buffer[count-1] == b'\n';
        bytes.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        if complete { bytes.pop(); return Ok(Some(bytes)); }
    }
}
fn ready(fd: i32, events: i16, deadline: Instant) -> Result<(), Error> {
    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(Error::Invalid)?;
        let mut poll = libc::pollfd { fd, events, revents: 0 };
        // SAFETY: poll points to one initialized pollfd and the timeout is bounded.
        let result = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().min(i32::MAX as u128) as i32) };
        if result > 0 { return Ok(()); }
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
        return Err(Error::Invalid);
    }
}
fn output(response: Value) -> Result<(), Error> {
    let response = if fits_frame(&response) { response } else {
        error(response.get("id").cloned().unwrap_or(Value::Null), -32603, "Response exceeds limit")
    };
    let mut bytes = Zeroizing::new(serde_json::to_vec(&response).map_err(|_| Error::Invalid)?);
    bytes.push(b'\n');
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut offset = 0;
    while offset < bytes.len() {
        ready(1, libc::POLLOUT, deadline)?;
        // SAFETY: the remaining slice is live for the duration of write. stdout is nonblocking.
        let count = unsafe { libc::write(1, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if count > 0 { offset += count as usize; }
        else if count == 0 || !matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINTR | libc::EAGAIN)) { return Err(Error::Invalid); }
    }
    Ok(())
}
pub(crate) fn run(path: &Path) -> Result<(), Error> {
    crate::agent_broker::harden()?;
    crate::agent_broker::close_unlisted(&std::collections::BTreeSet::new())?;
    // SAFETY: fcntl has no pointer arguments. Nonblocking writes enforce the stdout deadline.
    let flags = unsafe { libc::fcntl(1, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(1, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 { return Err(Error::Invalid); }
    let now_ts = chrono::Utc::now().timestamp();
    let (mut channel, expires_at) = crate::agent_bridge::connect(path, now_ts)?;
    let mut state = State::Initialize;
    // SAFETY: this command exclusively owns its stdin and never uses the stdio singleton.
    let mut input = BufReader::new(unsafe { File::from_raw_fd(0) });
    // The session file's expiry is the frontend deadline. connect already rejected an unbounded value.
    let deadline = Instant::now() + crate::agent_bridge::frontend_deadline(expires_at, chrono::Utc::now().timestamp())?;
    while let Some(bytes) = line(&mut input, deadline)? {
        match strict_json(&bytes) {
            Ok(value) => if let Some(response) = dispatch(value, &mut state, &mut channel) { output(response)?; },
            Err(_) => output(error(Value::Null, -32700, "Parse error"))?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn four_tools_publish_typed_inputs_without_administration() {
        let tools = tools();
        let tools = tools.as_array().unwrap();
        assert_eq!(tools.iter().map(|t| t["name"].as_str().unwrap()).collect::<Vec<_>>(),
            ["credman_generate", "credman_mutate", "credman_metadata", "credman_use"]);
        for tool in tools { assert_eq!(tool["inputSchema"]["additionalProperties"], false); }
        assert_eq!(tools[1]["inputSchema"]["properties"]["mutation"]["oneOf"].as_array().unwrap().len(), 5);
        assert_eq!(tools[1]["inputSchema"]["properties"]["mutation"]["oneOf"][4]["properties"]["ReportOutcome"]
            ["properties"]["state"]["enum"], json!(["Pending","Submitted","ReportedSuccess","Rejected","HumanRequired","Unknown"]));
        assert_eq!(tools[2]["inputSchema"]["properties"]["fields"]["items"]["enum"], json!(["Label","Username","Notes"]));
        assert_eq!(tools[3]["inputSchema"]["properties"]["usage"]["properties"]["action"]["enum"], json!(["Use"]));
        let mutation = &tools[1]["inputSchema"]["properties"]["mutation"];
        let encoded = serde_json::to_string(mutation).unwrap();
        for forbidden in ["\"Create\"", "\"Generate\"", "\"SecretRead\""] { assert!(!encoded.contains(forbidden)); }
        let patch = &mutation["oneOf"][0]["properties"]["Patch"]["properties"]["values"]["properties"];
        assert!(patch.get("Password").is_none() && patch.get("ApiKey").is_none());
    }
    #[test]
    fn tool_arguments_cannot_change_operation_or_inject_identity() {
        for args in [json!({"op":"status"}), json!({"owner":"someone"}), json!({"principal":"admin"})] {
            assert!(work_request(Call { name:"credman_metadata".into(), arguments:args.as_object().unwrap().clone() }).is_none());
        }
        assert!(work_request(Call { name:"issue_session".into(), arguments:Map::new() }).is_none());
        assert!(work_request(Call { name:"credman_read".into(), arguments:Map::new() }).is_none());
    }
    #[test]
    fn initialize_negotiates_only_implemented_versions_and_notifications_have_no_reply() {
        let (stream, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut channel = FramedChannel::new(stream, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        for (requested, expected) in [("2024-11-05", "2024-11-05"), ("2099-01-01", "2025-11-25")] {
            let mut state = State::Initialize;
            let response = dispatch(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":requested,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}}), &mut state, &mut channel).unwrap();
            assert_eq!(response["result"]["protocolVersion"], expected);
            assert_eq!(response["result"]["capabilities"], json!({"tools":{}}));
            assert!(dispatch(json!({"jsonrpc":"2.0","method":"notifications/initialized"}), &mut state, &mut channel).is_none());
            assert!(state == State::Ready);
            assert!(dispatch(json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"credman_mutate","arguments":{}}}), &mut state, &mut channel).is_none());
        }
    }
    #[test]
    fn sdk_metadata_and_null_cursor_preserve_the_workload_boundary() {
        let (stream, other) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut channel = FramedChannel::new(stream, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let mut broker = FramedChannel::new(other, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let mut state = State::Initialize;
        let meta = json!({"progressToken":"sdk-progress","owner":"untrusted","principal":"admin","sdk.example/trace":{"op":"status"}});
        let response = dispatch(strict_json(&serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"_meta":meta,
            "clientInfo":{"name":"sdk","version":"1","title":"SDK","websiteUrl":"https://sdk.example",
                "icons":[{"src":"https://sdk.example/icon.svg","mimeType":"image/svg+xml","sizes":["any"]}],
                "description":"cosmetic","principal":"admin"}}})).unwrap()).unwrap(), &mut state, &mut channel).unwrap();
        assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
        assert!(state == State::Initialized);
        assert!(dispatch(json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":null}}), &mut state, &mut channel).is_none());
        assert!(state == State::Initialized);
        assert!(dispatch(json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":meta}}), &mut state, &mut channel).is_none());
        assert!(state == State::Ready);
        for params in [None, Some(json!({})), Some(json!({"_meta":{}})), Some(json!({"cursor":null,"_meta":meta}))] {
            let mut request = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
            if let Some(params) = params { request["params"] = params; }
            assert_eq!(dispatch(request, &mut state, &mut channel).unwrap(), result(json!(2), json!({"tools":tools()})));
        }
        assert_eq!(dispatch(json!({"jsonrpc":"2.0","id":3,"method":"ping","params":{"_meta":{"progressToken":7}}}), &mut state, &mut channel).unwrap(), result(json!(3), json!({})));
        for params in [json!({"cursor":"unsupported-private-marker","_meta":meta}), json!({"cursor":7}),
            json!({"principal":"admin","_meta":meta}), json!({"_meta":null}), json!({"_meta":{"progressToken":{}}})] {
            assert_eq!(dispatch(json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":params}), &mut state, &mut channel).unwrap(), error(json!(4), -32602, "Invalid params"));
        }
        let args = json!({"task":"00000000-0000-0000-0000-000000000001","record":"00000000-0000-0000-0000-000000000002","fields":["Label"]});
        let mut call = json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"credman_metadata","arguments":args,"_meta":meta}});
        broker.send(&json!({"ok":false,"error":"access denied"})).unwrap();
        let response = dispatch(call.clone(), &mut state, &mut channel).unwrap();
        assert_eq!(response["result"]["structuredContent"], json!({"ok":false,"error":"access denied"}));
        let mut expected = args.clone();
        expected["op"] = json!("metadata");
        assert_eq!(broker.receive().unwrap(), expected);
        for key in ["owner", "principal", "op", "_meta", "unexpected"] {
            call["params"]["arguments"] = args.clone();
            call["params"]["arguments"][key] = json!("private-marker");
            assert_eq!(dispatch(call.clone(), &mut state, &mut channel).unwrap(), error(json!(5), -32602, "Invalid params"));
        }
        call["params"]["arguments"] = args;
        call["params"]["principal"] = json!("admin");
        assert_eq!(dispatch(call, &mut state, &mut channel).unwrap(), error(json!(5), -32602, "Invalid params"));
    }
    #[test]
    fn owner_disconnect_and_lost_commit_reply_are_not_policy_denials() {
        let args = json!({"task":"00000000-0000-0000-0000-000000000001",
            "request":"00000000-0000-0000-0000-000000000002",
            "kind":"Login","username":"private-user-marker"});
        let mut expected_request = args.clone();
        expected_request["op"] = json!("generate");
        for scenario in ["disconnected", "committed_reply_lost", "owner_denied"] {
            let (stream, other) = std::os::unix::net::UnixStream::pair().unwrap();
            let mut channel = FramedChannel::new(stream, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
            let owner = if scenario == "disconnected" {
                drop(other);
                None
            } else {
                let expected = expected_request.clone();
                Some(std::thread::spawn(move || {
                    let mut owner = FramedChannel::new(other, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
                    let request = owner.receive().unwrap();
                    assert_eq!(request, expected);
                    let mut committed = Vec::new();
                    if scenario == "committed_reply_lost" {
                        // Simulate the owner committing before closing without its reply.
                        committed.push(request);
                    } else {
                        owner.send(&json!({"ok":false,"error":"access denied"})).unwrap();
                    }
                    drop(owner);
                    committed
                }))
            };
            let response = dispatch(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"credman_generate","arguments":args,"_meta":{"progressToken":"private-meta-marker"}}}),
                &mut State::Ready, &mut channel).unwrap();
            let expected = if scenario == "owner_denied" {
                json!({"ok":false,"error":"access denied"})
            } else {
                json!({"ok":false,"error":"owner transport unavailable","outcome":"unknown"})
            };
            assert_eq!(response, result(json!(1), json!({"content":[{"type":"text","text":serde_json::to_string(&expected).unwrap()}],
                "isError":true,"structuredContent":expected})));
            let encoded = serde_json::to_string(&response).unwrap();
            for marker in ["private-label-marker", "private-user-marker", "private-secret-marker", "private-meta-marker",
                "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "mutation", "Password"] {
                assert!(!encoded.contains(marker));
            }
            if let Some(owner) = owner {
                let committed = owner.join().unwrap();
                if scenario == "committed_reply_lost" { assert_eq!(committed, vec![expected_request.clone()]); }
                else { assert!(committed.is_empty()); }
            }
        }
    }
    #[test]
    fn request_ids_and_envelopes_are_strict_without_input_echo() {
        let (stream, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut channel = FramedChannel::new(stream, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let mut state = State::Ready;
        for id in [Value::Null, json!(false), json!(1.5), json!([]), json!({"private":"marker"})] {
            let response = dispatch(json!({"jsonrpc":"2.0","id":id,"method":"ping"}), &mut state, &mut channel).unwrap();
            assert_eq!(response, error(Value::Null, -32600, "Invalid Request"));
        }
        let response = dispatch(json!({"jsonrpc":"2.0","id":1,"method":"ping","principal":"marker"}), &mut state, &mut channel).unwrap();
        assert_eq!(response, error(Value::Null, -32600, "Invalid Request"));
    }
}
