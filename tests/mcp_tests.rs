// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the rmcp protocol layer — the authoritative wire
//! coverage for the server.
//!
//! These tests drive [`NetdiagServer`] in-process over an in-memory
//! [`tokio::io::duplex`] pipe, send raw line-delimited JSON-RPC, and assert
//! on the responses — exercising the same MCP surface the binary speaks
//! over stdio. The command runner is stubbed (see [`StubRunner`]) so the
//! suite is hermetic: no real `ip` / `ping` / `journalctl` is spawned. The
//! end-to-end check through the release binary lives in
//! `tests/integration.rs`.

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use rmcp::ServiceExt;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use mcp_netdiag_rs::errors::NetdiagError;
use mcp_netdiag_rs::mcp::journal::JournalWriter;
use mcp_netdiag_rs::mcp::NetdiagServer;
use mcp_netdiag_rs::netdiag::commands::CommandRunner;
use mcp_netdiag_rs::netdiag::CommandExecutor;

// ---- helpers --------------------------------------------------------------

/// A hermetic stand-in for the real command runner. Every key resolves to
/// a canned successful `{ok, exit_code, stdout, stderr}` payload, so the
/// wire tests exercise handler logic — validation, normalization, journal
/// shaping — without spawning a process.
#[derive(Clone)]
struct StubRunner;

impl CommandExecutor for StubRunner {
    fn run(
        &self,
        key: &str,
        _extra: &[String],
    ) -> impl Future<Output = Result<Value, NetdiagError>> + Send {
        let key = key.to_string();
        async move {
            Ok(json!({
                "ok": true,
                "exit_code": 0,
                "stdout": format!("stub output for {key}"),
                "stderr": "",
            }))
        }
    }
}

/// Server backed by [`StubRunner`] with no journal.
fn stub_server() -> NetdiagServer<StubRunner> {
    NetdiagServer::new(StubRunner, None)
}

/// Drive the rmcp server over a duplex pipe: send a sequence of MCP request
/// lines, read one JSON response per request that carries an `id`.
async fn roundtrip<R: CommandExecutor>(server: NetdiagServer<R>, requests: &[Value]) -> Vec<Value> {
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);

    let server_task = tokio::spawn(async move {
        let svc = server.serve(server_io).await.expect("serve start");
        let _ = svc.waiting().await;
    });

    let (client_read, mut client_write) = tokio::io::split(client_io);
    let mut reader = BufReader::new(client_read);

    for req in requests {
        let mut line = serde_json::to_vec(req).expect("encode request");
        line.push(b'\n');
        client_write.write_all(&line).await.expect("write request");
    }
    client_write.flush().await.expect("flush");

    let expected = requests.iter().filter(|r| r.get("id").is_some()).count();
    let mut responses = Vec::with_capacity(expected);
    for _ in 0..expected {
        let mut buf = String::new();
        let n = timeout(Duration::from_secs(5), reader.read_line(&mut buf))
            .await
            .expect("response timeout")
            .expect("read line");
        assert!(n > 0, "EOF before all responses arrived");
        responses.push(serde_json::from_str(buf.trim_end()).expect("response JSON"));
    }

    drop(client_write);
    drop(reader);
    let _ = timeout(Duration::from_secs(2), server_task).await;

    responses
}

fn init_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "mcp-tests", "version": "0.0.1"},
        }
    })
}

fn initialized_notification() -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
}

fn call_request(id: i64, tool: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })
}

/// Handshake + a single `tools/call`; returns the call response.
async fn handshake_then_call<R: CommandExecutor>(
    server: NetdiagServer<R>,
    tool: &str,
    arguments: Value,
) -> Value {
    let responses = roundtrip(
        server,
        &[
            init_request(),
            initialized_notification(),
            call_request(2, tool, arguments),
        ],
    )
    .await;
    assert_eq!(responses.len(), 2, "expected initialize + tools/call");
    responses.into_iter().nth(1).expect("tools/call response")
}

/// Extract the JSON-RPC error code from a response, panicking if absent.
fn rpc_error_code(resp: &Value) -> i64 {
    resp.get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("expected JSON-RPC error.code in {resp}"))
}

const NET_TOOLS: [&str; 7] = [
    "net.if_status",
    "net.mac_lookup",
    "net.neighbors",
    "net.routes",
    "net.ping",
    "net.traceroute",
    "net.logs",
];

// ---- lifecycle / tools/list ----------------------------------------------

#[tokio::test]
async fn initialize_advertises_tools_capability_and_server_info() {
    let responses = roundtrip(stub_server(), &[init_request()]).await;
    assert_eq!(responses.len(), 1);
    let result = responses[0].get("result").expect("initialize result");

    assert_eq!(
        result["serverInfo"]["name"], "mcp-netdiag-rs",
        "serverInfo.name should be the crate name",
    );
    assert!(
        result["capabilities"].get("tools").is_some(),
        "capabilities.tools must be present; got {result:?}",
    );
}

#[tokio::test]
async fn tools_list_contains_all_seven_dotted_tools_with_input_schema() {
    let responses = roundtrip(
        stub_server(),
        &[
            init_request(),
            initialized_notification(),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ],
    )
    .await;
    let result = responses[1].get("result").expect("tools/list result");
    let tools = result["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 7, "all seven net.* tools must be listed");

    for name in NET_TOOLS {
        let t = tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("`{name}` must be listed under its dotted name"));
        assert!(
            t.get("inputSchema").is_some(),
            "rmcp must generate an input schema for `{name}`",
        );
        assert!(
            t.get("outputSchema").is_none(),
            "outputSchema for `{name}` should not be set",
        );
    }
}

#[tokio::test]
async fn tools_list_schema_advertises_integer_bounds() {
    let responses = roundtrip(
        stub_server(),
        &[
            init_request(),
            initialized_notification(),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ],
    )
    .await;
    let tools = responses[1]["result"]["tools"]
        .as_array()
        .expect("tools array");
    let ping = tools
        .iter()
        .find(|t| t["name"] == "net.ping")
        .expect("net.ping listed");
    let count = &ping["inputSchema"]["properties"]["count"];
    assert_eq!(
        count["minimum"], 1,
        "schemars range should advertise the lower bound",
    );
    assert_eq!(
        count["maximum"], 10,
        "schemars range should advertise the upper bound",
    );
}

// ---- tools/call: happy path ----------------------------------------------

#[tokio::test]
async fn call_net_routes_returns_structured_result() {
    let resp = handshake_then_call(stub_server(), "net.routes", json!({})).await;
    let result = resp.get("result").expect("tools/call result");

    let sc = result
        .get("structuredContent")
        .and_then(Value::as_object)
        .expect("rmcp adapter must emit structuredContent for object results");
    assert_eq!(sc["tool"], "net.routes");
    assert_eq!(sc["status"], "ok");
    assert_eq!(sc["signal"], "command_succeeded");
    assert_ne!(
        result.get("isError"),
        Some(&json!(true)),
        "a successful tools/call must not set isError=true",
    );
}

#[tokio::test]
async fn call_net_ping_normalizes_stub_output() {
    let resp = handshake_then_call(
        stub_server(),
        "net.ping",
        json!({"target": "127.0.0.1", "count": 2}),
    )
    .await;
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(sc["tool"], "net.ping");
    assert_eq!(sc["status"], "ok");
}

// ---- tools/call: error paths ---------------------------------------------

#[tokio::test]
async fn call_unknown_tool_returns_error() {
    let resp = handshake_then_call(stub_server(), "net.bogus", json!({})).await;
    assert_eq!(
        rpc_error_code(&resp),
        -32602,
        "an unknown tool name is an invalid-params failure",
    );
}

#[tokio::test]
async fn call_with_unknown_argument_returns_invalid_params() {
    // `deny_unknown_fields` on the param struct turns an unexpected field
    // into a deserialization failure, surfaced by rmcp as -32602.
    let resp = handshake_then_call(stub_server(), "net.if_status", json!({"bogus": true})).await;
    assert_eq!(rpc_error_code(&resp), -32602);
}

#[tokio::test]
async fn call_with_out_of_range_count_returns_invalid_param() {
    let resp = handshake_then_call(
        stub_server(),
        "net.ping",
        json!({"target": "127.0.0.1", "count": 99}),
    )
    .await;
    assert_eq!(
        rpc_error_code(&resp),
        -32010,
        "out-of-range integer is a pinned InvalidParam, not a -32602",
    );
}

#[tokio::test]
async fn call_with_bad_mac_returns_invalid_param() {
    let resp = handshake_then_call(stub_server(), "net.mac_lookup", json!({"mac": "zz"})).await;
    assert_eq!(rpc_error_code(&resp), -32010);
}

#[tokio::test]
async fn call_net_ping_rejects_target_with_leading_dash() {
    // A `-`-prefixed target would be parsed by `ping` as a CLI flag —
    // rejected up front as a pinned InvalidParam.
    let resp = handshake_then_call(stub_server(), "net.ping", json!({"target": "-f"})).await;
    assert_eq!(rpc_error_code(&resp), -32010);
}

#[tokio::test]
async fn call_net_traceroute_rejects_target_with_leading_dash() {
    let resp =
        handshake_then_call(stub_server(), "net.traceroute", json!({"target": "-q30"})).await;
    assert_eq!(rpc_error_code(&resp), -32010);
}

#[tokio::test]
async fn disabled_command_returns_not_allowed() {
    // NETDIAG_ALLOWLIST narrowed to exclude `routes`: the tool resolves but
    // the runner rejects the disabled key with CommandNotAllowed (-32011)
    // before spawning anything.
    let enabled: HashSet<String> = ["ping"].iter().map(|s| s.to_string()).collect();
    let server = NetdiagServer::new(CommandRunner::with_enabled(Some(&enabled)), None);
    let resp = handshake_then_call(server, "net.routes", json!({})).await;
    assert_eq!(rpc_error_code(&resp), -32011);
}

// ---- audit journal --------------------------------------------------------

#[tokio::test]
async fn journal_records_tool_call_pairs_and_skips_lifecycle() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let journal = JournalWriter::open(tmp.path()).await.unwrap();
    let server = NetdiagServer::new(StubRunner, Some(Arc::new(journal)));

    roundtrip(
        server,
        &[
            init_request(),
            initialized_notification(),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            call_request(3, "net.routes", json!({})),
        ],
    )
    .await;

    let contents = std::fs::read_to_string(tmp.path()).unwrap();
    let rows: Vec<Value> = contents
        .lines()
        .map(|l| serde_json::from_str(l).expect("journal line is JSON"))
        .collect();
    assert_eq!(
        rows.len(),
        2,
        "only the tools/call must be journaled — initialize and tools/list are lifecycle traffic: {contents}",
    );
    assert_eq!(rows[0]["direction"], "call");
    assert_eq!(rows[0]["tool"], "net.routes");
    assert_eq!(rows[0]["session_id"], "none");
    assert_eq!(rows[1]["direction"], "result");
    assert_eq!(rows[1]["summary"]["ok"], true);
    assert_eq!(rows[1]["summary"]["status"], "ok");
}

#[tokio::test]
async fn journal_records_pinned_error_code_for_failed_call() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let journal = JournalWriter::open(tmp.path()).await.unwrap();
    let server = NetdiagServer::new(StubRunner, Some(Arc::new(journal)));

    handshake_then_call(server, "net.mac_lookup", json!({"mac": "zz"})).await;

    let contents = std::fs::read_to_string(tmp.path()).unwrap();
    let result_row: Value = contents
        .lines()
        .map(|l| serde_json::from_str(l).expect("journal line"))
        .find(|r: &Value| r["direction"] == "result")
        .expect("a result row");
    assert_eq!(result_row["summary"]["ok"], false);
    assert_eq!(result_row["summary"]["error_code"], -32010);
}

#[tokio::test]
async fn degraded_mode_journal_none_still_dispatches() {
    // journal = None must never block a tool call.
    let resp = handshake_then_call(stub_server(), "net.routes", json!({})).await;
    assert!(resp.get("result").is_some(), "dispatch must still succeed");
}
