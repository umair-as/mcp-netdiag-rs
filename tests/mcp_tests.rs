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

const MCP_TOOLS: &[&str] = &[
    "net.if_status",
    "net.mac_lookup",
    "net.neighbors",
    "net.routes",
    "net.addr",
    "net.link_detail",
    "net.route_get",
    "net.rules",
    "net.ping",
    "net.traceroute",
    "net.sockets",
    "net.dns_status",
    "net.resolv_conf",
    "net.ethtool",
    "net.firewall",
    "net.conntrack",
    "net.tcpdump_sample",
    "net.logs",
    "sys.failed_units",
    "sys.service_status",
    "sys.dmesg",
    "sys.uptime",
    "sys.memory",
    "sys.filesystems",
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
async fn tools_list_contains_all_dotted_tools_with_input_schema() {
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
    assert_eq!(tools.len(), MCP_TOOLS.len(), "all MCP tools must be listed");

    for name in MCP_TOOLS {
        let t = tools
            .iter()
            .find(|t| t["name"] == *name)
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

#[tokio::test]
async fn call_net_route_get_normalizes_stub_output() {
    let resp = handshake_then_call(
        stub_server(),
        "net.route_get",
        json!({"target": "192.0.2.1"}),
    )
    .await;
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(sc["tool"], "net.route_get");
    assert_eq!(sc["status"], "ok");
}

#[tokio::test]
async fn call_sys_service_status_accepts_template_unit() {
    let resp = handshake_then_call(
        stub_server(),
        "sys.service_status",
        json!({"unit": "serial-getty@ttyS0.service", "lines": 10}),
    )
    .await;
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(sc["tool"], "sys.service_status");
    assert_eq!(sc["status"], "ok");
}

#[tokio::test]
async fn call_net_tcpdump_sample_rejects_out_of_range_count() {
    let resp = handshake_then_call(
        stub_server(),
        "net.tcpdump_sample",
        json!({"interface": "eth0", "count": 500}),
    )
    .await;
    assert_eq!(rpc_error_code(&resp), -32010);
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

// ---- privileged gating: wire-level --------------------------------------------

/// The six privileged tools (mirrors `netdiag::commands::PRIVILEGED_KEYS` but lives
/// under the dotted MCP tool names). Kept inline so the wire test asserts
/// the operator-facing names, not the internal command keys.
const PRIVILEGED_TOOLS: &[&str] = &[
    "net.ping",
    "net.traceroute",
    "net.tcpdump_sample",
    "net.firewall",
    "net.conntrack",
    "sys.dmesg",
];

#[tokio::test]
async fn tools_list_still_advertises_privileged_when_disabled() {
    // Disabled privileged tools must remain visible in tools/list — mirrors the
    // existing NETDIAG_ALLOWLIST behavior. The refusal happens at call time.
    let server = NetdiagServer::new(CommandRunner::with_layers(None, &HashSet::new()), None);
    let responses = roundtrip(
        server,
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
    for name in PRIVILEGED_TOOLS {
        assert!(
            tools.iter().any(|t| t["name"] == *name),
            "{name} must remain visible in tools/list even when disabled",
        );
    }
}

/// The three wire-emitting privileged tools. Each call emits packets on the
/// network or toggles promiscuous mode, so they advertise
/// `readOnlyHint = false` and `idempotentHint = false` per the MCP spec
/// (no host config changes, but observable environmental effects exist).
const PRIVILEGED_WIRE_EMITTERS: &[&str] = &["net.ping", "net.traceroute", "net.tcpdump_sample"];

/// The three privileged-read privileged tools. They query local kernel state
/// without emitting anything, so they keep `readOnlyHint = true` and
/// `idempotentHint = true`. They are privileged only because of the
/// capability requirement.
const PRIVILEGED_KERNEL_READS: &[&str] = &["net.firewall", "net.conntrack", "sys.dmesg"];

#[tokio::test]
async fn tools_list_marks_privileged_in_description_and_open_world_hint() {
    // Every privileged tool carries the "[Privileged: <CAP>...]" description
    // prefix, `openWorldHint = true`, and `destructiveHint = false`. The
    // readOnlyHint / idempotentHint split between wire-emitters and
    // privileged-reads is asserted in the two follow-up tests below.
    let server = NetdiagServer::new(
        CommandRunner::with_layers(
            None,
            &[mcp_netdiag_rs::config::PRIVILEGED_ALL_SENTINEL.to_string()]
                .into_iter()
                .collect(),
        ),
        None,
    );
    let responses = roundtrip(
        server,
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
    for name in PRIVILEGED_TOOLS {
        let t = tools
            .iter()
            .find(|t| t["name"] == *name)
            .unwrap_or_else(|| panic!("{name} listed"));
        let desc = t["description"].as_str().unwrap_or_default();
        assert!(
            desc.starts_with("[Privileged:"),
            "{name} description must carry the privileged capability marker: {desc:?}",
        );
        assert_eq!(
            t["annotations"]["openWorldHint"],
            json!(true),
            "{name} must advertise openWorldHint=true",
        );
        assert_eq!(t["annotations"]["destructiveHint"], json!(false));
    }
}

#[tokio::test]
async fn tools_list_wire_emitting_privileged_tools_flip_read_only_and_idempotent_hints() {
    // ping / traceroute / tcpdump_sample emit packets or toggle promisc —
    // per MCP spec, readOnlyHint and idempotentHint must be false because
    // each call produces fresh observable effects. The decision is locked
    // in SECURITY.md "Default vs privileged tool model"; regression guard.
    let server = NetdiagServer::new(
        CommandRunner::with_layers(
            None,
            &[mcp_netdiag_rs::config::PRIVILEGED_ALL_SENTINEL.to_string()]
                .into_iter()
                .collect(),
        ),
        None,
    );
    let responses = roundtrip(
        server,
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
    for name in PRIVILEGED_WIRE_EMITTERS {
        let t = tools
            .iter()
            .find(|t| t["name"] == *name)
            .unwrap_or_else(|| panic!("{name} listed"));
        assert_eq!(
            t["annotations"]["readOnlyHint"],
            json!(false),
            "{name} emits packets / toggles promisc — readOnlyHint must be false",
        );
        assert_eq!(
            t["annotations"]["idempotentHint"],
            json!(false),
            "{name} produces fresh observable effects — idempotentHint must be false",
        );
    }
}

#[tokio::test]
async fn tools_list_privileged_read_privileged_tools_keep_read_only_hints_true() {
    // firewall / conntrack / dmesg are pure reads of kernel state — they
    // are privileged only because they need elevated caps. The MCP-spec
    // readOnlyHint stays true; idempotentHint stays true (consecutive
    // calls have no additional effect on the environment).
    let server = NetdiagServer::new(
        CommandRunner::with_layers(
            None,
            &[mcp_netdiag_rs::config::PRIVILEGED_ALL_SENTINEL.to_string()]
                .into_iter()
                .collect(),
        ),
        None,
    );
    let responses = roundtrip(
        server,
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
    for name in PRIVILEGED_KERNEL_READS {
        let t = tools
            .iter()
            .find(|t| t["name"] == *name)
            .unwrap_or_else(|| panic!("{name} listed"));
        assert_eq!(
            t["annotations"]["readOnlyHint"],
            json!(true),
            "{name} is a pure kernel-state read — readOnlyHint must stay true",
        );
        assert_eq!(t["annotations"]["idempotentHint"], json!(true));
    }
}

#[tokio::test]
async fn tools_list_default_tool_advertises_closed_world_annotation() {
    // Spot-check: a default tool advertises open_world_hint=false and has no
    // privileged prefix in its description.
    let server = stub_server();
    let responses = roundtrip(
        server,
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
    let routes = tools
        .iter()
        .find(|t| t["name"] == "net.routes")
        .expect("net.routes listed");
    assert_eq!(routes["annotations"]["openWorldHint"], json!(false));
    assert!(!routes["description"]
        .as_str()
        .unwrap_or_default()
        .starts_with("[Privileged:"));
}

#[tokio::test]
async fn call_privileged_default_disabled_returns_privileged_message() {
    // Default deployment: NETDIAG_ENABLE_PRIVILEGED unset → empty opt-in set.
    // Every privileged tool refuses with -32011, message mentions the env var.
    for tool in PRIVILEGED_TOOLS {
        let server = NetdiagServer::new(CommandRunner::with_layers(None, &HashSet::new()), None);
        let args = privileged_call_args(tool);
        let resp = handshake_then_call(server, tool, args).await;
        assert_eq!(
            rpc_error_code(&resp),
            -32011,
            "{tool} must refuse by default: {resp}",
        );
        let msg = resp["error"]["message"]
            .as_str()
            .unwrap_or_else(|| panic!("error.message missing for {tool}: {resp}"));
        assert!(
            msg.contains("NETDIAG_ENABLE_PRIVILEGED"),
            "{tool} refusal must surface the env-var hint, got: {msg}",
        );
    }
}

#[tokio::test]
async fn call_privileged_subset_opts_in_only_listed_tool() {
    // NETDIAG_ENABLE_PRIVILEGED=ping (one tool) → ping passes the privileged gate;
    // the other five privileged tools still refuse with -32011.
    let privileged: HashSet<String> = ["ping"].iter().map(|s| s.to_string()).collect();

    // ping passes the gate. The StubRunner-equivalent isn't usable here
    // (it skips gating), so we use the real runner; ping with target
    // 127.0.0.1 returns successfully on a Linux test host. We only assert
    // the response is NOT a privileged refusal (status may be "ok" or "fail"
    // depending on host capabilities — the call reached past the gate).
    {
        let server = NetdiagServer::new(CommandRunner::with_layers(None, &privileged), None);
        let resp = handshake_then_call(
            server,
            "net.ping",
            json!({"target": "127.0.0.1", "count": 1, "timeout_secs": 1}),
        )
        .await;
        if let Some(err) = resp.get("error") {
            // Only acceptable error here is a spawn/exec issue, NOT privileged.
            let msg = err["message"].as_str().unwrap_or_default();
            assert!(
                !msg.contains("NETDIAG_ENABLE_PRIVILEGED"),
                "ping must pass privileged gate when opted in; got privileged refusal: {resp}",
            );
        }
    }

    // The other five privileged tools still refuse with privileged message.
    for tool in PRIVILEGED_TOOLS.iter().filter(|t| **t != "net.ping") {
        let server = NetdiagServer::new(CommandRunner::with_layers(None, &privileged), None);
        let resp = handshake_then_call(server, tool, privileged_call_args(tool)).await;
        assert_eq!(rpc_error_code(&resp), -32011, "{tool} must still refuse");
        let msg = resp["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("NETDIAG_ENABLE_PRIVILEGED"),
            "{tool} refusal must keep the env-var hint",
        );
    }
}

#[tokio::test]
async fn call_privileged_all_sentinel_admits_every_privileged_tool() {
    // NETDIAG_ENABLE_PRIVILEGED=all → every privileged tool passes the privileged gate.
    // We don't assert successful *execution* (the test host may lack
    // nft / conntrack / tcpdump / dmesg permissions); we only assert the
    // response does NOT carry the privileged env-var hint, proving the gate
    // didn't fire. Parallel structure to
    // `call_privileged_subset_opts_in_only_listed_tool` but for the `all`
    // sentinel path.
    let privileged: HashSet<String> = [mcp_netdiag_rs::config::PRIVILEGED_ALL_SENTINEL.to_string()]
        .into_iter()
        .collect();
    for tool in PRIVILEGED_TOOLS {
        let server = NetdiagServer::new(CommandRunner::with_layers(None, &privileged), None);
        let resp = handshake_then_call(server, tool, privileged_call_args(tool)).await;
        if let Some(err) = resp.get("error") {
            let msg = err["message"].as_str().unwrap_or_default();
            assert!(
                !msg.contains("NETDIAG_ENABLE_PRIVILEGED"),
                "{tool} must pass privileged gate under `all`; got privileged refusal: {resp}",
            );
        }
    }
}

#[tokio::test]
async fn call_privileged_allowlist_precedence_returns_command_not_allowed() {
    // NETDIAG_ALLOWLIST narrowed to exclude ping + NETDIAG_ENABLE_PRIVILEGED=all
    // → ping still refused, but with CommandNotAllowed (no env-var hint),
    // proving the allowlist takes precedence.
    let allow: HashSet<String> = ["routes"].iter().map(|s| s.to_string()).collect();
    let privileged: HashSet<String> = [mcp_netdiag_rs::config::PRIVILEGED_ALL_SENTINEL.to_string()]
        .into_iter()
        .collect();
    let server = NetdiagServer::new(CommandRunner::with_layers(Some(&allow), &privileged), None);
    let resp = handshake_then_call(
        server,
        "net.ping",
        json!({"target": "127.0.0.1", "count": 1, "timeout_secs": 1}),
    )
    .await;
    assert_eq!(rpc_error_code(&resp), -32011);
    let msg = resp["error"]["message"].as_str().unwrap_or_default();
    // CommandNotAllowed message format from errors.rs — does NOT mention
    // the privileged env var (allowlist precedence proof).
    assert!(
        msg.contains("not allowed") && !msg.contains("NETDIAG_ENABLE_PRIVILEGED"),
        "allowlist refusal must NOT surface privileged hint: {msg}",
    );
}

/// Build the minimal valid argument payload for each privileged tool. Per-tool
/// because the param structs use `deny_unknown_fields` and several tools
/// require an `interface` / `target` argument.
fn privileged_call_args(tool: &str) -> Value {
    match tool {
        "net.ping" => json!({"target": "127.0.0.1", "count": 1, "timeout_secs": 1}),
        "net.traceroute" => json!({"target": "127.0.0.1", "max_hops": 1}),
        "net.tcpdump_sample" => json!({"interface": "lo", "count": 1}),
        // Paramless tools take an empty object.
        _ => json!({}),
    }
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
