// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end test: drive the compiled binary as a subprocess over stdio.
//!
//! Unlike `tests/mcp_tests.rs` (which stubs the command runner), this test
//! runs the real binary with the real `CommandRunner` — `net.routes` and
//! `net.ping 127.0.0.1` shell out to the host's `ip` / `ping`, both present
//! and deterministic on a Linux CI runner. It is the regression guard for
//! the on-the-wire result envelope the example client consumes.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

use mcp_netdiag_rs::netdiag::commands::BUILTIN_COMMAND_COUNT;

/// A handle to the server binary running as a child process.
struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl Server {
    fn spawn(journal: &Path) -> Self {
        // `CARGO_BIN_EXE_<name>` is injected by cargo for integration tests.
        // `NETDIAG_ENABLE_PRIVILEGED=ping` opts in only the one privileged tool this
        // end-to-end test actually exercises (`net.ping 127.0.0.1`). The
        // privileged *gating* itself is covered by the in-process suite in
        // `tests/mcp_tests.rs`; this test cares about the on-the-wire
        // result envelope through the compiled binary.
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-netdiag-rs"))
            .env("NETDIAG_JOURNAL", journal)
            .env("NETDIAG_ENABLE_PRIVILEGED", "ping")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mcp-netdiag-rs binary");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let resp = self.read_line();
        assert_eq!(
            resp["id"].as_i64(),
            Some(id),
            "response id mismatch: {resp}"
        );
        resp
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn send(&mut self, v: &Value) {
        let mut line = serde_json::to_vec(v).expect("encode request");
        line.push(b'\n');
        self.stdin.write_all(&line).expect("write to server");
        self.stdin.flush().expect("flush server stdin");
    }

    fn read_line(&mut self) -> Value {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).expect("read from server");
        assert!(n > 0, "server closed stdout before responding");
        serde_json::from_str(line.trim()).expect("server response is JSON")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn handshake(s: &mut Server) {
    let init = s.request(
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "integration", "version": "0"},
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "mcp-netdiag-rs");
    s.notify("notifications/initialized", json!({}));
}

/// Assert a `tools/call` response carries the structured diagnostic
/// envelope. Tolerates `status: "fail"` — the host command may legitimately
/// fail; only the *envelope shape* is the contract under test.
fn assert_structured_envelope(resp: &Value, tool: &str) {
    assert!(
        resp.get("error").is_none(),
        "{tool} returned a JSON-RPC error: {resp}",
    );
    let sc = resp["result"]
        .get("structuredContent")
        .unwrap_or_else(|| panic!("{tool} must return structuredContent: {resp}"));
    assert_eq!(sc["tool"], tool);
    assert!(sc.get("status").is_some(), "missing status in {sc}");
    assert!(sc.get("signal").is_some(), "missing signal in {sc}");
    assert!(sc.get("raw").is_some(), "missing raw in {sc}");
}

#[test]
fn end_to_end_tools_list_and_calls_over_stdio() {
    let journal = tempfile::NamedTempFile::new().unwrap();
    let mut server = Server::spawn(journal.path());
    handshake(&mut server);

    // tools/list — full diagnostic tool catalog.
    let listed = server.request("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().expect("tools array");
    assert_eq!(
        tools.len(),
        BUILTIN_COMMAND_COUNT,
        "all MCP tools must be advertised",
    );

    // net.routes — real `ip route` on the host.
    let routes = server.request("tools/call", json!({"name": "net.routes", "arguments": {}}));
    assert_structured_envelope(&routes, "net.routes");

    // net.ping against loopback — deterministic on a Linux runner.
    let ping = server.request(
        "tools/call",
        json!({
            "name": "net.ping",
            "arguments": {"target": "127.0.0.1", "count": 1, "timeout_secs": 1},
        }),
    );
    assert_structured_envelope(&ping, "net.ping");

    // Each tools/call writes one `call` + one `result` row; lifecycle
    // traffic (initialize, tools/list) is not journaled.
    drop(server);
    let contents = std::fs::read_to_string(journal.path()).unwrap();
    assert_eq!(
        contents.lines().count(),
        4,
        "two tools/call should produce four journal rows: {contents}",
    );
}
