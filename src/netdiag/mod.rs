// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network-diagnostics domain.
//!
//! This module owns no MCP-protocol concerns — the rmcp adapter in
//! [`crate::mcp`] calls into it. It provides:
//!
//! - [`CommandExecutor`] — the seam between a tool handler and the process
//!   it shells out to. The production [`commands::CommandRunner`] implements
//!   it; tests substitute a stub so handler logic is exercised hermetically.
//! - [`normalize_tool_result`] — shapes a raw command result into the
//!   stable diagnostic envelope every tool returns.

pub mod commands;
pub mod validators;

use std::future::Future;

use serde_json::{json, Value};

use crate::config;
use crate::errors::NetdiagError;

/// The seam between a tool handler and command execution.
///
/// `key` is a logical command identifier (e.g. `"ping"`); `extra` is the
/// list of already-validated arguments to append to the allowlisted base
/// command. The returned future is `Send` so handlers stay usable inside
/// rmcp's concurrent dispatch.
pub trait CommandExecutor: Send + Sync + 'static {
    fn run(
        &self,
        key: &str,
        extra: &[String],
    ) -> impl Future<Output = Result<Value, NetdiagError>> + Send;
}

/// Shape a raw `{ok, exit_code, stdout, stderr}` command result into the
/// stable diagnostic envelope `{tool, status, signal, evidence,
/// suggested_action, raw}` that every diagnostic tool returns. A non-zero
/// exit is **not** an error here — it is a `status: "fail"` outcome,
/// reported as a successful tool result (see CLAUDE.md §Error semantics).
pub fn normalize_tool_result(tool: &str, raw: Value) -> Value {
    let ok = raw.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let status = if ok { "ok" } else { "fail" };
    let signal = signal_for(tool, ok);
    let evidence = raw
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let suggestion = suggested_action(tool, ok, evidence);

    json!({
        "tool": tool,
        "status": status,
        "signal": signal,
        "evidence": truncate_text(evidence, config::EVIDENCE_MAX_CHARS),
        "suggested_action": suggestion,
        "raw": raw,
    })
}

/// Map a tool + success flag to a coarse diagnostic signal string.
fn signal_for(tool: &str, ok: bool) -> &'static str {
    if ok {
        return "command_succeeded";
    }
    match tool {
        "net.if_status" => "interface_or_link_issue",
        "net.addr" => "address_state_issue",
        "net.link_detail" => "interface_or_link_issue",
        "net.mac_lookup" => "mac_table_lookup_failed",
        "net.neighbors" => "neighbor_resolution_issue",
        "net.routes" => "routing_state_issue",
        "net.route_get" => "route_resolution_failed",
        "net.rules" => "policy_routing_issue",
        "net.ping" => "connectivity_check_failed",
        "net.traceroute" => "path_diagnosis_failed",
        "net.sockets" => "socket_state_failed",
        "net.dns_status" | "net.resolv_conf" => "dns_state_failed",
        "net.ethtool" => "interface_driver_query_failed",
        "net.firewall" => "firewall_state_failed",
        "net.conntrack" => "conntrack_query_failed",
        "net.tcpdump_sample" => "packet_capture_failed",
        "net.logs" => "log_extraction_failed",
        "sys.failed_units" | "sys.service_status" => "systemd_state_failed",
        "sys.dmesg" => "kernel_log_failed",
        "sys.uptime" | "sys.memory" | "sys.filesystems" => "resource_query_failed",
        _ => "diagnostic_command_failed",
    }
}

/// Suggest a human-actionable next step from the tool outcome and a quick
/// scan of its evidence.
fn suggested_action(tool: &str, ok: bool, evidence: &str) -> &'static str {
    if !ok {
        return match tool {
            "net.ping" => "Verify VLAN, gateway route, and ACL/firewall path; run traceroute next.",
            "net.if_status" => {
                "Check cable/SFP, admin state, and interface counters for errors/drops."
            }
            "net.neighbors" => "Verify ARP/ND reachability on the expected L2 segment and VLAN.",
            "net.routes" => {
                "Validate route presence, metric preference, and next-hop reachability."
            }
            "net.dns_status" | "net.resolv_conf" => {
                "Verify resolver configuration, DNS server reachability, and split-DNS domains."
            }
            "net.firewall" => "Inspect firewall tables for dropped forwarding or input traffic.",
            "sys.service_status" | "sys.failed_units" => {
                "Inspect the failed unit logs and dependency chain."
            }
            "sys.memory" | "sys.filesystems" => {
                "Check for resource pressure before deeper network diagnosis."
            }
            _ => "Inspect stderr and rerun with narrower scope.",
        };
    }

    if matches!(tool, "net.if_status" | "net.link_detail")
        && (evidence.contains("DOWN") || evidence.contains("NO-CARRIER"))
    {
        "Link appears down; verify physical link, transceiver, and peer port state."
    } else {
        "No immediate fault signal from this command; continue with adjacent diagnostics."
    }
}

/// Truncate `text` to at most `max` bytes, appending an ellipsis when cut.
/// `max` is chosen at an ASCII-safe boundary by callers (command output is
/// decoded UTF-8-lossy first), so slicing on a byte index is safe here.
fn truncate_text(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_marks_success_envelope() {
        let raw = json!({"ok": true, "exit_code": 0, "stdout": "up", "stderr": ""});
        let out = normalize_tool_result("net.routes", raw);
        assert_eq!(out["tool"], "net.routes");
        assert_eq!(out["status"], "ok");
        assert_eq!(out["signal"], "command_succeeded");
    }

    #[test]
    fn normalize_marks_failure_envelope_with_tool_signal() {
        let raw = json!({"ok": false, "exit_code": 1, "stdout": "", "stderr": "boom"});
        let out = normalize_tool_result("net.ping", raw);
        assert_eq!(out["status"], "fail");
        assert_eq!(out["signal"], "connectivity_check_failed");
    }

    #[test]
    fn truncate_text_appends_ellipsis_past_limit() {
        assert_eq!(truncate_text("abcdef", 3), "abc...");
        assert_eq!(truncate_text("abc", 8), "abc");
    }
}
