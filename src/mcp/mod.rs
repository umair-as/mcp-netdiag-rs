// SPDX-License-Identifier: MIT OR Apache-2.0

//! rmcp adapter layer.
//!
//! The production MCP protocol layer: an MCP server built on the `rmcp`
//! SDK. `rmcp` owns the stdio transport and the `initialize` /
//! `tools/list` / `tools/call` framing; all seven `net.*` tools are wired
//! here as `#[tool]` handlers.
//!
//! This module owns no netdiag-domain logic — command execution, the
//! allowlist, validators, and result shaping live in [`crate::netdiag`].
//! It only adapts rmcp tool calls onto that domain, and is **stateless**:
//! every call is fire-and-forget, there is no session concept.

pub mod journal;

use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResult, Implementation, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::instrument;

use crate::errors::NetdiagError;
use crate::netdiag::commands::{validate_interface, validate_ip_or_host, validate_mac};
use crate::netdiag::{normalize_tool_result, CommandExecutor};
use journal::{JournalEntry, JournalWriter};

/// rmcp-facing server. Holds the command executor and the optional audit
/// journal, and registers the `net.*` tools with the `rmcp` SDK. Generic
/// over the [`CommandExecutor`] so tests can substitute a stub runner.
pub struct NetdiagServer<R: CommandExecutor> {
    runner: Arc<R>,
    /// Tool-call audit journal. `None` means degraded mode (journal open
    /// failed at startup); dispatch then proceeds without logging.
    journal: Option<Arc<JournalWriter>>,
    tool_router: ToolRouter<Self>,
}

// Manual `Clone` so we do not require `R: Clone` — `Arc<R>` is `Clone`
// regardless. The `tool_handler` macro requires `Self: Clone` to dispatch
// tool futures.
impl<R: CommandExecutor> Clone for NetdiagServer<R> {
    fn clone(&self) -> Self {
        Self {
            runner: Arc::clone(&self.runner),
            journal: self.journal.clone(),
            tool_router: self.tool_router.clone(),
        }
    }
}

#[tool_router(router = tool_router)]
impl<R: CommandExecutor> NetdiagServer<R> {
    pub fn new(runner: R, journal: Option<Arc<JournalWriter>>) -> Self {
        Self {
            runner: Arc::new(runner),
            journal,
            tool_router: Self::tool_router(),
        }
    }

    /// Interface state and counters (`ip -j -s link show [dev <iface>]`).
    #[tool(
        name = "net.if_status",
        description = "Show interface state and counters. Optionally restrict to one interface."
    )]
    #[instrument(skip(self, params))]
    pub async fn if_status(
        &self,
        params: Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        let extra = interface_args(p.interface.as_deref())?;
        let raw = self.runner.run("if_status", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.if_status",
            raw,
        )))
    }

    /// Bridge FDB lookup for a MAC address (`bridge -j fdb show to <mac>`).
    #[tool(
        name = "net.mac_lookup",
        description = "Look up a MAC address in the bridge forwarding database."
    )]
    #[instrument(skip(self, params))]
    pub async fn mac_lookup(
        &self,
        params: Parameters<MacLookupParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        validate_mac(&p.mac)?;
        let extra = vec!["to".to_string(), p.mac];
        let raw = self.runner.run("mac_table", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.mac_lookup",
            raw,
        )))
    }

    /// ARP / neighbor state (`ip -j neigh show [dev <iface>]`).
    #[tool(
        name = "net.neighbors",
        description = "Show ARP/neighbor state. Optionally restrict to one interface."
    )]
    #[instrument(skip(self, params))]
    pub async fn neighbors(
        &self,
        params: Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        let extra = interface_args(p.interface.as_deref())?;
        let raw = self.runner.run("neighbors", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.neighbors",
            raw,
        )))
    }

    /// Routing table across all tables (`ip -j route show table all`).
    #[tool(
        name = "net.routes",
        description = "Show the routing table across all routing tables."
    )]
    #[instrument(skip(self))]
    pub async fn routes(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("routes", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.routes",
            raw,
        )))
    }

    /// Bounded ICMP connectivity check (`ping -n -c <count> -W <wait>`).
    #[tool(
        name = "net.ping",
        description = "Bounded ping connectivity check against a target host."
    )]
    #[instrument(skip(self, params))]
    pub async fn ping(&self, params: Parameters<PingParams>) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        validate_ip_or_host(&p.target)?;
        let count = bounded(p.count, "count", 1, 10)?.unwrap_or(3);
        let wait = bounded(p.timeout_secs, "timeout_secs", 1, 5)?.unwrap_or(2);
        let extra = vec![
            "-c".to_string(),
            count.to_string(),
            "-W".to_string(),
            wait.to_string(),
            p.target,
        ];
        let raw = self.runner.run("ping", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.ping", raw,
        )))
    }

    /// Bounded path diagnosis (`traceroute -n -m <max_hops> <target>`).
    #[tool(
        name = "net.traceroute",
        description = "Bounded traceroute path diagnosis to a target host."
    )]
    #[instrument(skip(self, params))]
    pub async fn traceroute(
        &self,
        params: Parameters<TracerouteParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        validate_ip_or_host(&p.target)?;
        let hops = bounded(p.max_hops, "max_hops", 1, 30)?.unwrap_or(12);
        let extra = vec!["-m".to_string(), hops.to_string(), p.target];
        let raw = self.runner.run("traceroute", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.traceroute",
            raw,
        )))
    }

    /// Recent system logs (`journalctl -n <lines> [-u <unit>]`).
    #[tool(
        name = "net.logs",
        description = "Extract recent system log lines. Optionally restrict to one systemd unit."
    )]
    #[instrument(skip(self, params))]
    pub async fn logs(&self, params: Parameters<LogsParams>) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        let lines = bounded(p.lines, "lines", 1, 200)?.unwrap_or(50);
        let mut extra = vec!["-n".to_string(), lines.to_string()];
        if let Some(unit) = p.unit.as_deref() {
            validate_interface(unit)?;
            extra.push("-u".to_string());
            extra.push(unit.to_string());
        }
        let raw = self.runner.run("logs", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.logs", raw,
        )))
    }
}

/// Build the `dev <iface>` argument pair for the interface-scoped tools,
/// validating the name first. An absent interface yields no extra args.
fn interface_args(interface: Option<&str>) -> Result<Vec<String>, NetdiagError> {
    match interface {
        Some(iface) => {
            validate_interface(iface)?;
            Ok(vec!["dev".to_string(), iface.to_string()])
        }
        None => Ok(Vec::new()),
    }
}

/// Enforce an inclusive `[min, max]` range on an optional integer
/// parameter. `None` passes through; an out-of-range value is rejected
/// with the pinned `InvalidParam` code (-32010).
///
/// schemars advertises the same bounds in the generated input schema, but
/// that is advisory — rmcp does not reject out-of-range integers at
/// deserialization, so this runtime check is the enforced boundary.
fn bounded(
    value: Option<u64>,
    name: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, NetdiagError> {
    match value {
        Some(v) if v < min || v > max => Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: format!("must be in range [{min}, {max}]"),
        }),
        other => Ok(other),
    }
}

/// Input for the interface-scoped tools (`net.if_status`, `net.neighbors`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InterfaceParams {
    /// Restrict output to this interface; omit for all interfaces.
    #[serde(default)]
    pub interface: Option<String>,
}

/// Input for `net.mac_lookup`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MacLookupParams {
    /// MAC address to look up, in `aa:bb:cc:dd:ee:ff` form.
    pub mac: String,
}

/// Input for `net.ping`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PingParams {
    /// IP address or hostname to ping.
    pub target: String,
    /// Echo requests to send (1–10, default 3).
    #[serde(default)]
    #[schemars(range(min = 1, max = 10))]
    pub count: Option<u64>,
    /// Per-reply wait in seconds (1–5, default 2).
    #[serde(default)]
    #[schemars(range(min = 1, max = 5))]
    pub timeout_secs: Option<u64>,
}

/// Input for `net.traceroute`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TracerouteParams {
    /// IP address or hostname to trace.
    pub target: String,
    /// Maximum hops to probe (1–30, default 12).
    #[serde(default)]
    #[schemars(range(min = 1, max = 30))]
    pub max_hops: Option<u64>,
}

/// Input for `net.logs`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogsParams {
    /// Number of recent journal lines to return (1–200, default 50).
    #[serde(default)]
    #[schemars(range(min = 1, max = 200))]
    pub lines: Option<u64>,
    /// Restrict to this systemd unit; omit for all units.
    #[serde(default)]
    pub unit: Option<String>,
}

#[tool_handler(router = self.tool_router)]
impl<R: CommandExecutor> ServerHandler for NetdiagServer<R> {
    /// Override the macro-generated `call_tool` so dispatch has a single
    /// chokepoint for the tool-call audit journal. Lifecycle methods
    /// (`initialize`, `tools/list`, `notifications/initialized`) never
    /// enter this method, so narrowing the journal to "tool calls only"
    /// falls out of the hook point.
    ///
    /// One `call` row goes in before dispatch and one `result` row after,
    /// regardless of outcome. Journal I/O is wrapped in `JournalWriter::log`
    /// which warns-and-swallows on failure, so auditing never blocks a
    /// tool call.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // Capture what we need for journaling BEFORE moving `request`
        // into the SDK's ToolCallContext.
        let tool_name = request.name.to_string();
        let args_value: Value = request
            .arguments
            .as_ref()
            .map(|m| Value::Object(m.clone()))
            .unwrap_or(Value::Null);

        if let Some(j) = &self.journal {
            let entry = JournalEntry::new(
                tool_name.clone(),
                JournalEntry::DIR_CALL,
                journal::call_summary(&args_value),
            );
            j.log(&entry).await;
        }

        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        let result = self.tool_router.call(tcc).await;

        if let Some(j) = &self.journal {
            let result_ref: Result<&CallToolResult, &McpError> = result.as_ref();
            let entry = JournalEntry::new(
                tool_name,
                JournalEntry::DIR_RESULT,
                journal::result_summary(&result_ref),
            );
            j.log(&entry).await;
        }

        result
    }

    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` is `#[non_exhaustive]`, so start from `default()`
        // (already pinned to the latest protocol version) and overwrite
        // only what we set. `Implementation` is built explicitly rather
        // than via `from_build_env()` — that helper expands its
        // `env!("CARGO_PKG_*")` at the rmcp crate's build site and would
        // report `name = "rmcp"`.
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_passes_none_and_in_range() {
        assert_eq!(bounded(None, "count", 1, 10).unwrap(), None);
        assert_eq!(bounded(Some(5), "count", 1, 10).unwrap(), Some(5));
        assert_eq!(bounded(Some(1), "count", 1, 10).unwrap(), Some(1));
        assert_eq!(bounded(Some(10), "count", 1, 10).unwrap(), Some(10));
    }

    #[test]
    fn bounded_rejects_out_of_range_with_invalid_param() {
        let err = bounded(Some(99), "count", 1, 10).unwrap_err();
        assert!(matches!(err, NetdiagError::InvalidParam { ref name, .. } if name == "count"));
        assert_eq!(err.code(), -32010);
    }

    #[test]
    fn interface_args_validates_and_builds_pair() {
        assert_eq!(interface_args(None).unwrap(), Vec::<String>::new());
        assert_eq!(
            interface_args(Some("eth0")).unwrap(),
            vec!["dev".to_string(), "eth0".to_string()]
        );
        assert!(interface_args(Some("eth0;rm")).is_err());
    }
}
