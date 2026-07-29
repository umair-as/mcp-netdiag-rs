// SPDX-License-Identifier: MIT OR Apache-2.0

//! rmcp adapter layer.
//!
//! The production MCP protocol layer: an MCP server built on the `rmcp`
//! SDK. `rmcp` owns the stdio transport and the `initialize` /
//! `tools/list` / `tools/call` framing; all diagnostic tools are wired
//! here as `#[tool]` handlers.
//!
//! This module owns no netdiag-domain logic — command execution, the
//! allowlist, validators, and result shaping live in [`crate::netdiag`].
//! It only adapts rmcp tool calls onto that domain, and is **stateless**:
//! every call is fire-and-forget, there is no session concept.

pub mod journal;
pub mod params;

use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResult, Implementation, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde_json::Value;
use tracing::instrument;

use crate::errors::NetdiagError;
use crate::netdiag::validators::{
    validate_interface, validate_ip_or_host, validate_mac, validate_unit,
};
use crate::netdiag::{normalize_tool_result, CommandExecutor};
use journal::{JournalEntry, JournalWriter};
use params::{
    InterfaceParams, LogsParams, MacLookupParams, PingParams, RequiredInterfaceParams,
    ServiceStatusParams, TargetParams, TcpdumpParams, TracerouteParams,
};

/// rmcp-facing server. Holds the command executor and the optional audit
/// journal, and registers the diagnostic tools with the `rmcp` SDK. Generic
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
        description = "Show interface state and counters. Optionally restrict to one interface.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
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
        description = "Look up a MAC address in the bridge forwarding database.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
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
        description = "Show ARP/neighbor state. Optionally restrict to one interface.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
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
        description = "Show the routing table across all routing tables.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn routes(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("routes", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.routes",
            raw,
        )))
    }

    /// Interface addresses (`ip -j addr show [dev <iface>]`).
    #[tool(
        name = "net.addr",
        description = "Show interface addresses. Optionally restrict to one interface.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self, params))]
    pub async fn addr(
        &self,
        params: Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        let extra = interface_args(p.interface.as_deref())?;
        let raw = self.runner.run("addr", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.addr", raw,
        )))
    }

    /// Detailed link state (`ip -j -d link show [dev <iface>]`).
    #[tool(
        name = "net.link_detail",
        description = "Show detailed link state. Optionally restrict to one interface.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self, params))]
    pub async fn link_detail(
        &self,
        params: Parameters<InterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        let extra = interface_args(p.interface.as_deref())?;
        let raw = self.runner.run("link_detail", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.link_detail",
            raw,
        )))
    }

    /// Route lookup for a specific target (`ip -j route get <target>`).
    #[tool(
        name = "net.route_get",
        description = "Resolve the route the kernel would use for a target host.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self, params))]
    pub async fn route_get(
        &self,
        params: Parameters<TargetParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        validate_ip_or_host(&p.target)?;
        let raw = self.runner.run("route_get", &[p.target]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.route_get",
            raw,
        )))
    }

    /// Policy routing rules (`ip -j rule show`).
    #[tool(
        name = "net.rules",
        description = "Show policy routing rules.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn rules(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("rules", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.rules",
            raw,
        )))
    }

    /// Bounded ICMP connectivity check (`ping -n -c <count> -W <wait>`).
    ///
    /// `read_only_hint = false` / `idempotent_hint = false`: this tool
    /// emits ICMP echo requests on the wire. Each invocation produces
    /// fresh observable effects, so the MCP spec's "readOnly" / "idempotent"
    /// definitions do not apply — even though no host configuration
    /// changes. See SECURITY.md for the rationale.
    #[tool(
        name = "net.ping",
        description = "[Privileged: CAP_NET_RAW] Bounded ping connectivity check against a target host.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true,
        )
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
    ///
    /// `read_only_hint = false` / `idempotent_hint = false`: emits UDP/ICMP
    /// probes. Same rationale as `net.ping` — host config is unchanged
    /// but the wire is touched on every call.
    #[tool(
        name = "net.traceroute",
        description = "[Privileged: CAP_NET_RAW] Bounded traceroute path diagnosis to a target host.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true,
        )
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

    /// Socket snapshot (`ss -H -tuna`).
    #[tool(
        name = "net.sockets",
        description = "Show TCP/UDP socket state without process details.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn sockets(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("sockets", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.sockets",
            raw,
        )))
    }

    /// Resolver state (`resolvectl status`).
    #[tool(
        name = "net.dns_status",
        description = "Show systemd-resolved DNS state.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn dns_status(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("dns_status", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.dns_status",
            raw,
        )))
    }

    /// Resolver configuration file (`cat /etc/resolv.conf`).
    #[tool(
        name = "net.resolv_conf",
        description = "Show /etc/resolv.conf resolver configuration.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn resolv_conf(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("resolv_conf", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.resolv_conf",
            raw,
        )))
    }

    /// NIC driver/link details (`ethtool <iface>`).
    #[tool(
        name = "net.ethtool",
        description = "Show ethtool details for an interface.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self, params))]
    pub async fn ethtool(
        &self,
        params: Parameters<RequiredInterfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        validate_interface(&p.interface)?;
        let raw = self.runner.run("ethtool", &[p.interface]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.ethtool",
            raw,
        )))
    }

    /// Firewall ruleset (`nft list ruleset`).
    #[tool(
        name = "net.firewall",
        description = "[Privileged: CAP_NET_ADMIN] Show nftables firewall ruleset.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    #[instrument(skip(self))]
    pub async fn firewall(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("firewall", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.firewall",
            raw,
        )))
    }

    /// Connection tracking table (`conntrack -L`).
    #[tool(
        name = "net.conntrack",
        description = "[Privileged: CAP_NET_ADMIN] Show the connection tracking table.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    #[instrument(skip(self))]
    pub async fn conntrack(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("conntrack", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.conntrack",
            raw,
        )))
    }

    /// Bounded packet sample (`tcpdump -nn -i <iface> -c <count>`).
    ///
    /// `read_only_hint = false` / `idempotent_hint = false`: tcpdump opens
    /// an AF_PACKET socket and (without `-p`) toggles promiscuous mode on
    /// the interface for the capture window. The promisc transition is
    /// observable to other listeners on the link and to the kernel's
    /// link-flag state, so this is a genuine environmental side effect.
    /// See SECURITY.md for the rationale.
    #[tool(
        name = "net.tcpdump_sample",
        description = "[Privileged: CAP_NET_RAW + CAP_NET_ADMIN] Capture a bounded packet sample on one interface.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true,
        )
    )]
    #[instrument(skip(self, params))]
    pub async fn tcpdump_sample(
        &self,
        params: Parameters<TcpdumpParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        validate_interface(&p.interface)?;
        let count = bounded(p.count, "count", 1, 50)?.unwrap_or(10);
        let extra = vec![
            "-i".to_string(),
            p.interface,
            "-c".to_string(),
            count.to_string(),
        ];
        let raw = self.runner.run("tcpdump_sample", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.tcpdump_sample",
            raw,
        )))
    }

    /// Recent system logs (`journalctl -n <lines> [-u <unit>]`).
    #[tool(
        name = "net.logs",
        description = "Extract recent system log lines. Optionally restrict to one systemd unit.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self, params))]
    pub async fn logs(&self, params: Parameters<LogsParams>) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        let lines = bounded(p.lines, "lines", 1, 200)?.unwrap_or(50);
        let mut extra = vec!["-n".to_string(), lines.to_string()];
        if let Some(unit) = p.unit.as_deref() {
            validate_unit(unit)?;
            extra.push("-u".to_string());
            extra.push(unit.to_string());
        }
        let raw = self.runner.run("logs", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "net.logs", raw,
        )))
    }

    /// Failed systemd units (`systemctl --failed --no-pager --plain`).
    #[tool(
        name = "sys.failed_units",
        description = "Show failed systemd units.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn failed_units(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("failed_units", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "sys.failed_units",
            raw,
        )))
    }

    /// Systemd service status (`systemctl status --no-pager --lines <n> <unit>`).
    #[tool(
        name = "sys.service_status",
        description = "Show bounded systemd status for one unit.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self, params))]
    pub async fn service_status(
        &self,
        params: Parameters<ServiceStatusParams>,
    ) -> Result<CallToolResult, McpError> {
        let Parameters(p) = params;
        validate_unit(&p.unit)?;
        let lines = bounded(p.lines, "lines", 1, 200)?.unwrap_or(50);
        let extra = vec!["--lines".to_string(), lines.to_string(), p.unit];
        let raw = self.runner.run("service_status", &extra).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "sys.service_status",
            raw,
        )))
    }

    /// Kernel ring buffer (`dmesg -T`), bounded by output capture limits.
    #[tool(
        name = "sys.dmesg",
        description = "[Privileged: CAP_SYSLOG] Show kernel ring buffer messages.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true,
        )
    )]
    #[instrument(skip(self))]
    pub async fn dmesg(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("dmesg", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "sys.dmesg",
            raw,
        )))
    }

    /// System uptime and load (`uptime`).
    #[tool(
        name = "sys.uptime",
        description = "Show uptime and load average.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn uptime(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("uptime", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "sys.uptime",
            raw,
        )))
    }

    /// Memory summary (`free -h`).
    #[tool(
        name = "sys.memory",
        description = "Show memory usage summary.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn memory(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("memory", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "sys.memory",
            raw,
        )))
    }

    /// Filesystem usage (`df -h`).
    #[tool(
        name = "sys.filesystems",
        description = "Show filesystem usage summary.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false,
        )
    )]
    #[instrument(skip(self))]
    pub async fn filesystems(&self) -> Result<CallToolResult, McpError> {
        let raw = self.runner.run("filesystems", &[]).await?;
        Ok(CallToolResult::structured(normalize_tool_result(
            "sys.filesystems",
            raw,
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
