// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed tool-parameter structs.
//!
//! One struct per parameterised tool. `rmcp` derives each tool's input schema
//! from these via `schemars`, and `#[serde(deny_unknown_fields)]` makes the
//! SDK reject unknown arguments with `-32602`. Integer `range(...)` bounds are
//! advertised here but enforced at runtime in [`super`] (`bounded`), which is
//! the authoritative check.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Input for the interface-scoped tools (`net.if_status`, `net.neighbors`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InterfaceParams {
    /// Restrict output to this interface; omit for all interfaces.
    #[serde(default)]
    pub interface: Option<String>,
}

/// Input for tools that require an interface name.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequiredInterfaceParams {
    /// Interface to inspect.
    pub interface: String,
}

/// Input for target-scoped tools.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetParams {
    /// IP address or hostname to inspect.
    pub target: String,
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

/// Input for `sys.service_status`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatusParams {
    /// Systemd unit to inspect.
    pub unit: String,
    /// Number of status log lines to include (1-200, default 50).
    #[serde(default)]
    #[schemars(range(min = 1, max = 200))]
    pub lines: Option<u64>,
}

/// Input for `net.tcpdump_sample`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TcpdumpParams {
    /// Interface to capture from.
    pub interface: String,
    /// Packets to capture (1-50, default 10).
    #[serde(default)]
    #[schemars(range(min = 1, max = 50))]
    pub count: Option<u64>,
}
