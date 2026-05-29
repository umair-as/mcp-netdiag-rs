# mcp-netdiag-rs

A read-only MCP server for Linux network diagnostics. It exposes a small set
of vetted, allowlisted commands (`ip`, `bridge`, `ping`, `traceroute`,
`journalctl`, `systemctl`, `ss`, `ethtool`, `nft`, `conntrack`, `tcpdump`,
and small system probes) as MCP tools, so an MCP-capable assistant can inspect a host's
live network state without being handed a shell. It runs on any Linux host
with the standard `iproute2` / `ping` / `traceroute` / `systemd` userspace.

## Problem It Solves

Network troubleshooting on a Linux host is usually manual and command-heavy.
`mcp-netdiag-rs` provides a safe, structured diagnostics interface so an
MCP-capable assistant can:
- call vetted diagnostic tools,
- collect live network evidence from the host,
- return concise, actionable diagnosis to the operator.

## High-Level Architecture

1. User asks a troubleshooting question in an MCP client.
2. MCP client connects to `mcp-netdiag-rs` over the MCP protocol (`stdio`).
3. Server exposes tools via `tools/list` and executes via `tools/call`.
4. Each tool maps to an allowlisted Linux command on the same host.
5. Server returns structured result payloads (`status`, `signal`, `evidence`, `suggested_action`, `raw`).
6. Client/LLM synthesizes final diagnosis for the user.

## Scope and Requirements

### Functional Requirements

- Interface status and counters (`net.if_status`)
- MAC table lookup (`net.mac_lookup`)
- ARP/neighbor state (`net.neighbors`)
- Routing table state (`net.routes`)
- Address, detailed link, route lookup, and policy-rule state
- Connectivity checks (`net.ping`, `net.traceroute`) with bounds
- Socket, DNS, ethtool, firewall, conntrack, and bounded packet-capture probes
- Failed unit, service status, kernel log, uptime, memory, and filesystem checks
- Bounded log extraction (`net.logs`)

### Non-Functional Requirements

- Read-only diagnostics only (no config mutation)
- Strict command allowlist
- Input validation for all tool args
- Execution timeout guard
- Output size/line bounds
- MCP JSON-RPC compatibility for tool workflows

## MCP Protocol Layer

The protocol layer is the [`rmcp`](https://crates.io/crates/rmcp) SDK over its
stdio transport. The SDK owns `initialize`, `notifications/initialized`,
`tools/list`, `tools/call`, and the standard JSON-RPC
parse/invalid-request/method/params errors. Tool input schemas are derived from
typed parameter structs via `schemars`.

Project-specific tool errors use pinned codes: `-32010` invalid parameter,
`-32011` command not allowed, `-32012` command execution failed.

## Tool to Command Mapping

Basic diagnostics:

- `net.if_status` -> `ip -j -s link show [dev <interface>]`
- `net.mac_lookup` -> `bridge -j fdb show to <mac>`
- `net.neighbors` -> `ip -j neigh show [dev <interface>]`
- `net.routes` -> `ip -j route show table all`
- `net.addr` -> `ip -j addr show [dev <interface>]`
- `net.link_detail` -> `ip -j -d link show [dev <interface>]`
- `net.route_get` -> `ip -j route get <target>`
- `net.rules` -> `ip -j rule show`
- `net.ping` -> `ping -n -c <1..10> -W <1..5> <target>`
- `net.traceroute` -> `traceroute -n -m <1..30> <target>`
- `net.logs` -> `journalctl --no-pager --output=short-iso -n <1..200> [-u <unit>]`
- `sys.failed_units` -> `systemctl --failed --no-pager --plain`
- `sys.uptime` -> `uptime`
- `sys.memory` -> `free -h`
- `sys.filesystems` -> `df -h`

Extended diagnostics:

- `net.sockets` -> `ss -H -tuna`
- `net.dns_status` -> `resolvectl status`
- `net.resolv_conf` -> read `/etc/resolv.conf`
- `net.ethtool` -> `ethtool <interface>`
- `sys.service_status` -> `systemctl status --no-pager --lines <1..200> <unit>`
- `sys.dmesg` -> `dmesg -T`

Forensics-oriented diagnostics:

- `net.firewall` -> `nft list ruleset`
- `net.conntrack` -> `conntrack -L`
- `net.tcpdump_sample` -> `tcpdump -nn -i <interface> -c <1..50>`

Some extended and forensics-oriented diagnostics require elevated privileges
or Linux capabilities on typical systems. In particular, `net.firewall`,
`net.conntrack`, `net.tcpdump_sample`, `sys.dmesg`, and some `net.ethtool`
queries may return `status: "fail"` when the server process lacks the needed
permissions. That is reported as a normal diagnostic result, not as MCP
transport failure.

`net.tcpdump_sample` waits until the requested packet count is captured or the
server command timeout expires. On idle interfaces, prefer a small `count` and
expect a command-timeout tool error if no packets arrive.

## Security Model

The 24 tools split into two tiers. The split determines what runs by
default; both tiers share the compile-time command allowlist, the
per-token validators, the wall-clock timeout, and the output bounds
described in [SECURITY.md](SECURITY.md).

- **Tier 1 — 18 tools, enabled by default.** Pure reads of
  unprivileged Linux state: `ip` / `ss` / `resolvectl` / `systemctl` /
  `df` / `free` / `journalctl` / `ethtool` and friends. No
  capabilities required; safe to run as an unprivileged user.
- **Tier 2 — 6 tools, refused by default.** Either emit observable
  side effects on the wire (`net.ping`, `net.traceroute`,
  `net.tcpdump_sample`) or require elevated Linux capabilities to
  read kernel state (`net.firewall` / `net.conntrack` need
  `CAP_NET_ADMIN`, `net.tcpdump_sample` also needs `CAP_NET_RAW`,
  `sys.dmesg` needs `CAP_SYSLOG` when `kernel.dmesg_restrict=1`).
  The operator opts in per-deployment via `NETDIAG_ENABLE_TIER2`
  (see [Configuration](#configuration)). With the env var unset,
  every tier-2 call returns `-32011` and never spawns a subprocess.

The two opt-ins compose by AND: a tier-2 opt-in cannot widen a
narrower `NETDIAG_ALLOWLIST`. If a tool is not in the allowlist, no
env var can make it run.

See [SECURITY.md](SECURITY.md) for the threat model, the full per-tool
capability table, and a systemd unit recipe for tier-2 deployments.

## Configuration

Environment variables:

- `NETDIAG_JOURNAL` — path to the JSONL tool-call audit journal (default
  `/tmp/mcp-netdiag-journal.jsonl`). Always-on; an unwritable path degrades to
  a warning and the server continues without auditing.
- `NETDIAG_ALLOWLIST` — comma-separated subset of built-in command keys from
  the mapping table above. When set, only the listed commands are runnable.
  This is a *narrowing* filter — it can only disable built-in commands, never
  add programs or arguments.
- `NETDIAG_ENABLE_TIER2` — opt-in for the six tier-2 tools (see [Security
  Model](#security-model)). Accepts a comma-separated subset of
  `{ping, traceroute, tcpdump_sample, firewall, conntrack, dmesg}`, the
  literal `all`, or `none` / empty / unset. Case-sensitive. Default: unset
  → no tier-2 tools enabled. Composes with `NETDIAG_ALLOWLIST` by AND;
  cannot widen the allowlist.
- `RUST_LOG` — `tracing` filter (default `mcp_netdiag_rs=info`); logs go to
  stderr, never stdout.

## Deployment

Run the server locally on the host you want to diagnose, so its tools reflect
that host's real network state. It builds to a single self-contained binary —
install it however suits the target: a distro package, a container image, or
(for embedded Linux) a Yocto/BitBake recipe.

## Local Development

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Notes

- This server is intended to be invoked by an MCP client, not interacted with directly by humans.
- Transport is line-delimited JSON over `stdin`/`stdout`.
