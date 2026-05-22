# mcp-netdiag-rs

A read-only MCP server for Linux network diagnostics. It exposes a small set
of vetted, allowlisted commands (`ip`, `bridge`, `ping`, `traceroute`,
`journalctl`) as MCP tools, so an MCP-capable assistant can inspect a host's
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
- Connectivity checks (`net.ping`, `net.traceroute`) with bounds
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

- `net.if_status` -> `ip -j -s link show [dev <interface>]`
- `net.mac_lookup` -> `bridge -j fdb show to <mac>`
- `net.neighbors` -> `ip -j neigh show [dev <interface>]`
- `net.routes` -> `ip -j route show table all`
- `net.ping` -> `ping -n -c <1..10> -W <1..5> <target>`
- `net.traceroute` -> `traceroute -n -m <1..30> <target>`
- `net.logs` -> `journalctl --no-pager --output=short-iso -n <1..200> [-u <unit>]`

## Configuration

Environment variables:

- `NETDIAG_JOURNAL` — path to the JSONL tool-call audit journal (default
  `/tmp/mcp-netdiag-journal.jsonl`). Always-on; an unwritable path degrades to
  a warning and the server continues without auditing.
- `NETDIAG_ALLOWLIST` — comma-separated subset of command keys (`if_status`,
  `mac_table`, `neighbors`, `routes`, `ping`, `traceroute`, `logs`). When set,
  only the listed commands are runnable. This is a *narrowing* filter — it can
  only disable built-in commands, never add programs or arguments.
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
