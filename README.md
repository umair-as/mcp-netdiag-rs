# mcp-netdiag-rs

Read-only MCP server for network diagnostics on embedded Linux (target: IoT gateway / switch platform).

## Problem It Solves

Troubleshooting on gateway/switch devices is usually manual and command-heavy (`ip`, `bridge`, `ping`, `journalctl`).

`mcp-netdiag-rs` provides a safe, structured diagnostics interface so an MCP-capable assistant can:
- call vetted diagnostics tools,
- collect live network evidence from the target,
- return concise, actionable diagnosis to the operator.

## High-Level Architecture

1. User asks a troubleshooting question in an MCP client.
2. MCP client connects to `mcp-netdiag-rs` over JSON-RPC (`stdio`).
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

## MCP Methods Implemented

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`

Error handling includes standard JSON-RPC parse/invalid/method/params errors and project-specific tool errors.

## Tool to Command Mapping

- `net.if_status` -> `ip -j -s link show [dev <interface>]`
- `net.mac_lookup` -> `bridge -j fdb show to <mac>`
- `net.neighbors` -> `ip -j neigh show [dev <interface>]`
- `net.routes` -> `ip -j route show table all`
- `net.ping` -> `ping -n -c <1..10> -W <1..5> <target>`
- `net.traceroute` -> `traceroute -n -m <1..30> <target>`
- `net.logs` -> `journalctl --no-pager --output=short-iso -n <1..200> [-u <unit>]`

## Deployment Model

Target deployment is Yocto-managed `iotgw` (`aarch64`).

Recommended production path:
- package via BitBake recipe,
- include in image/packagegroup,
- run locally on target so diagnostics reflect real host network state.

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
