# Testing Guide: minimal-mcp-client + mcp-netdiag-rs

A quick validation walkthrough for the example client against the server.

## 1. Prerequisites

- Rust toolchain installed on the test machine.
- `mcp-netdiag-rs` source available.
- For remote-host tests: SSH access to the Linux host you want to diagnose.

## 2. Build server and client

From the repository root:

```bash
cargo build --release
cargo build --manifest-path examples/minimal-mcp-client/Cargo.toml
```

## 3. Local smoke test (human-readable)

From `examples/minimal-mcp-client`:

```bash
cargo run -- \
  --server ../../target/release/mcp-netdiag-rs \
  --question "host cannot reach gateway from vlan20" \
  --interface vlan20 \
  --target 8.8.8.8
```

Expected:
- MCP handshake lines (`initialized`, `tools discovered`, `plan`).
- Per-tool result lines with `status` / `signal`.
- A final diagnosis summary.

## 4. Local smoke test (JSON output)

```bash
cargo run -- \
  --server ../../target/release/mcp-netdiag-rs \
  --question "host cannot reach gateway from vlan20" \
  --interface vlan20 \
  --target 8.8.8.8 \
  --json
```

Expected: one JSON document with keys `question`, `context`, `mcp`,
`results`, `diagnosis`.

Quick parse check:

```bash
cargo run -- \
  --server ../../target/release/mcp-netdiag-rs \
  --question "gateway unreachable" \
  --target 8.8.8.8 \
  --json | jq '.diagnosis'
```

## 5. Run on a remote host (real test)

Replace `<host>` with the SSH target of the Linux host you want to diagnose.

### 5.1 Verify the server binary exists on the host

```bash
ssh <host> 'which mcp-netdiag-rs && file $(which mcp-netdiag-rs)'
```

Expected: an ELF binary built for the host's architecture.

### 5.2 Run one direct MCP exchange on the host

The server uses the rmcp SDK, which requires the `initialize` handshake
before any `tools/call`:

```bash
ssh <host> "printf '%s\n%s\n%s\n' \
'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"smoke\",\"version\":\"0\"}}}' \
'{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}' \
'{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"net.routes\",\"arguments\":{}}}' \
| mcp-netdiag-rs"
```

Expected: a JSON-RPC response whose `result.structuredContent` carries the
`tool` / `status` / `signal` / `evidence` envelope.

### 5.3 Run the minimal client against a remote server (optional)

The minimal client spawns the server as a local child process. To drive a
server on a remote host, run both the client and the server on that host, or
place an MCP relay/wrapper between them.

## 6. Test cases to demo

1. L2-style question:
```bash
cargo run -- --server ../../target/release/mcp-netdiag-rs --question "link flaps on vlan20" --interface vlan20 --json
```

2. L3-style question:
```bash
cargo run -- --server ../../target/release/mcp-netdiag-rs --question "cannot reach gateway" --target 10.10.20.1 --json
```

3. Generic question (auto mixed plan):
```bash
cargo run -- --server ../../target/release/mcp-netdiag-rs --question "network issue" --json
```

## 7. Known pitfalls

- `Exec format error`: the binary was built for the wrong architecture.
- A tool call reporting a missing command: the underlying program (e.g.
  `traceroute`) is not installed on the host.
- `Operation not permitted`: the run context lacks the needed network
  capabilities.
- Non-JSON-friendly output: pass the `--json` flag.

## 8. What "pass" looks like

- Handshake succeeds (`initialize`, `tools/list`).
- At least one `tools/call` returns a structured result.
- A JSON report is produced with `diagnosis.likely_domain` and per-tool
  entries.
