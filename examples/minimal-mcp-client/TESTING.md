# Testing Guide: minimal-mcp-client + mcp-netdiag-rs

This guide is for quick validation with a colleague.

## 1. Prerequisites

- Rust toolchain installed on test machine.
- `mcp-netdiag-rs` source available.
- For target-device tests: SSH access to `iotgw`.

## 2. Build Server and Client

From project root:

```bash
cd /home/umair/GitRepos/ai-learning/mcp-getting-started/mcp-netdiag-rs
cargo build --release
```

Build client:

```bash
cd examples/minimal-mcp-client
cargo build
```

## 3. Local Smoke Test (human-readable)

```bash
cd /home/umair/GitRepos/ai-learning/mcp-getting-started/mcp-netdiag-rs/examples/minimal-mcp-client
cargo run -- \
  --server ../../target/release/mcp-netdiag-rs \
  --question "host cannot reach gateway from vlan20" \
  --interface vlan20 \
  --target 8.8.8.8
```

Expected:
- MCP handshake lines (`initialized`, `tools discovered`, `plan`).
- Per-tool result lines with `status`/`signal`.
- Final diagnosis summary.

## 4. Local Smoke Test (JSON output)

```bash
cd /home/umair/GitRepos/ai-learning/mcp-getting-started/mcp-netdiag-rs/examples/minimal-mcp-client
cargo run -- \
  --server ../../target/release/mcp-netdiag-rs \
  --question "host cannot reach gateway from vlan20" \
  --interface vlan20 \
  --target 8.8.8.8 \
  --json
```

Expected:
- One JSON document with keys: `question`, `context`, `mcp`, `results`, `diagnosis`.

Quick parse check:

```bash
cargo run -- \
  --server ../../target/release/mcp-netdiag-rs \
  --question "gateway unreachable" \
  --target 8.8.8.8 \
  --json | jq '.diagnosis'
```

## 5. Run on iotgw (recommended real test)

### 5.1 Verify server binary exists on target

```bash
ssh iotgw 'which mcp-netdiag-rs && file $(which mcp-netdiag-rs)'
```

Expected: `aarch64` ELF.

### 5.2 Run one direct MCP call on target

```bash
ssh iotgw "printf '%s\n' \
'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"net.routes\",\"arguments\":{}}}' \
| mcp-netdiag-rs"
```

Expected: JSON-RPC response with `result.content[0].json`.

### 5.3 Run minimal client against target server via SSH pipe (optional)

If the client is on your laptop and server must run on `iotgw`, use an MCP relay/wrapper later. Current minimal client expects local process execution.

Practical approach now:
- run client directly on target if Rust/client binary is available there, OR
- run both server+client on same machine for protocol validation.

## 6. Test Cases to Demo With Colleague

1. L2 issue style question:
```bash
cargo run -- --server ../../target/release/mcp-netdiag-rs --question "link flaps on vlan20" --interface vlan20 --json
```

2. L3 issue style question:
```bash
cargo run -- --server ../../target/release/mcp-netdiag-rs --question "cannot reach gateway" --target 10.10.20.1 --json
```

3. Generic issue (auto mixed plan):
```bash
cargo run -- --server ../../target/release/mcp-netdiag-rs --question "network issue" --json
```

## 7. Known Pitfalls

- `Exec format error`: wrong architecture binary on target.
- `No such file or directory` for tool call: command missing on host (example: `traceroute` not installed).
- `Operation not permitted`: run context lacks needed network capabilities.
- Non-JSON-friendly output: use `--json` flag.

## 8. What “Pass” Looks Like

- Handshake succeeds (`initialize`, `tools/list`).
- At least one `tools/call` returns structured result.
- JSON report produced with `diagnosis.likely_domain` and per-tool entries.
- On `iotgw`, binary is `aarch64` and executable.
