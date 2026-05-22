# minimal-mcp-client

Minimal MCP client for `mcp-netdiag-rs`.

## What It Does

- Starts the MCP server process over `stdio`
- Runs MCP handshake (`initialize` + `notifications/initialized`)
- Executes a small rule-based diagnostics plan using `tools/call`
- Prints diagnosis summary with evidence and suggested actions

## Usage

```bash
cd examples/minimal-mcp-client
cargo run -- \
  --server ../../target/release/mcp-netdiag-rs \
  --question "host cannot reach gateway from vlan 20" \
  --interface vlan20 \
  --target 10.10.20.1 \
  --json
```

## Arguments

- `--server <path>`: path to MCP server binary (default: `../../target/release/mcp-netdiag-rs`)
- `--question <text>`: troubleshooting question
- `--interface <ifname>`: optional interface hint
- `--target <ip-or-host>`: optional target for ping/traceroute

## Notes

- This client is intentionally minimal and rule-based (no LLM required).
- It calls only MCP tools from the server; no direct shell diagnostics are executed by the client.
