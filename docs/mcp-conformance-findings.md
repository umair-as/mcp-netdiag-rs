# MCP Conformance Findings

Date: 2026-06-01

Scope: review of `mcp-netdiag-rs` against the MCP `2025-11-25` tool model and
the current implementation in `src/mcp`, `src/netdiag`, and tests.

## Summary

`mcp-netdiag-rs` is already more MCP-native than the serial server in several
areas:

- It advertises MCP tool annotations for every tool.
- It distinguishes normal diagnostic command failure from transport/protocol
  failure by returning a structured diagnostic envelope with `status: "fail"`.
- It keeps command execution behind a compile-time allowlist.
- It validates user-controlled argv fragments before spawning commands.
- It bounds command runtime and captured output.
- It has design docs for resources and progress/cancellation.

The main remaining conformance gap is how tool-domain failures are surfaced.
Runtime validation failures, command allowlist refusals, privileged-tool
refusals, spawn failures, and timeouts currently become JSON-RPC errors. MCP
tool guidance prefers returning a normal `tools/call` response with
`CallToolResult.isError = true` for errors that happen inside tool execution.

## Findings

### 1. Tool-domain failures should be `isError: true`

Current handlers return `Err(McpError)` for runtime validation and domain
failures. Examples:

- runtime bounds validation in `bounded(...)`
- token validation failures such as bad interface, target, MAC, or unit
- command allowlist refusal
- privileged tool disabled
- command spawn failure
- command timeout

Relevant files:

- `src/mcp/mod.rs`
- `src/errors.rs`
- `src/netdiag/commands.rs`

The current `NetdiagError -> rmcp::ErrorData` mapping preserves useful pinned
codes, but it turns tool-domain outcomes into JSON-RPC errors. For MCP clients,
these are better represented as tool results:

```json
{
  "isError": true,
  "structuredContent": {
    "ok": false,
    "code": -32011,
    "kind": "PrivilegedDisabled",
    "message": "privileged tool disabled; set NETDIAG_ENABLE_PRIVILEGED=ping or NETDIAG_ENABLE_PRIVILEGED=all to enable",
    "data": {
      "command": "ping",
      "privileged": true,
      "enable_env": "NETDIAG_ENABLE_PRIVILEGED"
    }
  }
}
```

Keep JSON-RPC errors for protocol/envelope problems:

- malformed JSON-RPC
- unknown method
- unknown tool name
- parameter deserialization failure, such as unknown fields rejected by
  `deny_unknown_fields`

### 2. Add `outputSchema` for every tool

The server exposes generated input schemas, but tests explicitly assert that
`outputSchema` is absent.

Relevant files:

- `src/mcp/mod.rs`
- `tests/mcp_tests.rs`

All tools currently return the same stable diagnostic envelope:

```json
{
  "tool": "net.routes",
  "status": "ok",
  "signal": "command_succeeded",
  "evidence": "...",
  "suggested_action": "...",
  "raw": {
    "ok": true,
    "exit_code": 0,
    "stdout": "...",
    "stderr": ""
  }
}
```

That shared shape is a good candidate for one reusable output schema.

Suggested schema fields:

- `tool`: string
- `status`: enum `"ok" | "fail"`
- `signal`: string
- `evidence`: string
- `suggested_action`: string
- `raw.ok`: boolean
- `raw.exit_code`: integer or null
- `raw.stdout`: string
- `raw.stderr`: string

If tool-domain failures are converted to `isError: true`, define the error
schema alongside the success envelope.

### 3. Tool annotations are present and should be kept

Unlike `mcp-serial-rs`, this server already uses MCP tool annotations
throughout `src/mcp/mod.rs`.

Good existing behavior:

- default local read diagnostics use `readOnlyHint = true`
- privileged wire emitters (`net.ping`, `net.traceroute`,
  `net.tcpdump_sample`) use `readOnlyHint = false` and
  `idempotentHint = false`
- privileged tools advertise `openWorldHint = true`
- tests lock the annotation behavior

This is a strength of the implementation, not a gap.

Potential refinement:

- Add a short note in the README explaining that `readOnlyHint = false` for
  ping/traceroute/tcpdump is intentional because these tools emit packets or
  toggle observable kernel/network state, even though they do not mutate host
  configuration.

### 4. Resources are designed but not implemented

There is already a design document for MCP resources:

- `docs/design/resources.md`

Current `ServerInfo` only enables tools. It does not advertise resources.

Relevant file:

- `src/mcp/mod.rs`

The resource design is sound and should be implemented when ready:

- `netdiag://etc/resolv.conf`
- `netdiag://etc/nsswitch.conf`
- `netdiag://etc/hosts`
- `netdiag://proc/version`
- `netdiag://proc/cmdline`
- `netdiag://journal/recent`
- `netdiag://audit/tail`

This would move static or attachable diagnostic context out of the tool-only
surface and into the MCP resource model.

### 5. Progress and cancellation are designed but not implemented

There is already a design document for progress notifications and
cancellation:

- `docs/design/progress-and-cancellation.md`

Current command execution uses `tokio::time::timeout` and `kill_on_drop(true)`,
which bounds execution, but clients do not receive progress events and cannot
explicitly cancel long-running calls.

Relevant file:

- `src/netdiag/commands.rs`

Highest-value tools for progress/cancellation:

- `net.ping`
- `net.traceroute`
- `net.tcpdump_sample`
- `net.conntrack`
- `net.firewall`
- `sys.dmesg`

Implementation should confirm exactly how `rmcp 1.7` exposes cancellation to
tool handlers before committing to a local cancellation token design.

### 6. Prompts are missing

The server exposes tools only. It does not expose MCP prompts.

Useful prompts:

- diagnose host network reachability
- diagnose DNS resolution
- inspect link/interface health
- inspect systemd/network service health
- collect a compact system/network triage bundle

Prompts would encode safe, repeatable diagnostic flows so agents do not have
to rediscover the order of `net.if_status`, `net.addr`, `net.routes`,
`net.neighbors`, `net.ping`, `net.traceroute`, and `net.logs`.

### 7. Completion and discovery helpers are missing

Clients would benefit from discovering valid values:

- interface names
- systemd unit names
- enabled command keys after `NETDIAG_ALLOWLIST`
- privileged tools enabled by `NETDIAG_ENABLE_PRIVILEGED`
- safe/common targets such as default route gateway or configured DNS servers

Depending on SDK support, this could be exposed through resources, prompts,
completion-capable argument metadata, or small read-only discovery tools.

### 8. Server metadata is minimal

`serverInfo.name` and version are set correctly. Other metadata is minimal.

Relevant file:

- `src/mcp/mod.rs`

Potential improvements, if supported by the SDK structs:

- title
- description
- repository or website URL
- icon metadata

## Feature Requests

### Convert domain errors to structured tool errors

Add a helper that converts `NetdiagError` into `CallToolResult::structured_error`.
Then use it at the handler boundary so domain failures are visible to the
model as tool results.

Keep the existing pinned numeric codes in the structured payload for clients
that branch on them.

### Add a shared diagnostic output schema

Define one reusable output schema for the diagnostic envelope and attach it to
all tools. Add a second schema for structured tool errors if error conversion
is implemented.

### Implement MCP resources

Use the existing `docs/design/resources.md` as the implementation plan. Keep
resource URIs closed under `netdiag://` and avoid arbitrary `file://` access.

### Implement progress and cancellation

Use the existing `docs/design/progress-and-cancellation.md` as the
implementation plan. Start with progress for `net.ping`, `net.traceroute`, and
`net.tcpdump_sample`; these provide the clearest user-visible value.

### Add MCP prompts

Start with a small set of prompts that encode common diagnostic workflows:

- `diagnose_reachability`
- `diagnose_dns`
- `diagnose_interface`
- `diagnose_systemd_network`
- `collect_triage_bundle`

### Add discovery surfaces

Expose low-risk discovery through resources or tools:

- `netdiag://interfaces`
- `netdiag://systemd/units`
- `netdiag://config/enabled-tools`
- `netdiag://config/privileged-tools`

This makes client planning easier and reduces invalid tool calls.

## Status

This is a static conformance review; no source files are changed by it. Each
finding above is a candidate for a follow-up change, tracked separately from
the release-tooling and hardening work. The two largest items — MCP resources
and progress/cancellation — have their own design docs under `docs/design/`.
