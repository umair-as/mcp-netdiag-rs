# Progress notifications + cancellation (Option B)

> Status: design doc — approved direction, not yet implemented. Tracks the
> planned progress-notification + cancellation work for netdiag's
> long-running tools.

## Why

Five of netdiag's tools (`net.ping`, `net.traceroute`, `net.tcpdump_sample`,
`net.conntrack`, `net.firewall`) run for seconds at a time. Today they are
opaque waits from the calling agent's perspective: the call blocks, then
returns. The agent can't show progress, can't be interrupted by the user,
and can't gracefully abort if a parallel decision invalidates the work.

The MCP spec defines two primitives that fix this without expanding the
trust boundary or breaking statelessness:

- `notifications/progress` ([spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress)) — server pushes
  progress events with `progress`, `total`, and optional `message` fields
  against a `progressToken` the client supplied in the request's `_meta`.
- `notifications/cancelled` ([spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation)) — client tells
  the server to stop work on an in-flight `requestId`.

Both are spec-defined since the 2024-10 protocol and supported by rmcp 1.7.
Both work over stdio today. Neither adds state that persists across calls.

## Open question to resolve before coding

**Does rmcp 1.7's stdio dispatch loop actually deliver
`notifications/cancelled` to the handler in a way a `tokio` cancellation
token can observe?** The handler-level wiring is the project's job, but
how rmcp signals it on a stdio cancel is the load-bearing protocol detail.

Steps to confirm:

1. Read `rmcp::handler::server` and the stdio service loop in
   `modelcontextprotocol/rust-sdk`. Look for how a `cancelled`
   notification routes to an in-flight tool handler.
2. If rmcp exposes a `CancellationToken` per tool call: use it.
3. If rmcp does NOT plumb cancellation to handlers: file an upstream
   issue / contribute the wiring, OR fall back to a local approach
   (rmcp drops the request future; the handler's `Drop` impl needs to
   tear down the child via `kill_on_drop(true)` — which we already set).

The fallback is acceptable for an MVP but the *explicit* token is the
right contract.

## Scope

### Tools that get progress + cancellation wiring

| Tool | Progress event shape | Cancellation effect |
|---|---|---|
| `net.ping` | One progress event per probe reply, `progress = i`, `total = count`. Message: `"reply from <target> seq=<n>"` if line-parsed, otherwise omitted. | `kill_on_drop` already triggers on `Drop`; explicit token-driven kill if rmcp supplies one. |
| `net.traceroute` | One progress event per hop line, `progress = i`, `total = max_hops`. Message: `"hop <i>: <addr>"` or `"hop <i>: *"`. | Same. |
| `net.tcpdump_sample` | One per captured packet, `progress = i`, `total = count`. Message: omitted (per-packet noise unhelpful) or a short summary. | Same. |
| `net.conntrack` | Single progress event at start: `progress = 0`, `total = none` (size unknown). Optional periodic byte-count progress if rows are streamed. | Same. |
| `net.firewall`, `sys.dmesg` | Same as conntrack — single "running" event at start; usually too fast to warrant more. | Same. |
| All other tools (18 tier-1) | No progress. They complete in milliseconds. Don't add noise. |

### Tools that explicitly do NOT get progress

The 18 tier-1 tools (`ip` / `ss` / `resolvectl` / `systemctl` / `df` /
`free` / `journalctl` / `uptime` / `bridge`). Each returns in milliseconds.
Emitting progress events would be noise that costs context tokens in the
agent's wire log.

## Implementation sketch

### Plumbing — handler signature

The current `#[tool]` handlers look like:

```rust
async fn net_ping(&self, params: PingParams) -> Result<CallToolResult, ErrorData> { ... }
```

After the change:

```rust
async fn net_ping(
    &self,
    params: PingParams,
    ctx: ToolCtx<'_>,         // new — exposes progress + cancellation
) -> Result<CallToolResult, ErrorData> { ... }
```

The exact rmcp 1.7 idiom for `ToolCtx` depends on what the SDK exposes.
Candidates seen in the SDK source (check current names):

- `RequestContext` / `Peer` for emitting `notify_progress`.
- A `CancellationToken` accessible from the context.

If rmcp 1.7 doesn't accept `ToolCtx` as a handler param, the alternative
is `self.peer().notify_progress(...)` from inside the handler and a
process-global cancellation token that the SDK signals on cancel.

### Plumbing — `CommandRunner`

Today: `CommandRunner::run(key, args)` returns `Result<CommandResult, ...>`.

After: add a streaming/cancellation-aware variant:

```rust
pub async fn run_with_progress<F>(
    &self,
    key: &str,
    args: &[&str],
    on_line: F,        // called per output line; F: FnMut(&str)
    cancel: CancellationToken,
) -> Result<CommandResult, NetdiagError>
where F: FnMut(&str) + Send;
```

The runner already line-counts and byte-caps. Adding a per-line callback
is mechanical. Cancellation: `tokio::select!` between the child's
exit/output future and `cancel.cancelled()`. On cancel, send SIGTERM,
then SIGKILL after a short grace period (250 ms is fine).

The non-streaming `run` stays for the 18 tier-1 tools that don't need
progress. They get their existing path verbatim.

### Plumbing — bridging output to progress events

For tools that produce one line per progress unit (`ping`, `traceroute`),
the per-line callback parses the line and emits one progress event. For
`tcpdump_sample`, every captured-packet line is a unit. Parsing is small
regex against the known output format.

For tools that produce one block (`conntrack`, `firewall`, `dmesg`),
emit a single start progress event with `total = none` and let the wait
be visible to the agent without per-event noise.

### Cancellation as a first-class outcome

When `notifications/cancelled` arrives mid-call, the spec says the server
should NOT send a final result for the cancelled `requestId`. Per
[the cancellation utility spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation), the in-flight handler should drop the work and the SDK suppresses
the response. Verify rmcp 1.7 actually suppresses the response — if it
doesn't, returning an `Err` with a sentinel code (a new `Cancelled`
variant, `-32012`?) is the fallback.

The audit journal needs a `cancelled: true` row when this happens so the
operator audit trail captures the abort. Extend `mcp/journal.rs`'s
`result_summary` to handle the cancellation outcome.

## Test plan

- Unit: `run_with_progress` invokes the callback once per output line,
  in order, then returns the same `CommandResult` as `run`.
- Unit: cancellation via the token kills the child within the grace
  period; child exit status surfaces as `Cancelled` outcome.
- Wire (`tests/mcp_tests.rs`): a `tools/call` with a `progressToken` in
  `_meta` receives ≥1 `notifications/progress` for `net.ping count=3`
  (the in-process test server records and asserts the notifications).
- Wire: `notifications/cancelled` sent during a `net.tcpdump_sample`
  call causes the call to terminate within ~500 ms; no final result
  is sent for that `requestId`.
- Wire: cancellation produces a `cancelled: true` row in the audit
  journal.

## What this does NOT change

- Trust boundary. Same as today (stdio, parent process is trusted).
- Statelessness (CLAUDE.md §5). Progress tokens are *per-request* fields
  in `_meta`, not persistent server state. Cancellation tokens are
  per-call. The session model stays "no sessions."
- The 18 tier-1 tools' code paths.
- The privileged-tool gating. Tier-2 tools still require
  `NETDIAG_ENABLE_PRIVILEGED`; cancellation works on whatever runs.
- Tool names, field shapes, error codes (with the possible exception of
  adding `-32012 Cancelled` — verify rmcp's cancellation suppression
  first).
- Audit journal format, except for the new `cancelled` field.

## Out of scope

- Streamable HTTP transport (Option A — separate decision).
- Resources / prompts (Option C — separate doc, lands after this).
- The 2026-07-28 RC's `Tasks` primitive (wait for final spec).

## File-level change estimate

| File | Change |
|---|---|
| `src/mcp/mod.rs` | Handler signatures grow `ToolCtx` arg; emit progress in the 6 long-running tools; pass cancellation to runner. |
| `src/netdiag/commands.rs` | New `run_with_progress` method; existing `run` stays. SIGTERM-then-SIGKILL cancellation. |
| `src/netdiag/mod.rs` | Re-exports. |
| `src/mcp/journal.rs` | `cancelled: true` summary field. |
| `src/errors.rs` | Possibly new `Cancelled` variant (`-32012`); confirm rmcp suppression behavior first. |
| `tests/mcp_tests.rs` | Wire tests for progress + cancellation. |
| `tests/integration.rs` | One end-to-end cancellation test through the compiled binary. |
| `CLAUDE.md` | §4 — note which tools emit progress; §7 — note cancellation semantics. |
| `SECURITY.md` | §"What this does not protect against" — note that cancellation lets a hostile client cause work-without-results (DOS surface, bounded by existing timeout/cap budget). |
| `README.md` | New paragraph in or near Security Model: progress + cancellation behavior. |

## Verification gauntlet (per CLAUDE.md §9)

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
cargo build --manifest-path examples/minimal-mcp-client/Cargo.toml
```

All five must pass. The example client probably needs a small update
to show how a client receives progress events — optional, not blocking.
