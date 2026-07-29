# MCP resources for static files

> Status: design doc — not yet implemented. Sequenced after the progress +
> cancellation work. Tracks the planned MCP resource surface for netdiag.

## Why

Three things netdiag currently exposes as **tools** are not actually tool
calls in the MCP semantic sense — they are file reads:

- `net.resolv_conf` — reads `/etc/resolv.conf`.
- *(currently absent)* — `/etc/nsswitch.conf` (would have been added as a tool).
- *(currently absent)* — `journalctl --no-pager -n 200` is requested via
  `net.logs` tool with parameters, but the recent log tail is exactly the
  kind of context an agent wants to *attach* once, not poll repeatedly.

MCP separates these concerns deliberately:

- **Tools** are model-controlled actions ([spec](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)). The agent decides
  to invoke them.
- **Resources** are application-controlled context ([spec](https://modelcontextprotocol.io/specification/2025-11-25/server/resources)). The host
  decides what to include in the LLM's context. Resources have URIs,
  can be listed, read, and (optionally) subscribed to.

`/etc/resolv.conf` is the canonical resource — a small, addressable,
relatively-static file. Treating it as a tool means the agent has to
remember to *call* it; treating it as a resource means a host like
Claude Desktop can attach it to context automatically when the user
opens a diagnostic conversation.

## Resources netdiag should expose

| URI | Source | Mime | Why a resource (not a tool) |
|---|---|---|---|
| `netdiag://etc/resolv.conf` | Read `/etc/resolv.conf` | `text/plain` | Static config file, small, no params. |
| `netdiag://etc/nsswitch.conf` | Read `/etc/nsswitch.conf` | `text/plain` | Same. |
| `netdiag://etc/hosts` | Read `/etc/hosts` | `text/plain` | Same. |
| `netdiag://proc/version` | Read `/proc/version` | `text/plain` | Kernel version snapshot. |
| `netdiag://proc/cmdline` | Read `/proc/cmdline` | `text/plain` | Boot config snapshot. |
| `netdiag://journal/recent` | `journalctl --no-pager -n 200 --output=short-iso` | `text/plain` | Last 200 lines of system journal — common "include for context" use case. Bound by the same line/byte caps as `net.logs`. |
| `netdiag://audit/tail` | Tail of `NETDIAG_JOURNAL` (the netdiag audit journal) | `application/x-ndjson` | Lets the agent reason about its own recent tool-call history. Useful for "what have I checked already?" |

Seven resources. Modest, focused, all read-only, all bounded.

## URI scheme: `netdiag://`, not `file://`

The MCP spec permits either. `netdiag://` is preferable because:

- The URI surface is **closed**: only paths the server allowlists are
  reachable. A `file://` scheme invites clients to ask for arbitrary
  paths, which the server then has to reject — extra surface for
  little benefit.
- The scheme advertises intent. A client seeing `netdiag://` knows it
  is talking to a specific server's curated view, not poking at the
  raw filesystem.
- The mapping `netdiag://etc/resolv.conf` → `/etc/resolv.conf` stays
  explicit in code (a small `match` on URI authority + path), which
  mirrors the compile-time command allowlist.

URI authorities: `etc`, `proc`, `journal`, `audit` (mirrored from the
table above). Path validation: alphanumeric + `_` + `-` + `.` only,
no `..`, no leading `/`. Same level of paranoia as `validate_token`.

## What happens to `net.resolv_conf` the tool?

Two options:

1. **Remove** — once the resource exists, the tool is redundant. The
   migration is a single-version breaking change; the agent harnesses
   the project actually has (single-digit) can be told.
2. **Keep both, deprecate the tool** — annotate `net.resolv_conf` with
   `deprecated = true` in its description, leave it functional, plan
   to remove in a later release.

Recommendation: **option 2**. The cost of keeping it is one tool
description and one short handler call into `read_resource` internally.
The benefit is no breakage for any existing client. Remove in the next
breaking-change window (or never).

## Resource subscriptions: out of scope for v1

The spec defines `resources/subscribe` and `notifications/resources/updated`.
For netdiag's seven resources:

- `/etc/resolv.conf` etc. — change very rarely. Polling on demand is fine.
- The journal tails — change continuously. Subscribing would be useful
  but introduces persistent server state (a subscription list) and
  resource-update notifications need careful debouncing.

Defer subscriptions to a follow-up. v1 implements `resources/list` and
`resources/read` only. The `listChanged` capability stays `false`.

## Allowlist + safety

The resource allowlist must be **compile-time** and `'static`, mirroring
the command allowlist in `src/netdiag/commands.rs`. There is no
`NETDIAG_RESOURCE_ALLOWLIST` env var because:

- The set is small (7 entries).
- None of these files have privileged contents on a standard Linux
  install. (`/etc/shadow` is explicitly NOT exposed, obviously.)
- Adding an env var would mirror complexity without serving a real
  use case.

If a deployment needs a narrower set, they can drop tools/resources at
the rmcp layer — same pattern as `NETDIAG_ALLOWLIST` narrowing. (Not
implementing this in v1.)

### Byte/line caps

Apply the same caps as the command runner:

- `MAX_STDOUT_BYTES` (64 KiB) — clamp resource bodies.
- `MAX_OUTPUT_LINES` (512) — for the journal-tail resource specifically,
  cap at 200 lines (matching the journalctl source command).
- No timeout needed for `/etc` file reads. The `journalctl` resource
  wraps the existing 5 s timeout used by `net.logs`.

## Implementation sketch

### `ServerHandler` additions

rmcp 1.7's `ServerHandler` trait has `list_resources` and `read_resource`
methods. Wire them in `src/mcp/mod.rs`:

```rust
impl ServerHandler for NetdiagServer {
    async fn list_resources(&self, _: PaginatedRequestParam, _: RequestContext<RoleServer>)
        -> Result<ListResourcesResult, ErrorData>
    {
        Ok(ListResourcesResult {
            resources: RESOURCE_REGISTRY.iter().map(|r| r.to_descriptor()).collect(),
            next_cursor: None,
        })
    }

    async fn read_resource(&self, params: ReadResourceRequestParam, _: RequestContext<RoleServer>)
        -> Result<ReadResourceResult, ErrorData>
    {
        let entry = RESOURCE_REGISTRY.iter()
            .find(|r| r.uri == params.uri)
            .ok_or_else(|| ErrorData::resource_not_found(&params.uri))?;
        entry.read().await
    }
}
```

### New module: `src/mcp/resources.rs`

```rust
pub struct ResourceEntry {
    pub uri: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub mime_type: &'static str,
    pub source: ResourceSource,
}

pub enum ResourceSource {
    File(&'static str),                // direct read, e.g. /etc/resolv.conf
    Command(&'static str, &'static [&'static str]),  // run + capture, e.g. journalctl
    AuditJournalTail,                  // special: read NETDIAG_JOURNAL path
}

pub static RESOURCE_REGISTRY: &[ResourceEntry] = &[ ... ];
```

The `read()` method on `ResourceEntry` dispatches to `CommandRunner` for
the `Command` variant (reusing the existing byte/line caps) and to a
small `tokio::fs::read_to_string` for the `File` variant (with the same
caps applied via `truncate_lines`).

### Audit journal

Resource reads should journal too. Reuse `mcp/journal.rs`'s shape but
add a new tool name space (`resource.read` or similar) so the audit row
distinguishes resource access from tool calls. Same `call` + `result`
row pattern.

## Open questions

1. **Should `net.logs` (the tool) be kept alongside `netdiag://journal/recent`
   (the resource)?** The tool takes parameters (`lines`, `unit`); the
   resource doesn't. Different use cases — recommend keep both.
2. **Should `netdiag://audit/tail` be exposed by default, or behind an
   env-var opt-in?** It contains command-history fingerprints that
   reveal what the agent has been checking. Probably keep it on by
   default; the operator launched netdiag, the audit journal is theirs.
3. **Pagination for `list_resources`** — spec supports it via cursor.
   Seven resources fit in one response; defer until N grows.

## Test plan

- Unit: `RESOURCE_REGISTRY.iter()` produces 7 distinct URIs, all
  starting with `netdiag://`.
- Unit: every URI parses to a known `ResourceSource`.
- Unit: each `ResourceSource::File` variant points at a path that
  passes a path-allowlist check (compile-time test via `static_assertions`
  or runtime test in CI).
- Wire: `resources/list` returns 7 entries with correct mime types.
- Wire: `resources/read` for `netdiag://etc/resolv.conf` returns the
  file contents (use a tempdir + symlink override pattern from existing
  tests, if any, or accept that this test only runs where
  `/etc/resolv.conf` exists, which is everywhere we'd ship).
- Wire: `resources/read` for an unknown URI returns `-32603` (per
  spec, "resource not found").
- Wire: the audit journal records `resource.read` rows with the same
  structure as tool-call rows.

## What this does NOT change

- Trust boundary, statelessness, transport (still stdio-only).
- The 6 privileged tools' gating.
- Tool names, field shapes, error codes for tools.
- Audit journal format, except for the new resource rows.

## Out of scope

- Resource subscriptions (`resources/subscribe`).
- `prompts/list` / `prompts/get` (separate feature; defer per research).
- Streamable HTTP transport.

## File-level change estimate

| File | Change |
|---|---|
| `src/mcp/mod.rs` | Implement `list_resources` + `read_resource`. |
| `src/mcp/resources.rs` (new) | `RESOURCE_REGISTRY`, `ResourceEntry`, dispatch. |
| `src/mcp/journal.rs` | Add `resource.read` summary shape (parallel to existing tool summaries). |
| `src/netdiag/commands.rs` | Possibly: extract the byte/line truncation logic so resources reuse it without going through `CommandRunner`. |
| `CLAUDE.md` | New §4.5 or extend §4 documenting the resource surface; note the deprecation of `net.resolv_conf`. |
| `SECURITY.md` | New "Resources" subsection in the per-tool table; note the allowlist mirroring of files. |
| `README.md` | One paragraph: "what resources netdiag exposes and when an agent uses them vs tools." |
| `tests/mcp_tests.rs` | Wire tests for `resources/list` and `resources/read`. |
| `examples/minimal-mcp-client/` | Optional: add a `--list-resources` flag to the example client. |

## Verification gauntlet (per CLAUDE.md §9)

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
cargo build --manifest-path examples/minimal-mcp-client/Cargo.toml
```

All five must pass.
