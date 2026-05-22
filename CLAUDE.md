# mcp-netdiag-rs — Claude Code Orientation

> Stateless MCP tool server exposing read-only network diagnostics over
> stdio. Target deployment: a Yocto-managed `aarch64` IoT gateway.

The MCP protocol layer is the `rmcp` SDK over its stdio transport. The
migration off the original hand-rolled JSON-RPC layer is complete — this
file is the current source of truth.

---

## 1  Decisions (do not re-litigate)

| Topic | Decision | Notes |
|---|---|---|
| Language | Rust, edition 2021 | MSRV 1.85 (required by `rmcp` 1.7's edition-2024 dependency chain). |
| Async runtime | **tokio** (multi-thread) | All I/O is async; no blocking calls on the stdio loop. |
| Error strategy | **thiserror** typed errors → MCP codes / structured results | NOT `anyhow` — typed variants are required. |
| MCP transport | **`rmcp` SDK over stdio** | The SDK owns `initialize`, `tools/list`, `tools/call`, `notifications/initialized`. The netdiag domain stays separate (§3). |
| Logging | **tracing** + **tracing-subscriber** (env-filter, stderr writer) | `rmcp::transport::stdio()` does NOT redirect logs — stderr setup is mandatory. |
| Serialisation | **serde** + **serde_json** + **schemars** | Tool params are typed structs; rmcp generates input schemas from them; results use `structuredContent`. |
| **State** | **Stateless** | netdiag tools are fire-and-forget. There is NO session concept — no `session_id`, no `SessionManager`, no per-call state. This is the load-bearing difference from the sibling `mcp-serial-rs`. |
| Command allowlist | **Compile-time** | Programs + base args are `'static` consts. `NETDIAG_ALLOWLIST` can only *narrow* the set, never add programs/args. |

- **Error semantics:** Protocol errors are for validation failures (bad
  params, disallowed command, unknown tool). A command that *runs* but
  exits non-zero is NOT an error — it is a successful tool result with
  `status: "fail"`. A command that cannot run at all (spawn failure,
  timeout) is a `CommandExec` protocol error.

## 2  Crate manifest (`Cargo.toml` `[dependencies]`)

```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
thiserror = "2"
rmcp = { version = "1.7", features = ["transport-io"] }
schemars = "1.0"
```

`rmcp`'s default features already include `macros` and `server`;
`transport-io` is enabled for the stdio transport. `[dev-dependencies]`:
`assert_matches`, `tempfile`.

Deliberately absent: `toml` (no device-profile file — netdiag has no
per-device config), `regex` (validators are hand-rolled char-class
checks), `tokio-serial`. No new runtime dependencies without approval.

## 3  Module map

```
mcp-netdiag-rs/
├── Cargo.toml
├── CLAUDE.md            ← you are here
├── docs/architecture.md ← sequence diagram, tool→command mapping
├── examples/minimal-mcp-client/  ← raw-JSON-RPC example client (own sub-crate)
├── src/
│   ├── lib.rs           ← crate root; re-exports modules for tests
│   ├── main.rs          ← tokio bootstrap; builds NetdiagServer, hands stdio to rmcp
│   ├── config.rs        ← bounds constants + env-var resolution
│   ├── errors.rs        ← NetdiagError enum, → rmcp::ErrorData adapter
│   ├── mcp/
│   │   ├── mod.rs       ← rmcp adapter: NetdiagServer, #[tool] handlers, journal hook
│   │   └── journal.rs   ← JournalWriter (JSONL sink) + summary shaping
│   └── netdiag/
│       ├── mod.rs       ← CommandExecutor trait + result shaping
│       └── commands.rs  ← CommandRunner, allowlist, validators (the security boundary)
└── tests/
    ├── mcp_tests.rs     ← in-process rmcp wire tests (stubbed runner)
    └── integration.rs   ← end-to-end through the compiled binary
```

Architecture constraint: keep the `mcp/` rmcp adapter separate from the
`netdiag/` domain. The adapter must not absorb command-execution logic;
`netdiag/` must not know about rmcp.

## 4  MCP tool surface

Tool names and field shapes are stable — do not rename or reshape them.
All seven tools are read-only.

| Tool | Params | Command |
|---|---|---|
| `net.if_status` | `{interface?}` | `ip -j -s link show [dev <iface>]` |
| `net.mac_lookup` | `{mac}` | `bridge -j fdb show to <mac>` |
| `net.neighbors` | `{interface?}` | `ip -j neigh show [dev <iface>]` |
| `net.routes` | — | `ip -j route show table all` |
| `net.ping` | `{target, count?, timeout_secs?}` | `ping -n -c <1..10> -W <1..5> <target>` |
| `net.traceroute` | `{target, max_hops?}` | `traceroute -n -m <1..30> <target>` |
| `net.logs` | `{lines?, unit?}` | `journalctl --no-pager --output=short-iso -n <1..200> [-u <unit>]` |

- Dotted tool names stay (no rename to `net_ping`).
- Every tool returns a structured envelope:
  `{tool, status, signal, evidence, suggested_action, raw}` via
  `CallToolResult::structured` (read on the wire as `structuredContent`).
- Integer bounds are advertised in the generated schema (`schemars`
  `range`) AND enforced at runtime — the runtime check is authoritative.
- `net.routes` is paramless: like `serial.list_ports` in the sibling, the
  rmcp SDK does not reject unknown arguments for a paramless tool. Tools
  with a param struct reject unknown fields (`deny_unknown_fields`) →
  `-32602`.

## 5  Statelessness

netdiag has no session machinery — this is intentional and load-bearing.
Each `tools/call` resolves a command, runs it, and returns. There is no
`session_id`, no state map, no locking. rmcp dispatches concurrently, but
handlers share nothing mutable, so concurrency needs no extra guarding
(unlike the serial server's per-port mutex). The journal's `session_id`
field is fixed to `"none"` so rows keep one stable shape.

## 6  Config & safety

```rust
// config.rs
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;
pub const MAX_STDOUT_BYTES: usize = 64 * 1024;
pub const MAX_STDERR_BYTES: usize = 8 * 1024;
pub const MAX_OUTPUT_LINES: usize = 512;
```

- The command allowlist (`netdiag/commands.rs`) is the security boundary.
  Programs and base args are compile-time `'static` consts; callers may
  only append arguments that pass the token validators
  (`validate_interface` / `validate_ip_or_host` / `validate_mac`).
- All commands run under a wall-clock timeout; output is byte- and
  line-bounded.

**Environment variables:**

| Var | Purpose | Default |
|---|---|---|
| `NETDIAG_JOURNAL` | JSONL tool-call audit journal path. Always-on; an unwritable path degrades to a `tracing::warn` and the server continues without auditing. | `/tmp/mcp-netdiag-journal.jsonl` |
| `NETDIAG_ALLOWLIST` | Comma-separated subset of command keys (`if_status`, `mac_table`, `neighbors`, `routes`, `ping`, `traceroute`, `logs`). When set, only the listed commands run. **Narrowing only** — cannot add programs/args. | unset → all enabled |
| `RUST_LOG` | `tracing-subscriber` env filter. | `mcp_netdiag_rs=info` |

## 7  MCP wire & framing

- **stdout is reserved for MCP messages only.** No `println!`, no debug
  prints. The caller MUST configure `tracing-subscriber` with a stderr
  writer — `rmcp::transport::stdio()` does not redirect anything.
- **Logs go to stderr only**, via `tracing`, driven by `RUST_LOG`.
- The audit journal is scoped to `tools/call` only (one `call` row + one
  `result` row). Lifecycle traffic is not journaled — it never enters the
  `call_tool` hook point.

## 8  Coding conventions

- `#![deny(clippy::all)]` in both crate roots (`main.rs`, `lib.rs`).
- No `unwrap()` / `expect()` in library code; `main.rs` may `expect()` on
  bootstrap only.
- Error variants carry context (param name, command, OS error string).
- `#[instrument]` on every tool handler.
- Line length soft limit: 100 columns.
- Tests: `tests/` for integration, inline `#[cfg(test)] mod tests` for unit.

## 9  Build verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
cargo build --manifest-path examples/minimal-mcp-client/Cargo.toml
```

All five must pass before reporting a task done.

## 10  Do NOT

- Do not add `anyhow` — use `thiserror`, typed variants are required.
- Do not add `toml`, `regex`, or `tokio-serial` — see §2.
- Do not rename tools from dotted (`net.ping`) to underscored.
- Do not add config-mutating tools — this server is read-only.
- Do not let `NETDIAG_ALLOWLIST` (or any env var) inject programs or
  arguments — it is a narrowing filter only.
- Do not port sessions / `SessionManager` from the sibling — netdiag is
  stateless by design (§5).
- Do not widen the audit journal beyond `tools/call`.
- Do not write to stdout except MCP-framed responses (via `rmcp`). All
  logs → stderr.
- Do not flatten the `mcp/` adapter into the `netdiag/` domain.
