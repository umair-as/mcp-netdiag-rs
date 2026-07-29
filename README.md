# 🌐 mcp-netdiag-rs

> A read-only [MCP](https://modelcontextprotocol.io) server that lets an
> AI assistant inspect a Linux host's live network state — without ever
> handing it a shell.

`mcp-netdiag-rs` turns a curated set of vetted, allowlisted diagnostic
commands (`ip`, `ss`, `resolvectl`, `ping`, `traceroute`, `tcpdump`, …) into
**24 structured MCP tools**. An MCP-capable client can ask "why can't this box
reach its gateway?" and the assistant answers by calling real tools against
the real host — inside a tight security boundary that no prompt can talk its
way out of.

- 🔒 **Read-only by design** — nothing edits a route, mutates a unit, or
  writes a file.
- 🧱 **Compile-time command allowlist** — programs and base arguments are
  `'static` constants; callers may only append *validated* tokens.
- 🎚️ **Privileged tools are opt-in** — the six tools that put packets on the
  wire or need elevated capabilities stay refused until the operator says
  otherwise.
- 📋 **Structured, actionable results** — every tool returns the same
  `{status, signal, evidence, suggested_action, raw}` envelope.
- 🐧 Runs on any Linux host with the standard `iproute2` / `ping` /
  `traceroute` / `systemd` userspace.

---

## 🔍 Why

Network troubleshooting on Linux is manual and command-heavy: a human SSHes
in, runs a dozen commands from memory, and eyeballs the output. Handing an AI
assistant a raw shell to do the same is powerful but reckless.

`mcp-netdiag-rs` gives the assistant a **safe, structured diagnostics
interface** instead. It can gather live evidence from the host and hand back a
concise diagnosis — while the set of things it can actually run is fixed at
compile time and every argument is validated before it reaches a subprocess.

## 🚀 Quick start

```sh
# Build the server (single self-contained binary).
cargo build --release

# Drive it with a raw MCP handshake, then call a tool.
(
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"demo","version":"0.1.0"}}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sys.uptime","arguments":{}}}'
) | ./target/release/mcp-netdiag-rs
```

Every tool call goes through a `tools/call` envelope. The parsed result lives
under `result.structuredContent` (a text rendering is also present in
`result.content` for clients that don't read structured output):

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "structuredContent": {
      "tool": "sys.uptime",
      "status": "ok",
      "signal": "command_succeeded",
      "evidence": "10:42:07 up 3 days,  1:12,  2 users,  load average: 0.14, 0.09, 0.03",
      "suggested_action": "No immediate fault signal from this command; continue with adjacent diagnostics.",
      "raw": { "ok": true, "exit_code": 0, "stdout": "…", "stderr": "" }
    }
  }
}
```

Swap `sys.uptime` for any tool in the **Tools** table below — e.g.
`net.routes` for the routing table, or `net.ping` with
`{"target":"1.1.1.1","count":3}` once you've enabled privileged tools.

### 🧭 Try the bundled example client

The repo ships a tiny reference client that speaks the full handshake, plans a
few tool calls from a plain-English question, and prints a diagnosis:

```sh
cargo run --manifest-path examples/minimal-mcp-client/Cargo.toml -- \
  --server ./target/release/mcp-netdiag-rs \
  --question "why can't eth0 reach its gateway?" \
  --interface eth0
```

## 🧰 Tools

All 24 tools return the same structured envelope. Tools marked 🔒 are
**privileged** and refused unless enabled via `NETDIAG_ENABLE_PRIVILEGED`
(see the **Security model** section).

### Network

| Tool | What it shows | Command |
| --- | --- | --- |
| `net.if_status` | Interface state + counters | `ip -j -s link show [dev <iface>]` |
| `net.addr` | Interface addresses | `ip -j addr show [dev <iface>]` |
| `net.link_detail` | Detailed link attributes | `ip -j -d link show [dev <iface>]` |
| `net.neighbors` | ARP / neighbor table | `ip -j neigh show [dev <iface>]` |
| `net.mac_lookup` | Bridge FDB entry for a MAC | `bridge -j fdb show to <mac>` |
| `net.routes` | Full routing table | `ip -j route show table all` |
| `net.route_get` | Route the kernel picks for a target | `ip -j route get <target>` |
| `net.rules` | Policy routing rules | `ip -j rule show` |
| `net.sockets` | Open TCP/UDP sockets | `ss -H -tuna` |
| `net.dns_status` | systemd-resolved status | `resolvectl status` |
| `net.resolv_conf` | Resolver config | read `/etc/resolv.conf` |
| `net.ethtool` | NIC driver / link settings | `ethtool <iface>` |
| `net.logs` | Bounded journal tail | `journalctl -n <1..200> [-u <unit>]` |
| 🔒 `net.ping` | ICMP reachability | `ping -n -c <1..10> -W <1..5> <target>` |
| 🔒 `net.traceroute` | Path to a target | `traceroute -n -m <1..30> <target>` |
| 🔒 `net.tcpdump_sample` | Bounded packet capture | `tcpdump -nn -i <iface> -c <1..50>` |
| 🔒 `net.firewall` | nftables ruleset | `nft list ruleset` |
| 🔒 `net.conntrack` | Connection tracking table | `conntrack -L` |

### System

| Tool | What it shows | Command |
| --- | --- | --- |
| `sys.failed_units` | Failed systemd units | `systemctl --failed --plain` |
| `sys.service_status` | Status of one unit | `systemctl status --lines <1..200> <unit>` |
| `sys.uptime` | Uptime + load average | `uptime` |
| `sys.memory` | Memory usage | `free -h` |
| `sys.filesystems` | Filesystem usage | `df -h` |
| 🔒 `sys.dmesg` | Kernel ring buffer | `dmesg -T` |

A command that *runs* but exits non-zero is **not** a protocol error — it's a
normal result with `status: "fail"`. Protocol errors (`-32010` invalid
parameter, `-32011` command not allowed / privileged-disabled, `-32012`
command execution failed) are reserved for calls that can't run at all.

## 🛡️ Security model

The 24 tools split into two groups. Both share the compile-time command
allowlist, the per-token validators, the wall-clock timeout, and the output
size/line bounds documented in **[SECURITY.md](SECURITY.md)**.

- **Default — 18 tools, enabled out of the box.** Pure reads of unprivileged
  Linux state (`ip` / `ss` / `resolvectl` / `systemctl` / `df` / `free` /
  `journalctl` / `ethtool` and friends). No capabilities required; safe to run
  as an unprivileged user.
- 🔒 **Privileged — 6 tools, refused by default.** They either emit observable
  side effects on the wire (`net.ping` / `net.traceroute` need `CAP_NET_RAW`;
  `net.tcpdump_sample` needs `CAP_NET_RAW + CAP_NET_ADMIN` and toggles
  promiscuous mode) or read privileged kernel state (`net.firewall` /
  `net.conntrack` need `CAP_NET_ADMIN`; `sys.dmesg` needs `CAP_SYSLOG` when
  `kernel.dmesg_restrict=1`). With `NETDIAG_ENABLE_PRIVILEGED` unset, every
  privileged call returns `-32011` and never spawns a subprocess.

The two opt-ins **compose by AND**: a privileged opt-in can never widen a
narrower `NETDIAG_ALLOWLIST`. If a tool isn't in the allowlist, no env var can
make it run. See [SECURITY.md](SECURITY.md) for the full threat model, the
per-tool capability table, and a systemd unit recipe for privileged
deployments.

## ⚙️ Configuration

All configuration is via environment variables — there is no config file.

| Variable | Purpose | Default |
| --- | --- | --- |
| `NETDIAG_ENABLE_PRIVILEGED` | Opt-in for the six 🔒 tools. Comma-separated subset of `{ping, traceroute, tcpdump_sample, firewall, conntrack, dmesg}`, the literal `all`, or `none`/empty. **Case-sensitive.** Composes with `NETDIAG_ALLOWLIST` by AND. | unset → all refused |
| `NETDIAG_ALLOWLIST` | Comma-separated subset of built-in command keys. When set, only those run. **Narrowing only** — can disable built-ins, never add programs or arguments. | unset → all enabled |
| `NETDIAG_JOURNAL` | Path to the JSONL tool-call audit journal. Always-on; an unwritable path degrades to a warning and the server keeps running without auditing. | `/tmp/mcp-netdiag-journal.jsonl` |
| `RUST_LOG` | `tracing` filter. Logs go to **stderr only**, never stdout. | `mcp_netdiag_rs=info` |

## 🏗️ How it works

```text
MCP client ──stdio (JSON-RPC)──▶ rmcp SDK ──▶ NetdiagServer
                                                  │
                              tools/call ─────────┤
                                                  ▼
                                   allowlist + token validators
                                                  ▼
                                   bounded subprocess (timeout, size caps)
                                                  ▼
                                   {status, signal, evidence, … , raw}
```

The MCP protocol layer is the [`rmcp`](https://crates.io/crates/rmcp) SDK over
its stdio transport — it owns `initialize`, `tools/list`, `tools/call`, and
the standard JSON-RPC errors. Tool input schemas are derived from typed
parameter structs via `schemars`. The server is **stateless**: each call
resolves a command, runs it, and returns — no sessions, no per-call state.
`stdout` is reserved exclusively for MCP messages.

See **[docs/architecture.md](docs/architecture.md)** for the sequence diagram
and the full tool→command mapping.

## 📦 Deployment

Run the server **locally on the host you want to diagnose**, so its tools
reflect that host's real network state. It builds to a single self-contained
binary — install it however suits the target: a distro package, a container
image, or (for embedded Linux) a Yocto/BitBake recipe. It's meant to be
launched by an MCP client, not driven by hand.

## 🧪 Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
cargo build --manifest-path examples/minimal-mcp-client/Cargo.toml
```

Supply-chain checks (run in CI, or locally):

```sh
cargo audit
cargo deny check bans licenses sources
```

## 🏷️ Releases

Releases are cut by a manually-dispatched GitHub Actions workflow that
validates the version, re-runs the full check suite, and publishes a tagged
binary. Release notes are generated from the git history via
[git-cliff](https://github.com/orhun/git-cliff). See
**[CHANGELOG.md](CHANGELOG.md)** for what shipped and
**[docs/RELEASE.md](docs/RELEASE.md)** for the process.

## 📄 License

Dual-licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
