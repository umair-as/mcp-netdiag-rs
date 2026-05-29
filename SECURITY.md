# Security Model

`mcp-netdiag-rs` exposes a small, fixed set of Linux network and system
diagnostics over MCP stdio. Every tool runs an allowlisted program with
pinned base arguments and validated extra tokens; there is no shell, no
interpreter, and no path through which a client can request an arbitrary
binary or flag. This document is the threat model, the security
boundaries that uphold it, and the operator guidance for deploying the
server safely.

## Threat model

**Trusted:**
- The operator who launches the server, the systemd unit (or equivalent)
  it runs under, and the environment variables set at startup.
- The host filesystem and the kernel.
- The compile-time command allowlist and the Rust source.

**Untrusted:**
- The MCP client (or a compromised one) that can send arbitrary
  `tools/call` JSON over stdio. All tool arguments — interface names,
  hostnames, unit names, integer bounds — are treated as adversarial.
- Command stdout and stderr captured from spawned programs.

**Out of scope:**
- Physical access to the host.
- Kernel CVEs and side-channel attacks at the OS/hardware layer.
- Network-level attacks on the gateway's other listening services.
- Trust of the data returned (the assistant is responsible for not
  acting on adversarial tool output beyond reading it).

## Security boundaries

The boundaries below are layered. A request must pass all of them to
spawn a subprocess.

### 1. Compile-time command allowlist

`src/netdiag/commands.rs::full_allowlist` is a `HashMap<&'static str,
DiagnosticSpec>` whose entries pin both the `program` and a `&'static
[&'static str]` of base arguments. Tool handlers append validated extra
tokens via `Command::args(...)`. There is no code path that runs an
arbitrary program or an arbitrary flag.

`NETDIAG_ALLOWLIST` can only *narrow* this map at startup; it cannot
add programs or arguments. See CLAUDE.md §6.

### 2. Per-token validators

Every caller-supplied token passes a typed validator in
`src/netdiag/commands.rs`:

- `validate_interface` / `validate_unit` / `validate_ip_or_host` —
  non-empty, ≤ 128 chars, restricted character class
  (`[A-Za-z0-9.:_/-]`, plus `@` for unit names), and **must not start
  with `-`** (argv-flag-injection guard; see PR #3).
- `validate_mac` — strict `aa:bb:cc:dd:ee:ff` shape, case-insensitive.

Integer bounds (`count`, `timeout_secs`, `max_hops`, `lines`) are
enforced at runtime by `bounded(...)` in `src/mcp/mod.rs`, not just
advertised in the `schemars` input schema.

### 3. No shell

Every command runs via `tokio::process::Command::new(program).args(...)`.
There is no `sh -c`, no string interpolation, no environment
inheritance beyond what tokio's default does. Shell metacharacters in
inputs are blocked by the validators above, but even if a token slipped
through, the absence of a shell means it cannot do anything.

### 4. Bounded execution

Every command runs under (`src/config.rs`):

- `DEFAULT_TIMEOUT_SECS = 5` wall-clock cap; exceeded → `CommandExec`
  (`-32012`) and the child is killed via `kill_on_drop(true)`.
- `MAX_STDOUT_BYTES = 64 KiB`, `MAX_STDERR_BYTES = 8 KiB` — captured
  output is truncated past these.
- `MAX_OUTPUT_LINES = 512` — lines beyond this are dropped.

### 5. Statelessness

There is no session id, no per-call state map, no in-memory token that
persists between calls. Every `tools/call` is fire-and-forget. This
removes a class of bugs (cross-call state confusion, leaked secrets in
in-memory caches) by construction.

## Default vs privileged tool model

The 24 tools split into two groups along an operational, not a
syntactic, boundary: what does the tool *do* on the host?

### Default — 18 tools, enabled by default

Pure reads of unprivileged Linux state. None require Linux capabilities
beyond what an ordinary unprivileged user has on a modern systemd
distro. Safe to run autonomously.

| Tool | Command |
|---|---|
| `net.if_status` | `ip -j -s link show [dev <iface>]` |
| `net.mac_lookup` | `bridge -j fdb show to <mac>` |
| `net.neighbors` | `ip -j neigh show [dev <iface>]` |
| `net.routes` | `ip -j route show table all` |
| `net.addr` | `ip -j addr show [dev <iface>]` |
| `net.link_detail` | `ip -j -d link show [dev <iface>]` |
| `net.route_get` | `ip -j route get <target>` |
| `net.rules` | `ip -j rule show` |
| `net.sockets` | `ss -H -tuna` |
| `net.dns_status` | `resolvectl status` |
| `net.resolv_conf` | read `/etc/resolv.conf` |
| `net.ethtool` | `ethtool <iface>` |
| `net.logs` | `journalctl -n <1..200> [-u <unit>]` |
| `sys.failed_units` | `systemctl --failed --no-pager --plain` |
| `sys.service_status` | `systemctl status --no-pager --lines <1..200> <unit>` |
| `sys.uptime` | `uptime` |
| `sys.memory` | `free -h` |
| `sys.filesystems` | `df -h` |

### Privileged — 6 tools, refused by default

Either emit observable side effects on the wire / kernel, or require
elevated Linux capabilities to run at all. The operator opts in
per-deployment via `NETDIAG_ENABLE_PRIVILEGED`; with the env var unset, the
server returns `-32011` for every privileged call and never spawns a
subprocess.

| Tool | Required cap | Side effect | Command |
|---|---|---|---|
| `net.ping` | `CAP_NET_RAW` (or `net.ipv4.ping_group_range`) | Emits ICMP echo requests | `ping -n -c <1..10> -W <1..5> <target>` |
| `net.traceroute` | `CAP_NET_RAW` | Emits UDP/ICMP probes | `traceroute -n -m <1..30> <target>` |
| `net.tcpdump_sample` | `CAP_NET_RAW` + `CAP_NET_ADMIN` | Opens AF_PACKET socket, toggles promiscuous mode on iface | `tcpdump -nn -i <iface> -c <1..50>` |
| `net.firewall` | `CAP_NET_ADMIN` | None (kernel-state read) | `nft list ruleset` |
| `net.conntrack` | `CAP_NET_ADMIN` | None (kernel-state read) | `conntrack -L` |
| `sys.dmesg` | `CAP_SYSLOG` when `kernel.dmesg_restrict=1` (distro default) | None (kernel-state read) | `dmesg -T` |

### Refusal semantics

| Refusal reason | Variant | Code | Message includes |
|---|---|---|---|
| Tool not in `NETDIAG_ALLOWLIST` (or unknown key) | `CommandNotAllowed` | `-32011` | `"command not allowed: <key>"` |
| Tool is privileged and not in `NETDIAG_ENABLE_PRIVILEGED` | `PrivilegedDisabled` | `-32011` | `"privileged tool disabled; set NETDIAG_ENABLE_PRIVILEGED=<key> or NETDIAG_ENABLE_PRIVILEGED=all to enable"` |

Both return `-32011` so client code can branch on a single error code,
but the message and `data` payload differ. `PrivilegedDisabled`'s `data`
carries `{command, privileged: true, enable_env: "NETDIAG_ENABLE_PRIVILEGED"}`
so operator-facing UIs can surface the env-var hint.

### Composition with `NETDIAG_ALLOWLIST`

The two filters are AND-ed. A tool runs iff:

```
NETDIAG_ALLOWLIST admits it     AND     (it is not privileged OR NETDIAG_ENABLE_PRIVILEGED admits it)
```

The allowlist is authoritative: a privileged opt-in cannot widen a narrower
allowlist. Inside `CommandRunner::run` the order is fixed —
`CommandNotAllowed` is checked first, `PrivilegedDisabled` second — so a
tool absent from `NETDIAG_ALLOWLIST` always returns the generic
not-allowed message, never the privileged-disabled message.

### MCP `ToolAnnotations` and why they are advisory

Each tool advertises `rmcp::model::ToolAnnotations` so MCP clients can
surface intent (read-only vs side-effecting, idempotent vs not,
closed-world vs open-world). They are advertisement, not gating: the
MCP spec is explicit that clients MUST consider annotations untrusted
unless they come from a trusted server (and even then, no major client
ships annotation-driven confirmation today). The enforcement gate is
`NETDIAG_ENABLE_PRIVILEGED`.

For privileged tools the annotation breakdown is:

- **`net.ping`, `net.traceroute`, `net.tcpdump_sample`** — wire-emitters
  / state-togglers. `readOnlyHint = false`, `idempotentHint = false`,
  `openWorldHint = true`. Each call produces fresh observable effects
  (packets on the wire, promisc mode change), so the MCP spec's
  "readOnly" / "idempotent" definitions do not apply. The host
  configuration is still unchanged — these tools do not write files,
  edit routes, or change interface state — which is why the project's
  broader "read-only diagnostics" framing still holds.
- **`net.firewall`, `net.conntrack`, `sys.dmesg`** — kernel-state reads.
  `readOnlyHint = true`, `idempotentHint = true`, `openWorldHint = true`.
  They query kernel state without emitting anything; the only reason
  they are privileged is the capability requirement.
- All privileged tools advertise `destructiveHint = false` — none of them
  destroy or overwrite anything. The audit journal records every call
  attempt regardless.

The asymmetry was a deliberate decision: blanket-marking every
privileged tool `readOnlyHint = true` would have been more convenient
but misleading about the wire emitters. Hint truthfulness comes ahead
of brevity.

## Deployment guidance

### Default deployment — unprivileged

Run as an unprivileged user. Every default tool works. Every privileged tool
refuses with `-32011`. No capabilities required.

```ini
# /etc/systemd/system/mcp-netdiag.service
[Service]
ExecStart=/usr/local/bin/mcp-netdiag-rs
User=netdiag
DynamicUser=true
NoNewPrivileges=true
Environment=NETDIAG_JOURNAL=/var/log/mcp-netdiag/journal.jsonl
# NETDIAG_ENABLE_PRIVILEGED is unset → privileged tools refused
StandardInput=socket
StandardOutput=socket

[Install]
WantedBy=multi-user.target
```

### Opting in to privileged tools

Enable only the privileged tools the deployment needs, and grant only the
capabilities those tools require. Example: gateway diagnostics that
need `ping` and `traceroute` but not packet capture or kernel
inspection:

```ini
[Service]
ExecStart=/usr/local/bin/mcp-netdiag-rs
User=netdiag
DynamicUser=true
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
Environment=NETDIAG_ENABLE_PRIVILEGED=ping,traceroute
Environment=NETDIAG_JOURNAL=/var/log/mcp-netdiag/journal.jsonl
```

For the full privileged set (packet sampling, firewall/conntrack
inspection, kernel logs):

```ini
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SYSLOG
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYSLOG
Environment=NETDIAG_ENABLE_PRIVILEGED=all
```

If a privileged tool is enabled but the matching capability is missing, the
underlying command fails at execution time — the result envelope
carries `status: "fail"` rather than the protocol returning an error.

### Audit trail

Every `tools/call` writes one `call` row and one `result` row to the
JSONL journal at `NETDIAG_JOURNAL` (default
`/tmp/mcp-netdiag-journal.jsonl`). Lifecycle traffic
(`initialize`, `tools/list`) is not journaled. Refused calls — both
`CommandNotAllowed` and `PrivilegedDisabled` — are captured with their
pinned error code in the result row, so a privileged attempt against a
default-closed deployment leaves a record.

Quick tail of the last few denials:

```sh
tail -F /var/log/mcp-netdiag/journal.jsonl \
  | jq -r 'select(.direction == "result" and .summary.ok == false)
           | "\(.ts) \(.tool) error=\(.summary.error_code) \(.summary.error_message)"'
```

## Reporting vulnerabilities

Please report security issues via GitHub Security Advisories on this
repository (Security → Advisories → "Report a vulnerability"). For
issues that cannot be reported through GitHub, contact the maintainer
listed in `Cargo.toml`. Please do not file public issues for suspected
vulnerabilities.
