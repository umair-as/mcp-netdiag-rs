// SPDX-License-Identifier: MIT OR Apache-2.0

//! The allowlisted command runner — the security boundary of the server.
//!
//! Every diagnostic tool resolves to one entry in a compile-time
//! [`HashMap`] of [`CommandSpec`]s. A spec pins both the `program` and its
//! `base_args`; callers may only append *validated* extra arguments. There
//! is no code path that runs an arbitrary program or an arbitrary flag, so
//! the server stays read-only and injection-safe by construction.
//!
//! `NETDIAG_ALLOWLIST` (see [`crate::config`]) can only *narrow* this map —
//! it never adds programs or arguments.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;

use super::CommandExecutor;
use crate::config;
use crate::errors::NetdiagError;

/// A pinned program invocation. `program` and `base_args` are
/// `'static` — they originate only from [`full_allowlist`], never from
/// caller input.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: &'static str,
    pub base_args: &'static [&'static str],
}

/// A pinned diagnostic operation.
#[derive(Debug, Clone)]
enum DiagnosticSpec {
    Process(CommandSpec),
    File { path: &'static str },
}

/// The six privileged command keys: tools that require elevated Linux
/// capabilities (CAP_NET_RAW / CAP_NET_ADMIN / CAP_SYSLOG) or that emit
/// observable side effects on the wire / kernel. Refused by default; the
/// operator opts in via `NETDIAG_ENABLE_PRIVILEGED` (see
/// [`crate::config::PRIVILEGED_ENABLE_ENV`]).
pub const PRIVILEGED_KEYS: &[&str] = &[
    "ping",
    "traceroute",
    "tcpdump_sample",
    "firewall",
    "conntrack",
    "dmesg",
];

/// Resolves logical command keys to allowlisted [`CommandSpec`]s and runs
/// them with a wall-clock timeout and bounded output capture.
#[derive(Debug, Clone)]
pub struct CommandRunner {
    allowlist: HashMap<&'static str, DiagnosticSpec>,
    privileged_enabled: HashSet<String>,
    timeout: Duration,
}

impl Default for CommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// The full, compile-time set of allowlisted commands. The keys are the
/// stable identifiers the rmcp tool handlers pass to [`CommandExecutor::run`];
/// they are also the names accepted by `NETDIAG_ALLOWLIST`.
pub const BUILTIN_COMMAND_COUNT: usize = 24;

fn full_allowlist() -> HashMap<&'static str, DiagnosticSpec> {
    HashMap::from([
        (
            "if_status",
            DiagnosticSpec::Process(CommandSpec {
                program: "ip",
                base_args: &["-j", "-s", "link", "show"],
            }),
        ),
        (
            "mac_table",
            DiagnosticSpec::Process(CommandSpec {
                program: "bridge",
                base_args: &["-j", "fdb", "show"],
            }),
        ),
        (
            "neighbors",
            DiagnosticSpec::Process(CommandSpec {
                program: "ip",
                base_args: &["-j", "neigh", "show"],
            }),
        ),
        (
            "routes",
            DiagnosticSpec::Process(CommandSpec {
                program: "ip",
                base_args: &["-j", "route", "show", "table", "all"],
            }),
        ),
        (
            "addr",
            DiagnosticSpec::Process(CommandSpec {
                program: "ip",
                base_args: &["-j", "addr", "show"],
            }),
        ),
        (
            "link_detail",
            DiagnosticSpec::Process(CommandSpec {
                program: "ip",
                base_args: &["-j", "-d", "link", "show"],
            }),
        ),
        (
            "route_get",
            DiagnosticSpec::Process(CommandSpec {
                program: "ip",
                base_args: &["-j", "route", "get"],
            }),
        ),
        (
            "rules",
            DiagnosticSpec::Process(CommandSpec {
                program: "ip",
                base_args: &["-j", "rule", "show"],
            }),
        ),
        (
            "ping",
            DiagnosticSpec::Process(CommandSpec {
                program: "ping",
                base_args: &["-n"],
            }),
        ),
        (
            "traceroute",
            DiagnosticSpec::Process(CommandSpec {
                program: "traceroute",
                base_args: &["-n"],
            }),
        ),
        (
            "sockets",
            DiagnosticSpec::Process(CommandSpec {
                program: "ss",
                base_args: &["-H", "-tuna"],
            }),
        ),
        (
            "dns_status",
            DiagnosticSpec::Process(CommandSpec {
                program: "resolvectl",
                base_args: &["status"],
            }),
        ),
        (
            "resolv_conf",
            DiagnosticSpec::File {
                path: "/etc/resolv.conf",
            },
        ),
        (
            "ethtool",
            DiagnosticSpec::Process(CommandSpec {
                program: "ethtool",
                base_args: &[],
            }),
        ),
        (
            "firewall",
            DiagnosticSpec::Process(CommandSpec {
                program: "nft",
                base_args: &["list", "ruleset"],
            }),
        ),
        (
            "conntrack",
            DiagnosticSpec::Process(CommandSpec {
                program: "conntrack",
                base_args: &["-L"],
            }),
        ),
        (
            "tcpdump_sample",
            DiagnosticSpec::Process(CommandSpec {
                program: "tcpdump",
                base_args: &["-nn"],
            }),
        ),
        (
            "logs",
            DiagnosticSpec::Process(CommandSpec {
                program: "journalctl",
                base_args: &["--no-pager", "--output=short-iso"],
            }),
        ),
        (
            "failed_units",
            DiagnosticSpec::Process(CommandSpec {
                program: "systemctl",
                base_args: &["--failed", "--no-pager", "--plain"],
            }),
        ),
        (
            "service_status",
            DiagnosticSpec::Process(CommandSpec {
                program: "systemctl",
                base_args: &["status", "--no-pager"],
            }),
        ),
        (
            "dmesg",
            DiagnosticSpec::Process(CommandSpec {
                program: "dmesg",
                base_args: &["-T"],
            }),
        ),
        (
            "uptime",
            DiagnosticSpec::Process(CommandSpec {
                program: "uptime",
                base_args: &[],
            }),
        ),
        (
            "memory",
            DiagnosticSpec::Process(CommandSpec {
                program: "free",
                base_args: &["-h"],
            }),
        ),
        (
            "filesystems",
            DiagnosticSpec::Process(CommandSpec {
                program: "df",
                base_args: &["-h"],
            }),
        ),
    ])
}

impl CommandRunner {
    /// Build a runner, applying both env-var-driven filters from the
    /// process environment at construction time:
    /// - `NETDIAG_ALLOWLIST` narrows the built-in command set
    ///   ([`crate::config::enabled_commands`]).
    /// - `NETDIAG_ENABLE_PRIVILEGED` opts in to the privileged tools
    ///   ([`crate::config::privileged_enabled`]).
    ///
    /// Both values are captured *once* here, never re-read per call — the
    /// runner stays stateless from the MCP request's point of view.
    pub fn new() -> Self {
        let allow = config::enabled_commands();
        let privileged = config::privileged_enabled();
        Self::with_layers(allow.as_ref(), &privileged)
    }

    /// Build a runner with an explicit allowlist narrowing filter, leaving
    /// privileged fully *disabled* (the default, safe choice). Production uses
    /// [`CommandRunner::new`]; this constructor exists so tests can exercise
    /// the narrowing filter without touching the process-global environment.
    pub fn with_enabled(enabled: Option<&HashSet<String>>) -> Self {
        Self::with_layers(enabled, &HashSet::new())
    }

    /// Build a runner with both filters specified explicitly — used by
    /// production [`CommandRunner::new`] and by privileged tests that need to
    /// control both axes without env-var races.
    ///
    /// `enabled = None` keeps every built-in command runnable; `Some(set)`
    /// narrows the allowlist to the listed keys. `privileged_enabled` is the
    /// opt-in set in [`crate::config::PRIVILEGED_ENABLE_ENV`] form
    /// (tool keys, or the `"all"` sentinel — see
    /// [`crate::config::PRIVILEGED_ALL_SENTINEL`]).
    pub fn with_layers(
        enabled: Option<&HashSet<String>>,
        privileged_enabled: &HashSet<String>,
    ) -> Self {
        let mut allowlist = full_allowlist();
        if let Some(set) = enabled {
            allowlist.retain(|key, _| set.contains(*key));
        }
        Self {
            allowlist,
            privileged_enabled: privileged_enabled.clone(),
            timeout: config::default_timeout(),
        }
    }

    /// Spawn `spec` with the validated `extra_args` appended, enforcing the
    /// wall-clock timeout and bounding the captured output.
    async fn run_spec(
        &self,
        spec: &DiagnosticSpec,
        extra_args: &[String],
    ) -> Result<Value, NetdiagError> {
        match spec {
            DiagnosticSpec::Process(process) => self.run_process(process, extra_args).await,
            DiagnosticSpec::File { path } => self.read_file(path, extra_args).await,
        }
    }

    async fn run_process(
        &self,
        spec: &CommandSpec,
        extra_args: &[String],
    ) -> Result<Value, NetdiagError> {
        let mut cmd = Command::new(spec.program);
        cmd.args(spec.base_args);
        cmd.args(extra_args);
        cmd.kill_on_drop(true);

        let output = timeout(self.timeout, cmd.output())
            .await
            .map_err(|_| NetdiagError::CommandExec {
                message: format!("timeout after {}s", self.timeout.as_secs()),
            })?
            .map_err(|e| NetdiagError::CommandExec {
                message: format!("spawn failed: {e}"),
            })?;

        let stdout = bounded_text(
            &output.stdout,
            config::MAX_STDOUT_BYTES,
            config::MAX_OUTPUT_LINES,
        );
        let stderr = bounded_text(
            &output.stderr,
            config::MAX_STDERR_BYTES,
            config::MAX_OUTPUT_LINES,
        );

        Ok(json!({
            "ok": output.status.success(),
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
        }))
    }

    async fn read_file(&self, path: &str, extra_args: &[String]) -> Result<Value, NetdiagError> {
        if !extra_args.is_empty() {
            return Err(NetdiagError::CommandExec {
                message: "file diagnostics do not accept extra arguments".to_string(),
            });
        }

        let bytes = timeout(self.timeout, fs::read(path))
            .await
            .map_err(|_| NetdiagError::CommandExec {
                message: format!("timeout after {}s", self.timeout.as_secs()),
            })?
            .map_err(|e| NetdiagError::CommandExec {
                message: format!("read failed: {e}"),
            })?;

        Ok(json!({
            "ok": true,
            "exit_code": 0,
            "stdout": bounded_text(&bytes, config::MAX_STDOUT_BYTES, config::MAX_OUTPUT_LINES),
            "stderr": "",
        }))
    }
}

impl CommandExecutor for CommandRunner {
    /// Resolve `key` against the (possibly narrowed) allowlist and the
    /// privileged opt-in set, then run it. Refusal precedence is fixed:
    /// 1. allowlist miss → `CommandNotAllowed` (-32011)
    /// 2. privileged key not opted in → `PrivilegedDisabled` (-32011, distinct message)
    ///
    /// Both refusals return before any process is spawned. Allowlist
    /// precedence means a privileged opt-in cannot widen a narrower
    /// `NETDIAG_ALLOWLIST`.
    async fn run(&self, key: &str, extra: &[String]) -> Result<Value, NetdiagError> {
        let spec =
            self.allowlist
                .get(key)
                .cloned()
                .ok_or_else(|| NetdiagError::CommandNotAllowed {
                    command: key.to_string(),
                })?;
        check_privileged(key, &self.privileged_enabled)?;
        self.run_spec(&spec, extra).await
    }
}

/// Pure privileged gating check: `Ok(())` if `key` is not privileged, or if the
/// caller's opt-in set admits it. `Err(PrivilegedDisabled)` otherwise. Kept
/// side-effect-free so the gating logic is unit-testable without any
/// runner or env-var state.
///
/// A `privileged_enabled` entry equal to [`crate::config::PRIVILEGED_ALL_SENTINEL`]
/// passes every privileged key. Other entries are matched literally — typos,
/// non-privileged names, and case-variants of the sentinel (`ALL`, `All`)
/// are inert because nothing in the matchable set is uppercase.
///
/// `pub(crate)` so [`crate::config`] tests can pipe `parse_privileged` output
/// through this function to assert the parser/check contract end-to-end.
pub(crate) fn check_privileged(
    key: &str,
    privileged_enabled: &HashSet<String>,
) -> Result<(), NetdiagError> {
    if !PRIVILEGED_KEYS.contains(&key) {
        return Ok(());
    }
    if privileged_enabled.contains(config::PRIVILEGED_ALL_SENTINEL)
        || privileged_enabled.contains(key)
    {
        return Ok(());
    }
    Err(NetdiagError::PrivilegedDisabled {
        key: key.to_string(),
    })
}

/// Clip raw command output to `max_bytes` then `max_lines`, decoding with
/// UTF-8 lossy conversion. The byte clip lands first so a pathological
/// single-line blob cannot blow the buffer before the line clip applies.
fn bounded_text(bytes: &[u8], max_bytes: usize, max_lines: usize) -> String {
    let clipped = if bytes.len() > max_bytes {
        &bytes[..max_bytes]
    } else {
        bytes
    };
    let text = String::from_utf8_lossy(clipped);
    let mut out = String::new();

    for (idx, line) in text.lines().enumerate() {
        if idx >= max_lines {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }

    out.trim_end().to_string()
}

/// Validate an interface (or systemd unit) name token.
pub fn validate_interface(value: &str) -> Result<(), NetdiagError> {
    validate_token("interface", value)
}

/// Validate a systemd unit name token.
pub fn validate_unit(value: &str) -> Result<(), NetdiagError> {
    validate_token_with_extra("unit", value, &['@'])
}

/// Validate an IP address or hostname token. Shares the leading-`-` reject
/// with [`validate_interface`] and [`validate_unit`] via [`validate_token`].
pub fn validate_ip_or_host(value: &str) -> Result<(), NetdiagError> {
    validate_token("target", value)
}

/// Validate a MAC address in `aa:bb:cc:dd:ee:ff` form (case-insensitive).
pub fn validate_mac(value: &str) -> Result<(), NetdiagError> {
    let normalized = value.to_ascii_lowercase();
    let parts: Vec<_> = normalized.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || !p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(NetdiagError::InvalidParam {
            name: "mac".to_string(),
            reason: "must be in aa:bb:cc:dd:ee:ff form".to_string(),
        });
    }
    Ok(())
}

/// Shared token validator: non-empty, ≤ 128 chars, must not start with `-`,
/// and restricted to a conservative character class. This is what blocks
/// shell-metacharacter injection and argv-flag injection (a leading `-`
/// would be parsed by the underlying command as a CLI option, breaking the
/// "no arbitrary flags" security boundary) — extra args reach the command
/// only through here.
fn validate_token(name: &str, value: &str) -> Result<(), NetdiagError> {
    validate_token_with_extra(name, value, &[])
}

fn validate_token_with_extra(
    name: &str,
    value: &str,
    extra_allowed: &[char],
) -> Result<(), NetdiagError> {
    if value.is_empty() || value.len() > 128 {
        return Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: "must be non-empty and <= 128 chars".to_string(),
        });
    }

    if value.starts_with('-') {
        return Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: "must not begin with '-'".to_string(),
        });
    }

    if !value.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | ':' | '-' | '_' | '/')
            || extra_allowed.contains(&c)
    }) {
        return Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: "contains unsupported characters".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_mac_accepts_valid_mac() {
        assert!(validate_mac("aa:bb:cc:dd:ee:ff").is_ok());
    }

    #[test]
    fn validate_mac_rejects_invalid_mac() {
        assert!(validate_mac("aa:bb:cc").is_err());
    }

    #[test]
    fn validate_token_rejects_bad_chars() {
        assert!(validate_token("target", "8.8.8.8;rm").is_err());
    }

    #[test]
    fn validate_unit_accepts_template_units() {
        assert!(validate_unit("serial-getty@ttyS0.service").is_ok());
    }

    #[test]
    fn validate_ip_or_host_accepts_normal_targets() {
        assert!(validate_ip_or_host("8.8.8.8").is_ok());
        assert!(validate_ip_or_host("gateway.local").is_ok());
    }

    #[test]
    fn validate_ip_or_host_rejects_leading_dash() {
        // A leading '-' would be parsed by ping/traceroute as a CLI flag.
        let err = validate_ip_or_host("-f").unwrap_err();
        assert!(matches!(err, NetdiagError::InvalidParam { ref name, .. } if name == "target"),);
        assert_eq!(err.code(), -32010);
        assert!(validate_ip_or_host("-q30").is_err());
    }

    #[test]
    fn validate_interface_accepts_normal_names() {
        assert!(validate_interface("eth0").is_ok());
        assert!(validate_interface("wlp3s0").is_ok());
        assert!(validate_interface("br-lan").is_ok());
    }

    #[test]
    fn validate_interface_rejects_leading_dash() {
        // ethtool is invoked with no base args, so a leading '-' would be
        // parsed as a CLI flag (e.g. "-h", "-i", "-S"). Block at validation.
        let err = validate_interface("-h").unwrap_err();
        assert!(
            matches!(err, NetdiagError::InvalidParam { ref name, ref reason, .. }
                if name == "interface" && reason.contains("must not begin with '-'"))
        );
        assert_eq!(err.code(), -32010);
        assert!(validate_interface("-i").is_err());
        assert!(validate_interface("--reset").is_err());
    }

    #[test]
    fn validate_unit_rejects_leading_dash() {
        // systemctl status / journalctl -u would parse a leading '-' as an
        // option flag (the validator-token then leaks past the consuming
        // flag in some argv positions). Block at validation.
        let err = validate_unit("-h").unwrap_err();
        assert!(
            matches!(err, NetdiagError::InvalidParam { ref name, ref reason, .. }
                if name == "unit" && reason.contains("must not begin with '-'"))
        );
        assert_eq!(err.code(), -32010);
        assert!(validate_unit("-foo.service").is_err());
    }

    #[test]
    fn new_runner_has_all_commands() {
        let runner = CommandRunner::with_enabled(None);
        assert_eq!(runner.allowlist.len(), BUILTIN_COMMAND_COUNT);
    }

    #[test]
    fn narrowing_filter_keeps_only_listed_keys() {
        let enabled: HashSet<String> = ["routes", "ping"].iter().map(|s| s.to_string()).collect();
        let runner = CommandRunner::with_enabled(Some(&enabled));
        assert_eq!(runner.allowlist.len(), 2);
        assert!(runner.allowlist.contains_key("routes"));
        assert!(!runner.allowlist.contains_key("logs"));
    }

    #[tokio::test]
    async fn disabled_key_is_not_allowed_without_spawning() {
        let enabled: HashSet<String> = ["routes"].iter().map(|s| s.to_string()).collect();
        let runner = CommandRunner::with_enabled(Some(&enabled));
        let err = runner.run("logs", &[]).await.unwrap_err();
        assert!(matches!(err, NetdiagError::CommandNotAllowed { .. }));
    }

    // ---- privileged gating -------------------------------------------------

    #[test]
    fn privileged_keys_match_designed_set() {
        // Regression guard: any change to PRIVILEGED_KEYS must be deliberate. The
        // designed set is the six tools requiring CAP_* or with on-wire
        // side effects.
        let expected = [
            "ping",
            "traceroute",
            "tcpdump_sample",
            "firewall",
            "conntrack",
            "dmesg",
        ];
        assert_eq!(PRIVILEGED_KEYS.len(), expected.len());
        for k in expected {
            assert!(PRIVILEGED_KEYS.contains(&k), "missing privileged key: {k}");
        }
    }

    #[test]
    fn check_privileged_default_blocks_every_privileged_key() {
        let empty = HashSet::new();
        for &k in PRIVILEGED_KEYS {
            let err = check_privileged(k, &empty).unwrap_err();
            assert!(
                matches!(err, NetdiagError::PrivilegedDisabled { ref key } if key == k),
                "expected PrivilegedDisabled for {k}, got {err:?}"
            );
            assert_eq!(err.code(), -32011);
        }
    }

    #[test]
    fn check_privileged_with_all_sentinel_admits_every_privileged_key() {
        let mut set = HashSet::new();
        set.insert(config::PRIVILEGED_ALL_SENTINEL.to_string());
        for &k in PRIVILEGED_KEYS {
            assert!(
                check_privileged(k, &set).is_ok(),
                "{k} must pass under `all`"
            );
        }
    }

    #[test]
    fn check_privileged_subset_admits_only_listed_keys() {
        let set: HashSet<String> = ["ping"].iter().map(|s| s.to_string()).collect();
        assert!(check_privileged("ping", &set).is_ok());
        for &k in PRIVILEGED_KEYS.iter().filter(|k| **k != "ping") {
            assert!(
                matches!(
                    check_privileged(k, &set),
                    Err(NetdiagError::PrivilegedDisabled { .. })
                ),
                "{k} must still be refused when only ping is opted in"
            );
        }
    }

    #[test]
    fn check_privileged_is_a_noop_for_non_privileged_keys() {
        // Default keys must pass regardless of the opt-in set's contents.
        let empty = HashSet::new();
        for k in ["routes", "if_status", "logs", "uptime"] {
            assert!(check_privileged(k, &empty).is_ok());
        }
    }

    #[test]
    fn check_privileged_ignores_unknown_or_non_privileged_entries_in_set() {
        // Operator typo / pasted default keys: silently inert. They never
        // accidentally enable a privileged tool because no privileged key matches
        // them; privileged tools stay refused.
        let set: HashSet<String> = ["bogus", "routes", "if_status"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        for &k in PRIVILEGED_KEYS {
            assert!(
                matches!(
                    check_privileged(k, &set),
                    Err(NetdiagError::PrivilegedDisabled { .. })
                ),
                "{k} must stay refused when only non-privileged names are listed"
            );
        }
    }

    #[tokio::test]
    async fn runner_default_refuses_privileged_with_privileged_disabled_variant() {
        // Default `with_enabled(None)` admits every command via the
        // allowlist but leaves privileged disabled — ping is refused with the
        // privileged variant (carrying the env-var hint), NOT CommandNotAllowed.
        let runner = CommandRunner::with_enabled(None);
        let err = runner.run("ping", &[]).await.unwrap_err();
        assert!(
            matches!(err, NetdiagError::PrivilegedDisabled { ref key } if key == "ping"),
            "expected PrivilegedDisabled, got {err:?}"
        );
        assert!(err.to_string().contains("NETDIAG_ENABLE_PRIVILEGED"));
    }

    #[tokio::test]
    async fn runner_privileged_all_passes_privileged_check_before_spawn() {
        // With `all` opted in, the privileged check is a no-op; we don't assert
        // the spawn outcome (the test host may not have `traceroute`
        // installed). We only assert that the refusal we'd otherwise see
        // does NOT come back as PrivilegedDisabled.
        let privileged: HashSet<String> = [config::PRIVILEGED_ALL_SENTINEL.to_string()]
            .into_iter()
            .collect();
        let runner = CommandRunner::with_layers(None, &privileged);
        let result = runner
            .run("traceroute", &["-m".into(), "1".into(), "127.0.0.1".into()])
            .await;
        if let Err(NetdiagError::PrivilegedDisabled { .. }) = result {
            panic!("privileged gate must not fire when `all` is opted in");
        }
    }

    #[tokio::test]
    async fn runner_allowlist_takes_precedence_over_privileged_opt_in() {
        // Operator narrows the allowlist to exclude `ping` but also opts
        // every privileged tool in. The allowlist wins — `ping` is refused
        // with CommandNotAllowed (the unconditional "not in allowlist"
        // refusal), NOT PrivilegedDisabled.
        let allow: HashSet<String> = ["routes"].iter().map(|s| s.to_string()).collect();
        let privileged: HashSet<String> = [config::PRIVILEGED_ALL_SENTINEL.to_string()]
            .into_iter()
            .collect();
        let runner = CommandRunner::with_layers(Some(&allow), &privileged);
        let err = runner.run("ping", &[]).await.unwrap_err();
        assert!(
            matches!(err, NetdiagError::CommandNotAllowed { ref command } if command == "ping"),
            "allowlist must refuse first; got {err:?}"
        );
    }
}
