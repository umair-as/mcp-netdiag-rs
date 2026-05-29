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

/// Resolves logical command keys to allowlisted [`CommandSpec`]s and runs
/// them with a wall-clock timeout and bounded output capture.
#[derive(Debug, Clone)]
pub struct CommandRunner {
    allowlist: HashMap<&'static str, DiagnosticSpec>,
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
    /// Build a runner, applying the `NETDIAG_ALLOWLIST` narrowing filter
    /// from the environment (see [`crate::config::enabled_commands`]).
    pub fn new() -> Self {
        Self::with_enabled(config::enabled_commands().as_ref())
    }

    /// Build a runner with an explicit enabled-key filter — `None` enables
    /// every built-in command, `Some(set)` keeps only the listed keys.
    /// Production uses [`CommandRunner::new`]; this constructor exists so
    /// tests can exercise the narrowing filter without touching the
    /// process-global environment.
    pub fn with_enabled(enabled: Option<&HashSet<String>>) -> Self {
        let mut allowlist = full_allowlist();
        if let Some(set) = enabled {
            allowlist.retain(|key, _| set.contains(*key));
        }
        Self {
            allowlist,
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
    /// Resolve `key` against the (possibly narrowed) allowlist and run it.
    /// A key that is unknown *or* disabled by `NETDIAG_ALLOWLIST` yields
    /// `CommandNotAllowed` before any process is spawned.
    async fn run(&self, key: &str, extra: &[String]) -> Result<Value, NetdiagError> {
        let spec =
            self.allowlist
                .get(key)
                .cloned()
                .ok_or_else(|| NetdiagError::CommandNotAllowed {
                    command: key.to_string(),
                })?;
        self.run_spec(&spec, extra).await
    }
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
}
