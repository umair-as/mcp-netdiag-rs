// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-time bounds and runtime environment configuration.
//! See CLAUDE.md §6.
//!
//! Hard limits stay as `pub const` so they participate in type-checking at
//! every call site. Three items are runtime-tunable via environment variables:
//!
//! - `NETDIAG_JOURNAL`     → path to the JSONL audit journal ([`journal_path`])
//! - `NETDIAG_ALLOWLIST`   → narrowing filter over the built-in command set
//!   ([`enabled_commands`])
//! - `NETDIAG_ENABLE_PRIVILEGED` → opt-in for the six privileged tools that require
//!   elevated Linux capabilities or have on-wire side effects ([`privileged_enabled`])

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

/// Wall-clock cap on any single diagnostic command. Commands exceeding it
/// are killed and reported as `CommandExec`.
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Maximum stdout bytes retained from a command before truncation.
pub const MAX_STDOUT_BYTES: usize = 64 * 1024;

/// Maximum stderr bytes retained from a command before truncation.
pub const MAX_STDERR_BYTES: usize = 8 * 1024;

/// Maximum lines retained from a command's captured output.
pub const MAX_OUTPUT_LINES: usize = 512;

/// Maximum characters of raw stdout retained in the diagnostic envelope's
/// `evidence` field (see [`crate::netdiag::normalize_tool_result`]).
pub const EVIDENCE_MAX_CHARS: usize = 500;

/// Maximum characters retained from any large free-form field when
/// summarised into the audit journal (see [`crate::mcp::journal`]).
/// Char-bounded (not byte-bounded) so the slice always lands on a UTF-8
/// boundary.
pub const JOURNAL_HEAD_CHARS: usize = 128;

/// [`DEFAULT_TIMEOUT_SECS`] as a [`Duration`], for the command runner.
pub fn default_timeout() -> Duration {
    Duration::from_secs(DEFAULT_TIMEOUT_SECS)
}

/// Env var pointing at the JSONL audit journal file. The journal is
/// always-on; an unwritable path degrades to a `tracing::warn` and the
/// server continues without auditing rather than failing to start.
pub const JOURNAL_ENV: &str = "NETDIAG_JOURNAL";

/// Default journal path when [`JOURNAL_ENV`] is unset.
pub const DEFAULT_JOURNAL_PATH: &str = "/tmp/mcp-netdiag-journal.jsonl";

/// Resolve the journal path: [`JOURNAL_ENV`] if set, else the default.
pub fn journal_path() -> PathBuf {
    std::env::var(JOURNAL_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_JOURNAL_PATH))
}

/// Env var that narrows the set of runnable command keys.
///
/// When set, it is a comma-separated subset of the built-in command keys
/// (`if_status`, `mac_table`, `neighbors`, `routes`, `addr`, `link_detail`,
/// `route_get`, `rules`, `ping`, `traceroute`, `sockets`, `dns_status`,
/// `resolv_conf`, `ethtool`, `firewall`, `conntrack`, `tcpdump_sample`,
/// `logs`, `failed_units`, `service_status`, `dmesg`, `uptime`, `memory`,
/// `filesystems`). Only the listed keys stay runnable; every other tool returns
/// `CommandNotAllowed` (-32011).
///
/// This is a **narrowing** filter: it can only *disable* built-in commands,
/// never add new programs or arguments. Program paths and base arguments
/// remain compile-time constants, so the command allowlist stays the
/// security boundary regardless of this variable. Unknown names are
/// no-ops (a name that matches no built-in key simply enables nothing).
pub const ALLOWLIST_ENV: &str = "NETDIAG_ALLOWLIST";

/// The set of enabled command keys, or `None` when [`ALLOWLIST_ENV`] is
/// unset (meaning every built-in command is enabled).
///
/// A variable set to an empty or all-whitespace string yields
/// `Some(empty set)` — every command disabled — which is a valid, if
/// extreme, lockdown.
pub fn enabled_commands() -> Option<HashSet<String>> {
    std::env::var(ALLOWLIST_ENV)
        .ok()
        .map(|raw| parse_allowlist(&raw))
}

/// Split a comma-separated allowlist string into a set of keys, dropping
/// empty / whitespace-only entries. Pure (no env access) so it is unit
/// testable without racing other tests on the process environment.
fn parse_allowlist(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Env var that opts in to the six privileged tools. Unlike [`ALLOWLIST_ENV`]
/// which defaults *open*, this defaults *closed*: privileged tools (those
/// requiring CAP_NET_RAW / CAP_NET_ADMIN / CAP_SYSLOG or that emit packets
/// on the wire) refuse to run unless the operator explicitly enables them.
///
/// Accepted forms:
/// - unset / empty / `none` → empty set (every privileged tool refused)
/// - `all` (case-sensitive) → every privileged tool enabled
/// - comma-separated list of privileged tool keys (e.g. `ping,traceroute`);
///   unknown or non-privileged names are silently ignored at check time
///
/// Composition with [`ALLOWLIST_ENV`]: a privileged tool runs iff it is *also*
/// admitted by `NETDIAG_ALLOWLIST` — the allowlist takes precedence and a
/// privileged opt-in cannot widen it.
pub const PRIVILEGED_ENABLE_ENV: &str = "NETDIAG_ENABLE_PRIVILEGED";

/// Sentinel value in [`PRIVILEGED_ENABLE_ENV`] meaning "every privileged tool". Kept
/// as a literal in the returned set; resolution against the privileged key list
/// lives in [`crate::netdiag::commands`] so this module stays unaware of the
/// concrete privileged keys.
pub const PRIVILEGED_ALL_SENTINEL: &str = "all";

/// The privileged opt-in set, parsed from [`PRIVILEGED_ENABLE_ENV`]. Returns an
/// empty set (the default, "all privileged disabled") when the variable is
/// unset, empty, whitespace-only, or `none`.
pub fn privileged_enabled() -> HashSet<String> {
    std::env::var(PRIVILEGED_ENABLE_ENV)
        .ok()
        .map(|raw| parse_privileged(&raw))
        .unwrap_or_default()
}

/// Pure parser for [`PRIVILEGED_ENABLE_ENV`]. Kept side-effect-free so it can be
/// unit tested without touching the process environment.
fn parse_privileged(raw: &str) -> HashSet<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "none" {
        return HashSet::new();
    }
    trimmed
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_allowlist_splits_and_trims() {
        let set = parse_allowlist(" routes , ping ,if_status");
        assert_eq!(set.len(), 3);
        assert!(set.contains("routes"));
        assert!(set.contains("ping"));
        assert!(set.contains("if_status"));
    }

    #[test]
    fn parse_allowlist_drops_empty_entries() {
        let set = parse_allowlist("routes,, ,,ping,");
        assert_eq!(set.len(), 2);
        assert!(set.contains("routes"));
        assert!(set.contains("ping"));
    }

    #[test]
    fn parse_allowlist_empty_string_is_full_lockdown() {
        assert!(parse_allowlist("").is_empty());
        assert!(parse_allowlist("   ").is_empty());
    }

    #[test]
    fn parse_privileged_empty_or_none_is_empty_set() {
        assert!(parse_privileged("").is_empty());
        assert!(parse_privileged("   ").is_empty());
        assert!(parse_privileged("none").is_empty());
    }

    #[test]
    fn parse_privileged_all_keeps_sentinel_literal() {
        let set = parse_privileged("all");
        assert_eq!(set.len(), 1);
        assert!(set.contains(PRIVILEGED_ALL_SENTINEL));
    }

    #[test]
    fn parse_privileged_subset_returns_listed_keys_verbatim() {
        let set = parse_privileged("ping, traceroute ,dmesg");
        assert_eq!(set.len(), 3);
        assert!(set.contains("ping"));
        assert!(set.contains("traceroute"));
        assert!(set.contains("dmesg"));
    }

    #[test]
    fn parse_privileged_drops_empty_entries() {
        let set = parse_privileged("ping,, ,,dmesg,");
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_privileged_is_case_sensitive_for_all_sentinel() {
        // The "all" sentinel is matched at check time against the literal
        // lowercase `PRIVILEGED_ALL_SENTINEL`. parse_privileged returns tokens
        // verbatim, so "ALL" lands in the set but is inert — it never
        // triggers the sentinel branch and matches no privileged key. Locks
        // in the case-sensitive contract documented in README.
        let upper = parse_privileged("ALL");
        assert_eq!(upper.len(), 1);
        assert!(upper.contains("ALL"));
        assert!(
            !upper.contains(PRIVILEGED_ALL_SENTINEL),
            "uppercase ALL must NOT collapse to the all-sentinel literal",
        );

        // End-to-end: pipe the resulting set through the downstream gate
        // and assert privileged tools are still refused. Closes the
        // inert-ness claim from the parser side through to the runner.
        assert!(matches!(
            crate::netdiag::commands::check_privileged("ping", &upper),
            Err(crate::errors::NetdiagError::PrivilegedDisabled { .. }),
        ));
    }

    #[test]
    fn parse_privileged_is_case_sensitive_for_none_token() {
        // Only the lowercase `none` collapses to an empty set. "NONE"
        // passes through as a literal inert token — the outcome (every
        // privileged tool refused) is the same as `none`, but the set is
        // non-empty.
        let set = parse_privileged("NONE");
        assert_eq!(set.len(), 1);
        assert!(set.contains("NONE"));
        assert!(
            !set.is_empty(),
            "uppercase NONE must NOT trigger the empty-set branch"
        );

        // End-to-end: a set containing only the inert "NONE" token still
        // refuses every privileged tool — the outcome matches lowercase
        // `none`'s empty-set branch, just by a different path.
        assert!(matches!(
            crate::netdiag::commands::check_privileged("ping", &set),
            Err(crate::errors::NetdiagError::PrivilegedDisabled { .. }),
        ));
    }

    #[test]
    fn parse_privileged_does_not_validate_names() {
        // Filtering of non-privileged names happens at check time (see
        // netdiag::commands::check_privileged). The parser keeps any non-empty
        // token, so an operator-side typo like "pign" lands in the set but
        // is inert because no privileged key matches it.
        let set = parse_privileged("ping,bogus,routes");
        assert_eq!(set.len(), 3);
        assert!(set.contains("bogus"));
    }

    #[test]
    fn journal_path_defaults_when_env_unset() {
        // Don't set the env var — that would race other tests. Exercising
        // the default branch is the safe assertion here.
        unsafe {
            std::env::remove_var(JOURNAL_ENV);
        }
        assert_eq!(journal_path(), PathBuf::from(DEFAULT_JOURNAL_PATH));
    }
}
