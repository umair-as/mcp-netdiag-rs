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
//! - `NETDIAG_ENABLE_TIER2` → opt-in for the six tier-2 tools that require
//!   elevated Linux capabilities or have on-wire side effects ([`tier2_enabled`])

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

/// Env var that opts in to the six tier-2 tools. Unlike [`ALLOWLIST_ENV`]
/// which defaults *open*, this defaults *closed*: tier-2 tools (those
/// requiring CAP_NET_RAW / CAP_NET_ADMIN / CAP_SYSLOG or that emit packets
/// on the wire) refuse to run unless the operator explicitly enables them.
///
/// Accepted forms:
/// - unset / empty / `none` → empty set (every tier-2 tool refused)
/// - `all` (case-sensitive) → every tier-2 tool enabled
/// - comma-separated list of tier-2 tool keys (e.g. `ping,traceroute`);
///   unknown or non-tier-2 names are silently ignored at check time
///
/// Composition with [`ALLOWLIST_ENV`]: a tier-2 tool runs iff it is *also*
/// admitted by `NETDIAG_ALLOWLIST` — the allowlist takes precedence and a
/// tier-2 opt-in cannot widen it.
pub const TIER2_ENABLE_ENV: &str = "NETDIAG_ENABLE_TIER2";

/// Sentinel value in [`TIER2_ENABLE_ENV`] meaning "every tier-2 tool". Kept
/// as a literal in the returned set; resolution against the tier-2 key list
/// lives in [`crate::netdiag::commands`] so this module stays unaware of the
/// concrete tier-2 keys.
pub const TIER2_ALL_SENTINEL: &str = "all";

/// The tier-2 opt-in set, parsed from [`TIER2_ENABLE_ENV`]. Returns an
/// empty set (the default, "all tier-2 disabled") when the variable is
/// unset, empty, whitespace-only, or `none`.
pub fn tier2_enabled() -> HashSet<String> {
    std::env::var(TIER2_ENABLE_ENV)
        .ok()
        .map(|raw| parse_tier2(&raw))
        .unwrap_or_default()
}

/// Pure parser for [`TIER2_ENABLE_ENV`]. Kept side-effect-free so it can be
/// unit tested without touching the process environment.
fn parse_tier2(raw: &str) -> HashSet<String> {
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
    fn parse_tier2_empty_or_none_is_empty_set() {
        assert!(parse_tier2("").is_empty());
        assert!(parse_tier2("   ").is_empty());
        assert!(parse_tier2("none").is_empty());
    }

    #[test]
    fn parse_tier2_all_keeps_sentinel_literal() {
        let set = parse_tier2("all");
        assert_eq!(set.len(), 1);
        assert!(set.contains(TIER2_ALL_SENTINEL));
    }

    #[test]
    fn parse_tier2_subset_returns_listed_keys_verbatim() {
        let set = parse_tier2("ping, traceroute ,dmesg");
        assert_eq!(set.len(), 3);
        assert!(set.contains("ping"));
        assert!(set.contains("traceroute"));
        assert!(set.contains("dmesg"));
    }

    #[test]
    fn parse_tier2_drops_empty_entries() {
        let set = parse_tier2("ping,, ,,dmesg,");
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_tier2_does_not_validate_names() {
        // Filtering of non-tier-2 names happens at check time (see
        // netdiag::commands::check_tier2). The parser keeps any non-empty
        // token, so an operator-side typo like "pign" lands in the set but
        // is inert because no tier-2 key matches it.
        let set = parse_tier2("ping,bogus,routes");
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
