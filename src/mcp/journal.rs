// SPDX-License-Identifier: MIT OR Apache-2.0

//! Append-only JSONL audit journal for every MCP tool call.
//!
//! One line per [`JournalEntry`]; each `tools/call` produces a `call` row
//! before dispatch and a `result` row after. Per CLAUDE.md §6 this is
//! always-on auditing — not opt-in — but I/O failures degrade gracefully
//! (logged via `tracing::warn`, the journal handle becomes `None`) so a
//! missing or unwritable journal never blocks tool execution.
//!
//! mcp-netdiag-rs is **stateless** — there is no session concept — so the
//! `session_id` field is fixed to [`JournalEntry::NO_SESSION`]. It is kept
//! (rather than removed) so journal rows share one stable shape.
//!
//! Time format: ISO 8601 UTC with millisecond precision. Hand-rolled
//! rather than pulling in a date crate.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::model::CallToolResult;
use rmcp::ErrorData;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Mutex as TokioMutex;
use tracing::warn;

/// One row in the journal. `summary` is tool-specific and kept small.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub ts: String,
    pub session_id: String,
    pub tool: String,
    pub direction: String,
    pub summary: Value,
}

impl JournalEntry {
    pub const DIR_CALL: &'static str = "call";
    pub const DIR_RESULT: &'static str = "result";
    /// `session_id` value for this stateless server — netdiag tools are
    /// fire-and-forget and mint no session ids.
    pub const NO_SESSION: &'static str = "none";

    pub fn new(tool: impl Into<String>, direction: &'static str, summary: Value) -> Self {
        Self {
            ts: iso8601_now(),
            session_id: Self::NO_SESSION.to_string(),
            tool: tool.into(),
            direction: direction.into(),
            summary,
        }
    }
}

/// Wraps an append-mode file. `log` serialises an entry as a single JSONL
/// line and flushes. Errors are logged via `tracing::warn` and swallowed —
/// journaling must never break tool execution.
#[derive(Debug)]
pub struct JournalWriter {
    inner: TokioMutex<BufWriter<tokio::fs::File>>,
    path: PathBuf,
}

impl JournalWriter {
    /// Open `path` in create+append mode.
    pub async fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            inner: TokioMutex::new(BufWriter::new(file)),
            path: path.to_path_buf(),
        })
    }

    /// Open `path` and wrap in `Arc`; on failure, log a warning and return
    /// `None` so callers stay in degraded mode without branching on
    /// `Result`.
    pub async fn try_open_arc(path: &Path) -> Option<Arc<Self>> {
        match Self::open(path).await {
            Ok(w) => {
                tracing::info!(path = %path.display(), "journal opened");
                Some(Arc::new(w))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "journal open failed — continuing in degraded mode (no auditing)"
                );
                None
            }
        }
    }

    /// Path the journal was opened at — surfaced for diagnostics / tests.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serialise `entry` to JSONL and flush. Any failure is logged at warn
    /// level and discarded; `self` is not poisoned so transient failures
    /// (e.g. a full tmpfs that later drains) are retried on the next write.
    pub async fn log(&self, entry: &JournalEntry) {
        let mut line = match serde_json::to_vec(entry) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "journal serialise failed");
                return;
            }
        };
        line.push(b'\n');
        let mut guard = self.inner.lock().await;
        if let Err(e) = guard.write_all(&line).await {
            warn!(error = %e, path = %self.path.display(), "journal write failed");
            return;
        }
        if let Err(e) = guard.flush().await {
            warn!(error = %e, path = %self.path.display(), "journal flush failed");
        }
    }
}

/// Shape the `summary` payload for a `call` row. netdiag tool arguments are
/// small (interface names, IPs, small integers), so they pass through
/// whole — no large-field clipping is needed on the call side.
pub fn call_summary(args: &Value) -> Value {
    json!({ "args": args })
}

/// Shape the `summary` payload for a `result` row. Errors carry the pinned
/// JSON-RPC code + message; successes carry the diagnostic `status` /
/// `signal` plus a clipped head of the evidence.
pub fn result_summary(result: &Result<&CallToolResult, &ErrorData>) -> Value {
    match result {
        Err(e) => json!({
            "ok": false,
            "error_code": e.code.0,
            "error_message": e.message,
        }),
        Ok(call_result) => {
            let sc = call_result.structured_content.as_ref();
            json!({
                "ok": true,
                "status": sc.and_then(|v| v.get("status")),
                "signal": sc.and_then(|v| v.get("signal")),
                "evidence_head": evidence_head(sc),
            })
        }
    }
}

/// First [`crate::config::JOURNAL_HEAD_CHARS`] chars of a result's `evidence`
/// field.
fn evidence_head(sc: Option<&Value>) -> String {
    sc.and_then(|v| v.get("evidence"))
        .and_then(Value::as_str)
        .map(|s| s.chars().take(crate::config::JOURNAL_HEAD_CHARS).collect())
        .unwrap_or_default()
}

/// Format `SystemTime::now()` as `YYYY-MM-DDTHH:MM:SS.sssZ`.
fn iso8601_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    iso8601_from_secs(dur.as_secs() as i64, dur.subsec_millis())
}

fn iso8601_from_secs(secs: i64, millis: u32) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let h = (tod / 3600) as u32;
    let mi = ((tod % 3600) / 60) as u32;
    let s = (tod % 60) as u32;
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant's date algorithm: days-since-Unix-epoch → (year, month,
/// day). See https://howardhinnant.github.io/date_algorithms.html.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ErrorCode;

    #[test]
    fn iso8601_epoch_renders_zero() {
        assert_eq!(iso8601_from_secs(0, 0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn iso8601_known_date() {
        assert_eq!(
            iso8601_from_secs(1_704_067_200, 0),
            "2024-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn entry_session_id_is_always_none() {
        let e = JournalEntry::new("net.routes", JournalEntry::DIR_CALL, json!({}));
        assert_eq!(e.session_id, JournalEntry::NO_SESSION);
    }

    #[test]
    fn result_summary_includes_pinned_error_code() {
        let err = ErrorData::new(ErrorCode(-32011), "command not allowed", None);
        let summary = result_summary(&Err(&err));
        assert_eq!(summary["ok"], json!(false));
        assert_eq!(summary["error_code"], json!(-32011));
        assert_eq!(summary["error_message"], json!("command not allowed"));
    }

    #[test]
    fn result_summary_extracts_status_and_signal() {
        let cr = CallToolResult::structured(json!({
            "status": "ok",
            "signal": "command_succeeded",
            "evidence": "x".repeat(300),
        }));
        let summary = result_summary(&Ok(&cr));
        assert_eq!(summary["ok"], json!(true));
        assert_eq!(summary["status"], json!("ok"));
        assert_eq!(summary["signal"], json!("command_succeeded"));
        assert_eq!(
            summary["evidence_head"].as_str().unwrap().chars().count(),
            crate::config::JOURNAL_HEAD_CHARS
        );
    }

    #[tokio::test]
    async fn writer_appends_one_jsonl_line_per_log() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let writer = JournalWriter::open(tmp.path()).await.unwrap();

        writer
            .log(&JournalEntry::new(
                "net.routes",
                JournalEntry::DIR_CALL,
                json!({"args": {}}),
            ))
            .await;
        writer
            .log(&JournalEntry::new(
                "net.routes",
                JournalEntry::DIR_RESULT,
                json!({"ok": true}),
            ))
            .await;

        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 lines, got:\n{contents}");

        let parsed: JournalEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.tool, "net.routes");
        assert_eq!(parsed.direction, "call");
        assert_eq!(parsed.session_id, "none");
        assert!(parsed.ts.ends_with('Z'));
    }

    #[tokio::test]
    async fn try_open_arc_returns_none_in_degraded_mode() {
        let result = JournalWriter::try_open_arc(Path::new("/proc/1/no-such-journal")).await;
        assert!(result.is_none(), "must degrade to None on open failure");
    }
}
