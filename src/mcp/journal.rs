// SPDX-License-Identifier: MIT OR Apache-2.0

//! Append-only JSONL audit journal for every MCP tool call.
//!
//! One line per [`JournalEntry`]; each `tools/call` produces a `call` row
//! before dispatch and a `result` row after. Per CLAUDE.md §6 this is
//! always-on auditing — not opt-in — but I/O failures degrade gracefully
//! (logged via `tracing::error`, the journal handle becomes `None`) so a
//! missing or unwritable journal never blocks tool execution.
//!
//! The open is hardened against a pre-planted path: `O_NOFOLLOW` refuses a
//! symlink, `O_NONBLOCK` stops a FIFO with no reader from hanging startup,
//! and the opened fd must be a regular file owned by the server's effective
//! uid. New files are created 0600 and a newly created parent directory
//! 0700.
//!
//! mcp-netdiag-rs is **stateless** — there is no session concept — so the
//! `session_id` field is fixed to [`JournalEntry::NO_SESSION`]. It is kept
//! (rather than removed) so journal rows share one stable shape.
//!
//! Time format: ISO 8601 UTC with millisecond precision. Hand-rolled
//! rather than pulling in a date crate.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
use tracing::{error, warn};

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
    /// Open `path` in create+append mode, refusing anything another user
    /// could have planted: a symlink, a non-regular file (FIFO, device,
    /// directory), or a file — or freshly-defaulted parent directory — not
    /// owned by the server's effective uid.
    pub async fn open(path: &Path) -> std::io::Result<Self> {
        let euid = crate::config::euid();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let strict_dir = crate::config::journal_tmp_fallback_dir(euid);
            prepare_parent(parent, euid, &strict_dir).await?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .await?;
        // fstat the fd, not the path, so a swap after open cannot fool it.
        let meta = file.metadata().await?;
        if !meta.is_file() {
            return Err(unsafe_path("journal path is not a regular file"));
        }
        if meta.uid() != euid {
            return Err(unsafe_path("journal file is owned by another user"));
        }
        // Narrow a pre-existing file we own (e.g. a 0644 v0.1.0 journal).
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await?;
        Ok(Self {
            inner: TokioMutex::new(BufWriter::new(file)),
            path: path.to_path_buf(),
        })
    }

    /// Open `path` and wrap in `Arc`; on failure, log an error and return
    /// `None` so callers stay in degraded mode without branching on
    /// `Result`.
    pub async fn try_open_arc(path: &Path) -> Option<Arc<Self>> {
        Self::try_open_first(&[path.to_path_buf()]).await
    }

    /// Try each candidate in order (see [`crate::config::journal_paths`])
    /// and keep the first that opens. A candidate refused as unsafe logs at
    /// error, any other failure before the last candidate at warn; if every
    /// candidate fails, log at error and return `None` (degraded mode).
    pub async fn try_open_first(paths: &[PathBuf]) -> Option<Arc<Self>> {
        for (i, path) in paths.iter().enumerate() {
            match Self::open(path).await {
                Ok(w) => {
                    tracing::info!(path = %path.display(), "journal opened");
                    return Some(Arc::new(w));
                }
                // A planted symlink or foreign-owned file/dir is a tampering
                // sign, not an environment problem: say so loudly even
                // though auditing continues on the fallback.
                Err(e) if i + 1 < paths.len() && is_refusal(&e) => error!(
                    error = %e,
                    path = %path.display(),
                    "journal path refused as unsafe — trying fallback path"
                ),
                Err(e) if i + 1 < paths.len() => warn!(
                    error = %e,
                    path = %path.display(),
                    "journal open failed — trying fallback path"
                ),
                Err(e) => error!(
                    error = %e,
                    path = %path.display(),
                    "journal open failed — continuing in degraded mode (no auditing)"
                ),
            }
        }
        None
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

/// Create the journal's parent directory (0700) if missing. `strict_dir`
/// is the per-uid `/tmp` fallback ([`crate::config::journal_tmp_fallback_dir`]):
/// it sits in a world-writable parent, so when `parent` is that directory it
/// must be a real directory owned by `euid` with no group/other bits. Any
/// other existing directory is left alone (it is under the user's home or an
/// operator-chosen path). Missing ancestors are created 0700 as well.
async fn prepare_parent(parent: &Path, euid: u32, strict_dir: &Path) -> std::io::Result<()> {
    if parent == strict_dir {
        // Non-recursive create: if another user wins the race and creates
        // it first we get AlreadyExists, and the check below always runs
        // against whatever is actually there.
        match tokio::fs::DirBuilder::new()
            .mode(0o700)
            .create(parent)
            .await
        {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let meta = tokio::fs::symlink_metadata(parent).await?;
        if !meta.is_dir() || meta.uid() != euid || meta.mode() & 0o077 != 0 {
            return Err(unsafe_path(
                "journal directory under /tmp is not a private directory owned by this user",
            ));
        }
        return Ok(());
    }
    match tokio::fs::symlink_metadata(parent).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tokio::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .await
        }
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

/// True for errors that mean "refused as unsafe" rather than "unavailable":
/// our own ownership/type checks, or `O_NOFOLLOW` hitting a symlink.
fn is_refusal(e: &std::io::Error) -> bool {
    // ELOOP: O_NOFOLLOW hit a symlink. ENXIO: O_NONBLOCK open of a FIFO with
    // no reader — a non-regular file, like the `!is_file()` refusal.
    matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENXIO))
        || (e.kind() == std::io::ErrorKind::PermissionDenied && e.raw_os_error().is_none())
}

fn unsafe_path(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
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
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

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
    async fn open_creates_file_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("journal.jsonl");
        JournalWriter::open(&path).await.unwrap();
        let file_mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        let dir_mode = std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[tokio::test]
    async fn open_narrows_existing_world_readable_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        JournalWriter::open(tmp.path()).await.unwrap();
        assert_eq!(std::fs::metadata(tmp.path()).unwrap().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn open_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("victim");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("journal.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = JournalWriter::open(&link).await.unwrap_err();
        assert!(is_refusal(&err), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn open_refuses_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("journal.jsonl");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        // Open on a separate OS thread with its own runtime: if O_NONBLOCK
        // regressed, the open would block forever, and a tokio timeout
        // cannot cancel a blocking-pool thread — the test binary would hang
        // instead of failing.
        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _ = tx.send(rt.block_on(JournalWriter::open(&path)).map(|_| ()));
        });
        let res = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("open on a reader-less FIFO must not block");
        let err = res.unwrap_err();
        assert!(is_refusal(&err), "{err}");
    }

    #[tokio::test]
    async fn strict_dir_is_created_private_and_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("fallback");
        let euid = crate::config::euid();
        prepare_parent(&dir, euid, &dir).await.unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        // Re-run with the directory already present (second server start).
        prepare_parent(&dir, euid, &dir).await.unwrap();
    }

    #[tokio::test]
    async fn strict_dir_refuses_shared_modes_symlinks_files_and_foreign_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let euid = crate::config::euid();
        for mode in [0o755, 0o770, 0o701] {
            let dir = tmp.path().join(format!("m{mode:o}"));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = prepare_parent(&dir, euid, &dir).await.unwrap_err();
            assert!(is_refusal(&err), "mode {mode:o} must be refused");
        }
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(prepare_parent(&link, euid, &link).await.is_err(), "symlink");
        let file = tmp.path().join("file");
        std::fs::write(&file, b"").unwrap();
        // 0600 so only the is_dir check can refuse it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(prepare_parent(&file, euid, &file).await.is_err(), "file");
        // A private dir owned by someone else (modelled with another euid).
        assert!(
            prepare_parent(&real, euid.wrapping_add(1), &real)
                .await
                .is_err(),
            "foreign owner"
        );
        // Only the strict dir is checked; any other existing dir is trusted.
        let shared = tmp.path().join("m755");
        assert!(prepare_parent(&shared, euid, &real).await.is_ok());
    }

    #[tokio::test]
    async fn open_refuses_non_regular_file() {
        assert!(JournalWriter::open(Path::new("/dev/null")).await.is_err());
    }

    #[tokio::test]
    async fn try_open_first_falls_back_past_unwritable_path() {
        let tmp = tempfile::tempdir().unwrap();
        let good = tmp.path().join("journal.jsonl");
        let paths = [PathBuf::from("/proc/1/no-such-journal"), good.clone()];
        let w = JournalWriter::try_open_first(&paths)
            .await
            .expect("second candidate must open");
        assert_eq!(w.path(), good);
    }

    #[tokio::test]
    async fn try_open_arc_returns_none_in_degraded_mode() {
        let result = JournalWriter::try_open_arc(Path::new("/proc/1/no-such-journal")).await;
        assert!(result.is_none(), "must degrade to None on open failure");
    }
}
