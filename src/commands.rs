use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::process::Command;
use tokio::time::timeout;

use crate::errors::NetdiagError;

const DEFAULT_TIMEOUT_SECS: u64 = 5;
const MAX_STDOUT_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: usize = 8 * 1024;
const MAX_OUTPUT_LINES: usize = 512;

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: &'static str,
    pub base_args: &'static [&'static str],
}

#[derive(Debug, Clone)]
pub struct CommandRunner {
    allowlist: HashMap<&'static str, CommandSpec>,
    timeout: Duration,
}

impl Default for CommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner {
    pub fn new() -> Self {
        let mut allowlist = HashMap::new();
        allowlist.insert(
            "if_status",
            CommandSpec {
                program: "ip",
                base_args: &["-j", "-s", "link", "show"],
            },
        );
        allowlist.insert(
            "mac_table",
            CommandSpec {
                program: "bridge",
                base_args: &["-j", "fdb", "show"],
            },
        );
        allowlist.insert(
            "neighbors",
            CommandSpec {
                program: "ip",
                base_args: &["-j", "neigh", "show"],
            },
        );
        allowlist.insert(
            "routes",
            CommandSpec {
                program: "ip",
                base_args: &["-j", "route", "show", "table", "all"],
            },
        );
        allowlist.insert(
            "ping",
            CommandSpec {
                program: "ping",
                base_args: &["-n"],
            },
        );
        allowlist.insert(
            "traceroute",
            CommandSpec {
                program: "traceroute",
                base_args: &["-n"],
            },
        );
        allowlist.insert(
            "logs",
            CommandSpec {
                program: "journalctl",
                base_args: &["--no-pager", "--output=short-iso"],
            },
        );

        Self {
            allowlist,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    pub async fn run(&self, key: &str, extra_args: &[String]) -> Result<Value, NetdiagError> {
        let spec = self
            .allowlist
            .get(key)
            .ok_or_else(|| NetdiagError::CommandNotAllowed {
                command: key.to_string(),
            })?;

        self.run_spec(spec, extra_args).await
    }

    async fn run_spec(
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

        let stdout = bounded_text(&output.stdout, MAX_STDOUT_BYTES, MAX_OUTPUT_LINES);
        let stderr = bounded_text(&output.stderr, MAX_STDERR_BYTES, MAX_OUTPUT_LINES);

        Ok(json!({
            "ok": output.status.success(),
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
        }))
    }
}

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

pub fn validate_interface(value: &str) -> Result<(), NetdiagError> {
    validate_token("interface", value)
}

pub fn validate_ip_or_host(value: &str) -> Result<(), NetdiagError> {
    validate_token("target", value)
}

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

fn validate_token(name: &str, value: &str) -> Result<(), NetdiagError> {
    if value.is_empty() || value.len() > 128 {
        return Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: "must be non-empty and <= 128 chars".to_string(),
        });
    }

    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_' | '/'))
    {
        return Err(NetdiagError::InvalidParam {
            name: name.to_string(),
            reason: "contains unsupported characters".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_mac, validate_token};

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
}
