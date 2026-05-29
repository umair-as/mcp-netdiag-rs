// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed errors for the netdiag domain, with a one-to-one mapping to
//! JSON-RPC error codes. See CLAUDE.md §Error semantics.
//!
//! Server-defined error codes occupy the JSON-RPC reserved range
//! -32000..=-32099. Each variant has a unique code so clients can branch
//! on it without parsing the message string. Parse / method-not-found /
//! invalid-request codes (-32700/-32600/-32601/-32602) are owned by the
//! `rmcp` SDK and are not represented here.

use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetdiagError {
    #[error("invalid parameter '{name}': {reason}")]
    InvalidParam { name: String, reason: String },

    #[error("command not allowed: {command}")]
    CommandNotAllowed { command: String },

    #[error(
        "privileged tool disabled; set NETDIAG_ENABLE_PRIVILEGED={key} or \
         NETDIAG_ENABLE_PRIVILEGED=all to enable"
    )]
    PrivilegedDisabled { key: String },

    #[error("command execution failed: {message}")]
    CommandExec { message: String },
}

impl NetdiagError {
    /// Unique JSON-RPC error code for this variant. All codes live inside
    /// the reserved server-defined range (-32000..=-32099).
    ///
    /// `PrivilegedDisabled` shares -32011 with `CommandNotAllowed` by design: a
    /// privileged refusal is a kind of "command not allowed" with extra operator
    /// guidance in the message + `data` payload, not a new failure class for
    /// clients to branch on.
    pub fn code(&self) -> i32 {
        match self {
            NetdiagError::InvalidParam { .. } => -32010,
            NetdiagError::CommandNotAllowed { .. } | NetdiagError::PrivilegedDisabled { .. } => {
                -32011
            }
            NetdiagError::CommandExec { .. } => -32012,
        }
    }

    /// Structured context attached as the JSON-RPC `data` field.
    pub fn data(&self) -> serde_json::Value {
        match self {
            NetdiagError::InvalidParam { name, reason } => {
                json!({ "name": name, "reason": reason })
            }
            NetdiagError::CommandNotAllowed { command } => json!({ "command": command }),
            NetdiagError::PrivilegedDisabled { key } => json!({
                "command": key,
                "privileged": true,
                "enable_env": "NETDIAG_ENABLE_PRIVILEGED",
            }),
            NetdiagError::CommandExec { message } => json!({ "message": message }),
        }
    }
}

impl From<NetdiagError> for rmcp::ErrorData {
    /// Preserve the project's pinned JSON-RPC error codes (`-32010` …
    /// `-32012`) and the structured `data` payload when adapting to rmcp's
    /// error type. A typed `From` keeps the rmcp handlers from drifting to
    /// `-32603 internal_error` for domain failures.
    fn from(err: NetdiagError) -> Self {
        let code = rmcp::model::ErrorCode(err.code());
        let data = err.data();
        rmcp::ErrorData::new(code, err.to_string(), Some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_unique_and_in_reserved_range() {
        // PrivilegedDisabled deliberately shares -32011 with CommandNotAllowed and
        // is excluded from this uniqueness check.
        let codes = [
            NetdiagError::InvalidParam {
                name: "x".into(),
                reason: "y".into(),
            }
            .code(),
            NetdiagError::CommandNotAllowed {
                command: "x".into(),
            }
            .code(),
            NetdiagError::CommandExec {
                message: "x".into(),
            }
            .code(),
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "error codes must be unique");
        for c in codes {
            assert!(
                (-32099..=-32000).contains(&c),
                "code {c} outside reserved range"
            );
        }
    }

    #[test]
    fn privileged_disabled_shares_command_not_allowed_code() {
        let err = NetdiagError::PrivilegedDisabled { key: "ping".into() };
        assert_eq!(err.code(), -32011);
    }

    #[test]
    fn privileged_disabled_maps_to_rmcp_with_env_hint_in_data() {
        let err = NetdiagError::PrivilegedDisabled { key: "ping".into() };
        let r: rmcp::ErrorData = err.into();
        assert_eq!(r.code, rmcp::model::ErrorCode(-32011));
        assert!(
            r.message.contains("NETDIAG_ENABLE_PRIVILEGED"),
            "message must surface the env var: {}",
            r.message
        );
        let data = r.data.as_ref().expect("data payload");
        assert_eq!(data.get("command").and_then(|v| v.as_str()), Some("ping"));
        assert_eq!(data.get("privileged").and_then(|v| v.as_bool()), Some(true));
        // Regression guard: operator-facing UIs key off `enable_env` to
        // surface the env var name. Lock the field name in.
        assert_eq!(
            data.get("enable_env").and_then(|v| v.as_str()),
            Some("NETDIAG_ENABLE_PRIVILEGED"),
        );
    }

    #[test]
    fn maps_to_rmcp_error_with_pinned_code_and_data() {
        // Regression guard: domain errors must keep their pinned code, NOT
        // collapse to -32603 internal_error.
        let err = NetdiagError::CommandNotAllowed {
            command: "rm".into(),
        };
        let r: rmcp::ErrorData = err.into();
        assert_eq!(r.code, rmcp::model::ErrorCode(-32011));
        assert_eq!(
            r.data
                .as_ref()
                .and_then(|d| d.get("command"))
                .and_then(|v| v.as_str()),
            Some("rm"),
        );
    }
}
