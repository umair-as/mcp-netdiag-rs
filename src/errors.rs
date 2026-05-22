use serde_json::json;
use thiserror::Error;

use crate::protocol;

#[derive(Debug, Error)]
pub enum NetdiagError {
    #[error("invalid parameter '{name}': {reason}")]
    InvalidParam { name: String, reason: String },

    #[error("command not allowed: {command}")]
    CommandNotAllowed { command: String },

    #[error("command execution failed: {message}")]
    CommandExec { message: String },
}

impl NetdiagError {
    pub fn code(&self) -> i32 {
        match self {
            NetdiagError::InvalidParam { .. } => -32010,
            NetdiagError::CommandNotAllowed { .. } => -32011,
            NetdiagError::CommandExec { .. } => -32012,
        }
    }

    pub fn data(&self) -> serde_json::Value {
        match self {
            NetdiagError::InvalidParam { name, reason } => {
                json!({ "name": name, "reason": reason })
            }
            NetdiagError::CommandNotAllowed { command } => json!({ "command": command }),
            NetdiagError::CommandExec { message } => json!({ "message": message }),
        }
    }
}

impl From<NetdiagError> for protocol::Error {
    fn from(err: NetdiagError) -> Self {
        protocol::Error::with_data(err.code(), err.to_string(), err.data())
    }
}
