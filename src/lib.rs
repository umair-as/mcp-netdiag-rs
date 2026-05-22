// SPDX-License-Identifier: MIT OR Apache-2.0

//! mcp-netdiag-rs library crate.
//!
//! A stateless MCP server exposing read-only network-diagnostic tools.
//! Modules are re-exported so the integration tests in `tests/` can drive
//! the server in-process.

#![deny(clippy::all)]

pub mod config;
pub mod errors;
pub mod mcp;
pub mod netdiag;
