// SPDX-License-Identifier: MIT OR Apache-2.0

//! mcp-netdiag-rs entry point.
//!
//! Bootstraps the tokio runtime, configures `tracing` for stderr-only
//! output (stdout is reserved for MCP messages), opens the always-on
//! JSONL audit journal, then hands stdio to the rmcp [`NetdiagServer`]
//! which owns dispatch from that point on.

#![deny(clippy::all)]

use rmcp::transport;
use rmcp::ServiceExt;

use mcp_netdiag_rs::config;
use mcp_netdiag_rs::mcp::journal::JournalWriter;
use mcp_netdiag_rs::mcp::NetdiagServer;
use mcp_netdiag_rs::netdiag::commands::CommandRunner;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Handle `--version` / `-V` before any runtime or transport setup. This is
    // a one-shot CLI query that prints to stdout and exits — it never enters
    // an MCP session, so the "stdout is MCP-only" rule (CLAUDE.md §7) does not
    // apply. Kept dependency-free (no clap) per the crate's no-new-deps rule.
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V")
    {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // `rmcp::transport::stdio()` returns the OS stdin/stdout pair and does
    // NOT configure logging — stderr-only `tracing` setup is mandatory,
    // otherwise crate logs would corrupt the MCP wire.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("mcp_netdiag_rs=info")),
        )
        .init();

    // Open the audit journal. Failure is non-fatal: the server runs in
    // degraded mode (no journaling) so a missing /tmp or permissions
    // problem never blocks tool dispatch.
    let journal_path = config::journal_path();
    let journal = JournalWriter::try_open_arc(&journal_path).await;

    let server = NetdiagServer::new(CommandRunner::new(), journal);

    // Hand stdio to rmcp. `serve()` runs the SDK dispatch loop; `.waiting()`
    // blocks until the peer closes the transport (EOF on stdin) or the
    // service errors out.
    let svc = server
        .serve(transport::stdio())
        .await
        .expect("rmcp serve() must start on stdio");
    let _ = svc.waiting().await;

    Ok(())
}
