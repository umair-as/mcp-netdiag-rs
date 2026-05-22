use std::io;

use mcp_netdiag_rs::protocol::{
    Error as RpcError, Request, Response, INVALID_REQUEST, JSONRPC_VERSION, PARSE_ERROR,
};
use mcp_netdiag_rs::tools::ToolService;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(io::stderr)
        .init();

    let service = ToolService::new();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();
    let mut out = tokio::io::BufWriter::new(stdout);

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        match parse_request(&line) {
            Ok(req) => {
                if req.id.is_none() {
                    let _ = service.handle(&req).await;
                    continue;
                }

                let id = req.id.clone().unwrap_or(Value::Null);
                let resp = match service.handle(&req).await {
                    Ok(result) => Response::success(id, result),
                    Err(err) => Response::failure(id, err),
                };
                write_response(&mut out, &resp).await?;
            }
            Err((id, err)) => {
                let resp = Response::failure(id, err);
                write_response(&mut out, &resp).await?;
            }
        }
    }

    out.flush().await
}

fn parse_request(line: &str) -> Result<Request, (Value, RpcError)> {
    let value: Value = serde_json::from_str(line).map_err(|e| {
        (
            Value::Null,
            RpcError::with_data(
                PARSE_ERROR,
                "parse error",
                json!({ "detail": e.to_string() }),
            ),
        )
    })?;

    let req: Request = serde_json::from_value(value.clone()).map_err(|e| {
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        (
            id,
            RpcError::with_data(
                INVALID_REQUEST,
                "invalid request",
                json!({ "detail": e.to_string() }),
            ),
        )
    })?;

    if req.jsonrpc != JSONRPC_VERSION {
        let id = req.id.clone().unwrap_or(Value::Null);
        return Err((id, RpcError::new(INVALID_REQUEST, "jsonrpc must be '2.0'")));
    }

    Ok(req)
}

async fn write_response(
    out: &mut tokio::io::BufWriter<tokio::io::Stdout>,
    resp: &Response,
) -> io::Result<()> {
    let encoded = serde_json::to_vec(resp)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    out.write_all(&encoded).await?;
    out.write_all(b"\n").await?;
    out.flush().await
}

#[cfg(test)]
mod tests {
    use crate::parse_request;

    #[test]
    fn parse_rejects_invalid_jsonrpc_version() {
        let bad = r#"{"jsonrpc":"1.0","id":1,"method":"initialize","params":{}}"#;
        let err = parse_request(bad).expect_err("must reject version");
        assert_eq!(err.1.code, crate::INVALID_REQUEST);
    }
}
