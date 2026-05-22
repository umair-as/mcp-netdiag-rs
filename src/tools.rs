use serde_json::{json, Value};

use crate::commands::{validate_interface, validate_ip_or_host, validate_mac, CommandRunner};
use crate::errors::NetdiagError;
use crate::protocol;

#[derive(Debug, Clone)]
pub struct ToolService {
    runner: CommandRunner,
}

impl Default for ToolService {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolService {
    pub fn new() -> Self {
        Self {
            runner: CommandRunner::new(),
        }
    }

    pub async fn handle(&self, req: &protocol::Request) -> Result<Value, protocol::Error> {
        match req.method.as_str() {
            "initialize" => Ok(handle_initialize()),
            "notifications/initialized" => Ok(json!({})),
            "tools/list" => Ok(handle_tools_list()),
            "tools/call" => self.handle_tools_call(&req.params).await,
            _ => Err(protocol::Error::new(
                protocol::METHOD_NOT_FOUND,
                "method not found",
            )),
        }
    }

    async fn handle_tools_call(&self, params: &Value) -> Result<Value, protocol::Error> {
        let name = required_str(params, "name")?;
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let args = args.as_object().ok_or_else(|| {
            protocol::Error::new(
                protocol::INVALID_PARAMS,
                "arguments must be a JSON object when provided",
            )
        })?;

        let result = match name {
            "net.if_status" => {
                reject_unknown_args(args, &["interface"])?;
                let mut extra = Vec::new();
                if let Some(iface) = args.get("interface").and_then(Value::as_str) {
                    validate_interface(iface).map_err(protocol::Error::from)?;
                    extra.push("dev".to_string());
                    extra.push(iface.to_string());
                }
                self.runner.run("if_status", &extra).await
            }
            "net.mac_lookup" => {
                reject_unknown_args(args, &["mac"])?;
                let mac = required_arg_str(args, "mac")?;
                validate_mac(mac).map_err(protocol::Error::from)?;
                self.runner
                    .run("mac_table", &["to".to_string(), mac.to_string()])
                    .await
            }
            "net.neighbors" => {
                reject_unknown_args(args, &["interface"])?;
                let mut extra = Vec::new();
                if let Some(iface) = args.get("interface").and_then(Value::as_str) {
                    validate_interface(iface).map_err(protocol::Error::from)?;
                    extra.push("dev".to_string());
                    extra.push(iface.to_string());
                }
                self.runner.run("neighbors", &extra).await
            }
            "net.routes" => {
                reject_unknown_args(args, &[])?;
                self.runner.run("routes", &[]).await
            }
            "net.ping" => {
                reject_unknown_args(args, &["target", "count", "timeout_secs"])?;
                let target = required_arg_str(args, "target")?;
                validate_ip_or_host(target).map_err(protocol::Error::from)?;
                let count = bounded_u64(args, "count", 1, 10)?.unwrap_or(3);
                let wait = bounded_u64(args, "timeout_secs", 1, 5)?.unwrap_or(2);
                self.runner
                    .run(
                        "ping",
                        &[
                            "-c".to_string(),
                            count.to_string(),
                            "-W".to_string(),
                            wait.to_string(),
                            target.to_string(),
                        ],
                    )
                    .await
            }
            "net.traceroute" => {
                reject_unknown_args(args, &["target", "max_hops"])?;
                let target = required_arg_str(args, "target")?;
                validate_ip_or_host(target).map_err(protocol::Error::from)?;
                let hops = bounded_u64(args, "max_hops", 1, 30)?.unwrap_or(12);
                self.runner
                    .run(
                        "traceroute",
                        &["-m".to_string(), hops.to_string(), target.to_string()],
                    )
                    .await
            }
            "net.logs" => {
                reject_unknown_args(args, &["lines", "unit"])?;
                let lines = bounded_u64(args, "lines", 1, 200)?.unwrap_or(50);
                let mut extra = vec!["-n".to_string(), lines.to_string()];
                if let Some(unit) = args.get("unit").and_then(Value::as_str) {
                    validate_interface(unit).map_err(protocol::Error::from)?;
                    extra.push("-u".to_string());
                    extra.push(unit.to_string());
                }
                self.runner.run("logs", &extra).await
            }
            _ => {
                return Err(protocol::Error::with_data(
                    protocol::INVALID_PARAMS,
                    "unknown tool",
                    json!({"name": name}),
                ))
            }
        };

        result
            .map(|raw| {
                let normalized = normalize_tool_result(name, raw);
                json!({"content": [{"type": "json", "json": normalized}]})
            })
            .map_err(protocol::Error::from)
    }
}

fn required_str<'a>(obj: &'a Value, key: &str) -> Result<&'a str, protocol::Error> {
    obj.get(key).and_then(Value::as_str).ok_or_else(|| {
        protocol::Error::new(protocol::INVALID_PARAMS, format!("missing string '{key}'"))
    })
}

fn required_arg_str<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, protocol::Error> {
    obj.get(key).and_then(Value::as_str).ok_or_else(|| {
        protocol::Error::new(
            protocol::INVALID_PARAMS,
            format!("missing argument '{key}'"),
        )
    })
}

fn bounded_u64(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, protocol::Error> {
    match obj.get(key).and_then(Value::as_u64) {
        Some(v) if v < min || v > max => Err(NetdiagError::InvalidParam {
            name: key.to_string(),
            reason: format!("must be in range [{min}, {max}]"),
        }
        .into()),
        Some(v) => Ok(Some(v)),
        None => Ok(None),
    }
}

fn reject_unknown_args(
    obj: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), protocol::Error> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(NetdiagError::InvalidParam {
                name: key.to_string(),
                reason: "unknown argument".to_string(),
            }
            .into());
        }
    }
    Ok(())
}

fn normalize_tool_result(tool: &str, raw: Value) -> Value {
    let ok = raw.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let status = if ok { "ok" } else { "fail" };
    let signal = signal_for(tool, ok);
    let evidence = raw
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let suggestion = suggested_action(tool, ok, evidence);

    json!({
        "tool": tool,
        "status": status,
        "signal": signal,
        "evidence": truncate_text(evidence, 500),
        "suggested_action": suggestion,
        "raw": raw
    })
}

fn signal_for(tool: &str, ok: bool) -> &'static str {
    if ok {
        return "command_succeeded";
    }
    match tool {
        "net.if_status" => "interface_or_link_issue",
        "net.mac_lookup" => "mac_table_lookup_failed",
        "net.neighbors" => "neighbor_resolution_issue",
        "net.routes" => "routing_state_issue",
        "net.ping" => "connectivity_check_failed",
        "net.traceroute" => "path_diagnosis_failed",
        "net.logs" => "log_extraction_failed",
        _ => "diagnostic_command_failed",
    }
}

fn suggested_action(tool: &str, ok: bool, evidence: &str) -> &'static str {
    if !ok {
        return match tool {
            "net.ping" => "Verify VLAN, gateway route, and ACL/firewall path; run traceroute next.",
            "net.if_status" => {
                "Check cable/SFP, admin state, and interface counters for errors/drops."
            }
            "net.neighbors" => "Verify ARP/ND reachability on the expected L2 segment and VLAN.",
            "net.routes" => {
                "Validate route presence, metric preference, and next-hop reachability."
            }
            _ => "Inspect stderr and rerun with narrower scope.",
        };
    }

    if tool == "net.if_status" && (evidence.contains("DOWN") || evidence.contains("NO-CARRIER")) {
        "Link appears down; verify physical link, transceiver, and peer port state."
    } else {
        "No immediate fault signal from this command; continue with adjacent diagnostics."
    }
}

fn truncate_text(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    format!("{}...", &text[..max])
}

fn handle_initialize() -> Value {
    json!({
        "protocolVersion": "2024-11-05",
        "serverInfo": {
            "name": "mcp-netdiag-rs",
            "version": "0.1.0"
        },
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        }
    })
}

fn handle_tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "net.if_status",
                "description": "Show interface state and counters using ip -j -s link show",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "interface": { "type": "string" }
                    }
                }
            },
            {
                "name": "net.mac_lookup",
                "description": "Lookup a MAC in bridge FDB",
                "inputSchema": {
                    "type": "object",
                    "required": ["mac"],
                    "additionalProperties": false,
                    "properties": {
                        "mac": { "type": "string" }
                    }
                }
            },
            {
                "name": "net.neighbors",
                "description": "Show ARP/neighbor state",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "interface": { "type": "string" }
                    }
                }
            },
            {
                "name": "net.routes",
                "description": "Show routing table state",
                "inputSchema": { "type": "object", "additionalProperties": false }
            },
            {
                "name": "net.ping",
                "description": "Bounded ping check",
                "inputSchema": {
                    "type": "object",
                    "required": ["target"],
                    "additionalProperties": false,
                    "properties": {
                        "target": { "type": "string" },
                        "count": { "type": "integer", "minimum": 1, "maximum": 10 },
                        "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 5 }
                    }
                }
            },
            {
                "name": "net.traceroute",
                "description": "Bounded traceroute check",
                "inputSchema": {
                    "type": "object",
                    "required": ["target"],
                    "additionalProperties": false,
                    "properties": {
                        "target": { "type": "string" },
                        "max_hops": { "type": "integer", "minimum": 1, "maximum": 30 }
                    }
                }
            },
            {
                "name": "net.logs",
                "description": "Extract recent bounded system logs",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "lines": { "type": "integer", "minimum": 1, "maximum": 200 },
                        "unit": { "type": "string" }
                    }
                }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::protocol::Request;

    use super::ToolService;

    #[tokio::test]
    async fn handles_initialize() {
        let svc = ToolService::new();
        let req = Request {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: json!({}),
        };

        let out = svc.handle(&req).await.expect("initialize should work");
        assert_eq!(out["serverInfo"]["name"], "mcp-netdiag-rs");
    }

    #[tokio::test]
    async fn rejects_unknown_method() {
        let svc = ToolService::new();
        let req = Request {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "unknown".to_string(),
            params: json!({}),
        };

        let err = svc.handle(&req).await.expect_err("must fail");
        assert_eq!(err.code, crate::protocol::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn accepts_initialized_notification_method() {
        let svc = ToolService::new();
        let req = Request {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "notifications/initialized".to_string(),
            params: json!({}),
        };
        let out = svc.handle(&req).await.expect("must be accepted");
        assert_eq!(out, json!({}));
    }

    #[tokio::test]
    async fn rejects_unknown_tool_argument() {
        let svc = ToolService::new();
        let req = Request {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: json!({
                "name": "net.routes",
                "arguments": {"unexpected": true}
            }),
        };
        let err = svc.handle(&req).await.expect_err("must reject");
        assert_eq!(err.code, -32010);
    }
}
