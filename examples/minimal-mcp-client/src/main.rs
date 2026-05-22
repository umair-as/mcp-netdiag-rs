use std::collections::BTreeMap;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
enum ClientError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("protocol error: {0}")]
    Protocol(String),
}

struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

#[derive(Debug, Clone)]
struct AppConfig {
    server_path: String,
    question: String,
    interface: Option<String>,
    target: Option<String>,
    json_output: bool,
}

#[derive(Debug, Clone)]
struct PlanStep {
    tool: &'static str,
    args: Value,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ClientError> {
    let cfg = parse_args()?;
    let mut client = McpClient::spawn(&cfg.server_path)?;

    let init = client.request("initialize", json!({}))?;
    if !cfg.json_output {
        println!("initialized: {}", init["serverInfo"]["name"]);
    }
    client.notify("notifications/initialized", json!({}))?;

    let tools = client.request("tools/list", json!({}))?;
    let tools_count = tools["tools"].as_array().map_or(0, |v| v.len());
    if !cfg.json_output {
        println!("tools discovered: {tools_count}");
    }

    let plan = build_plan(&cfg);
    if !cfg.json_output {
        println!("plan: {} steps", plan.len());
    }

    let mut outputs: Vec<(String, Value)> = Vec::new();
    for step in &plan {
        let res = client.request(
            "tools/call",
            json!({
                "name": step.tool,
                "arguments": step.args,
            }),
        );

        let normalized = match res {
            Ok(value) => value
                .get("content")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|entry| entry.get("json"))
                .cloned()
                .map(normalize_payload)
                .unwrap_or_else(|| json!({"status": "unknown", "signal": "malformed_tool_result"})),
            Err(err) => json!({
                "tool": step.tool,
                "status": "fail",
                "signal": "mcp_tool_call_failed",
                "evidence": "",
                "suggested_action": "Inspect server error details for missing command/dependency.",
                "raw": {"error": err.to_string()},
            }),
        };

        outputs.push((step.tool.to_string(), normalized));
    }

    if cfg.json_output {
        print_json_report(&cfg, &outputs, tools_count)?;
    } else {
        print_diagnosis(&cfg, &outputs);
    }
    client.shutdown();
    Ok(())
}

impl McpClient {
    fn spawn(server_path: &str) -> Result<Self, ClientError> {
        let mut child = Command::new(server_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ClientError::Protocol("missing child stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ClientError::Protocol("missing child stdout".to_string()))?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        })
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;

        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        self.send(&req)?;
        let resp = self.read_line_json()?;

        if let Some(err) = resp.get("error") {
            return Err(ClientError::Protocol(format!(
                "server error for {method}: {err}"
            )));
        }

        let got_id = resp.get("id").and_then(Value::as_u64).unwrap_or(0);
        if got_id != id {
            return Err(ClientError::Protocol(format!(
                "response id mismatch: expected {id}, got {got_id}"
            )));
        }

        resp.get("result")
            .cloned()
            .ok_or_else(|| ClientError::Protocol("missing result in response".to_string()))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), ClientError> {
        let req = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.send(&req)
    }

    fn send(&mut self, value: &Value) -> Result<(), ClientError> {
        let encoded = serde_json::to_vec(value)?;
        self.stdin.write_all(&encoded)?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        Ok(())
    }

    fn read_line_json(&mut self) -> Result<Value, ClientError> {
        let mut line = String::new();
        let bytes = self.stdout.read_line(&mut line)?;
        if bytes == 0 {
            return Err(ClientError::Protocol(
                "server closed stdout before response".to_string(),
            ));
        }
        Ok(serde_json::from_str(line.trim())?)
    }

    fn shutdown(&mut self) {
        if let Err(err) = self.child.kill() {
            eprintln!("warn: failed to stop server process: {err}");
        }
    }
}

fn parse_args() -> Result<AppConfig, ClientError> {
    let mut args = env::args().skip(1);

    let mut cfg = AppConfig {
        server_path: "../../target/release/mcp-netdiag-rs".to_string(),
        question: "network issue".to_string(),
        interface: None,
        target: None,
        json_output: false,
    };

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--server" => cfg.server_path = require_value(&mut args, "--server")?,
            "--question" => cfg.question = require_value(&mut args, "--question")?,
            "--interface" => cfg.interface = Some(require_value(&mut args, "--interface")?),
            "--target" => cfg.target = Some(require_value(&mut args, "--target")?),
            "--json" => cfg.json_output = true,
            _ => {
                return Err(ClientError::Protocol(format!(
                    "unknown argument: {flag}. expected --server/--question/--interface/--target/--json"
                )))
            }
        }
    }

    Ok(cfg)
}

fn require_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, ClientError> {
    args.next()
        .ok_or_else(|| ClientError::Protocol(format!("missing value for {flag}")))
}

fn build_plan(cfg: &AppConfig) -> Vec<PlanStep> {
    let mut steps = Vec::new();
    let question = cfg.question.to_ascii_lowercase();

    let include_l2 = question.contains("link")
        || question.contains("interface")
        || question.contains("mac")
        || question.contains("vlan")
        || question.contains("arp")
        || question.contains("neighbor");

    let include_l3 = question.contains("route")
        || question.contains("gateway")
        || question.contains("reach")
        || question.contains("ping")
        || question.contains("traceroute");

    if include_l2 || (!include_l2 && !include_l3) {
        let mut args = BTreeMap::new();
        if let Some(iface) = &cfg.interface {
            args.insert("interface", json!(iface));
        }
        steps.push(PlanStep {
            tool: "net.if_status",
            args: json!(args),
        });

        let mut n_args = BTreeMap::new();
        if let Some(iface) = &cfg.interface {
            n_args.insert("interface", json!(iface));
        }
        steps.push(PlanStep {
            tool: "net.neighbors",
            args: json!(n_args),
        });
    }

    if question.contains("mac") {
        steps.push(PlanStep {
            tool: "net.mac_lookup",
            args: json!({"mac": "aa:bb:cc:dd:ee:ff"}),
        });
    }

    if include_l3 || (!include_l2 && !include_l3) {
        steps.push(PlanStep {
            tool: "net.routes",
            args: json!({}),
        });
    }

    if let Some(target) = &cfg.target {
        steps.push(PlanStep {
            tool: "net.ping",
            args: json!({"target": target, "count": 3, "timeout_secs": 2}),
        });
        steps.push(PlanStep {
            tool: "net.traceroute",
            args: json!({"target": target, "max_hops": 12}),
        });
    }

    steps.push(PlanStep {
        tool: "net.logs",
        args: json!({"lines": 40}),
    });

    steps
}

fn print_diagnosis(cfg: &AppConfig, outputs: &[(String, Value)]) {
    println!("\nQuestion: {}", cfg.question);
    println!("\nTool Results:");
    for (tool, result) in outputs {
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let signal = result
            .get("signal")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let evidence = result.get("evidence").and_then(Value::as_str).unwrap_or("");
        let suggestion = result
            .get("suggested_action")
            .and_then(Value::as_str)
            .unwrap_or("no suggestion");

        println!("- {tool}: status={status}, signal={signal}");
        if !evidence.is_empty() {
            println!("  evidence: {}", one_line(evidence));
        }
        println!("  action: {suggestion}");
    }

    let failures: Vec<_> = outputs
        .iter()
        .filter(|(_, v)| v.get("status").and_then(Value::as_str) == Some("fail"))
        .collect();

    println!("\nDiagnosis Summary:");
    if failures.is_empty() {
        println!("No direct command failures observed. Continue with deeper path-specific checks.");
    } else {
        let signals: Vec<_> = failures
            .iter()
            .filter_map(|(_, v)| v.get("signal").and_then(Value::as_str))
            .collect();
        println!(
            "Observed {} failing diagnostics: {}",
            failures.len(),
            signals.join(", ")
        );
        println!("Most likely issue domain: {}", infer_domain(&signals));
    }
}

fn print_json_report(
    cfg: &AppConfig,
    outputs: &[(String, Value)],
    tools_count: usize,
) -> Result<(), ClientError> {
    let failures: Vec<_> = outputs
        .iter()
        .filter(|(_, v)| v.get("status").and_then(Value::as_str) == Some("fail"))
        .map(|(tool, value)| {
            json!({
                "tool": tool,
                "signal": value.get("signal").and_then(Value::as_str).unwrap_or("unknown"),
            })
        })
        .collect();

    let signals: Vec<&str> = outputs
        .iter()
        .filter(|(_, v)| v.get("status").and_then(Value::as_str) == Some("fail"))
        .filter_map(|(_, v)| v.get("signal").and_then(Value::as_str))
        .collect();

    let report = json!({
        "question": cfg.question,
        "context": {
            "interface": cfg.interface,
            "target": cfg.target,
        },
        "mcp": {
            "tools_discovered": tools_count,
            "plan_steps": outputs.len(),
        },
        "results": outputs.iter().map(|(tool, value)| {
            json!({
                "tool": tool,
                "status": value.get("status").and_then(Value::as_str).unwrap_or("unknown"),
                "signal": value.get("signal").and_then(Value::as_str).unwrap_or("unknown"),
                "evidence": value.get("evidence").and_then(Value::as_str).unwrap_or(""),
                "suggested_action": value.get("suggested_action").and_then(Value::as_str).unwrap_or(""),
                "raw": value.get("raw").cloned().unwrap_or(Value::Null),
            })
        }).collect::<Vec<Value>>(),
        "diagnosis": {
            "failure_count": failures.len(),
            "failures": failures,
            "likely_domain": infer_domain(&signals),
        }
    });

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn infer_domain(signals: &[&str]) -> &'static str {
    if signals
        .iter()
        .any(|s| s.contains("link") || s.contains("mac") || s.contains("neighbor"))
    {
        "Layer 2 (link/VLAN/neighbor)"
    } else if signals
        .iter()
        .any(|s| s.contains("routing") || s.contains("connectivity") || s.contains("path"))
    {
        "Layer 3 (routing/path/reachability)"
    } else {
        "General diagnostic failure"
    }
}

fn one_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_string()
}

fn normalize_payload(value: Value) -> Value {
    if value.get("status").is_some() {
        return value;
    }
    if let Some(ok) = value.get("ok").and_then(Value::as_bool) {
        let status = if ok { "ok" } else { "fail" };
        return json!({
            "tool": "unknown",
            "status": status,
            "signal": if ok { "command_succeeded" } else { "diagnostic_command_failed" },
            "evidence": value.get("stdout").and_then(Value::as_str).unwrap_or(""),
            "suggested_action": "Legacy response shape detected; consider upgrading server build.",
            "raw": value,
        });
    }
    value
}
