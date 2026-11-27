use crate::json::{base64_decode, parse, Value};
use crate::pathconv::{linux_to_win, win_to_linux};
use crate::wsl::{
    bg_start, capture_result_to_json, kill_linux_pgid_direct, query_status, run_bash_captured,
    run_captured, CaptureRequest, Config,
};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Framing {
    Newline,
    ContentLength,
}

fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<(String, Framing)>> {
    let mut first_line = String::new();
    loop {
        first_line.clear();
        let n = reader.read_line(&mut first_line)?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = first_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.to_ascii_lowercase().starts_with("content-length:") {
            let mut content_len: usize = trimmed["content-length:".len()..]
                .trim()
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Content-Length"))?;
            loop {
                let mut hdr = String::new();
                let hn = reader.read_line(&mut hdr)?;
                if hn == 0 {
                    return Ok(None);
                }
                let ht = hdr.trim();
                if ht.is_empty() {
                    break;
                }
                if ht.to_ascii_lowercase().starts_with("content-length:") {
                    if let Ok(cl) = ht["content-length:".len()..].trim().parse::<usize>() {
                        content_len = cl;
                    }
                }
            }
            let mut buf = vec![0u8; content_len];
            reader.read_exact(&mut buf)?;
            let body = String::from_utf8(buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf8 body"))?;
            return Ok(Some((body, Framing::ContentLength)));
        } else {
            return Ok(Some((trimmed.to_string(), Framing::Newline)));
        }
    }
}

fn send_json(out: &Arc<Mutex<io::Stdout>>, framing: Framing, msg: &Value) {
    let payload = msg.to_json_string();
    if let Ok(mut w) = out.lock() {
        match framing {
            Framing::Newline => {
                let _ = w.write_all(payload.as_bytes());
                let _ = w.write_all(b"\n");
            }
            Framing::ContentLength => {
                let header = format!("Content-Length: {}\r\n\r\n", payload.len());
                let _ = w.write_all(header.as_bytes());
                let _ = w.write_all(payload.as_bytes());
            }
        }
        let _ = w.flush();
    }
}

fn rpc_ok(id: Value, result: Value) -> Value {
    Value::obj(vec![
        ("jsonrpc", Value::Str("2.0".to_string())),
        ("id", id),
        ("result", result),
    ])
}

fn rpc_err(id: Value, code: i64, message: &str) -> Value {
    Value::obj(vec![
        ("jsonrpc", Value::Str("2.0".to_string())),
        ("id", id),
        (
            "error",
            Value::obj(vec![
                ("code", Value::Int(code)),
                ("message", Value::Str(message.to_string())),
            ]),
        ),
    ])
}

fn tool_result(data: Value, is_error: bool) -> Value {
    Value::obj(vec![
        (
            "content",
            Value::Array(vec![Value::obj(vec![
                ("type", Value::Str("text".to_string())),
                ("text", Value::Str(data.to_json_string())),
            ])]),
        ),
        ("isError", Value::Bool(is_error)),
    ])
}

fn schema_prop(ty: &str, desc: &str) -> Value {
    Value::obj(vec![
        ("type", Value::Str(ty.to_string())),
        ("description", Value::Str(desc.to_string())),
    ])
}

fn tools_list_value() -> Value {
    let tools = vec![
        Value::obj(vec![
            ("name", Value::Str("wsl_exec".to_string())),
            (
                "description",
                Value::Str(
                    "Execute a Linux binary directly inside Debian WSL1 (amamiya) with exact argv pass-through (no shell quoting). Supports optional passwordless sudo, cwd, env, stdin, and timeout."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Value::obj(vec![
                    ("type", Value::Str("object".to_string())),
                    (
                        "properties",
                        Value::obj(vec![
                            ("program", schema_prop("string", "Executable name or absolute Linux path (e.g. 'git', '/usr/bin/rg').")),
                            (
                                "args",
                                Value::obj(vec![
                                    ("type", Value::Str("array".to_string())),
                                    ("items", Value::obj(vec![("type", Value::Str("string".to_string()))])),
                                    ("description", Value::Str("Argument array passed verbatim to the executable.".to_string())),
                                ]),
                            ),
                            ("cwd", schema_prop("string", "Optional working directory (Windows C:\\... or Linux /mnt/c/... or /home/...).")),
                            (
                                "env",
                                Value::obj(vec![
                                    ("type", Value::Str("object".to_string())),
                                    ("additionalProperties", Value::obj(vec![("type", Value::Str("string".to_string()))])),
                                    ("description", Value::Str("Optional extra environment variables to pass through.".to_string())),
                                ]),
                            ),
                            ("stdin", schema_prop("string", "Optional UTF-8 text stdin.")),
                            ("stdin_base64", schema_prop("string", "Optional raw binary stdin encoded as Base64.")),
                            ("sudo", schema_prop("boolean", "Run via passwordless sudo as root (default false).")),
                            ("timeout_sec", schema_prop("integer", "Timeout in seconds (default 120).")),
                            ("include_base64", schema_prop("boolean", "Also include lossless stdout_base64/stderr_base64 (default false).")),
                        ]),
                    ),
                    ("required", Value::Array(vec![Value::Str("program".to_string())])),
                ]),
            ),
        ]),
        Value::obj(vec![
            ("name", Value::Str("wsl_bash".to_string())),
            (
                "description",
                Value::Str(
                    "Run a bash command or multi-line script directly in Debian WSL1 (amamiya). Automatically handles long scripts (>24KB), preserves binary/UTF-8 output without BOM/CRLF pollution, and cleans up the Linux process group on timeout/cancellation."
                        .to_string(),
                ),
            ),
            (
                "inputSchema",
                Value::obj(vec![
                    ("type", Value::Str("object".to_string())),
                    (
                        "properties",
                        Value::obj(vec![
                            ("script", schema_prop("string", "Bash command or multi-line script content.")),
                            (
                                "args",
                                Value::obj(vec![
                                    ("type", Value::Str("array".to_string())),
                                    ("items", Value::obj(vec![("type", Value::Str("string".to_string()))])),
                                    ("description", Value::Str("Optional positional arguments ($1, $2, ...).".to_string())),
                                ]),
                            ),
                            ("cwd", schema_prop("string", "Optional working directory (Windows or Linux path).")),
                            (
                                "env",
                                Value::obj(vec![
                                    ("type", Value::Str("object".to_string())),
                                    ("additionalProperties", Value::obj(vec![("type", Value::Str("string".to_string()))])),
                                    ("description", Value::Str("Optional extra environment variables.".to_string())),
                                ]),
                            ),
                            ("stdin", schema_prop("string", "Optional UTF-8 text stdin.")),
                            ("stdin_base64", schema_prop("string", "Optional raw binary stdin encoded as Base64.")),
                            ("login", schema_prop("boolean", "Run bash as a login shell (-l, default false).")),
                            ("sudo", schema_prop("boolean", "Run via passwordless sudo as root (default false).")),
                            ("timeout_sec", schema_prop("integer", "Timeout in seconds (default 120).")),
                            ("include_base64", schema_prop("boolean", "Also include stdout_base64/stderr_base64 (default false).")),
                        ]),
                    ),
                    ("required", Value::Array(vec![Value::Str("script".to_string())])),
                ]),
            ),
        ]),
        Value::obj(vec![
            ("name", Value::Str("wsl_path".to_string())),
            (
                "description",
                Value::Str("Convert paths between Windows (C:\\...) and Debian WSL1 (/mnt/c/... or /c/...).".to_string()),
            ),
            (
                "inputSchema",
                Value::obj(vec![
                    ("type", Value::Str("object".to_string())),
                    (
                        "properties",
                        Value::obj(vec![
                            ("path", schema_prop("string", "Path string to convert.")),
                            ("direction", schema_prop("string", "Conversion direction: 'to_linux', 'to_win', or 'mixed' (default 'to_linux').")),
                        ]),
                    ),
                    ("required", Value::Array(vec![Value::Str("path".to_string())])),
                ]),
            ),
        ]),
        Value::obj(vec![
            ("name", Value::Str("wsl_status".to_string())),
            (
                "description",
                Value::Str("Inspect live Debian WSL1 status, effective user (amamiya), passwordless sudo readiness, kernel, mounts, and available Linux tools.".to_string()),
            ),
            (
                "inputSchema",
                Value::obj(vec![
                    ("type", Value::Str("object".to_string())),
                    ("properties", Value::obj(vec![])),
                ]),
            ),
        ]),
        Value::obj(vec![
            ("name", Value::Str("wsl_bg_start".to_string())),
            (
                "description",
                Value::Str("Start a detached background process inside Debian WSL1 in its own process group (PGID) and return immediately with pid/pgid.".to_string()),
            ),
            (
                "inputSchema",
                Value::obj(vec![
                    ("type", Value::Str("object".to_string())),
                    (
                        "properties",
                        Value::obj(vec![
                            ("program", schema_prop("string", "Executable name or Linux path (e.g. '/usr/bin/python3' or '/usr/bin/bash').")),
                            (
                                "args",
                                Value::obj(vec![
                                    ("type", Value::Str("array".to_string())),
                                    ("items", Value::obj(vec![("type", Value::Str("string".to_string()))])),
                                    ("description", Value::Str("Arguments passed to the executable.".to_string())),
                                ]),
                            ),
                            ("cwd", schema_prop("string", "Optional working directory (Windows or Linux path).")),
                            (
                                "env",
                                Value::obj(vec![
                                    ("type", Value::Str("object".to_string())),
                                    ("additionalProperties", Value::obj(vec![("type", Value::Str("string".to_string()))])),
                                    ("description", Value::Str("Optional extra environment variables.".to_string())),
                                ]),
                            ),
                            ("log_path", schema_prop("string", "Optional log file path for stdout/stderr (defaults to /dev/null).")),
                            ("sudo", schema_prop("boolean", "Run via passwordless sudo (default false).")),
                        ]),
                    ),
                    ("required", Value::Array(vec![Value::Str("program".to_string())])),
                ]),
            ),
        ]),
        Value::obj(vec![
            ("name", Value::Str("wsl_bg_stop".to_string())),
            (
                "description",
                Value::Str("Stop a background process group previously started in Debian WSL1 by its pgid (SIGTERM then SIGKILL).".to_string()),
            ),
            (
                "inputSchema",
                Value::obj(vec![
                    ("type", Value::Str("object".to_string())),
                    (
                        "properties",
                        Value::obj(vec![("pgid", schema_prop("integer", "Linux process group ID returned by wsl_bg_start."))]),
                    ),
                    ("required", Value::Array(vec![Value::Str("pgid".to_string())])),
                ]),
            ),
        ]),
    ];

    Value::obj(vec![("tools", Value::Array(tools))])
}

fn parse_string_array(val: Option<&Value>) -> Vec<String> {
    val.and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_env_object(val: Option<&Value>) -> Vec<(String, String)> {
    val.and_then(|v| v.as_object())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_stdin_bytes(args: &Value) -> Result<Option<Vec<u8>>, String> {
    if let Some(b64) = args.get("stdin_base64").and_then(|v| v.as_str()) {
        return Ok(Some(base64_decode(b64)?));
    }
    if let Some(s) = args.get("stdin").and_then(|v| v.as_str()) {
        return Ok(Some(s.as_bytes().to_vec()));
    }
    Ok(None)
}

fn dispatch_tool(cfg: &Config, name: &str, args: &Value, cancel: Arc<AtomicBool>) -> Value {
    match name {
        "wsl_exec" => {
            let program = match args.get("program").and_then(|v| v.as_str()) {
                Some(p) if !p.is_empty() => p.to_string(),
                _ => {
                    return tool_result(
                        Value::obj(vec![("error", Value::Str("missing required 'program'".to_string()))]),
                        true,
                    );
                }
            };
            let stdin = match parse_stdin_bytes(args) {
                Ok(s) => s,
                Err(e) => {
                    return tool_result(Value::obj(vec![("error", Value::Str(e))]), true);
                }
            };
            let include_b64 = args
                .get("include_base64")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let req = CaptureRequest {
                program,
                args: parse_string_array(args.get("args")),
                cwd: args.get("cwd").and_then(|v| v.as_str()).map(|s| s.to_string()),
                env: parse_env_object(args.get("env")),
                stdin,
                sudo: args.get("sudo").and_then(|v| v.as_bool()).unwrap_or(false),
                timeout_sec: args.get("timeout_sec").and_then(|v| v.as_u64()).unwrap_or(120),
                max_output_bytes: 0,
                cancel: Some(cancel),
            };
            match run_captured(cfg, req) {
                Ok(res) => tool_result(capture_result_to_json(&res, include_b64), false),
                Err(e) => tool_result(Value::obj(vec![("error", Value::Str(e))]), true),
            }
        }
        "wsl_bash" => {
            let script = match args.get("script").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    return tool_result(
                        Value::obj(vec![("error", Value::Str("missing required 'script'".to_string()))]),
                        true,
                    );
                }
            };
            let stdin = match parse_stdin_bytes(args) {
                Ok(s) => s,
                Err(e) => {
                    return tool_result(Value::obj(vec![("error", Value::Str(e))]), true);
                }
            };
            let include_b64 = args
                .get("include_base64")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            match run_bash_captured(
                cfg,
                script,
                parse_string_array(args.get("args")),
                args.get("cwd").and_then(|v| v.as_str()).map(|s| s.to_string()),
                parse_env_object(args.get("env")),
                stdin,
                args.get("login").and_then(|v| v.as_bool()).unwrap_or(false),
                args.get("sudo").and_then(|v| v.as_bool()).unwrap_or(false),
                args.get("timeout_sec").and_then(|v| v.as_u64()).unwrap_or(120),
                0,
                Some(cancel),
            ) {
                Ok(res) => tool_result(capture_result_to_json(&res, include_b64), false),
                Err(e) => tool_result(Value::obj(vec![("error", Value::Str(e))]), true),
            }
        }
        "wsl_path" => {
            let path = match args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => {
                    return tool_result(
                        Value::obj(vec![("error", Value::Str("missing required 'path'".to_string()))]),
                        true,
                    );
                }
            };
            let dir = args
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("to_linux");
            let converted = match dir {
                "to_linux" | "unix" => win_to_linux(path),
                "to_win" | "windows" => linux_to_win(path, false),
                "mixed" => linux_to_win(path, true),
                other => {
                    return tool_result(
                        Value::obj(vec![(
                            "error",
                            Value::Str(format!("unsupported direction '{}'", other)),
                        )]),
                        true,
                    );
                }
            };
            tool_result(
                Value::obj(vec![
                    ("input", Value::Str(path.to_string())),
                    ("direction", Value::Str(dir.to_string())),
                    ("result", Value::Str(converted)),
                ]),
                false,
            )
        }
        "wsl_status" => tool_result(query_status(cfg), false),
        "wsl_bg_start" => {
            let program = match args.get("program").and_then(|v| v.as_str()) {
                Some(p) if !p.is_empty() => p,
                _ => {
                    return tool_result(
                        Value::obj(vec![("error", Value::Str("missing required 'program'".to_string()))]),
                        true,
                    );
                }
            };
            let bg_args = parse_string_array(args.get("args"));
            let cwd = args.get("cwd").and_then(|v| v.as_str());
            let env = parse_env_object(args.get("env"));
            let log_path = args.get("log_path").and_then(|v| v.as_str());
            let sudo = args.get("sudo").and_then(|v| v.as_bool()).unwrap_or(false);
            match bg_start(cfg, program, &bg_args, cwd, &env, log_path, sudo) {
                Ok(v) => tool_result(v, false),
                Err(e) => tool_result(Value::obj(vec![("error", Value::Str(e))]), true),
            }
        }
        "wsl_bg_stop" => {
            let pgid = match args.get("pgid").and_then(|v| v.as_i64()) {
                Some(p) => p,
                None => {
                    return tool_result(
                        Value::obj(vec![("error", Value::Str("missing required integer 'pgid'".to_string()))]),
                        true,
                    );
                }
            };
            match kill_linux_pgid_direct(cfg, pgid) {
                Ok(killed) => tool_result(
                    Value::obj(vec![
                        ("pgid", Value::Int(pgid)),
                        ("stopped", Value::Bool(killed)),
                    ]),
                    false,
                ),
                Err(e) => tool_result(Value::obj(vec![("error", Value::Str(e))]), true),
            }
        }
        other => tool_result(
            Value::obj(vec![("error", Value::Str(format!("unknown tool '{}'", other)))]),
            true,
        ),
    }
}

fn id_key(v: &Value) -> String {
    v.to_json_string()
}

pub fn run_mcp_server(cfg: &Config) -> i32 {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let inflight: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (raw, framing) = match read_message(&mut reader) {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(e) => {
                eprintln!("wsl-bridge mcp: read error: {}", e);
                break;
            }
        };

        let msg = match parse(&raw) {
            Ok(v) => v,
            Err(e) => {
                send_json(&stdout, framing, &rpc_err(Value::Null, -32700, &format!("Parse error: {}", e)));
                continue;
            }
        };

        let method = match msg.get("method").and_then(|v| v.as_str()) {
            Some(m) => m.to_string(),
            None => continue,
        };
        let id = msg.get("id").cloned();
        let params = msg.get("params").cloned().unwrap_or(Value::obj(vec![]));

        match method.as_str() {
            "initialize" => {
                let req_ver = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2025-03-26");
                let res = Value::obj(vec![
                    ("protocolVersion", Value::Str(req_ver.to_string())),
                    (
                        "capabilities",
                        Value::obj(vec![("tools", Value::obj(vec![("listChanged", Value::Bool(false))]))]),
                    ),
                    (
                        "serverInfo",
                        Value::obj(vec![
                            ("name", Value::Str("wsl-bridge".to_string())),
                            ("version", Value::Str(env!("CARGO_PKG_VERSION").to_string())),
                        ]),
                    ),
                ]);
                if let Some(req_id) = id {
                    send_json(&stdout, framing, &rpc_ok(req_id, res));
                }
            }
            "notifications/initialized" => {}
            "notifications/cancelled" => {
                if let Some(req_id) = params.get("requestId") {
                    let key = id_key(req_id);
                    if let Ok(map) = inflight.lock() {
                        if let Some(flag) = map.get(&key) {
                            flag.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }
            "ping" => {
                if let Some(req_id) = id {
                    send_json(&stdout, framing, &rpc_ok(req_id, Value::obj(vec![])));
                }
            }
            "tools/list" => {
                if let Some(req_id) = id {
                    send_json(&stdout, framing, &rpc_ok(req_id, tools_list_value()));
                }
            }
            "tools/call" => {
                let Some(req_id) = id else { continue };
                let tool_name = match params.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n.to_string(),
                    None => {
                        send_json(&stdout, framing, &rpc_err(req_id, -32602, "missing tool name"));
                        continue;
                    }
                };
                let tool_args = params.get("arguments").cloned().unwrap_or(Value::obj(vec![]));
                let cancel = Arc::new(AtomicBool::new(false));
                let key = id_key(&req_id);
                if let Ok(mut map) = inflight.lock() {
                    map.insert(key.clone(), Arc::clone(&cancel));
                }

                let cfg_clone = cfg.clone();
                let out_clone = Arc::clone(&stdout);
                let inflight_clone = Arc::clone(&inflight);
                thread::spawn(move || {
                    let res = dispatch_tool(&cfg_clone, &tool_name, &tool_args, cancel);
                    if let Ok(mut map) = inflight_clone.lock() {
                        map.remove(&key);
                    }
                    send_json(&out_clone, framing, &rpc_ok(req_id, res));
                });
            }
            _ => {
                if let Some(req_id) = id {
                    send_json(
                        &stdout,
                        framing,
                        &rpc_err(req_id, -32601, &format!("Method not found: {}", method)),
                    );
                }
            }
        }
    }

    if let Ok(map) = inflight.lock() {
        for flag in map.values() {
            flag.store(true, Ordering::SeqCst);
        }
    }
    0
}
