use crate::json::{parse, Value};
use crate::pathconv::{is_windows_drive_path, resolve_cwd_for_wsl, win_to_linux};
use crate::win::{ctrl_triggered, install_ctrl_handler, local_data_dir, system_data_dir, user_data_dir};
use crate::wsl::{collect_passthrough_env, CaptureRequest, CaptureResult, Config};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const T_REQ: u8 = 0x01;
const T_STDIN: u8 = 0x02;
const T_STDIN_EOF: u8 = 0x03;
const T_SIGNAL: u8 = 0x04;
const T_BG_START: u8 = 0x05;
const T_BG_STOP: u8 = 0x06;
const T_STATUS: u8 = 0x07;

const T_STARTED: u8 = 0x10;
const T_STDOUT: u8 = 0x11;
const T_STDERR: u8 = 0x12;
const T_EXIT: u8 = 0x13;
const T_JSON_RESP: u8 = 0x14;

const DEFAULT_MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BrokerInfo {
    pub port: u16,
    pub token: String,
    pub distro: String,
    pub user: String,
}

static CACHED_INFO: OnceLock<Mutex<Option<BrokerInfo>>> = OnceLock::new();

pub fn broker_info_path() -> PathBuf {
    local_data_dir().join("broker.json")
}

pub fn broker_disabled() -> bool {
    matches!(
        env::var("WSL_BRIDGE_NO_BROKER").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

fn load_info_from_disk() -> Option<BrokerInfo> {
    let text = fs::read_to_string(system_data_dir().join("broker.json"))
        .or_else(|_| fs::read_to_string(user_data_dir().join("broker.json")))
        .ok()?;
    let v = parse(&text).ok()?;
    let port = v.get("port")?.as_u64()? as u16;
    let token = v.get("token")?.as_str()?.to_string();
    let distro = v.get("distro")?.as_str()?.to_string();
    let user = v.get("user")?.as_str()?.to_string();
    if port == 0 || token.is_empty() {
        return None;
    }
    Some(BrokerInfo {
        port,
        token,
        distro,
        user,
    })
}

fn connect_broker(cfg: &Config) -> Option<(TcpStream, BrokerInfo)> {
    if broker_disabled() {
        return None;
    }
    let cache = CACHED_INFO.get_or_init(|| Mutex::new(None));
    let mut cached = cache.lock().ok().and_then(|g| g.clone());

    for attempt in 0..2 {
        let info = match cached.take() {
            Some(i) if i.distro == cfg.distro && i.user == cfg.user => i,
            _ => {
                if attempt == 1 {
                    return None;
                }
                let fresh = load_info_from_disk()?;
                if fresh.distro != cfg.distro || fresh.user != cfg.user {
                    return None;
                }
                fresh
            }
        };

        let addr = SocketAddr::from(([127, 0, 0, 1], info.port));
        if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(120)) {
            let _ = stream.set_nodelay(true);
            if let Ok(mut g) = cache.lock() {
                *g = Some(info.clone());
            }
            return Some((stream, info));
        }
        // Cache was stale; clear and retry once from disk
        if let Ok(mut g) = cache.lock() {
            *g = None;
        }
    }
    None
}

fn write_frame<W: Write>(w: &mut W, ftype: u8, payload: &[u8]) -> io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = ftype;
    let len_be = (payload.len() as u32).to_be_bytes();
    hdr[1..5].copy_from_slice(&len_be);
    w.write_all(&hdr)?;
    if !payload.is_empty() {
        w.write_all(payload)?;
    }
    w.flush()
}

fn read_frame<R: Read>(r: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr)?;
    let ftype = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload)?;
    }
    Ok((ftype, payload))
}

fn cwd_to_linux(cwd: Option<&str>) -> String {
    match resolve_cwd_for_wsl(cwd) {
        Some(c) if !c.is_empty() => {
            if is_windows_drive_path(&c) {
                win_to_linux(&c)
            } else {
                c
            }
        }
        _ => "/".to_string(),
    }
}

fn build_req_json(
    token: &str,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    extra_env: &[(String, String)],
    sudo: bool,
) -> Value {
    let merged_env = collect_passthrough_env(extra_env);
    let env_entries: Vec<(String, Value)> = merged_env
        .into_iter()
        .map(|(k, v)| (k, Value::Str(v)))
        .collect();
    Value::obj(vec![
        ("token", Value::Str(token.to_string())),
        ("program", Value::Str(program.to_string())),
        (
            "args",
            Value::Array(args.iter().map(|s| Value::Str(s.clone())).collect()),
        ),
        ("cwd", Value::Str(cwd_to_linux(cwd))),
        ("env", Value::Object(env_entries)),
        ("sudo", Value::Bool(sudo)),
    ])
}

/// Fast-path raw binary pass-through for non-TTY CLI calls (`bash.exe`, `sh.exe`, `exec`).
/// Returns `Some(exit_code)` if served by broker, or `None` to fall back to `wsl.exe`.
pub fn try_exec_passthrough(
    cfg: &Config,
    cwd: Option<&str>,
    env_pairs: &[(String, String)],
    sudo: bool,
    program: &str,
    args: &[String],
) -> Option<i32> {
    let (mut stream, info) = connect_broker(cfg)?;
    install_ctrl_handler();

    let req = build_req_json(&info.token, program, args, cwd, env_pairs, sudo);
    if write_frame(&mut stream, T_REQ, req.to_json_string().as_bytes()).is_err() {
        return None;
    }

    let tx = stream.try_clone().ok()?;
    let tx_writer = Arc::new(Mutex::new(stream.try_clone().ok()?));

    // Forward Windows stdin bytes -> broker STDIN frames without blocking process exit
    let tx_in = Arc::clone(&tx_writer);
    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buf = [0u8; 16384];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    if let Ok(mut w) = tx_in.lock() {
                        let _ = write_frame(&mut *w, T_STDIN_EOF, &[]);
                    }
                    break;
                }
                Ok(n) => {
                    if let Ok(mut w) = tx_in.lock() {
                        if write_frame(&mut *w, T_STDIN, &buf[..n]).is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let mut sent_ctrl = false;

    loop {
        if !sent_ctrl && ctrl_triggered() {
            sent_ctrl = true;
            if let Ok(mut w) = tx_writer.lock() {
                let _ = write_frame(&mut *w, T_SIGNAL, &[15u8]);
            }
        }
        match read_frame(&mut stream) {
            Ok((T_STARTED, _)) => continue,
            Ok((T_STDOUT, data)) => {
                let _ = stdout.write_all(&data);
                let _ = stdout.flush();
            }
            Ok((T_STDERR, data)) => {
                let _ = stderr.write_all(&data);
                let _ = stderr.flush();
            }
            Ok((T_EXIT, data)) => {
                let text = String::from_utf8_lossy(&data);
                if let Ok(v) = parse(&text) {
                    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
                        let _ = writeln!(stderr, "wsl-bridge: {}", err);
                    }
                    let rc = v.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(1) as i32;
                    let _ = tx.shutdown(std::net::Shutdown::Both);
                    return Some(if sent_ctrl { 130 } else { rc });
                }
                return Some(1);
            }
            Ok(_) => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => {
                return Some(if sent_ctrl { 130 } else { 1 });
            }
        }
    }
}

/// Fast-path captured execution for MCP (`wsl_exec`, `wsl_bash`).
pub fn try_exec_captured(cfg: &Config, req: &CaptureRequest) -> Option<Result<CaptureResult, String>> {
    let start = Instant::now();
    let (mut stream, info) = connect_broker(cfg)?;
    let max_bytes = if req.max_output_bytes == 0 {
        DEFAULT_MAX_OUTPUT_BYTES
    } else {
        req.max_output_bytes
    };

    let req_json = build_req_json(
        &info.token,
        &req.program,
        &req.args,
        req.cwd.as_deref(),
        &req.env,
        req.sudo,
    );
    if write_frame(&mut stream, T_REQ, req_json.to_json_string().as_bytes()).is_err() {
        return None;
    }

    if let Some(ref data) = req.stdin {
        for chunk in data.chunks(32768) {
            if write_frame(&mut stream, T_STDIN, chunk).is_err() {
                return Some(Err("broker stdin write failed".to_string()));
            }
        }
    }
    if write_frame(&mut stream, T_STDIN_EOF, &[]).is_err() {
        return Some(Err("broker stdin eof failed".to_string()));
    }

    let timeout = if req.timeout_sec == 0 {
        Duration::from_secs(120)
    } else {
        Duration::from_secs(req.timeout_sec)
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(25)));

    let mut out_buf = Vec::new();
    let mut err_buf = Vec::new();
    let mut out_trunc = false;
    let mut err_trunc = false;
    let mut timed_out = false;
    let mut cancelled = false;

    loop {
        if !timed_out && !cancelled {
            if let Some(ref c) = req.cancel {
                if c.load(Ordering::SeqCst) {
                    cancelled = true;
                    let _ = write_frame(&mut stream, T_SIGNAL, &[15u8]);
                }
            }
            if !cancelled && start.elapsed() >= timeout {
                timed_out = true;
                let _ = write_frame(&mut stream, T_SIGNAL, &[15u8]);
            }
        }

        match read_frame(&mut stream) {
            Ok((T_STARTED, _)) => continue,
            Ok((T_STDOUT, data)) => {
                if out_buf.len() < max_bytes {
                    let take = (max_bytes - out_buf.len()).min(data.len());
                    out_buf.extend_from_slice(&data[..take]);
                    if take < data.len() {
                        out_trunc = true;
                    }
                } else {
                    out_trunc = true;
                }
            }
            Ok((T_STDERR, data)) => {
                if err_buf.len() < max_bytes {
                    let take = (max_bytes - err_buf.len()).min(data.len());
                    err_buf.extend_from_slice(&data[..take]);
                    if take < data.len() {
                        err_trunc = true;
                    }
                } else {
                    err_trunc = true;
                }
            }
            Ok((T_EXIT, data)) => {
                let text = String::from_utf8_lossy(&data);
                let mut exit_code = 1;
                if let Ok(v) = parse(&text) {
                    exit_code = v.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(1) as i32;
                    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
                        if err_buf.is_empty() {
                            err_buf.extend_from_slice(err.as_bytes());
                        }
                    }
                }
                if timed_out {
                    exit_code = 124;
                } else if cancelled {
                    exit_code = 130;
                }
                return Some(Ok(CaptureResult {
                    exit_code,
                    stdout: out_buf,
                    stderr: err_buf,
                    stdout_truncated: out_trunc,
                    stderr_truncated: err_trunc,
                    timed_out,
                    cancelled,
                    duration_ms: start.elapsed().as_millis() as u64,
                }));
            }
            Ok(_) => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                if (timed_out || cancelled) && start.elapsed() >= timeout + Duration::from_secs(2) {
                    return Some(Ok(CaptureResult {
                        exit_code: if timed_out { 124 } else { 130 },
                        stdout: out_buf,
                        stderr: err_buf,
                        stdout_truncated: out_trunc,
                        stderr_truncated: err_trunc,
                        timed_out,
                        cancelled,
                        duration_ms: start.elapsed().as_millis() as u64,
                    }));
                }
                continue;
            }
            Err(e) => {
                return Some(Err(format!("broker read error: {}", e)));
            }
        }
    }
}

/// Fast-path MCP proxy over broker TCP loopback.
pub fn try_mcp_proxy(
    cfg: &Config,
    cwd: Option<&str>,
    env_pairs: &[(String, String)],
    program: &str,
    args: &[String],
) -> Option<i32> {
    let (mut stream, info) = connect_broker(cfg)?;
    install_ctrl_handler();

    let req = build_req_json(&info.token, program, args, cwd, env_pairs, false);
    if write_frame(&mut stream, T_REQ, req.to_json_string().as_bytes()).is_err() {
        return None;
    }

    let tx_writer = Arc::new(Mutex::new(stream.try_clone().ok()?));
    let stdin_eof = Arc::new(AtomicBool::new(false));
    let eof_flag = Arc::clone(&stdin_eof);
    let tx_in = Arc::clone(&tx_writer);

    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buf = [0u8; 16384];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    if let Ok(mut w) = tx_in.lock() {
                        let _ = write_frame(&mut *w, T_STDIN_EOF, &[]);
                    }
                    eof_flag.store(true, Ordering::SeqCst);
                    break;
                }
                Ok(n) => {
                    if let Ok(mut w) = tx_in.lock() {
                        if write_frame(&mut *w, T_STDIN, &buf[..n]).is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let _ = stream.set_read_timeout(Some(Duration::from_millis(25)));
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let mut eof_since: Option<Instant> = None;
    let mut sent_sig = false;

    loop {
        if !sent_sig && ctrl_triggered() {
            sent_sig = true;
            if let Ok(mut w) = tx_writer.lock() {
                let _ = write_frame(&mut *w, T_SIGNAL, &[15u8]);
            }
        }
        if !sent_sig && stdin_eof.load(Ordering::SeqCst) {
            let since = *eof_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_millis(1500) {
                sent_sig = true;
                if let Ok(mut w) = tx_writer.lock() {
                    let _ = write_frame(&mut *w, T_SIGNAL, &[15u8]);
                }
            }
        }

        match read_frame(&mut stream) {
            Ok((T_STARTED, _)) => continue,
            Ok((T_STDOUT, data)) => {
                let _ = stdout.write_all(&data);
                let _ = stdout.flush();
            }
            Ok((T_STDERR, data)) => {
                let _ = stderr.write_all(&data);
                let _ = stderr.flush();
            }
            Ok((T_EXIT, data)) => {
                let text = String::from_utf8_lossy(&data);
                let rc = parse(&text)
                    .ok()
                    .and_then(|v| v.get("exit_code").and_then(|x| x.as_i64()))
                    .unwrap_or(0) as i32;
                return Some(rc);
            }
            Ok(_) => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return Some(0),
        }
    }
}

pub fn try_status(cfg: &Config) -> Option<(Value, u64)> {
    let start = Instant::now();
    let (mut stream, info) = connect_broker(cfg)?;
    let req = Value::obj(vec![("token", Value::Str(info.token))]);
    write_frame(&mut stream, T_STATUS, req.to_json_string().as_bytes()).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let (ftype, data) = read_frame(&mut stream).ok()?;
    if ftype != T_JSON_RESP {
        return None;
    }
    let val = parse(&String::from_utf8_lossy(&data)).ok()?;
    Some((val, start.elapsed().as_millis() as u64))
}

pub fn try_bg_start(
    cfg: &Config,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    env_pairs: &[(String, String)],
    log_path: Option<&str>,
    sudo: bool,
) -> Option<Result<Value, String>> {
    let (mut stream, info) = connect_broker(cfg)?;
    let linux_log = match log_path {
        Some(p) if !p.is_empty() => {
            if is_windows_drive_path(p) {
                win_to_linux(p)
            } else {
                p.to_string()
            }
        }
        _ => "/dev/null".to_string(),
    };
    let merged_env = collect_passthrough_env(env_pairs);
    let env_entries: Vec<(String, Value)> = merged_env
        .into_iter()
        .map(|(k, v)| (k, Value::Str(v)))
        .collect();
    let req = Value::obj(vec![
        ("token", Value::Str(info.token)),
        ("program", Value::Str(program.to_string())),
        (
            "args",
            Value::Array(args.iter().map(|s| Value::Str(s.clone())).collect()),
        ),
        ("cwd", Value::Str(cwd_to_linux(cwd))),
        ("env", Value::Object(env_entries)),
        ("log_path", Value::Str(linux_log)),
        ("sudo", Value::Bool(sudo)),
    ]);
    if write_frame(&mut stream, T_BG_START, req.to_json_string().as_bytes()).is_err() {
        return None;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    match read_frame(&mut stream) {
        Ok((T_JSON_RESP, data)) => match parse(&String::from_utf8_lossy(&data)) {
            Ok(v) => {
                if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                    Some(Ok(v))
                } else {
                    let err = v
                        .get("error")
                        .and_then(|e| e.as_str())
                        .unwrap_or("bg_start failed")
                        .to_string();
                    Some(Err(err))
                }
            }
            Err(e) => Some(Err(e)),
        },
        _ => None,
    }
}

pub fn try_bg_stop(cfg: &Config, pgid: i64) -> Option<Result<bool, String>> {
    let (mut stream, info) = connect_broker(cfg)?;
    let req = Value::obj(vec![
        ("token", Value::Str(info.token)),
        ("pgid", Value::Int(pgid)),
    ]);
    if write_frame(&mut stream, T_BG_STOP, req.to_json_string().as_bytes()).is_err() {
        return None;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    match read_frame(&mut stream) {
        Ok((T_JSON_RESP, data)) => match parse(&String::from_utf8_lossy(&data)) {
            Ok(v) => {
                if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                    Some(Ok(v.get("stopped").and_then(|x| x.as_bool()).unwrap_or(false)))
                } else {
                    let err = v
                        .get("error")
                        .and_then(|e| e.as_str())
                        .unwrap_or("bg_stop failed")
                        .to_string();
                    Some(Err(err))
                }
            }
            Err(e) => Some(Err(e)),
        },
        _ => None,
    }
}
