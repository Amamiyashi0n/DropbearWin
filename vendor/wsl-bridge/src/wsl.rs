use crate::broker_client;
use crate::json::{base64_encode, Value};
use crate::pathconv::{is_windows_drive_path, resolve_cwd_for_wsl, win_to_linux};
use crate::win::{
    is_console_tty, random_token_hex,
    ctrl_triggered, install_ctrl_handler, kill_pid, local_data_dir, process_alive,
    process_priority_name, set_current_high_priority, spawn_detached_no_inherit, wait_child_ms,
    NamedMutex, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, HIGH_PRIORITY_CLASS,
};
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const WSL_EXE: &str = r"C:\Windows\System32\wsl.exe";
const LARGE_SCRIPT_THRESHOLD: usize = 20 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const PERL_B64_EXEC: &str = "use MIME::Base64; exec map { decode_base64($_) } @ARGV";
const EMBEDDED_BROKER_PY: &str = include_str!("broker.py");

static SEQ_COUNTER: AtomicU64 = AtomicU64::new(1);
static BASE_WSLENV_CACHE: OnceLock<Vec<String>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct Config {
    pub distro: String,
    pub user: String,
}

impl Config {
    pub fn from_env() -> Self {
        let distro = env::var("WSL_BRIDGE_DISTRO")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Debian".to_string());
        let user = env::var("WSL_BRIDGE_USER")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "amamiya".to_string());
        Self { distro, user }
    }
}

fn next_unique_tag() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}", std::process::id(), ts, seq)
}

fn has_non_ascii(program: &str, args: &[String]) -> bool {
    !program.is_ascii() || args.iter().any(|a| !a.is_ascii())
}

pub fn push_utf8_safe_exec(cmd: &mut Command, program: &str, args: &[String]) {
    if has_non_ascii(program, args) {
        cmd.args(["/usr/bin/perl", "-e", PERL_B64_EXEC, "--"]);
        cmd.arg(base64_encode(program.as_bytes()));
        for a in args {
            cmd.arg(base64_encode(a.as_bytes()));
        }
    } else {
        cmd.arg(program);
        cmd.args(args);
    }
}

fn is_transient_wsl_com_error(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> bool {
    exit_code == -1
        || (exit_code == 1 && stderr.is_empty() && stdout.len() >= 4 && stdout.contains(&0u8))
}

fn is_safe_passthrough_var(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "PATH"
            | "PATHEXT"
            | "HOME"
            | "USERPROFILE"
            | "HOMEDRIVE"
            | "HOMEPATH"
            | "TEMP"
            | "TMP"
            | "COMSPEC"
            | "SYSTEMROOT"
            | "WINDIR"
            | "WSLENV"
            | "PWD"
            | "OLDPWD"
            | "SHELL"
            | "USER"
            | "LOGNAME"
            | "USERNAME"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "PROGRAMFILES"
            | "PROGRAMFILES(X86)"
            | "PROGRAMDATA"
            | "OS"
    ) {
        return false;
    }
    if matches!(
        upper.as_str(),
        "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "NO_PROXY"
            | "ALL_PROXY"
            | "TERM"
            | "COLORTERM"
            | "CI"
            | "NO_COLOR"
            | "FORCE_COLOR"
            | "CLICOLOR"
            | "CLICOLOR_FORCE"
            | "LANG"
            | "LC_ALL"
            | "TZ"
            | "EDITOR"
            | "VISUAL"
            | "PAGER"
            | "NODE_ENV"
            | "RUST_LOG"
            | "RUST_BACKTRACE"
    ) {
        return true;
    }
    const PREFIXES: &[&str] = &[
        "GIT_",
        "CLAUDE_",
        "CODEX_",
        "ZCODE_",
        "ANTHROPIC_",
        "OPENAI_",
        "GEMINI_",
        "AGY_",
        "CURSOR_",
        "OPENCODE_",
        "GH_",
        "GITHUB_",
        "CARGO_",
        "PIP_",
        "UV_",
        "NPM_CONFIG_",
    ];
    PREFIXES.iter().any(|p| upper.starts_with(p))
}

fn cached_base_wslenv_entries() -> &'static [String] {
    BASE_WSLENV_CACHE
        .get_or_init(|| {
            let mut keys: BTreeSet<String> = BTreeSet::new();
            if let Ok(existing) = env::var("WSLENV") {
                for part in existing.split(':') {
                    let trimmed = part.trim();
                    if !trimmed.is_empty() {
                        keys.insert(trimmed.to_string());
                    }
                }
            }
            for (k, _) in env::vars() {
                if is_safe_passthrough_var(&k) {
                    keys.insert(format!("{}/u", k));
                }
            }
            if let Ok(custom) = env::var("WSL_BRIDGE_ENV_PASSTHROUGH") {
                for part in custom.split(|c| c == ',' || c == ';' || c == ':') {
                    let k = part.trim();
                    if !k.is_empty() && env::var_os(k).is_some() {
                        keys.insert(format!("{}/u", k));
                    }
                }
            }
            keys.into_iter().collect()
        })
        .as_slice()
}

pub fn build_wslenv(extra_keys: &[String]) -> String {
    let base = cached_base_wslenv_entries();
    if extra_keys.is_empty() {
        return base.join(":");
    }
    let mut keys: BTreeSet<String> = base.iter().cloned().collect();
    for k in extra_keys {
        if !k.is_empty() && k != "WSLENV" {
            keys.insert(format!("{}/u", k));
        }
    }
    keys.into_iter().collect::<Vec<_>>().join(":")
}


pub fn collect_passthrough_env(extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in env::vars() {
        if is_safe_passthrough_var(&k) {
            map.insert(k, v);
        }
    }
    if let Ok(custom) = env::var("WSL_BRIDGE_ENV_PASSTHROUGH") {
        for part in custom.split(|c| c == ',' || c == ';' || c == ':') {
            let k = part.trim();
            if !k.is_empty() {
                if let Ok(v) = env::var(k) {
                    map.insert(k.to_string(), v);
                }
            }
        }
    }
    for (k, v) in extra {
        if !k.is_empty() && k != "WSLENV" {
            map.insert(k.clone(), v.clone());
        }
    }
    map.into_iter().collect()
}

struct TempScriptGuard {
    win_path: PathBuf,
    linux_path: String,
}

impl TempScriptGuard {
    fn create(script: &str) -> Result<Self, String> {
        let dir = local_data_dir().join("tmp");
        fs::create_dir_all(&dir).map_err(|e| format!("create tmp dir failed: {}", e))?;
        let file_name = format!("cmd-{}.sh", next_unique_tag());
        let win_path = dir.join(file_name);
        fs::write(&win_path, script.as_bytes())
            .map_err(|e| format!("write temp script failed: {}", e))?;
        let linux_path = win_to_linux(&win_path.to_string_lossy());
        Ok(Self {
            win_path,
            linux_path,
        })
    }
}

impl Drop for TempScriptGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.win_path);
    }
}

pub fn kill_linux_pgid(cfg: &Config, pgid_file: &str) {
    let kill_script = r#"p=$(cat "$1" 2>/dev/null || true); rm -f "$1"; if [ -n "$p" ]; then /bin/kill -TERM -"$p" "$p" 2>/dev/null || true; sleep 0.2; /bin/kill -KILL -"$p" "$p" 2>/dev/null || true; fi"#;
    let _ = Command::new(WSL_EXE)
        .args([
            "-d",
            &cfg.distro,
            "-u",
            &cfg.user,
            "--exec",
            "/bin/sh",
            "-c",
            kill_script,
            "_",
            pgid_file,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

pub fn kill_linux_pgid_direct(cfg: &Config, pgid: i64) -> Result<bool, String> {
    if pgid <= 1 {
        return Err("invalid pgid".to_string());
    }
    if let Some(res) = broker_client::try_bg_stop(cfg, pgid) {
        return res;
    }
    let script = r#"p="$1"; if /bin/kill -0 -"$p" 2>/dev/null || /bin/kill -0 "$p" 2>/dev/null; then /bin/kill -TERM -"$p" "$p" 2>/dev/null || true; sleep 0.25; /bin/kill -KILL -"$p" "$p" 2>/dev/null || true; echo KILLED; else echo NOT_FOUND; fi"#;
    let out = Command::new(WSL_EXE)
        .args([
            "-d",
            &cfg.distro,
            "-u",
            &cfg.user,
            "--exec",
            "/bin/sh",
            "-c",
            script,
            "_",
            &pgid.to_string(),
        ])
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("failed to spawn wsl.exe: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout.contains("KILLED"))
}

pub fn run_shell_passthrough(cfg: &Config, shell_path: &str, args: &[String]) -> i32 {
    if !is_console_tty() {
        // Convert leading Windows drive script path argument (e.g. bash C:\path\script.sh)
        let mut broker_args: Vec<String> = Vec::with_capacity(args.len());
        let mut saw_c_or_dash = false;
        let mut converted = false;
        for a in args {
            if !saw_c_or_dash && !converted {
                if a == "--" || a == "-c" || a == "-s" || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('c')) {
                    saw_c_or_dash = true;
                } else if !a.starts_with('-') {
                    converted = true;
                    if is_windows_drive_path(a) {
                        broker_args.push(win_to_linux(a));
                        continue;
                    }
                }
            }
            broker_args.push(a.clone());
        }
        if let Some(rc) = broker_client::try_exec_passthrough(cfg, None, &[], false, shell_path, &broker_args) {
            return rc;
        }
    }
    install_ctrl_handler();
    let mut staged_script: Option<TempScriptGuard> = None;
    let mut forwarded: Vec<String> = Vec::with_capacity(args.len() + 2);

    let mut i = 0usize;
    let mut saw_c = false;
    let mut saw_double_dash = false;
    let mut converted_script_file = false;

    while i < args.len() {
        let a = &args[i];
        if !saw_c && !saw_double_dash && !converted_script_file {
            if a == "--" {
                saw_double_dash = true;
                forwarded.push(a.clone());
                i += 1;
                continue;
            }
            if a == "-c"
                || (a.starts_with('-')
                    && !a.starts_with("--")
                    && a[1..].contains('c')
                    && a[1..].chars().all(|c| c.is_ascii_alphabetic()))
            {
                saw_c = true;
                if i + 1 < args.len() {
                    let script = &args[i + 1];
                    if script.len() > LARGE_SCRIPT_THRESHOLD {
                        match TempScriptGuard::create(script) {
                            Ok(guard) => {
                                let flag_without_c: String = a.chars().filter(|&c| c != 'c').collect();
                                if flag_without_c.len() > 1 {
                                    forwarded.push(flag_without_c);
                                }
                                forwarded.push(guard.linux_path.clone());
                                staged_script = Some(guard);
                                if i + 2 < args.len() {
                                    forwarded.extend_from_slice(&args[i + 3..]);
                                }
                                break;
                            }
                            Err(e) => {
                                eprintln!("wsl-bridge: {}", e);
                                return 1;
                            }
                        }
                    } else {
                        forwarded.push(a.clone());
                        forwarded.push(script.clone());
                        i += 2;
                        continue;
                    }
                } else {
                    forwarded.push(a.clone());
                    i += 1;
                    continue;
                }
            } else if a == "-s" {
                forwarded.push(a.clone());
                forwarded.extend_from_slice(&args[i + 1..]);
                break;
            } else if !a.starts_with('-') {
                converted_script_file = true;
                if is_windows_drive_path(a) {
                    forwarded.push(win_to_linux(a));
                } else {
                    forwarded.push(a.clone());
                }
                i += 1;
                continue;
            }
        }
        forwarded.push(a.clone());
        i += 1;
    }

    let mut cmd = Command::new(WSL_EXE);
    cmd.args(["-d", &cfg.distro, "-u", &cfg.user]);
    if let Some(cwd) = resolve_cwd_for_wsl(None) {
        cmd.args(["--cd", &cwd]);
    }
    cmd.arg("--exec");
    push_utf8_safe_exec(&mut cmd, shell_path, &forwarded);

    let wslenv = build_wslenv(&[]);
    if !wslenv.is_empty() {
        cmd.env("WSLENV", wslenv);
    }

    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wsl-bridge: failed to spawn wsl.exe: {}", e);
            return 127;
        }
    };

    let code = loop {
        if wait_child_ms(&child, 25) {
            break child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
        }
        if ctrl_triggered() {
            let _ = child.kill();
            let _ = child.wait();
            break 130;
        }
    };
    drop(staged_script);
    code
}

pub fn run_exec_passthrough(
    cfg: &Config,
    cwd: Option<&str>,
    env_pairs: &[(String, String)],
    sudo: bool,
    program: &str,
    args: &[String],
) -> i32 {
    if !is_console_tty() {
        if let Some(rc) = broker_client::try_exec_passthrough(cfg, cwd, env_pairs, sudo, program, args) {
            return rc;
        }
    }
    install_ctrl_handler();
    let mut cmd = Command::new(WSL_EXE);
    cmd.args(["-d", &cfg.distro, "-u", &cfg.user]);
    if let Some(c) = resolve_cwd_for_wsl(cwd) {
        cmd.args(["--cd", &c]);
    }
    cmd.arg("--exec");

    let extra_keys: Vec<String> = env_pairs.iter().map(|(k, _)| k.clone()).collect();
    let mut target_prog = program.to_string();
    let mut target_args: Vec<String> = args.to_vec();
    if sudo {
        let mut sudo_args: Vec<String> = vec!["-n".to_string()];
        if !env_pairs.is_empty() {
            sudo_args.push("/usr/bin/env".to_string());
            for (k, v) in env_pairs {
                sudo_args.push(format!("{}={}", k, v));
            }
        }
        sudo_args.push(target_prog);
        sudo_args.extend(target_args);
        target_prog = "/usr/bin/sudo".to_string();
        target_args = sudo_args;
    } else {
        for (k, v) in env_pairs {
            cmd.env(k, v);
        }
    }
    push_utf8_safe_exec(&mut cmd, &target_prog, &target_args);

    let wslenv = build_wslenv(&extra_keys);
    if !wslenv.is_empty() {
        cmd.env("WSLENV", wslenv);
    }

    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wsl-bridge: failed to spawn wsl.exe: {}", e);
            return 127;
        }
    };

    loop {
        if wait_child_ms(&child, 25) {
            return child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
        }
        if ctrl_triggered() {
            let _ = child.kill();
            let _ = child.wait();
            return 130;
        }
    }
}

pub struct CaptureRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub stdin: Option<Vec<u8>>,
    pub sudo: bool,
    pub timeout_sec: u64,
    pub max_output_bytes: usize,
    pub cancel: Option<Arc<AtomicBool>>,
}

pub struct CaptureResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    pub duration_ms: u64,
}

fn read_capped<R: Read>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 16384];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = (cap - buf.len()).min(n);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (buf, truncated)
}

fn run_captured_once(cfg: &Config, req: &CaptureRequest) -> Result<CaptureResult, String> {
    let start = Instant::now();
    let pgid_file = format!("/tmp/wslb-pgid-{}", next_unique_tag());
    let max_bytes = if req.max_output_bytes == 0 {
        DEFAULT_MAX_OUTPUT_BYTES
    } else {
        req.max_output_bytes
    };

    let mut cmd = Command::new(WSL_EXE);
    cmd.args(["-d", &cfg.distro, "-u", &cfg.user]);
    if let Some(c) = resolve_cwd_for_wsl(req.cwd.as_deref()) {
        cmd.args(["--cd", &c]);
    }

    // Minimal-fork PGID supervisor: 1 setsid + 1 dash wrapper (saves an extra fork per call).
    let wrapper = r#"pf="$1"; shift; echo $$ > "$pf"; "$@"; rc=$?; rm -f "$pf"; exit $rc"#;
    cmd.args(["--exec", "/usr/bin/setsid", "-w", "/bin/sh", "-c", wrapper, "_", &pgid_file]);

    let extra_keys: Vec<String> = req.env.iter().map(|(k, _)| k.clone()).collect();
    let mut target_prog = req.program.clone();
    let mut target_args = req.args.clone();
    if req.sudo {
        let mut sudo_args = vec!["-n".to_string()];
        if !req.env.is_empty() {
            sudo_args.push("/usr/bin/env".to_string());
            for (k, v) in &req.env {
                sudo_args.push(format!("{}={}", k, v));
            }
        }
        sudo_args.push(target_prog);
        sudo_args.extend(target_args);
        target_prog = "/usr/bin/sudo".to_string();
        target_args = sudo_args;
    } else {
        for (k, v) in &req.env {
            cmd.env(k, v);
        }
    }
    push_utf8_safe_exec(&mut cmd, &target_prog, &target_args);

    let wslenv = build_wslenv(&extra_keys);
    if !wslenv.is_empty() {
        cmd.env("WSLENV", wslenv);
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn wsl.exe: {}", e))?;

    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take().ok_or("missing child stdout")?;
    let child_stderr = child.stderr.take().ok_or("missing child stderr")?;

    let stdin_data = req.stdin.clone();
    let stdin_handle = thread::spawn(move || {
        if let (Some(mut writer), Some(data)) = (child_stdin, stdin_data) {
            let _ = writer.write_all(&data);
            let _ = writer.flush();
        }
    });

    let stdout_handle = thread::spawn(move || read_capped(child_stdout, max_bytes));
    let stderr_handle = thread::spawn(move || read_capped(child_stderr, max_bytes));

    let timeout = if req.timeout_sec == 0 {
        Duration::from_secs(120)
    } else {
        Duration::from_secs(req.timeout_sec)
    };

    let mut timed_out = false;
    let mut cancelled = false;
    let exit_code = loop {
        if wait_child_ms(&child, 25) {
            break child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
        }
        if let Some(ref c) = req.cancel {
            if c.load(Ordering::SeqCst) {
                cancelled = true;
                kill_linux_pgid(cfg, &pgid_file);
                let _ = child.kill();
                let _ = child.wait();
                break 130;
            }
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            kill_linux_pgid(cfg, &pgid_file);
            let _ = child.kill();
            let _ = child.wait();
            break 124;
        }
    };

    let _ = stdin_handle.join();
    let (stdout, stdout_truncated) = stdout_handle.join().unwrap_or_else(|_| (Vec::new(), false));
    let (stderr, stderr_truncated) = stderr_handle.join().unwrap_or_else(|_| (Vec::new(), false));

    Ok(CaptureResult {
        exit_code,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
        cancelled,
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

pub fn run_captured(cfg: &Config, req: CaptureRequest) -> Result<CaptureResult, String> {
    if let Some(res) = broker_client::try_exec_captured(cfg, &req) {
        return res;
    }
    let first = run_captured_once(cfg, &req)?;
    if !first.timed_out
        && !first.cancelled
        && is_transient_wsl_com_error(first.exit_code, &first.stdout, &first.stderr)
    {
        thread::sleep(Duration::from_millis(120));
        return run_captured_once(cfg, &req);
    }
    Ok(first)
}

pub fn run_bash_captured(
    cfg: &Config,
    script: &str,
    args: Vec<String>,
    cwd: Option<String>,
    env: Vec<(String, String)>,
    stdin: Option<Vec<u8>>,
    login: bool,
    sudo: bool,
    timeout_sec: u64,
    max_output_bytes: usize,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<CaptureResult, String> {
    if !broker_client::broker_disabled() && broker_client::broker_info_path().exists() {
        let mut fast_args: Vec<String> = Vec::new();
        if login {
            fast_args.push("-l".to_string());
        }
        fast_args.push("-c".to_string());
        fast_args.push(script.to_string());
        if !args.is_empty() {
            fast_args.push("bash".to_string());
            fast_args.extend(args.clone());
        }
        let fast_req = CaptureRequest {
            program: "/usr/bin/bash".to_string(),
            args: fast_args,
            cwd: cwd.clone(),
            env: env.clone(),
            stdin: stdin.clone(),
            sudo,
            timeout_sec,
            max_output_bytes,
            cancel: cancel.clone(),
        };
        if let Some(res) = broker_client::try_exec_captured(cfg, &fast_req) {
            return res;
        }
    }
    let mut bash_args: Vec<String> = Vec::new();
    if login {
        bash_args.push("-l".to_string());
    }
    let _staged: Option<TempScriptGuard>;
    if script.len() > LARGE_SCRIPT_THRESHOLD {
        let guard = TempScriptGuard::create(script)?;
        bash_args.push(guard.linux_path.clone());
        bash_args.extend(args);
        _staged = Some(guard);
    } else {
        bash_args.push("-c".to_string());
        bash_args.push(script.to_string());
        if !args.is_empty() {
            bash_args.push("bash".to_string());
            bash_args.extend(args);
        }
        _staged = None;
    }

    run_captured(
        cfg,
        CaptureRequest {
            program: "/usr/bin/bash".to_string(),
            args: bash_args,
            cwd,
            env,
            stdin,
            sudo,
            timeout_sec,
            max_output_bytes,
            cancel,
        },
    )
}

fn keepalive_pid_path() -> PathBuf {
    local_data_dir().join("keepalive.pid")
}

fn daemon_pid_path() -> PathBuf {
    local_data_dir().join("daemon.pid")
}

fn daemon_log_path() -> PathBuf {
    local_data_dir().join("daemon.log")
}

fn append_daemon_log(msg: &str) {
    let dir = local_data_dir();
    let _ = fs::create_dir_all(&dir);
    let path = daemon_log_path();
    // Keep log file bounded (< 256KB)
    if let Ok(meta) = fs::metadata(&path) {
        if meta.len() > 256 * 1024 {
            let _ = fs::write(&path, b"");
        }
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{}] {}", ts, msg);
    }
}

pub fn daemon_status() -> (bool, Option<u32>, Option<&'static str>) {
    let p = daemon_pid_path();
    if let Ok(text) = fs::read_to_string(&p) {
        if let Ok(pid) = text.trim().parse::<u32>() {
            if process_alive(pid) {
                return (true, Some(pid), process_priority_name(pid));
            }
        }
    }
    (false, None, None)
}

/// High-priority boot-time & always-on supervisor daemon for Debian WSL1.
/// Runs with HIGH_PRIORITY_CLASS, holds single-instance mutex, and supervises
/// a warm WSL1 sleep process with 0% idle CPU via WaitForSingleObject.
pub fn run_daemon(cfg: &Config) -> i32 {
    install_ctrl_handler();
    let high_ok = set_current_high_priority();

    let mutex_name = format!("Global\\WslBridgeDaemon-{}", cfg.distro);
    let _guard = match NamedMutex::try_acquire(&mutex_name) {
        Ok(Some(g)) => g,
        Ok(None) => {
            append_daemon_log("daemon already running; exiting duplicate instance");
            return 0;
        }
        Err(_) => {
            // Fallback to Local namespace if Global creation is denied
            let local_name = format!("Local\\WslBridgeDaemon-{}", cfg.distro);
            match NamedMutex::try_acquire(&local_name) {
                Ok(Some(g)) => g,
                Ok(None) => return 0,
                Err(e) => {
                    append_daemon_log(&format!("mutex error: {}", e));
                    return 1;
                }
            }
        }
    };

    let dir = local_data_dir();
    let _ = fs::create_dir_all(&dir);
    let my_pid = std::process::id();
    let _ = fs::write(daemon_pid_path(), my_pid.to_string());
    append_daemon_log(&format!(
        "daemon started pid={} high_priority={} distro={} user={}",
        my_pid, high_ok, cfg.distro, cfg.user
    ));

    let broker_py_win = dir.join("broker.py");
    let _ = fs::write(&broker_py_win, EMBEDDED_BROKER_PY.as_bytes());
    let broker_py_linux = win_to_linux(&broker_py_win.to_string_lossy());
    let broker_info_win = broker_client::broker_info_path();
    let broker_info_linux = win_to_linux(&broker_info_win.to_string_lossy());

    let mut backoff_sec: u64 = 2;
    while !ctrl_triggered() {
        let token = random_token_hex();
        let _ = fs::remove_file(&broker_info_win);
        let mut child = match Command::new(WSL_EXE)
            .args([
                "-d",
                &cfg.distro,
                "-u",
                &cfg.user,
                "--exec",
                "/usr/bin/python3",
                "-u",
                &broker_py_linux,
                "--info-file",
                &broker_info_linux,
                "--distro",
                &cfg.distro,
            ])
            .env("WSL_BRIDGE_BROKER_TOKEN", &token)
            .env("WSLENV", "WSL_BRIDGE_BROKER_TOKEN/u")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | HIGH_PRIORITY_CLASS)
            .spawn()
        {
            Ok(c) => {
                append_daemon_log(&format!(
                    "supervised wsl keepalive started child_pid={}",
                    c.id()
                ));
                c
            }
            Err(e) => {
                append_daemon_log(&format!(
                    "failed to spawn wsl keepalive: {} (retry in {}s)",
                    e, backoff_sec
                ));
                for _ in 0..(backoff_sec * 10) {
                    if ctrl_triggered() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                backoff_sec = (backoff_sec * 2).min(15);
                continue;
            }
        };

        let started_at = Instant::now();
        loop {
            if wait_child_ms(&child, 500) {
                let code = child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
                append_daemon_log(&format!(
                    "wsl keepalive exited rc={} after {}s",
                    code,
                    started_at.elapsed().as_secs()
                ));
                break;
            }
            if ctrl_triggered() {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }

        if ctrl_triggered() {
            break;
        }
        if started_at.elapsed() >= Duration::from_secs(30) {
            backoff_sec = 2;
        }
        for _ in 0..(backoff_sec * 10) {
            if ctrl_triggered() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        backoff_sec = (backoff_sec * 2).min(15);
    }

    let _ = fs::remove_file(daemon_pid_path());
    let _ = fs::remove_file(&broker_info_win);
    append_daemon_log("daemon stopped cleanly");
    0
}

pub fn keepalive_status() -> (bool, Option<u32>) {
    let p = keepalive_pid_path();
    if let Ok(text) = fs::read_to_string(&p) {
        if let Ok(pid) = text.trim().parse::<u32>() {
            if process_alive(pid) {
                return (true, Some(pid));
            }
        }
    }
    (false, None)
}

pub fn keepalive_start(cfg: &Config) -> Result<u32, String> {
    if let (true, Some(pid)) = keepalive_status() {
        return Ok(pid);
    }
    let dir = local_data_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("create data dir failed: {}", e))?;
    let pid = spawn_detached_no_inherit(
        WSL_EXE,
        &["-d", &cfg.distro, "-u", &cfg.user, "--exec", "/bin/sleep", "infinity"],
        true,
    )?;
    fs::write(keepalive_pid_path(), pid.to_string())
        .map_err(|e| format!("write keepalive pid failed: {}", e))?;
    Ok(pid)
}

pub fn keepalive_stop() -> bool {
    let (alive, pid_opt) = keepalive_status();
    let _ = fs::remove_file(keepalive_pid_path());
    if alive {
        if let Some(pid) = pid_opt {
            return kill_pid(pid);
        }
    }
    false
}

pub fn query_status(cfg: &Config) -> Value {
    let probe_script = r#"
printf 'USER=%s\n' "$(whoami 2>/dev/null || true)"
printf 'UID=%s\n' "$(id -u 2>/dev/null || true)"
printf 'HOME=%s\n' "$HOME"
printf 'KERNEL=%s\n' "$(uname -a 2>/dev/null || true)"
printf 'OS=%s\n' "$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || true)"
if sudo -n id -u >/dev/null 2>&1; then printf 'SUDO_NOPASSWD=true\n'; else printf 'SUDO_NOPASSWD=false\n'; fi
for t in bash sh sudo git rg fd jq python3 curl ssh tar make gcc node; do
  p=$(command -v "$t" 2>/dev/null || true)
  [ -n "$p" ] && printf 'TOOL:%s=%s\n' "$t" "$p"
done
for d in /mnt/[a-z]; do
  [ -d "$d" ] && printf 'MOUNT=%s\n' "$d"
done
"#;

    let (ka_running, ka_pid) = keepalive_status();
    let (dm_running, dm_pid, dm_prio) = daemon_status();
    if let Some((bval, ms)) = broker_client::try_status(cfg) {
        return Value::obj(vec![
            ("ok", Value::Bool(bval.get("ok").and_then(|v| v.as_bool()).unwrap_or(true))),
            ("version", Value::Str(env!("CARGO_PKG_VERSION").to_string())),
            ("transport", Value::Str("broker".to_string())),
            ("distro", Value::Str(cfg.distro.clone())),
            ("configured_user", Value::Str(cfg.user.clone())),
            ("effective_user", bval.get("effective_user").cloned().unwrap_or(Value::Str(String::new()))),
            ("uid", bval.get("uid").cloned().unwrap_or(Value::Str(String::new()))),
            ("home", bval.get("home").cloned().unwrap_or(Value::Str(String::new()))),
            ("sudo_nopasswd", bval.get("sudo_nopasswd").cloned().unwrap_or(Value::Bool(false))),
            ("os", bval.get("os").cloned().unwrap_or(Value::Str(String::new()))),
            ("kernel", bval.get("kernel").cloned().unwrap_or(Value::Str(String::new()))),
            ("mounts", bval.get("mounts").cloned().unwrap_or(Value::Array(vec![]))),
            ("tools", bval.get("tools").cloned().unwrap_or(Value::obj(vec![]))),
            ("broker_active", Value::Bool(true)),
            ("daemon_running", Value::Bool(dm_running)),
            ("daemon_pid", dm_pid.map(|p| Value::Int(p as i64)).unwrap_or(Value::Null)),
            ("daemon_priority", dm_prio.map(|s| Value::Str(s.to_string())).unwrap_or(Value::Null)),
            ("keepalive_running", Value::Bool(ka_running)),
            ("keepalive_pid", ka_pid.map(|p| Value::Int(p as i64)).unwrap_or(Value::Null)),
            ("probe_duration_ms", Value::Int(ms as i64)),
        ]);
    }
    match run_bash_captured(
        cfg,
        probe_script,
        Vec::new(),
        None,
        Vec::new(),
        None,
        false,
        false,
        15,
        256 * 1024,
        None,
    ) {
        Ok(res) => {
            let text = String::from_utf8_lossy(&res.stdout);
            let mut user = String::new();
            let mut uid = String::new();
            let mut home = String::new();
            let mut kernel = String::new();
            let mut os_name = String::new();
            let mut sudo_ok = false;
            let mut tools: Vec<(String, Value)> = Vec::new();
            let mut mounts: Vec<Value> = Vec::new();

            for line in text.lines() {
                if let Some(v) = line.strip_prefix("USER=") {
                    user = v.to_string();
                } else if let Some(v) = line.strip_prefix("UID=") {
                    uid = v.to_string();
                } else if let Some(v) = line.strip_prefix("HOME=") {
                    home = v.to_string();
                } else if let Some(v) = line.strip_prefix("KERNEL=") {
                    kernel = v.to_string();
                } else if let Some(v) = line.strip_prefix("OS=") {
                    os_name = v.to_string();
                } else if let Some(v) = line.strip_prefix("SUDO_NOPASSWD=") {
                    sudo_ok = v == "true";
                } else if let Some(rest) = line.strip_prefix("TOOL:") {
                    if let Some((k, v)) = rest.split_once('=') {
                        tools.push((k.to_string(), Value::Str(v.to_string())));
                    }
                } else if let Some(v) = line.strip_prefix("MOUNT=") {
                    mounts.push(Value::Str(v.to_string()));
                }
            }

            Value::obj(vec![
                ("ok", Value::Bool(res.exit_code == 0)),
                ("version", Value::Str(env!("CARGO_PKG_VERSION").to_string())),
                ("distro", Value::Str(cfg.distro.clone())),
                ("configured_user", Value::Str(cfg.user.clone())),
                ("effective_user", Value::Str(user)),
                ("uid", Value::Str(uid)),
                ("home", Value::Str(home)),
                ("sudo_nopasswd", Value::Bool(sudo_ok)),
                ("os", Value::Str(os_name)),
                ("kernel", Value::Str(kernel)),
                ("mounts", Value::Array(mounts)),
                ("tools", Value::Object(tools)),
                ("daemon_running", Value::Bool(dm_running)),
                (
                    "daemon_pid",
                    dm_pid.map(|p| Value::Int(p as i64)).unwrap_or(Value::Null),
                ),
                (
                    "daemon_priority",
                    dm_prio.map(|s| Value::Str(s.to_string())).unwrap_or(Value::Null),
                ),
                ("keepalive_running", Value::Bool(ka_running)),
                (
                    "keepalive_pid",
                    ka_pid.map(|p| Value::Int(p as i64)).unwrap_or(Value::Null),
                ),
                ("probe_duration_ms", Value::Int(res.duration_ms as i64)),
            ])
        }
        Err(e) => Value::obj(vec![
            ("ok", Value::Bool(false)),
            ("distro", Value::Str(cfg.distro.clone())),
            ("error", Value::Str(e)),
            ("daemon_running", Value::Bool(dm_running)),
            ("keepalive_running", Value::Bool(ka_running)),
        ]),
    }
}

pub fn bg_start(
    cfg: &Config,
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    env: &[(String, String)],
    log_path: Option<&str>,
    sudo: bool,
) -> Result<Value, String> {
    if let Some(res) = broker_client::try_bg_start(cfg, program, args, cwd, env, log_path, sudo) {
        return res;
    }
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

    let pid_win = local_data_dir()
        .join("tmp")
        .join(format!("bg-{}.pid", next_unique_tag()));
    if let Some(parent) = pid_win.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let pid_linux = win_to_linux(&pid_win.to_string_lossy());
    let launcher = r#"pf="$1"; log="$2"; shift 2; setsid -w /bin/sh -c 'echo $$ > "$1"; log="$2"; shift 2; exec "$@" </dev/null >>"$log" 2>&1' _ "$pf" "$log" "$@""#;
    let mut full_args: Vec<String> = vec![
        "-c".to_string(),
        launcher.to_string(),
        "_".to_string(),
        pid_linux,
        linux_log.clone(),
    ];
    if sudo {
        full_args.push("/usr/bin/sudo".to_string());
        full_args.push("-n".to_string());
        if !env.is_empty() {
            full_args.push("/usr/bin/env".to_string());
            for (k, v) in env {
                full_args.push(format!("{}={}", k, v));
            }
        }
    }
    full_args.push(program.to_string());
    full_args.extend(args.iter().cloned());

    let mut cmd = Command::new(WSL_EXE);
    cmd.args(["-d", &cfg.distro, "-u", &cfg.user]);
    if let Some(c) = resolve_cwd_for_wsl(cwd) {
        cmd.args(["--cd", &c]);
    }
    cmd.arg("--exec");
    push_utf8_safe_exec(&mut cmd, "/bin/sh", &full_args);

    let extra_keys: Vec<String> = env.iter().map(|(k, _)| k.clone()).collect();
    if !sudo {
        for (k, v) in env {
            cmd.env(k, v);
        }
    }
    let wslenv = build_wslenv(&extra_keys);
    if !wslenv.is_empty() {
        cmd.env("WSLENV", wslenv);
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn bg process: {}", e))?;
    let wait_start = Instant::now();
    let mut pgid_opt: Option<i64> = None;
    while wait_start.elapsed() < Duration::from_secs(10) {
        if let Ok(text) = fs::read_to_string(&pid_win) {
            if let Ok(p) = text.trim().parse::<i64>() {
                pgid_opt = Some(p);
                break;
            }
        }
        if wait_child_ms(&child, 20) {
            if let Ok(text) = fs::read_to_string(&pid_win) {
                if let Ok(p) = text.trim().parse::<i64>() {
                    pgid_opt = Some(p);
                    break;
                }
            }
            let code = child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
            let _ = fs::remove_file(&pid_win);
            return Err(format!("bg launcher exited early (rc={})", code));
        }
    }
    let _ = fs::remove_file(&pid_win);
    let pgid = pgid_opt.ok_or_else(|| "timed out waiting for bg process pid".to_string())?;

    Ok(Value::obj(vec![
        ("detached", Value::Bool(true)),
        ("pid", Value::Int(pgid)),
        ("pgid", Value::Int(pgid)),
        ("log_path", Value::Str(linux_log)),
        ("distro", Value::Str(cfg.distro.clone())),
        ("user", Value::Str(cfg.user.clone())),
    ]))
}

pub fn capture_result_to_json(res: &CaptureResult, include_base64: bool) -> Value {
    let mut entries = vec![
        ("exit_code", Value::Int(res.exit_code as i64)),
        (
            "stdout",
            Value::Str(String::from_utf8_lossy(&res.stdout).to_string()),
        ),
        (
            "stderr",
            Value::Str(String::from_utf8_lossy(&res.stderr).to_string()),
        ),
        ("stdout_truncated", Value::Bool(res.stdout_truncated)),
        ("stderr_truncated", Value::Bool(res.stderr_truncated)),
        ("timed_out", Value::Bool(res.timed_out)),
        ("cancelled", Value::Bool(res.cancelled)),
        ("duration_ms", Value::Int(res.duration_ms as i64)),
    ];
    if include_base64 {
        entries.push(("stdout_base64", Value::Str(base64_encode(&res.stdout))));
        entries.push(("stderr_base64", Value::Str(base64_encode(&res.stderr))));
    }
    Value::obj(entries)
}
