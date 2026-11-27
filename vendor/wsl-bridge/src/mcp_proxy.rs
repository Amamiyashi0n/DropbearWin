use crate::broker_client::try_mcp_proxy;
use crate::pathconv::resolve_cwd_for_wsl;
use crate::win::{ctrl_triggered, install_ctrl_handler, wait_child_ms, CREATE_NO_WINDOW};
use crate::wsl::{build_wslenv, kill_linux_pgid, push_utf8_safe_exec, Config, WSL_EXE};
use std::io::{self, Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn run_mcp_proxy(
    cfg: &Config,
    cwd: Option<&str>,
    env_pairs: &[(String, String)],
    program: &str,
    args: &[String],
) -> i32 {
    if let Some(rc) = try_mcp_proxy(cfg, cwd, env_pairs, program, args) {
        return rc;
    }
    install_ctrl_handler();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pgid_file = format!("/tmp/wslb-mcp-proxy-{}-{}", std::process::id(), ts);

    let mut cmd = Command::new(WSL_EXE);
    cmd.args(["-d", &cfg.distro, "-u", &cfg.user]);
    if let Some(c) = resolve_cwd_for_wsl(cwd) {
        cmd.args(["--cd", &c]);
    }
    let wrapper = r#"pf="$1"; shift; echo $$ > "$pf"; "$@"; rc=$?; rm -f "$pf"; exit $rc"#;
    cmd.args(["--exec", "/usr/bin/setsid", "-w", "/bin/sh", "-c", wrapper, "_", &pgid_file]);
    push_utf8_safe_exec(&mut cmd, program, args);

    let extra_keys: Vec<String> = env_pairs.iter().map(|(k, _)| k.clone()).collect();
    for (k, v) in env_pairs {
        cmd.env(k, v);
    }
    let wslenv = build_wslenv(&extra_keys);
    if !wslenv.is_empty() {
        cmd.env("WSLENV", wslenv);
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wsl-bridge mcp-proxy: failed to spawn wsl.exe: {}", e);
            return 127;
        }
    };

    let mut child_stdin = match child.stdin.take() {
        Some(s) => s,
        None => return 1,
    };
    let mut child_stdout = match child.stdout.take() {
        Some(s) => s,
        None => return 1,
    };
    let mut child_stderr = match child.stderr.take() {
        Some(s) => s,
        None => return 1,
    };

    let stdin_eof = Arc::new(AtomicBool::new(false));
    let stdin_eof_flag = Arc::clone(&stdin_eof);

    let _t_in = thread::spawn(move || {
        let mut host_in = io::stdin().lock();
        let mut buf = [0u8; 16384];
        loop {
            match host_in.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if child_stdin.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = child_stdin.flush();
                }
                Err(_) => break,
            }
        }
        drop(child_stdin);
        stdin_eof_flag.store(true, Ordering::SeqCst);
    });

    let t_out = thread::spawn(move || {
        let mut host_out = io::stdout().lock();
        let mut buf = [0u8; 16384];
        loop {
            match child_stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if host_out.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = host_out.flush();
                }
                Err(_) => break,
            }
        }
    });

    let t_err = thread::spawn(move || {
        let mut host_err = io::stderr().lock();
        let mut buf = [0u8; 16384];
        loop {
            match child_stderr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if host_err.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = host_err.flush();
                }
                Err(_) => break,
            }
        }
    });

    let mut eof_since: Option<Instant> = None;
    let code = loop {
        if wait_child_ms(&child, 25) {
            break child.wait().map(|s| s.code().unwrap_or(0)).unwrap_or(0);
        }
        if ctrl_triggered() {
            kill_linux_pgid(cfg, &pgid_file);
            let _ = child.kill();
            let _ = child.wait();
            break 130;
        }
        if stdin_eof.load(Ordering::SeqCst) {
            let since = *eof_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_millis(1500) {
                kill_linux_pgid(cfg, &pgid_file);
                let _ = child.kill();
                let _ = child.wait();
                break 0;
            }
        }
    };

    let _ = t_out.join();
    let _ = t_err.join();
    code
}
