mod broker_client;
mod json;
mod mcp;
mod mcp_proxy;
mod pathconv;
mod win;
mod wsl;

use crate::json::Value;
use crate::mcp::run_mcp_server;
use crate::mcp_proxy::run_mcp_proxy;
use crate::pathconv::{linux_to_win, win_to_linux};
use crate::wsl::{
    daemon_status, keepalive_start, keepalive_status, keepalive_stop, query_status, run_daemon,
    run_exec_passthrough, run_shell_passthrough, Config,
};
use std::env;
use std::path::Path;
use std::process;

fn print_usage() {
    eprintln!(
        "wsl-bridge {} - Direct pass-through bridge, boot daemon & MCP server for Debian WSL1\n\
\n\
Usage:\n\
  bash.exe [bash-args...]                          Drop-in POSIX bash pass-through\n\
  sh.exe [sh-args...]                              Drop-in POSIX sh pass-through\n\
  wsl-bridge bash|sh [args...]                     Explicit shell pass-through\n\
  wsl-bridge exec [options] -- <cmd> [args...]     Direct binary pass-through\n\
  wsl-bridge path --to-linux|--to-win|--mixed <p>  Convert Windows <-> WSL path\n\
  wsl-bridge status [--distro D] [--user U]        UTF-8 JSON health status\n\
  wsl-bridge daemon [--distro D] [--user U]        High-priority boot-time WSL1 supervisor\n\
  wsl-bridge keepalive [start|stop|status]         Manage lightweight WSL1 keepalive\n\
  wsl-bridge mcp [--distro D] [--user U]           Run built-in stdio MCP server\n\
  wsl-bridge mcp-proxy [options] -- <cmd> [args]   Proxy a Linux MCP server over stdio\n\
\n\
Options (exec / mcp-proxy):\n\
  --distro <name>   WSL distro name (default: Debian or $WSL_BRIDGE_DISTRO)\n\
  --user <name>     Linux user (default: amamiya or $WSL_BRIDGE_USER)\n\
  --cwd <path>      Working directory (Windows or Linux path)\n\
  --env <K=V>       Extra environment variable (repeatable)\n\
  --sudo            Run via passwordless sudo (exec mode only)",
        env!("CARGO_PKG_VERSION")
    );
}

fn exe_stem_lower() -> String {
    env::args_os()
        .next()
        .and_then(|a| {
            Path::new(&a)
                .file_stem()
                .map(|s| s.to_string_lossy().to_ascii_lowercase())
        })
        .unwrap_or_default()
}

fn parse_exec_like(
    mut cfg: Config,
    args: &[String],
    allow_sudo: bool,
) -> Result<(Config, Option<String>, Vec<(String, String)>, bool, String, Vec<String>), String> {
    let mut cwd: Option<String> = None;
    let mut env_pairs: Vec<(String, String)> = Vec::new();
    let mut sudo = false;
    let mut i = 0usize;

    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                i += 1;
                break;
            }
            "--distro" | "-d" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for --distro".to_string());
                }
                cfg.distro = args[i].clone();
            }
            "--user" | "-u" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for --user".to_string());
                }
                cfg.user = args[i].clone();
            }
            "--cwd" | "--cd" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for --cwd".to_string());
                }
                cwd = Some(args[i].clone());
            }
            "--env" | "-e" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for --env".to_string());
                }
                if let Some((k, v)) = args[i].split_once('=') {
                    env_pairs.push((k.to_string(), v.to_string()));
                } else {
                    return Err(format!("invalid --env '{}', expected K=V", args[i]));
                }
            }
            "--sudo" if allow_sudo => {
                sudo = true;
            }
            s if s.starts_with('-') => {
                return Err(format!("unknown option '{}'", s));
            }
            _ => break,
        }
        i += 1;
    }

    if i >= args.len() {
        return Err("missing target command".to_string());
    }
    let program = args[i].clone();
    let rest = args[i + 1..].to_vec();
    Ok((cfg, cwd, env_pairs, sudo, program, rest))
}

fn parse_cfg_only(mut cfg: Config, args: &[String]) -> Result<Config, String> {
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--distro" | "-d" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for --distro".to_string());
                }
                cfg.distro = args[i].clone();
            }
            "--user" | "-u" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value for --user".to_string());
                }
                cfg.user = args[i].clone();
            }
            other => return Err(format!("unknown option '{}'", other)),
        }
        i += 1;
    }
    Ok(cfg)
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cfg = Config::from_env();
    let stem = exe_stem_lower();

    if stem == "bash" {
        process::exit(run_shell_passthrough(&cfg, "/usr/bin/bash", &args));
    }
    if stem == "sh" {
        process::exit(run_shell_passthrough(&cfg, "/bin/sh", &args));
    }

    if args.is_empty() {
        print_usage();
        process::exit(0);
    }

    let sub = args[0].as_str();
    let rest = &args[1..];
    let code = match sub {
        "-h" | "--help" | "help" => {
            print_usage();
            0
        }
        "-V" | "--version" | "version" => {
            println!("wsl-bridge {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "bash" | "shell" => run_shell_passthrough(&cfg, "/usr/bin/bash", rest),
        "sh" => run_shell_passthrough(&cfg, "/bin/sh", rest),
        "exec" => match parse_exec_like(cfg, rest, true) {
            Ok((c, cwd, env_p, sudo, prog, pargs)) => {
                run_exec_passthrough(&c, cwd.as_deref(), &env_p, sudo, &prog, &pargs)
            }
            Err(e) => {
                eprintln!("wsl-bridge exec: {}", e);
                2
            }
        },
        "path" => {
            if rest.is_empty() {
                eprintln!("wsl-bridge path: expected --to-linux|--to-win|--mixed <path>");
                2
            } else {
                let (mode, target) = if rest.len() >= 2 && rest[0].starts_with('-') {
                    (rest[0].as_str(), rest[1].as_str())
                } else {
                    ("--to-linux", rest[0].as_str())
                };
                match mode {
                    "--to-linux" | "-u" => {
                        println!("{}", win_to_linux(target));
                        0
                    }
                    "--to-win" | "-w" => {
                        println!("{}", linux_to_win(target, false));
                        0
                    }
                    "--mixed" | "-m" => {
                        println!("{}", linux_to_win(target, true));
                        0
                    }
                    _ => {
                        eprintln!("wsl-bridge path: unknown mode '{}'", mode);
                        2
                    }
                }
            }
        }
        "status" | "health" => match parse_cfg_only(cfg, rest) {
            Ok(c) => {
                let v = query_status(&c);
                let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                println!("{}", v.to_json_string());
                if ok { 0 } else { 1 }
            }
            Err(e) => {
                eprintln!("wsl-bridge status: {}", e);
                2
            }
        },
        "daemon" => {
            if rest.first().map(|s| s.as_str()) == Some("status") {
                let (running, pid, prio) = daemon_status();
                println!(
                    "{}",
                    Value::obj(vec![
                        ("running", Value::Bool(running)),
                        ("pid", pid.map(|p| Value::Int(p as i64)).unwrap_or(Value::Null)),
                        (
                            "priority",
                            prio.map(|s| Value::Str(s.to_string())).unwrap_or(Value::Null),
                        ),
                    ])
                    .to_json_string()
                );
                0
            } else {
                match parse_cfg_only(cfg, rest) {
                    Ok(c) => run_daemon(&c),
                    Err(e) => {
                        eprintln!("wsl-bridge daemon: {}", e);
                        2
                    }
                }
            }
        }
        "keepalive" => {
            let action = rest.first().map(|s| s.as_str()).unwrap_or("status");
            match action {
                "start" => match keepalive_start(&cfg) {
                    Ok(pid) => {
                        println!(
                            "{}",
                            Value::obj(vec![
                                ("running", Value::Bool(true)),
                                ("pid", Value::Int(pid as i64)),
                            ])
                            .to_json_string()
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!("wsl-bridge keepalive: {}", e);
                        1
                    }
                },
                "stop" => {
                    let stopped = keepalive_stop();
                    println!(
                        "{}",
                        Value::obj(vec![
                            ("running", Value::Bool(false)),
                            ("stopped", Value::Bool(stopped)),
                        ])
                        .to_json_string()
                    );
                    0
                }
                "status" => {
                    let (running, pid) = keepalive_status();
                    println!(
                        "{}",
                        Value::obj(vec![
                            ("running", Value::Bool(running)),
                            ("pid", pid.map(|p| Value::Int(p as i64)).unwrap_or(Value::Null)),
                        ])
                        .to_json_string()
                    );
                    0
                }
                other => {
                    eprintln!("wsl-bridge keepalive: unknown action '{}'", other);
                    2
                }
            }
        }
        "mcp" => match parse_cfg_only(cfg, rest) {
            Ok(c) => run_mcp_server(&c),
            Err(e) => {
                eprintln!("wsl-bridge mcp: {}", e);
                2
            }
        },
        "mcp-proxy" => match parse_exec_like(cfg, rest, false) {
            Ok((c, cwd, env_p, _sudo, prog, pargs)) => {
                run_mcp_proxy(&c, cwd.as_deref(), &env_p, &prog, &pargs)
            }
            Err(e) => {
                eprintln!("wsl-bridge mcp-proxy: {}", e);
                2
            }
        },
        other => {
            eprintln!("wsl-bridge: unknown subcommand '{}'", other);
            print_usage();
            2
        }
    };
    process::exit(code);
}
