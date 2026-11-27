#!/usr/bin/env python3
"""Resident ultra-low-latency Debian WSL1 pass-through broker for wsl-bridge.

Wire protocol (TCP 127.0.0.1, TCP_NODELAY):
  Each frame: 1 byte type + 4 bytes big-endian length + payload bytes.
  Client -> Broker:
    0x01 REQ       UTF-8 JSON {token, program, args, cwd, env, sudo}
    0x02 STDIN     raw binary chunk
    0x03 STDIN_EOF empty
    0x04 SIGNAL    1 byte signal number (default 15)
    0x05 BG_START  UTF-8 JSON {token, program, args, cwd, env, log_path, sudo}
    0x06 BG_STOP   UTF-8 JSON {token, pgid}
    0x07 STATUS    UTF-8 JSON {token}
  Broker -> Client:
    0x10 STARTED   UTF-8 JSON {pid, pgid}
    0x11 STDOUT    raw binary chunk
    0x12 STDERR    raw binary chunk
    0x13 EXIT      UTF-8 JSON {exit_code, error?}
    0x14 JSON_RESP UTF-8 JSON (for BG_START / BG_STOP / STATUS)
"""
import argparse
import getpass
import hmac
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

T_REQ = 0x01
T_STDIN = 0x02
T_STDIN_EOF = 0x03
T_SIGNAL = 0x04
T_BG_START = 0x05
T_BG_STOP = 0x06
T_STATUS = 0x07

T_STARTED = 0x10
T_STDOUT = 0x11
T_STDERR = 0x12
T_EXIT = 0x13
T_JSON_RESP = 0x14

TOKEN = ""
BASE_ENV = {}
STATIC_INFO = {}


def send_frame(sock: socket.socket, ftype: int, payload: bytes) -> None:
    hdr = struct.pack(">BI", ftype, len(payload))
    sock.sendall(hdr + payload)


def send_json(sock: socket.socket, ftype: int, obj: dict) -> None:
    send_frame(sock, ftype, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("socket closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket):
    hdr = recv_exact(sock, 5)
    ftype, length = struct.unpack(">BI", hdr)
    payload = recv_exact(sock, length) if length else b""
    return ftype, payload


def auth_ok(req: dict) -> bool:
    t = req.get("token")
    return isinstance(t, str) and hmac.compare_digest(t, TOKEN)


def kill_pgid_force(pgid: int, sig: int = signal.SIGTERM) -> bool:
    if pgid <= 1:
        return False
    alive = False
    try:
        os.killpg(pgid, 0)
        alive = True
    except ProcessLookupError:
        try:
            os.kill(pgid, 0)
            alive = True
        except OSError:
            return False
    except PermissionError:
        alive = True
    try:
        os.killpg(pgid, sig)
    except OSError:
        try:
            os.kill(pgid, sig)
        except OSError:
            pass
    if sig == signal.SIGTERM:
        deadline = time.monotonic() + 0.25
        while time.monotonic() < deadline:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                break
            time.sleep(0.02)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            try:
                os.kill(pgid, signal.SIGKILL)
            except OSError:
                pass
    return alive


def build_exec_argv_env(req: dict):
    program = req.get("program") or ""
    args = req.get("args") or []
    env_extra = req.get("env") or {}
    sudo = bool(req.get("sudo", False))
    cwd = req.get("cwd") or os.path.expanduser("~")
    if not os.path.isdir(cwd):
        raise FileNotFoundError(f"working directory does not exist: {cwd}")

    env = BASE_ENV.copy()
    if sudo:
        argv = ["/usr/bin/sudo", "-n"]
        if env_extra:
            argv.append("/usr/bin/env")
            for k, v in env_extra.items():
                argv.append(f"{k}={v}")
        argv.append(program)
        argv.extend(args)
    else:
        for k, v in env_extra.items():
            env[str(k)] = str(v)
        argv = [program] + list(args)
    return argv, env, cwd


def handle_exec(conn: socket.socket, req: dict) -> None:
    try:
        argv, env, cwd = build_exec_argv_env(req)
    except Exception as e:
        send_json(conn, T_EXIT, {"exit_code": 1, "error": str(e)})
        return

    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
    except FileNotFoundError as e:
        send_json(conn, T_EXIT, {"exit_code": 127, "error": str(e)})
        return
    except PermissionError as e:
        send_json(conn, T_EXIT, {"exit_code": 126, "error": str(e)})
        return
    except Exception as e:
        send_json(conn, T_EXIT, {"exit_code": 1, "error": str(e)})
        return

    pgid = proc.pid
    try:
        send_json(conn, T_STARTED, {"pid": proc.pid, "pgid": pgid})
    except OSError:
        kill_pgid_force(pgid, signal.SIGKILL)
        proc.wait()
        return

    stdin_fd = proc.stdin.fileno()
    stdout_fd = proc.stdout.fileno()
    stderr_fd = proc.stderr.fileno()
    os.set_blocking(stdout_fd, False)
    os.set_blocking(stderr_fd, False)
    conn.setblocking(False)

    stdin_open = True
    stdout_open = True
    stderr_open = True
    conn_open = True
    rx_buf = bytearray()
    client_aborted = False

    def close_stdin():
        nonlocal stdin_open
        if stdin_open:
            stdin_open = False
            try:
                proc.stdin.close()
            except OSError:
                pass

    try:
        while stdout_open or stderr_open:
            rlist = []
            if stdout_open:
                rlist.append(stdout_fd)
            if stderr_open:
                rlist.append(stderr_fd)
            if conn_open:
                rlist.append(conn)
            if not rlist:
                break

            ready, _, _ = select.select(rlist, [], [], 0.05)

            if stdout_open and stdout_fd in ready:
                try:
                    data = os.read(stdout_fd, 65536)
                    if not data:
                        stdout_open = False
                    else:
                        conn.setblocking(True)
                        send_frame(conn, T_STDOUT, data)
                        conn.setblocking(False)
                except BlockingIOError:
                    pass
                except OSError:
                    stdout_open = False
                    client_aborted = True
                    break

            if stderr_open and stderr_fd in ready:
                try:
                    data = os.read(stderr_fd, 65536)
                    if not data:
                        stderr_open = False
                    else:
                        conn.setblocking(True)
                        send_frame(conn, T_STDERR, data)
                        conn.setblocking(False)
                except BlockingIOError:
                    pass
                except OSError:
                    stderr_open = False
                    client_aborted = True
                    break

            if conn_open and conn in ready:
                try:
                    chunk = conn.recv(65536)
                except BlockingIOError:
                    chunk = None
                except OSError:
                    chunk = b""

                if chunk == b"":
                    conn_open = False
                    close_stdin()
                    if proc.poll() is None:
                        client_aborted = True
                        kill_pgid_force(pgid, signal.SIGTERM)
                        break
                elif chunk:
                    rx_buf.extend(chunk)
                    while len(rx_buf) >= 5:
                        ftype, flen = struct.unpack(">BI", rx_buf[:5])
                        if len(rx_buf) < 5 + flen:
                            break
                        payload = bytes(rx_buf[5 : 5 + flen])
                        del rx_buf[: 5 + flen]
                        if ftype == T_STDIN:
                            if stdin_open and payload:
                                try:
                                    proc.stdin.write(payload)
                                    proc.stdin.flush()
                                except OSError:
                                    close_stdin()
                        elif ftype == T_STDIN_EOF:
                            close_stdin()
                        elif ftype == T_SIGNAL:
                            sig = payload[0] if payload else signal.SIGTERM
                            kill_pgid_force(pgid, sig)
                            if sig in (signal.SIGTERM, signal.SIGKILL):
                                close_stdin()
    finally:
        close_stdin()
        try:
            proc.stdout.close()
        except OSError:
            pass
        try:
            proc.stderr.close()
        except OSError:
            pass

    if client_aborted and proc.poll() is None:
        kill_pgid_force(pgid, signal.SIGKILL)

    rc = proc.wait()
    exit_code = (128 + (-rc)) if rc < 0 else rc
    if conn_open and not client_aborted:
        try:
            conn.setblocking(True)
            send_json(conn, T_EXIT, {"exit_code": exit_code})
        except OSError:
            pass


def handle_bg_start(conn: socket.socket, req: dict) -> None:
    try:
        argv, env, cwd = build_exec_argv_env(req)
        log_path = req.get("log_path") or "/dev/null"
        log_f = open(log_path, "ab")
        devnull = open("/dev/null", "rb")
        try:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=devnull,
                stdout=log_f,
                stderr=log_f,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            log_f.close()
            devnull.close()
        # Reap in background thread so no zombie accumulates
        threading.Thread(target=proc.wait, daemon=True).start()
        send_json(
            conn,
            T_JSON_RESP,
            {
                "ok": True,
                "detached": True,
                "pid": proc.pid,
                "pgid": proc.pid,
                "log_path": log_path,
                "user": STATIC_INFO.get("effective_user", ""),
            },
        )
    except Exception as e:
        send_json(conn, T_JSON_RESP, {"ok": False, "error": str(e)})


def handle_bg_stop(conn: socket.socket, req: dict) -> None:
    try:
        pgid = int(req.get("pgid", 0))
        if pgid <= 1:
            send_json(conn, T_JSON_RESP, {"ok": False, "error": "invalid pgid"})
            return
        stopped = kill_pgid_force(pgid, signal.SIGTERM)
        send_json(conn, T_JSON_RESP, {"ok": True, "pgid": pgid, "stopped": stopped})
    except Exception as e:
        send_json(conn, T_JSON_RESP, {"ok": False, "error": str(e)})


def handle_status(conn: socket.socket) -> None:
    send_json(conn, T_JSON_RESP, STATIC_INFO)


def handle_client(conn: socket.socket) -> None:
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ftype, payload = recv_frame(conn)
        req = json.loads(payload.decode("utf-8")) if payload else {}
        if not auth_ok(req):
            send_json(conn, T_EXIT, {"exit_code": 1, "error": "unauthorized"})
            return
        if ftype == T_REQ:
            handle_exec(conn, req)
        elif ftype == T_BG_START:
            handle_bg_start(conn, req)
        elif ftype == T_BG_STOP:
            handle_bg_stop(conn, req)
        elif ftype == T_STATUS:
            handle_status(conn)
        else:
            send_json(conn, T_EXIT, {"exit_code": 1, "error": f"unknown frame {ftype}"})
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def collect_static_info() -> dict:
    user = getpass.getuser()
    uid = str(os.getuid())
    home = os.path.expanduser("~")
    u = os.uname()
    kernel = f"{u.sysname} {u.nodename} {u.release} {u.version} {u.machine}"
    os_name = ""
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:
        pass
    sudo_ok = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/id", "-u"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    tools = {}
    for t in ("bash", "sh", "sudo", "git", "rg", "fd", "jq", "python3", "curl", "ssh", "tar", "make", "gcc", "node"):
        p = shutil.which(t)
        if p:
            tools[t] = p
    mounts = []
    if os.path.isdir("/mnt"):
        for name in sorted(os.listdir("/mnt")):
            if len(name) == 1 and name.isalpha() and os.path.isdir(f"/mnt/{name}"):
                mounts.append(f"/mnt/{name}")
    return {
        "ok": True,
        "effective_user": user,
        "uid": uid,
        "home": home,
        "sudo_nopasswd": sudo_ok,
        "os": os_name,
        "kernel": kernel,
        "mounts": mounts,
        "tools": tools,
        "broker_pid": os.getpid(),
    }


def main() -> None:
    global TOKEN, BASE_ENV, STATIC_INFO
    ap = argparse.ArgumentParser()
    ap.add_argument("--info-file", required=True)
    ap.add_argument("--distro", default="Debian")
    args = ap.parse_args()

    TOKEN = os.environ.pop("WSL_BRIDGE_BROKER_TOKEN", "")
    if not TOKEN:
        sys.stderr.write("broker: missing WSL_BRIDGE_BROKER_TOKEN\n")
        sys.exit(2)

    BASE_ENV = os.environ.copy()
    if not BASE_ENV.get("LANG"):
        BASE_ENV["LANG"] = "en_US.UTF-8"
    STATIC_INFO = collect_static_info()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(128)
    port = srv.getsockname()[1]

    info = {
        "port": port,
        "token": TOKEN,
        "linux_pid": os.getpid(),
        "distro": args.distro,
        "user": STATIC_INFO["effective_user"],
    }
    tmp_path = args.info_file + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(info, f)
    os.replace(tmp_path, args.info_file)

    stop = False

    def on_term(_sig, _frame):
        nonlocal stop
        stop = True
        try:
            srv.close()
        except OSError:
            pass

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    try:
        while not stop:
            try:
                conn, _ = srv.accept()
            except OSError:
                if stop:
                    break
                continue
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
    finally:
        try:
            os.remove(args.info_file)
        except OSError:
            pass


if __name__ == "__main__":
    main()
