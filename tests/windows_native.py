"""Native Windows regression: python windows_native.py path/to/dropbearmulti.exe.

Requires Paramiko on the build machine only. Creates disposable local accounts
and servers bound to 127.0.0.1, never reuses the deployment account directory.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import paramiko

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from windows_exec import encode_request


def execute(client, command):
    channel = client.get_transport().open_session(timeout=15)
    channel.settimeout(20)
    channel.exec_command(command)
    channel.shutdown_write()
    output = channel.makefile("rb").read()
    error = channel.makefile_stderr("rb").read()
    status = channel.recv_exit_status()
    channel.close()
    return output, error, status


def run(executable, backend):
    with tempfile.TemporaryDirectory(prefix="dropbear-agent-") as directory:
        directory = Path(directory)
        password = secrets.token_hex(16)
        salt = secrets.token_bytes(32)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        (directory / "account.conf").write_text(
            f"agent\npbkdf2-sha256$100000${salt.hex()}${digest.hex()}\n")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, DROPBEAR_WIN_DATA_DIR=str(directory),
                   DROPBEAR_WIN_ACCOUNT_FILE=str(directory / "account.conf"),
                   DROPBEAR_WIN_SHELL=backend)
        with open(directory / "server.log", "wb") as log:
            server = subprocess.Popen([executable, "-p", f"127.0.0.1:{port}"],
                                      env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                for attempt in range(60):
                    try:
                        client.connect("127.0.0.1", port=port, username="agent",
                                       password=password, look_for_keys=False,
                                       allow_agent=False, timeout=2)
                        break
                    except (OSError, paramiko.SSHException):
                        if server.poll() is not None:
                            raise RuntimeError("server exited")
                        time.sleep(.1)
                else:
                    raise RuntimeError("server startup timed out")
                first_snapshot = None
                for pty in (False, True):
                    welcome = client.get_transport().open_session(timeout=15)
                    welcome.settimeout(15)
                    if pty:
                        welcome.get_pty(term="xterm")
                    welcome.invoke_shell()
                    banner = b""
                    while b"Raw mode:" not in banner:
                        chunk = welcome.recv(4096)
                        assert chunk, banner
                        banner += chunk
                        assert len(banner) < 16384, banner
                    assert b"Welcome to Dropbear for Windows" in banner, banner
                    for field in (b"Host:", b"System:", b"SSH user:", b"Windows user:",
                                  b"Shell:", b"Working dir:", b"Snapshot:", b"Disk (cwd):"):
                        assert field in banner, (field, banner)
                    cpu = re.search(rb"([\d.]+)% busy", banner)
                    assert cpu and 0 <= float(cpu[1]) <= 100, banner
                    assert re.search(rb"Memory: +[\d.]+ / [\d.]+ GiB used", banner), banner
                    assert re.search(rb"Disk \(cwd\): +[\d.]+ / [\d.]+ GiB used", banner), banner
                    snapshot = banner.split(b" Snapshot:", 1)[1].split(b"-----", 1)[0]
                    if first_snapshot is None:
                        first_snapshot = snapshot
                        time.sleep(1.1)
                    else:
                        assert snapshot != first_snapshot, "new shell reused stale login resources"
                    welcome.close()
                out, err, status = execute(client, "__dropbear_win_probe__")
                probe = json.loads(out)
                assert status == 0 and not err and probe["shell"] == backend, (out, err, status)
                assert probe["exec_subsystem"] == "dropbear-exec-v1"
                assert probe["control_encoding"] == "base64"
                assert probe["exec_protocols"] == [1, 2] and probe["exec_protocol_default"] == 2
                if backend == "cmd":
                    quoted_program = directory / "quoted command.exe"
                    shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe", quoted_program)
                    command = f'"{quoted_program}" /d /c "echo quoted&exit /b 7"'
                    out, err, status = execute(client, command)
                    assert b"quoted" in out and status == 7, (out, err, status)
                    out, err, status = execute(client, "echo %USER%&echo %SSH_CONNECTION%")
                    assert b"agent" in out and b"127.0.0.1" in out, (out, err, status)
                else:
                    command = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Write-Output '中文 & $literal'; exit 7"
                    out, err, status = execute(client, command)
                    assert "中文 & $literal" in out.decode("utf-8-sig") and status == 7, (out, err, status)
                script = directory / "inspect args.py"
                script.write_text(
                    "import sys,os,json,hashlib\n"
                    "data=sys.stdin.buffer.read()\n"
                    "print(json.dumps([sys.argv[1:],os.getcwd(),os.environ['DBX_TEST'],hashlib.sha256(data).hexdigest()]))\n"
                    "sys.stderr.write('separate stderr')\n"
                    "sys.exit(23)\n", encoding="utf-8")
                arguments = ["", "space argument", 'embedded"quote', "trailing\\", "中文😀",
                             "&|% !^()", "CR\rLF\nTAB\tEND", "$literal`'\\\\\"", "YWJj=="]
                env_value = "literal&中文\r\n\t%PATH%\"'\\"
                request = {"program": sys.executable, "cwd": str(directory),
                           "args": [str(script)] + arguments, "env": {"DBX_TEST": env_value}}
                data = b"DBX2\r\nYWJj==\0" + bytes(range(256)) * 1024
                for protocol in (1, 2):
                    channel = client.get_transport().open_session(timeout=15)
                    channel.settimeout(20)
                    channel.invoke_subsystem("dropbear-exec-v1")
                    payload = encode_request(request, protocol=protocol)
                    # Split lengths, UTF-8 sequences and Base64 quartets over SSH writes.
                    for offset in range(0, len(payload), 7):
                        channel.sendall(payload[offset:offset + 7])
                    channel.sendall(data)
                    channel.shutdown_write()
                    out = channel.makefile("rb").read()
                    err = channel.makefile_stderr("rb").read()
                    status = channel.recv_exit_status()
                    actual = json.loads(out)
                    assert actual == [arguments, str(directory), env_value,
                                      hashlib.sha256(data).hexdigest()], (protocol, actual)
                    assert err == b"separate stderr" and status == 23, (protocol, err, status)
                    channel.close()
                channel = client.get_transport().open_session(timeout=15)
                channel.settimeout(20)
                channel.invoke_subsystem("dropbear-exec-v1")
                channel.sendall(b"DBX2\x00\x00\x00\x04AB==")  # Noncanonical pad bits / decoded NUL.
                channel.shutdown_write()
                assert not channel.makefile("rb").read()
                assert b"invalid request" in channel.makefile_stderr("rb").read()
                assert channel.recv_exit_status() == 125
                channel.close()
                assert execute(client, "__dropbear_win_probe__")[2] == 0
                # Immediate exit after a large binary output must not truncate it.
                channel = client.get_transport().open_session(timeout=15)
                channel.settimeout(20)
                channel.invoke_subsystem("dropbear-exec-v1")
                channel.sendall(encode_request({"program": sys.executable, "args": [
                    "-c", "import sys; sys.stdout.buffer.write(bytes(range(256))*8192); sys.exit(125)"]}))
                channel.shutdown_write()
                out = channel.makefile("rb").read()
                err = channel.makefile_stderr("rb").read()
                assert len(out) == 2097152 and out == bytes(range(256)) * 8192, (len(out), err, channel.recv_exit_status())
                assert not err and channel.recv_exit_status() == 125, err
                channel.close()
                with client.open_sftp() as sftp:
                    remote = str(directory / "binary 中文.dat").replace("\\", "/")
                    data = bytes(range(256)) * 1000
                    with sftp.file(remote, "wb") as file:
                        file.write(data)
                    with sftp.file(remote, "rb") as file:
                        assert file.read() == data
                print(f"PASS {Path(executable).name} {backend}: welcome/resources (PTY and no PTY), probe, shell, environment, structured exec, binary stdin, stderr, exit status, SFTP")
            except Exception:
                log.flush()
                print((directory / "server.log").read_text(errors="replace"), file=sys.stderr)
                raise
            finally:
                client.close()
                server.terminate()
                server.wait(timeout=10)
                # Listener termination signals connection watcher threads;
                # Windows can keep their inherited log handle open briefly.
                log.close()
                for attempt in range(200):
                    try:
                        (directory / "server.log").unlink()
                        break
                    except PermissionError:
                        if attempt == 199:
                            raise
                        time.sleep(.05)


if __name__ == "__main__":
    executable = str(Path(sys.argv[1]).resolve())
    for invalid in (b"BAD!", b"DBX1", b"DBX1\xff\xff\xff\xff",
                    b"DBX1\x00\x00\x00\x01\xff", b"DBX1\x00\x00\x00\x01\x00"):
        result = subprocess.run([executable, "--dropbear-win-exec"], input=invalid,
                                capture_output=True, timeout=10)
        assert result.returncode == 125 and not result.stdout, result
    for backend in ("cmd", "powershell"):
        run(executable, backend)
