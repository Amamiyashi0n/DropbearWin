"""Run long-script integration checks against a disposable loopback server.

Windows: python tests/test_run_script.py dist/dropbear-win-x64.exe --node-program C:\\Tools\\node.exe
Linux/Wine: supply --wine and Windows --python-program/--node-program paths.
Use --powershell under Wine only when a real PowerShell installation is available.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from dropbear_mcp import Remote, Settings, paramiko
from windows_exec import encode_request


def windows_path(path, wine):
    return "Z:" + str(path.resolve()).replace("/", "\\") if wine else str(path.resolve())


@contextmanager
def fixture(executable, wine):
    with tempfile.TemporaryDirectory(prefix="dropbear script ") as temporary:
        directory = Path(temporary)
        private_temp = directory / "temp 中文"
        private_temp.mkdir()
        password = secrets.token_hex(16)
        salt = secrets.token_bytes(32)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        (directory / "account.conf").write_text(
            f"fixture\npbkdf2-sha256$100000${salt.hex()}${digest.hex()}\n")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, WINEDEBUG="-all", DROPBEAR_WIN_SHELL="cmd",
                   DROPBEAR_WIN_DATA_DIR=windows_path(directory, wine),
                   DROPBEAR_WIN_ACCOUNT_FILE=windows_path(directory / "account.conf", wine),
                   TEMP=windows_path(private_temp, wine), TMP=windows_path(private_temp, wine))
        with (directory / "server.log").open("wb") as log:
            server = subprocess.Popen((["wine"] if wine else []) + [str(executable), "-p", f"127.0.0.1:{port}"],
                                      env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            enrollment = paramiko.SSHClient()
            enrollment.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline and server.poll() is None:
                    try:
                        enrollment.connect("127.0.0.1", port=port, username="fixture", password=password,
                                           look_for_keys=False, allow_agent=False, timeout=2)
                        break
                    except (OSError, paramiko.SSHException):
                        time.sleep(.2)
                else:
                    raise RuntimeError((directory / "server.log").read_text(errors="replace"))
                known_hosts = directory / "known_hosts"
                enrollment.save_host_keys(str(known_hosts))
                enrollment.close()
                remote = Remote(Settings("127.0.0.1", "fixture", port, password, str(known_hosts)))
                yield remote, private_temp, windows_path(directory, wine)
            finally:
                enrollment.close()
                server.terminate()
                try:
                    server.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


def check_long_script(remote, runtime, program, cwd):
    args = ["space argument", "literal&value", "中文"]
    stdin = bytes(range(256)) * 100
    if runtime == "python":
        script = "# long script 中文\n" * 6000 + (
            "import sys, os, json, base64\n"
            "print(json.dumps(dict(args=sys.argv[1:], cwd=os.getcwd(), env=os.environ['SCRIPT_TEST'], "
            "stdin=base64.b64encode(sys.stdin.buffer.read()).decode())))\n"
            "sys.stderr.write('script stderr')\nsys.exit(7)\n")
    elif runtime == "node":
        script = "// long script 中文\n" * 6000 + (
            "const fs=require('fs'); console.log(JSON.stringify({args:process.argv.slice(2), cwd:process.cwd(), "
            "env:process.env.SCRIPT_TEST, stdin:fs.readFileSync(0).toString('base64')})); "
            "process.stderr.write('script stderr');process.exitCode=7;")
    else:
        script = "# long script 中文\n" * 6000 + (
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "$stream=New-Object IO.MemoryStream\n[Console]::OpenStandardInput().CopyTo($stream)\n"
            "@{args=@($args);cwd=[Environment]::CurrentDirectory;env=$env:SCRIPT_TEST;"
            "stdin=[Convert]::ToBase64String($stream.ToArray())}|ConvertTo-Json -Compress\n"
            "[Console]::Error.Write('script stderr')\nexit 7\n")
    result = remote.run_script(script, runtime, program, args=args, cwd=cwd,
                               env={"SCRIPT_TEST": "独立环境"}, stdin_base64=base64.b64encode(stdin).decode(),
                               encoding="utf-8")
    assert result["exit_code"] == 7 and result["script_cleanup"]["removed"], result
    assert result["stderr"] == "script stderr", result
    output = json.loads(result["stdout"])
    assert output["args"] == args and output["env"] == "独立环境", output
    assert output["cwd"].casefold() == cwd.casefold(), output
    assert base64.b64decode(output["stdin"]) == stdin
    print("PASS long script, Unicode, args, cwd, environment, stdin and cleanup:", runtime, flush=True)


def check_failure_cleanup(remote, program, temporary):
    for script, timeout, expected in (
            ("import time; time.sleep(10)", 1, "timed out"),
            ("import sys; sys.stdout.write('x' * 2000000)", 30, "exceeded")):
        try:
            remote.run_script(script, "python", program, timeout=timeout)
        except RuntimeError as exc:
            assert expected in str(exc) and "script_cleanup=" not in str(exc), str(exc)
        else:
            raise AssertionError("Expected execution failure")
        assert not list(temporary.glob("dropbear-script-*")), list(temporary.iterdir())
    print("PASS timeout and output-limit cleanup", flush=True)


def check_native_staging(remote):
    context = remote.probe()
    assert context["script_staging"] is True
    executable = context["server_executable"]
    stage_id = uuid.uuid4().hex

    def operation(option, token=stage_id):
        return remote.exchange(payload=encode_request({"program": executable, "args": [option, token]}))

    assert operation("--script-stage", "../bad")[2] == 2
    out, err, status = operation("--script-stage")
    assert status == 0 and not err, (out, err, status)
    directory = json.loads(out)["directory"].replace("\\", "/")
    client = remote.connect()
    try:
        with client.open_sftp() as sftp:
            with sftp.file(directory + "/preserve.txt", "wx") as stream:
                stream.write(b"keep")
            assert operation("--script-stage")[2] != 0
            assert operation("--script-cleanup")[2] != 0
            with sftp.file(directory + "/preserve.txt", "rb") as stream:
                assert stream.read() == b"keep"
            sftp.remove(directory + "/preserve.txt")
            assert operation("--script-cleanup")[2] == 0
            assert operation("--script-cleanup")[2] == 0
    finally:
        client.close()
    print("PASS native staging: invalid IDs, collisions, preserved files, repeat cleanup", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executables", nargs="+", type=lambda value: Path(value).resolve())
    parser.add_argument("--wine", action="store_true")
    parser.add_argument("--python-program")
    parser.add_argument("--node-program")
    parser.add_argument("--powershell", action="store_true")
    args = parser.parse_args()
    python = args.python_program or (sys.executable if not args.wine else None)
    if not python:
        parser.error("Wine checks need --python-program pointing to a Windows Python interpreter")
    for executable in args.executables:
        with fixture(executable, args.wine) as (remote, temporary, cwd):
            check_native_staging(remote)
            check_long_script(remote, "python", python, cwd)
            if args.node_program:
                check_long_script(remote, "node", args.node_program, cwd)
            if not args.wine or args.powershell:
                check_long_script(remote, "powershell", None, cwd)
            check_failure_cleanup(remote, python, temporary)
            assert not list(temporary.glob("dropbear-script-*"))
            print("PASS run_script integration:", executable.name, flush=True)


if __name__ == "__main__":
    main()
