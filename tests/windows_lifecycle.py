"""Windows listener/connection/task lifecycle regression.

Run with native Windows Python and Paramiko. --service additionally creates and
deletes a uniquely named, demand-start SCM service (requires Administrator).
All accounts, keys, listeners and command processes are disposable fixtures.
"""
import argparse
import contextlib
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import paramiko
from windows_native import execute

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from windows_exec import encode_request

kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.OpenProcess.restype = wintypes.HANDLE
kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel.CloseHandle.argtypes = [wintypes.HANDLE]


def eventually(check, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.1)
    raise AssertionError("condition timed out")


def gone(pid):
    handle = kernel.OpenProcess(0x100000, False, pid)
    if not handle:
        return ctypes.get_last_error() == 87
    try:
        return kernel.WaitForSingleObject(handle, 0) == 0
    finally:
        kernel.CloseHandle(handle)


def account(directory):
    directory.mkdir(parents=True, exist_ok=True)
    password = secrets.token_hex(16)
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    (directory / "account.conf").write_text(
        f"agent\npbkdf2-sha256$100000${salt.hex()}${digest.hex()}\n")
    return password


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def connect(port, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=port, username="agent", password=password,
                       look_for_keys=False, allow_agent=False, timeout=3,
                       auth_timeout=5, banner_timeout=5)
        return client
    except Exception:
        client.close()
        raise


@contextlib.contextmanager
def server(executable, *options, **extra_env):
    with tempfile.TemporaryDirectory(prefix="dropbear-lifecycle-") as temp:
        directory = Path(temp)
        password = account(directory)
        port = free_port()
        env = dict(os.environ, DROPBEAR_WIN_DATA_DIR=str(directory),
                   DROPBEAR_WIN_ACCOUNT_FILE=str(directory / "account.conf"),
                   DROPBEAR_WIN_SHELL="cmd", **extra_env)
        with (directory / "server.log").open("wb") as log:
            process = subprocess.Popen([executable, "-p", f"127.0.0.1:{port}", *options],
                                       env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            try:
                def ready():
                    if process.poll() is not None:
                        raise AssertionError("listener exited")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            return True
                    except OSError:
                        return False
                eventually(ready)
                time.sleep(.4)
                yield process, port, password
            except Exception:
                log.flush()
                print((directory / "server.log").read_text(errors="replace"), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)
                time.sleep(.4)


def task(client, exit_parent=False):
    channel = client.get_transport().open_session(timeout=5)
    channel.settimeout(10)
    channel.invoke_subsystem("dropbear-exec-v1")
    code = ("import os,subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']); "
            "print(os.getpid(),p.pid,flush=True); "
            + ("sys.exit(7)" if exit_parent else "time.sleep(120)"))
    channel.sendall(encode_request({"program": sys.executable, "args": ["-c", code]}))
    channel.shutdown_write()
    pids = tuple(map(int, channel.makefile("rb").readline().split()))
    assert len(pids) == 2, pids
    return channel, pids


def options_test(executable):
    with server(executable, "-c", 'echo "forced value"', "-j", "-k") as (_, port, password):
        with connect(port, password) as client:
            out, err, status = execute(client, "echo ORIGINAL")
            assert out.strip() == b'"forced value"' and not err and status == 0, (out, err, status)
            try:
                client.get_transport().open_channel("direct-tcpip", ("127.0.0.1", port), ("127.0.0.1", 0))
            except paramiko.ChannelException:
                pass
            else:
                raise AssertionError("-j lost in connection child")
            try:
                client.get_transport().request_port_forward("127.0.0.1", 0)
            except paramiko.SSHException:
                pass
            else:
                raise AssertionError("-k lost in connection child")
    with server(executable, "-I", "2") as (_, port, password):
        with connect(port, password) as client:
            eventually(lambda: not client.get_transport().is_active(), timeout=8)
    with server(executable, "-K", "1") as (_, port, password):
        with connect(port, password) as client:
            transport = client.get_transport()
            received = []
            original = transport._handler_table[80]
            transport._handler_table = dict(transport._handler_table)
            def global_request(message):
                received.append(True)
                original(message)
            transport._handler_table[80] = global_request
            eventually(lambda: bool(received), timeout=8)
    print("PASS: quoted forced command, -j/-k, idle timeout and keepalive inheritance", flush=True)


def preauth_test(executable):
    # Default flood limits: five unauthenticated connections in total, and
    # the per-address default matches it. Over-limit connections are accepted
    # and closed at once.
    with server(executable) as (_, port, password):
        pending = []
        clients = []
        try:
            for _ in range(5):
                sock = socket.create_connection(("127.0.0.1", port), timeout=3)
                pending.append(sock)
                assert sock.recv(256).startswith(b"SSH-"), "preauth slot rejected early"
            with socket.create_connection(("127.0.0.1", port), timeout=3) as extra:
                try:
                    assert extra.recv(256) == b"", "sixth unauthenticated connection accepted"
                except ConnectionResetError:
                    pass
            pending.pop().close()
            time.sleep(.7)
            # Four unauthenticated slots remain occupied. Authenticated clients
            # must release their slot on authentication, even while their
            # transport stays open.
            for _ in range(7):
                clients.append(connect(port, password))
                time.sleep(.35)
            assert execute(clients[-1], "echo alive")[0].strip() == b"alive"
        finally:
            for client in clients:
                client.close()
            for sock in pending:
                sock.close()
    print("PASS: total preauth limit; slots released on disconnect and "
          "authentication", flush=True)
    # A tightened per-address limit applies before the total one.
    with server(executable, DROPBEAR_WIN_MAX_UNAUTH="30",
                DROPBEAR_WIN_MAX_UNAUTH_PER_IP="2") as (_, port, password):
        pending = []
        try:
            for _ in range(2):
                sock = socket.create_connection(("127.0.0.1", port), timeout=3)
                pending.append(sock)
                assert sock.recv(256).startswith(b"SSH-"), "per-address slot rejected early"
            with socket.create_connection(("127.0.0.1", port), timeout=3) as extra:
                try:
                    assert extra.recv(256) == b"", "third same-address connection accepted"
                except ConnectionResetError:
                    pass
            sock = socket.create_connection(("127.0.0.1", port), timeout=3,
                source_address=("127.0.0.2", 0))
            pending.append(sock)
            assert sock.recv(256).startswith(b"SSH-"), "other address hit the tightened limit"
        finally:
            for sock in pending:
                sock.close()
    print("PASS: tightened per-address limit rejects the third connection "
          "from one source while others continue", flush=True)
    with server(executable, DROPBEAR_WIN_MAX_UNAUTH="30",
                DROPBEAR_WIN_MAX_UNAUTH_PER_IP="5",
                DROPBEAR_WIN_CONN_RATE="64") as (_, port, password):
        pending = []
        try:
            for index in range(30):
                sock = socket.create_connection(("127.0.0.1", port), timeout=3,
                    source_address=(f"127.0.0.{index // 5 + 2}", 0))
                pending.append(sock)
                assert sock.recv(256).startswith(b"SSH-"), f"global slot {index} rejected early"
            with socket.create_connection(("127.0.0.1", port), timeout=3) as extra:
                try:
                    assert extra.recv(256) == b"", "31st unauthenticated connection accepted"
                except ConnectionResetError:
                    pass
            pending.pop().close()
            time.sleep(.7)
            with connect(port, password) as client:
                assert execute(client, "echo global-slot-released")[2] == 0
        finally:
            for sock in pending:
                sock.close()
    print("PASS: environment override raises the total limit across six "
          "loopback source addresses", flush=True)


def tasks_test(executable):
    with server(executable) as (process, port, password):
        with connect(port, password) as client:
            channel, pids = task(client)
            channel.close()
            eventually(lambda: all(gone(pid) for pid in pids))
            assert execute(client, "echo still-connected")[0].strip() == b"still-connected"
            channel, pids = task(client, exit_parent=True)
            assert channel.recv_exit_status() == 7
            channel.close()
            eventually(lambda: all(gone(pid) for pid in pids))
            channel, pids = task(client)
        eventually(lambda: all(gone(pid) for pid in pids))
        with connect(port, password) as client:
            channel, pids = task(client)
            process.kill()
            process.wait(timeout=5)
            eventually(lambda: all(gone(pid) for pid in pids))
            eventually(lambda: not client.get_transport().is_active())
    print("PASS: channel close, task exit, transport disconnect, listener crash reclaim task trees", flush=True)


def service_test(executable):
    name = "DropbearWinTest_" + secrets.token_hex(6)
    sc = str(Path(os.environ["SystemRoot"]) / "System32" / "sc.exe")
    def command(*args, check=True):
        return subprocess.run([sc, *args], check=check, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=15)
    with tempfile.TemporaryDirectory(prefix="dropbear-service-") as temp:
        directory = Path(temp)
        deployed = directory / "dropbear-win.exe"
        shutil.copy2(executable, deployed)
        password = account(directory / "dropbear-win-data")
        port = free_port()
        binary = subprocess.list2cmdline([str(deployed), "--service", name,
                                          "-p", f"127.0.0.1:{port}", "-j"])
        command("create", name, "binPath=", binary, "start=", "demand")
        try:
            command("start", name)
            eventually(lambda: b"RUNNING" in command("query", name).stdout)
            with connect(port, password) as client:
                channel, pids = task(client)
                command("stop", name)
                eventually(lambda: b"STOPPED" in command("query", name).stdout)
                eventually(lambda: all(gone(pid) for pid in pids))
                eventually(lambda: not client.get_transport().is_active())
            command("start", name)
            eventually(lambda: b"RUNNING" in command("query", name).stdout)
            with connect(port, password) as client:
                assert execute(client, "echo restarted")[0].strip() == b"restarted"
            command("stop", name)
            eventually(lambda: b"STOPPED" in command("query", name).stdout)
            time.sleep(.5)
            assert (directory / "dropbear-win-data" / "service.log").stat().st_size > 0
            (directory / "dropbear-win-data" / "account.conf").unlink()
            command("start", name, check=False)
            eventually(lambda: b"STOPPED" in command("query", name).stdout)
            assert "Service requires an existing account.conf" in (
                directory / "dropbear-win-data" / "service.log").read_text(errors="replace")
            account(directory / "dropbear-win-data")
            with socket.socket() as occupied:
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                occupied.bind(("127.0.0.1", port))
                occupied.listen(1)
                command("start", name, check=False)
                eventually(lambda: b"STOPPED" in command("query", name).stdout)
            print("PASS: real SCM start/stop/restart, task cleanup, missing configuration failure", flush=True)
        finally:
            command("stop", name, check=False)
            eventually(lambda: b"STOPPED" in command("query", name).stdout)
            command("delete", name)
            time.sleep(.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=lambda value: str(Path(value).resolve()))
    parser.add_argument("--service", action="store_true")
    args = parser.parse_args()
    options_test(args.executable)
    preauth_test(args.executable)
    tasks_test(args.executable)
    if args.service:
        service_test(args.executable)
