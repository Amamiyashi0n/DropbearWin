"""Windows password KDF compatibility and CPU-throttle regression.

Run with native Windows Python: python windows_kdf.py dist/dropbear-win-x64.exe
Uses disposable accounts, random loopback ports and loopback source addresses.
"""
import hashlib
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time

import paramiko
import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

EXE = Path(sys.argv[1]).resolve()
USER = "agent"
FLOOD_ADDRESSES = ["127.0.0.%d" % index for index in range(1, 7)]
FLOOD_PER_ADDRESS = 5  # Matches MAX_UNAUTH_PER_IP, so all 30 preauth slots are used.
LEGIT_ADDRESS = "127.0.0.10"

# Acquires one throttle slot and dies holding it, which is what a connection
# process killed by a port takeover or restart looks like.
ABANDON_SLOT_SCRIPT = r"""
import ctypes, sys, time
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateMutexW.restype = ctypes.c_void_p
handle = kernel.CreateMutexW(None, False, "Local\\DropbearWin-pbkdf2-0")
if not handle:
    sys.exit(2)
kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
if kernel.WaitForSingleObject(ctypes.c_void_p(handle), 10000) != 0:
    sys.exit(3)
print("ACQUIRED", flush=True)
time.sleep(120)
"""


def write_account(directory, password, iterations):
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    (directory / "account.conf").write_text(
        f"{USER}\npbkdf2-sha256${iterations}${salt.hex()}${digest.hex()}\n")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Server:
    def __init__(self, data_dir, **environment):
        self.data_dir = Path(data_dir)
        self.port = free_port()
        env = dict(os.environ,
                   DROPBEAR_WIN_DATA_DIR=str(self.data_dir),
                   DROPBEAR_WIN_ACCOUNT_FILE=str(self.data_dir / "account.conf"),
                   DROPBEAR_WIN_SHELL="cmd", **environment)
        self.log_path = self.data_dir / "server.log"
        self.log = self.log_path.open("wb")
        self.process = subprocess.Popen([str(EXE), "-p", f"127.0.0.1:{self.port}"],
                                        env=env, stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=self.log)
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError("listener exited")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=.2):
                    return
            except OSError:
                time.sleep(.1)
        raise RuntimeError("listener did not start")

    def tree(self):
        try:
            process = psutil.Process(self.process.pid)
            return [process] + process.children(recursive=True)
        except psutil.Error:
            return []

    def cpu_seconds(self):
        total = 0.0
        for process in self.tree():
            try:
                times = process.cpu_times()
                total += times.user + times.system
            except psutil.Error:
                pass
        return total

    def cpu_sampler(self, interval=.05):
        """Accumulate CPU per live process, so exited children are still counted.

        Connection processes are short lived during a flood; sampling only the
        final tree would drop most of the work they performed.
        """
        server = self

        class Sampler(threading.Thread):
            def __init__(self):
                super().__init__(daemon=True)
                self.seen = {}
                self.running = True

            def sample(self):
                processes = []
                try:
                    listener = psutil.Process(server.process.pid)
                    processes = [listener] + listener.children(recursive=True)
                except psutil.Error:
                    return
                for process in processes:
                    try:
                        key = (process.pid, process.create_time())
                        times = process.cpu_times()
                        self.seen[key] = times.user + times.system
                    except psutil.Error:
                        continue

            def run(self):
                while self.running:
                    self.sample()
                    time.sleep(interval)

            @property
            def total(self):
                self.sample()
                return sum(self.seen.values())

        return Sampler()

    def text(self):
        self.log.flush()
        return self.log_path.read_text(errors="replace")

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.log.close()


def transport(port, address="127.0.0.1"):
    sock = socket.socket()
    sock.bind((address, 0))
    sock.connect(("127.0.0.1", port))
    client = paramiko.Transport(sock)
    client.start_client(timeout=15)
    return client


def login(port, password, address="127.0.0.1"):
    client = transport(port, address)
    client.auth_password(USER, password)
    return client


def verify_interop(root):
    """Every case is hashed by hashlib and must be accepted by the server."""
    # DROPBEAR_MAX_PASSWORD_LEN caps usable passwords at 100 bytes, so 80 and
    # 100 byte keys cover the "longer than the SHA-256 block" key path.
    passwords = ["simple", "pässwörd-中文", "x" * 80, " " * 5, "a" * 100]
    cases = [(password, iterations)
             for iterations in (10000, 100000, 200000)
             for password in passwords]
    failures = []
    for index, (password, iterations) in enumerate(cases):
        directory = root / f"interop-{index}"
        directory.mkdir()
        write_account(directory, password, iterations)
        server = Server(directory)
        try:
            client = login(server.port, password)
            client.close()
            try:
                login(server.port, password + "wrong").close()
                failures.append((password, iterations, "wrong password accepted"))
            except paramiko.AuthenticationException:
                pass
        except Exception as error:  # noqa: BLE001 - report the raw outcome
            failures.append((password, iterations, f"{type(error).__name__}: {error}"))
        finally:
            server.close()
    assert not failures, failures
    print(f"PASS: {len(cases)} PBKDF2 interop cases (iterations 10k/100k/200k, "
          "long and non-ASCII passwords, wrong password rejected)", flush=True)


def suspect_worker(port, address, deadline, attempts, refused, errors):
    """Keep a source address busy with unauthenticated password attempts."""
    while time.monotonic() < deadline:
        try:
            client = transport(port, address)
        except (paramiko.SSHException, OSError):
            # The per-address preauth slot limit refuses extra connections;
            # that is the expected backpressure, not a test failure.
            with attempts_lock:
                refused[0] += 1
            time.sleep(.05)
            continue
        try:
            for index in range(10):
                try:
                    client.auth_password(USER, f"guess-{address}-{index}-{time.monotonic()}")
                except paramiko.AuthenticationException:
                    continue
                except Exception:  # noqa: BLE001 - server hangup ends this socket
                    break
        except Exception as error:  # noqa: BLE001 - report the raw outcome
            errors.append(f"{address}: {type(error).__name__}: {error}")
        finally:
            client.close()
        with attempts_lock:
            attempts[0] += 1


attempts_lock = threading.Lock()


def flood(root, permits, seconds=8):
    """Measure server CPU demand while unauthenticated clients hammer the port."""
    directory = root / f"flood-{permits}"
    directory.mkdir()
    password = secrets.token_hex(16)
    write_account(directory, password, 100000)
    server = Server(directory, DROPBEAR_WIN_KDF_CONCURRENCY=str(permits))
    attempts = [0]
    refused = [0]
    errors = []
    sampler = server.cpu_sampler()
    sampler.start()
    start = time.monotonic()
    deadline = start + seconds
    threads = [threading.Thread(target=suspect_worker,
                                args=(server.port, address, deadline, attempts, refused, errors),
                                daemon=True)
               for address in FLOOD_ADDRESSES
               for _ in range(FLOOD_PER_ADDRESS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=seconds + 30)
    elapsed = time.monotonic() - start
    cpu = sampler.total
    sampler.running = False
    assert server.process.poll() is None, "listener died under load: " + server.text()[-2000:]

    # A legitimate client from an unrelated address must still authenticate.
    login_start = time.monotonic()
    client = login(server.port, password, LEGIT_ADDRESS)
    client.close()
    login_seconds = time.monotonic() - login_start
    server.close()
    assert not errors, errors
    print(f"[flood] kdf_concurrency={permits}: {len(threads)} client threads, "
          f"{attempts[0]} connection batches, {refused[0]} slot refusals, "
          f"{elapsed:.1f}s wall, {cpu:.1f}s server CPU "
          f"= {cpu / elapsed:.1f} cores, legit login {login_seconds:.1f}s", flush=True)
    return cpu / elapsed, login_seconds


def verify_abandoned_slot(root):
    """A slot must survive a connection process dying while it holds the lock."""
    directory = root / "abandon"
    directory.mkdir()
    password = secrets.token_hex(16)
    write_account(directory, password, 100000)
    server = Server(directory, DROPBEAR_WIN_KDF_CONCURRENCY="1")
    helper = subprocess.Popen([sys.executable, "-c", ABANDON_SLOT_SCRIPT],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert "ACQUIRED" in helper.stdout.readline(), "helper could not take a slot"
        helper.kill()
        helper.wait(10)
        assert helper.returncode is not None
        start = time.monotonic()
        login(server.port, password).close()
        elapsed = time.monotonic() - start
        assert elapsed < 15, f"abandoned slot was not reclaimed: {elapsed:.1f}s"
        print(f"PASS: abandoned throttle slot reclaimed, login after kill {elapsed:.1f}s",
              flush=True)
    finally:
        if helper.poll() is None:
            helper.kill()
        server.close()


def verify_first_run_setup(root):
    """First-run setup must write a hash that hashlib reproduces exactly."""
    directory = root / "setup"
    directory.mkdir()
    password = secrets.token_hex(12)
    command = [str(EXE), "-p", f"127.0.0.1:{free_port()}"]
    port = int(command[2].rsplit(":", 1)[1])
    env = dict(os.environ, DROPBEAR_WIN_DATA_DIR=str(directory),
               DROPBEAR_WIN_SHELL="cmd")
    process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        process.stdin.write(f"{USER}\n{password}\n{password}\n".encode())
        process.stdin.flush()
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("setup exited: " + process.stdout.read().decode(errors="replace"))
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError("setup did not start listening")
        stored_user, stored_hash = (directory / "account.conf").read_text().splitlines()[:2]
        algorithm, iterations, salt_text, digest_text = stored_hash.split("$")
        expected = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                       bytes.fromhex(salt_text), int(iterations)).hex()
        assert stored_user == USER, stored_user
        assert algorithm == "pbkdf2-sha256" and int(iterations) == 100000, stored_hash
        assert digest_text == expected, "first-run hash is not standard PBKDF2-HMAC-SHA256"
        login(port, password).close()
        print("PASS: first-run setup hash matches hashlib and logs in", flush=True)
    finally:
        process.terminate()
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    flood_only = "--flood-only" in sys.argv
    if flood_only:
        sys.argv.remove("--flood-only")
        EXE = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="dropbear-kdf-") as temp:
        root = Path(temp)
        if flood_only:
            flood(root, permits=2)
            flood(root, permits=16)
        else:
            verify_first_run_setup(root)
            verify_interop(root)
            verify_abandoned_slot(root)
            throttled, login_seconds = flood(root, permits=2)
            unthrottled, _ = flood(root, permits=16)
            assert throttled <= 4.0, f"throttle did not bound CPU: {throttled:.1f} cores"
            assert login_seconds <= 10.0, f"legitimate login stalled: {login_seconds:.1f}s"
            print(f"PASS: throttle held {throttled:.1f} cores vs {unthrottled:.1f} cores "
                  "unthrottled, logins stayed available", flush=True)
