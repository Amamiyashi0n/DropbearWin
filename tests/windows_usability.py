"""Real Windows startup, restart, log and console usability tests.

Uses disposable accounts/processes. The default-port test first requires 52222
to be unused, then takes over only fixtures it creates. Requires Paramiko/psutil.
"""
import concurrent.futures
import contextlib
import ctypes
import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import secrets
import time

import psutil
from windows_lifecycle import account, connect, eventually, free_port, task, gone
from windows_native import execute
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def console_read(pid):
    class Coord(ctypes.Structure):
        _fields_ = [("x", ctypes.c_short), ("y", ctypes.c_short)]
    class Rect(ctypes.Structure):
        _fields_ = [(key, ctypes.c_short) for key in ("left", "top", "right", "bottom")]
    class Info(ctypes.Structure):
        _fields_ = [("size", Coord), ("cursor", Coord), ("attributes", ctypes.c_ushort),
                    ("window", Rect), ("maximum", Coord)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FreeConsole()
    assert kernel.AttachConsole(pid), ctypes.get_last_error()
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                                  ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    handle = kernel.CreateFileW("CONOUT$", 0xC0000000, 3, None, 3, 0, None)
    assert handle != ctypes.c_void_p(-1).value
    kernel.GetConsoleScreenBufferInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Info)]
    kernel.ReadConsoleOutputCharacterW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                                  ctypes.c_ulong, Coord, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    try:
        info = Info()
        assert kernel.GetConsoleScreenBufferInfo(handle, ctypes.byref(info))
        length = min(info.size.x * (info.cursor.y + 1), 500000)
        text = ctypes.create_unicode_buffer(length + 1)
        read = ctypes.c_ulong()
        assert kernel.ReadConsoleOutputCharacterW(handle, text, length, Coord(0, 0), ctypes.byref(read))
        lines = [text.value[index:index + info.size.x].rstrip() for index in range(0, read.value, info.size.x)]
    finally:
        kernel.CloseHandle(handle)
        kernel.FreeConsole()
    print(json.dumps(lines), flush=True)


def console_control(pid, mode):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FreeConsole()
    assert kernel.AttachConsole(pid), ctypes.get_last_error()
    handler_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_ulong)
    handler = handler_type(lambda event: 1)
    assert kernel.SetConsoleCtrlHandler(handler, True)
    if mode == "close":
        kernel.GetConsoleWindow.restype = ctypes.c_void_p
        window = kernel.GetConsoleWindow()
        assert window
        user = ctypes.WinDLL("user32", use_last_error=True)
        user.PostMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
        assert user.PostMessageW(window, 0x0010, 0, 0)
    else:
        assert kernel.GenerateConsoleCtrlEvent(0 if mode == "ctrl-c" else 1, 0), ctypes.get_last_error()
    time.sleep(.2)
    kernel.FreeConsole()


def console_write(pid, text):
    """Queue keystrokes into another process's console input buffer.

    Must run as a subprocess (--console-write): attaching detaches this
    process from its own console, like console_read and console_control.
    """
    class KeyEvent(ctypes.Structure):
        _fields_ = [("key_down", ctypes.c_int), ("repeat", ctypes.c_ushort),
                    ("virtual_key", ctypes.c_ushort), ("scan", ctypes.c_ushort),
                    ("unicode", ctypes.c_wchar), ("state", ctypes.c_ulong)]
    class Record(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ushort), ("key", KeyEvent)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FreeConsole()
    assert kernel.AttachConsole(pid), ctypes.get_last_error()
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                                  ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    handle = kernel.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)
    assert handle != ctypes.c_void_p(-1).value
    records = (Record * (2 * len(text)))()
    for index, char in enumerate(text):
        for offset, down in ((0, 1), (1, 0)):
            records[2 * index + offset].type = 1
            records[2 * index + offset].key = KeyEvent(down, 1, 0, 0, char, 0)
    kernel.WriteConsoleInputW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Record),
                                          ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    written = ctypes.c_ulong()
    assert kernel.WriteConsoleInputW(handle, records, 2 * len(text), ctypes.byref(written))
    assert written.value == 2 * len(text), written.value
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle(handle)
    kernel.FreeConsole()


def queue_console_text(pid, text):
    subprocess.run([sys.executable, __file__, "--console-write", str(pid), text],
                   check=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)


def listeners(port):
    return {item.pid for item in psutil.net_connections(kind="tcp")
            if item.status == "LISTEN" and item.laddr.port == port}


class Deployment:
    def __init__(self, executable, directory):
        self.executable = executable
        self.directory = directory
        self.password = account(directory)
        self.env = dict(os.environ, DROPBEAR_WIN_DATA_DIR=str(directory),
                        DROPBEAR_WIN_ACCOUNT_FILE=str(directory / "account.conf"),
                        DROPBEAR_WIN_SHELL="cmd",
                        DROPBEAR_WIN_CONN_RATE="64")
        self.processes = []
        self.logs = []

    def start(self, port, *args, console=False, address="127.0.0.1", restricted=False, console_output=False, setup_input=None):
        path = self.directory / f"server-{len(self.logs)}.log"
        self.logs.append(path)
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = 0
        with path.open("wb") as log:
            process = subprocess.Popen([self.executable, "-p", f"{address}:{port}", *args],
                env=self.env, stdin=subprocess.PIPE if setup_input else (None if console_output else subprocess.DEVNULL),
                stdout=None if console_output else log,
                stderr=None if console_output else log,
                creationflags=(subprocess.CREATE_NEW_CONSOLE if console else subprocess.CREATE_NO_WINDOW)
                    | (4 if restricted else 0),
                startupinfo=info)
        self.processes.append(process)
        if setup_input:
            process.stdin.write(setup_input)
            process.stdin.close()
        if restricted:
            # The desktop agent may inherit enabled SeDebugPrivilege. Disable
            # privileges only in this suspended fixture, so its DACL denial
            # test models a normal launcher instead of bypassing the DACL.
            security = ctypes.WinDLL("advapi32", use_last_error=True)
            token = ctypes.c_void_p()
            security.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
            security.AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                                      ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
            assert security.OpenProcessToken(int(process._handle), 0x28, ctypes.byref(token))
            try:
                assert security.AdjustTokenPrivileges(token, True, None, 0, None, None)
            finally:
                ctypes.windll.kernel32.CloseHandle(token)
            native = ctypes.WinDLL("ntdll")
            native.NtResumeProcess.argtypes = [ctypes.c_void_p]
            assert native.NtResumeProcess(int(process._handle)) == 0
        return process

    def ready(self, process, port):
        def check():
            assert process.poll() is None, self.logtext()
            return process.pid in listeners(port)
        eventually(check, timeout=15)

    def logtext(self):
        return "\n".join(path.read_text(errors="replace") for path in self.logs)

    def close(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
        # Parent and connection log handles close asynchronously on hard stop.
        for path in self.logs:
            def release():
                try:
                    path.unlink(missing_ok=True)
                    return True
                except PermissionError:
                    return False
            eventually(release)


@contextlib.contextmanager
def deployment(executable):
    with tempfile.TemporaryDirectory(prefix="dropbear usability ") as temp:
        fixture = Deployment(executable, Path(temp))
        try:
            yield fixture
        except Exception:
            print(fixture.logtext(), file=sys.stderr)
            raise
        finally:
            fixture.close()


def run(executable):
    with deployment(executable) as fixture:
        (fixture.directory / "account.conf").unlink()
        port = free_port()
        process = fixture.start(port, setup_input=(
            f"agent\nfirst-password\ndifferent-password\n"
            f"{fixture.password}\n{fixture.password}\n").encode())
        fixture.ready(process, port)
        with connect(port, fixture.password) as client:
            assert execute(client, "echo first-run")[2] == 0
        assert b"pbkdf2-sha256$" in (fixture.directory / "account.conf").read_bytes()
        assert "Passwords do not match. Please try again." in fixture.logtext()
    print("PASS: first-run account setup produces a usable authenticated server", flush=True)

    with deployment(executable) as fixture:
        port = free_port()
        first = fixture.start(port)
        fixture.ready(first, port)
        second = fixture.start(port)
        assert second.wait(timeout=10) != 0
        assert listeners(port) == {first.pid}
        assert "RUNNING" not in fixture.logs[-1].read_text(errors="replace")
        with connect(port, fixture.password) as client:
            assert execute(client, "echo original")[0].strip() == b"original"
    print("PASS: nondefault port collision rejected; original remains healthy", flush=True)

    assert not listeners(52222), "52222 already has a real listener; default-port fixture not started"
    with deployment(executable) as fixture:
        current = fixture.start(52222)
        fixture.ready(current, 52222)
        identity = {name: (fixture.directory / name).read_bytes()
                    for name in ("account.conf", "hostkey_ed25519")}
        for cycle in range(3):
            with connect(52222, fixture.password) as client:
                channel, pids = task(client)
                replacement = fixture.start(52222)
                fixture.ready(replacement, 52222)
                current.wait(timeout=10)
                eventually(lambda: all(gone(pid) for pid in pids))
                eventually(lambda: not client.get_transport().is_active())
            assert listeners(52222) == {replacement.pid}
            current = replacement
            assert all((fixture.directory / name).read_bytes() == data for name, data in identity.items())
        with connect(52222, fixture.password) as client:
            assert execute(client, "echo replaced")[0].strip() == b"replaced"
            try:
                client.get_transport().request_port_forward("127.0.0.1", 52222)
            except Exception:
                pass
            else:
                raise AssertionError("forward request rebound listener")
            assert execute(client, "echo still-alive")[2] == 0
        assert "terminating listening PID" in fixture.logtext()
        # Serializing concurrent starts prevents shared binding, even if the
        # later starter intentionally replaces the earlier starter.
        contenders = [fixture.start(52222) for _ in range(3)]
        eventually(lambda: sum(p.poll() is None for p in [current, *contenders]) == 1, timeout=20)
        survivor = next(p for p in contenders if p.poll() is None)
        fixture.ready(survivor, 52222)
        assert listeners(52222) == {survivor.pid}
        with connect(52222, fixture.password) as client:
            assert execute(client, "echo last-start")[2] == 0
    print("PASS: 52222 takeover/repeated and concurrent starts; old task trees reclaimed", flush=True)

    # A different server implementation on 52222 is also an explicitly scoped
    # port owner. Spawn it separately so the test controller is never a target.
    with deployment(executable) as fixture:
        child_pidfile = fixture.directory / "legacy-child.pid"
        other = subprocess.Popen([sys.executable, "-c",
            "import socket,time,subprocess,sys,pathlib; s=socket.socket(); "
            "s.bind(('127.0.0.1',52222)); s.listen(); "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)", str(child_pidfile)],
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            eventually(lambda: other.pid in listeners(52222))
            eventually(lambda: child_pidfile.exists())
            legacy_child = int(child_pidfile.read_text())
            replacement = fixture.start(52222)
            fixture.ready(replacement, 52222)
            other.wait(timeout=10)
            eventually(lambda: gone(legacy_child))
            assert listeners(52222) == {replacement.pid}
        finally:
            if other.poll() is None:
                other.terminate()
            other.wait(timeout=5)
    print("PASS: 52222 takeover reclaims listener and legacy child without a watcher", flush=True)

    with deployment(executable) as fixture:
        other = subprocess.Popen([sys.executable, "-c",
            "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',52222)); s.listen(); time.sleep(60)"],
            creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            eventually(lambda: other.pid in listeners(52222))
            security = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            descriptor = ctypes.c_void_p()
            security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
                ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
            security.SetKernelObjectSecurity.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            assert security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                "D:(D;;0x1;;;WD)(A;;GA;;;WD)", 1, ctypes.byref(descriptor), None)
            try:
                assert security.SetKernelObjectSecurity(int(other._handle), 4, descriptor)
            finally:
                kernel.LocalFree(descriptor)
            rejected = fixture.start(52222, restricted=True)
            assert rejected.wait(timeout=10) != 0
            assert other.poll() is None and listeners(52222) == {other.pid}
            assert "opening PID" in fixture.logtext() and "RUNNING" not in fixture.logtext()
        finally:
            # This handle predates the test DACL and retains termination rights.
            if other.poll() is None:
                other.terminate()
            other.wait(timeout=5)
    print("PASS: denied takeover reports PID/error, does not falsely announce RUNNING", flush=True)

    with deployment(executable) as fixture:
        old = fixture.start(52222, address="[::1]")
        fixture.ready(old, 52222)
        new = fixture.start(52222, address="[::1]")
        fixture.ready(new, 52222)
        old.wait(timeout=10)
        assert listeners(52222) == {new.pid}
    print("PASS: IPv6 default-port owner takeover", flush=True)

    for close_window in (False, True):
        with deployment(executable) as fixture:
            port = free_port()
            process = fixture.start(port, console=True)
            fixture.ready(process, port)
            with connect(port, fixture.password) as client:
                channel, pids = task(client)
                control = subprocess.run([sys.executable, __file__, "--console-control", str(process.pid),
                                "close" if close_window else "break"],
                               timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                assert control.returncode == 0 or (close_window and control.returncode == 0xC000013A), control.returncode
                process.wait(timeout=10)
                eventually(lambda: all(gone(pid) for pid in pids))
                eventually(lambda: not client.get_transport().is_active())
            assert not (fixture.directory / "dropbear.pid").exists(), "orderly stop left pidfile"
            restart = fixture.start(port)
            fixture.ready(restart, port)
            with connect(port, fixture.password) as client:
                assert execute(client, "echo restarted")[2] == 0
    print("PASS: real console Ctrl+Break/window close, task cleanup and immediate restart", flush=True)
    console_ctrl_c_test(executable)

    with deployment(executable) as fixture:
        port = free_port()
        fixture.env["DROPBEAR_WIN_TRACE_EXEC"] = "1"
        process = fixture.start(port)
        fixture.ready(process, port)
        def churn(index):
            with connect(port, fixture.password) as client:
                assert execute(client, "echo log-test")[2] == 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(churn, range(60)))
        time.sleep(1)
        lines = fixture.logtext().splitlines()
        events = [line for line in lines if any(word in line for word in
                   ("Child connection", "Password auth succeeded", "Exit (agent)"))]
        assert sum("Password auth succeeded" in line for line in events) == 60, events
        assert sum("Exit (agent)" in line for line in events) == 60, events
        assert sum(line == "SSH exec (13 bytes): echo log-test" for line in lines) == 60, lines
        pattern = re.compile(r"^\[\d+\] [A-Za-z]{3} +\d+ \d\d:\d\d:\d\d .+$")
        assert all(pattern.fullmatch(line) and line.count("[") == 1 for line in events), events
    print("PASS: concurrent connection logs retain complete lines and event counts", flush=True)

    with deployment(executable) as fixture:
        port = free_port()
        fixture.env["DROPBEAR_WIN_TRACE_EXEC"] = "1"
        process = fixture.start(port, console=True, console_output=True)
        queue_console_text(process.pid, "n\r")
        fixture.ready(process, port)
        def console_churn(index):
            with connect(port, fixture.password) as client:
                assert execute(client, "echo console-log")[2] == 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(console_churn, range(20)))
        time.sleep(.5)
        captured = subprocess.run([sys.executable, __file__, "--console-read", str(process.pid)],
            check=True, capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        rows = json.loads(captured.stdout)
        events = [row for row in rows if "Password auth succeeded" in row or "Exit (agent)" in row]
        assert sum("Password auth succeeded" in row for row in events) == 20, rows
        assert sum("Exit (agent)" in row for row in events) == 20, rows
        assert sum(row == "SSH exec (16 bytes): echo console-log" for row in rows) == 20, rows
        assert all(re.match(r"^\[\d+\] [A-Za-z]{3} +\d+ \d\d:\d\d:\d\d ", row) for row in events), events
    print("PASS: actual Windows console buffer has intact concurrent log lines", flush=True)

    with deployment(executable) as fixture:
        port = free_port()
        (fixture.directory / "dropbear.pid").write_text("999999\n")
        process = fixture.start(port)
        fixture.ready(process, port)
        eventually(lambda: (fixture.directory / "dropbear.pid").read_text().strip() == str(process.pid))
        second = fixture.start(free_port(), "-p", f"127.0.0.1:{port}")
        assert second.wait(timeout=10) != 0
        assert "RUNNING" not in fixture.logs[-1].read_text(errors="replace")
        assert process.poll() is None
    print("PASS: stale pidfile ignored; partial multi-port failure never advertises RUNNING", flush=True)

    with deployment(executable) as fixture:
        (fixture.directory / "account.conf").unlink()
        for option in ("-h", "-V"):
            result = subprocess.run([executable, option], env=fixture.env,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            assert b"SSH username" not in result.stdout + result.stderr
            assert b"Dropbear" in result.stdout + result.stderr
        for bad in ("", "agent\ninvalid\n", "agent\npbkdf2-sha256$100000$bad$bad\n"):
            (fixture.directory / "account.conf").write_text(bad)
            result = subprocess.run([executable, "-p", f"127.0.0.1:{free_port()}"], env=fixture.env,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            assert result.returncode != 0 and b"Invalid or unreadable account" in result.stderr
            assert b"RUNNING" not in result.stdout
        account(fixture.directory)
        result = subprocess.run([executable, "-p", "127.0.0.1:0"],
            env=dict(fixture.env, DROPBEAR_WIN_SHELL="misspelled"),
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        assert result.returncode != 0 and b"must be cmd or powershell" in result.stderr
    print("PASS: help/version without setup; corrupt accounts and invalid shell fail clearly", flush=True)

    with tempfile.TemporaryDirectory(prefix="dropbear path 空间 ") as temp:
        deployed = Path(temp) / "dropbear win.exe"
        shutil.copy2(executable, deployed)
        with deployment(str(deployed)) as fixture:
            port = free_port()
            process = fixture.start(port)
            fixture.ready(process, port)
            with connect(port, fixture.password) as client:
                assert execute(client, "echo path-ok")[0].strip() == b"path-ok"
    print("PASS: executable path containing spaces and Chinese characters", flush=True)


def service_takeover(executable):
    assert not listeners(52222), "52222 already has a real listener"
    name = "DropbearUsability_" + secrets.token_hex(6)
    sc = str(Path(os.environ["SystemRoot"]) / "System32" / "sc.exe")
    def command(*args, check=True):
        return subprocess.run([sc, *args], check=check, capture_output=True, timeout=15)
    with tempfile.TemporaryDirectory(prefix="dropbear service replacement ") as temp:
        folder = Path(temp)
        deployed = folder / "dropbear-win.exe"
        shutil.copy2(executable, deployed)
        password = account(folder / "dropbear-win-data")
        binary = subprocess.list2cmdline([str(deployed), "--service", name, "-p", "127.0.0.1:52222"])
        command("create", name, "binPath=", binary, "start=", "demand")
        try:
            command("start", name)
            eventually(lambda: b"RUNNING" in command("query", name).stdout)
            with deployment(executable) as fixture:
                with connect(52222, password) as client:
                    channel, pids = task(client)
                    replacement = fixture.start(52222)
                    fixture.ready(replacement, 52222)
                    eventually(lambda: b"STOPPED" in command("query", name).stdout)
                    eventually(lambda: all(gone(pid) for pid in pids))
                with connect(52222, fixture.password) as client:
                    assert execute(client, "echo console-replaced-service")[2] == 0
                command("start", name)
                eventually(lambda: b"RUNNING" in command("query", name).stdout)
                replacement.wait(timeout=10)
                with connect(52222, password) as client:
                    assert execute(client, "echo service-replaced-console")[2] == 0
            command("stop", name)
            eventually(lambda: b"STOPPED" in command("query", name).stdout)
            eventually(lambda: not listeners(52222))
        finally:
            command("stop", name, check=False)
            eventually(lambda: b"STOPPED" in command("query", name).stdout)
            command("delete", name)
            time.sleep(.5)
    print("PASS: real SCM service and console replace each other on 52222", flush=True)


def console_ctrl_c_test(executable):
    with deployment(executable) as fixture:
        port = free_port()
        process = fixture.start(port, console=True)
        fixture.ready(process, port)
        with connect(port, fixture.password) as client:
            channel, pids = task(client)
            subprocess.run([sys.executable, __file__, "--console-control", str(process.pid), "ctrl-c"],
                           check=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            process.wait(timeout=10)
            eventually(lambda: all(gone(pid) for pid in pids))
        assert not (fixture.directory / "dropbear.pid").exists()
    print("PASS: real console Ctrl+C reclaims tasks and removes pidfile", flush=True)


def interactive_register_test(executable):
    """On a disposable Windows host, install from a portable copy and verify
    that the service reads migrated ProgramData rather than the old directory.
    Never disturb an existing DropbearWin installation on a developer host.
    """
    sc = str(Path(os.environ["SystemRoot"]) / "System32" / "sc.exe")
    def command(*args, check=True):
        return subprocess.run([sc, *args], check=check, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=15)
    install_dir = Path(os.environ["SystemDrive"] + r"\Program Files\DropbearWin")
    installed_data = Path(os.environ["ProgramData"]) / "DropbearWin"
    if (install_dir.exists() or installed_data.exists() or
            command("query", "DropbearWin", check=False).returncode == 0):
        print("SKIP: installation test needs an unused Windows host", flush=True)
        return
    with tempfile.TemporaryDirectory(prefix="dropbear portable ") as temp:
        deployed = Path(temp) / "dropbear-win.exe"
        shutil.copy2(executable, deployed)
        portable_data = Path(temp) / "dropbear-win-data"
        password = account(portable_data)
        original_account = (portable_data / "account.conf").read_bytes()
        port = free_port()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("DROPBEAR_WIN_")}
        process = subprocess.Popen([str(deployed), "-p", f"127.0.0.1:{port}"],
                                   env=env, creationflags=subprocess.CREATE_NEW_CONSOLE)
        try:
            queue_console_text(process.pid, "y\r")
            assert process.wait(timeout=30) == 0
            installed_exe = install_dir / deployed.name
            assert installed_exe.is_file()
            assert (install_dir / "dropbear-win.installed").is_file()
            assert (installed_data / "account.conf").read_bytes() == original_account
            eventually(lambda: not deployed.exists())
            eventually(lambda: not portable_data.exists())
            eventually(lambda: not Path(temp).exists())
            query = " ".join(command("qc", "DropbearWin").stdout.decode(
                errors="replace").replace('"', ' ').split())
            assert "AUTO_START" in query and str(installed_exe) in query, query
            command("start", "DropbearWin")
            eventually(lambda: b"RUNNING" in command("query", "DropbearWin").stdout)
            with connect(port, password) as client:
                assert execute(client, "echo installed")[0].strip() == b"installed"
            assert (installed_data / "hostkey_ed25519").is_file()
            assert (installed_data / "service.log").is_file()
            removed = subprocess.run([str(installed_exe), "--uninstall"], env=env,
                                     capture_output=True, timeout=45)
            assert removed.returncode == 0, removed.stdout + removed.stderr
            eventually(lambda: command("query", "DropbearWin", check=False).returncode != 0,
                       timeout=20)
            assert (installed_data / "account.conf").read_bytes() == original_account
            assert (installed_data / "hostkey_ed25519").is_file()
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            command("stop", "DropbearWin", check=False)
            command("delete", "DropbearWin", check=False)
            eventually(lambda: command("query", "DropbearWin", check=False).returncode != 0,
                       timeout=20)
            shutil.rmtree(install_dir, ignore_errors=True)
            shutil.rmtree(installed_data, ignore_errors=True)
    print("PASS: portable EXE and account migrated; installed service uses ProgramData", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "--console-control":
        console_control(int(sys.argv[2]), sys.argv[3])
    elif sys.argv[1] == "--console-read":
        console_read(int(sys.argv[2]))
    elif sys.argv[1] == "--console-write":
        console_write(int(sys.argv[2]), sys.argv[3])
    else:
        run(str(Path(sys.argv[1]).resolve()))
        if "--service" in sys.argv[2:]:
            service_takeover(str(Path(sys.argv[1]).resolve()))
            interactive_register_test(str(Path(sys.argv[1]).resolve()))
