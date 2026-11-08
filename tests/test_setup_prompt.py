"""Exercise actual startup prompts using a console and disposable SCM entries.

Linux/Wine only; requires an explicit test WINEPREFIX and no existing DropbearWin
installation there. Builds the small console driver with MinGW-w64.
"""
import argparse
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executables", nargs="+", type=Path)
    args = parser.parse_args()
    assert os.name != "nt" and os.environ.get("WINEPREFIX"), "Use an explicit disposable Wine prefix"
    prefix = Path(os.environ["WINEPREFIX"]).resolve()
    managed = prefix / "drive_c/Program Files/DropbearWin"
    installed_data = prefix / "drive_c/ProgramData/DropbearWin"
    assert not managed.exists() and not installed_data.exists(), "Existing installation must not be modified"
    driver = ROOT / "build/setup-console-probe.exe"
    subprocess.run(["x86_64-w64-mingw32-gcc", "-mcrtdll=msvcrt-os", "-municode", "-O2", "-static",
                    str(ROOT / "tests/windows_setup_prompt.c"), "-o", str(driver), "-ladvapi32", "-luser32"], check=True)
    env = dict(os.environ, WINEDEBUG="-all")
    keepalive = subprocess.Popen(["wine", "cmd"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=env)
    subprocess.run(["wine", "cmd", "/c", "ver"], env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)

    def winpath(path):
        path = Path(path).resolve()
        try: return "C:\\" + str(path.relative_to(prefix / "drive_c")).replace("/", "\\")
        except ValueError: return "Z:" + str(path).replace("/", "\\")

    try:
        for artifact in args.executables:
            artifact = artifact.resolve()
            for mode, expected in (("new", "Register this server"),
                                   ("portable-service", "Continue with the installation?"),
                                   ("first-run-portable-service", "Continue with the installation?"),
                                   ("managed", "-"),
                                   ("missing-marker", "Continue with the installation?"),
                                   ("upgrade", "Continue with the upgrade?"),
                                   ("foreign", "Continue with the replacement?"),
                                   ("confirm-y", "Register this server")):
                with tempfile.TemporaryDirectory(prefix="dropbear-setup-") as temp:
                    portable = Path(temp)
                    exe = portable / "dropbear-win-x64.exe"
                    managed.mkdir(parents=True, exist_ok=True)
                    target = managed / exe.name
                    shutil.copy2(artifact, exe)
                    shutil.copy2(artifact, target)
                    marker = managed / "dropbear-win.installed"
                    if mode in ("managed", "upgrade"): marker.write_bytes(b"")
                    if mode in ("managed", "missing-marker"): exe = target
                    data = exe.parent / "dropbear-win-data"
                    data.mkdir(exist_ok=True)
                    if mode != "first-run-portable-service":
                        salt = secrets.token_bytes(32)
                        digest = hashlib.pbkdf2_hmac("sha256", b"fixture-only-password", salt, 100000)
                        (data / "account.conf").write_text(f"setup-fixture\npbkdf2-sha256$100000${salt.hex()}${digest.hex()}\n")
                    fixture_env = dict(env, DROPBEAR_WIN_DATA_DIR=winpath(data),
                                       DROPBEAR_WIN_ACCOUNT_FILE=winpath(data / "account.conf"))
                    with socket.socket() as sock:
                        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
                    if mode in ("portable-service", "first-run-portable-service", "managed", "missing-marker"):
                        service_binary = winpath(exe)
                    elif mode == "upgrade": service_binary = winpath(target)
                    elif mode == "foreign": service_binary = r"C:\Windows\System32\cmd.exe"
                    else: service_binary = "-"
                    answer = "y" if mode == "confirm-y" else "n"
                    result = subprocess.run(["wine", str(driver), winpath(exe), str(port), service_binary,
                                             expected, answer], env=fixture_env, capture_output=True, timeout=50)
                    text = result.stdout.decode("utf-8", "replace")
                    assert result.returncode == 0, (artifact.name, mode, result.returncode, text, result.stderr)
                    if mode in ("portable-service", "first-run-portable-service", "new", "upgrade", "foreign"):
                        assert not (portable / "uninstall-dropbear-service.cmd").exists(), text
                    if mode == "first-run-portable-service":
                        assert "Configuration created in" in text, text
                    if mode == "confirm-y":
                        assert marker.exists() and (managed / "SKILL.md").exists(), text
                        assert (installed_data / "account.conf").exists(), text
                        assert (managed / "uninstall-dropbear-service.cmd").exists(), text
                        assert (managed / "dropbear-win-x64.exe").read_bytes() == artifact.read_bytes()
                        for _ in range(60):
                            if not exe.exists(): break
                            time.sleep(.1)
                        assert not exe.exists() and not data.exists(), "Portable cleanup did not finish"
                    print("PASS", artifact.name, mode, flush=True)
                shutil.rmtree(managed, ignore_errors=True)
                shutil.rmtree(installed_data, ignore_errors=True)
    finally:
        shutil.rmtree(managed, ignore_errors=True)
        shutil.rmtree(installed_data, ignore_errors=True)
        if keepalive.poll() is None: keepalive.communicate(b"exit\r\n", timeout=10)


if __name__ == "__main__": main()
