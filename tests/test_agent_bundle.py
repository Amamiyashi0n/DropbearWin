"""Exercise the shipped EXE, including extraction upgrade and write-failure rollback.

Linux: WINEPREFIX=/absolute/prefix python3 tests/test_agent_bundle.py --wine dist/*.exe
Windows: python tests/test_agent_bundle.py path/to/dropbear-win-x64.exe
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bundle_builder", ROOT / "scripts/embed-agent-bundle.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def test_executable(executable, wine):
    expected = builder.bundle_files()
    prefix = ["wine"] if wine else []
    env = dict(os.environ, WINEDEBUG="-all")

    def winpath(path):
        return "Z:" + str(path).replace("/", "\\") if wine else str(path)

    def invoke(*args, success=True):
        result = subprocess.run(prefix + [str(executable), *args], env=env,
                                capture_output=True, timeout=30)
        assert (result.returncode == 0) == success, (result.returncode, result.stdout, result.stderr)
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="dropbear-bundle-") as temp:
        directory = Path(temp)
        invoke("--export-agent-files", winpath(directory))
        assert {p.name for p in directory.iterdir()} == set(expected)
        for name, content in expected.items():
            assert (directory / name).read_bytes() == content, name
        manifest = json.loads((directory / "bundle-manifest.json").read_bytes())
        for entry in manifest["files"]:
            content = (directory / entry["name"]).read_bytes()
            assert len(content) == entry["size"]
            assert hashlib.sha256(content).hexdigest() == entry["sha256"]
        for command, name in (("--dropbear-win-skill", "SKILL.md"), ("--dropbear-win-mcp", "mcp.json")):
            assert invoke(command) == expected[name]
        # A second extraction upgrades all generated files and preserves user files.
        (directory / "keep-user.txt").write_bytes(b"keep")
        (directory / "dropbear_mcp.py").write_bytes(b"old version")
        invoke("--export-agent-files", winpath(directory))
        assert (directory / "dropbear_mcp.py").read_bytes() == expected["dropbear_mcp.py"]
        assert (directory / "keep-user.txt").read_bytes() == b"keep"
        # Fail staging at the last entry: none of the previous files may change.
        (directory / "dropbear_mcp.py").write_bytes(b"old version")
        (directory / "bundle-manifest.json").unlink()
        (directory / "bundle-manifest.json").mkdir()
        invoke("--export-agent-files", winpath(directory), success=False)
        assert (directory / "dropbear_mcp.py").read_bytes() == b"old version"
        (directory / "bundle-manifest.json").rmdir()
        (directory / "bundle-manifest.json").write_bytes(expected["bundle-manifest.json"])
        # Fail after earlier entries were already replaced: restore their exact old bytes.
        protected = directory / "session_display.ps1"
        attribute = prefix + (["cmd", "/c", "attrib"] if wine else ["attrib"])
        subprocess.run(attribute + ["+R", winpath(protected)], env=env, check=True, capture_output=True, timeout=30)
        try:
            invoke("--export-agent-files", winpath(directory), success=False)
            assert (directory / "dropbear_mcp.py").read_bytes() == b"old version"
            assert protected.read_bytes() == expected[protected.name]
        finally:
            subprocess.run(attribute + ["-R", winpath(protected)], env=env, check=True, capture_output=True, timeout=30)
        assert not list(directory.glob("*.bundle-*")), list(directory.iterdir())
        invoke("--export-agent-files", winpath(directory))
        assert (directory / "keep-user.txt").read_bytes() == b"keep"
        assert (directory / "dropbear_mcp.py").read_bytes() == expected["dropbear_mcp.py"]
        # On-disk discovery paths must follow an installed marker beside the EXE.
        installed = directory / executable.name
        installed.write_bytes(executable.read_bytes())
        (directory / "dropbear-win.installed").write_bytes(b"")
        result = subprocess.run(prefix + [str(installed), "--dropbear-win-manifest"],
                                env=env, capture_output=True, check=True, timeout=30)
        discovered = json.loads(result.stdout)
        assert discovered["bundle_directory"].lower() == winpath(directory).lower(), discovered
        assert discovered["skill_sha256"] == hashlib.sha256(expected["SKILL.md"]).hexdigest()
        assert discovered["mcp_sha256"] == hashlib.sha256(expected["mcp.json"]).hexdigest()
    print("PASS embedded bundle: extraction, upgrade, hashing, rollback, flat discovery:", executable.name)


def test_wine_uninstall(executable):
    """Run the real uninstaller in a Wine-only fixture, never on the target host."""
    assert os.name != "nt" and os.environ.get("WINEPREFIX"), "Requires an explicit test Wine prefix"
    prefix = Path(os.environ["WINEPREFIX"]).resolve()
    directory = prefix / "drive_c/Program Files/DropbearWin"
    data = prefix / "drive_c/ProgramData/DropbearWin"
    assert not directory.exists() and not data.exists(), "Refusing to overwrite existing Wine fixture data"
    expected = builder.bundle_files()
    env = dict(os.environ, WINEDEBUG="-all")

    def invoke(program, *args, success=True):
        result = subprocess.run(["wine", str(program), *args], env=env,
                                capture_output=True, timeout=30)
        assert (result.returncode == 0) == success, (result.returncode, result.stdout, result.stderr)

    try:
        for purge in (False, True):
            directory.mkdir(parents=True, exist_ok=True)
            data.mkdir(parents=True, exist_ok=True)
            for name, content in expected.items():
                (directory / name).write_bytes(content)
            installed = directory / "dropbear-win-x64.exe"
            installed.write_bytes(executable.read_bytes())
            (directory / "dropbear-win.installed").write_bytes(b"")
            (directory / "uninstall-dropbear-service.cmd").write_bytes(b"test")
            # Unknown files must survive both uninstall modes.
            (directory / "keep-user.txt").write_bytes(b"user content")
            (data / "account.conf").write_bytes(b"fixture account")
            (data / "hostkey_ed25519").write_bytes(b"fixture host key")
            invoke(installed, "--uninstall", *(["--purge-data"] if purge else []))
            assert all(not (directory / name).exists() for name in expected)
            assert not (directory / "uninstall-dropbear-service.cmd").exists()
            assert (directory / "keep-user.txt").read_bytes() == b"user content"
            if purge:
                assert not data.exists()
            else:
                assert (data / "account.conf").read_bytes() == b"fixture account"
                assert (data / "hostkey_ed25519").read_bytes() == b"fixture host key"
        print("PASS real uninstall: embedded resources removed, unknown files preserved, default data retention and purge")
    finally:
        # Only these two fixture directories were created after asserting absence.
        import shutil
        shutil.rmtree(directory, ignore_errors=True)
        shutil.rmtree(data, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wine", action="store_true")
    parser.add_argument("--wine-uninstall", action="store_true", help="Also exercise uninstall in an empty Wine fixture")
    parser.add_argument("executables", nargs="+", type=Path)
    args = parser.parse_args()
    for executable in args.executables:
        test_executable(executable.resolve(), args.wine)
    if args.wine_uninstall:
        assert args.wine
        test_wine_uninstall(args.executables[0].resolve())
