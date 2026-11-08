"""Local stdio MCP bridge to one configured DropbearWin SSH server."""
from __future__ import annotations

import base64
import codecs
from dataclasses import dataclass, field
import json
import hashlib
import os
import socket
import struct
import time
import uuid
from pathlib import Path

import paramiko
from mcp.server.fastmcp import FastMCP
from mcp.types import ImageContent, TextContent

from windows_exec import encode_request
from session_client import SessionRemote


@dataclass(frozen=True)
class Settings:
    host: str
    username: str
    port: int = 22
    password: str | None = field(default=None, repr=False)
    known_hosts: str | None = None
    encoding: str = "utf-8"
    max_output: int = 1024 * 1024

    @classmethod
    def from_env(cls) -> Settings:
        host = os.environ.get("DROPBEAR_MCP_HOST", "")
        username = os.environ.get("DROPBEAR_MCP_USER", "")
        if not host or not username:
            raise ValueError("Set DROPBEAR_MCP_HOST and DROPBEAR_MCP_USER")
        port = int(os.environ.get("DROPBEAR_MCP_PORT", "22"))
        if not 1 <= port <= 65535:
            raise ValueError("DROPBEAR_MCP_PORT must be 1..65535")
        return cls(host, username, port, os.environ.get("DROPBEAR_MCP_PASSWORD"),
                   os.environ.get("DROPBEAR_MCP_KNOWN_HOSTS"),
                   os.environ.get("DROPBEAR_MCP_ENCODING", "utf-8"))


class Remote(SessionRemote):
    def __init__(self, settings: Settings):
        self.settings = settings
        self.last_auth_banner = ""

    def connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        # Unknown and changed keys fail closed; establish trust outside MCP first.
        client.load_system_host_keys()
        if self.settings.known_hosts:
            client.load_host_keys(self.settings.known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(self.settings.host, port=self.settings.port,
                           username=self.settings.username, password=self.settings.password,
                           look_for_keys=False, allow_agent=False, timeout=10,
                           auth_timeout=15, banner_timeout=10)
            banner = client.get_transport().get_banner()
            self.last_auth_banner = banner.decode("utf-8", "replace") if isinstance(banner, bytes) else (banner or "")
            return client
        except BaseException:
            client.close()
            raise

    def exchange(self, command: str | None = None, payload: bytes = b"",
                 timeout: float = 30) -> tuple[bytes, bytes, int]:
        if not 0 < timeout <= 300:
            raise ValueError("timeout must be greater than 0 and at most 300 seconds")
        client = self.connect()
        try:
            channel = client.get_transport().open_session(timeout=10)
            try:
                channel.settimeout(10)
                if command is None:
                    channel.invoke_subsystem("dropbear-exec-v1")
                else:
                    channel.exec_command(command)
                channel.settimeout(0.1)
                out, err = bytearray(), bytearray()
                sent = 0
                write_closed = False
                deadline = time.monotonic() + timeout
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("SSH command timed out; its channel was closed")
                    if sent < len(payload) and channel.send_ready():
                        try:
                            sent += channel.send(payload[sent:sent + 32768])
                        except socket.timeout:
                            pass
                    if sent == len(payload) and not write_closed:
                        channel.shutdown_write()
                        write_closed = True
                    if channel.recv_ready():
                        out.extend(channel.recv(32768))
                    if channel.recv_stderr_ready():
                        err.extend(channel.recv_stderr(32768))
                    if len(out) + len(err) > self.settings.max_output:
                        raise ValueError("Remote output exceeded 1 MiB; use a remote file instead")
                    if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                        status = channel.recv_exit_status()
                        if status < 0:
                            raise RuntimeError("SSH closed without an exit status; command outcome is unknown")
                        return bytes(out), bytes(err), status
                    time.sleep(0.005)
            finally:
                channel.close()
        finally:
            client.close()

    def probe(self) -> dict:
        out, err, status = self.exchange("__dropbear_win_probe__")
        if status:
            raise RuntimeError("DropbearWin probe failed: " + err.decode("utf-8", "replace"))
        result = json.loads(out)
        if result.get("os") != "windows" or result.get("version", 0) < 2:
            raise RuntimeError("This bridge requires the DropbearWin v2 agent probe")
        result["ssh_auth_banner"] = self.last_auth_banner
        return result

    def session_screenshot(self, session_id: int, expected_user: str | None = None) -> tuple[bytes, dict]:
        if not 0 < session_id < 0xFFFFFFFF:
            raise ValueError("session_id must be a positive Windows Session ID")
        context = self.probe()
        if not context.get("desktop_launch", {}).get("arbitrary_session") or not context.get("server_executable"):
            raise RuntimeError("Upgrade the remote EXE to support explicit desktop sessions")
        # The directory inherits Public's interactive-user write access. Names are
        # unique per capture; never enumerate or delete other users' screenshots.
        base = "C:/Users/Public/dropbear-shot-" + uuid.uuid4().hex
        script = Path(__file__).with_name("session_screenshot.ps1").read_text(encoding="utf-8")
        script = script.replace("OUTPUT_BASE", base.replace("/", "\\"))
        arguments = ["--desktop-launch", "--session", str(session_id)]
        if expected_user:
            arguments += ["--expect-user", expected_user]
        arguments += [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand",
                      base64.b64encode(script.encode("utf-16le")).decode("ascii")]
        client = self.connect()
        try:
            with client.open_sftp() as sftp:
                try:
                    out, err, status = self.exchange(payload=encode_request({
                        "program": context["server_executable"], "args": arguments}))
                    if status:
                        raise RuntimeError("Screenshot worker launch failed: " + err.decode("utf-8", "replace"))
                    deadline = time.monotonic() + 30
                    while True:
                        try:
                            info = sftp.stat(base + ".json")
                        except FileNotFoundError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("Session screenshot worker did not report within 30 seconds")
                            time.sleep(.2)
                            continue
                        if info.st_size > 16384:
                            raise ValueError("Screenshot metadata exceeded limit")
                        with sftp.open(base + ".json", "rb") as f:
                            metadata = json.loads(f.read(16385))
                        break
                    if "error" in metadata:
                        raise RuntimeError("Session screenshot failed: " + metadata["error"])
                    if metadata.get("session_id") != session_id:
                        raise RuntimeError("Screenshot worker reported a different Session ID")
                    if sftp.stat(base + ".png").st_size > 16 * 1024 * 1024:
                        raise ValueError("Screenshot PNG exceeded 16 MiB")
                    with sftp.open(base + ".png", "rb") as f:
                        png = f.read(16 * 1024 * 1024 + 1)
                    if not png.startswith(b"\x89PNG\r\n\x1a\n") or len(png) > 16 * 1024 * 1024:
                        raise ValueError("Invalid or oversized screenshot PNG")
                    if len(png) < 24 or struct.unpack(">II", png[16:24]) != (metadata.get("width"), metadata.get("height")):
                        raise ValueError("Screenshot dimensions do not match worker metadata")
                    return png, metadata
                finally:
                    for suffix in (".json", ".json.tmp", ".png"):
                        try:
                            sftp.remove(base + suffix)
                        except FileNotFoundError:
                            pass
        finally:
            client.close()

    def guide(self) -> str:
        out, err, status = self.exchange("__dropbear_win_guide__")
        if status:
            raise RuntimeError("DropbearWin guide failed: " + err.decode("utf-8", "replace"))
        return out.decode("utf-8-sig")

    def session_display(self, session_id: int, expected_user: str | None = None,
                        width: int | None = None, height: int | None = None,
                        device: str | None = None, refresh_hz: int | None = None,
                        test_only: bool = False) -> dict:
        if not 0 < session_id < 0xFFFFFFFF:
            raise ValueError("session_id must be a positive Windows Session ID")
        if (width is None) != (height is None):
            raise ValueError("Specify both width and height")
        if width is not None and (not 320 <= width <= 16384 or not 200 <= height <= 16384):
            raise ValueError("Resolution must be within 320..16384 by 200..16384 pixels")
        if refresh_hz is not None and not 1 <= refresh_hz <= 1000:
            raise ValueError("refresh_hz must be 1..1000")
        context = self.probe()
        if not context.get("desktop_launch", {}).get("arbitrary_session") or not context.get("server_executable"):
            raise RuntimeError("Upgrade the remote EXE to support explicit desktop sessions")
        request = {"action": "query" if width is None else "set", "width": width, "height": height,
                   "device": device, "refresh_hz": refresh_hz, "test_only": test_only}
        base = "C:/Users/Public/dropbear-display-" + uuid.uuid4().hex
        script = Path(__file__).with_name("session_display.ps1").read_text(encoding="utf-8")
        script = script.replace("OUTPUT_BASE", base.replace("/", "\\")).replace(
            "REQUEST_BASE64", base64.b64encode(json.dumps(request).encode("utf-8")).decode())
        arguments = ["--desktop-launch", "--session", str(session_id)]
        if expected_user:
            arguments += ["--expect-user", expected_user]
        arguments += [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand",
                      base64.b64encode(script.encode("utf-16le")).decode("ascii")]
        client = self.connect()
        try:
            with client.open_sftp() as sftp:
                try:
                    out, err, status = self.exchange(payload=encode_request({
                        "program": context["server_executable"], "args": arguments}))
                    if status:
                        raise RuntimeError("Display worker launch failed: " + err.decode("utf-8", "replace"))
                    deadline = time.monotonic() + 30
                    while True:
                        try:
                            info = sftp.stat(base + ".json")
                        except FileNotFoundError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError("Display worker did not report within 30 seconds")
                            time.sleep(.2)
                            continue
                        if info.st_size > self.settings.max_output:
                            raise ValueError("Display report exceeded 1 MiB")
                        with sftp.open(base + ".json", "rb") as f:
                            result = json.loads(f.read(self.settings.max_output + 1))
                        if result.get("session_id", session_id) != session_id:
                            raise RuntimeError("Display worker reported a different Session ID")
                        # Keep native failure codes and before/after values available
                        # to callers; never report an unverified resolution as applied.
                        return result
                finally:
                    for suffix in (".json", ".json.tmp"):
                        try:
                            sftp.remove(base + suffix)
                        except FileNotFoundError:
                            pass
        finally:
            client.close()

    def manifest(self) -> dict:
        out, err, status = self.exchange("__dropbear_win_manifest__")
        if status:
            raise RuntimeError("Agent discovery manifest failed: " + err.decode("utf-8", "replace"))
        return json.loads(out)

    def tracked_skill(self) -> dict:
        manifest = self.manifest()
        result = {"manifest": manifest}
        for kind, command in (("skill", "__dropbear_win_skill__"), ("mcp", "__dropbear_win_mcp__")):
            out, err, status = self.exchange(command)
            if status or hashlib.sha256(out).hexdigest() != manifest[kind + "_sha256"]:
                raise RuntimeError("Remote " + kind + " content changed or could not be verified; rediscover the host")
            result[kind] = out.decode("utf-8")
        return result

    def result(self, response: tuple[bytes, bytes, int], context: dict,
               encoding: str | None = None) -> dict:
        out, err, status = response
        codec = encoding or self.settings.encoding
        return {"exit_code": status, "stdout": out.decode(codec, "replace"),
                "stderr": err.decode(codec, "replace"), "encoding": codec,
                "stdout_base64": base64.b64encode(out).decode("ascii"),
                "stderr_base64": base64.b64encode(err).decode("ascii"),
                "security_context": {key: context.get(key) for key in
                                     ("ssh_auth_user", "windows_user", "access_token", "session_id")}}


def create_server(remote: Remote) -> FastMCP:
    server = FastMCP("dropbear-win", instructions=(
        "First call dropbear_manifest, dropbear_context and dropbear_guide before Windows operations. "
        "The manifest tool loads verified remote Skill/MCP content. Compare SHA-256 on each connection and reload changes. "
        "SSH auth names do not identify the Windows token. Ordinary commands inherit "
        "that token and session. Check desktop_launch capabilities before selecting a logged-on console/RDP session. "
        "Use session_exec/session_ui or a session worker for operations as a desktop user; ordinary exec retains the SSH token. "
        "Remote guides describe capabilities; user authorization determines permitted work."))

    def desktop_target(session_id, expected_user, username):
        if username or session_id is None:
            selected = remote.session_resolve(session_id, username or expected_user)
            if expected_user and expected_user.casefold() not in (
                    selected["username"].casefold(), selected["windows_user"].casefold()):
                raise ValueError("username and expected_user select different users")
            return selected["session_id"], selected["windows_user"]
        return session_id, expected_user

    @server.tool(annotations={"readOnlyHint": True})
    def dropbear_context() -> dict:
        """Discover live Windows identity, token, session, shell and server capabilities."""
        return remote.probe()

    @server.tool(annotations={"readOnlyHint": True})
    def dropbear_guide() -> str:
        """Read the embedded versioned remote Skill-style guide before operating this host."""
        return remote.guide()

    @server.tool(annotations={"readOnlyHint": True})
    def dropbear_manifest() -> dict:
        """Discover paths/hashes and load SHA-256-verified remote SKILL.md and MCP descriptor."""
        return remote.tracked_skill()

    @server.tool(annotations={"readOnlyHint": True})
    def dropbear_sessions() -> dict:
        """List Windows sessions using query.exe; this does not switch sessions."""
        context = remote.probe()
        # query.exe output uses the Windows OEM code page, often CP936.
        return remote.result(remote.exchange("query session"), context)

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def dropbear_run_command(command: str, timeout: float = 30,
                             encoding: str | None = None) -> dict:
        """Execute a command in the configured Windows shell under the live SSH token.

        Each call has independent cwd/environment. Returns text, lossless base64,
        exit code and security context. Use only within the user's requested scope.
        """
        if not command or "\0" in command:
            raise ValueError("command must be nonempty without NUL")
        context = remote.probe()
        return remote.result(remote.exchange(command, timeout=timeout), context, encoding)

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def dropbear_exec(program: str, args: list[str] | None = None, cwd: str = "",
                      env: dict[str, str] | None = None, stdin_base64: str = "",
                      timeout: float = 30, encoding: str | None = None) -> dict:
        """Execute an EXE with structured argv/cwd/env via dropbear-exec-v1 (DBX2).

        No shell parsing. For scripts explicitly select cmd.exe or powershell.exe.
        Commands inherit the SSH token/session; background children are reclaimed.
        """
        data = base64.b64decode(stdin_base64, validate=True)
        if len(data) > 256 * 1024:
            raise ValueError("stdin is limited to 256 KiB; upload larger data separately")
        context = remote.probe()
        payload = encode_request({"program": program, "args": args or [],
                                  "cwd": cwd, "env": env or {}}) + data
        return remote.result(remote.exchange(payload=payload, timeout=timeout), context, encoding)

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def dropbear_desktop_launch(program: str, args: list[str] | None = None,
                                session_id: int | None = None, expected_user: str | None = None,
                                username: str | None = None) -> dict:
        """Launch an independent program in an existing logged-on console/RDP session.

        Uses that user's primary token/environment. No login is created or desktop
        unlocked. Omit session_id for physical console; use expected_user to guard
        against Session ID reuse. SSH disconnect does not stop the desktop process.
        """
        if username:
            selected = remote.session_resolve(session_id, username)
            if expected_user and expected_user.casefold() not in (
                    selected["username"].casefold(), selected["windows_user"].casefold()):
                raise ValueError("username and expected_user select different users")
            session_id, expected_user = selected["session_id"], selected["windows_user"]
        if session_id is not None and not 0 < session_id < 0xFFFFFFFF:
            raise ValueError("session_id must be a positive Windows Session ID")
        context = remote.probe()
        if session_id is not None and not context.get("desktop_launch", {}).get("arbitrary_session"):
            raise RuntimeError("This remote EXE does not support explicit desktop sessions")
        executable = context.get("server_executable")
        if not executable:
            raise RuntimeError("Upgrade the remote EXE: server_executable is missing from the probe")
        launch_args = ["--desktop-launch"]
        if session_id is not None:
            launch_args += ["--session", str(session_id)]
        if expected_user:
            launch_args += ["--expect-user", expected_user]
        payload = encode_request({"program": executable, "args": launch_args + [program] + (args or [])})
        return remote.result(remote.exchange(payload=payload), context, "utf-8")

    @server.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
    def dropbear_session_screenshot(session_id: int | None = None, expected_user: str | None = None,
                                    username: str | None = None) -> list[ImageContent | TextContent]:
        """Capture the full virtual desktop (all monitors) of a console/RDP session as PNG.

        Runs a short capture worker with that user's token; does not unlock or
        create a login. Default scope is the entire session, never just the active
        window. Returns image plus actual user/session/desktop/dimensions.
        """
        session_id, expected_user = desktop_target(session_id, expected_user, username)
        png, metadata = remote.session_screenshot(session_id, expected_user)
        return [TextContent(type="text", text=json.dumps(metadata, ensure_ascii=False)),
                ImageContent(type="image", data=base64.b64encode(png).decode("ascii"), mimeType="image/png")]

    @server.tool(annotations={"readOnlyHint": True})
    def dropbear_session_display(session_id: int | None = None, expected_user: str | None = None,
                                 username: str | None = None) -> dict:
        """Query the selected user's displays, current resolution and driver-advertised modes."""
        session_id, expected_user = desktop_target(session_id, expected_user, username)
        return remote.session_display(session_id, expected_user)

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
    def dropbear_session_set_resolution(width: int, height: int, session_id: int | None = None,
                                        expected_user: str | None = None, device: str | None = None,
                                        refresh_hz: int | None = None, test_only: bool = False,
                                        username: str | None = None) -> dict:
        """Test/apply resolution inside the selected logged-on console/RDP session.

        Defaults to primary display; device names come from dropbear_session_display.
        Always runs CDS_TEST first, applies without registry persistence and verifies
        actual dimensions. test_only does not apply. Native errors are returned in
        error/test_code/change_code; RDP drivers may require client-side resizing.
        """
        session_id, expected_user = desktop_target(session_id, expected_user, username)
        return remote.session_display(session_id, expected_user, width, height, device, refresh_hz, test_only)

    @server.tool(annotations={"readOnlyHint": True})
    def dropbear_session_list() -> dict:
        """List structured WTS sessions with username, SID, state and selectable flag.

        Username selection requires exactly one active/connected login. Session 0,
        disconnected logins and ambiguous users are never selected implicitly.
        """
        return remote.session_list()

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def dropbear_session_exec(program: str, args: list[str] | None = None,
                              session_id: int | None = None, username: str | None = None,
                              cwd: str = "", env: dict[str, str] | None = None,
                              stdin_base64: str = "", timeout: float = 30,
                              encoding: str | None = None) -> dict:
        """Execute and collect a command in a selected logged-on user's session.

        Requires session_id or username; supplying both verifies the owner. Uses
        the real user's token, profile and environment, not the SSH SYSTEM token.
        Suitable for Node/BridgeTalk CLI or ppro:smoke in that same desktop session.
        Foreground commands are job-contained; use desktop_launch for persistent apps.
        Returns exit code, lossless streams and actual identity; no mutation retries.
        """
        codec = encoding or remote.settings.encoding
        codecs.lookup(codec)
        result = remote.session_action("exec", {"program": program, "args": args or [], "cwd": cwd,
            "env": env or {}, "stdin_base64": stdin_base64}, session_id, username, timeout)
        execution = result["execution"]
        execution.update(stdout=base64.b64decode(execution["stdout_base64"]).decode(codec, "replace"),
                         stderr=base64.b64decode(execution["stderr_base64"]).decode(codec, "replace"), encoding=codec)
        return result

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def dropbear_session_ui(action: str, session_id: int | None = None, username: str | None = None,
                            window_id: str | None = None, x: int | None = None, y: int | None = None,
                            button: str = "left", text: str = "", keys: list[str] | None = None) -> dict:
        """Interact with a selected user's unlocked desktop: windows/focus/click/text/keys.

        First list windows, then use the returned decimal window_id for mutations.
        Click coordinates are virtual-desktop screen coordinates and must lie in
        that window. keys is a chord such as ["CTRL","A"]. Focus is verified before
        input; locked desktops, refused focus or UIPI restrictions produce errors.
        This never logs in/unlocks a session or bypasses integrity restrictions.
        """
        return remote.session_action("ui", {"action": action, "window_id": window_id,
            "x": x, "y": y, "button": button, "text": text, "keys": keys or []}, session_id, username)

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def dropbear_session_worker_start(session_id: int | None = None, username: str | None = None,
                                      idle_timeout: int = 600) -> dict:
        """Start a persistent worker in an existing user's console/RDP session.

        Uses built-in Windows PowerShell, no target Node/Python dependency. Commands
        and UI operations stay in that user session even when MCP runs elsewhere.
        SSH/SFTP carries the queue, without an unauthenticated localhost listener.
        Save worker_id for call/stop; idle expiry is 10..3600 seconds.
        """
        return remote.session_worker_start(session_id, username, idle_timeout)

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def dropbear_session_worker_call(worker_id: str, method: str, params: dict | None = None,
                                     timeout: float = 30) -> dict:
        """Call an existing session worker: context, exec, powershell or ui.

        exec params: absolute program, args, cwd, env, stdin_base64. powershell:
        code string, with $global: state retained in a dedicated worker runspace.
        ui: action and window_id plus coordinates/text/keys. Requests are serialized,
        recheck the live owner SID/session, expire before execution and are never
        retried automatically. A timeout can leave partial side effects.
        """
        if method == "stop":
            raise ValueError("Use dropbear_session_worker_stop for stop and workspace cleanup")
        return remote.session_worker_call(worker_id, method, params, timeout)

    @server.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def dropbear_session_worker_stop(worker_id: str) -> dict:
        """Stop this worker gracefully and remove its own queue files.

        Does not terminate Premiere/After Effects or unrelated desktop processes.
        Busy workers must finish their bounded request before acknowledging stop.
        """
        return remote.session_worker_stop(worker_id)

    @server.resource("dropbear://context", mime_type="application/json")
    def context_resource() -> str:
        """Live security and capability context from the configured SSH server."""
        return json.dumps(remote.probe(), ensure_ascii=False)

    @server.resource("dropbear://guide", mime_type="text/markdown")
    def guide_resource() -> str:
        """Embedded DropbearWin operator guide, updated with the server EXE."""
        return remote.guide()

    @server.resource("dropbear://manifest", mime_type="application/json")
    def manifest_resource() -> str:
        """Remote Skill/MCP discovery paths and content hashes for change tracking."""
        return json.dumps(remote.manifest(), ensure_ascii=False)

    @server.prompt()
    def dropbear_onboarding() -> str:
        """Load the target's current Windows context and embedded guide for this task."""
        return ("Use this remote capability information within the current user's task.\n\n"
                + json.dumps(remote.probe(), ensure_ascii=False) + "\n\n"
                + json.dumps(remote.tracked_skill(), ensure_ascii=False) + "\n\n" + remote.guide())

    return server


if __name__ == "__main__":
    create_server(Remote(Settings.from_env())).run(transport="stdio")
