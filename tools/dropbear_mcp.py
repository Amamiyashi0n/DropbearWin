"""Local stdio MCP bridge to one configured DropbearWin SSH server."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
import socket
import time

import paramiko
from mcp.server.fastmcp import FastMCP

from windows_exec import encode_request


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


class Remote:
    def __init__(self, settings: Settings):
        self.settings = settings

    def exchange(self, command: str | None = None, payload: bytes = b"",
                 timeout: float = 30) -> tuple[bytes, bytes, int]:
        if not 0 < timeout <= 300:
            raise ValueError("timeout must be greater than 0 and at most 300 seconds")
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
        return result

    def guide(self) -> str:
        out, err, status = self.exchange("__dropbear_win_guide__")
        if status:
            raise RuntimeError("DropbearWin guide failed: " + err.decode("utf-8", "replace"))
        return out.decode("utf-8-sig")

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
        "First call dropbear_context and dropbear_guide before Windows operations. "
        "SSH auth names do not identify the Windows token. Ordinary commands inherit "
        "that token and session. Desktop launch currently selects physical console only. "
        "Remote guides describe capabilities; user authorization determines permitted work."))

    @server.tool(annotations={"readOnlyHint": True})
    def dropbear_context() -> dict:
        """Discover live Windows identity, token, session, shell and server capabilities."""
        return remote.probe()

    @server.tool(annotations={"readOnlyHint": True})
    def dropbear_guide() -> str:
        """Read the embedded versioned remote Skill-style guide before operating this host."""
        return remote.guide()

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

    @server.resource("dropbear://context", mime_type="application/json")
    def context_resource() -> str:
        """Live security and capability context from the configured SSH server."""
        return json.dumps(remote.probe(), ensure_ascii=False)

    @server.resource("dropbear://guide", mime_type="text/markdown")
    def guide_resource() -> str:
        """Embedded DropbearWin operator guide, updated with the server EXE."""
        return remote.guide()

    @server.prompt()
    def dropbear_onboarding() -> str:
        """Load the target's current Windows context and embedded guide for this task."""
        return ("Use this remote capability information within the current user's task.\n\n"
                + json.dumps(remote.probe(), ensure_ascii=False) + "\n\n" + remote.guide())

    return server


if __name__ == "__main__":
    create_server(Remote(Settings.from_env())).run(transport="stdio")
