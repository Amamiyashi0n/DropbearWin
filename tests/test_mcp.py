"""MCP stdio contract tests; --live uses connection environment for safe probes."""
import asyncio
import base64
import json
import hashlib
import os
import socket
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from dropbear_mcp import Remote, Settings, create_server
import dropbear_mcp


class FixtureRemote(Remote):
    def session_list(self):
        return {"sessions": [{"session_id": 3, "username": "agent", "windows_user": "host\\agent",
            "sid": "S-1-5-21-fixture", "state": "Active", "selectable": True}]}

    def session_worker_start(self, session_id=None, username=None, idle_timeout=600):
        return {"worker_id": "a" * 32, "security_context": self.session_resolve(session_id, username)}

    def session_worker_call(self, worker_id, method, params=None, timeout=30):
        return {"session_id": 3, "windows_user": "host\\agent", "method": method}

    def session_worker_stop(self, worker_id):
        return {"stopped": True}

    def session_action(self, method, params, session_id=None, username=None, timeout=30):
        return {"security_context": self.session_resolve(session_id, username),
                "execution": {"exit_code": 7, "stdout_base64": "b2s=", "stderr_base64": ""}}

    def session_display(self, session_id, expected_user=None, width=None, height=None,
                        device=None, refresh_hz=None, test_only=False):
        if width is None:
            return {"session_id": session_id, "displays": [{"current": {"width": 1600, "height": 900}}]}
        return {"session_id": session_id, "applied": not test_only, "verified": not test_only,
                "test_code": 0, "after": {"width": width, "height": height}}

    def session_screenshot(self, session_id, expected_user=None):
        return base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a5v8AAAAASUVORK5CYII="), {
            "session_id": session_id, "width": 1, "height": 1, "windows_user": "host\\agent"}
    def manifest(self):
        return {"schema_version": 1, "skill_sha256": hashlib.sha256(b"skill").hexdigest(),
                "mcp_sha256": hashlib.sha256(b"{}").hexdigest()}

    def probe(self):
        return {"version": 2, "os": "windows", "session_id": 0,
                "windows_user": "NT AUTHORITY\\SYSTEM", "shell": "cmd"}

    def guide(self):
        return "# Fixture guide\nUse the live Windows token."

    def exchange(self, command=None, payload=b"", timeout=30):
        if command == "__dropbear_win_skill__":
            return b"skill", b"", 0
        if command == "__dropbear_win_mcp__":
            return b"{}", b"", 0
        if command == "failure":
            raise TimeoutError("fixture timeout")
        if command is None:
            assert payload.startswith(b"DBX2")
            return b"binary\x00\xff", b"stderr", 7
        return ("session 3: agent" if command == "query session" else "echo-ok").encode(), b"", 0


class MCPContract(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_surface(self):
        params = StdioServerParameters(command=sys.executable, args=[__file__, "--fixture"])
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as client:
                initialized = await client.initialize()
                self.assertIn("dropbear_context", initialized.instructions)
                listed = await client.list_tools()
                tools = {tool.name: tool for tool in listed.tools}
                self.assertEqual(set(tools), {"dropbear_context", "dropbear_guide",
                    "dropbear_manifest", "dropbear_sessions", "dropbear_run_command", "dropbear_exec", "dropbear_desktop_launch", "dropbear_session_screenshot", "dropbear_session_display", "dropbear_session_set_resolution",
                    "dropbear_session_list", "dropbear_session_exec", "dropbear_session_ui", "dropbear_session_worker_start", "dropbear_session_worker_call", "dropbear_session_worker_stop"})
                self.assertEqual(set(tools), set(json.loads((ROOT / "src/windows/agent-mcp.json").read_bytes())["tools"]))
                listed_sessions = await client.call_tool("dropbear_session_list")
                self.assertEqual(json.loads(listed_sessions.content[0].text)["sessions"][0]["session_id"], 3)
                executed = await client.call_tool("dropbear_session_exec", {
                    "program": "C:\\Windows\\System32\\cmd.exe", "username": "agent"})
                self.assertFalse(executed.isError)
                self.assertEqual(json.loads(executed.content[0].text)["execution"]["stdout"], "ok")
                worker = await client.call_tool("dropbear_session_worker_start", {"username": "agent"})
                self.assertFalse(worker.isError)
                worker_id = json.loads(worker.content[0].text)["worker_id"]
                called = await client.call_tool("dropbear_session_worker_call", {"worker_id": worker_id, "method": "context"})
                self.assertEqual(json.loads(called.content[0].text)["session_id"], 3)
                stopped = await client.call_tool("dropbear_session_worker_stop", {"worker_id": worker_id})
                self.assertTrue(json.loads(stopped.content[0].text)["stopped"])
                self.assertTrue(tools["dropbear_context"].annotations.readOnlyHint)
                self.assertTrue(tools["dropbear_exec"].annotations.destructiveHint)
                display = await client.call_tool("dropbear_session_display", {"session_id": 3})
                self.assertEqual(json.loads(display.content[0].text)["displays"][0]["current"]["width"], 1600)
                tested = await client.call_tool("dropbear_session_set_resolution", {
                    "session_id": 3, "width": 1280, "height": 720, "test_only": True})
                self.assertFalse(json.loads(tested.content[0].text)["applied"])
                shot = await client.call_tool("dropbear_session_screenshot", {"session_id": 3, "expected_user": "agent"})
                self.assertFalse(shot.isError)
                self.assertEqual(shot.content[1].type, "image")
                self.assertEqual(shot.content[1].mimeType, "image/png")
                by_user = await client.call_tool("dropbear_session_screenshot", {"username": "agent"})
                self.assertFalse(by_user.isError)
                self.assertTrue(base64.b64decode(shot.content[1].data).startswith(b"\x89PNG"))
                resources = await client.list_resources()
                self.assertEqual({str(r.uri) for r in resources.resources},
                                 {"dropbear://context", "dropbear://guide", "dropbear://manifest"})
                loaded = await client.call_tool("dropbear_manifest")
                self.assertEqual(json.loads(loaded.content[0].text)["skill"], "skill")
                result = await client.read_resource("dropbear://context")
                self.assertEqual(json.loads(result.contents[0].text)["session_id"], 0)
                prompt = await client.get_prompt("dropbear_onboarding")
                self.assertIn("Fixture guide", prompt.messages[0].content.text)
                result = await client.call_tool("dropbear_exec", {"program": "C:\\tool.exe"})
                self.assertFalse(result.isError)
                value = json.loads(result.content[0].text)
                self.assertEqual(value["exit_code"], 7)
                self.assertEqual(base64.b64decode(value["stdout_base64"]), b"binary\x00\xff")
                self.assertEqual(value["security_context"]["windows_user"], "NT AUTHORITY\\SYSTEM")
                result = await client.call_tool("dropbear_run_command", {"command": "failure"})
                self.assertTrue(result.isError)
                result = await client.call_tool("dropbear_exec", {
                    "program": "C:\\tool.exe", "stdin_base64": "invalid!"})
                self.assertTrue(result.isError)


class TransportTests(unittest.TestCase):
    def test_invalid_display_inputs_do_not_connect(self):
        remote = Remote(Settings("host", "user"))
        for kwargs in ({"session_id": 0}, {"session_id": 3, "width": 1280},
                       {"session_id": 3, "width": 1, "height": 720},
                       {"session_id": 3, "width": 1280, "height": 720, "refresh_hz": 0}):
            with patch.object(remote, "connect") as connect:
                with self.assertRaises(ValueError):
                    remote.session_display(**kwargs)
                connect.assert_not_called()

    def test_changed_skill_is_rejected(self):
        remote = FixtureRemote(Settings("host", "user"))
        with patch.object(remote, "exchange", return_value=(b"changed", b"", 0)):
            with self.assertRaisesRegex(RuntimeError, "changed"):
                remote.tracked_skill()

    def test_binary_streams_and_host_verification(self):
        client = MagicMock()
        channel = client.get_transport.return_value.open_session.return_value
        channel.recv_ready.side_effect = [True, False]
        channel.recv_stderr_ready.side_effect = [True, False]
        channel.recv.return_value = b"\x00\xff"
        channel.recv_stderr.return_value = b"err"
        channel.recv_exit_status.return_value = 7
        channel.send.return_value = 4
        with patch.object(dropbear_mcp.paramiko, "SSHClient", return_value=client):
            result = Remote(Settings("host", "user", password="secret")).exchange(payload=b"DBX2")
        self.assertEqual(result, (b"\x00\xff", b"err", 7))
        client.load_system_host_keys.assert_called_once()
        self.assertIsInstance(client.set_missing_host_key_policy.call_args.args[0],
                              dropbear_mcp.paramiko.RejectPolicy)
        channel.invoke_subsystem.assert_called_once_with("dropbear-exec-v1")
        channel.shutdown_write.assert_called_once()
        channel.close.assert_called_once()
        client.close.assert_called_once()
        self.assertNotIn("secret", repr(Settings("host", "user", password="secret")))

    def test_timeout_closes_channel_without_retry(self):
        client = MagicMock()
        channel = client.get_transport.return_value.open_session.return_value
        with patch.object(dropbear_mcp.paramiko, "SSHClient", return_value=client), \
                patch.object(dropbear_mcp.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaises(TimeoutError):
                Remote(Settings("host", "user")).exchange(command="echo probe", timeout=1)
        client.connect.assert_called_once()
        channel.close.assert_called_once()
        client.close.assert_called_once()


async def live():
    remote = Remote(Settings.from_env())
    # The discovery entrypoint must be visible before key exchange/authentication.
    with socket.create_connection((remote.settings.host, remote.settings.port), timeout=8) as sock:
        with sock.makefile("rb") as stream:
            identification = stream.readline(256)
    assert identification.startswith(b"SSH-2.0-dropbear_") and identification.endswith(b"\r\n"), identification
    assert b" skill-mcp=__dropbear_win_manifest__" in identification, identification
    assert len(identification) <= 255, identification
    print("Raw SSH identification:", identification.decode("ascii").rstrip())
    probe = remote.probe()
    assert "DropbearWin Agent discovery" in probe["ssh_auth_banner"], probe
    tracked = remote.tracked_skill()
    manifest = tracked["manifest"]
    # Confirm files announced by the auth banner exist and match SSH exec bytes.
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if remote.settings.known_hosts:
        ssh.load_host_keys(remote.settings.known_hosts)
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        ssh.connect(remote.settings.host, port=remote.settings.port, username=remote.settings.username,
                    password=remote.settings.password, look_for_keys=False, allow_agent=False, timeout=10)
        with ssh.open_sftp() as sftp:
            for kind in ("skill", "mcp"):
                with sftp.open(manifest[kind + "_path"].replace("\\", "/"), "rb") as f:
                    raw = f.read()
                assert hashlib.sha256(raw).hexdigest() == manifest[kind + "_sha256"]
                assert raw.decode("utf-8") == tracked[kind]
    finally:
        ssh.close()
    params = StdioServerParameters(command=sys.executable,
                                  args=[str(ROOT / "tools" / "dropbear_mcp.py")],
                                  env=dict(os.environ))
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as client:
            await client.initialize()
            context = await client.call_tool("dropbear_context")
            assert not context.isError, context
            value = json.loads(context.content[0].text)
            assert value["version"] >= 2 and value["os"] == "windows", value
            guide = await client.call_tool("dropbear_guide")
            assert not guide.isError and "dropbear-win-agent-context" in guide.content[0].text
            tracked = await client.call_tool("dropbear_manifest")
            assert not tracked.isError, tracked
            tracked_value = json.loads(tracked.content[0].text)
            assert tracked_value["skill"].startswith("---\nname:"), tracked_value
            assert json.loads(tracked_value["mcp"])["transport"] == "stdio"
            for uri in ("dropbear://context", "dropbear://guide", "dropbear://manifest"):
                assert (await client.read_resource(uri)).contents
            assert (await client.get_prompt("dropbear_onboarding")).messages
            for tool, arguments in (
                ("dropbear_sessions", {}),
                ("dropbear_run_command", {"command": "echo mcp-shell-ok"}),
                ("dropbear_exec", {
                    "program": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "args": ["-NoProfile", "-NonInteractive", "-EncodedCommand",
                             base64.b64encode(("[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
                                 "Write-Output ('mcp-exec-ok '+$env:DB_MCP_TEST); exit 7"
                             ).encode("utf-16le")).decode("ascii")],
                    "env": {"DB_MCP_TEST": "structured-env"}, "encoding": "utf-8"})):
                result = await client.call_tool(tool, arguments)
                assert not result.isError, result
                data = json.loads(result.content[0].text)
                if tool == "dropbear_sessions":
                    # query.exe on this Windows build can return 1 with a valid listing.
                    assert "services" in data["stdout"], data
                else:
                    assert data["exit_code"] == (7 if tool == "dropbear_exec" else 0), data
                    assert "mcp-" in data["stdout"], data
                    if tool == "dropbear_exec":
                        assert "structured-env" in data["stdout"], data
            print("PASS live stdio MCP: discovery, resources, prompt, sessions, shell, structured exec")
            print(json.dumps({k: value[k] for k in ("windows_user", "session_id", "default_port")}))


if __name__ == "__main__":
    if "--fixture" in sys.argv:
        create_server(FixtureRemote(Settings("fixture", "fixture"))).run(transport="stdio")
    elif "--live" in sys.argv:
        asyncio.run(live())
    else:
        unittest.main()
