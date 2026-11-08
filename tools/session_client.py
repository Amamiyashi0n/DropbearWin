"""Session-bound MCP transport over authenticated SSH/SFTP; no listening TCP port."""
from __future__ import annotations

import base64
import json
import ntpath
from pathlib import Path
import re
import time
import uuid

from windows_exec import encode_request


def absolute_windows(path: str, label: str) -> None:
    if not isinstance(path, str) or "\0" in path or not ntpath.splitdrive(path)[0] or not ntpath.isabs(path):
        raise ValueError(label + " must be an absolute Windows path")


def select_session(rows: list[dict], session_id: int | None, username: str | None) -> dict:
    if session_id is None and not username:
        raise ValueError("Provide session_id or username; no desktop is selected implicitly")
    if session_id is not None and (isinstance(session_id, bool) or not 0 < session_id < 0xFFFFFFFF):
        raise ValueError("session_id must be a positive Windows Session ID")
    candidates = [row for row in rows if row.get("selectable") and row.get("session_id", 0) > 0]
    if session_id is not None:
        candidates = [row for row in candidates if row["session_id"] == session_id]
    if username:
        name = username.casefold()
        candidates = [row for row in candidates if name == row.get("windows_user", "").casefold()
                      or ("\\" not in username and name == row.get("username", "").casefold())]
    if not candidates:
        raise ValueError("No matching active/connected Windows login; no login or unlock will be attempted")
    if len(candidates) != 1:
        raise ValueError("Username matches multiple sessions; specify session_id: "
                         + ", ".join(str(row["session_id"]) for row in candidates))
    return candidates[0]


def validate_work(method: str, params: dict, timeout: float) -> dict:
    if not 0 < timeout <= 300:
        raise ValueError("timeout must be greater than 0 and at most 300 seconds")
    params = dict(params)
    if method == "exec":
        absolute_windows(params.get("program"), "program")
        args = params.get("args", [])
        if not isinstance(args, list) or any(not isinstance(v, str) or "\0" in v for v in args):
            raise ValueError("args must be an array of NUL-free strings")
        if params.get("cwd"):
            absolute_windows(params["cwd"], "cwd")
        env = params.get("env", {})
        if not isinstance(env, dict) or any(not isinstance(k, str) or not k or "=" in k or "\0" in k
                                            or not isinstance(v, str) or "\0" in v for k, v in env.items()):
            raise ValueError("env must map valid variable names to NUL-free strings")
        if len(base64.b64decode(params.get("stdin_base64", ""), validate=True)) > 256 * 1024:
            raise ValueError("stdin is limited to 256 KiB")
        params.update(args=args, env=env, timeout=timeout)
    elif method == "ui":
        action = params.get("action")
        if action not in ("windows", "focus", "click", "text", "keys"):
            raise ValueError("Unknown UI action")
        if action != "windows" and not re.fullmatch(r"[1-9][0-9]{0,19}", str(params.get("window_id", ""))):
            raise ValueError("window_id must come from this session's windows action")
        if action == "click":
            if any(not isinstance(params.get(k), int) or isinstance(params[k], bool) for k in ("x", "y")):
                raise ValueError("click requires integer virtual-desktop coordinates x and y")
            if params.get("button", "left") not in ("left", "right"):
                raise ValueError("button must be left or right")
            params.setdefault("button", "left")
        if action == "text" and (not isinstance(params.get("text"), str)
                                  or len(params["text"].encode("utf-16le")) > 8192 or "\0" in params["text"]):
            raise ValueError("text is limited to 4096 UTF-16 code units without NUL")
        if action == "keys" and (not isinstance(params.get("keys"), list) or not 1 <= len(params["keys"]) <= 5
                                  or any(not isinstance(k, str) for k in params["keys"])):
            raise ValueError("keys must be a chord of 1 to 5 key names")
    elif method == "powershell":
        if not isinstance(params.get("code"), str) or len(params["code"].encode("utf-8")) > 65536:
            raise ValueError("powershell code must be a string of at most 64 KiB")
        params["timeout"] = timeout
    elif method not in ("context", "stop"):
        raise ValueError("Unknown worker method")
    return params


class SessionRemote:
    def _session_control(self, request: dict) -> dict:
        manifest = self.manifest()
        directory = manifest.get("bundle_directory")
        if not directory:
            raise RuntimeError("Upgrade the remote EXE to the embedded session-interaction bundle")
        encoded = base64.b64encode(json.dumps(request, ensure_ascii=False).encode()).decode()
        # The control phase runs as the SSH token (often SYSTEM). Execute trusted
        # client bundle bytes, not potentially user-writable portable disk scripts.
        bootstrap = ("$p=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
                     "Add-Type -TypeDefinition $p.cs;"
                     "& ([ScriptBlock]::Create($p.ps)) -RequestBase64 $p.request")
        source = json.dumps({"request": encoded,
            "cs": Path(__file__).with_name("session_interact.cs").read_text(encoding="utf-8"),
            "ps": Path(__file__).with_name("session_interact.ps1").read_text(encoding="utf-8")},
            ensure_ascii=False).encode()
        response = self.exchange(payload=encode_request({
            "program": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "args": ["-NoProfile", "-NonInteractive", "-EncodedCommand",
                     base64.b64encode(bootstrap.encode("utf-16le")).decode()]}) + source, timeout=30)
        out, err, status = response
        if status:
            raise RuntimeError("Session control failed: " + (out + err).decode("utf-8", "replace"))
        result = json.loads(out.decode("utf-8-sig"))
        if result.get("error"):
            raise RuntimeError(result["error"])
        return result

    def session_list(self) -> dict:
        return self._session_control({"mode": "list"})

    def session_resolve(self, session_id=None, username=None) -> dict:
        return select_session(self.session_list()["sessions"], session_id, username)

    @staticmethod
    def _read_worker_json(sftp, path: str) -> dict:
        if sftp.stat(path).st_size > 2 * 1024 * 1024:
            raise ValueError("Session worker response exceeded 2 MiB")
        with sftp.file(path, "rb") as stream:
            return json.loads(stream.read().decode("utf-8-sig"))

    @staticmethod
    def _check_identity(actual, expected):
        if actual.get("session_id") != expected.get("session_id") or actual.get("sid") != expected.get("sid"):
            raise RuntimeError("Session worker identity/session mismatch; no further request was sent")

    @staticmethod
    def _worker_path(root, worker_id):
        if not re.fullmatch(r"[0-9a-f]{32}", worker_id):
            raise ValueError("worker_id must be a value returned by worker_start")
        return ntpath.join(root, "session-" + worker_id).replace("\\", "/")

    def session_worker_start(self, session_id=None, username=None, idle_timeout=600) -> dict:
        if not isinstance(idle_timeout, int) or not 10 <= idle_timeout <= 3600:
            raise ValueError("idle_timeout must be 10 to 3600 seconds")
        selected = self.session_resolve(session_id, username)
        context = self.probe()
        if not context.get("desktop_launch", {}).get("arbitrary_session"):
            raise RuntimeError("Remote EXE does not support explicit desktop sessions")
        worker_id = uuid.uuid4().hex
        prepared = self._session_control({"mode": "prepare", "worker_id": worker_id,
                                          "session_id": selected["session_id"], "sid": selected["sid"]})
        directory = prepared["directory"].replace("\\", "/")
        request = base64.b64encode(json.dumps({"mode": "worker", "worker_id": worker_id,
            "session_id": selected["session_id"], "sid": selected["sid"], "idle_timeout": idle_timeout}).encode()).decode()
        script = ntpath.join(context["agent_discovery"]["bundle_directory"], "session_interact.ps1")
        out, err, status = self.exchange(payload=encode_request({"program": context["server_executable"], "args": [
            "--desktop-launch", "--session", str(selected["session_id"]), "--expect-user", selected["windows_user"],
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile", "-NonInteractive",
            "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", script, "-RequestBase64", request]}))
        if status:
            self._cleanup_worker(directory)
            raise RuntimeError("Session worker launch failed: " + (out + err).decode("utf-8", "replace"))
        client = self.connect()
        try:
            with client.open_sftp() as sftp:
                deadline = time.monotonic() + 20
                while True:
                    try:
                        ready = self._read_worker_json(sftp, directory + "/ready.json")
                        self._check_identity(ready, selected)
                        if ready.get("worker_id") != worker_id:
                            raise RuntimeError("Worker ID mismatch")
                        return {"worker_id": worker_id, "directory": directory,
                                "idle_timeout": idle_timeout, "security_context": ready}
                    except FileNotFoundError:
                        try:
                            failure = self._read_worker_json(sftp, directory + "/error.json")
                        except FileNotFoundError:
                            pass
                        else:
                            raise RuntimeError("Worker startup failed: " + str(failure.get("error")))
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Worker did not become ready; it may still start and will expire when idle: " + worker_id)
                        time.sleep(.1)
        finally:
            client.close()

    def _cleanup_worker(self, directory):
        client = self.connect()
        try:
            with client.open_sftp() as sftp:
                for name in sftp.listdir(directory):
                    if name in ("ready.json", "stopped.json", "error.json") or re.fullmatch(
                            r"[0-9a-f]{32}\.(request|response)\.json(\.tmp)?", name):
                        sftp.remove(directory + "/" + name)
                sftp.rmdir(directory)  # Unknown files are preserved and reported.
        finally:
            client.close()

    def session_worker_call(self, worker_id, method, params=None, timeout=30) -> dict:
        params = validate_work(method, params or {}, timeout)
        sessions = self.session_list()
        directory = self._worker_path(sessions["runtime_root"], worker_id)
        client = self.connect()
        call_id = uuid.uuid4().hex
        response_path = directory + "/" + call_id + ".response.json"
        request_path = directory + "/" + call_id + ".request.json"
        try:
            with client.open_sftp() as sftp:
                ready = self._read_worker_json(sftp, directory + "/ready.json")
                selected = select_session(sessions["sessions"], ready["session_id"], ready["windows_user"])
                self._check_identity(ready, selected)
                try:
                    sftp.stat(directory + "/stopped.json")
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeError("Worker already stopped; start a new worker explicitly")
                request = json.dumps({"id": call_id, "method": method, "params": params,
                    "expected_session": selected["session_id"], "expected_sid": selected["sid"],
                    # Use the host clock snapshot, allowing a short transport margin.
                    "expires_ticks": int(sessions["utc_ticks"]) + int((timeout + 5) * 10_000_000)},
                    ensure_ascii=False).encode()
                if len(request) > 524288:
                    raise ValueError("Worker request exceeds 512 KiB")
                with sftp.file(request_path + ".tmp", "wb") as stream:
                    stream.write(request)
                sftp.rename(request_path + ".tmp", request_path)
                deadline = time.monotonic() + timeout + 10
                while True:
                    try:
                        response = self._read_worker_json(sftp, response_path)
                        break
                    except FileNotFoundError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Worker call timed out; outcome is unknown, do not automatically retry: " + call_id)
                        time.sleep(.1)
                self._check_identity(response.get("security_context", {}), selected)
                if response.get("id") != call_id:
                    raise RuntimeError("Worker response ID mismatch")
                sftp.remove(response_path)
                if response.get("error"):
                    raise RuntimeError(response["error"])
                return response["result"]
        finally:
            client.close()

    def session_worker_stop(self, worker_id) -> dict:
        sessions = self.session_list()
        directory = self._worker_path(sessions["runtime_root"], worker_id)
        client = self.connect()
        already_stopped = False
        try:
            with client.open_sftp() as sftp:
                ready = self._read_worker_json(sftp, directory + "/ready.json")
                try:
                    stopped = self._read_worker_json(sftp, directory + "/stopped.json")
                    self._check_identity(stopped["security_context"], ready)
                    already_stopped = True
                except FileNotFoundError:
                    pass
        finally:
            client.close()
        result = {"stopped": True, "already_stopped": True} if already_stopped else self.session_worker_call(worker_id, "stop", timeout=10)
        # Acknowledge process-loop termination before deleting its files.
        client = self.connect()
        try:
            with client.open_sftp() as sftp:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        self._read_worker_json(sftp, directory + "/stopped.json")
                        break
                    except FileNotFoundError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Worker acknowledged stop but has not finished; workspace retained")
                        time.sleep(.1)
        finally:
            client.close()
        self._cleanup_worker(directory)
        return result

    def session_action(self, method, params, session_id=None, username=None, timeout=30):
        validate_work(method, params, timeout)  # Reject invalid requests before creating anything.
        worker = self.session_worker_start(session_id, username, idle_timeout=30)
        try:
            result = self.session_worker_call(worker["worker_id"], method, params, timeout)
        except BaseException as error:
            try:
                self.session_worker_stop(worker["worker_id"])
            except Exception as cleanup:
                if hasattr(error, "add_note"):
                    error.add_note("Worker cleanup failed; inspect " + worker["worker_id"] + ": " + str(cleanup))
            raise
        try:
            self.session_worker_stop(worker["worker_id"])
        except Exception as cleanup:
            result["worker_cleanup"] = {"worker_id": worker["worker_id"], "error": str(cleanup)}
        return result
