# MCP connection

The repository's `tools/dropbear_mcp.py` runs on the Agent/client machine as a
stdio MCP server using the official Python MCP SDK v1 API and Paramiko. Windows
only needs the existing DropbearWin EXE with probe v2 and the embedded guide.

The EXE embeds the bridge, both session helpers, Skill, this reference and an MCP
descriptor. Installation/upgrade extracts a flat bundle into the EXE's install
directory, and uninstall removes it. Discover `bundle_directory` and
`bundle_manifest_path` with `__dropbear_win_manifest__`, then download the listed
files over SFTP and verify their SHA-256. In this bundle the scripts and
`requirements-mcp.txt` are siblings; follow `agent-mcp.md` for client setup.
`--export-agent-files EXISTING_DIRECTORY` also exports the embedded bundle
without installing a service. No Python interpreter/dependencies are bundled.

Create a Python 3.10+ virtual environment and install `tools/requirements-mcp.txt`.
Configure the MCP host to run that environment's Python with the absolute path
to `tools/dropbear_mcp.py`. No HTTP listener or target-side Python is needed.

Required environment:

| Variable | Meaning |
| --- | --- |
| `DROPBEAR_MCP_HOST` | Target IP/DNS name, without SSH username |
| `DROPBEAR_MCP_USER` | Dropbear authentication name |
| `DROPBEAR_MCP_PASSWORD` | Password supplied through the client secret environment |
| `DROPBEAR_MCP_PORT` | Optional; default 22 |
| `DROPBEAR_MCP_KNOWN_HOSTS` | Optional additional OpenSSH known_hosts file |
| `DROPBEAR_MCP_ENCODING` | Optional output text codec; default utf-8, often cp936 for Windows utilities |

Verify and enroll the target host key with an ordinary trusted SSH connection
before starting MCP. Unknown/changed keys are rejected. Authentication is password
only for this DropbearWin build; local ssh-agent and key-file discovery are disabled.

## Surface

| Tool | Arguments / return |
| --- | --- |
| `dropbear_context` | No arguments; live probe JSON |
| `dropbear_guide` | No arguments; embedded Markdown |
| `dropbear_manifest` | No arguments; manifest plus SHA-256-verified remote Skill/MCP content |
| `dropbear_sessions` | No arguments; `query session` result and security context |
| `dropbear_run_command` | `command`, optional `timeout`, `encoding` |
| `dropbear_exec` | `program`, optional `args`, `cwd`, `env`, `stdin_base64`, `timeout`, `encoding` |
| `dropbear_run_script` | `script`, optional `runtime=powershell`, interpreter `program`, script `args`, `cwd`, `env`, `stdin_base64`, `timeout`, `encoding` |
| `dropbear_desktop_launch` | `program`, optional `args`, `session_id`, `expected_user`; launches using the selected logged-on user's token |
| `dropbear_session_screenshot` | `session_id`, optional `expected_user`; PNG image and actual user/session/dimensions |
| `dropbear_session_display` | `session_id`, optional `expected_user`; displays/current and driver-advertised modes |
| `dropbear_session_set_resolution` | `session_id`, `width`, `height`; optional `expected_user`, `device`, `refresh_hz`, `test_only` |
| `dropbear_session_list` | Structured WTS rows: ID, user, SID, state, selectable |
| `dropbear_session_exec` | `program`, optional `args/cwd/env/stdin_base64/timeout/encoding`; select `session_id` or `username` |
| `dropbear_session_ui` | `action=windows/focus/click/text/keys`; select `session_id` or `username`; mutations require `window_id` |
| `dropbear_session_worker_start` | Select `session_id` or `username`, optional `idle_timeout=600`; returns `worker_id` and actual user/session/profile |
| `dropbear_session_worker_call` | `worker_id`, `method=context/exec/powershell/ui`, `params`, optional `timeout` |
| `dropbear_session_worker_stop` | `worker_id`; graceful stop and removal of its own queue files |

Unlike ordinary SSH execution, session execution uses the logged-on user's token
and environment. A username must resolve to one active/connected login. Both ID
and username together verify ownership. Session 0 and disconnected logins are
rejected. The worker needs Windows PowerShell (tested with 5.1 on Windows 10),
but no target-side Python/Node dependency; Node is only required for Node commands.
Desktop launch, screenshot, display queries and resolution tools also accept
`username` instead of an explicit `session_id`; existing ID calls remain valid.

The persistent worker's `exec` params mirror `dropbear_session_exec` (encoding is
handled by the client; worker results contain base64). `powershell` takes `code`,
retaining explicit `$global:` variables in a separate runspace. `ui` takes the
same action/window/coordinate/text/keys fields as `dropbear_session_ui`.
Read `execution.exit_code`, `timed_out`, `output_limit_exceeded` and actual
`security_context`. Output is bounded to 1 MiB and stdin to 256 KiB. Foreground
commands and descendants are job-contained; start persistent apps explicitly
with desktop_launch. No automatic retry is made after a timeout.

Workers serialize requests through per-worker ACL-protected JSON queues under
ProgramData/DropbearWin, without opening an extra port. Requests include an ID,
expiry and owner SID/session guard. Use worker_stop on completion; idle-expired
workers can also be cleaned with worker_stop. A busy or crashed worker may need
inspection; returned `worker_cleanup` errors retain the worker ID for this purpose.
Do not concurrently submit dependent requests to the same worker.

UI mutations require a window ID returned by windows in the selected session.
Focus must actually become foreground; input uses SendInput, physical screen
coordinates and the full virtual desktop. It cannot bypass a locked/secure
desktop, Windows focus policy or UIPI. Verify the resulting UI independently.

Display setting results include native test/change codes, before/after mode,
`applied`, `verified`, and any `error`. `test_only=true` never applies a mode.
For RDP a reported `client_resize_required` means the client must resize/reconnect;
do not describe the requested resolution as achieved. No display registry settings
are written by this tool.

Execution returns `exit_code`, `stdout`, `stderr`, `stdout_base64`,
`stderr_base64`, `encoding`, and `security_context`. Nonzero remote exit codes
are command results; SSH, protocol, output-limit and timeout failures become
MCP tool errors. There are no automatic retries for mutations.

The bridge fetches the live probe before each execution. Timeouts are limited
to 300 seconds, combined output to 1 MiB, and structured stdin to 256 KiB.
For larger output/data, use files and SFTP separately.

Resources: `dropbear://context` (JSON), `dropbear://guide` (Markdown),
`dropbear://manifest` (file paths and SHA-256 tracking).
Prompt: `dropbear_onboarding` (live context plus guide).

The MCP host controls loading resources/prompts and approval of tools. Installing
the server does not force every Agent to read its resources. The Skill and MCP
server instructions tell the Agent to discover context first.

## Long scripts

`dropbear_run_script` uploads script text through SFTP, then runs the interpreter
through DBX2. Script bytes are stored in a file, and stdin remains available to
the running script. Supported runtimes are `powershell`, `python`, and `node`.
PowerShell defaults to the server's Windows PowerShell path and receives a
UTF-8 BOM script with process-scoped `-ExecutionPolicy Bypass`. Python and Node
require an absolute `program` path to the installed interpreter. `args` contains
script arguments. The script runs as the SSH Windows identity/session with the
usual command Job lifetime, cwd, environment, output and exit-code behavior.

```json
{
  "script": "import sys, json\nprint(json.dumps([sys.argv[1:], sys.stdin.read()]))\nsys.exit(7)",
  "runtime": "python",
  "program": "C:\\Python311\\python.exe",
  "args": ["argument with spaces"],
  "cwd": "C:\\Users\\Public",
  "stdin_base64": "aW5wdXQ=",
  "timeout": 30,
  "encoding": "utf-8"
}
```

The live probe must advertise `script_staging=true`. The native EXE creates a
unique directory under its Windows temporary directory with an ACL granting
access to the SSH Windows identity, SYSTEM and Administrators. Staging, upload,
execution and cleanup share one authenticated SSH connection. The script limit
is 1 MiB including its encoding marker, stdin 256 KiB, combined output 1 MiB and
execution timeout 300 seconds. Interpreter paths and arguments still fit within
the Windows process command-line limit. For larger script files, use SFTP and
`dropbear_exec` directly.

Successful calls return the normal execution result and `script_cleanup` with
`stage_id`, `directory`, and `removed`. Nonzero script exit codes are ordinary
results. Upload/transport/timeout failures raise a tool error after attempting
cleanup. Cleanup failure preserves the execution result or original error and
reports the directory and staging ID. There is no automatic script retry.
If staging itself loses its connection, the error reports the ID with an unknown
staging outcome. To retry cleanup, use structured exec on the same server EXE
with `args=["--script-cleanup", "<stage_id>"]` under the original SSH identity.
Cleanup removes the uploaded script names and then the empty directory, preserving
other files created by the script. Inspect those files when cleanup reports a
nonempty directory.
