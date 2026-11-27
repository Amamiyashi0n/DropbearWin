---
name: dropbear-win
description: Connect to DropbearWin Windows SSH hosts, discover the effective Windows identity and session, and execute commands using its MCP bridge or native SSH agent endpoints. Use for DropbearWin operations and desktop-session diagnosis.
---

# DropbearWin

Use the target selected by the user or configured MCP server. Credentials belong in
the connection environment or client secret store; do not put them into this skill.

## Discover before operating

The initial SSH identification advertises `skill-mcp=__dropbear_win_manifest__`
in its comments field. Follow that entrypoint after SSH authentication to discover
the remote Skill/MCP files even when authentication banners are hidden or filtered.

SSH authentication also publishes an Agent discovery banner, including for non-PTY
commands and SFTP. It points to the actual remote `SKILL.md` and `mcp.json`.
Some SDKs expose this through their authentication-banner API rather than text.

The EXE embeds the complete client bundle. Installation/upgrade extracts it flat
beside the installed EXE; uninstall removes those generated files. The manifest's
`bundle_manifest_path` lists file sizes and SHA-256 for an SFTP download to the
client. Follow `agent-mcp.md` there for setup. The bundle contains bridge source
and helpers; Python and its dependencies are still required on the client.

With the `dropbear-win` MCP server, call `dropbear_manifest`, `dropbear_context` and `dropbear_guide`.
The manifest tool loads remote Skill/MCP content and verifies SHA-256. On each
connection compare its `skill_sha256` and `mcp_sha256` with the loaded version;
reload changed content. Never reuse a Session/identity snapshot as live state.
The same information is exposed as `dropbear://context` and `dropbear://guide`
resources; `dropbear_onboarding` loads both as an MCP prompt.

Without MCP, run from the SSH client:

```sh
ssh user@host __dropbear_win_probe__
ssh user@host __dropbear_win_manifest__
ssh user@host __dropbear_win_skill__
ssh user@host __dropbear_win_mcp__
ssh user@host __dropbear_win_guide__
```

Read `windows_user`, `access_token`, `session_id`, and `shell` from the live probe.
The SSH username is a Dropbear authentication label. Ordinary commands and file
operations use the server's Windows token; an installed LocalSystem service
normally reports `NT AUTHORITY\SYSTEM` and Session 0. A portable instance can use
a different identity. The guide documents capabilities and does not expand the
user's requested scope.

## Query Windows system information

Check `system_query_commands` in `__dropbear_win_probe__` before relying on the
built-in commands. Send each command as a standalone SSH exec request.
Interactive commands, pipelines, and redirections use the remote shell's
normal command lookup.

```sh
ssh user@host uname -a
ssh user@host uname -m
ssh user@host sysinfo
ssh user@host cpuinfo
ssh user@host meminfo
ssh user@host diskinfo
```

`uname` prints `Windows_NT` by default. Use `-n` for the hostname, `-r` for
the NT major/minor version, `-v` for the build number, `-m` for the native OS
architecture, and `-o` for the OS name. `-a` prints all fields and `--help`
lists the supported flags. `sysinfo` includes the Windows version, EXE
architecture, logical CPUs and recent utilization, physical memory, and disk
space. `diskinfo` reports the volume containing the SSH working directory.
Use `dropbear_run_command(command="uname -m", encoding="utf-8")` or the
same MCP tool with any command above. For older servers without the capability,
use the probe for connection context or `ver` when `shell` is `cmd`.

## Execute

Prefer `dropbear_exec` for EXE/argument-array/cwd/environment requests. It uses
the byte-preserving `dropbear-exec-v1` subsystem, avoiding shell quoting.
Use `dropbear_run_command` when shell syntax is needed, following the live
`shell` value (`cmd` or `powershell`, without POSIX assumptions).

Use `dropbear_run_script` for long PowerShell, embedded QuickJS-ng (`qjs`), Python, or Node scripts. `qjs` requires no external interpreter (check `qjs=true` in the probe; provides globals `std`, `os`, and `db` with file/JSON/Base64/stdin helpers) and can also run directly via SSH `qjs -e ...` or `qjs -`. Pass
`script` as text, `runtime`, script `args`, and an absolute interpreter `program`
for Python/Node. It stages the file over SFTP in a private directory and uses
structured exec with separate `stdin_base64`, `cwd`, and `env`. It uses the SSH
Windows token and requires `script_staging=true` in the live probe. Check
`script_cleanup.removed` and any leftover directory/error. See the
[long-script reference](references/mcp.md#long-scripts) for limits and recovery.

Each exec has independent cwd/environment. Previous `cd` and variable assignments
do not carry over. Results include exit code, text and lossless base64 streams.
Select the actual output encoding when decoding Windows utilities (often CP936
on Chinese Windows); retain base64 for binary results.

Children normally end when the command or SSH channel ends. Use a dedicated
service or an explicitly requested desktop launcher for persistent processes.
Timeouts can leave partial side effects; inspect the result before retrying writes.

## Desktop sessions

Use `dropbear_sessions` to inspect sessions. Session IDs can change after logon.
SYSTEM in Session 0 does not imply access to a visible user desktop.

Consult `desktop_launch` capabilities in the probe. The current EXE supports:

```cmd
"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --desktop-launch "C:\absolute\program.exe" [args]
"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --desktop-launch --session 3 --expect-user agent "C:\absolute\program.exe" [args]
```

It defaults to the physical console; `--session ID` selects an existing
active/connected console or RDP login when the live probe advertises support.
Use `--expect-user USER` (optionally DOMAIN\USER) to guard against ID reuse.
The process uses that user's primary token/environment; Session 0 and mismatched
users are rejected. This creates no new login and does not unlock the desktop.
Use MCP `dropbear_desktop_launch` with `session_id` and `expected_user` where available.
Verify process identity, Session ID and UI readiness separately after launch.
Use `dropbear_session_screenshot(session_id=3, expected_user="agent")` to capture
that user's full virtual desktop (all monitors) as an MCP PNG image. It returns actual identity/session and
dimensions, uses a short user-token worker and cleans its temporary capture files.
Locked or unavailable input desktops fail; this tool does not unlock a session.
Use `dropbear_session_display` to read the selected session's displays, current
mode and available modes. `dropbear_session_set_resolution` accepts width/height,
optional device/refresh rate and `test_only`. Check `applied`, `verified` and
`error`; a driver success code alone does not prove resolution changed.
RDP drivers may require resizing/reconnecting the RDP client (`client_resize_required`).
Changes are applied dynamically without writing display settings to the registry.
For an existing worker in a user session, keep its commands and UI operations
in that session; SSH can coordinate through the worker's configured interface.

For commands that must run as the desktop user, use `dropbear_session_exec`
instead of ordinary `dropbear_exec`. It collects exit code and lossless streams
from that user's session/profile/environment. Specify `session_id`, `username`,
or both as an owner guard. `dropbear_session_list` returns structured WTS rows
with owner SID and `selectable`; usernames matching multiple sessions are rejected.
Use `dropbear_desktop_launch(username="agent", ...)` for persistent GUI programs.

For repeated operations use `dropbear_session_worker_start(username="agent")`,
save `worker_id`, then `dropbear_session_worker_call` with `context`, `exec`,
`powershell` or `ui`. A dedicated PowerShell runspace retains explicit `$global:`
state. Commands launched by `exec` inherit the worker's user and session.
Each exec starts a separate process; use desktop_launch for independently
persistent programs.
Stop the worker explicitly with `dropbear_session_worker_stop` when done.
Queues use authenticated SSH/SFTP and a per-worker user/SYSTEM/Administrators ACL;
there is no extra network listener. Workers expire after an idle timeout.

For UI, first call `dropbear_session_ui(action="windows", username="agent")` and
select the intended window's `window_id`. Mutations require that ID: `focus`,
`click` (physical virtual-desktop screen x/y), `text`, or `keys` (e.g. CTRL+A).
The worker verifies foreground focus before input and reports denied focus/UIPI
or locked desktops as errors. Partial input is possible if focus changes; inspect
before retrying. Do not operate another session's windows to work around a failure.

Verify the target application's actual result and UI readiness after execution;
successful transport or identity checks alone do not prove an application task succeeded.

For MCP installation, environment variables and tool schemas, read
[the integration reference](references/mcp.md).

## Environment & Tool Discovery

On connect, Dropbear-win merges live System and User Registry `PATH` (including the logged-on interactive user when running as a service) and exposes discovered executables in `probe.tools` (and via `ssh user@host toolsinfo`). `dropbear_run_script` automatically uses `probe.tools` for `python`/`node` when `program` is omitted.

## Silent User Switching (`dropbear_run_as_user` / `su`)

When the service runs as `NT AUTHORITY\SYSTEM`, commands do not see a logged-on user's `USERPROFILE`, `HKCU`, Git config, or Windows Credential Manager. Use `dropbear_run_as_user` (or SSH `su` / `runas-user`) to run commands silently as a Windows user without disturbing their desktop:

- **Default (Session 0 isolated)**: `dropbear_run_as_user(command="git push", username="Amamiya")` or `active=True` runs in Session 0 with the user's primary token, profile, and credentials — physically isolated from the user's desktop (zero window flash, zero focus steal, zero busy cursor).
- **In-session silent mode**: pass `in_session=True` or an explicit `session_id` (from `dropbear_session_list` or `su --list`) when a task requires the user's actual WTS session (e.g. session-scoped COM/pipes/GPU). It still runs silently (`CREATE_NO_WINDOW`, `SW_HIDE`, `STARTF_FORCEOFFFEEDBACK`, `GIT_TERMINAL_PROMPT=0`, `GCM_INTERACTIVE=never`, `SSH_ASKPASS_REQUIRE=never`).
- **Elevated Local Administrator**: set `admin=True` (or SSH `su --admin`) to elevate a UAC split token via `TokenLinkedToken` to High Mandatory Level.
- **Force-logon non-logged-in user**: pass `username` + `password` (or SSH `su [--admin] -p <password> <user> <cmd>`) to log on a local user or built-in `Administrator` via `LogonUserW` + `LoadUserProfileW`.

## Detached Background Processes (`dropbear_bg_start` / `bg`)

Ordinary SSH commands live inside a channel Job that terminates child trees on disconnect. For long-running daemons, dev servers, or tasks that must survive SSH disconnect, use `dropbear_bg_start` (or SSH `bg [--log <file>] [--active|--user <u|id>|--admin|--in-session] <cmd>`) instead of creating Windows Scheduled Tasks:

- Breaks out of the SSH Job cleanly (`CREATE_BREAKAWAY_FROM_JOB`), runs silently (`CREATE_NO_WINDOW`, `SW_HIDE`, `STARTF_FORCEOFFFEEDBACK`), detaches stdio to `NUL` or `log_path`, and returns `{"detached": true, "pid": ...}` immediately.

## Embedded `wsl-bridge` (Debian WSL1 Direct Pass-Through)

`dropbear-win-x64.exe` embeds the zero-dependency Rust `wsl-bridge.exe` binary (`vendor/wsl-bridge`) by default at build time as a Win32 PE `RCDATA` resource while preserving strict Windows XP/2003 DLL imports (`ADVAPI32`, `KERNEL32`, `msvcrt`, `WS2_32` only).

- **Automatic WSL Detection & Built-in Bridge Supervisor (Single-Service)**: On startup, `DropbearWin` automatically probes the host for WSL (`C:\Windows\System32\wsl.exe` + `Lxss` registry across logged-in and unloaded profiles). When WSL exists, `DropbearWin` itself automatically ensures `LxssManager` is running, secures `C:\ProgramData\wsl-bridge`, launches and supervises the `HIGH_PRIORITY_CLASS` loopback broker (via WTS Session 0 or passwordless `MSV1_0` S4U logon even with no user logged on), and advertises `wsl-bridge` to agents — **no separate `wsl-bridge` daemon or Scheduled Task is needed**. On Windows hosts without WSL, the bridge stays completely dormant.

- **Direct SSH built-ins** (bypass `cmd.exe`, lossless UTF-8 & binary stdio, ~1–22 ms via shared `C:\ProgramData\wsl-bridge\broker.json`):
  - `ssh HOST wsl-bridge status`
  - `ssh HOST wsl-bridge exec [--cwd <dir>] [--env K=V] [--sudo] -- <cmd> [args...]`
  - `ssh HOST wsl-bash -c "whoami && sudo -n id -u"`
  - `ssh HOST wsl-bridge path --to-linux "C:\Users\Amamiya"`
- **Local CLI flags**:
  - `dropbear-win-x64.exe --wsl-bridge <args...>`
  - `dropbear-win-x64.exe --wsl-bridge --extract [dir]`
  - `dropbear-win-x64.exe --wsl-bridge --install-shims [dir]` (extracts `wsl-bridge.exe`, `bash.exe`, `sh.exe`)
- **MCP tools** (in `tools/dropbear_mcp.py`): `dropbear_wsl_status`, `dropbear_wsl_exec`, `dropbear_wsl_bash`.
