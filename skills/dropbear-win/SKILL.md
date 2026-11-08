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

## Execute

Prefer `dropbear_exec` for EXE/argument-array/cwd/environment requests. It uses
the byte-preserving `dropbear-exec-v1` subsystem, avoiding shell quoting.
Use `dropbear_run_command` when shell syntax is needed, following the live
`shell` value (`cmd` or `powershell`, without POSIX assumptions).

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
state. Node/BridgeTalk commands launched by `exec` inherit the worker's user and
session; Node is still supplied by the project. Each Node exec is a new process;
an existing project's persistent Node worker can be launched with desktop_launch.
Stop the worker explicitly with `dropbear_session_worker_stop` when done.
Queues use authenticated SSH/SFTP and a per-worker user/SYSTEM/Administrators ACL;
there is no extra network listener. Workers expire after an idle timeout.

For UI, first call `dropbear_session_ui(action="windows", username="agent")` and
select the intended window's `window_id`. Mutations require that ID: `focus`,
`click` (physical virtual-desktop screen x/y), `text`, or `keys` (e.g. CTRL+A).
The worker verifies foreground focus before input and reports denied focus/UIPI
or locked desktops as errors. Partial input is possible if focus changes; inspect
before retrying. Do not operate another session's windows to work around a failure.

For Adobe workflows, launch Premiere and After Effects with desktop_launch in the
same selected login, then run the project's BridgeTalk/ppro:smoke commands through
session_exec or worker_call(exec). Verify the actual Adobe result and UI readiness;
successful transport/identity checks alone do not prove the Adobe smoke suite passed.

For MCP installation, environment variables and tool schemas, read
[the integration reference](references/mcp.md).
