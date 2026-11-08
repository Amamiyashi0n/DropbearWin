---
name: dropbear-win
description: Connect to DropbearWin Windows SSH hosts, discover the effective Windows identity and session, and execute commands using its MCP bridge or native SSH agent endpoints. Use for DropbearWin operations and desktop-session diagnosis.
---

# DropbearWin

Use the target selected by the user or configured MCP server. Credentials belong in
the connection environment or client secret store; do not put them into this skill.

## Discover before operating

SSH authentication publishes an Agent discovery banner, including for non-PTY
commands and SFTP. It points to the actual remote `SKILL.md` and `mcp.json`.
Some SDKs expose this through their authentication-banner API rather than text.

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
```

It selects the active physical console and uses that user's primary token and
environment. Arbitrary/RDP Session selection is currently unsupported. Do not
invent a `--session` flag or assume this command targets an RDP agent worker.
For an existing worker in a user session, keep its commands and UI operations
in that session; SSH can coordinate through the worker's configured interface.

For MCP installation, environment variables and tool schemas, read
[the integration reference](references/mcp.md).
