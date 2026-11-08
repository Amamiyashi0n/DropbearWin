# MCP connection

The repository's `tools/dropbear_mcp.py` runs on the Agent/client machine as a
stdio MCP server using the official Python MCP SDK v1 API and Paramiko. Windows
only needs the existing DropbearWin EXE with probe v2 and the embedded guide.

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
| `dropbear_desktop_launch` | `program`, optional `args`, `session_id`, `expected_user`; launches using the selected logged-on user's token |
| `dropbear_session_screenshot` | `session_id`, optional `expected_user`; PNG image and actual user/session/dimensions |

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
