# wsl-bridge

Native Windows x64 direct pass-through bridge, ultra-low-latency loopback broker, high-priority boot daemon, and built-in MCP server for **Debian WSL1** — compiled from a single zero-external-crate Rust binary (`~648 KB`, standard Windows system DLLs only).

Designed to replace MSYS2 / Git Bash shims on Windows with real Debian Linux tooling (UTF-8 clean, lossless binary stdio, full `bash`/`sh`/POSIX utilities, passwordless `sudo`) while remaining accessible from both **Windows system services (`NT AUTHORITY\SYSTEM`)** and **interactive user / AI Agent CLI sessions**.

---

## Architecture

```text
Windows Clients (SYSTEM services, DropbearWin SSH, PowerShell, cmd, Agent CLIs)
   │
   ├─► C:\Program Files\wsl-bridge\bash.exe | sh.exe | wsl-bridge.exe
   │        │
   │        ├─[Fast Path: Non-TTY / MCP]──► Reads C:\ProgramData\wsl-bridge\broker.json
   │        │                               (fallback: %LOCALAPPDATA%\wsl-bridge\broker.json)
   │        │                                       │
   │        │                                       ▼ 127.0.0.1 TCP (TCP_NODELAY, 256-bit Token, 5B binary frames)
   │        │                               Debian WSL1 Resident Broker (broker.py)
   │        │                               ▲ supervised by WslBridgeDaemon (BootTrigger + S4U + HIGH_PRIORITY_CLASS)
   │        │
   │        └─[Fallback: Interactive TTY / WSL_BRIDGE_NO_BROKER=1]──► C:\Windows\System32\wsl.exe --exec
   ▼
Debian 13 (trixie) WSL1 (default user: amamiya, UID 1000, NOPASSWD sudo)
```

---

## Key Features

- **Ultra-Low-Latency Loopback Broker (`v0.3.0`)**:
  - Exploits WSL1's shared `127.0.0.1` loopback stack using a resident Python broker (`src/broker.py`, embedded via `include_str!`), authenticated by a per-start 256-bit random token, with `TCP_NODELAY` and a 5-byte binary streaming framing protocol.
  - Eliminates per-call `wsl.exe` COM activation overhead (`~93 ms` → **`~1–22 ms`**).
  - Automatically falls back to direct `wsl.exe --exec` for interactive console TTYs or when `WSL_BRIDGE_NO_BROKER=1`.
- **Drop-in POSIX Shell Pass-Through (`bash.exe` / `sh.exe`)**:
  - Lossless UTF-8 `argv`, `--cwd`, and environment pass-through (CJK, Emoji, 4-byte UTF-8).
  - Raw binary `stdin`/`stdout`/`stderr` (all 256 byte values `0x00..0xFF`, no UTF-8 BOM, no LF/CRLF mangling).
  - Automatically stages long `-c` scripts (`>24 KB`) to temp files while keeping `stdin` intact.
  - Converts Windows paths (`C:\...`, `C:/...`), supports `/c` symlink and `cygpath` compatibility inside WSL1.
- **System-Wide (`HKLM` + `Program Files` + `ProgramData`) & No-Logon Boot Support**:
  - Binaries installed in `C:\Program Files\wsl-bridge\`, prepended to machine `HKLM` `Path` ahead of `C:\Windows\System32`.
  - Shared broker metadata in `C:\ProgramData\wsl-bridge\broker.json` protected by strict NTFS ACL (`SYSTEM`, `Administrators`, target user only) so **`NT AUTHORITY\SYSTEM` services (such as DropbearWin SSH)** can directly invoke `bash`, `wsl-bridge status`, and `wsl-bridge mcp` without user switching (`su`).
  - `WslBridgeDaemon` Scheduled Task (`BootTrigger` + `LogonType=S4U` + `RunLevel=HighestAvailable` + `Priority=1` + `HIGH_PRIORITY_CLASS`) plus `LxssManager` set to `auto`, ensuring WSL1 + broker start automatically at boot **even when no user is logged on**.
- **Built-in Zero-Dependency MCP Server (`wsl-bridge mcp`) & Linux MCP Proxy (`wsl-bridge mcp-proxy`)**:
  - Supports both newline-delimited JSON-RPC 2.0 and LSP-style `Content-Length` framing.
  - Per-command Linux PGID isolation with automatic `SIGTERM` → `SIGKILL` cleanup on timeout or cancellation (zero orphan processes).
- **Zero External Rust Crates & Debian WSL1 Cross-Compilation**:
  - Built using only `std` + minimal Win32 FFI (`x86_64-pc-windows-gnu` via `mingw-w64` inside Debian WSL1).
  - Automated PE import verification guarantees only standard Windows system DLLs (`KERNEL32.dll`, `ADVAPI32.dll`, `WS2_32.dll`, `ntdll.dll`, `msvcrt.dll`, `bcryptprimitives.dll`, `api-ms-win-core-synch-l1-2-0.dll`).

---

## Verified Performance (`v0.3.0`, Cross-Compiled PE32+)

Measured on Windows 10 Enterprise LTSC 2021 (build `19041`) + Debian 13 (trixie) WSL1:

| Workload | Latency / Throughput | Notes |
| --- | ---: | --- |
| MCP `wsl_status` (broker) | **~1.0 ms** | Resident MCP session over loopback broker |
| MCP `wsl_exec` (broker) | **~4.7 ms** | Direct `execve` without shell |
| MCP `wsl_bash` (broker) | **~10.3 ms** | Full `/usr/bin/bash` invocation |
| CLI `wsl-bridge status` (`SYSTEM` or User) | **~2 ms** (probe) | Reads `C:\ProgramData\wsl-bridge\broker.json` |
| CLI `bash.exe -c true` (broker) | **~22.6 ms** | vs **~93.6 ms** direct `wsl.exe` fallback (**4.1x faster**) |
| Binary pipe throughput | **190–217 MiB/s** | 16 MiB raw binary streaming |
| Binary size | **648 KB** | Stripped `x86_64-pc-windows-gnu` release build |

---

## System-Wide Installation & Deployment

### 1. Debian WSL1 Prerequisites

Inside Debian WSL1 (configured as default user `amamiya`, UID `1000`):

```bash
# /etc/wsl.conf
cat <<'EOF' | sudo tee /etc/wsl.conf
[user]
default=amamiya

[automount]
enabled=true
options="metadata"

[interop]
enabled=true
appendWindowsPath=true
EOF

# Passwordless sudo for default user
echo "amamiya ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/amamiya
sudo chmod 0440 /etc/sudoers.d/amamiya

# /c symlink & cygpath compatibility shim
sudo ln -sfn /mnt/c /c

# Recommended CLI & cross-compile tools
sudo apt-get update && sudo apt-get install -y \
  sudo git ripgrep fd-find jq python3 ca-certificates procps psmisc \
  mingw-w64 gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 binutils-mingw-w64-x86-64 rustup
rustup toolchain install stable && rustup target add x86_64-pc-windows-gnu
```

### 2. Cross-Compile in Debian WSL1 & Deploy

Build directly inside Debian WSL1 (runs PE import check automatically):

```bash
bash scripts/build-cross.sh
```

Or build, stop `WslBridgeDaemon`, deploy `wsl-bridge.exe` / `bash.exe` / `sh.exe` to `C:\Program Files\wsl-bridge\`, and restart the daemon from elevated Windows PowerShell:

```powershell
.\scripts\build-via-wsl.ps1 -Deploy
```

### 3. Install High-Priority Boot Auto-Start (No User Logon Required)

Run elevated as the target Windows user (`Amamiya`):

```powershell
# Creates C:\ProgramData\wsl-bridge with strict ACL, sets LxssManager=auto,
# registers and starts WslBridgeDaemon (BootTrigger + S4U + Priority=1 + HIGH_PRIORITY_CLASS)
.\scripts\install-autostart.ps1

# Uninstall
.\scripts\uninstall-autostart.ps1
```

### 4. Machine-Wide (`HKLM`) Environment Variables

To expose `wsl-bridge` across **both `NT AUTHORITY\SYSTEM` services and all user sessions**:

```powershell
# Run in an elevated PowerShell session
$sysDir = "C:\Program Files\wsl-bridge"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"

# 1. Prepend C:\Program Files\wsl-bridge ahead of C:\Windows\System32 in System PATH
$cur = (Get-ItemProperty -Path $regPath -Name Path).Path
$parts = $cur.Split(';') | Where-Object { $_ -and ($_.TrimEnd('\') -ine $sysDir) }
$newPath = (@($sysDir) + $parts) -join ';'
Set-ItemProperty -Path $regPath -Name Path -Value $newPath

# 2. Set machine-wide CLAUDE_CODE_GIT_BASH_PATH
Set-ItemProperty -Path $regPath -Name CLAUDE_CODE_GIT_BASH_PATH -Value "$sysDir\bash.exe"
```

> **Note on Win32 `CreateProcessW` search order**: When a Windows program calls `CreateProcessW` with a bare `"bash"` string **without** consulting `PATH` (for example Python `subprocess.run(["bash", ...])` without `shell=True` or `shutil.which("bash")`), Windows searches `C:\Windows\System32\bash.exe` before `PATH`. Tools that resolve via `PATH` (`cmd.exe`, PowerShell, `where bash`, `shutil.which`, Node/Agent CLIs, `CLAUDE_CODE_GIT_BASH_PATH`, and DropbearWin `toolsinfo`) all resolve `C:\Program Files\wsl-bridge\bash.exe` first.

---

## CLI Reference

```text
bash.exe [bash-args...]                          Drop-in POSIX bash pass-through
sh.exe [sh-args...]                              Drop-in POSIX sh pass-through
wsl-bridge bash|sh [args...]                     Explicit shell pass-through
wsl-bridge exec [options] -- <cmd> [args...]     Direct binary pass-through
wsl-bridge path --to-linux|--to-win|--mixed <p>  Convert Windows <-> WSL path
wsl-bridge status [--distro D] [--user U]        UTF-8 JSON health status
wsl-bridge daemon [--distro D] [--user U]        High-priority boot-time WSL1 supervisor
wsl-bridge keepalive [start|stop|status]         Manage lightweight WSL1 keepalive
wsl-bridge mcp [--distro D] [--user U]           Run built-in stdio MCP server
wsl-bridge mcp-proxy [options] -- <cmd> [args]   Proxy a Linux MCP server over stdio
```

### Common Options (`exec` / `mcp-proxy`)

- `--distro <name>`: WSL distro name (default: `Debian` or `$WSL_BRIDGE_DISTRO`)
- `--user <name>`: Linux user (default: `amamiya` or `$WSL_BRIDGE_USER`)
- `--cwd <path>`: Working directory (Windows `C:\...` or Linux `/mnt/c/...` or `/home/...`)
- `--env <K=V>`: Extra environment variable (repeatable)
- `--sudo`: Execute via passwordless `sudo` (`exec` mode only)

### Environment Variables

| Variable | Purpose |
| --- | --- |
| `WSL_BRIDGE_DISTRO` | Override default WSL distribution (`Debian`) |
| `WSL_BRIDGE_USER` | Override default Linux user (`amamiya`) |
| `WSL_BRIDGE_NO_BROKER` | Set to `1` to bypass the loopback broker and force direct `wsl.exe` execution |
| `WSL_BRIDGE_ENV_PASSTHROUGH` | Colon/semicolon-separated extra Windows env vars to forward into WSL1 |
| `WSL_BRIDGE_BROKER_TOKEN` | Internal token passed by `daemon` to `broker.py` |

---

## Built-in MCP Server (`wsl-bridge mcp`)

| Tool | Required Args | Optional Args | Description |
| --- | --- | --- | --- |
| `wsl_exec` | `program` | `args`, `cwd`, `env`, `stdin`, `stdin_base64`, `sudo`, `timeout_sec`, `include_base64` | Execute a Linux binary directly with exact `argv` (no shell quoting) |
| `wsl_bash` | `script` | `args`, `cwd`, `env`, `stdin`, `stdin_base64`, `login`, `sudo`, `timeout_sec`, `include_base64` | Run a bash command or multi-line script with PGID timeout cleanup |
| `wsl_path` | `path` | `direction` (`to_linux` \| `to_win` \| `mixed`) | Convert paths between Windows and Debian WSL1 |
| `wsl_status` | *(none)* | *(none)* | Return live Debian WSL1 health, broker status, user, sudo, mounts, and tools |
| `wsl_bg_start` | `program` | `args`, `cwd`, `env`, `log_path`, `sudo` | Start a detached background process in its own Linux PGID |
| `wsl_bg_stop` | `pgid` | *(none)* | Stop a Linux background process group (`SIGTERM` → `SIGKILL`) |

---

## Agent CLI Integration Examples

### Claude Code

- System env (set in `HKLM`): `CLAUDE_CODE_GIT_BASH_PATH=C:\Program Files\wsl-bridge\bash.exe`
- `~/.claude/settings.json`:
  ```json
  {
    "env": {
      "CLAUDE_CODE_GIT_BASH_PATH": "C:\\Program Files\\wsl-bridge\\bash.exe"
    }
  }
  ```
- `~/.claude.json`:
  ```json
  {
    "mcpServers": {
      "wsl-bridge": {
        "command": "C:\\Program Files\\wsl-bridge\\wsl-bridge.exe",
        "args": ["mcp"]
      }
    }
  }
  ```

### OpenAI Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.wsl_bridge]
command = "C:\\Program Files\\wsl-bridge\\wsl-bridge.exe"
args = ["mcp"]
```

### OpenCode (`~/.config/opencode/opencode.jsonc`)

```jsonc
{
  "mcp": {
    "wsl-bridge": {
      "type": "local",
      "command": ["C:\\Program Files\\wsl-bridge\\wsl-bridge.exe", "mcp"],
      "enabled": true
    }
  }
}
```

### Gemini CLI / Antigravity (`~/.gemini/config/mcp_config.json` & `~/.gemini/settings.json`) and Cursor (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "wsl-bridge": {
      "command": "C:\\Program Files\\wsl-bridge\\wsl-bridge.exe",
      "args": ["mcp"]
    }
  }
}
```

### Proxy an MCP Server Running Inside Debian WSL1

```json
{
  "mcpServers": {
    "linux-mcp": {
      "command": "C:\\Program Files\\wsl-bridge\\wsl-bridge.exe",
      "args": [
        "mcp-proxy",
        "--cwd", "C:\\Users\\Amamiya\\Dev-ws",
        "--",
        "/usr/bin/python3", "/home/amamiya/server.py"
      ]
    }
  }
}
```

---

## Verification & Testing

Run the full 40-test suite (14 encoding/binary tests + 26 functional/MCP/PGID/proxy tests):

```powershell
# Encoding, CJK/Emoji/4-byte UTF-8, raw 256-byte binary stdio, Chinese CWD, MCP & mcp-proxy UTF-8 (14 tests)
python test_encoding.py

# Shell pass-through, cygpath, >25KB scripts, WSLENV, sudo, MCP tools, timeout PGID cleanup, keepalive (26 tests)
python verify_wsl_bridge.py

# Quick health check (works under both NT AUTHORITY\SYSTEM and interactive users)
wsl-bridge status
```

Expected results:
- Interactive user session (`Amamiya`): **40/40 PASS** (`14/14` + `26/26`).
- `NT AUTHORITY\SYSTEM` direct session (via `C:\ProgramData\wsl-bridge\broker.json`): `test_encoding.py` **14/14 PASS**, `verify_wsl_bridge.py` **25/26 PASS** (only `keepalive` is user-session-specific because `SYSTEM` has no `HKCU\Lxss` registry hive; WSL1 lifetime is already maintained by `WslBridgeDaemon`).
