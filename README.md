# Dropbear-win

Dropbear-win 是基于 Dropbear 的原生 Windows SSH 服务端。它提供 x64 和 x86 单文件 EXE，
支持便携运行、安装为开机自启服务、SSH 命令执行、SFTP/SCP 文件传输，以及通过 Skill 和
MCP 操作已登录的 Windows 桌面。目标机运行基础 SSH 服务只需对应架构的 EXE 和 Windows
系统组件。

## 快速开始

从 [构建](#构建) 步骤生成 EXE，将对应架构的文件复制到 Windows 上的便携目录。

| Windows 架构 | 构建产物 | PE 兼容基线 |
| --- | --- | --- |
| x64 | `dist/dropbear-win-x64.exe` | NT 5.2 |
| x86 | `dist/dropbear-win-x86.exe` | NT 5.1 |

在目标机双击 EXE，或通过 PowerShell 启动。

```powershell
.\dropbear-win-x64.exe
```

1. 在启用 UAC 的系统上同意管理员权限请求。
2. 首次启动输入 SSH 用户名和密码，再输一遍确认。两次密码不一致时可重新输入。
3. 账号就绪后选择运行方式。输入 `y` 并回车，安装为 Windows 服务。直接回车则继续便携运行。

```text
Register this server as the Windows service "DropbearWin"? [y/N]
```

便携版显示 `[OK]` 和 `RUNNING` 后，可在另一台机器上连接。将示例中的认证名和
主机地址替换为启动时设置的 SSH 用户名和控制台显示的目标地址。

```sh
ssh ssh-user@windows-host
ssh ssh-user@windows-host whoami
```

默认监听 `0.0.0.0:22`。指定其他端口时，服务端使用 `-p 22222`，客户端使用
`ssh -p 22222 ssh-user@windows-host`。若只需本机访问，可用
`-p 127.0.0.1:22222`。便携版按 Ctrl+C 停止。

**启动前请核对 22 端口的占用情况。** 当 22 端口已有监听者时，Dropbear-win 会尝试
结束占用该端口的进程并重新绑定，包括其他 SSH 服务。已有连接可能断开。其他端口
冲突时直接报错。

## 安装、升级与卸载

| 项目 | 便携运行 | 内置安装 |
| --- | --- | --- |
| 程序 | 手动启动的 EXE | `C:\Program Files\DropbearWin\dropbear-win-x64.exe`（x86 使用对应文件） |
| 数据 | EXE 旁的 `dropbear-win-data\` | `%ProgramData%\DropbearWin\` |
| 启动 | 从控制台启动 | `DropbearWin` 服务随系统启动 |
| 命令身份 | 启动 EXE 的 Windows 身份 | 默认 `NT AUTHORITY\SYSTEM` |

表中的安装路径以系统盘为 C 盘的常见配置为例。数据目录保存 `account.conf`、
`hostkey_ed25519` 和运行文件。服务日志在数据目录的 `service.log`。

**安装。** 在便携 EXE 的真实控制台中确认 `[y/N]` 后，安装器复制 EXE、迁移账号及主机
密钥、展开内嵌 Skill/MCP 文件，并注册和启动自动服务。安装器退出后，辅助进程自动
清理原 EXE 和相邻数据目录中的程序文件。若无法启动清理辅助进程，程序会尝试安排
原 EXE 在下次重启时删除，并报告结果。安装目录包含配套卸载脚本。

已有服务指向桌面上的便携 EXE，或指向缺少安装标记的当前 EXE 时，程序仍会询问
是否迁移安装。服务指向当前系统盘安装副本且安装标记存在时，启动该副本会跳过
安装询问。安装提示需要控制台输入，服务模式和重定向 stdin 的启动方式会跳过提示。

**升级。** 从安装目录之外启动新版 EXE，按提示确认升级。升级会替换已安装程序与服务
配置，并保留原 SSH 账号和主机密钥。若已有同名服务指向其他程序，交互安装会先提示
替换，确认后停止该服务并更新配置。安装启动失败时，可从控制台的 Windows 错误码
和服务日志排查。

脚本部署可显式请求安装，后面可带服务器参数。此方式直接进入安装流程。缺少账号
配置时仍需输入账号和密码。

```powershell
.\dropbear-win-x64.exe --install-autostart
sc.exe query DropbearWin
sc.exe qc DropbearWin
```

服务正常启动后，`query` 应显示 `RUNNING`，`qc` 应显示 `AUTO_START`，并指向
系统盘安装副本。自定义 SCM 注册方式及 `--service` 用法见
[手动注册服务](docs/windows-service.md#手动注册--service)。

**卸载。** 在目标机的本地管理员终端运行安装目录中的 `uninstall-dropbear-service.cmd`，
或从同一目录运行以下命令之一。

```powershell
# 卸载服务、程序和内嵌资源，保留账号、主机密钥及日志
.\dropbear-win-x64.exe --uninstall

# 同时删除已安装的账号、主机密钥和日志
.\dropbear-win-x64.exe --uninstall --purge-data
```

卸载可能提示重启以完成在用文件的删除。默认卸载后，从一份没有相邻账号配置的新 EXE
执行 `--install-autostart`，可复用保留下来的账号和主机密钥。

## SSH 身份与文件传输

SSH 用户名和密码由 Dropbear-win 单独管理。登录后，命令和文件操作继承服务端当前
Windows 令牌。默认安装服务以 **LocalSystem、Session 0** 运行，凭有效 SSH 口令即可
取得该 Windows 身份的访问权限。登录信息和 `__dropbear_win_probe__` 分别显示 SSH
认证名、实际 Windows 用户、令牌与会话。口令以带盐的 PBKDF2-HMAC-SHA256 保存，
本构建仅支持口令登录，主机密钥使用 ED25519。

```sh
sftp ssh-user@windows-host
scp local.bin ssh-user@windows-host:C:/Temp/remote.bin
scp ssh-user@windows-host:C:/Temp/remote.bin local.bin
scp -O local.bin ssh-user@windows-host:C:/Temp/remote.bin
```

现代 OpenSSH 的 `scp` 默认使用内嵌的 SFTP v3 服务，`scp -O` 使用内嵌传统 SCP。
Windows 路径可写成 `C:/Temp/remote.bin`。含空格或中文的路径优先通过 SFTP 传输。

交互 Shell 默认使用 `cmd.exe`，终端管道在 UTF-8 和系统 OEM 代码页之间转码。通过
`DROPBEAR_WIN_SHELL=powershell` 可选择已安装的 Windows PowerShell。无 PTY 的命令
保留原始 stdout/stderr。每次远程执行拥有自己的工作目录和环境，前一次的 `cd` 与
环境变量赋值不会延续。

## Agent、Skill 与 MCP

### 通过 SSH 发现能力

SSH 协议标识包含 `skill-mcp=__dropbear_win_manifest__`，认证 Banner 也会提示发现命令。
认证后可用普通 SSH 客户端读取。

```sh
ssh ssh-user@windows-host __dropbear_win_manifest__
ssh ssh-user@windows-host __dropbear_win_probe__
ssh ssh-user@windows-host __dropbear_win_guide__
ssh ssh-user@windows-host __dropbear_win_skill__
ssh ssh-user@windows-host __dropbear_win_mcp__
```

Agent 或连接包装器可跟随发现命令读取清单，按 SHA-256 核对 Skill/MCP 内容，再用
探测结果确认实时 Windows 身份、Shell 与 Session。普通 SSH 客户端是否自动跟随发现
入口取决于客户端实现。

EXE 内嵌 `SKILL.md`、`mcp.json`、MCP 桥接源码和会话辅助脚本。安装时平铺到安装
目录，便携启动时释放到 `dropbear-win-data`。连接端可通过清单和 SFTP 下载整包，
或在 Windows 上用 `--export-agent-files C:\existing-folder` 导出到已有目录。

### 配置连接端 MCP

MCP 是在连接端运行的 Python stdio 桥接器，通过现有 SSH 端口通信。从仓库启动时，
先在连接端准备 Python 3.10 或更新版本。

```sh
python3 -m venv build/mcp-venv
build/mcp-venv/bin/python -m pip install -r tools/requirements-mcp.txt
```

在 MCP 客户端配置中将命令设为虚拟环境 Python 的绝对路径，参数设为
`tools/dropbear_mcp.py` 的绝对路径。通过客户端环境传入
`DROPBEAR_MCP_HOST`、`DROPBEAR_MCP_USER`、`DROPBEAR_MCP_PASSWORD`，
可选 `DROPBEAR_MCP_PORT`（默认 22）和 `DROPBEAR_MCP_ENCODING`。
桥接器按连接端 `known_hosts` 校验主机密钥。完整配置和下载包用法见
[Skill 与 MCP 集成](docs/agent-mcp.md)。

### 命令与桌面会话

| 任务 | MCP 接口 |
| --- | --- |
| 读取发现清单、实时身份与指南 | `dropbear_manifest`、`dropbear_context`、`dropbear_guide` |
| 按当前 SSH 身份执行命令 | `dropbear_run_command`、`dropbear_exec` |
| 查找已登录的控制台或 RDP 会话 | `dropbear_session_list` |
| 在所选用户桌面启动独立程序 | `dropbear_desktop_launch` |
| 以所选用户身份执行并收集结果 | `dropbear_session_exec` |
| 列出窗口、聚焦、点击、输入文字及快捷键 | `dropbear_session_ui` |
| 截取所选会话的整个虚拟桌面（含所有显示器） | `dropbear_session_screenshot` |
| 查询显示模式、测试或应用分辨率 | `dropbear_session_display`、`dropbear_session_set_resolution` |
| 在同一用户会话连续执行多步任务 | `dropbear_session_worker_start/call/stop` |

桌面操作使用所选登录用户的令牌和环境。先枚举会话，再用 Session ID、用户名或两者
共同选定目标。用户有多个可用会话时用 ID 消除歧义。桌面启动针对已有登录，截图和
窗口输入需要可用的桌面。UI 操作先列出窗口，再用返回的 `window_id` 指定目标。
分辨率工具会核验实际结果，RDP 驱动要求客户端调整时会返回对应状态。

从已安装服务的 SSH CMD 中也可直接启动桌面应用。将会话编号和用户名替换为
`query session` 查到的目标。

```cmd
"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --desktop-launch --session 3 --expect-user desktop-user "C:\Windows\System32\notepad.exe"
```

普通命令可用 `tools/windows_exec.py` 通过原生子系统传递 EXE、参数数组、工作目录
和环境，适合含空格、Unicode 或 shell 特殊字符的参数。执行批处理或 PowerShell 脚本时
显式选择对应解释器。将下面的示例请求保存为 `task.json`。

```json
{
  "program": "C:\\Windows\\System32\\whoami.exe",
  "args": [],
  "cwd": "C:\\Users\\Public"
}
```

```sh
python3 tools/windows_exec.py --request task.json ssh-user@windows-host
```

子系统名为 `dropbear-exec-v1`，默认 DBX2 帧。支持 `--input` 传递原始 stdin，
并返回原始 stdout/stderr 和退出码。旧 DBX1 服务可用 `--protocol 1`。普通命令的
子进程受 Windows Job 管理，持续运行的桌面程序使用专用桌面启动接口。

## 构建

Linux 交叉编译需要 Bash、make、Python 3 及目标架构的 MinGW-w64 GCC/binutils。
x64 使用 `x86_64-w64-mingw32-*`，x86 使用 `i686-w64-mingw32-*`。
GCC 需支持 `-mcrtdll=msvcrt-os`，以链接 Windows 系统 CRT。

```sh
bash scripts/build-cross.sh --architecture all --jobs 6
```

用 `--architecture x64` 或 `--architecture x86` 单独构建，`--clean` 可重建所选架构
的构建目录。EXE 输出到 `dist/`，`dist/build-manifest.json` 记录本次构建的文件名、
大小与 SHA-256。Windows 本机构建可使用 MSYS2 和对应 MinGW 工具链。

```powershell
.\scripts\build-native.ps1 -Msys2Root C:\msys64 -Architecture all
```

构建会检查 PE 架构、子系统版本、管理员清单和 DLL/API 导入表。NT 5.1/5.2 是基础 SSH
的静态兼容基线，旧系统仍需实机验证。桌面启动依赖 Vista / Server 2008 或更新系统
的 WTS 接口，截图、分辨率和会话 worker 还需要目标机 Windows PowerShell 及相关 .NET
组件。会话交互已在 Windows 10 / PowerShell 5.1 上验证。

## 验证与排查

Windows 测试机安装 Paramiko 后，可运行基础 SSH 和协议回归。MCP 客户端可在前面
配置的虚拟环境中运行 `tests/test_mcp.py`。

```powershell
python tests/windows_native.py dist/dropbear-win-x64.exe
python tests/windows_protocol.py dist/dropbear-win-x64.exe
python tests/windows_lifecycle.py dist/dropbear-win-x64.exe
```

安装确认、迁移及自动清理可在专用 Wine 环境中回归，包括限制清理进程脱离 Job 的场景。
测试会创建并删除临时 SCM 服务和安装文件，请使用没有现有 DropbearWin 安装的 Wine prefix。

```sh
WINEPREFIX="$PWD/build/wine-setup-test" python3 tests/test_setup_prompt.py \
  dist/dropbear-win-x64.exe dist/dropbear-win-x86.exe
```

- 启动后没有监听时，先检查控制台输出、端口占用和服务状态。以 `RUNNING` 作为监听成功的依据。
- 升级后遇到 SSH 主机指纹不符时，先通过可信渠道核对目标机的实际指纹。
- 非交互输出出现乱码时，按远端程序的实际编码解码，MCP 的 Base64 字段保留原始字节。
- 连接前限流默认全局 5 个、每地址最多 5 个未认证连接，认证宽限 60 秒。启动前可用
  `DROPBEAR_WIN_MAX_UNAUTH`、`DROPBEAR_WIN_MAX_UNAUTH_PER_IP`、
  `DROPBEAR_WIN_AUTH_TIMEOUT` 和 `DROPBEAR_WIN_CONN_RATE` 调整；口令派生并发由
  `DROPBEAR_WIN_KDF_CONCURRENCY` 控制。测试覆盖见 [Windows 回归测试](tests/)。

## 源码与许可

| 目录 | 内容 |
| --- | --- |
| `src/windows/` | 服务安装、端口接管、日志和内嵌资源 |
| `vendor/dropbear/` | 包含 Windows 适配的 Dropbear 源码快照和加密库 |
| `scripts/` | Linux 交叉编译、Windows 本机构建和资源打包 |
| `tools/`、`skills/` | SSH 结构化执行客户端、MCP 桥接与 Agent Skill |
| `tests/`、`docs/` | 回归测试及维护说明 |

维护上游源码快照时参见 [依赖边界](docs/dependencies.md)。许可与版权见
[项目许可](LICENSE) 和 [Dropbear 及组件许可](vendor/dropbear/LICENSE)。

目标仓库初始化时的 [MPL 2.0 许可文本](LICENSES/MPL-2.0.txt) 单独保留。
