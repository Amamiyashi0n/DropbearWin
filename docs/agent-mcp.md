# DropbearWin Skill 与 MCP

Skill 位于 `skills/dropbear-win/`，MCP 入口位于 `tools/dropbear_mcp.py`。
桥接服务运行在 Agent 所在机，通过 SSH 读取目标机内嵌指南、查询身份及执行命令。
目标机使用现有 EXE 即可，不需要额外 Python 或开放新端口。

## 安装

EXE 已内嵌完整 Skill、MCP 桥接源码和会话辅助脚本。安装或升级时，自动将
`SKILL.md`、`mcp.json`、`dropbear_mcp.py`、`windows_exec.py`、`requirements-mcp.txt`、
`session_screenshot.ps1`、`session_display.ps1`、`session_client.py`、`session_interact.ps1`、
`session_interact.cs`、`mcp-reference.md`、`agent-mcp.md`
和 `bundle-manifest.json` 平铺释放到 EXE 的安装目录。
卸载时按内嵌白名单清理这些文件，默认保留 ProgramData 中的账号和主机密钥。
安装失败会回退已更换的资源。无需再手工向目标机复制目录。

通过 SSH Manifest 的 `bundle_directory` 和 `bundle_manifest_path` 下载及校验整包，
再按包内 `agent-mcp.md` 在连接端配置 MCP。绿色版可用
`dropbear-win-x64.exe --export-agent-files C:\existing-folder` 导出同一组文件。
Python 解释器和第三方依赖仍由连接端安装。

发布包回归可用 Windows Python 执行
`python tests/test_agent_bundle.py dist/dropbear-win-x64.exe`。
Linux 可设置独立 `WINEPREFIX` 后加 `--wine` 测试两种 EXE；
`--wine-uninstall` 在未安装 DropbearWin 的隔离 Wine 环境验证默认保留数据和彻底卸载。

在仓库根目录执行（连接端需要 Python 3.10+）：

```sh
python3 -m venv build/mcp-venv
build/mcp-venv/bin/pip install -r tools/requirements-mcp.txt
```

将 `skills/dropbear-win` 文件夹复制到 Agent 的 Skills 目录。例如支持 Codex Skills
的客户端可复制到 `~/.codex/skills/dropbear-win`，然后重新加载 Skill 列表。

MCP 配置示例（通用 JSON 客户端格式；替换为本机实际绝对路径）：

```json
{
  "mcpServers": {
    "dropbear-win": {
      "command": "/absolute/repo/build/mcp-venv/bin/python",
      "args": ["/absolute/repo/tools/dropbear_mcp.py"],
      "env": {
        "DROPBEAR_MCP_HOST": "192.168.30.110",
        "DROPBEAR_MCP_USER": "yunchuan",
        "DROPBEAR_MCP_PORT": "22",
        "DROPBEAR_MCP_ENCODING": "cp936"
      }
    }
  }
}
```

在启动 MCP 的客户端进程环境或其 Secret 配置里提供 `DROPBEAR_MCP_PASSWORD`。
stdio 无法交互询问密码。不要把真实密码提交到仓库。
需使用当前 DropbearWin v2 探测入口；该构建使用口令认证，桥接器不尝试公钥认证。

先通过可信渠道核对目标指纹并用普通 SSH 接受主机密钥。桥接器读取默认
`~/.ssh/known_hosts`，或由 `DROPBEAR_MCP_KNOWN_HOSTS` 指向额外文件。
未知或改变的主机密钥会使连接失败。

## 功能与使用

| 类型 | 名称 | 功能 |
| --- | --- | --- |
| Tool | `dropbear_context` | 实时 Windows 身份、令牌、Session、Shell、能力 JSON |
| Tool | `dropbear_guide` | 目标 EXE 内嵌 Markdown 指南 |
| Tool | `dropbear_manifest` | 发现真实 Skill/MCP 文件路径，并加载 SHA-256 验证后的内容 |
| Tool | `dropbear_sessions` | 查询 Windows Session，返回原始字节和解码文本 |
| Tool | `dropbear_run_command` | 按当前 CMD/PowerShell 语法执行命令 |
| Tool | `dropbear_exec` | 通过 DBX2 执行 EXE、参数数组、cwd、环境及二进制 stdin |
| Tool | `dropbear_desktop_launch` | 在指定的已登录控制台/RDP 会话启动独立程序，可核验用户名 |
| Tool | `dropbear_session_screenshot` | 返回指定 Session 的 PNG 图片及真实用户、Session、尺寸 |
| Tool | `dropbear_session_display` | 查询指定会话的显示设备、当前分辨率和驱动公布的模式 |
| Tool | `dropbear_session_set_resolution` | 预检查并修改指定会话分辨率，重新读取实际值验证 |
| Tool | `dropbear_session_list` | 结构化 WTS 会话、真实用户名、SID、状态和可选标志 |
| Tool | `dropbear_session_exec` | 按 Session/用户执行并收集输出，使用桌面用户环境 |
| Tool | `dropbear_session_ui` | 在指定会话列出窗口、聚焦、点击、输入文字和快捷键 |
| Tool | `dropbear_session_worker_start` | 在指定用户会话中启动常驻 worker |
| Tool | `dropbear_session_worker_call` | 经 SSH/SFTP 调用该 worker 的命令、PowerShell 或 UI 操作 |
| Tool | `dropbear_session_worker_stop` | 正常停止 worker 并清理该 worker 的临时队列 |
| Resource | `dropbear://context` | JSON 格式的实时上下文 |
| Resource | `dropbear://guide` | Markdown 格式的远程指南 |
| Resource | `dropbear://manifest` | Skill/MCP 文件路径与 SHA-256 标识 |
| Prompt | `dropbear_onboarding` | 将实时上下文与指南载入当前任务 |

SSH 最初的协议标识行包含 `skill-mcp=__dropbear_win_manifest__`，直接读取 TCP 开头
及 OpenSSH `-v` 的远端版本行即可发现入口。该标识位于 RFC 4253 的可选注释字段，
整行（包含 CRLF）不超过 255 字节；读取完整清单仍需 SSH 认证。

SSH 认证阶段还默认发送 Agent discovery Banner，非交互 exec 和 SFTP 同样收到，
OpenSSH 客户端显示在 stderr；不会把指引混入命令的 stdout、SFTP 或 DBX2 数据流。
SDK 客户端可能需要读取认证 Banner API（例如 Paramiko `Transport.get_banner()`）。
静默模式和部分客户端可能隐藏此消息。

安装版的 `SKILL.md` 和 `mcp.json` 位于 EXE 安装目录（通常为
`C:\Program Files\DropbearWin`），绿色版启动时将整包生成到 EXE 旁
`dropbear-win-data`。旧版 ProgramData 中的发现文件在升级成功后清理。这些文件由 EXE
维护，随版本更新覆盖，不供用户手工编辑。认证 Banner 给出路径和发现命令：

```sh
ssh user@host __dropbear_win_manifest__
ssh user@host __dropbear_win_skill__
ssh user@host __dropbear_win_mcp__
```

Manifest 给出 `skill_sha256`、`mcp_sha256` 和文件路径。每次连接比较 SHA-256，
变化时重读对应文件。可通过特殊 exec 命令或 SFTP 获取相同原始字节；自动生成文件
失败时仍可使用内嵌命令。MCP 清单描述连接端 stdio 桥接功能，不代表目标机额外运行
MCP 网络端口，也不会自动安装客户端组件。

Agent 先调用 `dropbear_manifest`、`dropbear_context` 和 `dropbear_guide`，再按任务使用执行工具。
MCP 初始化的 instructions 及 Skill 都声明这一发现流程；客户端决定何时读取资源或
提示词，因此不能保证所有 MCP 客户端自动把资源注入上下文。

## 将操作固定在 agent 的桌面会话

普通 `dropbear_exec` 和 `dropbear_run_command` 仍使用 SSH 服务的 SYSTEM 令牌。
新增会话接口明确使用已登录用户的真实令牌、用户配置和环境。通过
`dropbear_session_list` 读取 WTS 的结构化信息，使用 `session_id=3` 或 `username="agent"`
选择目标；两者同时提供时核验所有者。相同用户名有多个可用会话会拒绝选择，需指定 ID。
不会新建登录、解锁、切换其他人的 RDP 连接，也不把 SYSTEM 身份带到用户桌面。
桌面启动、截图、显示查询和分辨率设置也接受 `username` 选择已登录用户。

常驻桌面程序使用 `dropbear_desktop_launch` 启动，选择所需 `username` 或
`session_id` 并核对 PID/窗口。工作目录需要该用户可访问，程序路径需要该用户可执行。
执行命令并收集结果时可直接调用：

```json
{
  "tool": "dropbear_session_exec",
  "arguments": {
    "session_id": 3,
    "username": "agent",
    "program": "C:\\Windows\\System32\\cmd.exe",
    "args": ["/d", "/c", "whoami"],
    "cwd": "C:\\Users\\Public",
    "timeout": 30,
    "encoding": "cp936"
  }
}
```

批处理需显式通过 `cmd.exe /d /s /c` 执行。
结果中的 `security_context` 给出真实 SID、Session、USERPROFILE、APPDATA 和 cwd；
`execution` 给出退出码、Base64/文本输出及 `timed_out`、`output_limit_exceeded`。
普通非零退出码正常返回。命令在恢复执行前加入 Job，结束或超时后回收该命令的子进程；
需要常驻的程序使用 `dropbear_desktop_launch`。

重复操作可使用常驻 worker，MCP 本体留在任何会话/其他机器：

1. `dropbear_session_worker_start(username="agent", idle_timeout=600)`，保存返回的 `worker_id`。
2. `dropbear_session_worker_call(worker_id=..., method="context")` 核对实际用户/Session。
3. `method="exec"` 的 `params` 接受 program/args/cwd/env/stdin_base64，可执行命令行程序与脚本。
4. `method="powershell"` 的 `params={"code":"..."}` 在独立 runspace 执行，可用 `$global:` 保存状态。
5. `method="ui"` 的 params 接受下述 UI 字段；完成后调用 `dropbear_session_worker_stop`。

worker 使用 Windows PowerShell；运行其他语言的脚本时，由调用方提供对应解释器。
每次 exec 是独立进程。需要保持进程内部状态时，可用 desktop_launch 启动常驻程序，
再通过该程序自身的接口交互。应用任务是否成功，需要核验应用自身结果和界面状态。

队列位于 ProgramData/DropbearWin 的随机 `session-<worker_id>` 目录，ACL 仅允许
目标用户、SYSTEM 和 Administrators，传输走已有的 SSH/SFTP，不另开 localhost 服务。
请求含唯一 ID、过期时间、SID 和 Session 核验，串行处理；不要并发提交有前后依赖的请求。
worker 空闲 10～3600 秒自动退出，可用 worker_stop 清理已空闲退出的队列。
主动 stop 后，独立启动的桌面程序继续运行。会话注销会使 worker 不可用，需重新发现。
超时不自动重试，可能已经产生部分副作用；`worker_cleanup` 记录未完成清理的 worker ID。
卸载前请先停止仍在使用的 worker。已在 Windows 10/PowerShell 5.1 验证，核心 SSH
保留原有系统兼容目标，旧系统的桌面交互还需满足 PowerShell 和桌面启动能力要求。

UI 首先执行 `dropbear_session_ui(action="windows", username="agent")`，选定返回的窗口 ID。
`focus/click/text/keys` 都需显式 `window_id`；点击使用物理虚拟桌面屏幕坐标（支持负坐标），
坐标必须位于该窗口内；`keys=["CTRL","A"]` 表示快捷键。可使用现有全屏截图检查结果。
发送前核验实际前台焦点，拒绝聚焦时不会继续发送输入。焦点竞争可能导致部分输入，需检查后
决定是否重试。锁屏/安全桌面不解锁，输入仍受
[Windows SendInput/UIPI](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput)
和 [前台焦点策略](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow) 限制。

回归测试：`tests/test_session_client.py` 验证选择、请求和身份约束；
`tests/test_session_interaction.py 3 agent --node-exe C:\absolute\node.exe --ui`
在真实会话测试用户环境、输出、超时、常驻状态以及独立测试窗口的输入，结束后清理。

`dropbear_exec` 参数示例：

```json
{
  "program": "C:\\Windows\\System32\\whoami.exe",
  "args": [],
  "cwd": "C:\\Users\\Public",
  "timeout": 30,
  "encoding": "cp936"
}
```

执行工具返回 `exit_code`、`stdout`、`stderr`、`stdout_base64`、`stderr_base64`、
`encoding` 和 `security_context`。非零命令退出码仍作为完整结果返回；网络、认证、
超时和协议错误作为 MCP 工具错误返回。桥接器不会自动重试命令。
超时上限 300 秒，输出总量上限 1 MiB，结构化 stdin 上限 256 KiB。
输出编码只影响文本字段，Base64 始终保留原始字节。

普通命令使用 SSH 当前 Windows 令牌及 Session。`dropbear_desktop_launch` 根据实时
探测定位服务器 EXE，再通过结构化通道执行 `--desktop-launch`，支持 `session_id=3`
和 `expected_user="agent"`。它使用所选已登录用户的令牌和环境，新程序独立于 SSH。
不指定 Session 时默认物理控制台。它不创建登录、不解锁桌面；Session 0、已断开或
身份不符会失败。旧版 EXE 未公布相关能力时，工具会报错而非猜测启动参数。

截图示例：`dropbear_session_screenshot(session_id=3, expected_user="agent")`。
客户端桥接器使用随附的 `tools/session_screenshot.ps1`，通过新 launcher 在所选
用户桌面创建短时隐藏截图进程；PNG 经 SFTP 传回，作为 MCP `image/png` 内容返回，
另附实际 Windows 用户、Session、桌面名及虚拟屏幕尺寸/偏移。
截图默认覆盖整个 Session 的虚拟桌面（包含全部显示器），不是只截前台窗口；
返回 `capture_mode=virtual_desktop`。读取后删除唯一命名的
临时文件，不影响其他截图。依赖目标 Windows PowerShell、.NET System.Drawing。
输入桌面锁定、会话不可用或采集失败会报错。PNG 上限 16 MiB，虚拟桌面上限 4000 万
像素。输出是当前可采集桌面的实际像素；工具不解锁、不建立 RDP 登录。

分辨率操作示例：

```text
dropbear_session_display(session_id=3, expected_user="agent")
dropbear_session_set_resolution(session_id=3, expected_user="agent", width=1920, height=1080, test_only=true)
dropbear_session_set_resolution(session_id=3, expected_user="agent", width=1920, height=1080)
```

默认选择主显示器；多显示器时用查询结果中的 `device` 精确选择，可选 `refresh_hz`。
请求始终先做 `CDS_TEST`，随后动态应用，最多等待 3 秒核验实际值；不写注册表、
不修改 DPI 或桌面拓扑。`test_only=true` 只预检查，`applied=false` 是预期结果。
检查返回的 `before`、`after`、`test_code`、`change_code`、`applied`、`verified` 和 `error`。
RDP 驱动可能返回成功但忽略修改，工具会返回 `status=client_resize_required`，此时需
在 RDP 客户端动态调整窗口或用目标分辨率重连。该工具不替用户断开或重建 RDP 会话。
临时结果经 SFTP 读取后删除。

## 验证

```sh
build/mcp-venv/bin/python tests/test_mcp.py
# 配置好上述连接环境后，验证真实 SSH/MCP 链路（只读查询和 echo 探针）：
build/mcp-venv/bin/python tests/test_mcp.py --live
# 桌面探针与截图（参数为已登录的 Session ID 和预期用户名）：
build/mcp-venv/bin/python tests/test_desktop_launch.py 3 agent
build/mcp-venv/bin/python tests/test_session_screenshot.py 3 agent
build/mcp-venv/bin/python tests/test_session_display.py 3 agent
# 可选实测切换到 1280x720，再恢复原模式；RDP 忽略修改时验证错误状态：
build/mcp-venv/bin/python tests/test_session_display.py 3 agent --change
```

本项目使用官方 [MCP Python SDK v1](https://py.sdk.modelcontextprotocol.io/v1/)
的 FastMCP stdio API，并约束 `mcp<2` 以固定 API 主版本。
