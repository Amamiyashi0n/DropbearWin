# DropbearWin Skill 与 MCP

Skill 位于 `skills/dropbear-win/`，MCP 入口位于 `tools/dropbear_mcp.py`。
桥接服务运行在 Agent 所在机，通过 SSH 读取目标机内嵌指南、查询身份及执行命令。
目标机使用现有 EXE 即可，不需要额外 Python 或开放新端口。

## 安装

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

服务启动时在数据目录生成 `SKILL.md` 和 `mcp.json`（安装版通常为
`C:\ProgramData\DropbearWin`，绿色版为 EXE 旁 `dropbear-win-data`）。这些文件由 EXE
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
