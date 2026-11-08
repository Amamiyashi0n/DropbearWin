# DropbearWin 安装目录中的 Skill 和 MCP

这些文件内嵌在 EXE 中，安装及升级时自动释放到 EXE 所在的安装目录
（通常为 `C:\Program Files\DropbearWin`），卸载时一起清理。
`bundle-manifest.json` 记录各文件的长度和 SHA-256。请勿直接修改生成的文件，
升级会覆盖它们。账号和主机密钥仍保存在 `C:\ProgramData\DropbearWin`，
默认卸载保留；`--uninstall --purge-data` 才删除这些数据。

同目录的 `session_client.py`、`session_interact.ps1` 和 `session_interact.cs`
提供按 Session/用户执行、窗口输入和常驻 worker；运行 worker 时会在 ProgramData
生成受 ACL 保护的临时队列目录，完成后用 `dropbear_session_worker_stop` 清理。
会话交互使用 Windows 自带 PowerShell，已在 Windows 10/PowerShell 5.1 验证。

## 从 SSH 发现及读取

```sh
ssh user@host __dropbear_win_manifest__
ssh user@host __dropbear_win_skill__
ssh user@host __dropbear_win_mcp__
ssh user@host __dropbear_win_probe__
```

按照清单中的路径，通过 SFTP 下载整个平铺文件包到连接端。
绿色版也可执行 `dropbear-win-x64.exe --export-agent-files C:\existing-folder`
释放同一组文件；该命令不安装服务。

## 在连接端启动 MCP

MCP 是连接端的 Python stdio 桥接器。目标 Windows 服务运行不需要 Python；
EXE 内嵌了桥接源码和辅助脚本，没有内嵌 Python 解释器或依赖库。
在连接端准备 Python 3.10+，并在下载目录执行：

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-mcp.txt
```

Windows 使用 `.venv\Scripts\python.exe` 和 `.venv\Scripts\pip.exe`。
MCP 客户端通用配置示例（按实际下载位置替换绝对路径）：

```json
{
  "mcpServers": {
    "dropbear-win": {
      "command": "/absolute/client/bundle/.venv/bin/python",
      "args": ["/absolute/client/bundle/dropbear_mcp.py"],
      "env": {
        "DROPBEAR_MCP_HOST": "windows-host",
        "DROPBEAR_MCP_USER": "ssh-user",
        "DROPBEAR_MCP_PORT": "22"
      }
    }
  }
}
```

通过客户端进程环境或密钥存储提供 `DROPBEAR_MCP_PASSWORD`。
先通过可信渠道核对 SSH 主机指纹并加入连接端的 `known_hosts`。
更多工具、编码和会话操作说明见 [mcp-reference.md](mcp-reference.md)。
要安装 Skill 到客户端，可将 `SKILL.md` 和 `mcp-reference.md` 放到其
`dropbear-win` Skill 文件夹中。安装目录布局中的相对链接已适配。
