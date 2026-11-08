# Windows 服务模式

EXE 同时支持直接运行和 Windows SCM 服务模式。

**权限提醒：项目 SSH 账号独立于 Windows 用户，不会在登录时切换 Windows 身份。
默认服务以 LocalSystem 运行，远程命令及文件传输继承该服务身份。**

## 从 SSH 启动已登录用户的桌面程序

普通 SSH 命令留在服务的会话 0。需要在目标机物理控制台显示 GUI 时，在 SSH
交互式 CMD 中明确调用：

```cmd
"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --desktop-launch "C:\Windows\System32\notepad.exe"
"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --desktop-launch --session 3 --expect-user agent "C:\Windows\System32\notepad.exe"
```

桌面程序使用所选会话用户的 Windows 主令牌及环境，不继承服务的 SYSTEM
权限，也不会因 SSH 断开而退出。程序路径必须是带盘符的绝对 EXE 路径，后面可以
传递程序参数。默认选择物理控制台；`--session ID` 可选择已有 Active/Connected 的
RDP/控制台会话。建议同时传 `--expect-user agent` 或 `DOMAIN\agent` 防止会话编号复用。
Session 0、未登录、已断开或用户不符会拒绝启动。这不创建新 Windows 登录、不解锁
桌面；应先 `query session`，再选择目标。GUI 启动和 UI 自动化就绪需要分别验证。
此命令依赖 Windows Vista / Server 2008 及更新系统的 WTS 用户令牌接口，
XP / Server 2003 上只禁用该命令，普通 SSH 服务和命令仍保持原兼容目标。

## 使用参数设置开机自动启动

可从任意临时目录在 Windows 控制台或 PowerShell 中运行：

```powershell
.\dropbear-win-x64.exe --install-autostart
# 默认端口是 22；可附加其他服务参数，例如：-p 22222 -K 30
```

32 位系统使用 `dropbear-win-x86.exe`。EXE 内嵌管理员权限请求清单；在支持 UAC
的系统上，首次手动运行会弹出系统权限提示。没有账号配置时，安装命令先交互创建
独立 SSH 账号，再将 EXE 复制到系统盘 `Program Files\DropbearWin`，将账号、
主机密钥迁移到 `%ProgramData%\DropbearWin`，注册自动启动的 `DropbearWin` 服务。
服务以 LocalSystem 身份在开机后、用户登录前运行。XP / Server 2003 的数据目录
使用 `%ALLUSERSPROFILE%\Application Data\DropbearWin`。

复制及注册成功后会清理原 EXE 旁的 `dropbear-win-data`；原 EXE 若仍被当前进程
占用，将在下次重启时删除。安装失败时保留便携文件。已有旧版服务时会明确提示并
在确认后停止、删除和替换；同名服务指向其他程序时也会明确警告，只有确认后才会
接管。目标数据若与便携账号或主机密钥冲突，安装会中止。显式安装命令始终读取当前 EXE 旁的数据，不继承 SSH 服务的
`DROPBEAR_WIN_DATA_DIR` / `DROPBEAR_WIN_ACCOUNT_FILE` 环境变量。
安装后运行 `sc.exe qc DropbearWin`
检查 `START_TYPE` 为 `AUTO_START`，运行 `sc.exe query DropbearWin` 检查服务已启动。
安装目录中的 `uninstall-dropbear-service.cmd` 可执行配套卸载。服务启动不会
弹出 UAC；以后手动运行 EXE 仍会按 Windows 规则请求提升，系统不会永久记住一次
UAC 同意。XP/Server 2003 没有 UAC 时，需要从管理员会话运行安装命令。

SSH 登录 Banner 中的 `SSH user` 只是 Dropbear 自有认证名，不是 Windows 账号。
`Windows user`、`Access token` 和 `Session ID` 才是普通 SSH 命令的实际安全上下文；
服务模式通常明确显示 `NT AUTHORITY\SYSTEM`、`LocalSystem / full SYSTEM`（并注明
它不是普通的提权 Administrator 令牌）和
`Session ID: 0 (service/non-interactive)`。同一 Banner 会显示当前 EXE 的
`--desktop-launch` 调用方式和权限变化：新 GUI 使用所选会话用户的主令牌与
环境，不保留 SSH 的 SYSTEM 令牌；`--session` 可显式选择已登录的 RDP 会话。

## 交互式注册(免参数)

以管理员身份打开控制台直接运行 EXE(不带参数),完成账号设置
(或读取到已有账号)后,程序会询问:

```text
Register this server as the Windows service "DropbearWin"? [y/N]
```

回答 `y` 会将 EXE 与数据迁移到 C 盘、注册自动启动服务、生成卸载脚本并退出
便携进程；回车或其他回答跳过安装,继续作为绿色版控制台程序运行。注册内容:

- 服务名 `DropbearWin`,显示名 `Dropbear for Windows`,自动启动,LocalSystem 身份。
- 服务命令行携带本次启动的全部原始参数,例如
  `"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --service DropbearWin -p 22222`。
- 在安装目录生成 `uninstall-dropbear-service.cmd`，调用 EXE 的 `--uninstall`。
  默认保留 `account.conf`、主机密钥及日志；传入 `--purge-data` 才删除这些数据。
- 由安装后的 EXE 等待当前便携进程退出，再清理原 EXE 和相邻
  `dropbear-win-data` 中的已知程序文件，正常情况下不再依赖重启 Windows 才删除
  原 EXE。绿色版所在目录为空时一并删除；其中的其他文件会保留。

服务已注册且指向本程序时,后续控制台启动不再询问(缺卸载脚本时会补写)。服务名
指向带安装标记的 `Program Files\DropbearWin` 旧版时，会提示继续安装将替换旧程序
和服务配置，并保留已安装的 SSH 账号与主机密钥；确认后执行升级。服务名指向其他
程序时，会提示确认停止该服务并使用当前版本替换其服务配置。权限不足时报告
Windows 错误并退出
当前安装尝试。从管道或重定向 stdin 启动时不出现询问;`--service` 方式与
脚本化部署不受影响。安装或替换完成后会立即启动服务；启动失败时保留
`AUTO_START` 并显示 Windows 错误码，也可随后运行 `net start DropbearWin`。

## 手动注册(--service)

服务入口是：

```text
dropbear-win-x64.exe --service DropbearWin -p 22 -K 30
```

这条命令应由 SCM 启动；直接在终端运行 `--service` 会返回 dispatcher 错误。
32 位系统替换为 `dropbear-win-x86.exe`。服务名必须与注册的名字相同。

## 配置与注册

1. 将 EXE 放到固定目录，例如 `C:\Tools\DropbearWin`。
2. 先直接运行 EXE，完成 SSH 账号设置并确认正常监听，然后按 Ctrl+C 停止。
3. 在管理员 PowerShell 中注册服务：

```powershell
New-Service -Name 'DropbearWin' -DisplayName 'Dropbear for Windows' `
  -BinaryPathName '"C:\Tools\DropbearWin\dropbear-win-x64.exe" --service DropbearWin -p 22 -K 30' `
  -StartupType Manual
Start-Service DropbearWin
Get-Service DropbearWin
```

无需 PowerShell 的系统可在管理员 CMD 使用系统自带的 `sc.exe`：

```bat
sc.exe create DropbearWin binPath= "\"C:\Tools\DropbearWin\dropbear-win-x64.exe\" --service DropbearWin -p 22 -K 30" start= demand
sc.exe start DropbearWin
sc.exe query DropbearWin
```

示例注册为手动启动。需要随系统启动时运行 `sc.exe config DropbearWin start= auto`。
服务注册使用系统默认的 LocalSystem 身份；远程命令继承服务的 Windows 身份。
自定义 SSH 用户名仍然是本项目账号，不是 Windows 用户切换。

## 数据、日志和启动状态

绿色版默认数据目录是 EXE 旁的 `dropbear-win-data`。内置安装流程完成后，
安装目录中的标记使 EXE 改用 `%ProgramData%\DropbearWin`；手工 `sc.exe create`
不会执行迁移，仍使用 EXE 旁的便携数据目录。
服务的默认工作目录固定为 EXE 所在目录，不使用 SCM 的 System32 工作目录。
SCM 服务环境独立于当前终端；在终端设置的 `DROPBEAR_WIN_*` 环境变量不会自动
成为服务配置。上面的基本部署使用默认数据位置和 CMD 后端。

服务模式将启动及连接诊断追加到数据目录的 `service.log`。当前不包含日志轮转。
排查服务启动失败时查看该文件及 `sc.exe query DropbearWin` 的退出码；日志文件
本身打开失败时，通过 SCM 的非零服务退出码反映。缺少账号配置时服务不等待键盘
输入，格式损坏的账号文件会报错退出。默认 22 被占用时会先接管旧监听进程；
权限不足、接管失败或其他端口冲突时不报告 RUNNING。启动阶段为 START_PENDING，监听成功后为
RUNNING，收到停止请求后经 STOP_PENDING 到 STOPPED。

## 停止、升级和任务生命周期

### 卸载内置安装

在目标机本地的管理员控制台运行：

```bat
"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --uninstall
rem 同时删除账号、主机密钥和日志时：
"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --uninstall --purge-data
```

也可运行安装目录中的 `uninstall-dropbear-service.cmd`，并向脚本传入可选的
`--purge-data`。卸载会核验服务指向本安装 EXE，停止并删除服务，然后移除安装
目录中的程序文件。正在运行的 EXE 或脚本可能需要重启 Windows 才能清理完成。
默认保留 `%ProgramData%\DropbearWin` 以便以后重装继续使用原账号和主机身份；
`--purge-data` 只删除本程序已知的数据文件，目录中其他文件会保留并报错。
再次安装时，若便携 EXE 旁没有账号配置，会自动复用保留的数据。若卸载提示需重启
完成文件清理，请重启后再安装。不要从该服务的 SSH 会话执行卸载，因为停止服务会
中断当前命令。

```bat
sc.exe stop DropbearWin
sc.exe query DropbearWin
```

确认 STOPPED 后替换 EXE，再运行 `sc.exe start DropbearWin`。取消注册：

```bat
sc.exe delete DropbearWin
```

取消注册保留 EXE、账号、密钥及日志。服务停止或监听进程意外退出时，连接进程及
其命令进程树会被回收。关闭一个 SSH channel 只回收该 channel 的任务，其他 channel
继续运行。普通命令退出也会清理它产生的后台子孙进程，避免后台进程占住管道导致
客户端一直等不到 EOF。长驻业务进程应使用独立服务，不依赖 SSH 断线后继续运行。
`--desktop-launch` 是明确请求的例外：桌面程序在登录用户的独立会话中运行。

22 的接管同样适用于服务实例：启动控制台实例可以结束旧服务进程，随后 SCM
显示该服务停止；再次启动服务也可以接管控制台实例。双方始终独占绑定，不共享
监听端口。接管会终止旧会话及任务，服务配置、账号和主机密钥保留。如果自行配置了
SCM 自动故障重启，切换到控制台实例前应先用 `sc.exe stop` 停止旧服务，避免恢复策略
再次拉起服务并触发反向接管。

进程树管理采用 XP 可用的 Job API，每个命令一个 Job，不在监听层创建外层 Job。
如果外部启动器已经给服务套入限制性 Job，旧系统上命令分配可能失败；应让 SCM
直接启动 EXE。PE/API 静态检查覆盖旧系统基线，XP/Server 2003 实机运行仍需单独验证。

默认 keepalive 和 idle timeout 未在本次调整中改变。示例的 `-K 30` 是显式设置；
需要空闲断连可追加 `-I 秒数`。此版本不自动配置 SCM 故障重启策略。
