# Dropbear for native Windows

## 仓库目录

```text
.
├── vendor/dropbear/   引用的 Dropbear 源码快照，含现有 Windows 适配补丁
├── src/windows/       Windows 服务、端口接管、日志与资源信息集成
├── tests/             Dropbear-win 的 Windows SSH 回归测试
├── tools/             Agent 调用端工具
├── scripts/           Linux 交叉编译与 Windows 本机构建入口
├── docs/              Dropbear-win 的维护与依赖说明
├── build/             本地构建缓存，Git 忽略
└── dist/              可交付 EXE 与本地运行数据，Git 忽略
```

这是 Dropbear-win 仓库；Dropbear 的源码、Autotools、加密库、Unix 测试、工作流及
文档整体放在 `vendor/dropbear/`，不作为本项目的顶层目录。依赖目录保持原有内部
布局。当前引用是包含 Windows 修改的源码快照，并非干净的上游发布包或 Git 子模块；
维护方式见 [依赖说明](docs/dependencies.md)。构建使用 `build/x64` 和
`build/x86`。

该项目把 Dropbear SSH server 编译为原生 Windows 控制台程序，也支持 SCM 服务模式。
MinGW-w64 只参与编译；Linux 交叉构建无需 MSYS2，目标机不需要 MSYS2、MinGW、
Cygwin、PowerShell 或额外运行库。
EXE 内嵌 `requireAdministrator` 清单：在支持 UAC 的 Windows 上，手动启动时由
系统弹出管理员权限提示；服务由 SCM 启动，不需要有人登录确认。

两个交付文件均为静态单文件：

| 文件 | 架构 | PE/系统兼容基线 |
| --- | --- | --- |
| `dist\dropbear-win-x64.exe` | x64 | NT 5.2：XP x64 SP2、Server 2003 SP2 |
| `dist\dropbear-win-x86.exe` | x86 | NT 5.1：XP SP3、WinPE 1.6 |

SSH 面向新版 OpenSSH 和 Xshell，只提供 ED25519 主机密钥及现代算法，不启用 RSA、
SHA-1、CBC、group1、3DES 或 DSS。XP、Server 2003 和 WinPE 1.6 的真实设备运行结果
仍需在对应设备上验证；构建过程会执行 PE 版本和旧系统 API 静态门禁。

## 构建

在 Linux 上使用 MinGW-w64 交叉编译。构建机需要 Bash、make、Python 3，
以及 `x86_64-w64-mingw32-*` 和 `i686-w64-mingw32-*` 的 GCC/binutils 工具链。
GCC 需支持 `-mcrtdll=msvcrt-os`，以链接旧版 Windows 的系统 CRT：

```bash
bash scripts/build-cross.sh --clean
```

`--architecture` 可取 `x64`、`x86` 或 `all`，默认值为 `all`；`--jobs N` 设置并行任务数。
x64 和 x86 使用独立
构建目录 `build/x64`、`build/x86`，输出分别位于 `dist\dropbear-win-x64.exe` 和
`dist\dropbear-win-x86.exe`。

Windows 本机仍可使用 `scripts/build-native.ps1` 与 MSYS2 构建。交叉编译脚本会检查
PE 机器类型、子系统版本、DLL/API 导入表及静态链接状态，并拒绝 Vista+ API、UCRT
或 MSYS2 运行库依赖。

每次构建生成 `dist/build-manifest.json`，列出本次实际生成的架构、文件名、大小和
SHA-256。部署时使用清单中的 EXE；`dist/` 不保留旧版 EXE。

## 运行

直接运行：

```powershell
.\dropbear-win-x64.exe
# 32 位系统使用：.\dropbear-win-x86.exe
```

首次运行会询问自定义 SSH 用户名和密码，随后默认监听 `0.0.0.0:52222`。
**权限提醒：此 SSH 账号有意独立于 Windows 用户数据库；认证成功不会切换 Windows
访问令牌。远程命令和文件传输继承启动 EXE 的 Windows 身份；注册为默认服务时，
该身份是 LocalSystem。** 绿色版直接运行时，数据位于 EXE 旁的
`dropbear-win-data`；同一目录中的 x64 与 x86 程序可共用账号和主机密钥。

监听成功后，控制台会显示 `[OK]`、`RUNNING`、绑定地址、实际可访问的本机 IPv4
地址、SSH 连接命令、认证用户名、Shell、PID 和数据目录。端口占用等监听错误不会
显示成功状态，进程会返回非零退出码。

所有 Windows TCP 监听使用独占绑定。默认 **52222** 发生冲突时，新实例会查询
实际监听 PID，终止旧监听进程及其可回收的子进程，等待结束并重新独占绑定；这也
适用于占用 52222 的其他程序。旧 SSH 会话和任务会结束，账号与主机密钥保留。
多个实例同时启动时会串行执行接管。权限不足或端口仍未释放时，新实例明确报错
退出，不报告 RUNNING，不退回共享绑定。其他端口发生冲突时只报错，不终止占用者。
远程端口转发请求不会触发进程接管。

配置了多个监听端口时，任何一项失败都会使启动失败，避免显示未实际监听的地址。
已有 `account.conf` 会检查内容格式，损坏或读取失败时明确报错；`-h`、`-V` 不会
进入首次账号设置。Ctrl+C、Ctrl+Break 和关闭控制台窗口均触发退出清理。
普通连接日志先格式化完整一行，再通过监听进程与连接进程共享的互斥量写出；
exec 字节调试日志也在同一把锁内输出完整记录，避免多个进程在同一个控制台或
服务日志中逐字符交错。

### 口令认证与验证开销

本移植只提供口令认证：公钥、证书和密钥登录被有意关闭（`DROPBEAR_SVR_PUBKEY_AUTH`
编译为 0），因此不读取 `authorized_keys`，也不需要分发或维护密钥。口令以标准
PBKDF2-HMAC-SHA256（`pbkdf2-sha256$迭代数$盐$摘要`，默认 100000 次）保存，
与 `hashlib.pbkdf2_hmac` 逐字节兼容，单次长度上限为
`DROPBEAR_MAX_PASSWORD_LEN`（100 字节）。

每次口令尝试都要完成一次完整派生，未认证客户端可以随意建连，因此派生并发数有
全局上限：默认取处理器数的四分之一，最少 1、最多 3，可用启动前的
`DROPBEAR_WIN_KDF_CONCURRENCY=1..16` 覆盖。上限通过会话命名互斥量在监听进程和
所有连接进程之间共享；拿不到名额的尝试最多等待 30 秒后失败，避免排队无限增长。
一次失败尝试的服务端 CPU 约 50 ms（优化前的 HMAC 实现约 128 ms）；在默认预认证
限制与进程启动限速之下，30 路未认证连接同时爆破的实测服务端 CPU 约 0.8 核，
同时正常口令登录仍在 0.3 秒内完成。上限只限制并发派生数，不改变失败尝试的
固定退避和每连接最大尝试次数。

### 连接限制与泛洪防护

未认证连接是端口洪水的入口，服务在监听进程一侧做了四层防护，全部默认生效：

1. **并发槽位上限与复用**。默认每个来源地址最多 5 个、全局最多 5 个未认证连接
   进程，超限连接被立即关闭；连接退出或完成认证的瞬间槽位即回收复用。槽位在
   内核 backlog 上排队等待，不消耗进程和内存。
2. **预认证绝对宽限**。连接建立后必须在 60 秒内完成认证，超时断开；持续发送
   数据不能延长宽限，慢速滴注（slowloris）无法长期霸占槽位。正常客户端的
   密钥交换与认证在 1 秒内完成，交互输密码远低于该上限。
3. **进程启动令牌桶**。新连接进程默认以每秒 10 个、突发 20 个的速率启动；
   预算耗尽时新连接在监听 backlog 中排队等待下一轮配额，而不是被关闭。重连
   洪水因此无法把监听进程的 spawn 开销放大成 CPU 负载。
4. **失败背退**。accept 或连接进程创建持续失败（句柄/描述符耗尽）时，监听
   循环自动休眠背退，不会空转打满 CPU。

以上默认值均可用启动前的环境变量覆盖：`DROPBEAR_WIN_MAX_UNAUTH=1..30`（全局
未认证上限）、`DROPBEAR_WIN_MAX_UNAUTH_PER_IP`（每地址上限，不超过全局值）、
`DROPBEAR_WIN_AUTH_TIMEOUT=1..600`（预认证宽限秒数）、`DROPBEAR_WIN_CONN_RATE=
1..200`（每秒启动配额）。设置 `DROPBEAR_WIN_TRACE_LIMITS=1` 后，服务端日志会
按类型记录限流拒绝（每类每秒最多一条），用于现场排查。

`tests/windows_flood.py` 回归覆盖：五槽位上限与超限快速关闭、拒绝风暴的 CPU
上界、宽限超时后的槽位回收、令牌桶的排队与匀速放行。

认证成功后的会话不受以上限制约束，由口令门槛保护。

交互式 SSH 登录会在 Shell 提示符之前显示 MOTD，其中包括 Windows 内核版本和
架构、当前二进制架构、系统兼容模式、主机名、SSH/Windows 用户、当前访问令牌和
完整性级别、Shell、客户端请求的终端类型、实际终端传输方式、连接地址、工作目录
及系统代码页。通过 SSH 执行单条命令时不输出 MOTD，便于脚本稳定读取标准输出。

欢迎页还显示登录时的资源快照：服务器本地时间、逻辑处理器数、CPU 忙碌百分比
（约 200 ms 采样，当前处理器组）、物理内存已用/总量/可用及占用率，以及当前
工作目录所在卷的已用/总量/可用和占用率。容量使用 GiB；磁盘按当前 Windows
身份可见的配额统计。读取失败的指标显示 `unavailable`，不阻止登录。数据为一次性
登录时采集的最新数据，每次登录或打开新的交互式 Shell 都重新采集，显示后不持续
刷新，不复用上次登录的数据；普通 exec、结构化执行和 SFTP 不插入欢迎页。

CMD 交互 Shell 和带 PTY 的 CMD 远程命令会在 SSH 管道边界进行双向流式转码：客户端一侧
统一为 UTF-8，`cmd.exe` 一侧使用目标系统的 OEM 代码页。PowerShell 后端使用原始字节流。
未请求 PTY 的远程命令保持原始字节不变；需要终端文本转码时使用 `ssh -t`，需要
重定向或传输原始数据时不要请求 PTY。

MOTD 会分别列出客户端文本编码、Shell 代码页及其 Windows 名称、输入和输出方向
的转换规则，并明确提示无 PTY 的远程命令保留原始字节且不做文本转换。Shell 为
`cmd.exe` 时，MOTD 会额外给出 `CMD encoding` 行，明确标注 cmd.exe 当前会话正在
使用的代码页及其 Windows 名称；MOTD 本身始终以 UTF-8 直写进 SSH 通道、不经过
终端转码，两端看到的文本完全一致。

默认 shell 是系统目录中的 `cmd.exe`。可以在启动前设置
`DROPBEAR_WIN_SHELL=powershell` 显式选择系统 Windows PowerShell；后端缺失或配置
拼写错误时启动报错，不会悄悄切换解释器。可通过 Dropbear 的 `-p` 参数覆盖监听地址或端口，例如：

```powershell
.\dropbear-win-x64.exe -p 22222
.\dropbear-win-x64.exe -p 127.0.0.1:22222
```

## Windows agent 自动化

Windows 管道现在等待真正的输出 EOF 后再结束通道，避免进程刚退出时截断尚在桥接
线程中的输出。Winsock 非阻塞背压统一映射为 Dropbear 使用的 `EAGAIN`，避免大块
输出时出现 `Error writing: Unknown error` 并断开 SSH。

命令进程退出时通过 Windows 等待回调立即唤醒 SSH 会话循环，减少短命令等待退出码
时的轮询延迟；回调仅负责通知，进程回收和通道关闭仍由会话线程处理，输出仍等待
真实 EOF。`tests/windows_latency.py EXE 报告.json` 可测量持久连接上有输出和无输出
短命令的完整往返延迟，每类预热 5 次后统计 30 次。

服务使用 Windows 原生执行语义，不包含 BusyBox 或 POSIX shell。普通 SSH exec 默认
按 CMD 语法解析。服务端为 CMD `/s /c` 添加外层引号，保留命令内部引号；PowerShell
后端使用 UTF-16LE `-EncodedCommand`，不经过 CMD。命令在客户端发送之前已丢失的
引号仍需在客户端修正。复杂或很长的脚本建议通过 SFTP 上传后执行。

选择 PowerShell（CMD 中可用 `set DROPBEAR_WIN_SHELL=powershell`）：

```powershell
$env:DROPBEAR_WIN_SHELL = 'powershell'
.\dropbear-win-x64.exe
```

Agent 首次连接应执行以下探测，再根据 `shell` 决定语法：

```text
ssh -p 52222 user@host __dropbear_win_probe__
```

返回版本化 JSON，包含 `os=windows`、`shell`、`pty=false`、`transport=pipes`、
`exec_encoding=raw`、`sftp=true`、`exec_subsystem=dropbear-exec-v1`。探测不输出 MOTD。
`pty=false` 表示没有真正的控制台终端，当前管道模式不实现完整的窗口缩放和终端
控制序列。自动化任务优先使用无 PTY exec。

每个命令拥有独立环境块，包含 `USER`、`LOGNAME`、`HOME`、`SHELL`、`TERM`、
`SSH_CLIENT`、`SSH_CONNECTION`。HOME 与默认工作目录为服务启动目录。每个 exec 是
新进程，上一次 exec 的 `cd` 或变量赋值不延续到下一次。

无 PTY 命令与结构化执行入口保留 stdout/stderr 原始字节，不承诺外部工具统一输出
UTF-8。CMD 交互会话保留原有 OEM 转码；PowerShell 后端保留原始字节，避免按 OEM
误解码。PowerShell 文本脚本可显式设置 `[Console]::OutputEncoding`；二进制数据使用
原始流或 SFTP。

### 避免多层转义：原生程序执行

本机客户端 `tools/windows_exec.py` 从 JSON 文件读取请求，通过 SSH subsystem
直接传递程序、参数数组、工作目录和环境变量。远端只需本项目 EXE；Python 和
OpenSSH 仅需安装在调用端，登录密码由 OpenSSH 交互读取。

例如 `task.json`（程序路径请填写目标 Windows 上的实际路径）：

```json
{
  "program": "C:\\Tools\\Python\\python.exe",
  "args": ["C:\\Work\\inspect.py", "argument with spaces", "literal&value", "中文", ""],
  "cwd": "C:\\Work",
  "env": {"TASK_MODE": "test"}
}
```

```text
python tools/windows_exec.py --request task.json --port 52222 user@host
python tools/windows_exec.py --request task.json --input input.bin user@host
```

stdout/stderr 分开返回，退出码通过 SSH exit-status 返回。`program` 应为原生 EXE；
参数按 Microsoft CRT 引号规则编码。自行解析原始命令行的程序（尤其 CMD）仍有自己
的语法；执行 `.cmd`、`.ps1` 请显式调用对应解释器。入口不自动猜测 shell，未实现
持久工作目录或完整伪终端。每个命令使用独立 Windows Job 管理进程树；命令结束、
客户端关闭 channel、连接断开或服务停止时，会回收该命令的子孙进程。不要通过
SSH 命令把后台进程留驻；需要独立常驻的程序应注册为单独的 Windows 服务。

控制工具默认把 program、cwd、环境变量和参数分别编码为 UTF-8，再转成 Base64；
服务端逐字段解码后调用 Windows 原生进程接口。这一层由两端自动处理，JSON 请求
保持原来的写法。普通 `ssh host "命令"` 仍按 shell 语法执行；调用端在交给工具之前
已经丢失的引号或字符，需要从调用端修正。

SSH 子系统名称继续使用 `dropbear-exec-v1`，新请求魔数为四字节 `DBX2`；接着是
program、cwd 字符串、环境变量数量及 name/value 对、参数数量及参数字符串。
数字均为大端 uint32，字符串为“大端 uint32 Base64 字节长度 + Base64 内容”。
只接受标准 Base64 字母表和规范的 `=` 填充，不接受空白、非法 UTF-8 或解码后的 NUL。
完整头部（含魔数、长度、计数和编码内容）最多 1 MiB；环境变量最多 256 个、参数
最多 4096 个，仍受 Windows 32767 字符命令行限制。解析或启动失败返回 125。

头部之后的字节直接作为程序 stdin，stdout/stderr 也保持原始字节，不进行 Base64
转换；客户端通过无 PTY 的 SSH 二进制通道发送，EOF 表示输入结束。Base64 是字段
编码，传输加密由 SSH 提供。服务端继续接受旧 `DBX1` 的原始 UTF-8 字段；连接旧版
服务端时可以给控制工具加 `--protocol 1`。探测结果中的 `exec_protocols: [1,2]` 和
`exec_protocol_default: 2` 声明支持版本，`control_encoding: "base64"` 声明默认编码。

调试时设置 `DROPBEAR_WIN_TRACE_EXEC=1`，服务端 stderr 会记录收到的 exec 字节长度
和转义内容。日志可能包含命令参数；用完删除该环境变量即可关闭。

### Windows 回归测试

`tests/windows_native.py` 使用一次性账号和 loopback 服务，覆盖 CMD/PowerShell、
探测、会话环境、参数转义、Unicode、二进制 stdin、stderr、退出码及 SFTP。
在 Windows 测试机上安装 Paramiko 后执行：

```text
python tests/windows_native.py dist/dropbear-win-x64.exe
python tests/windows_native.py dist/dropbear-win-x86.exe
python tests/windows_protocol.py dist/dropbear-win-x64.exe
python tests/windows_protocol.py dist/dropbear-win-x86.exe
python tests/windows_flood.py dist/dropbear-win-x64.exe
python tests/windows_flood.py dist/dropbear-win-x86.exe
python tests/windows_lifecycle.py dist/dropbear-win-x64.exe
python tests/windows_lifecycle.py dist/dropbear-win-x86.exe
python tests/windows_kdf.py dist/dropbear-win-x64.exe
python tests/windows_kdf.py dist/dropbear-win-x86.exe
```

协议测试覆盖新旧帧、非法 Base64/UTF-8/NUL、截断、长度及计数上限；原生回归还验证
SSH 分片发送、特殊字符逐项还原、二进制输入哈希以及坏请求之后连接仍可继续使用。

口令测试用 `hashlib` 生成的哈希反向验证服务端派生结果，覆盖 10000/100000/200000
迭代数、长口令和非 ASCII 口令，并测量 30 路未认证连接洪泛下的服务端 CPU 占用
（需要 `psutil`）。`tests/windows_flood.py` 验证预认证槽位上限、拒绝风暴 CPU
上界、预认证宽限超时回收与令牌桶排队（需要 `psutil`）：

生命周期测试覆盖启动参数继承、keepalive/idle timeout、认证前连接数限制、认证后
名额释放，以及 channel/连接/监听进程退出时的任务树回收。管理员终端追加
`--service` 会创建随机名称的一次性 SCM 服务，验证启动、停止、重启及启动失败，
结束后删除测试服务。测试账号、密钥和监听端口均独立于部署数据。

`tests/windows_stress.py` 提供有界的本机压力测试，Windows 测试机还需安装 `psutil`。
依次使用 4/12/24 个已认证连接，测试连续命令、交互欢迎页、24 路 1 MiB SFTP
上传下载、100 次登录断连和认证前限流；JSON 报告记录延迟、错误、进程树内存及
句柄峰值、空闲后的监听进程状态和观察到的残留进程。它不是长时间稳定性测试。

```text
python tests/windows_stress.py dist/dropbear-win-x64.exe build/stress-x64.json
python tests/windows_stress.py dist/dropbear-win-x86.exe build/stress-x86.json
```

`tests/windows_usability.py EXE --service` 覆盖首次配置、重复/并发启动、52222
接管、权限失败、IPv6、真实控制台退出和日志、坏配置、带空格/中文路径及服务和
控制台互相接管。需要管理员权限运行完整服务测试；开始前要求本机 52222 没有
现有监听，仅接管测试自己创建的进程。测试结果矩阵见
[使用性排查记录](docs/usability-audit.md)。

## Windows 服务值守

### 从 SSH 启动桌面程序

服务及普通 SSH 命令仍以 LocalSystem 在 Windows 会话 0 运行。需要把 GUI 显示到
当前已登录的物理控制台桌面时，在 SSH 的 CMD 中使用专用命令：

```cmd
"C:\Program Files\DropbearWin\dropbear-win-x64.exe" --desktop-launch "C:\Windows\System32\notepad.exe"
```

可在程序路径后追加参数。程序路径必须是带盘符的绝对 EXE 路径。启动的桌面程序使用
该控制台登录用户的 Windows 令牌和环境，独立于 SSH 会话；SSH 断开后程序仍会运行。
它不会继承 SSH 服务的 SYSTEM 权限。没有用户登录物理控制台时命令明确失败。
此功能需要 Windows Vista / Server 2008 或更新版本；在 XP / Server 2003 上，
普通 SSH 与服务仍可使用。普通 SSH 命令继续保留原有 SYSTEM 权限和会话 0 行为。
若需要启动 RDP 桌面，此命令目前只选择物理控制台会话，不会猜测其他用户的会话。

### 开机自动启动

可从任意临时目录运行：

```powershell
.\dropbear-win-x64.exe --install-autostart
# 需要指定监听端口时：.\dropbear-win-x64.exe --install-autostart -p 52222
```

32 位 Windows 改用 `dropbear-win-x86.exe`。首次运行会申请管理员权限并设置本项目的
SSH 账号，然后将 EXE 复制到系统盘的 `Program Files\DropbearWin`，账号与主机密钥
迁移到 `%ProgramData%\DropbearWin`，注册自动启动服务 `DropbearWin` 指向安装副本。
复制及注册成功后清理原 EXE 旁的便携数据；仍被当前进程使用的原 EXE 会安排在下次
重启时删除。若服务已存在，先停止服务再重新安装；目标位置已有不同账号或主机密钥
时安装会中止并保留两份数据。安装命令不立即启动服务；可运行
`sc start DropbearWin` 启动，用 `sc qc DropbearWin` 核对 `AUTO_START`。

Windows 不会永久记住一次 UAC 同意：以后手动启动 EXE 时仍可能提示；开机时由 SCM
直接启动已注册的服务。默认服务以 LocalSystem 身份运行，SSH 登录后的命令和文件
传输继承该身份。卸载请在目标机本地运行安装目录中的
`uninstall-dropbear-service.cmd`，或执行安装 EXE 的 `--uninstall`；默认保留账号
和主机密钥，附加 `--purge-data` 才会删除安装数据。

直接在控制台运行 EXE(不需要任何参数)时，程序会在账号就绪后询问是否把当前
程序注册为 Windows 服务 `DropbearWin`：回答 `y` 会执行同样的 C 盘迁移并注册
自动启动服务，随后退出当前便携进程；安装目录生成卸载脚本
`uninstall-dropbear-service.cmd`（停止并删除服务及程序文件；安装后的账号与主机密钥
默认保留）。安装成功后，系统盘中的新 EXE 会等待便携进程退出，再自动删除原 EXE
及其 `dropbear-win-data` 中的程序数据；绿色版所在目录为空时也会删除。目录中的其他
文件不会被递归删除。
回答其他值或直接回车则跳过，继续以绿色版控制台方式运行。注册一次
之后，后续启动检测到服务已指向本程序，不再重复询问。若服务指向带安装标记的
系统盘旧版，绿色版会明确提示继续安装将替换旧程序和服务配置，同时保留已安装的
SSH 账号与主机密钥。若同名服务指向其他程序，确认后会停止该服务并用当前版本
替换其服务配置。安装或替换完成后会立即启动新服务；若启动失败，自动启动配置
仍会保留并显示 Windows 错误码。

注册与卸载脚本要求管理员权限；权限不足时报告 Windows 错误并继续控制台运行。
从管道或重定向文件读取 stdin 时不会出现询问，自动化脚本不受影响。

脚本化部署仍可使用 `--service 服务名` 接入 Windows SCM，后面继续接受 `-p`、
`-K`、`-I`、`-j`、`-k` 等 Dropbear 参数。部署、启动及删除命令见
[Windows 服务说明](docs/windows-service.md)。先交互运行完成账号配置，再注册服务；
服务模式缺少账号配置时会快速报错退出。服务只在监听成功后报告 RUNNING。

监听进程向每个连接子进程传递完整启动参数。认证前默认每个来源地址最多 5 个、
全局最多 5 个未认证连接进程（见[连接限制与泛洪防护](#连接限制与泛洪防护)）；
认证成功或连接退出后槽位立即复用。监听进程登记连接进程，连接进程监视监听
进程存活状态，并用每命令一个 Job 回收任务树，避免采用 XP/Server 2003 不支持的
嵌套 Job。正常停止与监听进程意外退出均覆盖这一回收路径。

## SCP 文件传输

两个架构的 EXE 都内置文件传输服务，不要求目标机安装 `scp.exe`、
`sftp-server.exe`、PowerShell、MSYS2 或 Cygwin。新版 OpenSSH 的 `scp` 默认通过
内置 SFTP v3 传输；使用 `scp -O` 时由同一个 EXE 处理传统 SCP 协议。两个模式都
继承启动服务进程的 Windows 访问令牌，并保持二进制原始字节流，不经过终端编码转换。

```powershell
# 上传（新版 OpenSSH 默认模式）
scp -P 52222 .\local.bin user@192.168.1.10:C:/Temp/remote.bin

# 下载
scp -P 52222 user@192.168.1.10:C:/Temp/remote.bin .\local.bin

# 递归传输目录
scp -r -P 52222 .\folder user@192.168.1.10:C:/Temp/

# 强制使用传统 SCP 协议
scp -O -P 52222 .\local.bin user@192.168.1.10:C:/Temp/remote.bin
```

远端 Windows 路径建议使用正斜杠，例如 `C:/Temp/file.bin`。包含空格或中文的路径
优先使用新版默认模式；传统 `scp -O` 仍受客户端远端 shell 引用规则影响。

绿色版运行时，账户、ED25519 主机密钥和 PID 文件保存在 EXE 旁的
`dropbear-win-data`；内置安装完成后改用 `%ProgramData%\DropbearWin`。
停止服务并删除当前数据目录中的 `account.conf`，下次启动时会重新进入账户设置。

每次启动都会先执行 RFC 8032 ED25519 已知向量自检，再验证主机密钥是否可解析，
以及私钥与公钥是否确实匹配。若升级前的旧版本曾留下损坏或无法正确签名的主机
密钥，程序会直接删除坏密钥，不创建 `.invalid` 备份；随后保留 `account.conf` 并
自动生成新密钥。客户端看到主机密钥发生变化时，需要删除对应的旧 `known_hosts`
记录后重新确认新指纹。
