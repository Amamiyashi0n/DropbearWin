# Dropbear-win 的依赖边界

Dropbear-win 负责 Windows 单文件交付、构建、Agent 调用工具及 Windows 集成测试。
项目自身的服务入口、端口接管、日志及资源信息模块位于 `src/windows/`；依赖
Makefile 通过明确规则编译这些集成文件，不把 Windows 集成代码伪装为上游源码。
`vendor/dropbear/` 保存引用的 Dropbear 源码树，内部的 `src/`、`libtomcrypt/`、
`libtommath/`、`test/`、Autotools 和 Unix 打包文件属于这个依赖。

当前快照自报版本为 2026.94，已经包含本项目的 Windows 适配修改：例如
`src/win32-*.c`、`src/win-account.c`、`src/win-sftp.c`，以及 SSH 核心中的条件编译
分支。本次整理完整保留这些修改，没有将其描述为未经修改的上游代码，也没有创建
指向未知提交的子模块。根目录 Git 历史和未提交修改均保留。

Linux 交叉编译从根目录运行 `scripts/build-cross.sh`；Windows 本机可使用
`scripts/build-native.ps1`。两者均以 `vendor/dropbear/` 为源码根，在
`build/x64`、`build/x86` 中进行 out-of-tree 编译，输出到 `dist/`。
Windows 测试位于 `tests/`，上游测试仍在 `vendor/dropbear/test/`。
依赖内的 `.github/` 是上游参考内容，不作为 Dropbear-win 根目录工作流执行。

升级依赖时必须保留或迁移 Windows 补丁，并运行 Windows 回归测试；不要直接用
上游压缩包覆盖此目录。将 Windows 改动进一步整理成可重复应用的补丁集属于后续
依赖升级工作，不应在一次目录整理中通过覆盖现有源码来完成。

上游版权与许可保留在 `vendor/dropbear/LICENSE` 及各内嵌库的 LICENSE 中。
