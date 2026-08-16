# DSE-Patcher

一个 Windows GUI 小工具，用于临时禁用 / 恢复 Windows 的「驱动签名强制」（Driver Signature Enforcement，DSE）。

- 原作者：gmh5225
- 许可证：GPLv3
- 原项目地址：<https://github.com/gmh5225/DSE-Patcher>

> ⚠️ **警告**
>
> 本工具通过 BYOVD（Bring Your Own Vulnerable Driver）方式加载带有微软签名的旧漏洞驱动，并获得内核任意读写能力。
> 仅限在你自己拥有或已获授权的系统上用于安全研究、教学与故障排查。
> 禁用 DSE 会显著降低系统安全性；在现代 Windows 上，驱动黑名单、HVCI / 内存完整性、VBS 等机制可能导致漏洞驱动无法加载，或 patch 不生效。
> 使用本工具产生的一切后果由使用者自行承担。

---

## 原理

1. 工具内嵌以下经过微软签名、但存在任意内核读写漏洞的旧驱动之一：
   - RTCore64 v4.6.2（来自 MSI Afterburner）
   - Dell DBUtil v2.3 / v2.5 / v2.6 / v2.7
2. 程序以管理员权限运行，释放并加载所选驱动，通过其 IOCTL 获得内核内存读写能力。
3. 程序定位内核中的 DSE 开关变量：
   - Windows Vista / 7：`ntoskrnl.exe` 中的 `g_CiEnabled`
   - Windows 8 及更高版本：`ci.dll` 中的 `g_CiOptions`
4. 将变量改写为：
   - Disable：`0`（`g_CiEnabled`）或 `0`（`g_CiOptions`）
   - Enable：`1`（`g_CiEnabled`）或 `6`（`g_CiOptions`）

修改仅影响当前运行中的内核，重启后一般会恢复；GUI 也提供 Restore 功能写回第一次读取到的原始值。

---

## 当前分支：`fix/x64support`

本分支在 32 位（WOW64）宿主支持与健壮性上做了以下主要修复：

- 修复 32 位进程解析 `NtQuerySystemInformation(SystemModuleInformation)` 时结构体错位的问题，不再报 `Can't get image base of CI.DLL!`。
- 不再用 `LoadLibraryEx` 加载 64 位内核 PE；改为读取磁盘文件并自行解析 PE。
- 在 32 位进程读取 `C:\Windows\System32\ntoskrnl.exe` / `ci.dll` 时，临时关闭 WOW64 文件系统重定向。
- 重新定义内核模块信息结构为 `RTL_PROCESS_MODULES64` / `RTL_PROCESS_MODULE_INFORMATION64`，避免与 `winternl.h` 同名类型冲突，并保持 x64 构建正常。
- 修复 `RtlGetVersion` 的 ANSI / Wide 结构体混用问题。
- 补齐 PE 解析、导出表解析、特征码扫描的边界检查。
- 修复 `g_CiOptions` 反汇编匹配中的一处 `&&` / `||` 优先级问题。
- 修复驱动文件半解包、服务停止流程、ACL 内存泄漏、计时器缓冲区溢出等健壮性问题。
- Win32 构建改用 `/MT` 默认静态 CRT；x64 Release 继续使用内嵌的 amd64 `msvcrt.lib` 方案，免装 VC 运行库。

详细改动见提交历史与 `fix/x64support` 分支的 `git diff`。

---

## 支持的驱动

| 驱动 | 来源 | 最低系统 | 备注 |
|------|------|----------|------|
| RTCore64 v4.6.2 | MSI Afterburner v4.6.2 Build 15658 | Windows Vista | 服务方式加载 |
| Dell DBUtil v2.3 | OptiPlex 7070 v1.0.2 BIOS Update | Windows Vista | 服务方式加载；Win11 22H2+ 被驱动黑名单阻止 |
| Dell DBUtil v2.5 | OptiPlex 7070 v1.7.0 BIOS Update | Windows 10 1507+ | INF / PnP 方式安装 |
| Dell DBUtil v2.6 | OptiPlex 7070 v1.7.2 BIOS Update | Windows 10 1507+ | INF / PnP 方式安装 |
| Dell DBUtil v2.7 | OptiPlex 7070 v1.10.0 BIOS Update | Windows 8 | INF / PnP 方式安装 |

内嵌驱动均为 64 位，因此**宿主机必须运行 64 位 Windows**；宿主的 DSE-Patcher 进程可以是 64 位，也可以是 32 位（WOW64）。

---

## 构建

### 环境

- Windows 10 / 11 x64
- Visual Studio 2022
- LLVM-MSVC v143 工具链
- Windows 10 SDK
- 字符集：MultiByte

### 使用 Visual Studio

1. 打开 `DSE-Patcher.sln`。
2. 配置选择 `Release | x64`（推荐）或 `Release | Win32`（32 位宿主）。
3. 生成解决方案。

### 使用命令行

```bat
msbuild DSE-Patcher.sln /p:Configuration=Release /p:Platform=x64
msbuild DSE-Patcher.sln /p:Configuration=Release /p:Platform=Win32
```

### 构建说明

- `Release|x64` 使用 `IgnoreAllDefaultLibraries + 项目内 amd64 msvcrt.lib`，生成物不依赖额外安装的 VC 运行库。
- `Release|Win32` 使用 `/MT` 默认静态 CRT，避免误链 amd64 的 `msvcrt.lib`。
- 两个 Release 配置均设置 `RequireAdministrator` UAC。

---

## 使用

1. 以管理员身份运行 `DSE-Patcher.exe`。
2. 在驱动下拉框中选择一个可用的漏洞驱动。
3. 启动时程序会自动读取当前 DSE 状态。
4. 点击对应按钮：
   - `DSE Disable`：禁用驱动签名强制
   - `DSE Enable`：启用驱动签名强制
   - `DSE Restore`：恢复为启动时读取到的原始值
5. 观察界面中的 DSE Patch Data 与状态栏输出。

如果弹窗提示 `Can't create and start service!` / `Can't install driver!`，通常说明所选漏洞驱动被当前系统的驱动黑名单、HVCI / 内存完整性或杀软拦截，这属于系统侧限制。

---

## 文件结构

```text
DSE-Patcher/
├── DSE-Patcher.sln
└── DSE-Patcher/
    ├── DSE-Patcher.vcxproj
    ├── MyDialog1.cpp / .h    # GUI 入口、对话框、按钮、tooltip、状态栏
    ├── MyFunctions.cpp / .h  # 版本探测、内核模块基址、特征码定位、服务与驱动安装
    ├── RTCore64.cpp / .h     # RTCore64 驱动内嵌字节数组与 IOCTL 封装
    ├── DBUtil.cpp / .h       # Dell DBUtil 驱动内嵌字节数组与 IOCTL 封装
    ├── hde64.c / .h          # Hacker Disassembler Engine 64
    ├── table64.h
    ├── pstdint.h
    └── msvcrt.lib            # x64 Release 使用的 amd64 导入库
```

---

## 常见问题

### 提示 `Can't get image base of CI.DLL!`

本分支已修复 32 位（WOW64）宿主下的结构体错位问题。请确认：

- 使用 `fix/x64support` 分支源码；
- 重新构建对应的 Win32 / x64 配置；
- 以管理员身份运行。

### 驱动加载失败

优先检查：

- 是否启用了 Windows 内存完整性（HVCI）；
- Windows 11 22H2+ 是否已阻止所选驱动（尤其 Dell DBUtil v2.3）；
- 安全软件 / EDR 是否拦截了服务或驱动文件释放。

### 32 位进程安装 DBUtil v2.5 / v2.6 / v2.7

RTCore64 与 DBUtil v2.3 使用服务管理器加载，32 位宿主路径最直接。DBUtil v2.5+ 使用 SetupAPI / INF 安装，建议在 32 位宿主上优先选择前两者，或使用 x64 构建。

---

## 许可证

本项目以 GPLv3 许可证发布，详见 `gpl.txt`。

---

## 免责声明

本工具仅供合法授权下的安全研究、教学与系统维护使用。请勿在无权访问的系统上运行。修改内核安全变量、加载漏洞驱动可能导致系统不稳定、安全机制失效或蓝屏，风险由使用者自行承担。
