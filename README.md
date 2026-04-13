# Crash - Windows Crash Dump Analysis Toolchain

Windows x64 平台上的崩溃转储（minidump）生成与分析工具集，涵盖三种 dump 生成方案和一套离线符号化分析器。

## 项目结构

```
Crash/
├── CrashDump/           # 崩溃程序 + 方式 B（启动外部进程写 dump）
├── CrashMonitor/        # 外部 dump 写入进程（方式 A 调试器模式 + 方式 B attach 模式）
├── CrashDumpThread/     # 方式 C：UE5 风格后台线程写 dump
├── CrashDumpSymbol/     # minidump 离线符号化分析器
└── bin/                 # 编译输出目录（Release/Debug）
```

## 三种 Dump 生成方案

### 方式 A — 调试器父进程（CrashMonitor Mode A）

```
CrashMonitor.exe MyApp.exe [args...]
```

CrashMonitor 以 `DEBUG_ONLY_THIS_PROCESS` 启动子进程，作为调试器监听异常事件。子进程崩溃时，调试器在 second-chance exception 时捕获完整的线程上下文并写 dump。

- 崩溃线程 CONTEXT 干净（RBP 指向真实栈帧），调用栈完整
- 需要修改启动命令，对现有部署有侵入

### 方式 B — 崩溃时启动外部进程（CrashDump + CrashMonitor Mode B）

程序正常运行，崩溃时在 `SetUnhandledExceptionFilter` 中启动 `CrashMonitor.exe`，通过命令行传入进程/线程 ID 和崩溃时的寄存器值：

```
CrashMonitor.exe --pid <PID> --tid <TID> --excode 0xC0000005 --exaddr 0x... --rip 0x... --rsp 0x... --rbp 0x...
```

CrashMonitor 通过 `OpenProcess` + `MiniDumpWriteDump` attach 到目标进程写 dump。崩溃线程在 handler 中 `WaitForSingleObject` 等待 dump 完成后再退出。

- 无需修改启动方式，对部署无侵入
- 崩溃线程 RBP 已被 OS 异常分发器修改，调用栈回溯只有 1 帧
- ExceptionStream 中异常地址正确
- 需要额外部署 CrashMonitor.exe

### 方式 C — 后台线程写 dump（CrashDumpThread）

UE5 风格方案：程序启动时预创建后台线程，等待事件信号。崩溃时 handler 将异常信息拷贝到全局存储，通知后台线程写 dump，崩溃线程挂起等待完成。

- 全进程内完成，无外部依赖
- 实现最简单
- 与方式 B 相同的 RBP 脏问题，调用栈只有 1 帧
- ExceptionStream 中异常地址正确

### 方案对比

| | 方式 A (调试器) | 方式 B (外部进程) | 方式 C (后台线程) |
|---|---|---|---|
| 崩溃地址 | 正确 | 正确 | 正确 |
| 调用栈 | 完整 | 仅 1 帧 | 仅 1 帧 |
| 部署侵入 | 需改启动命令 | 需部署 exe | 无 |
| 外部依赖 | 无 | CrashMonitor.exe | 无 |
| 实现复杂度 | 中 | 中 | 低 |

## Dump 分析器（DumpSymbolizeThreads）

离线分析 minidump 文件，输出模块列表、异常信息、线程上下文和符号化调用栈。

```
DumpSymbolizeThreads.exe <dumpfile> [module_search_dir] [symbol_path]
```

### 功能

- 解析 SystemInfo / Exception / ModuleList / ThreadList 流
- 符号化异常地址（函数名 + 偏移 + 源文件行号）
- 自动加载 PDB 符号文件
- 支持 Microsoft 符号服务器 (`srv*CacheDir*URL` 格式)
- x64 调用栈回溯：
  - RBP 链式回溯（Debug 构建或开启帧指针时）
  - 栈扫描回退（Release 构建帧指针省略时）
  - 支持 Memory64ListStream（`MiniDumpWithFullMemory` 生成的大内存 dump）
- 异常线程第 0 帧使用 ExceptionStream 中的异常地址（而非 CONTEXT 中的 RIP）
- 过滤非模块地址和零偏移地址，避免垃圾帧

### 输出示例

```
[INFO] Exception code      : 0xC0000005
[INFO] Exception address   : 0x00007FF7A9CA1EF2
[INFO] AV operation       : write
[INFO] AV address         : 0x0000000000000000

[SYMBOLIZE EXCEPTION ADDRESS]
  Symbol : Crash + 0x2
  Source : CrashDumpThread.cpp:140

[CALL STACKS]
[THREAD 000 TID=57612]  <== Exception Thread
    #00 0x00007FF7A9CA1EF2  Crash + 0x2 [CrashDumpThread.cpp:140]
```

## 编译

要求 Visual Studio 2019+ 和 CMake 3.15+。

```bash
# 编译单个项目
cd CrashDumpSymbol
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# 输出到 bin/Release/ 目录
```

所有子项目的 CMakeLists.txt 配置了统一的输出目录 `../bin/$<CONFIG>`，编译产物集中到 `bin/Release/` 或 `bin/Debug/`。

Release 构建自动启用 `/Zi /Oy- /DEBUG`，生成 PDB 并尽量保留帧指针。

## 技术要点

### RBP 污染问题

Windows x64 的 OS 异常分发器在调用 `UnhandledExceptionFilter` 之前会修改寄存器上下文。RBP 不再指向崩溃时的栈帧，而是指向 handler 的栈帧。这导致基于 RBP 链的调用栈回溯只能得到 1 帧（崩溃点本身），无法回溯到调用者。

方式 A 通过调试器模式避免了这个问题——调试器在 second-chance exception 时直接通过 `GetThreadContext` 获取未修改的线程上下文。

### Memory64ListStream

使用 `MiniDumpWithFullMemory` 标志生成的 dump，内存数据存储在 `Memory64ListStream` 而非 `MemoryListStream` 中。线程的 `Stack.Rva` 为 0，需要通过 `Memory64ListStream` 的 `BaseRva` + 顺序遍历 `MINIDUMP_MEMORY_DESCRIPTOR64` 来定位栈内存。

### 符号路径格式

```
srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

格式为 `srv*<本地缓存目录>*<符号服务器URL>`。DbgHelp 先查本地缓存，未找到则从服务器下载并缓存。多个路径用分号分隔。