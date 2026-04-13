#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <filesystem>

#pragma comment(lib, "dbghelp.lib")

#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64 12
#endif

struct MappedFile
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = nullptr;
    void* base = nullptr;

    bool Open(const wchar_t* path)
    {
        hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[ERR] CreateFileW failed: %lu\n", GetLastError());
            return false;
        }

        hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap)
        {
            wprintf(L"[ERR] CreateFileMappingW failed: %lu\n", GetLastError());
            Close();
            return false;
        }

        base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!base)
        {
            wprintf(L"[ERR] MapViewOfFile failed: %lu\n", GetLastError());
            Close();
            return false;
        }
        return true;
    }

    void Close()
    {
        if (base)
        {
            UnmapViewOfFile(base);
            base = nullptr;
        }
        if (hMap)
        {
            CloseHandle(hMap);
            hMap = nullptr;
        }
        if (hFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
    }

    ~MappedFile()
    {
        Close();
    }
};

static std::wstring ReadMiniDumpString(void* dumpBase, RVA rva)
{
    if (rva == 0)
        return L"";

    auto p = reinterpret_cast<MINIDUMP_STRING*>((BYTE*)dumpBase + rva);
    if (!p)
        return L"";

    return std::wstring(p->Buffer, p->Length / sizeof(WCHAR));
}

static bool FileExists(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring GetFileNameOnly(const std::wstring& fullPath)
{
    std::filesystem::path p(fullPath);
    return p.filename().wstring();
}

static void PrintLastErrorA(const char* prefix)
{
    DWORD err = GetLastError();
    printf("%s failed, GetLastError=%lu\n", prefix, err);
}

static const wchar_t* GetArchText(USHORT processorArchitecture)
{
    switch (processorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_AMD64: return L"x64";
    case PROCESSOR_ARCHITECTURE_INTEL: return L"x86";
    case PROCESSOR_ARCHITECTURE_ARM64: return L"ARM64";
    default: return L"Unknown";
    }
}

static void PrintExceptionInfo(const MINIDUMP_EXCEPTION_STREAM* exStream)
{
    if (!exStream)
        return;

    wprintf(L"[INFO] Exception thread id : %lu\n", exStream->ThreadId);
    wprintf(L"[INFO] Exception code      : 0x%08lX\n", exStream->ExceptionRecord.ExceptionCode);
    wprintf(L"[INFO] Exception flags     : 0x%08lX\n", exStream->ExceptionRecord.ExceptionFlags);
    wprintf(L"[INFO] Exception address   : 0x%p\n", (void*)exStream->ExceptionRecord.ExceptionAddress);

    if (exStream->ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        exStream->ExceptionRecord.NumberParameters >= 2)
    {
        ULONG_PTR op = exStream->ExceptionRecord.ExceptionInformation[0];
        ULONG_PTR badAddr = exStream->ExceptionRecord.ExceptionInformation[1];

        const wchar_t* opText = L"unknown";
        if (op == 0) opText = L"read";
        else if (op == 1) opText = L"write";
        else if (op == 8) opText = L"execute";

        wprintf(L"[INFO] AV operation       : %s\n", opText);
        wprintf(L"[INFO] AV address         : 0x%p\n", (void*)badAddr);
    }
}

static void PrintThreadContext(const MINIDUMP_THREAD& th, void* dumpBase, USHORT arch)
{
    if (th.ThreadContext.DataSize == 0 || th.ThreadContext.Rva == 0)
    {
        wprintf(L"    Context   : <none>\n");
        return;
    }

    auto ctxBytes = reinterpret_cast<const BYTE*>(dumpBase) + th.ThreadContext.Rva;

    if (arch == PROCESSOR_ARCHITECTURE_AMD64)
    {
        const CONTEXT* ctx = reinterpret_cast<const CONTEXT*>(ctxBytes);
        wprintf(L"    RIP=0x%016llX RSP=0x%016llX RBP=0x%016llX\n",
            static_cast<unsigned long long>(ctx->Rip),
            static_cast<unsigned long long>(ctx->Rsp),
            static_cast<unsigned long long>(ctx->Rbp));
        wprintf(L"    RCX=0x%016llX RDX=0x%016llX R8 =0x%016llX R9 =0x%016llX\n",
            static_cast<unsigned long long>(ctx->Rcx),
            static_cast<unsigned long long>(ctx->Rdx),
            static_cast<unsigned long long>(ctx->R8),
            static_cast<unsigned long long>(ctx->R9));
    }
    else if (arch == PROCESSOR_ARCHITECTURE_INTEL)
    {
#ifdef _M_IX86
        const CONTEXT* ctx = reinterpret_cast<const CONTEXT*>(ctxBytes);
        wprintf(L"    EIP=0x%08lX ESP=0x%08lX EBP=0x%08lX\n",
            ctx->Eip, ctx->Esp, ctx->Ebp);
        wprintf(L"    EAX=0x%08lX EBX=0x%08lX ECX=0x%08lX EDX=0x%08lX\n",
            ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx);
#else
        wprintf(L"    Context   : x86 register dump not supported in x64 build\n");
#endif
    }
    else if (arch == PROCESSOR_ARCHITECTURE_ARM64)
    {
        wprintf(L"    Context   : ARM64 register dump not implemented\n");
    }
    else
    {
        wprintf(L"    Context   : unsupported arch for register dump\n");
    }
}

// Find memory range in Memory64ListStream or MemoryListStream by virtual address
struct DumpMemoryRange { const BYTE* data; DWORD64 startAddr; DWORD64 size; };

static DumpMemoryRange FindMemoryInRange(void* dumpBase, DWORD64 targetAddr)
{
    PMINIDUMP_DIRECTORY dir = nullptr;
    PVOID stream = nullptr;
    ULONG streamSize = 0;

    // Try Memory64ListStream first (used by MiniDumpWithFullMemory)
    if (MiniDumpReadDumpStream(dumpBase, Memory64ListStream, &dir, &stream, &streamSize) && stream)
    {
        auto* mem64List = reinterpret_cast<MINIDUMP_MEMORY64_LIST*>(stream);
        DWORD64 baseRva = mem64List->BaseRva;
        DWORD64 fileOffset = baseRva;

        for (ULONG i = 0; i < mem64List->NumberOfMemoryRanges; ++i)
        {
            const MINIDUMP_MEMORY_DESCRIPTOR64& md = mem64List->MemoryRanges[i];
            DWORD64 mdEnd = md.StartOfMemoryRange + md.DataSize;
            if (targetAddr >= md.StartOfMemoryRange && targetAddr < mdEnd)
            {
                DWORD64 offset = targetAddr - md.StartOfMemoryRange;
                return {
                    reinterpret_cast<const BYTE*>(dumpBase) + static_cast<DWORD64>(fileOffset) + offset,
                    targetAddr,
                    md.DataSize - offset
                };
            }
            fileOffset += md.DataSize;
        }
    }

    // Fallback to MemoryListStream
    if (MiniDumpReadDumpStream(dumpBase, MemoryListStream, &dir, &stream, &streamSize) && stream)
    {
        auto* memList = reinterpret_cast<MINIDUMP_MEMORY_LIST*>(stream);
        for (ULONG i = 0; i < memList->NumberOfMemoryRanges; ++i)
        {
            const MINIDUMP_MEMORY_DESCRIPTOR& md = memList->MemoryRanges[i];
            DWORD64 mdEnd = md.StartOfMemoryRange + md.Memory.DataSize;
            if (targetAddr >= md.StartOfMemoryRange && targetAddr < mdEnd)
            {
                DWORD64 offset = targetAddr - md.StartOfMemoryRange;
                return {
                    reinterpret_cast<const BYTE*>(dumpBase) + md.Memory.Rva + offset,
                    targetAddr,
                    md.Memory.DataSize - offset
                };
            }
        }
    }

    return {nullptr, 0, 0};
}

static void SymbolizeAddress(HANDLE hProcess, DWORD64 addr, UINT frame)
{
    char symBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
    PSYMBOL_INFO pSym = reinterpret_cast<PSYMBOL_INFO>(symBuffer);
    pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSym->MaxNameLen = MAX_SYM_NAME;

    DWORD64 disp = 0;
    const char* symName = "???";
    if (SymFromAddr(hProcess, addr, &disp, pSym))
        symName = pSym->Name;

    IMAGEHLP_LINE64 line = {};
    line.SizeOfStruct = sizeof(line);
    DWORD lineDisp = 0;

    char lineInfo[256] = {};
    if (SymGetLineFromAddr64(hProcess, addr, &lineDisp, &line))
        snprintf(lineInfo, sizeof(lineInfo), " [%s:%lu]", line.FileName, line.LineNumber);

    printf("    #%02u 0x%016llX  %s + 0x%llX%s\n",
        frame,
        static_cast<unsigned long long>(addr),
        symName,
        static_cast<unsigned long long>(disp),
        lineInfo);
}

static void PrintCallStackFromDump(HANDLE hProcess, const MINIDUMP_THREAD& th,
                                    void* dumpBase, USHORT arch,
                                    DWORD exceptionThreadId, DWORD64 exceptionAddr)
{
    if (arch != PROCESSOR_ARCHITECTURE_AMD64)
    {
        wprintf(L"    Stack walk not supported for this architecture.\n");
        return;
    }

    if (th.ThreadContext.DataSize == 0 || th.ThreadContext.Rva == 0)
    {
        wprintf(L"    No thread context available.\n");
        return;
    }

    auto ctxBytes = reinterpret_cast<const BYTE*>(dumpBase) + th.ThreadContext.Rva;
    const CONTEXT* ctx = reinterpret_cast<const CONTEXT*>(ctxBytes);

    DWORD64 stackStart = th.Stack.StartOfMemoryRange;
    DWORD64 stackSize  = th.Stack.Memory.DataSize;
    const BYTE* stackBase = nullptr;

    if (th.Stack.Memory.Rva != 0)
    {
        stackBase = reinterpret_cast<const BYTE*>(dumpBase) + th.Stack.Memory.Rva;
    }
    else if (stackSize > 0)
    {
        // Stack.Rva == 0 with MiniDumpWithFullMemory — look up in MemoryListStream
        DumpMemoryRange range = FindMemoryInRange(dumpBase, stackStart);
        if (range.data)
        {
            stackBase = range.data + (stackStart - range.startAddr);
            stackSize = range.size - (stackStart - range.startAddr);
        }
    }

    if (!stackBase || stackSize == 0)
    {
        wprintf(L"    No stack memory available.\n");
        return;
    }

    UINT frame = 0;

    // For the exception thread, use the exception address as frame 0
    DWORD64 rip = (th.ThreadId == exceptionThreadId) ? exceptionAddr : ctx->Rip;
    DWORD64 rbp = ctx->Rbp;

    SymbolizeAddress(hProcess, rip, frame++);

    // Try RBP chain first
    if (rbp != 0 && rbp >= stackStart && rbp < stackStart + stackSize)
    {
        for (UINT depth = 0; depth < 32; ++depth)
        {
            DWORD64 rbpOffset = rbp - stackStart;
            if (rbpOffset + 16 > stackSize)
                break;

            const BYTE* rbpPtr = stackBase + rbpOffset;
            DWORD64 savedRbp = *reinterpret_cast<const DWORD64*>(rbpPtr);
            DWORD64 retAddr  = *reinterpret_cast<const DWORD64*>(rbpPtr + 8);

            if (retAddr == 0)
                break;

            // Skip return addresses that don't belong to any loaded module
            IMAGEHLP_MODULE64 modInfo = {};
            modInfo.SizeOfStruct = sizeof(modInfo);
            if (!SymGetModuleInfo64(hProcess, retAddr, &modInfo))
                break;

            SymbolizeAddress(hProcess, retAddr, frame++);

            if (savedRbp <= rbp || savedRbp < stackStart || savedRbp >= stackStart + stackSize)
                break;

            rbp = savedRbp;
        }
    }
    else
    {
        // RBP is not usable — scan stack from RSP upward for return addresses
        DWORD64 rspOffset = (ctx->Rsp >= stackStart && ctx->Rsp < stackStart + stackSize)
                            ? ctx->Rsp - stackStart : 0;

        DWORD64 lastAddr = 0;
        for (DWORD64 off = rspOffset; off + 8 <= stackSize; off += 8)
        {
            DWORD64 val = *reinterpret_cast<const DWORD64*>(stackBase + off);

            // Skip zeros and repeats
            if (val == 0 || val == lastAddr)
                continue;

            // Skip if it doesn't look like a code address (must be in a known module)
            IMAGEHLP_MODULE64 modInfo = {};
            modInfo.SizeOfStruct = sizeof(modInfo);
            if (!SymGetModuleInfo64(hProcess, val, &modInfo))
                continue;

            // Skip module base addresses (displacement == 0 means exact module start)
            char symBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
            PSYMBOL_INFO pSym = reinterpret_cast<PSYMBOL_INFO>(symBuffer);
            pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
            pSym->MaxNameLen = MAX_SYM_NAME;

            DWORD64 disp = 0;
            if (!SymFromAddr(hProcess, val, &disp, pSym))
                continue;

            // Skip module entry points with zero displacement (likely not return addresses)
            if (disp == 0)
                continue;

            // Skip tiny displacements — likely module entry or syscall stubs,
            // but keep CRT entry points which may have small offsets
            if (disp < 0x10)
                continue;

            SymbolizeAddress(hProcess, val, frame++);
            lastAddr = val;
        }
    }
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        wprintf(L"Usage:\n");
        wprintf(L"  DumpSymbolizeThreads.exe <dumpfile> [module_search_dir] [symbol_path]\n\n");
        wprintf(L"Examples:\n");
        wprintf(L"  DumpSymbolizeThreads.exe crash.dmp\n");
        wprintf(L"  DumpSymbolizeThreads.exe crash.dmp D:\\bin\n");
        wprintf(L"  DumpSymbolizeThreads.exe crash.dmp D:\\bin \"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols;D:\\pdb\"\n");
        return 1;
    }

    const wchar_t* dumpPath = argv[1];
    std::wstring moduleSearchDir;
    std::wstring symbolPath;

    if (argc >= 3)
        moduleSearchDir = argv[2];
    if (argc >= 4)
        symbolPath = argv[3];
    else
        symbolPath = L"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols";

    MappedFile dumpFile;
    if (!dumpFile.Open(dumpPath))
        return 1;

    HANDLE hProcess = GetCurrentProcess();

    SymSetOptions(
        SYMOPT_UNDNAME |
        SYMOPT_DEFERRED_LOADS |
        SYMOPT_LOAD_LINES |
        SYMOPT_FAIL_CRITICAL_ERRORS
    );

    if (!SymInitializeW(hProcess, symbolPath.c_str(), FALSE))
    {
        wprintf(L"[ERR] SymInitializeW failed: %lu\n", GetLastError());
        return 1;
    }

    wprintf(L"[INFO] Symbol path: %s\n", symbolPath.c_str());

    PMINIDUMP_DIRECTORY dir = nullptr;
    PVOID stream = nullptr;
    ULONG streamSize = 0;

    // -----------------------------------------------------------------
    // 1) SystemInfo
    // -----------------------------------------------------------------
    MINIDUMP_SYSTEM_INFO* sysInfo = nullptr;
    USHORT arch = 0xFFFF;

    if (MiniDumpReadDumpStream(dumpFile.base, SystemInfoStream, &dir, &stream, &streamSize))
    {
        sysInfo = reinterpret_cast<MINIDUMP_SYSTEM_INFO*>(stream);
        arch = sysInfo->ProcessorArchitecture;

        wprintf(L"[INFO] Processor arch      : %s (%u)\n", GetArchText(arch), arch);
        wprintf(L"[INFO] Number of processors: %u\n", sysInfo->NumberOfProcessors);
        wprintf(L"[INFO] OS version          : %u.%u build %u\n",
            sysInfo->MajorVersion, sysInfo->MinorVersion, sysInfo->BuildNumber);
    }
    else
    {
        wprintf(L"[WARN] No SystemInfoStream found.\n");
    }

    // -----------------------------------------------------------------
    // 2) ExceptionStream
    // -----------------------------------------------------------------
    MINIDUMP_EXCEPTION_STREAM* exStream = nullptr;
    DWORD exceptionThreadId = 0;

    if (MiniDumpReadDumpStream(dumpFile.base, ExceptionStream, &dir, &stream, &streamSize))
    {
        exStream = reinterpret_cast<MINIDUMP_EXCEPTION_STREAM*>(stream);
        exceptionThreadId = exStream->ThreadId;
        PrintExceptionInfo(exStream);
    }
    else
    {
        wprintf(L"[WARN] No ExceptionStream found.\n");
    }

    // -----------------------------------------------------------------
    // 3) ModuleListStream
    // -----------------------------------------------------------------
    MINIDUMP_MODULE_LIST* moduleList = nullptr;
    if (!MiniDumpReadDumpStream(dumpFile.base, ModuleListStream, &dir, &stream, &streamSize))
    {
        wprintf(L"[ERR] ModuleListStream not found.\n");
        SymCleanup(hProcess);
        return 1;
    }

    moduleList = reinterpret_cast<MINIDUMP_MODULE_LIST*>(stream);
    wprintf(L"[INFO] Module count         : %lu\n", moduleList->NumberOfModules);

    for (ULONG i = 0; i < moduleList->NumberOfModules; ++i)
    {
        const MINIDUMP_MODULE& mod = moduleList->Modules[i];
        std::wstring dumpModulePath = ReadMiniDumpString(dumpFile.base, mod.ModuleNameRva);
        std::wstring fileNameOnly = GetFileNameOnly(dumpModulePath);

        std::wstring localModulePath = dumpModulePath;
        if (!moduleSearchDir.empty())
        {
            std::filesystem::path candidate = std::filesystem::path(moduleSearchDir) / fileNameOnly;
            if (FileExists(candidate.wstring()))
                localModulePath = candidate.wstring();
        }

        wprintf(L"\n[MODULE %03lu]\n", i);
        wprintf(L"  DumpPath   : %s\n", dumpModulePath.c_str());
        wprintf(L"  LoadPath   : %s\n", localModulePath.c_str());
        wprintf(L"  Base       : 0x%llX\n", static_cast<unsigned long long>(mod.BaseOfImage));
        wprintf(L"  Size       : 0x%lX\n", mod.SizeOfImage);
        wprintf(L"  TimeDate   : 0x%08lX\n", mod.TimeDateStamp);

        DWORD64 loadedBase = SymLoadModuleExW(
            hProcess,
            nullptr,
            FileExists(localModulePath) ? localModulePath.c_str() : nullptr,
            fileNameOnly.empty() ? nullptr : fileNameOnly.c_str(),
            mod.BaseOfImage,
            mod.SizeOfImage,
            nullptr,
            0
        );

        if (loadedBase == 0)
        {
            wprintf(L"  SymLoadModuleExW: FAILED (GLE=%lu)\n", GetLastError());
        }
        else
        {
            wprintf(L"  SymLoadModuleExW: OK     (LoadedBase=0x%llX)\n",
                static_cast<unsigned long long>(loadedBase));
        }
    }

    // -----------------------------------------------------------------
    // 4) ThreadListStream
    // -----------------------------------------------------------------
    MINIDUMP_THREAD_LIST* threadList = nullptr;
    if (MiniDumpReadDumpStream(dumpFile.base, ThreadListStream, &dir, &stream, &streamSize))
    {
        threadList = reinterpret_cast<MINIDUMP_THREAD_LIST*>(stream);
        wprintf(L"\n[THREAD LIST]\n");
        wprintf(L"[INFO] Thread count         : %lu\n", threadList->NumberOfThreads);

        for (ULONG i = 0; i < threadList->NumberOfThreads; ++i)
        {
            const MINIDUMP_THREAD& th = threadList->Threads[i];
            bool isExceptionThread = (th.ThreadId == exceptionThreadId);

            wprintf(L"\n[THREAD %03lu]%s\n", i, isExceptionThread ? L"  <== Exception Thread" : L"");
            wprintf(L"    ThreadId : %lu\n", th.ThreadId);
            wprintf(L"    Suspend  : %lu\n", th.SuspendCount);
            wprintf(L"    Priority : %lu\n", th.Priority);
            wprintf(L"    Teb      : 0x%llX\n", static_cast<unsigned long long>(th.Teb));
            wprintf(L"    Stack.StartOfMemoryRange : 0x%llX\n",
                static_cast<unsigned long long>(th.Stack.StartOfMemoryRange));
            wprintf(L"    Stack.DataSize           : 0x%lX\n", th.Stack.Memory.DataSize);
            wprintf(L"    Stack.Rva                : 0x%lX\n", th.Stack.Memory.Rva);
            wprintf(L"    Context.DataSize         : 0x%lX\n", th.ThreadContext.DataSize);
            wprintf(L"    Context.Rva              : 0x%lX\n", th.ThreadContext.Rva);

            PrintThreadContext(th, dumpFile.base, arch);
        }
    }
    else
    {
        wprintf(L"[WARN] No ThreadListStream found.\n");
    }

    // -----------------------------------------------------------------
    // 5) Symbolize exception address
    // -----------------------------------------------------------------
    if (exStream)
    {
        DWORD64 addr = static_cast<DWORD64>(exStream->ExceptionRecord.ExceptionAddress);

        wprintf(L"\n[SYMBOLIZE EXCEPTION ADDRESS]\n");
        wprintf(L"  Address: 0x%llX\n", static_cast<unsigned long long>(addr));

        IMAGEHLP_MODULE64 moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);

        if (SymGetModuleInfo64(hProcess, addr, &moduleInfo))
        {
            printf("  Module : %s\n", moduleInfo.ModuleName);
            printf("  Image  : %s\n", moduleInfo.ImageName ? moduleInfo.ImageName : "(null)");
            printf("  LoadedImage : %s\n", moduleInfo.LoadedImageName ? moduleInfo.LoadedImageName : "(null)");
        }
        else
        {
            PrintLastErrorA("  SymGetModuleInfo64");
        }

        char symBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
        PSYMBOL_INFO pSym = reinterpret_cast<PSYMBOL_INFO>(symBuffer);
        pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSym->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(hProcess, addr, &displacement, pSym))
        {
            printf("  Symbol : %s + 0x%llX\n", pSym->Name, displacement);
        }
        else
        {
            PrintLastErrorA("  SymFromAddr");
        }

        IMAGEHLP_LINE64 line = {};
        line.SizeOfStruct = sizeof(line);
        DWORD lineDisplacement = 0;

        if (SymGetLineFromAddr64(hProcess, addr, &lineDisplacement, &line))
        {
            printf("  Source : %s:%lu (+0x%lX)\n", line.FileName, line.LineNumber, lineDisplacement);
        }
        else
        {
            PrintLastErrorA("  SymGetLineFromAddr64");
        }
    }

    // -----------------------------------------------------------------
    // 6) Stack walk for each thread
    // -----------------------------------------------------------------
    if (threadList)
    {
        wprintf(L"\n[CALL STACKS]\n");

        for (ULONG i = 0; i < threadList->NumberOfThreads; ++i)
        {
            const MINIDUMP_THREAD& th = threadList->Threads[i];
            bool isExceptionThread = (th.ThreadId == exceptionThreadId);

            wprintf(L"\n[THREAD %03lu TID=%lu]%s\n", i, th.ThreadId,
                isExceptionThread ? L"  <== Exception Thread" : L"");

            if (th.ThreadContext.DataSize == 0 || th.ThreadContext.Rva == 0)
            {
                wprintf(L"    No thread context available.\n");
                continue;
            }

            PrintCallStackFromDump(hProcess, th, dumpFile.base, arch, exceptionThreadId,
                    exStream ? static_cast<DWORD64>(exStream->ExceptionRecord.ExceptionAddress) : 0);
        }
    }

    SymCleanup(hProcess);
    return 0;
}
