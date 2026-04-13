#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <string>

#pragma comment(lib, "dbghelp.lib")

// ---------------------------------------------------------------------
// Global state shared between crash handler and background dump thread
// ---------------------------------------------------------------------
static HANDLE g_hStartEvent    = nullptr;   // Signal background thread to write dump
static HANDLE g_hCompleteEvent = nullptr;   // Signal crash thread that dump is written

// Safe copies of exception info (not on the crashing thread's stack)
static EXCEPTION_RECORD   g_ExceptionRecord  = {};
static CONTEXT            g_ExceptionContext = {};
static EXCEPTION_POINTERS g_ExceptionPointers = {};
static DWORD              g_CrashThreadId    = 0;

// ---------------------------------------------------------------------
// Build dump file path: <exe_dir>\<exe_name>_<timestamp>.dmp
// ---------------------------------------------------------------------
static std::string BuildDumpPath()
{
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    std::string dumpDir;
    std::string dumpPrefix;
    auto pos = std::string(exePath).find_last_of("\\/");
    if (pos != std::string::npos)
    {
        dumpDir    = std::string(exePath).substr(0, pos);
        dumpPrefix = std::string(exePath).substr(pos + 1);
    }
    else
    {
        dumpDir    = ".";
        dumpPrefix = exePath;
    }

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char dumpPath[MAX_PATH] = {};
    snprintf(dumpPath, MAX_PATH, "%s\\%s_%04d%02d%02d_%02d%02d%02d.dmp",
        dumpDir.c_str(), dumpPrefix.c_str(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return dumpPath;
}

// ---------------------------------------------------------------------
// Background thread: waits for crash signal, then writes minidump
// ---------------------------------------------------------------------
static DWORD WINAPI DumpThreadProc(LPVOID /*lpParam*/)
{
    // Wait until the crash handler signals us
    WaitForSingleObject(g_hStartEvent, INFINITE);

    printf("[DumpThread] Woke up, writing minidump...\n");

    std::string dumpPath = BuildDumpPath();

    HANDLE hFile = CreateFileA(dumpPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[DumpThread] CreateFileA failed: %lu\n", GetLastError());
        SetEvent(g_hCompleteEvent);
        return 1;
    }

    MINIDUMP_EXCEPTION_INFORMATION mei = {};
    mei.ThreadId          = g_CrashThreadId;
    mei.ExceptionPointers = &g_ExceptionPointers;
    mei.ClientPointers    = FALSE;  // Same process, pointers are in our address space

    MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithDataSegs  |
        MiniDumpWithFullMemory |
        MiniDumpWithHandleData |
        MiniDumpWithThreadInfo);

    BOOL ok = MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        dumpType,
        &mei,
        nullptr,
        nullptr);

    CloseHandle(hFile);

    if (ok)
        printf("[DumpThread] Dump written: %s\n", dumpPath.c_str());
    else
        printf("[DumpThread] MiniDumpWriteDump failed: %lu\n", GetLastError());

    // Signal the crash thread that we are done
    SetEvent(g_hCompleteEvent);
    return 0;
}

// ---------------------------------------------------------------------
// Unhandled exception filter: saves crash info, signals dump thread
// ---------------------------------------------------------------------
static LONG WINAPI UnhandledHandler(EXCEPTION_POINTERS* ep)
{
    printf("[CrashHandler] Exception code: 0x%08lX\n", ep->ExceptionRecord->ExceptionCode);
    printf("[CrashHandler] Exception address: 0x%llX\n",
        static_cast<unsigned long long>(reinterpret_cast<DWORD64>(ep->ExceptionRecord->ExceptionAddress)));
    printf("[CrashHandler] RIP=0x%llX RSP=0x%llX RBP=0x%llX\n",
        static_cast<unsigned long long>(ep->ContextRecord->Rip),
        static_cast<unsigned long long>(ep->ContextRecord->Rsp),
        static_cast<unsigned long long>(ep->ContextRecord->Rbp));

    // Copy exception info to global storage so the dump thread doesn't
    // depend on the crashing thread's stack remaining valid.
    CopyMemory(&g_ExceptionRecord,  ep->ExceptionRecord, sizeof(EXCEPTION_RECORD));
    CopyMemory(&g_ExceptionContext, ep->ContextRecord,   sizeof(CONTEXT));
    g_ExceptionPointers.ExceptionRecord = &g_ExceptionRecord;
    g_ExceptionPointers.ContextRecord   = &g_ExceptionContext;
    g_CrashThreadId = GetCurrentThreadId();

    // Wake up the background dump thread
    SetEvent(g_hStartEvent);

    // Suspend this thread until the dump is written
    WaitForSingleObject(g_hCompleteEvent, 10000);

    return EXCEPTION_EXECUTE_HANDLER;
}

// ---------------------------------------------------------------------
// Test crash function
// ---------------------------------------------------------------------
__declspec(noinline) void Crash()
{
    int* p = nullptr;
    *p = 42;
}

// ---------------------------------------------------------------------
// Initialize: create events, start background thread, register handler
// ---------------------------------------------------------------------
static bool InitCrashDump()
{
    g_hStartEvent    = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    g_hCompleteEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);

    if (!g_hStartEvent || !g_hCompleteEvent)
    {
        printf("CreateEvent failed: %lu\n", GetLastError());
        return false;
    }

    HANDLE hThread = CreateThread(nullptr, 0, DumpThreadProc, nullptr, 0, nullptr);
    if (!hThread)
    {
        printf("CreateThread failed: %lu\n", GetLastError());
        return false;
    }
    CloseHandle(hThread);

    SetUnhandledExceptionFilter(UnhandledHandler);

    return true;
}

// ---------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------
int main()
{
    if (!InitCrashDump())
    {
        printf("Failed to initialize crash dump system\n");
        return 1;
    }

    printf("Crash dump system initialized (background thread ready).\n");
    printf("About to crash: writing to null pointer...\n");
    fflush(stdout);

    Crash();

    return 0;
}