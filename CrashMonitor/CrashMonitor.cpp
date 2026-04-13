#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <string>

#pragma comment(lib, "dbghelp.lib")

// ---------------------------------------------------------------------
// Shared: write a minidump for a target process
// ---------------------------------------------------------------------
static bool WriteDumpForProcess(HANDLE hProcess, DWORD dwProcessId,
                                const char* dumpPath,
                                MINIDUMP_EXCEPTION_INFORMATION* pMei)
{
    HANDLE hFile = CreateFileA(dumpPath, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("  CreateFileA failed: %lu\n", GetLastError());
        return false;
    }

    MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithDataSegs |
        MiniDumpWithFullMemory |
        MiniDumpWithHandleData |
        MiniDumpWithThreadInfo);

    BOOL ok = MiniDumpWriteDump(hProcess, dwProcessId, hFile, dumpType,
                                pMei, nullptr, nullptr);

    CloseHandle(hFile);

    if (ok)
        printf("  Dump written: %s\n", dumpPath);
    else
        printf("  MiniDumpWriteDump failed: %lu\n", GetLastError());

    return !!ok;
}

static std::string BuildDumpPath(const std::string& exePath)
{
    std::string dumpDir;
    std::string dumpPrefix;
    auto pos = exePath.find_last_of("\\/");
    if (pos != std::string::npos)
    {
        dumpDir    = exePath.substr(0, pos);
        dumpPrefix = exePath.substr(pos + 1);
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

static std::string GetProcessExePath(HANDLE hProcess)
{
    DWORD size = MAX_PATH;
    char buf[MAX_PATH] = {};
    if (QueryFullProcessImageNameA(hProcess, 0, buf, &size))
        return buf;
    return "";
}

// ---------------------------------------------------------------------
// Mode B: attach to a running process by PID and write dump
// ---------------------------------------------------------------------
static int ModeB(DWORD pid, DWORD tid, DWORD exceptionCode, DWORD64 exceptionAddress,
                  DWORD64 crashRip, DWORD64 crashRsp, DWORD64 crashRbp)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        printf("OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return 1;
    }

    std::string exePath = GetProcessExePath(hProcess);
    printf("Attaching to: %s (PID=%lu TID=%lu)\n", exePath.c_str(), pid, tid);

    // Build a synthetic EXCEPTION_RECORD from the crash info passed via command line
    EXCEPTION_RECORD exRec = {};
    exRec.ExceptionCode    = exceptionCode;
    exRec.ExceptionAddress = reinterpret_cast<PVOID>(exceptionAddress);

    // Build a synthetic CONTEXT using the crash-time registers from the
    // EXCEPTION_POINTERS the target's UnhandledExceptionFilter received.
    // These are the TRUE register values at the moment of the crash,
    // before the OS exception dispatcher modified them.
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    ctx.Rip = crashRip;
    ctx.Rsp = crashRsp;
    ctx.Rbp = crashRbp;

    EXCEPTION_POINTERS ep = {};
    ep.ExceptionRecord = &exRec;
    ep.ContextRecord   = &ctx;

    MINIDUMP_EXCEPTION_INFORMATION mei = {};
    mei.ThreadId          = tid;
    mei.ExceptionPointers = &ep;
    mei.ClientPointers    = FALSE;

    std::string dumpPath = BuildDumpPath(exePath);
    WriteDumpForProcess(hProcess, pid, dumpPath.c_str(), &mei);

    CloseHandle(hProcess);
    return 0;
}

// ---------------------------------------------------------------------
// Mode A: launch child as debugged process
// ---------------------------------------------------------------------
static int ModeA(wchar_t* argv[], int argc)
{
    std::wstring cmdLine;
    for (int i = 1; i < argc; ++i)
    {
        if (i > 1) cmdLine += L' ';
        cmdLine += argv[i];
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(nullptr, cmdLine.data(), nullptr, nullptr, FALSE,
                         DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi))
    {
        printf("CreateProcessW failed: %lu\n", GetLastError());
        return 1;
    }

    std::string childExePath = GetProcessExePath(pi.hProcess);
    printf("Monitoring: %s (PID=%lu)\n", childExePath.c_str(), pi.dwProcessId);

    std::string dumpDir;
    std::string dumpPrefix;
    auto lastSlash = childExePath.find_last_of("\\/");
    if (lastSlash != std::string::npos)
    {
        dumpDir    = childExePath.substr(0, lastSlash);
        dumpPrefix = childExePath.substr(lastSlash + 1);
    }
    else
    {
        dumpDir    = ".";
        dumpPrefix = childExePath;
    }

    DEBUG_EVENT de = {};
    BOOL stillDebugging = TRUE;

    while (stillDebugging)
    {
        if (!WaitForDebugEvent(&de, INFINITE))
        {
            printf("WaitForDebugEvent failed: %lu\n", GetLastError());
            break;
        }

        DWORD continueStatus = DBG_CONTINUE;

        switch (de.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
        {
            DWORD code = de.u.Exception.ExceptionRecord.ExceptionCode;
            if (de.u.Exception.dwFirstChance)
            {
                printf("First-chance exception: 0x%08lX\n", code);
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
            else
            {
                printf("Second-chance exception: 0x%08lX -- writing crash dump\n", code);

                SYSTEMTIME st = {};
                GetLocalTime(&st);
                char dumpPath[MAX_PATH] = {};
                snprintf(dumpPath, MAX_PATH, "%s\\%s_%04d%02d%02d_%02d%02d%02d.dmp",
                    dumpDir.c_str(), dumpPrefix.c_str(),
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, de.dwThreadId);
                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_FULL;
                if (hThread && GetThreadContext(hThread, &ctx))
                {
                    EXCEPTION_POINTERS ep = {};
                    ep.ExceptionRecord = &de.u.Exception.ExceptionRecord;
                    ep.ContextRecord   = &ctx;

                    MINIDUMP_EXCEPTION_INFORMATION mei = {};
                    mei.ThreadId          = de.dwThreadId;
                    mei.ExceptionPointers = &ep;
                    mei.ClientPointers    = FALSE;

                    WriteDumpForProcess(pi.hProcess, pi.dwProcessId, dumpPath, &mei);
                }
                else
                {
                    WriteDumpForProcess(pi.hProcess, pi.dwProcessId, dumpPath, nullptr);
                }
                if (hThread) CloseHandle(hThread);

                TerminateProcess(pi.hProcess, 1);
                stillDebugging = FALSE;
            }
            break;
        }

        case CREATE_PROCESS_DEBUG_EVENT:
            if (de.u.CreateProcessInfo.hFile)
                CloseHandle(de.u.CreateProcessInfo.hFile);
            break;

        case LOAD_DLL_DEBUG_EVENT:
            if (de.u.LoadDll.hFile)
                CloseHandle(de.u.LoadDll.hFile);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            printf("Child exited with code: %lu\n", de.u.ExitProcess.dwExitCode);
            stillDebugging = FALSE;
            break;

        default:
            break;
        }

        if (stillDebugging || de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

// ---------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    // Mode B: CrashMonitor.exe --pid <PID> --tid <TID> [--excode <code>] [--exaddr <addr>] [--rip <addr> --rsp <addr> --rbp <addr>]
    if (argc >= 5 && wcscmp(argv[1], L"--pid") == 0 && wcscmp(argv[3], L"--tid") == 0)
    {
        DWORD pid = static_cast<DWORD>(_wtoi(argv[2]));
        DWORD tid = static_cast<DWORD>(_wtoi(argv[4]));
        DWORD exCode = 0;
        DWORD64 exAddr = 0;
        DWORD64 crashRip = 0, crashRsp = 0, crashRbp = 0;

        for (int i = 5; i + 1 < argc; ++i)
        {
            if (wcscmp(argv[i], L"--excode") == 0)
                exCode = static_cast<DWORD>(wcstoul(argv[++i], nullptr, 16));
            else if (wcscmp(argv[i], L"--exaddr") == 0)
                exAddr = static_cast<DWORD64>(_wcstoi64(argv[++i], nullptr, 16));
            else if (wcscmp(argv[i], L"--rip") == 0)
                crashRip = static_cast<DWORD64>(_wcstoi64(argv[++i], nullptr, 16));
            else if (wcscmp(argv[i], L"--rsp") == 0)
                crashRsp = static_cast<DWORD64>(_wcstoi64(argv[++i], nullptr, 16));
            else if (wcscmp(argv[i], L"--rbp") == 0)
                crashRbp = static_cast<DWORD64>(_wcstoi64(argv[++i], nullptr, 16));
        }

        return ModeB(pid, tid, exCode, exAddr, crashRip, crashRsp, crashRbp);
    }

    // Mode A: CrashMonitor.exe <child.exe> [args...]
    if (argc >= 2)
        return ModeA(argv, argc);

    printf("Usage:\n");
    printf("  Mode A: CrashMonitor.exe <child.exe> [args...]\n");
    printf("  Mode B: CrashMonitor.exe --pid <PID> --tid <TID>\n");
    return 1;
}