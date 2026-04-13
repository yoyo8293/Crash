#include <windows.h>
#include <cstdio>
#include <string>

__declspec(noinline) void Crash()
{
    int* p = nullptr;
    *p = 42;
}

static LONG WINAPI UnhandledHandler(EXCEPTION_POINTERS* ep)
{
    // Find CrashMonitor.exe in the same directory as this exe
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    std::string monitorPath = exePath;
    auto pos = monitorPath.find_last_of("\\/");
    if (pos != std::string::npos)
        monitorPath = monitorPath.substr(0, pos + 1) + "CrashMonitor.exe";
    else
        monitorPath = "CrashMonitor.exe";

    char cmd[1024] = {};
    snprintf(cmd, sizeof(cmd),
        "\"%s\" --pid %lu --tid %lu"
        " --excode 0x%08lX --exaddr 0x%llX"
        " --rip 0x%llX --rsp 0x%llX --rbp 0x%llX",
        monitorPath.c_str(),
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        ep->ExceptionRecord->ExceptionCode,
        static_cast<unsigned long long>(reinterpret_cast<DWORD64>(ep->ExceptionRecord->ExceptionAddress)),
        static_cast<unsigned long long>(ep->ContextRecord->Rip),
        static_cast<unsigned long long>(ep->ContextRecord->Rsp),
        static_cast<unsigned long long>(ep->ContextRecord->Rbp));

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        // Wait for CrashMonitor to finish writing the dump
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    else
    {
        printf("Failed to launch CrashMonitor: %lu\n", GetLastError());
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

int main()
{
    SetUnhandledExceptionFilter(UnhandledHandler);

    printf("About to crash: writing to null pointer...\n");
    fflush(stdout);

    Crash();

    return 0;
}