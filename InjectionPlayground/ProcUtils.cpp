#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"

FARPROC GetRemoteFunction(LPCWSTR moduleName, LPCSTR functionName) {
    HMODULE hModule = GetModuleHandleW(moduleName);
    if (hModule == NULL) {
        LogError(L"GetModuleHandleW");
        return NULL;
    }
    FARPROC proc = GetProcAddress(hModule, functionName);
    if (!proc) {
        LogError(L"GetProcAddress");
    }
    return proc;
}

// Code by AzureGreen via https://github.com/AzureGreen/InjectCollection
BOOL GetProcessThreadIds(DWORD processId, std::vector<DWORD>& threadIds) {
    // Scan with CreateToolhelp32Snapshot
    // This will enumerate all threads running in the system,
    // but it doesn't require non-standard API functions

    THREADENTRY32 threadEntry = { 0 };
    threadEntry.dwSize = sizeof(THREADENTRY32);

    wil::unique_handle threadSnapshotHandle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!threadSnapshotHandle) {
        return FALSE;
    }

    if (Thread32First(threadSnapshotHandle.get(), &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                threadIds.emplace_back(threadEntry.th32ThreadID);
            }
        } while (Thread32Next(threadSnapshotHandle.get(), &threadEntry));
    }

    return TRUE;
}
