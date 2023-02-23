#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"
#include "WindowsHookDllCommon.h"
#include "InjectionSetWindowsHookEx.h"


bool InjectThreadWithSetWindowHookEx(DWORD processId, DWORD threadId, const std::wstring& dllPath) {
    (void)(processId);

    HMODULE dllModule = LoadLibraryW(dllPath.c_str());
    if (dllModule == NULL) {
        LogError(L"LoadLibraryW");
        return false;
    }

    FARPROC functionAddress = GetProcAddress(dllModule, WINDOWS_HOOK_DLL_LOADER_FUNC_STR);
    if (functionAddress == NULL) {
        LogError(L"GetProcAddress");
        return false;
    }

    // constexpr int hookId = WH_KEYBOARD;
    constexpr int hookId = WH_GETMESSAGE;
    wil::unique_hhook hookHandle(SetWindowsHookExW(hookId, (HOOKPROC)functionAddress, dllModule, threadId));
    if (!hookHandle) {
        LogError(L"SetWindowsHookExW");
        return false;
    }

    Sleep(1000);

    return true;
}

bool InjectWithSetWindowHookEx(DWORD processId, const std::wstring& dllPath) {
    std::vector<DWORD> threadIds;
    if (!GetProcessThreadIds(processId, threadIds)) {
        return false;
    }

    DWORD remoteThreadId = threadIds[0]; // TODO: Select in a better way

    return InjectThreadWithSetWindowHookEx(processId, remoteThreadId, dllPath);
}
