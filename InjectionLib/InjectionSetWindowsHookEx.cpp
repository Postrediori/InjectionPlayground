#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"
#include "WindowsHookDllCommon.h"
#include "InjectionSetWindowsHookEx.h"


bool InjectThreadWithSetWindowHookEx(DWORD processId, DWORD threadId, const std::wstring& dllPath, int hookType) {
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

    wil::unique_hhook hookHandle(SetWindowsHookExW(hookType, (HOOKPROC)functionAddress, dllModule, threadId));
    if (!hookHandle) {
        LogError(L"SetWindowsHookExW");
        return false;
    }

    Sleep(1000);

    return true;
}

bool InjectWithSetWindowHookEx(DWORD processId, const std::wstring& dllPath, int hookType) {
    std::vector<DWORD> threadIds;
    if (!GetProcessThreadIds(processId, threadIds)) {
        return false;
    }

    DWORD remoteThreadId = threadIds[0]; // TODO: Select in a better way

    if (hookType == 0) {
        hookType = DefaultWindowHookId;
    }
    return InjectThreadWithSetWindowHookEx(processId, remoteThreadId, dllPath, hookType);
}
