#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"
#include "InjectionByApc.h"

bool InjectIntoThreadHandleWithApc(FARPROC loadLibraryFunc, HANDLE remoteThreadHandle, UINT_PTR dllPathData) {
    __try {
        if (QueueUserAPC((PAPCFUNC)loadLibraryFunc, remoteThreadHandle, dllPathData) == 0) {
            return false;
        }
    }
    __except (EXCEPTION_CONTINUE_EXECUTION) {
        return false;
    }

    return true;
}

bool InjectIntoThreadWithApc(DWORD processId, DWORD remoteThreadId, const std::wstring& dllPath) {
    wil::unique_handle remoteProcessHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId));
    if (!remoteProcessHandle) {
        LogError(L"OpenProcess");
        return false;
    }

    wil::unique_handle remoteThreadHandle(OpenThread(THREAD_ALL_ACCESS, FALSE, remoteThreadId));
    if (!remoteThreadHandle) {
        LogError(L"OpenThread");
        return false;
    }

    // Calculate how many bytes to write into the remote buffer
    size_t libraryPathSizeBytes = (dllPath.length() + 1) * sizeof(wchar_t);

    // Allocate library address in the remote process
    LPBYTE buffer = static_cast<LPBYTE>(VirtualAllocEx(remoteProcessHandle.get(), NULL, libraryPathSizeBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!buffer) {
        LogError(L"VirtualAllocEx");
        return false;
    }

    if (WriteProcessMemory(remoteProcessHandle.get(), buffer, dllPath.c_str(), libraryPathSizeBytes, NULL) == 0) {
        LogError(L"WriteProcessMemory");
        return false;
    }

    // Get address of LoadLibraryW function
    FARPROC loadLibraryFunc = GetRemoteFunction(L"kernel32.dll", "LoadLibraryW");
    if (!loadLibraryFunc) {
        return false;
    }

    if (!InjectIntoThreadHandleWithApc(loadLibraryFunc, remoteThreadHandle.get(), (UINT_PTR)buffer)) {
        LogError(L"QueueUserAPC");
        return false;
    }

    return true;
}


bool InjectWithApc(DWORD processId, const std::wstring& dllPath) {
    std::vector<DWORD> threadIds;
    if (!GetProcessThreadIds(processId, threadIds)) {
        return false;
    }

    // This one tries to inject into all threads, but usually only one is successfull
    // TODO: Try to actually check what thread is successfull
    for (const auto& remoteThreadId : threadIds) {
        std::cout << "[ThreadId=" << remoteThreadId << " Status=";
        if (InjectIntoThreadWithApc(processId, remoteThreadId, dllPath)) {
            std::cout << "OK";
        }
        else {
            std::cout << "Failed";
        }
        std::cout << "] ";
    }

    return true;
}
