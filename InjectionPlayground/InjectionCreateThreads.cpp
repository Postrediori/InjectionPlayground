#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"
#include "InjectionCreateThreads.h"


bool InjectWithRemoteThread(DWORD processId, const std::wstring& dllPath, RemoteThreadFunc remoteThreadFunc) {
    WCHAR szDllFullPath[MAX_PATH] = { 0 };
    wcscpy_s(szDllFullPath, dllPath.c_str());
    DWORD dwDllNameSize = (wcslen(szDllFullPath) + 1) * sizeof(wchar_t);

    const DWORD DesiredAccess = PROCESS_ALL_ACCESS;
    wil::unique_handle hProcess(OpenProcess(DesiredAccess, FALSE, processId));
    if (!hProcess) {
        LogError(L"OpenProcess", false);
        return false;
    }

    LPVOID lpBaseAddress = VirtualAllocEx(hProcess.get(), NULL, dwDllNameSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpBaseAddress == NULL) {
        LogError(L"VirtualAllocEx", false);
        return false;
    }

    bool status = true;

    do {
        if (!WriteProcessMemory(hProcess.get(), lpBaseAddress, (LPCVOID)szDllFullPath, (SIZE_T)dwDllNameSize, NULL)) {
            LogError(L"WriteProcessMemory", false);
            status = false;
            break;
        }

        FARPROC pLoadLibrary = GetRemoteFunction(L"kernel32.dll", "LoadLibraryW");
        if (!pLoadLibrary) {
            status = false;
            break;
        }

        wil::unique_handle hRemoteThread(remoteThreadFunc(hProcess.get(), (LPTHREAD_START_ROUTINE)pLoadLibrary, lpBaseAddress));
        if (!hRemoteThread) {
            LogError(L"Remote Thread Returned NULL", false);
            status = false;
            break;
        }

        DWORD waitingTime = 1000; // INFINITE
        if (WaitForSingleObject(hRemoteThread.get(), waitingTime) == WAIT_FAILED) {
            LogError(L"Remote Thread Wait Failed", false);
            status = false;
            break;
        }
    } while (false);

    VirtualFreeEx(hProcess.get(), lpBaseAddress, 0, MEM_RELEASE);

    return status;
}

HANDLE UseCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pLoadLibrary, PVOID lpBaseAddress) {
    return CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, lpBaseAddress, 0, NULL);
}

HANDLE UseRtlCreateUserThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pLoadLibrary, PVOID lpBaseAddress) {
    using RtlCreateUserThread_t = DWORD(WINAPI*)(
        IN HANDLE               ProcessHandle,
        IN PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN BOOL                 CreateSuspended,
        IN ULONG                StackZeroBits,
        IN OUT PULONG           StackReserved,
        IN OUT PULONG           StackCommit,
        IN LPVOID               StartAddress,
        IN LPVOID               StartParameter,
        OUT HANDLE              ThreadHandle,
        OUT LPVOID              ClientID);

    RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t)GetRemoteFunction(L"ntdll.dll", "RtlCreateUserThread");
    if (pRtlCreateUserThread == NULL) {
        return NULL;
    }

    HANDLE hRemoteThread = NULL;
    NTSTATUS status = pRtlCreateUserThread(hProcess, NULL, FALSE,
        0, NULL, NULL,
        pLoadLibrary, lpBaseAddress,
        &hRemoteThread, NULL);

    if (status != 0) {
        return NULL;
    }

    return hRemoteThread;
}

HANDLE UseNtCreateThreadEx(HANDLE hProcess, LPTHREAD_START_ROUTINE pLoadLibrary, PVOID lpBaseAddress) {
    using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
        OUT PHANDLE hThread,
        IN ACCESS_MASK DesiredAccess,
        IN PVOID ObjectAttributes,
        IN HANDLE ProcessHandle,
        IN PVOID lpStartAddress,
        IN PVOID lpParameter,
        IN ULONG Flags,
        IN SIZE_T StackZeroBits,
        IN SIZE_T SizeOfStackCommit,
        IN SIZE_T SizeOfStackReserve,
        OUT PVOID lpBytesBuffer);

    NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)GetRemoteFunction(L"ntdll.dll", "NtCreateThreadEx");
    if (pNtCreateThreadEx == NULL) {
        return NULL;
    }

    HANDLE hRemoteThread = NULL;
    NTSTATUS status = pNtCreateThreadEx(
        &hRemoteThread, THREAD_ALL_ACCESS, NULL, hProcess,
        pLoadLibrary, lpBaseAddress,
        FALSE, NULL, NULL, NULL, NULL);
    if (status != 0) {
        return NULL;
    }

    return hRemoteThread;
}
