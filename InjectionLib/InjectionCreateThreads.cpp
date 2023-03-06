#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"
#include "InjectionCreateThreads.h"


bool InjectWithRemoteThread(DWORD processId, const std::wstring& dllPath, RemoteThreadFunc remoteThreadFunc) {
    constexpr DWORD DesiredAccess = PROCESS_CREATE_THREAD | // for CreateRemoteThread
        PROCESS_VM_OPERATION | // for VirtualAllocEx/VirtualFreeEx
        PROCESS_VM_WRITE; // for WriteProcessMemory
    wil::unique_handle hProcess(OpenProcess(DesiredAccess, FALSE, processId));
    if (!hProcess) {
        LogError(L"OpenProcess");
        return false;
    }

    DWORD dwDllNameSize = (dllPath.length() + 1) * sizeof(wchar_t);

    wistd::unique_ptr<BYTE, std::function<void(LPBYTE)>> lpBaseAddress(
        (LPBYTE)VirtualAllocEx(hProcess.get(), NULL, dwDllNameSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE),
        [&hProcess](LPBYTE mem) {
            if (mem) {
                VirtualFreeEx(hProcess.get(), (LPVOID)mem, 0, MEM_RELEASE);
            }
        });
    if (!lpBaseAddress) {
        LogError(L"VirtualAllocEx");
        return false;
    }

    if (!WriteProcessMemory(hProcess.get(), lpBaseAddress.get(), (LPCVOID)dllPath.c_str(), (SIZE_T)dwDllNameSize, NULL)) {

        LogError(L"WriteProcessMemory");
        return false;
    }

    FARPROC pLoadLibrary = GetRemoteFunction(L"kernel32.dll", "LoadLibraryW");
    if (!pLoadLibrary) {
        return false;
    }

    wil::unique_handle hRemoteThread(remoteThreadFunc(hProcess.get(), (LPTHREAD_START_ROUTINE)pLoadLibrary, lpBaseAddress.get()));
    if (!hRemoteThread) {
        LogError(L"Remote Thread Returned NULL");
        return false;
    }

#define WAITING_TIME 100 // INFINITE
#ifdef WAITING_TIME
    if (WaitForSingleObject(hRemoteThread.get(), WAITING_TIME) == WAIT_FAILED) {
        LogError(L"Remote Thread Wait Failed");
        return false;
    }
#endif

    return true;
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
