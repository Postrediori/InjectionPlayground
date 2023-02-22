#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"
#include "Assembly.h"
#include "InjectionSetThreadContext.h"


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
        LogError(L"OpenThread");
        return false;
    }

    SYSTEM_INFO systemInformation;
    GetSystemInfo(&systemInformation);

    // Allocate systemInformation.dwPageSize bytes in the remote process
    LPBYTE buffer = static_cast<LPBYTE>(VirtualAllocEx(remoteProcessHandle.get(), NULL, systemInformation.dwPageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!buffer) {
        LogError(L"VirtualAllocEx");
        return false;
    }

    // Calculate how many bytes to write into the remote buffer
    size_t libraryPathSizeBytes = (dllPath.length() + 1) * sizeof(wchar_t);

    if (WriteProcessMemory(remoteProcessHandle.get(),
        buffer + systemInformation.dwPageSize / 2, dllPath.c_str(), libraryPathSizeBytes, NULL) == 0) {
        LogError(L"WriteProcessMemory");
        return false;
    }

    if (SuspendThread(remoteThreadHandle.get()) == (DWORD)(-1)) {
        LogError(L"SuspendThread");
        return false;
    }

    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(remoteThreadHandle.get(), &context)) {
        LogError(L"GetThreadContext");
        return false;
    }

    // Get address of LoadLibraryW function
    // Note: AzureGreen's code uses GetLoadLibraryAddressInTargetProcessImportTable function
    // to locate LoadLibraryA in the process import table itself. However, I didn't find
    // the case where getting the pointer from kernel32 won't work. In addition,
    // some processes use LoadLibraryEx function (e.g. winword) and it would
    // require additional checks in addition to implementing another injection program with opcodes.
    FARPROC loadLibraryFunc = GetRemoteFunction(L"kernel32.dll", "LoadLibraryW");

    using namespace IntegerTypes;
#ifdef _WIN64
    CpuProgram injectedCode = {
        // sub rsp, 28h
        {0x48_8, 0x83_8, 0xec_8, 0x28_8},
        // mov [rsp + 18h], rax
        {0x48_8, 0x89_8, 0x44_8, 0x24_8, 0x18_8},
        // mov [rsp + 10h], rcx
        {0x48_8, 0x89_8, 0x4c_8, 0x24_8, 0x10_8},
        // mov rcx, uint64_t pointer to DLL path
        {0x48_8, 0xb9_8, reinterpret_cast<DWORD64>(buffer + systemInformation.dwPageSize / 2)},
        // mov rax, uint64_t pointer to “LoadLibraryW” address
        {0x48_8, 0xb8_8, reinterpret_cast<DWORD64>(loadLibraryFunc)},
        // call rax
        {0xff_8, 0xd0_8},
        // mov rcx, [rsp + 10h]
        {0x48_8, 0x8b_8, 0x4c_8, 0x24_8, 0x10_8},
        // mov rax, [rsp + 18h]
        {0x48_8, 0x8b_8, 0x44_8, 0x24_8, 0x18_8},
        // add rsp, 28h
        {0x48_8, 0x83_8, 0xc4_8, 0x28_8},
        // mov r11, uint64_t pointer to the original RIP
        {0x49_8, 0xbb_8, static_cast<DWORD64>(context.Rip)},
        // jmp r11
        {0x41_8, 0xff_8, 0xe3_8}
    };
#else
#  ifdef _WIN32
    // Code by AzureGreen via https://github.com/AzureGreen/InjectCollection
    CpuProgram injectedCode = {
        // [0] pusha
        {0x60_8},
        // [1] pushf
        {0x9c_8},
        // [2] push uint32_t pointer to DLL path
        {0x68_8, reinterpret_cast<DWORD>(buffer + systemInformation.dwPageSize / 2)},
        // [7] call DWORD PTR [uint32_t pointer to “LoadLibraryW” address]
        {0xff_8, 0x15_8, reinterpret_cast<DWORD>(buffer + 25)},
        // [13] popf
        {0x9d_8},
        // [14] popa
        {0x61_8},
        // [15] jmp DWORD PTR [uint32_t pointer to the original EIP]
        {0xff_8, 0x25_8, reinterpret_cast<DWORD>(buffer + 21)},

        // The following are the actual addresses
        // [21], pointer to the original EIP
        {static_cast<DWORD>(context.Eip)},
        // [25], pointer to “LoadLibraryW” address
        {reinterpret_cast<DWORD>(loadLibraryFunc)}
    };
#  else
#    error Unknown architecture
#  endif
#endif
    BinaryData data = ParseProgram(injectedCode);

    if (WriteProcessMemory(remoteProcessHandle.get(),
        buffer, static_cast<LPCVOID>(data.data()), data.size(), NULL) == 0) {
        LogError(L"WriteProcessMemory");
        return false;
    }

#ifdef _WIN64
    context.Rip = reinterpret_cast<DWORD64>(buffer);
#else
#  ifdef _WIN32
    context.Eip = reinterpret_cast<DWORD>(buffer);
#  else
#    error Unknown architecture
#  endif
#endif

    if (!SetThreadContext(remoteThreadHandle.get(), &context)) {
        LogError(L"SetThreadContext");
    }

    if (ResumeThread(remoteThreadHandle.get()) == (DWORD)(-1)) {
        LogError(L"ResumeThread");
    }

    // Don't need to execute VirtualFreeEx for buffer (?)

    return true;
}

bool InjectWithSetThreadContext(DWORD processId, const std::wstring& dllPath) {
    std::vector<DWORD> threadIds;
    if (!GetProcessThreadIds(processId, threadIds)) {
        return false;
    }

    DWORD remoteThreadId = threadIds[0]; // TODO: Select in a better way

    return InjectIntoThread(processId, remoteThreadId, dllPath);
}
