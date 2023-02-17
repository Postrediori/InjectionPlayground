#include "pch.h"
#include "Utils.h"
#include "Define.h"
#include "ProcUtils.h"

FARPROC GetRemoteFunction(LPCWSTR moduleName, LPCSTR functionName) {
    HMODULE hKernel32 = GetModuleHandleW(moduleName);
    if (hKernel32 == NULL) {
        LogError(L"GetModuleHandleW", false);
        return NULL;
    }
    return GetProcAddress(hKernel32, functionName);
}

// Code by AzureGreen via https://github.com/AzureGreen/InjectCollection
std::vector<DWORD> GetProcessThreadIds(DWORD processId) {
    using pfnZwQuerySystemInformation = NTSTATUS(NTAPI*)(
            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
            OUT PVOID SystemInformation,
            IN UINT32 SystemInformationLength,
            OUT PUINT32 ReturnLength OPTIONAL);

    BOOL                        bOk = FALSE;
    NTSTATUS                    status = 0;
    PSYSTEM_PROCESS_INFO        spi = NULL;
    pfnZwQuerySystemInformation ZwQuerySystemInformation = NULL;

    ZwQuerySystemInformation = reinterpret_cast<pfnZwQuerySystemInformation>(GetRemoteFunction(
        L"ntdll.dll", "ZwQuerySystemInformation"));
    if (ZwQuerySystemInformation == NULL) {
        return {};
    }

    const size_t BufferSize = 1024 * 1024; // 1mb TODO: is it possible to use less memory(?)
    std::vector<BYTE> buffer(BufferSize);

    // In the QuerySystemInformation series of functions, when querying SystemProcessInformation, 
    // memory must be requested in advance, and the length cannot be queried first and then re-called
    status = ZwQuerySystemInformation(SystemProcessInformation,
        static_cast<PVOID>(buffer.data()), BufferSize, NULL);
    if (!NT_SUCCESS(status)) {
        LogError(L"ZwQuerySystemInformation", false);
        return {};
    }

    spi = reinterpret_cast<PSYSTEM_PROCESS_INFO>(buffer.data());

    // Iterate through the processes and find our target process
    while (TRUE) {
        bOk = FALSE;
        if (spi->UniqueProcessId == (HANDLE)processId) {
            bOk = TRUE;
            break;
        }
        else if (spi->NextEntryOffset) {
            spi = (PSYSTEM_PROCESS_INFO)((PUINT8)spi + spi->NextEntryOffset);
        }
        else {
            break;
        }
    }

    std::vector<DWORD> ids;

    if (bOk) {
        for (INT i = 0; i < spi->NumberOfThreads; i++) {
            // Return the found threads Id
            ids.push_back(reinterpret_cast<UINT32>(spi->Threads[i].ClientId.UniqueThread));
        }
    }

    return ids;
}
