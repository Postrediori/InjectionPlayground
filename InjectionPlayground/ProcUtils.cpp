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

    const size_t BufferSize = 1024 * 1024; // 1mb
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
            ids.push_back((UINT32)spi->Threads[i].ClientId.UniqueThread);
        }
    }

    return ids;
}

BOOL GetPebByProcessId(IN UINT32 ProcessId, OUT PPEB Peb)
{
	BOOL						bOk = FALSE;
	NTSTATUS					Status = 0;
	HANDLE						ProcessHandle = NULL;
	UINT32						ReturnLength = 0;
	SIZE_T						NumberOfBytesRead = 0;
	PROCESS_BASIC_INFORMATION	pbi = { 0 };

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (ProcessHandle == NULL)
	{
		return FALSE;
	}
	
	using pfnNtQueryInformationProcess = NTSTATUS(NTAPI*)(
			__in HANDLE ProcessHandle,
			__in PROCESSINFOCLASS ProcessInformationClass,
			__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
			__in UINT32 ProcessInformationLength,
			__out_opt PUINT32 ReturnLength
			);

	pfnNtQueryInformationProcess NtQueryInformationProcess =
		(pfnNtQueryInformationProcess)GetRemoteFunction(L"ntdll.dll", "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL)
	{
		CloseHandle(ProcessHandle);
		ProcessHandle = NULL;
		return FALSE;
	}

	Status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &ReturnLength);
	if (!NT_SUCCESS(Status))
	{
		CloseHandle(ProcessHandle);
		ProcessHandle = NULL;
		return FALSE;
	}

	bOk = ReadProcessMemory(ProcessHandle, pbi.PebBaseAddress, Peb, sizeof(PEB), &NumberOfBytesRead);
	if (bOk == FALSE)
	{
		CloseHandle(ProcessHandle);
		ProcessHandle = NULL;
		return FALSE;
	}

	CloseHandle(ProcessHandle);
	return TRUE;
}

BOOL GetRemoteFunctonInTargetProcessImportTable(IN UINT32 ProcessId, OUT PUINT_PTR ImportFunctionAddress,
	const std::string& libraryName, const std::string& functionName)
{
	BOOL					bOk = FALSE;
	INT						i = 0, j = 0;
	HANDLE					ProcessHandle = NULL;
	PEB						Peb = { 0 };
	UINT_PTR				ModuleBase = 0;
	IMAGE_DOS_HEADER		DosHeader = { 0 };
	IMAGE_NT_HEADERS		NtHeader = { 0 };
	IMAGE_IMPORT_DESCRIPTOR	ImportDescriptor = { 0 };
	CHAR					szImportModuleName[MAX_PATH] = { 0 };
	IMAGE_THUNK_DATA		OriginalFirstThunk = { 0 };
	PIMAGE_IMPORT_BY_NAME	ImageImportByName = NULL;
	CHAR					szImportFunctionName[MAX_PATH] = { 0 };
	UINT32					ImportDescriptorRVA = 0;

	bOk = GetPebByProcessId(ProcessId, &Peb);
	if (bOk == FALSE)
	{
		return FALSE;
	}

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (ProcessHandle == NULL)
	{
		return FALSE;
	}

	ModuleBase = (UINT_PTR)Peb.ImageBaseAddress;

	ReadProcessMemory(ProcessHandle, (PVOID)ModuleBase, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + DosHeader.e_lfanew), &NtHeader, sizeof(IMAGE_NT_HEADERS), NULL);

	ImportDescriptorRVA = NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// Iterate through each

	for (i = 0, ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptorRVA), &ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL);
		ImportDescriptor.FirstThunk != 0;
		++i, ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptorRVA + i * sizeof(IMAGE_IMPORT_DESCRIPTOR)), &ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL))
	{
		// Read the import table

		if (ImportDescriptor.OriginalFirstThunk == 0 && ImportDescriptor.FirstThunk == 0)
		{
			break;
		}

		// Read the imported module name
		ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptor.Name), szImportModuleName, MAX_PATH, NULL);

		if (_stricmp(szImportModuleName, libraryName.c_str()) == 0)
		{
			// The target module is found, start traversing the IAT INT
			ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptor.OriginalFirstThunk), &OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA), NULL);
			for (j = 0;
				OriginalFirstThunk.u1.AddressOfData != 0;
				++j)
			{
				// Serial number import is not processed
				if (IMAGE_SNAP_BY_ORDINAL(OriginalFirstThunk.u1.Ordinal))
				{
					continue;
				}

				// Name of the imported function
				ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PUINT8)ModuleBase + OriginalFirstThunk.u1.AddressOfData);
				ReadProcessMemory(ProcessHandle, ImageImportByName->Name, szImportFunctionName, MAX_PATH, NULL);

				// Get the address of the import function
				ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptor.FirstThunk + j * sizeof(IMAGE_THUNK_DATA)), ImportFunctionAddress, sizeof(UINT_PTR), NULL);

				if (_stricmp(szImportFunctionName, functionName.c_str()) == 0)
				{
					// Hit!
					return TRUE;
				}

				ReadProcessMemory(ProcessHandle, (PVOID)((PUINT8)ModuleBase + ImportDescriptor.OriginalFirstThunk + j * sizeof(IMAGE_THUNK_DATA)), &OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA), NULL);
			}
		}
	}

	return FALSE;
}
