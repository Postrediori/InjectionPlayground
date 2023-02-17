#pragma once

FARPROC GetRemoteFunction(LPCWSTR moduleName, LPCSTR functionName);

std::vector<DWORD> GetProcessThreadIds(DWORD processId);

BOOL GetRemoteFunctonInTargetProcessImportTable(IN UINT32 ProcessId, OUT PUINT_PTR ImportFunctionAddress,
    const std::string& libraryName, const std::string& functionName);
