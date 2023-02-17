#pragma once

FARPROC GetRemoteFunction(LPCWSTR moduleName, LPCSTR functionName);

std::vector<DWORD> GetProcessThreadIds(DWORD processId);
