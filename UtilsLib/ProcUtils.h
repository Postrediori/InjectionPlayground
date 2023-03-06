#pragma once

/// <summary>
/// Get address of exported function from a specified module
/// </summary>
/// <param name="moduleName">Name of the DLL module</param>
/// <param name="functionName">Function name</param>
/// <returns>Address of the exported function, NULL if the function fails</returns>
FARPROC GetRemoteFunction(LPCWSTR moduleName, LPCSTR functionName);

/// <summary>
/// Get IDs of threads that belong to a process
/// </summary>
/// <param name="processId">Owner process ID</param>
/// <param name="threadIds">Array of that will be filled with thread IDs</param>
/// <returns>TRUE if the lookup was successfull, FALSE otherwise</returns>
BOOL GetProcessThreadIds(DWORD processId, std::vector<DWORD>& threadIds);
