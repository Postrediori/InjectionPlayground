#pragma once

using RemoteThreadFunc = HANDLE(*)(HANDLE, LPTHREAD_START_ROUTINE, PVOID);

bool InjectWithRemoteThread(DWORD processId, const std::wstring& dllPath, RemoteThreadFunc remoteThreadFunc);

HANDLE UseCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pLoadLibrary, PVOID lpBaseAddress);

HANDLE UseRtlCreateUserThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pLoadLibrary, PVOID lpBaseAddress);

HANDLE UseNtCreateThreadEx(HANDLE hProcess, LPTHREAD_START_ROUTINE pLoadLibrary, PVOID lpBaseAddress);
