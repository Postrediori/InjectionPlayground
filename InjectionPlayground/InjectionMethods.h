#pragma once

enum class InjectionMethod {
    CreateRemoteThread,
    RtlCreateUserThread,
    NtCreateThreadEx,
    SetThreadContext
};

bool InjectIntoProcessDll(DWORD processId, const std::wstring& dllPath, InjectionMethod method);
