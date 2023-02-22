#pragma once

enum class InjectionMethod {
    CreateRemoteThread,
    RtlCreateUserThread,
    NtCreateThreadEx,
    SetThreadContext,
    QueueUserApc
};

bool InjectIntoProcessDll(DWORD processId, const std::wstring& dllPath, InjectionMethod method);
