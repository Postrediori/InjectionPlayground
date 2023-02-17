#pragma once

enum class InjectionMethod {
    CreateRemoteThread,
    RtlCreateUserThread,
    SetThreadContext
};

bool InjectIntoProcessDll(DWORD processId, const std::wstring& dllPath, InjectionMethod method);
