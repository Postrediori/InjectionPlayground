#pragma once

enum class InjectionMethod {
    CreateRemoteThread,
    RtlCreateUserThread,
    NtCreateThreadEx,
    SetThreadContext,
    QueueUserApc,
    SetWindowsHookInjection
};

std::wstring GetInjectionMethodName(InjectionMethod method);

bool InjectIntoProcessDll(DWORD processId, const std::wstring& dllPath, InjectionMethod method);
