#include "pch.h"
#include "Utils.h"
#include "InjectionCreateThreads.h"
#include "InjectionSetThreadContext.h"
#include "InjectionByApc.h"
#include "InjectionSetWindowsHookEx.h"
#include "InjectionMethods.h"

std::wstring GetInjectionMethodName(InjectionMethod method) {
    switch (method) {
    case InjectionMethod::CreateRemoteThread:
        return L"CreateRemoteThread";
    case InjectionMethod::RtlCreateUserThread:
        return L"RtlCreateUserThread";
    case InjectionMethod::NtCreateThreadEx:
        return L"NtCreateThreadEx";
    case InjectionMethod::SetThreadContext:
        return L"SetThreadContext";
    case InjectionMethod::QueueUserApc:
        return L"QueueUserApc";
    case InjectionMethod::SetWindowsHookInjection:
        return L"SetWindowsHookEx";
    default:
        return L"Error: Unknown injection method";
    }

    return L"Error: Unknown injection method";
}

bool InjectIntoProcessDll(DWORD processId, const std::wstring& dllPath, InjectionMethod method, int hookType) {
    switch (method) {
    case InjectionMethod::CreateRemoteThread:
        return InjectWithRemoteThread(processId, dllPath, UseCreateRemoteThread);
    case InjectionMethod::RtlCreateUserThread:
        return InjectWithRemoteThread(processId, dllPath, UseRtlCreateUserThread);
    case InjectionMethod::NtCreateThreadEx:
        return InjectWithRemoteThread(processId, dllPath, UseNtCreateThreadEx);
    case InjectionMethod::SetThreadContext:
        return InjectWithSetThreadContext(processId, dllPath);
    case InjectionMethod::QueueUserApc:
        return InjectWithApc(processId, dllPath);
    case InjectionMethod::SetWindowsHookInjection:
        return InjectWithSetWindowHookEx(processId, dllPath, hookType);
    default:
        break;
    }

    return false;
}
