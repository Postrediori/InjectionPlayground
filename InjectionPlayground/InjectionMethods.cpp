#include "pch.h"
#include "Utils.h"
#include "InjectionCreateThreads.h"
#include "InjectionSetThreadContext.h"
#include "InjectionByApc.h"
#include "InjectionMethods.h"


bool InjectIntoProcessDll(DWORD processId, const std::wstring& dllPath, InjectionMethod method) {
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
    default:
        break;
    }

    return false;
}
