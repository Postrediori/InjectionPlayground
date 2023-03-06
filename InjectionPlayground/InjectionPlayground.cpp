#include "pch.h"
#include "Utils.h"
#include "ProcUtils.h"
#include "InjectionMethods.h"
#include "InjectionSetWindowsHookEx.h"

#ifdef _WIN64
const std::filesystem::path DefaultDllName = L"InjectedDll.x64.dll";
const std::filesystem::path WindowsHookDllName = L"WindowsHookDll.x64.dll";
#else
#  ifdef _WIN32
const std::filesystem::path DefaultDllName = L"InjectedDll.x86.dll";
const std::filesystem::path WindowsHookDllName = L"WindowsHookDll.x86.dll";
#  else
#    error Unknown architecture
#  endif
#endif


int InjectToProcessesByName(const std::wstring& processName, const std::filesystem::path& dllPath,
        InjectionMethod method, int hookType = 0) {
    wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        LogErrorLn(L"CreateToolhelp32Snapshot");
        return 1;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    std::wcout << L"Injecting with method " << GetInjectionMethodName(method) << std::endl;
    if (method == InjectionMethod::SetWindowsHookInjection) {
        auto hookMethodDescription = std::find_if(SetWindowsHookValues.begin(), SetWindowsHookValues.end(),
            [=](const std::tuple<std::wstring, int>& info) {
                return std::get<1>(info) == hookType;
            });

        if (hookMethodDescription == SetWindowsHookValues.end()) {
            std::wcout << L"Error: Unknown injection hook id" << std::endl;
            return false;
        }

        std::wcout << L"Setting hook for message " << std::get<0>(*hookMethodDescription) << std::endl;
    }
    std::wcout << L"Looking for processes with name '" << processName << "'" << std::endl;

    std::vector<DWORD> injectedProcesses;
    while (Process32NextW(snapshot.get(), (LPPROCESSENTRY32W)&pe)) {
        if (!CaseInsensitiveEqual(pe.szExeFile, processName)) {
            continue;
        }

        DWORD dwProcessId = pe.th32ProcessID;
        if (std::find(injectedProcesses.begin(), injectedProcesses.end(), dwProcessId) != injectedProcesses.end()) {
            continue;
        }

        std::wcout << L"  " << L"Process ID=" << dwProcessId << " ... ";
        if (InjectIntoProcessDll(dwProcessId, dllPath.wstring(), method, hookType)) {
            std::wcout << L"OK";
        }
        else {
            std::wcout << L" FAILED";
        }
        std::wcout << std::endl;

        injectedProcesses.push_back(dwProcessId);
    }

    if (injectedProcesses.empty()) {
        std::wcout << L"No process with name " << processName << L" was found" << std::endl;
    }

    return 0;
}

int wmain(int argc, const wchar_t* argv[]) {

    const wchar_t* modulePath = argv[0];
    if (argc < 2) {
        std::wcout << L"Usage: " << modulePath << L" <process_name.exe> [injection method id] [type of hook for SetWindowsHook]" << std::endl;
        std::wcout << L"Injection methods:" << std::endl;
        std::wcout << L"  1 - CreateRemoteThread (default)" << std::endl;
        std::wcout << L"  2 - RtlCreateUserThread" << std::endl;
        std::wcout << L"  3 - NtCreateThreadEx" << std::endl;
        std::wcout << L"  4 - SetThreadContext" << std::endl;
        std::wcout << L"  5 - QueueUserApc" << std::endl;
        std::wcout << L"  6 - SetWindowsHook" << std::endl;

        std::wcout << L"Types of hook for SetWindowsHook:" << std::endl;
        for (const auto& info : SetWindowsHookValues) {
            std::wcout << L"  " << std::get<0>(info) << std::endl;
        }
        return 1;
    }

    const wchar_t* processName = argv[1];

    InjectionMethod method = InjectionMethod::CreateRemoteThread;
    if (argc >= 3) {
        const wchar_t* injectionMethod = argv[2];
        int k = _wtoi(injectionMethod);
        switch (k) {
        case 1:
            method = InjectionMethod::CreateRemoteThread;
            break;
        case 2:
            method = InjectionMethod::RtlCreateUserThread;
            break;
        case 3:
            method = InjectionMethod::NtCreateThreadEx;
            break;
        case 4:
            method = InjectionMethod::SetThreadContext;
            break;
        case 5:
            method = InjectionMethod::QueueUserApc;
            break;
        case 6:
            method = InjectionMethod::SetWindowsHookInjection;
            break;
        default:
            std::wcerr << "Error: Unknown injection method id" << std::endl;
            return 1;
        }
    }

    // Hook type for SetWindowsHook injection
    int hookType = DefaultWindowHookId;
    if (argc >= 4) {
        if (method != InjectionMethod::SetWindowsHookInjection) {
            std::wcerr << "Error: hook type can be set only for SetWindowsHook injection method" << std::endl;
            return 1;
        }

        const wchar_t* hookTypeArg = argv[3];
        bool foundHookType = false;
        for (const auto& info : SetWindowsHookValues) {
            if (CaseInsensitiveEqual(std::get<0>(info), hookTypeArg)) {
                hookType = std::get<1>(info);
                foundHookType = true;
                break;
            }
        }

        if (!foundHookType) {
            std::wcerr << "Error: Unknown hook type for SetWindowsHook" << std::endl;
            return 1;
        }
    }

    // Select injected DLL file name
    std::wstring dllName;
    switch (method) {
    case InjectionMethod::CreateRemoteThread:
    case InjectionMethod::RtlCreateUserThread:
    case InjectionMethod::NtCreateThreadEx:
    case InjectionMethod::SetThreadContext:
    case InjectionMethod::QueueUserApc:
        dllName = DefaultDllName;
        break;
    case InjectionMethod::SetWindowsHookInjection:
        dllName = WindowsHookDllName;
        break;
    default:
        std::wcerr << "Error: Unknown injection method id" << std::endl;
        return 1;
    }
    auto dllPath = PrepareDllPath(modulePath, dllName);

    if (InjectToProcessesByName(processName, dllPath, method, hookType) != 0) {
        return 1;
    }

    return 0;
}
