#include "pch.h"
#include "Utils.h"
#include "InjectionMethods.h"

const std::filesystem::path DllName = L"InjectedDll.dll";


int InjectToProcessesByName(const std::wstring& processName, const std::filesystem::path& dllPath, InjectionMethod method) {
    wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        LogError(L"CreateToolhelp32Snapshot");
        return 1;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    std::wcout << L"Looking for processes with name '" << processName << "'" << std::endl;

    std::vector<DWORD> injectedProcesses;
    while (Process32Next(snapshot.get(), (LPPROCESSENTRY32W)&pe)) {
        if (!CaseInsensitiveEqual(pe.szExeFile, processName)) {
            continue;
        }

        DWORD dwProcessId = pe.th32ProcessID;
        if (std::find(injectedProcesses.begin(), injectedProcesses.end(), dwProcessId) != injectedProcesses.end()) {
            continue;
        }

        std::wcout << L"  " << L"Process ID=" << dwProcessId << " ... ";
        if (InjectIntoProcessDll(dwProcessId, dllPath.wstring(), method)) {
            std::wcout << L"OK";
        }
        else {
            std::wcout << L" FAILED";
        }
        std::wcout << std::endl;

        injectedProcesses.push_back(dwProcessId);
    }

    return 0;
}

int wmain(int argc, const wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: " << argv[0] << L" <process_name.exe> [injection method id]" << std::endl;
        std::wcout << L"Injection methods:" << std::endl;
        std::wcout << L"  1 - CreateRemoteThread (default)" << std::endl;
        std::wcout << L"  2 - RtlCreateUserThread" << std::endl;
        std::wcout << L"  3 - SetThreadContext" << std::endl;
        return 1;
    }

    auto dllPath = PrepareDllPath(argv[0], DllName);

    InjectionMethod method = InjectionMethod::CreateRemoteThread;
    if (argc >= 3) {
        int k = _wtoi(argv[2]);
        switch (k) {
        case 1:
            method = InjectionMethod::CreateRemoteThread;
            break;
        case 2:
            method = InjectionMethod::RtlCreateUserThread;
            break;
        case 3:
            method = InjectionMethod::SetThreadContext;
            break;
        default:
            std::wcerr << "Error: Unknown injection method id" << std::endl;
            return 1;
        }
    }

    if (InjectToProcessesByName(argv[1], dllPath, method) != 0) {
        return 1;
    }

    return 0;
}
