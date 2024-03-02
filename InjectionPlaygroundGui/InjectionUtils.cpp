#include "pch.h"
#include "Utils.h"
#include "InjectionMethods.h"
#include "InjectionSetWindowsHookEx.h"
#include "InjectionUtils.h"

bool InjectToProcessesByName(std::ostream& log, const std::filesystem::path& processName, const std::filesystem::path& dllPath,
    InjectionMethod method, int hookType) {

    wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        LogErrorLn(L"CreateToolhelp32Snapshot");
        return false;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    log << "Injecting DLL " << dllPath.filename() << " with method " << ToAsciiString(GetInjectionMethodName(method)) << std::endl;
    if (method == InjectionMethod::SetWindowsHookInjection) {
        auto hookMethodDescription = std::find_if(SetWindowsHookValues.begin(), SetWindowsHookValues.end(),
            [=](const std::tuple<std::wstring, int>& info) {
                return std::get<1>(info) == hookType;
            });

        if (hookMethodDescription == SetWindowsHookValues.end()) {
            log << "Error: Unknown injection hook id " << hookType << std::endl;
            return false;
        }

        log << "Setting hook for message " << ToAsciiString(std::get<0>(*hookMethodDescription)) << std::endl;
    }
    log << "Looking for processes with name '" << processName.string() << "'" << std::endl;

    std::vector<DWORD> injectedProcesses;
    while (Process32NextW(snapshot.get(), (LPPROCESSENTRY32W)&pe)) {
        if (!CaseInsensitiveEqual(pe.szExeFile, processName.wstring())) {
            continue;
        }

        DWORD dwProcessId = pe.th32ProcessID;
        if (std::find(injectedProcesses.begin(), injectedProcesses.end(), dwProcessId) != injectedProcesses.end()) {
            continue;
        }

        bool status = InjectIntoProcessDll(dwProcessId, dllPath.wstring(), method, hookType);
        log << "  " << "Process ID=" << dwProcessId << " ... " << (status ? "OK" : "FAILED") << std::endl;

        injectedProcesses.push_back(dwProcessId);
    }

    if (injectedProcesses.empty()) {
        log << "No process with name " << processName << " was found" << std::endl;
    }

    return true;
}
