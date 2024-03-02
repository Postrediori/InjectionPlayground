#pragma once


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


/*****************************************************************************
 * Inject into processes by name
 ****************************************************************************/
bool InjectToProcessesByName(std::ostream& log, const std::filesystem::path& processName, const std::filesystem::path& dllPath,
    InjectionMethod method, int hookType = 0);
