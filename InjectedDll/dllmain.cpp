#include "pch.h"

void ShowGreeting() {
    DWORD processId = GetCurrentProcessId();
    DWORD threadId = GetCurrentThreadId();

    WCHAR fileName[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(NULL, fileName, MAX_PATH)) {
        return;
    }

    std::filesystem::path path(fileName);
    std::wstringstream s;
    s << "Greetings from process='" << path.filename().wstring() << "' pid=" << processId << " tid=" << threadId;

    MessageBoxW(NULL, s.str().c_str(), L"Injected Code", MB_OK | MB_ICONEXCLAMATION);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        ShowGreeting();
        break;

    case DLL_PROCESS_DETACH:
        break;

    default:
        break;
    }
    return TRUE;
}
