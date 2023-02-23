#include "pch.h"

void WriteToLog(const std::wstring& log) {
    const wchar_t LogPath[] = L"%UserProfile%\\Desktop\\log_file.txt";

    wchar_t cOutputPath[MAX_PATH];
    ExpandEnvironmentStringsW(LogPath, cOutputPath, MAX_PATH);

    std::wofstream logFile(cOutputPath, std::ios_base::out | std::ios_base::app);
    if (!logFile) {
        return;
    }

    logFile << log << std::endl;
}

void ShowGreeting() noexcept {
    try {
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
    catch (const std::exception& ex) {
        //
    }
}
