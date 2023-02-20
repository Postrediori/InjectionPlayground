// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

LPWSTR GetFormatedMessage(LPCWSTR pMessage, ...) {
    LPWSTR buffer = NULL;

    va_list args = NULL;
    va_start(args, pMessage);

    FormatMessageW(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER,
        pMessage,
        0, 0,
        (LPWSTR)&buffer, 0,
        &args);

    va_end(args);

    return buffer;
}

void ShowGreeting() {
    DWORD processId, threadId;
    WCHAR filePath[MAX_PATH];
    LPCWSTR fileName = NULL;
    LPWSTR message = NULL;

    processId = GetCurrentProcessId();
    threadId = GetCurrentThreadId();

    if (!GetModuleFileNameW(NULL, filePath, MAX_PATH)) {
        return;
    }

    fileName = PathFindFileNameW(filePath);

    message = GetFormatedMessage(L"Greetings from process='%1!s!' pid=%2!d! tid=%3!d!",
        fileName, processId, threadId);

    MessageBoxW(0, message, L"Injected Code", MB_OK | MB_ICONEXCLAMATION);

    LocalFree(message);
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
