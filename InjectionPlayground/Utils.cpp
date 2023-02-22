#include "pch.h"
#include "Utils.h"

std::wstring GetErrorDescription(DWORD dwErrorCode) {
    wil::unique_hlocal lpBuffer;

    // Ask Win32 to give the string representation of the error code
    DWORD dwSize = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), static_cast<LPWSTR>(lpBuffer.get()), 0, NULL);

    std::wstring s(static_cast<LPCWSTR>(lpBuffer.get()), dwSize);

    return s;
}

void LogError(const std::wstring& szFunctionName) {
    DWORD dwErrorCode = GetLastError();
    if (dwErrorCode == 0) {
        // No error
        return;
    }

    std::wcerr << L"ERROR function='" << szFunctionName <<
        L"' code=" << dwErrorCode <<
        L" decription='" << GetErrorDescription(dwErrorCode) << "'";
}

void LogErrorLn(const std::wstring& szFunctionName) {
    LogError(szFunctionName);
    std::cout << std::endl;
}

std::filesystem::path PrepareDllPath(const std::wstring& procArgv, const std::filesystem::path& dllName) {
    std::filesystem::path procPath(procArgv);
    procPath = std::filesystem::canonical(procPath);

    std::filesystem::path procDirectory = procPath.parent_path();
    return procDirectory / dllName;
}

bool CaseInsensitiveEqual(const std::wstring& nameA, const std::wstring& nameB) {
    return std::equal(
        nameA.begin(), nameA.end(),
        nameB.begin(), nameB.end(),
        [](wchar_t a, wchar_t b) {
            return std::tolower(a) == std::tolower(b);
        }
    );
}
