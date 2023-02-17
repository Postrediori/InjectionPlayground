#pragma once

void LogError(const std::wstring& szFunctionName, bool newLine = true);

std::filesystem::path PrepareDllPath(const std::wstring& procArgv, const std::filesystem::path& dllName);

bool CaseInsensitiveEqual(const std::wstring& nameA, const std::wstring& nameB);
