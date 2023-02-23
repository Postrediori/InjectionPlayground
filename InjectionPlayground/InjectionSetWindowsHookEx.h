#pragma once

bool InjectWithSetWindowHookEx(DWORD processId, const std::wstring& dllPath);
