#pragma once

const std::vector<std::tuple<std::wstring, int>> SetWindowsHookValues = {
    { L"WH_CALLWNDPROC", WH_CALLWNDPROC},
    { L"WH_CALLWNDPROCRET", WH_CALLWNDPROCRET },
    { L"WH_CBT", WH_CBT },
    { L"WH_DEBUG", WH_DEBUG },
    { L"WH_FOREGROUNDIDLE", WH_FOREGROUNDIDLE },
    { L"WH_GETMESSAGE", WH_GETMESSAGE },
    { L"WH_JOURNALPLAYBACK", WH_JOURNALPLAYBACK },
    { L"WH_JOURNALRECORD", WH_JOURNALRECORD },
    { L"WH_KEYBOARD", WH_KEYBOARD },
    { L"WH_KEYBOARD_LL", WH_KEYBOARD_LL },
    { L"WH_MOUSE", WH_MOUSE },
    { L"WH_MOUSE_LL", WH_MOUSE_LL },
    { L"WH_MSGFILTER", WH_MSGFILTER },
    { L"WH_SHELL", WH_SHELL },
    { L"WH_SYSMSGFILTER", WH_SYSMSGFILTER }
};

constexpr int DefaultWindowHookId = WH_GETMESSAGE;

bool InjectWithSetWindowHookEx(DWORD processId, const std::wstring& dllPath, int hookType = 0);
