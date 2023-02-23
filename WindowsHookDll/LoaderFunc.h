#pragma once

#include "WindowsHookDllCommon.h"

#define LOADREMOTEDLL_API __declspec(dllexport)

extern "C" {
    LOADREMOTEDLL_API LRESULT WINDOWS_HOOK_DLL_LOADER_FUNC(int nCode, WPARAM wParam, LPARAM lParam);
}

