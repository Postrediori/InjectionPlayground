#include "pch.h"
#include "InjectionLib.h"
#include "LoaderFunc.h"

LRESULT WINDOWS_HOOK_DLL_LOADER_FUNC(int nCode, WPARAM wParam, LPARAM lParam) {
    ShowGreeting();

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
