#pragma once

#include <filesystem>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>

#include <wil/resource.h>
