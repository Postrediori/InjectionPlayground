#pragma once

#include <algorithm>
#include <filesystem>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <stdint.h>

// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>

#include <wil/resource.h>
