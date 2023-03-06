#pragma once

#include <filesystem>
#include <functional>
#include <iostream>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include <wil/resource.h>
