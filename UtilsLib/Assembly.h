#pragma once

using CpuOpCode = std::variant<BYTE, WORD, DWORD, DWORD64>;
using CpuInstruction = std::initializer_list< CpuOpCode >;
using CpuProgram = std::initializer_list< CpuInstruction >;
using BinaryData = std::vector<uint8_t>;

// We need this to explicitly define size of an integer for CpuOpCode
namespace IntegerTypes {
    constexpr inline BYTE operator ""_8(DWORD64 Param) {
        return static_cast<BYTE>(Param);
    }

    constexpr inline WORD operator ""_16(DWORD64 Param) {
        return static_cast<WORD>(Param);
    }

    constexpr inline DWORD operator ""_32(DWORD64 Param) {
        return static_cast<DWORD>(Param);
    }

    constexpr inline DWORD64 operator ""_64(DWORD64 Param) {
        return static_cast<DWORD64>(Param);
    }
}

// Convert initializer list to byte sequence
BinaryData ParseProgram(CpuProgram program);
