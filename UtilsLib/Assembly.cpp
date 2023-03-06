#include "pch.h"
#include "Assembly.h"


// Looks ugly, but preserves endianess
template<typename T>
void InsertConvertedOpCode(CpuOpCode value, BinaryData& data) {
    BinaryData byteBuffer(sizeof(T));
    T* binaryPtr = reinterpret_cast<T*>(byteBuffer.data());
    *binaryPtr = std::get<T>(value);
    data.insert(data.end(), byteBuffer.begin(), byteBuffer.end());
}

BinaryData ParseProgram(CpuProgram program) {
    BinaryData data;
    for (const auto& instruction : program) {
        for (const auto& opCode : instruction) {
            // Expand all non-byte operands
            if (std::holds_alternative<BYTE>(opCode)) {
                data.push_back(std::get<BYTE>(opCode));
            }
            else if (std::holds_alternative<WORD>(opCode)) {
                InsertConvertedOpCode<WORD>(opCode, data);
            }
            else if (std::holds_alternative<DWORD>(opCode)) {
                InsertConvertedOpCode<DWORD>(opCode, data);
            }
            else if (std::holds_alternative<DWORD64>(opCode)) {
                InsertConvertedOpCode<DWORD64>(opCode, data);
            }
        }
    }
    return data;
}
