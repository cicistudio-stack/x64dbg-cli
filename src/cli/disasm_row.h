#pragma once

#include "../bridge/bridgemain.h"

#include <functional>
#include <string>

namespace cli
{
struct DisRow
{
    unsigned long long addr = 0;
    int size = 1;
    std::string text;
    bool tail = false;
    std::string kind = "normal"; // normal|branch|stack
    std::string truncatedReason; // "unreadable" when the first byte cannot be read
};

typedef std::function<bool(duint, void*, duint)> MemReader;

struct DisApi
{
    std::function<void(duint, DISASM_INSTR*)> disasmAt;
    std::function<void(duint, BASIC_INSTRUCTION_INFO*)> fastAt;
    std::function<bool(const char*, size_t, char*)> format; // StringFormatInline
    static DisApi core();
};

MemReader coreMemReader();

// One shared decode of a single instruction row (design 3.7). Three steps:
// DbgDisasmAt -> text from DbgDisasmFastAt / StringFormatInline -> Zydis tail decode near the end of memory.
DisRow decodeRow(duint addr, const MemReader & read, const DisApi & api);

// GUI_GET_DISASSEMBLY host side: copies the raw instruction text. Returns false when unreadable.
bool disasmText(duint addr, char* out, size_t cap);
}
