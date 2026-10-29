#include "disasm_row.h"

#include "../dbg/_dbgfunctions.h"
#include "../zydis_wrapper/zydis_wrapper.h"

#include <cstdio>
#include <cstring>

namespace cli
{
DisApi DisApi::core()
{
    DisApi api;
    api.disasmAt = [](duint a, DISASM_INSTR * di)
    {
        DbgDisasmAt(a, di);
    };
    api.fastAt = [](duint a, BASIC_INSTRUCTION_INFO * bi)
    {
        DbgDisasmFastAt(a, bi);
    };
    api.format = [](const char* fmt, size_t n, char* out) -> bool
    {
        const DBGFUNCTIONS* f = DbgFunctions();
        return f && f->StringFormatInline && f->StringFormatInline(fmt, n, out);
    };
    return api;
}

MemReader coreMemReader()
{
    return [](duint a, void* d, duint n) -> bool
    {
        return DbgMemRead(a, d, n);
    };
}

static const char* kindName(DISASM_INSTRTYPE t)
{
    switch(t)
    {
    case instr_branch:
        return "branch";
    case instr_stack:
        return "stack";
    default:
        return "normal";
    }
}

DisRow decodeRow(duint addr, const MemReader & read, const DisApi & api)
{
    DisRow row;
    row.addr = addr;

    // step 1: structure from DbgDisasmAt
    DISASM_INSTR di;
    memset(&di, 0, sizeof(di));
    api.disasmAt(addr, &di);
    if(di.instr_size != 0)
    {
        row.size = di.instr_size;
        row.kind = kindName(di.type);
        // step 2: text
        BASIC_INSTRUCTION_INFO bi;
        memset(&bi, 0, sizeof(bi));
        api.fastAt(addr, &bi);
        if(bi.instruction[0] != 0 && bi.size == di.instr_size)
        {
            row.text = bi.instruction;
        }
        else
        {
            char fmt[64];
            snprintf(fmt, sizeof(fmt), "{dis.text(0x%llx)}", (unsigned long long)addr);
            std::string buf(1024, '\0');
            if(api.format(fmt, buf.size(), &buf[0]))
                row.text = buf.c_str();
            else
                row.text = "???";
        }
        return row;
    }

    // step 3: tail rows. Find the largest readable window of 15..1 bytes.
    unsigned char bytes[16] = {};
    int n = 0;
    for(int k = 15; k >= 1; k--)
    {
        if(read(addr, bytes, k))
        {
            n = k;
            break;
        }
    }
    if(n == 0)
    {
        row.size = 1;
        row.text = "???";
        row.truncatedReason = "unreadable";
        return row;
    }
    Zydis z;
    if(z.Disassemble(addr, bytes, (size_t)n))
    {
        row.size = z.Size();
        row.text = z.InstructionText();
        row.tail = true;
        row.kind = z.IsBranchType(Zydis::BTAny) ? "branch" : "normal";
    }
    else
    {
        row.size = 1;
        row.text = "???";
        row.tail = true;
    }
    return row;
}

bool disasmText(duint addr, char* out, size_t cap)
{
    if(!addr || !out || !cap || !DbgIsDebugging())
        return false;
    DisRow r = decodeRow(addr, coreMemReader(), DisApi::core());
    if(!r.truncatedReason.empty())
        return false;
    strncpy_s(out, cap, r.text.c_str(), _TRUNCATE);
    return true;
}
}
