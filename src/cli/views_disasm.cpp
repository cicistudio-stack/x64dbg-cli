#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "disasm_row.h"
#include "util.h"
#include "views.h"

#include <cstdio>
#include <cstring>
#include <memory>

namespace cli
{
const char* funcName(FUNCTYPE t)
{
    static const char* const n[] = { "none", "begin", "middle", "end", "single" };
    return (unsigned)t < 5 ? n[t] : "none";
}

const char* loopName(LOOPTYPE t)
{
    static const char* const n[] = { "none", "begin", "middle", "entry", "end", "single" };
    return (unsigned)t < 6 ? n[t] : "none";
}

const char* argTypeName(ARGTYPE t)
{
    static const char* const n[] = { "none", "begin", "middle", "end", "single" };
    return (unsigned)t < 5 ? n[t] : "none";
}

const char* encodingName(ENCODETYPE t)
{
    static const char* const n[] =
    {
        "code", "byte", "word", "dword", "fword", "qword", "tbyte", "oword", "mmword", "xmmword", "ymmword", "zmmword",
        "real4", "real8", "real10", "ascii", "unicode", "code", "junk", "middle"
    };
    return (unsigned)t < sizeof(n) / sizeof(n[0]) ? n[t] : "code";
}

static Json invalidRow(duint addr, const DisRow & r)
{
    (void)r;
    Json j = Json::object();
    j.set("addr", hexAddr(addr));
    j.set("size", 1);
    j.set("bytes", "3f3f");
    j.set("text", "???");
    j.set("kind", "invalid");
    j.set("is_cip", false);
    j.set("label", nullptr);
    j.set("module", nullptr);
    j.set("comment", nullptr);
    j.set("bp", "none");
    j.set("bp_disabled", false);
    j.set("bookmark", false);
    j.set("function", "none");
    j.set("loop", "none");
    j.set("argument", "none");
    j.set("branch", nullptr);
    j.set("args", Json::array());
    j.set("xrefs", 0);
    j.set("encoding", "code");
    j.set("string", nullptr);
    return j;
}

static Json buildRow(duint addr, const DisRow & row, bool withBytes, bool atCip, bool haveCip)
{
    if(!row.truncatedReason.empty())
        return invalidRow(addr, row);
    Json j = Json::object();
    j.set("addr", hexAddr(addr));
    j.set("size", row.size);
    if(withBytes)
    {
        unsigned char buf[32] = {};
        size_t n = (size_t)row.size > sizeof(buf) ? sizeof(buf) : (size_t)row.size;
        j.set("bytes", DbgMemRead(addr, buf, n) ? bytesToHex(buf, n) : std::string());
    }
    j.set("text", row.text);
    bool invalid = row.tail && row.text == "???";
    j.set("kind", invalid ? "invalid" : row.kind);
    j.set("is_cip", haveCip && atCip);
    j.set("label", strOrNull(labelAt(addr)));
    j.set("module", strOrNull(moduleAt(addr)));
    char comment[MAX_COMMENT_SIZE] = "";
    std::string c;
    if(DbgGetCommentAt(addr, comment))
        c = comment[0] == '\1' ? comment + 1 : comment;
    j.set("comment", strOrNull(c));
    BPXTYPE bt = DbgGetBpxTypeAt(addr);
    const char* bpName = "none";
    if(bt & bp_normal)
        bpName = "normal";
    else if(bt & bp_hardware)
        bpName = "hardware";
    else if(bt & bp_memory)
        bpName = "memory";
    bool disabled = DbgIsBpDisabled(addr);
    if(disabled && !strcmp(bpName, "none"))
        bpName = "normal";
    j.set("bp", bpName);
    j.set("bp_disabled", disabled);
    j.set("bookmark", DbgGetBookmarkAt(addr));
    j.set("function", funcName(DbgGetFunctionTypeAt(addr)));
    j.set("loop", loopName(DbgGetLoopTypeAt(addr, 0)));
    j.set("argument", argTypeName(DbgGetArgTypeAt(addr)));

    // structure from DbgDisasmAt: branch information and operands (never its truncated instruction text)
    DISASM_INSTR di;
    memset(&di, 0, sizeof(di));
    BASIC_INSTRUCTION_INFO bi;
    memset(&bi, 0, sizeof(bi));
    if(!row.tail)
    {
        DbgDisasmAt(addr, &di);
        DbgDisasmFastAt(addr, &bi);
    }
    bool isBranch = row.kind == "branch";
    if(isBranch)
    {
        Json br = Json::object();
        duint target = row.tail ? 0 : DbgGetBranchDestination(addr);
        br.set("target", target ? Json(hexAddr(target)) : Json());
        br.set("target_label", target ? strOrNull(labelAt(target)) : Json());
        bool call = bi.call;
        if(row.tail)
        {
            std::string t = lower(row.text);
            call = t.compare(0, 4, "call") == 0;
        }
        br.set("call", call);
        bool conditional = false;
        if(!call)
        {
            char expr[64];
            snprintf(expr, sizeof(expr), "dis.iscond(0x%llx)", (unsigned long long)addr);
            bool ok = false;
            duint v = DbgEval(expr, &ok);
            std::string t = lower(row.text);
            conditional = ok && v != 0 && (t[0] == 'j' || t.compare(0, 4, "loop") == 0 || t.compare(0, 6, "xbegin") == 0);
        }
        br.set("conditional", conditional);
        br.set("taken", atCip && haveCip && conditional ? Json(DbgIsJumpGoingToExecute(addr)) : Json());
        j.set("branch", br);
    }
    else
        j.set("branch", nullptr);
    Json args = Json::array();
    for(int i = 0; i < di.argcount && i < 3; i++)
    {
        Json a = Json::object();
        a.set("type", di.arg[i].type == arg_memory ? "memory" : "normal");
        a.set("text", di.arg[i].mnemonic);
        a.set("value", hexAddr(di.arg[i].value));
        a.set("mem_value", hexAddr(di.arg[i].memvalue));
        args.push(a);
    }
    j.set("args", args);
    j.set("xrefs", (unsigned long long)DbgGetXrefCountAt(addr));
    j.set("encoding", encodingName(DbgGetEncodeTypeAt(addr, (duint)row.size)));
    char str[MAX_STRING_SIZE] = "";
    j.set("string", DbgGetStringAt(addr, str) && str[0] ? Json(str) : Json());
    if(row.tail)
        j.set("tail", true);
    return j;
}

void viewDis(Session &, Request & req, Result & res)
{
    long long count = 16;
    bool haveCount = argInt(req.args, "count", count);
    if(count < 1 || count > 4096)
    {
        res.fail("E_BAD_ARG", "count must be in 1..4096 (the maximum is 4096)");
        return;
    }
    long long back = 0;
    argInt(req.args, "back", back);
    if(back < 0 || back > 4096)
    {
        res.fail("E_BAD_ARG", "back must be in 0..4096");
        return;
    }
    bool live = isLive();
    duint cip = 0;
    bool haveCip = false;
    if(!live)
    {
        // registers first, so that register-indirect branch targets resolve (design 3.8)
        std::unique_ptr<REGDUMP_AVX512> dump(new REGDUMP_AVX512());
        DbgGetRegDumpEx(dump.get(), sizeof(REGDUMP_AVX512));
        cip = DbgEval("cip", &haveCip);
    }
    std::string addrText;
    duint addr = 0;
    if(argText(req.args, "addr", addrText, true))
    {
        if(!evalExpr(res, addrText, "addr", addr))
            return;
    }
    else
    {
        if(!haveCip)
        {
            res.fail("E_RUNNING", "dis without an address starts at the current instruction pointer, which is unknown while the debuggee runs; pass addr");
            return;
        }
        addr = cip;
    }
    bool haveUntil = false;
    duint until = 0;
    std::string untilText;
    if(argText(req.args, "until", untilText, true))
    {
        if(!evalExpr(res, untilText, "until", until))
            return;
        haveUntil = true;
    }
    bool withBytes = argBool(req.args, "bytes", true);

    for(long long i = 0; i < back; i++)
    {
        char expr[64];
        snprintf(expr, sizeof(expr), "dis.prev(0x%llx)", (unsigned long long)addr);
        bool ok = false;
        duint prev = DbgEval(expr, &ok);
        if(!ok || prev == 0 || prev >= addr)
            break;
        addr = prev;
    }

    MemReader read = coreMemReader();
    DisApi api = DisApi::core();
    Json rows = Json::array();
    duint at = addr;
    std::string why;
    long long produced = 0;
    long long cap = haveUntil && !haveCount ? 4096 : count;
    while(produced < cap)
    {
        if(haveUntil && at >= until)
            break;
        DisRow row = decodeRow(at, read, api);
        rows.push(buildRow(at, row, withBytes, haveCip && at == cip, haveCip));
        produced++;
        if(!row.truncatedReason.empty())
        {
            why = row.truncatedReason;
            break;
        }
        at += (duint)row.size;
    }
    if(why.empty() && produced >= cap && haveUntil && at < until)
        why = "limit";
    Json d = Json::object();
    d.set("start", hexAddr(addr));
    d.set("cip", haveCip ? Json(hexAddr(cip)) : Json());
    d.set("live", live);
    d.set("count", (long long)produced);
    if(!why.empty())
        d.set("truncated_reason", why);
    d.set("instructions", rows);
    res.data = d;
}
}
