#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "disasm_row.h"
#include "host.h"
#include "util.h"
#include "views.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>

namespace cli
{
namespace
{
std::string absolutePath(const std::string & path)
{
    std::wstring w = wideOf(path);
    wchar_t full[MAX_PATH * 2];
    DWORD n = GetFullPathNameW(w.c_str(), (DWORD)(sizeof(full) / sizeof(full[0])), full, nullptr);
    return n && n < sizeof(full) / sizeof(full[0]) ? utf8Of(full) : path;
}

bool cleanLineText(Result & res, const char* what, const std::string & s)
{
    if(s.empty() || s.find_first_of(std::string("\r\n\0", 3)) != std::string::npos)
    {
        res.fail("E_BAD_ARG", std::string(what) + " must be a non-empty single line");
        return false;
    }
    return true;
}

bool isRunningNow()
{
    return DbgIsDebugging() && DbgIsRunning();
}

// ------------------------------------------------------------------ trace

const char* traceTypeName(TRACERECORDTYPE t)
{
    switch(t)
    {
    case TraceRecordBitExec:
        return "bit";
    case TraceRecordByteWithExecTypeAndCounter:
        return "byte";
    case TraceRecordWordWithExecTypeAndCounter:
        return "word";
    default:
        return "none";
    }
}

const char* traceByteTypeName(TRACERECORDBYTETYPE t)
{
    static const char* const n[] =
    {
        "instruction_body", "instruction_heading", "instruction_tailing", "instruction_overlapped", "data_byte", "data_word",
        "data_dword", "data_qword", "data_float", "data_double", "data_longdouble", "data_xmm", "data_ymm", "data_mmx",
        "data_mixed", "instruction_data_mixed"
    };
    return (unsigned)t < sizeof(n) / sizeof(n[0]) ? n[t] : "instruction_body";
}

bool memRegionOf(duint addr, duint & base, duint & size)
{
    MEMMAP map;
    memset(&map, 0, sizeof(map));
    if(!DbgMemMap(&map))
        return false;
    BridgeBuf<MEMPAGE> guard;
    guard.p = map.page;
    for(int i = 0; i < map.count; i++)
    {
        duint b = (duint)map.page[i].mbi.BaseAddress;
        duint s = (duint)map.page[i].mbi.RegionSize;
        if(addr >= b && addr < b + s)
        {
            base = b;
            size = s;
            return true;
        }
    }
    return false;
}

bool recordingNow()
{
    bool ok = false;
    duint v = DbgEval("tr.isrecording()", &ok);
    return ok && v != 0;
}
}

void viewTrace(Session & s, Request & req, Result & res)
{
    std::string action;
    if(!argText(req.args, "action", action, false))
    {
        res.fail("E_BAD_ARG", "trace requires action (info|set_type|reset|disable|start|stop)");
        return;
    }
    action = lower(action);
    struct Rule
    {
        const char* action;
        const char* required;
        const char* forbidden;
    } rules[] =
    {
        { "info", "", "type file" },
        { "set_type", "type", "file" },
        { "reset", "", "type file" },
        { "disable", "", "type file" },
        { "start", "file", "addr type" },
        { "stop", "", "addr type file" },
    };
    const Rule* rule = nullptr;
    for(auto & r : rules)
        if(action == r.action)
            rule = &r;
    if(!rule)
    {
        res.fail("E_BAD_ARG", "action must be info, set_type, reset, disable, start or stop");
        return;
    }
    auto listed = [](const char* list, const std::string & key) -> bool
    {
        std::string l = std::string(" ") + list + " ";
        return l.find(" " + key + " ") != std::string::npos;
    };
    for(auto & m : req.args.members())
    {
        if(m.first == "action" || m.second.isNull())
            continue;
        if(listed(rule->forbidden, m.first))
        {
            res.fail("E_BAD_ARG", "trace " + action + " does not take " + m.first);
            return;
        }
    }
    for(const char* k : { "type", "file" })
        if(listed(rule->required, k) && !req.args.find(k))
        {
            res.fail("E_BAD_ARG", "trace " + action + " requires " + k);
            return;
        }
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn)
    {
        res.fail("E_UNSUPPORTED", "this core has no trace coverage API");
        return;
    }
    if(action == "start" || action == "stop")
    {
        std::string line;
        if(action == "start")
        {
            std::string file;
            argText(req.args, "file", file, false);
            if(!cleanLineText(res, "file", file))
                return;
            line = "StartTraceRecording \"" + commandEscape(absolutePath(file)) + "\"";
        }
        else
            line = "StopTraceRecording";
        if(!s.execLine(req, res, line))
            return;
        Json d = Json::object();
        d.set("recording", recordingNow());
        res.data = d;
        return;
    }
    // info / set_type / reset / disable work on the memory region that contains addr (default: cip)
    duint addr = 0;
    std::string addrText;
    if(argText(req.args, "addr", addrText, true))
    {
        if(!evalExpr(res, addrText, "addr", addr))
            return;
    }
    else
    {
        if(isRunningNow())
        {
            res.fail("E_RUNNING", "trace without addr uses cip; pause first or pass addr");
            return;
        }
        bool ok = false;
        addr = DbgEval("cip", &ok);
        if(!ok)
        {
            res.fail("E_COMMAND_FAILED", "cip is not available");
            return;
        }
    }
    duint base = 0, size = 0;
    if(!memRegionOf(addr, base, size))
    {
        res.fail("E_MEMORY", "no memory region at " + hexAddr(addr));
        return;
    }
    Json d = Json::object();
    d.set("addr", hexAddr(addr));
    Json region = Json::object();
    region.set("base", hexAddr(base));
    region.set("size", (unsigned long long)size);
    d.set("region", region);
    d.set("pages", (long long)((size + 0xfff) / 0x1000));
    if(action == "info")
    {
        duint page = addr & ~(duint)0xfff;
        d.set("record_type", traceTypeName(fn->GetTraceRecordType ? fn->GetTraceRecordType(page) : TraceRecordNone));
        d.set("hit_count", (unsigned long long)(fn->GetTraceRecordHitCount ? fn->GetTraceRecordHitCount(addr) : 0));
        d.set("byte_type", traceByteTypeName(fn->GetTraceRecordByteType ? fn->GetTraceRecordByteType(addr) : InstructionBody));
        d.set("recording", recordingNow());
        res.data = d;
        return;
    }
    if(!fn->SetTraceRecordType || !fn->GetTraceRecordType)
    {
        res.fail("E_UNSUPPORTED", "this core cannot set the trace coverage type");
        return;
    }
    TRACERECORDTYPE type = TraceRecordNone;
    std::string typeName = "none";
    if(action == "set_type")
    {
        std::string t;
        argText(req.args, "type", t, false);
        t = lower(t);
        if(t == "bit")
            type = TraceRecordBitExec;
        else if(t == "byte")
            type = TraceRecordByteWithExecTypeAndCounter;
        else if(t == "word")
            type = TraceRecordWordWithExecTypeAndCounter;
        else
        {
            res.fail("E_BAD_ARG", "type must be bit, byte or word");
            return;
        }
        typeName = t;
        for(duint p = base; p < base + size; p += 0x1000)
            if(!fn->SetTraceRecordType(p, type))
            {
                res.fail("E_INTERNAL", "failed to enable trace coverage for page " + hexAddr(p));
                return;
            }
    }
    else if(action == "reset")
    {
        std::string firstFailure;
        for(duint p = base; p < base + size; p += 0x1000)
        {
            TRACERECORDTYPE t = fn->GetTraceRecordType(p);
            if(t == TraceRecordNone)
                continue;
            if(!fn->SetTraceRecordType(p, TraceRecordNone) || !fn->SetTraceRecordType(p, t))
                if(firstFailure.empty())
                    firstFailure = hexAddr(p);
        }
        if(!firstFailure.empty())
        {
            res.fail("E_INTERNAL", "failed to reset trace coverage for page " + firstFailure);
            return;
        }
        // reset clears the counters and keeps the recording type
        typeName = traceTypeName(fn->GetTraceRecordType(addr & ~(duint)0xfff));
    }
    else // disable
    {
        for(duint p = base; p < base + size; p += 0x1000)
            if(!fn->SetTraceRecordType(p, TraceRecordNone))
            {
                res.fail("E_INTERNAL", "failed to disable trace coverage for page " + hexAddr(p));
                return;
            }
    }
    // the GUI follows set_type and reset with "traceexecute cip" (it marks the instruction that is about to run)
    if(action != "disable" && !isRunningNow())
        if(!s.execLine(req, res, "traceexecute cip"))
            return;
    d.set("record_type", typeName);
    res.data = d;
}

// ------------------------------------------------------------------ script

namespace
{
const char* scriptLineType(SCRIPTLINETYPE t)
{
    switch(t)
    {
    case linecommand:
        return "command";
    case linebranch:
        return "branch";
    case linelabel:
        return "label";
    case linecomment:
        return "comment";
    default:
        return "empty";
    }
}

Json stringArray(const std::vector<std::string> & v)
{
    Json a = Json::array();
    for(auto & s : v)
        a.push(s);
    return a;
}

Json scriptLinesJson(int only)
{
    std::vector<std::string> lines;
    {
        std::lock_guard<std::mutex> lk(host().mu);
        lines = host().scriptLines;
    }
    Json arr = Json::array();
    for(size_t i = 0; i < lines.size(); i++)
    {
        int n = (int)i + 1;
        if(only && n != only)
            continue;
        Json j = Json::object();
        j.set("n", n);
        j.set("text", lines[i]);
        j.set("type", scriptLineType(DbgScriptGetLineType(n)));
        arr.push(j);
    }
    return arr;
}

size_t scriptLineCount()
{
    std::lock_guard<std::mutex> lk(host().mu);
    return host().scriptLines.size();
}

void clearScriptTexts()
{
    std::lock_guard<std::mutex> lk(host().mu);
    host().scriptMessages.clear();
    host().scriptErrors.clear();
}

void addScriptState(Json & d, bool withTexts)
{
    Host & h = host();
    std::lock_guard<std::mutex> lk(h.mu);
    d.set("ip", h.scriptIp);
    if(withTexts)
    {
        d.set("messages", stringArray(h.scriptMessages));
        d.set("errors", stringArray(h.scriptErrors));
    }
}

// Maps the result of a native script command: false from the core is "the script did not run to its end", not a failed op.
bool scriptNative(Session & s, Request & req, Result & res, const std::string & line, bool & finished)
{
    finished = s.execLine(req, res, line);
    if(!finished && res.pending == Result::PendingCommandFailed)
    {
        res.ok = true;
        res.pending = Result::PendingNone;
        res.code.clear();
        res.message.clear();
        res.failSegment.clear();
    }
    return res.ok;
}
}

void viewScript(Session & s, Request & req, Result & res)
{
    std::string action;
    if(!argText(req.args, "action", action, false))
    {
        res.fail("E_BAD_ARG", "script requires action");
        return;
    }
    action = lower(action);
    static const char* const known[] = { "load", "unload", "run", "step", "abort", "state", "lines", "bp_toggle", "bp_get", "set_ip", "exec", "cmd" };
    bool valid = false;
    for(const char* k : known)
        valid = valid || action == k;
    if(!valid)
    {
        res.fail("E_BAD_ARG", "action must be load, unload, run, step, abort, state, lines, bp_toggle, bp_get, set_ip, exec or cmd");
        return;
    }
    std::string file, command;
    long long line = 0;
    bool hasFile = argText(req.args, "file", file, false);
    bool hasLine = argInt(req.args, "line", line);
    bool hasCommand = argText(req.args, "command", command, false);
    auto allowed = [&](bool f, bool l, bool c) -> bool
    {
        const char* bad = (!f && hasFile) ? "file" : (!l && hasLine) ? "line" : (!c && hasCommand) ? "command" : nullptr;
        if(bad)
        {
            res.fail("E_BAD_ARG", "script " + action + " does not take " + bad);
            return false;
        }
        return true;
    };
    auto needLine = [&]() -> bool
    {
        if(!hasLine || line < 1 || (size_t)line > scriptLineCount())
        {
            res.fail("E_BAD_ARG", "script " + action + " requires line in 1.." + std::to_string(scriptLineCount()));
            return false;
        }
        return true;
    };
    auto needScript = [&]() -> bool
    {
        if(!scriptLineCount())
        {
            res.fail("E_COMMAND_FAILED", "no script is loaded (use script load)");
            return false;
        }
        return true;
    };
    auto notRunning = [&]() -> bool
    {
        if(isRunningNow())
        {
            res.fail("E_RUNNING", "the debuggee is running; scripts need a paused debuggee (pause first)");
            return false;
        }
        return true;
    };
    Json d = Json::object();
    if(action == "load")
    {
        if(!allowed(true, false, false))
            return;
        if(!hasFile || !cleanLineText(res, "file", file))
        {
            if(res.ok)
                res.fail("E_BAD_ARG", "script load requires file");
            return;
        }
        clearScriptTexts();
        DbgScriptLoad(absolutePath(file).c_str());
        std::vector<std::string> errors;
        {
            std::lock_guard<std::mutex> lk(host().mu);
            errors = host().scriptErrors;
        }
        if(!errors.empty() || !scriptLineCount())
        {
            res.fail("E_COMMAND_FAILED", errors.empty() ? "the script file produced no lines" : errors.front());
            return;
        }
        d.set("lines", scriptLinesJson(0));
        {
            std::lock_guard<std::mutex> lk(host().mu);
            d.set("title", host().scriptTitle);
        }
        addScriptState(d, true);
    }
    else if(action == "unload")
    {
        if(!allowed(false, false, false))
            return;
        DbgScriptUnload();
    }
    else if(action == "run")
    {
        if(!allowed(false, true, false) || !needScript() || !notRunning())
            return;
        if(hasLine)
        {
            if(!needLine())
                return;
            // "Run until selection": the native cannot take a line, so set the script breakpoint first (it stays set)
            if(!DbgScriptBpGet((int)line))
                DbgScriptBpToggle((int)line);
        }
        bool finished = false;
        if(!scriptNative(s, req, res, "scriptrun", finished))
            return;
        d.set("finished", finished);
        addScriptState(d, false);
    }
    else if(action == "exec")
    {
        if(!allowed(true, false, false) || !notRunning())
            return;
        if(!hasFile || !cleanLineText(res, "file", file))
        {
            if(res.ok)
                res.fail("E_BAD_ARG", "script exec requires file");
            return;
        }
        bool finished = false;
        if(!scriptNative(s, req, res, "scriptexec \"" + commandEscape(absolutePath(file)) + "\"", finished))
            return;
        d.set("finished", finished);
        addScriptState(d, false);
    }
    else if(action == "cmd")
    {
        if(!allowed(false, false, true) || !notRunning())
            return;
        if(!hasCommand || !cleanLineText(res, "command", command))
        {
            if(res.ok)
                res.fail("E_BAD_ARG", "script cmd requires command");
            return;
        }
        if(splitSemicolon(command).size() > 1)
        {
            res.fail("E_BAD_ARG", "command must be one script command (no ';')");
            return;
        }
        bool finished = false;
        if(!scriptNative(s, req, res, "scriptcmd " + command, finished))
            return;
        d.set("finished", finished);
        addScriptState(d, false);
    }
    else if(action == "step")
    {
        if(!allowed(false, false, false) || !needScript() || !notRunning())
            return;
        clearScriptTexts();
        Host & h = host();
        long long seq;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            seq = h.scriptIpSeq;
        }
        long long limit = std::min<long long>(s.timeoutOf(req), 5000);
        if(limit < 0)
            limit = 5000;
        auto t0 = std::chrono::steady_clock::now();
        DbgScriptStep();
        bool got;
        {
            std::unique_lock<std::mutex> lk(h.mu);
            got = h.cv.wait_for(lk, std::chrono::milliseconds(limit), [&]
            {
                return h.scriptIpSeq > seq;
            });
        }
        res.wait.waited = true;
        res.wait.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        if(got)
            res.wait.reason = "paused";
        else
        {
            res.wait.reason = "timeout";
            res.wait.timedOut = true;
            res.warnings.push_back("script_step_no_ip");
        }
        addScriptState(d, true);
    }
    else if(action == "abort")
    {
        if(!allowed(false, false, false))
            return;
        DbgScriptAbort();
    }
    else if(action == "state")
    {
        if(!allowed(false, false, false))
            return;
        Host & h = host();
        std::lock_guard<std::mutex> lk(h.mu);
        d.set("title", h.scriptTitle);
        auto it = h.scriptInfo.find(h.scriptIp);
        d.set("info", it != h.scriptInfo.end() ? it->second : std::string());
        d.set("ip", h.scriptIp);
        d.set("messages", stringArray(h.scriptMessages));
        d.set("errors", stringArray(h.scriptErrors));
    }
    else if(action == "lines")
    {
        if(!allowed(false, true, false))
            return;
        if(hasLine && !needLine())
            return;
        d.set("lines", scriptLinesJson(hasLine ? (int)line : 0));
        if(hasLine)
        {
            SCRIPTBRANCH br;
            memset(&br, 0, sizeof(br));
            if(DbgScriptGetBranchInfo((int)line, &br) && br.type != scriptnobranch)
            {
                static const char* const types[] = { "none", "jmp", "jne", "je", "jb", "ja", "jbe", "jae", "call" };
                Json b = Json::object();
                b.set("start", line);
                b.set("end", br.dest);
                b.set("type", (unsigned)br.type < 9 ? types[br.type] : "jmp");
                b.set("dest", br.dest);
                b.set("label", br.branchlabel);
                d.set("branch", b);
            }
            else
                d.set("branch", nullptr);
        }
    }
    else if(action == "bp_toggle" || action == "bp_get")
    {
        if(!allowed(false, true, false) || !needScript() || !needLine())
            return;
        if(action == "bp_toggle")
            DbgScriptBpToggle((int)line);
        d.set("bp", DbgScriptBpGet((int)line));
    }
    else // set_ip
    {
        if(!allowed(false, true, false) || !needScript() || !needLine())
            return;
        DbgScriptSetIp((int)line);
        addScriptState(d, false);
    }
    res.data = d;
}

// ------------------------------------------------------------------ types

void viewTypes(Session &, Request &, Result & res)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn || !fn->EnumStructs)
    {
        res.fail("E_UNSUPPORTED", "this core has no type enumeration");
        return;
    }
    std::vector<std::string> names;
    fn->EnumStructs([](const char* str, void* user)
    {
        ((std::vector<std::string>*)user)->push_back(str ? str : "");
    }, &names);
    std::sort(names.begin(), names.end());
    Json d = Json::object();
    d.set("structs", stringArray(names));
    res.data = d;
}

namespace
{
struct TypeNode
{
    std::string name, type, value;
    bool hasValue = false;
    long long offset = 0, size = 0;
    std::vector<TypeNode*> children;
};

struct TypeCtx
{
    std::deque<TypeNode> nodes;
    TypeNode* root = nullptr;
};

void* typeVisit(void* parent, const TYPEDESCRIPTOR* t, void* user)
{
    TypeCtx* ctx = (TypeCtx*)user;
    ctx->nodes.emplace_back();
    TypeNode* n = &ctx->nodes.back();
    n->name = t->name ? t->name : "";
    n->type = t->magic == TYPEDESCRIPTOR_MAGIC && t->typeName ? t->typeName : "";
    n->offset = (long long)t->offset;
    n->size = t->magic == TYPEDESCRIPTOR_MAGIC ? t->sizeBits / 8 : t->sizeBits;
    if(t->callback)
    {
        char value[128] = "";
        size_t count = sizeof(value);
        bool ok = t->callback(t, value, &count);
        if(ok)
        {
            n->value = value;
            n->hasValue = true;
        }
        else if(count && count != sizeof(value) && count < (1u << 20))
        {
            std::vector<char> big(count + 1, 0);
            size_t c2 = count;
            if(t->callback(t, big.data(), &c2))
            {
                n->value = big.data();
                n->hasValue = true;
            }
        }
    }
    if(parent)
        ((TypeNode*)parent)->children.push_back(n);
    else if(!ctx->root)
        ctx->root = n;
    return n;
}

Json typeJson(const TypeNode* n)
{
    Json j = Json::object();
    j.set("name", n->name);
    j.set("type", n->type);
    j.set("offset", n->offset);
    j.set("size", n->size);
    j.set("value", n->hasValue ? Json(n->value) : Json());
    Json kids = Json::array();
    for(auto* c : n->children)
        kids.push(typeJson(c));
    j.set("children", kids);
    return j;
}
}

void viewStruct(Session &, Request & req, Result & res)
{
    std::string type, addrText;
    if(!argText(req.args, "type", type, false) || trim(type).empty())
    {
        res.fail("E_BAD_ARG", "struct requires type");
        return;
    }
    if(!argText(req.args, "addr", addrText, true))
    {
        res.fail("E_BAD_ARG", "struct requires addr");
        return;
    }
    duint addr = 0;
    if(!evalExpr(res, addrText, "addr", addr))
        return;
    TypeCtx ctx;
    TYPEVISITDATA data;
    memset(&data, 0, sizeof(data));
    data.typeName = type.c_str();
    data.declName = nullptr;
    data.root = nullptr;
    data.addr = addr;
    data.maxPtrDepth = -1;
    data.maxExpandDepth = -1;
    data.maxExpandArray = -1;
    data.createLabels = false;
    data.callback = typeVisit;
    data.userdata = &ctx;
    if(!DbgTypeVisit(&data) || !ctx.root)
    {
        res.fail("E_COMMAND_FAILED", "failed to visit type " + type + " (is it defined? see types)");
        return;
    }
    Json d = Json::object();
    d.set("root", typeJson(ctx.root));
    res.data = d;
}

// ------------------------------------------------------------------ cfg

void viewCfg(Session &, Request & req, Result & res)
{
    duint entry = 0;
    std::string text;
    if(argText(req.args, "entry", text, true))
    {
        if(!evalExpr(res, text, "entry", entry))
            return;
    }
    else
    {
        {
            std::lock_guard<std::mutex> lk(host().mu);
            entry = (duint)host().nav.graph;
        }
        if(!entry)
        {
            if(isRunningNow())
            {
                res.fail("E_RUNNING", "cfg without entry uses cip; pause first or pass entry");
                return;
            }
            bool ok = false;
            entry = DbgEval("cip", &ok);
            if(!ok)
            {
                res.fail("E_BAD_ARG", "cfg requires entry");
                return;
            }
        }
    }
    BridgeCFGraphList list;
    memset(&list, 0, sizeof(list));
    if(!DbgAnalyzeFunction(entry, &list))
    {
        res.fail("E_COMMAND_FAILED", "no function could be analysed at " + hexAddr(entry));
        return;
    }
    BridgeCFGraph graph(&list, true); // converts the list and releases the Bridge buffers (rule L5)
    std::map<duint, const BridgeCFNode*> sorted;
    for(auto & kv : graph.nodes)
        sorted[kv.first] = &kv.second;
    Json nodes = Json::array();
    for(auto & kv : sorted)
    {
        const BridgeCFNode & n = *kv.second;
        Json j = Json::object();
        j.set("start", hexAddr(n.start));
        j.set("end", hexAddr(n.end));
        j.set("brtrue", hexAddr(n.brtrue));
        j.set("brfalse", hexAddr(n.brfalse));
        j.set("terminal", n.terminal);
        j.set("split", n.split);
        j.set("indirectcall", n.indirectcall);
        j.set("icount", (unsigned long long)n.icount);
        Json exits = Json::array();
        for(duint e : n.exits)
            exits.push(hexAddr(e));
        j.set("exits", exits);
        Json instrs = Json::array();
        for(auto & ins : n.instrs)
        {
            DisRow row = decodeRow(ins.addr, coreMemReader(), DisApi::core());
            size_t len = (size_t)std::max(1, std::min(row.size, 15));
            Json ij = Json::object();
            ij.set("addr", hexAddr(ins.addr));
            ij.set("hex", bytesToHex(ins.data, len));
            ij.set("text", row.text);
            instrs.push(ij);
        }
        j.set("instrs", instrs);
        nodes.push(j);
    }
    Json d = Json::object();
    d.set("entry", hexAddr(graph.entryPoint));
    d.set("nodes", nodes);
    res.data = d;
}

// ------------------------------------------------------------------ notes

void viewNotes(Session &, Request & req, Result & res)
{
    std::string action = "get", scope, text;
    argText(req.args, "action", action, false);
    action = lower(action);
    bool hasScope = argText(req.args, "scope", scope, false);
    bool hasText = argText(req.args, "text", text, false);
    scope = lower(scope);
    if(hasScope && scope != "global" && scope != "debuggee")
    {
        res.fail("E_BAD_ARG", "scope must be global or debuggee");
        return;
    }
    Host & h = host();
    if(action == "get")
    {
        if(hasText)
        {
            res.fail("E_BAD_ARG", "notes get does not take text");
            return;
        }
    }
    else if(action == "set")
    {
        if(!hasScope || !hasText)
        {
            res.fail("E_BAD_ARG", "notes set requires scope and text");
            return;
        }
        if(text.size() > (1u << 20))
        {
            res.fail("E_BAD_ARG", "text is longer than 1 MiB");
            return;
        }
        {
            std::lock_guard<std::mutex> lk(h.mu);
            (scope == "global" ? h.globalNotes : h.debuggeeNotes) = text;
        }
    }
    else
    {
        res.fail("E_BAD_ARG", "action must be get or set");
        return;
    }
    Json d = Json::object();
    std::lock_guard<std::mutex> lk(h.mu);
    d.set("global", h.globalNotes);
    d.set("debuggee", h.debuggeeNotes);
    res.data = d;
}

// ------------------------------------------------------------------ source

namespace
{
std::string toUtf8Text(const std::string & raw)
{
    if(raw.empty())
        return raw;
    if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), (int)raw.size(), nullptr, 0) > 0)
        return raw;
    int n = MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)raw.size(), nullptr, 0);
    if(n <= 0)
        return sanitizeUtf8(raw);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, raw.data(), (int)raw.size(), &w[0], n);
    return utf8Of(w.c_str());
}
}

void viewSource(Session &, Request & req, Result & res)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn || !fn->GetSourceFromAddr)
    {
        res.fail("E_UNSUPPORTED", "this core has no source line API");
        return;
    }
    std::string addrText, file;
    long long line = 0, context = 10;
    bool hasAddr = argText(req.args, "addr", addrText, true);
    bool hasFile = argText(req.args, "file", file, false);
    bool hasLine = argInt(req.args, "line", line);
    argInt(req.args, "context", context);
    if(context < 0 || context > 200)
    {
        res.fail("E_BAD_ARG", "context must be in 0..200");
        return;
    }
    if(hasAddr == (hasFile || hasLine) || hasFile != hasLine)
    {
        res.fail("E_BAD_ARG", "pass either addr, or file together with line");
        return;
    }
    duint addr = 0;
    bool haveAddr = false;
    char srcFile[MAX_PATH * 2] = "";
    if(hasAddr)
    {
        if(!evalExpr(res, addrText, "addr", addr))
            return;
        int l = 0;
        if(!fn->GetSourceFromAddr(addr, srcFile, &l) || !srcFile[0])
        {
            res.fail("E_COMMAND_FAILED", "no source line information for " + hexAddr(addr));
            return;
        }
        file = srcFile;
        line = l;
        haveAddr = true;
    }
    else
    {
        if(line < 1)
        {
            res.fail("E_BAD_ARG", "line must be >= 1");
            return;
        }
        // GetAddrFromLine is a stub in the core (always 0); the module-aware GetAddrFromLineEx does the lookup
        std::vector<std::pair<unsigned long long, std::string>> mods;
        {
            std::lock_guard<std::mutex> lk(host().mu);
            mods = host().modules;
        }
        for(auto & m : mods)
        {
            addr = fn->GetAddrFromLineEx ? fn->GetAddrFromLineEx((duint)m.first, file.c_str(), (int)line) : 0;
            if(addr)
                break;
        }
        haveAddr = addr != 0;
    }
    Json lines = Json::array();
    std::ifstream in(wideOf(file), std::ios::binary);
    if(in)
    {
        std::string raw;
        long long n = 0;
        long long from = std::max<long long>(1, line - context), to = line + context;
        while(std::getline(in, raw) && n < to)
        {
            n++;
            if(n < from)
                continue;
            if(!raw.empty() && raw.back() == '\r')
                raw.pop_back();
            Json j = Json::object();
            j.set("n", n);
            j.set("text", toUtf8Text(raw));
            lines.push(j);
        }
    }
    Json d = Json::object();
    d.set("addr", haveAddr ? Json(hexAddr(addr)) : Json());
    d.set("file", file);
    d.set("line", line);
    d.set("lines", lines);
    res.data = d;
}

// ------------------------------------------------------------------ nav

void viewNav(Session &, Request &, Result & res)
{
    Host & h = host();
    std::lock_guard<std::mutex> lk(h.mu);
    auto addrOrNull = [](unsigned long long v) -> Json
    {
        return v ? Json(hexAddr(v)) : Json();
    };
    auto sel = [&](unsigned long long v) -> Json
    {
        if(!v)
            return Json();
        Json s = Json::object();
        s.set("start", hexAddr(v));
        s.set("end", hexAddr(v));
        return s;
    };
    Json d = Json::object();
    d.set("disasm", addrOrNull(h.nav.disasm));
    d.set("cip", addrOrNull(h.nav.cip));
    Json dump = Json::array();
    if(h.dumpTabs.empty() && h.nav.dump)
        dump.push(hexAddr(h.nav.dump));
    for(auto & kv : h.dumpTabs)
        dump.push(hexAddr(kv.second));
    d.set("dump", dump);
    d.set("stack", addrOrNull(h.nav.stack));
    d.set("csp", addrOrNull(h.nav.csp));
    d.set("graph", addrOrNull(h.nav.graph));
    d.set("memmap", addrOrNull(h.nav.memmap));
    d.set("symmod", addrOrNull(h.nav.symmod));
    d.set("title", h.windowTitle.empty() ? Json() : Json(h.windowTitle));
    d.set("recent_files", stringArray(h.recentFiles));
    Json selection = Json::object();
    selection.set("disasm", sel(h.nav.disasm));
    selection.set("dump", sel(h.nav.dump));
    selection.set("stack", sel(h.nav.stack));
    d.set("selection", selection);
    res.data = d;
}
}
