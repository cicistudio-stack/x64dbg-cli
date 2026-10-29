#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "util.h"
#include "views.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace cli
{
namespace
{
const char* kindOf(BPXTYPE t)
{
    switch(t)
    {
    case bp_normal:
        return "sw";
    case bp_hardware:
        return "hw";
    case bp_memory:
        return "mem";
    case bp_dll:
        return "dll";
    case bp_exception:
        return "exception";
    default:
        return "";
    }
}

BPXTYPE typeOfKind(const std::string & k)
{
    if(k == "sw")
        return bp_normal;
    if(k == "hw")
        return bp_hardware;
    if(k == "mem")
        return bp_memory;
    if(k == "dll")
        return bp_dll;
    if(k == "exception")
        return bp_exception;
    return bp_none;
}

std::string idOf(const BRIDGEBP & b)
{
    std::string kind = kindOf(b.type);
    if(b.type == bp_dll)
        return kind + ":" + lower(b.mod);
    return kind + ":" + hexAddr(b.addr);
}

std::vector<BRIDGEBP> listBps()
{
    std::vector<BRIDGEBP> out;
    BPMAP map;
    memset(&map, 0, sizeof(map));
    DbgGetBpList(bp_none, &map);
    BridgeBuf<BRIDGEBP> guard;
    guard.p = map.bp;
    for(int i = 0; i < map.count && map.bp; i++)
        out.push_back(map.bp[i]);
    return out;
}

bool refOf(const BRIDGEBP & b, BP_REF & ref)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    memset(&ref, 0, sizeof(ref));
    if(!fn)
        return false;
    switch(b.type)
    {
    case bp_dll:
        if(!fn->BpRefDll)
            return false;
        fn->BpRefDll(&ref, b.mod);
        return true;
    case bp_exception:
        if(!fn->BpRefException)
            return false;
        fn->BpRefException(&ref, (unsigned int)b.addr);
        return true;
    default:
        return fn->BpRefVa && fn->BpRefVa(&ref, b.type, b.addr);
    }
}

std::string fieldText(const BP_REF * ref, BP_FIELD field, const char* fallback)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    std::string out = fallback ? fallback : "";
    if(ref && fn && fn->BpGetFieldText)
    {
        std::string got;
        bool ok = fn->BpGetFieldText(ref, field, [](const char* str, void* user)
        {
            *(std::string*)user = str ? str : "";
        }, &got);
        if(ok)
            out = got;
    }
    return out;
}

Json bpToJson(const BRIDGEBP & b)
{
    BP_REF ref;
    bool haveRef = refOf(b, ref);
    const BP_REF* rp = haveRef ? &ref : nullptr;
    const std::string kind = kindOf(b.type);
    Json j = Json::object();
    j.set("id", idOf(b));
    j.set("kind", kind);
    j.set("addr", hexAddr(b.addr));
    bool addressBased = b.type == bp_normal || b.type == bp_hardware || b.type == bp_memory;
    j.set("label", addressBased ? strOrNull(labelAt(b.addr)) : Json());
    j.set("module", strOrNull(b.mod));
    j.set("name", fieldText(rp, bpf_name, b.name));
    j.set("enabled", b.enabled);
    j.set("active", b.active);
    j.set("singleshoot", b.singleshoot);
    j.set("silent", b.silent);
    j.set("fast_resume", b.fastResume);
    j.set("hit_count", (unsigned long long)b.hitCount);
    j.set("break_condition", fieldText(rp, bpf_breakcondition, b.breakCondition));
    j.set("log_text", fieldText(rp, bpf_logtext, b.logText));
    j.set("log_condition", fieldText(rp, bpf_logcondition, b.logCondition));
    j.set("command_text", fieldText(rp, bpf_commandtext, b.commandText));
    j.set("command_condition", fieldText(rp, bpf_commandcondition, b.commandCondition));
    std::string lf = fieldText(rp, bpf_logfile, "");
    j.set("log_file", strOrNull(lf));
    if(b.type == bp_hardware)
    {
        static const char* const kinds[] = { "access", "write", "execute" };
        static const int sizes[] = { 1, 2, 4, 8 };
        Json hw = Json::object();
        hw.set("kind", b.typeEx < 3 ? kinds[b.typeEx] : "access");
        hw.set("size", b.hwSize < 4 ? sizes[b.hwSize] : 1);
        hw.set("slot", (int)b.slot);
        j.set("hw", hw);
    }
    else if(b.type == bp_memory)
    {
        static const char* const kinds[] = { "access", "read", "write", "execute" };
        Json m = Json::object();
        m.set("kind", b.typeEx < 4 ? kinds[b.typeEx] : "access");
        j.set("mem", m);
    }
    else if(b.type == bp_dll)
    {
        Json dl = Json::object();
        dl.set("name", b.mod);
        dl.set("event", b.typeEx == dll_load ? "load" : b.typeEx == dll_unload ? "unload" : "all");
        j.set("dll", dl);
    }
    else if(b.type == bp_exception)
    {
        Json ex = Json::object();
        ex.set("chance", b.typeEx == ex_firstchance ? "first" : b.typeEx == ex_secondchance ? "second" : "all");
        ex.set("code", hexAddr(b.addr));
        j.set("exception", ex);
    }
    return j;
}

// A native-command argument that names one breakpoint: 0x<addr>, "<dll>" or 0x<code>.
std::string keyArg(const BRIDGEBP & b)
{
    if(b.type == bp_dll)
        return "\"" + commandEscape(b.mod) + "\"";
    return hexArg((long long)b.addr);
}

bool cleanText(Result & res, const char* what, const std::string & s)
{
    if(s.find('\0') != std::string::npos || s.find('\r') != std::string::npos || s.find('\n') != std::string::npos)
    {
        res.fail("E_BAD_ARG", std::string(what) + " must not contain NUL, CR or LF");
        return false;
    }
    return true;
}

std::string quoted(const std::string & s)
{
    return "\"" + commandEscape(s) + "\"";
}

const char* const kKinds[] = { "sw", "hw", "mem", "dll", "exception" };

bool validKind(const std::string & k)
{
    for(auto n : kKinds)
        if(k == n)
            return true;
    return false;
}

std::string prefixOf(const std::string & kind)
{
    if(kind == "sw")
        return "SetBreakpoint";
    if(kind == "hw")
        return "SetHardwareBreakpoint";
    if(kind == "mem")
        return "SetMemoryBreakpoint";
    if(kind == "dll")
        return "SetLibrarianBreakpoint";
    return "SetExceptionBreakpoint";
}

// A memory breakpoint covers a whole memory region and is keyed by the region base.
duint memRegionBase(duint addr)
{
    duint size = 0;
    duint base = DbgMemFindBaseAddr(addr, &size);
    return base ? base : addr;
}

// Finds the listed breakpoint that an id ("kind:key") or kind + target names.
bool resolveOne(Result & res, const std::string & kind, const std::string & key, const std::vector<BRIDGEBP> & list, BRIDGEBP & out)
{
    std::string id;
    if(kind == "dll")
        id = "dll:" + lower(trim(key));
    else
    {
        duint v = 0;
        if(!evalExpr(res, key, "target", v))
            return false;
        if(kind == "mem")
            v = memRegionBase(v);
        id = kind + ":" + hexAddr(v);
    }
    for(auto & b : list)
        if(idOf(b) == id)
        {
            out = b;
            return true;
        }
    res.fail("E_BAD_ARG", "no such breakpoint: " + id);
    return false;
}

bool splitId(const std::string & id, std::string & kind, std::string & key)
{
    size_t c = id.find(':');
    if(c == std::string::npos)
        return false;
    kind = id.substr(0, c);
    key = id.substr(c + 1);
    return validKind(kind) && !key.empty();
}

Json reread(const std::string & id)
{
    for(auto & b : listBps())
        if(idOf(b) == id)
            return bpToJson(b);
    return Json();
}

void doAdd(Session & s, Request & req, Result & res)
{
    const Json & a = req.args;
    std::string kind = "sw";
    argText(a, "kind", kind, false);
    kind = lower(kind);
    if(!validKind(kind))
    {
        res.fail("E_BAD_ARG", "kind must be one of sw, hw, mem, dll, exception");
        return;
    }
    std::string target;
    if(!argText(a, "target", target, true) || trim(target).empty())
    {
        res.fail("E_BAD_ARG", "bp add requires target");
        return;
    }
    std::string name, cond, log, logCond, cmd, cmdCond;
    argText(a, "name", name, false);
    argText(a, "condition", cond, false);
    argText(a, "log", log, false);
    argText(a, "log_condition", logCond, false);
    argText(a, "command", cmd, false);
    argText(a, "command_condition", cmdCond, false);
    for(auto p : { std::make_pair("name", &name), std::make_pair("condition", &cond), std::make_pair("log", &log),
                   std::make_pair("log_condition", &logCond), std::make_pair("command", &cmd),
                   std::make_pair("command_condition", &cmdCond), std::make_pair("target", &target)
                 })
        if(!cleanText(res, p.first, *p.second))
            return;
    bool once = argBool(a, "once", false);
    bool silent = argBool(a, "silent", false);
    bool fastResume = argBool(a, "fast_resume", false);

    std::set<std::string> before;
    for(auto & b : listBps())
        before.insert(idOf(b));

    std::string line;
    std::string wantId; // the id the breakpoint has when the target is known in advance
    if(kind == "sw" || kind == "hw" || kind == "mem")
    {
        duint addr = 0;
        if(!evalExpr(res, target, "target", addr))
            return;
        wantId = kind + ":" + hexAddr(kind == "mem" ? memRegionBase(addr) : addr);
        if(kind == "sw")
        {
            line = "bp " + hexArg((long long)addr);
            if(!name.empty())
                line += "," + quoted(name);
            if(once)
                line += ",ss";
        }
        else if(kind == "hw")
        {
            std::string type = "x";
            argText(a, "hw_type", type, false);
            type = lower(type);
            long long size = 1;
            argInt(a, "size", size);
            if(type != "x" && type != "r" && type != "w")
            {
                res.fail("E_BAD_ARG", "hw_type must be x, r or w");
                return;
            }
            if(size != 1 && size != 2 && size != 4 && size != 8)
            {
                res.fail("E_BAD_ARG", "size must be 1, 2, 4 or 8");
                return;
            }
            line = "bph " + hexArg((long long)addr) + "," + type + "," + hexArg(size);
        }
        else
        {
            std::string type = "a";
            argText(a, "mem_type", type, false);
            type = lower(type);
            if(type != "a" && type != "r" && type != "w" && type != "x")
            {
                res.fail("E_BAD_ARG", "mem_type must be a, r, w or x");
                return;
            }
            line = "bpm " + hexArg((long long)addr) + "," + (argBool(a, "restore", false) ? "1" : "0") + "," + type;
        }
    }
    else if(kind == "dll")
    {
        std::string ev = "all";
        argText(a, "dll_event", ev, false);
        ev = lower(ev);
        if(ev != "load" && ev != "unload" && ev != "all")
        {
            res.fail("E_BAD_ARG", "dll_event must be load, unload or all");
            return;
        }
        wantId = "dll:" + lower(trim(target));
        line = "bpdll " + quoted(trim(target)) + "," + (ev == "load" ? "l" : ev == "unload" ? "u" : "a");
        if(once)
            line += ",ss";
    }
    else
    {
        std::string chance = "first";
        argText(a, "chance", chance, false);
        chance = lower(chance);
        if(chance != "first" && chance != "second" && chance != "all")
        {
            res.fail("E_BAD_ARG", "chance must be first, second or all");
            return;
        }
        line = "SetExceptionBPX " + quoted(trim(target)) + "," + chance;
    }
    if(!s.execLine(req, res, line))
        return;

    // which breakpoint is it? the id predicted from the target, else the one that appeared
    BRIDGEBP bp;
    bool have = false;
    std::vector<BRIDGEBP> after = listBps();
    for(auto & b : after)
        if(!wantId.empty() ? idOf(b) == wantId : !before.count(idOf(b)))
        {
            bp = b;
            have = true;
            break;
        }
    if(!have)
    {
        res.fail("E_COMMAND_FAILED", "the core accepted the command but no such breakpoint exists");
        return;
    }
    std::string ka = keyArg(bp);
    std::string pre = prefixOf(kind);
    std::vector<std::string> setters;
    if(!name.empty() && kind != "sw")
        setters.push_back(pre + "Name " + ka + "," + quoted(name));
    if(!cond.empty())
        setters.push_back(pre + "Condition " + ka + "," + quoted(cond));
    if(!log.empty())
        setters.push_back(pre + "Log " + ka + "," + quoted(log));
    if(!logCond.empty())
        setters.push_back(pre + "LogCondition " + ka + "," + quoted(logCond));
    if(!cmd.empty())
        setters.push_back(pre + "Command " + ka + "," + quoted(cmd));
    if(!cmdCond.empty())
        setters.push_back(pre + "CommandCondition " + ka + "," + quoted(cmdCond));
    if(once && kind != "sw" && kind != "dll")
        setters.push_back(pre + "Singleshoot " + ka + ",1");
    if(silent)
        setters.push_back(pre + "Silent " + ka + ",1");
    if(fastResume)
        setters.push_back(pre + "FastResume " + ka + ",1");
    for(auto & l : setters)
        if(!s.execLine(req, res, l))
            return;
    Json d = Json::object();
    d.set("breakpoint", reread(idOf(bp)));
    res.data = d;
}

void doChange(Session & s, Request & req, Result & res, const std::string & action)
{
    const Json & a = req.args;
    std::string idArg, kind, target;
    bool haveId = argText(a, "id", idArg, false);
    bool haveTarget = argText(a, "target", target, true);
    bool haveKind = argText(a, "kind", kind, false);
    bool all = argBool(a, "all", false);
    kind = lower(kind);
    if(haveKind && !validKind(kind))
    {
        res.fail("E_BAD_ARG", "kind must be one of sw, hw, mem, dll, exception");
        return;
    }
    std::vector<BRIDGEBP> list = listBps();
    std::vector<BRIDGEBP> picked;
    if(all)
    {
        for(auto & b : list)
            if(!haveKind || kindOf(b.type) == kind)
                picked.push_back(b);
    }
    else
    {
        std::string k, key;
        if(haveId)
        {
            if(!splitId(idArg, k, key))
            {
                res.fail("E_BAD_ARG", "id must look like sw:0x401000, hw:0x..., mem:0x..., dll:name or exception:0x... (see bps)");
                return;
            }
        }
        else if(haveTarget)
        {
            if(!splitId(target, k, key))
            {
                k = haveKind ? kind : "sw";
                key = target;
            }
        }
        else
        {
            res.fail("E_BAD_ARG", "give id, or kind and target, or all");
            return;
        }
        BRIDGEBP b;
        if(!resolveOne(res, k, key, list, b))
            return;
        picked.push_back(b);
    }
    static const char* const del[] = { "bpc", "bphc", "bpmc", "bcdll", "DeleteExceptionBPX" };
    static const char* const ena[] = { "bpe", "bphe", "bpme", "bpedll", "EnableExceptionBPX" };
    static const char* const dis[] = { "bpd", "bphd", "bpmd", "bpddll", "DisableExceptionBPX" };
    static const char* const rst[] = { "ResetBreakpointHitCount", "ResetHardwareBreakpointHitCount", "ResetMemoryBreakpointHitCount",
                                       "ResetLibrarianBreakpointHitCount", "ResetExceptionBreakpointHitCount"
                                     };
    const char* const* names = action == "delete" ? del : action == "enable" ? ena : action == "disable" ? dis : rst;
    long long changed = 0;
    for(auto & b : picked)
    {
        int idx = b.type == bp_normal ? 0 : b.type == bp_hardware ? 1 : b.type == bp_memory ? 2 : b.type == bp_dll ? 3 : 4;
        if(!s.execLine(req, res, std::string(names[idx]) + " " + keyArg(b)))
            return;
        changed++;
    }
    Json d = Json::object();
    d.set("breakpoint", picked.size() == 1 && !all && action != "delete" ? reread(idOf(picked[0])) : Json());
    if(action == "delete")
        d.set("deleted", changed);
    else
        d.set("changed", changed);
    res.data = d;
}
}

void viewBps(Session &, Request & req, Result & res)
{
    std::string kind = "all";
    argText(req.args, "kind", kind, false);
    kind = lower(kind);
    if(kind != "all" && !validKind(kind))
    {
        res.fail("E_BAD_ARG", "kind must be all, sw, hw, mem, dll or exception");
        return;
    }
    Json arr = Json::array();
    for(auto & b : listBps())
        if(kind == "all" || kind == kindOf(b.type))
            arr.push(bpToJson(b));
    Json d = Json::object();
    d.set("breakpoints", arr);
    d.set("count", (long long)arr.items().size());
    res.data = d;
}

void viewBp(Session & s, Request & req, Result & res)
{
    std::string action;
    if(!argText(req.args, "action", action, false))
    {
        res.fail("E_BAD_ARG", "bp requires action (add, delete, enable, disable, reset_hits)");
        return;
    }
    action = lower(action);
    if(action == "add")
        doAdd(s, req, res);
    else if(action == "delete" || action == "enable" || action == "disable" || action == "reset_hits")
        doChange(s, req, res, action);
    else
        res.fail("E_BAD_ARG", "unknown action '" + action + "' (add, delete, enable, disable, reset_hits)");
}
}
