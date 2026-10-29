#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "disasm_row.h"
#include "util.h"
#include "views.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

namespace cli
{
namespace
{
// Runs a table-producing native list command and returns the captured table as data.table.
void tableWrapper(Session & s, Request & req, Result & res, const char* line)
{
    if(!s.execLine(req, res, line))
        return;
    Json d = Json::object();
    d.set("table", takeLastTable(req));
    res.data = d;
}

// Optional "addr[,size]" arguments of strref / modcallfind / reffunctionpointer. Expressions are passed as typed; the
// characters that would change the meaning of the native line are refused.
bool searchLine(Request & req, Result & res, const char* command, std::string & line)
{
    std::string addr, size;
    bool hasAddr = argText(req.args, "addr", addr, true);
    bool hasSize = argText(req.args, "size", size, true);
    auto clean = [&](const std::string & s, const char* what) -> bool
    {
        if(s.find_first_of(",;\r\n\"") != std::string::npos || trim(s).empty())
        {
            res.fail("E_BAD_ARG", std::string(what) + " must be one expression without ',' ';' or quotes");
            return false;
        }
        return true;
    };
    line = command;
    if(hasSize && !hasAddr)
    {
        res.fail("E_BAD_ARG", "size needs addr");
        return false;
    }
    if(!hasAddr && !(DbgIsDebugging() && DbgIsRunning()))
    {
        // The natives default to the disassembly selection, which the host only learns about a few milliseconds after a
        // pause. cip is the selection the GUI has after a pause, and it is never stale.
        line += " cip";
    }
    else if(hasAddr)
    {
        if(!clean(addr, "addr"))
            return false;
        line += " " + trim(addr);
        if(hasSize)
        {
            if(!clean(size, "size"))
                return false;
            line += "," + trim(size);
        }
    }
    return true;
}

void searchWrapper(Session & s, Request & req, Result & res, const char* command)
{
    std::string line;
    if(!searchLine(req, res, command, line))
        return;
    tableWrapper(s, req, res, line.c_str());
}

const char* bpKindName(BPXTYPE bt, bool disabled)
{
    const char* n = "none";
    if(bt & bp_normal)
        n = "normal";
    else if(bt & bp_hardware)
        n = "hardware";
    else if(bt & bp_memory)
        n = "memory";
    else if(bt & bp_dll)
        n = "dll";
    else if(bt & bp_exception)
        n = "exception";
    if(disabled && !strcmp(n, "none"))
        n = "normal";
    return n;
}
}

void viewLabels(Session & s, Request & req, Result & res)
{
    tableWrapper(s, req, res, "labellist");
}

void viewComments(Session & s, Request & req, Result & res)
{
    tableWrapper(s, req, res, "commentlist");
}

void viewBookmarks(Session & s, Request & req, Result & res)
{
    tableWrapper(s, req, res, "bookmarklist");
}

void viewFunctions(Session & s, Request & req, Result & res)
{
    tableWrapper(s, req, res, "functionlist");
}

void viewArguments(Session & s, Request & req, Result & res)
{
    tableWrapper(s, req, res, "argumentlist");
}

void viewLoops(Session & s, Request & req, Result & res)
{
    tableWrapper(s, req, res, "looplist");
}

void viewStrings(Session & s, Request & req, Result & res)
{
    searchWrapper(s, req, res, "strref");
}

void viewCalls(Session & s, Request & req, Result & res)
{
    searchWrapper(s, req, res, "modcallfind");
}

void viewPtrs(Session & s, Request & req, Result & res)
{
    searchWrapper(s, req, res, "reffunctionpointer");
}

void viewAddrInfo(Session &, Request & req, Result & res)
{
    std::string text;
    duint addr = 0;
    if(!argText(req.args, "addr", text, true))
    {
        res.fail("E_BAD_ARG", "addrinfo requires addr");
        return;
    }
    if(!evalExpr(res, text, "addr", addr))
        return;
    Json d = Json::object();
    d.set("addr", hexAddr(addr));
    d.set("label", strOrNull(labelAt(addr)));
    char comment[MAX_COMMENT_SIZE] = "";
    std::string c;
    if(DbgGetCommentAt(addr, comment))
        c = comment[0] == '\1' ? comment + 1 : comment;
    d.set("comment", strOrNull(c));
    d.set("bookmark", DbgGetBookmarkAt(addr));
    d.set("module", strOrNull(moduleAt(addr)));
    duint start = 0, end = 0;
    if(DbgFunctionGet(addr, &start, &end))
    {
        Json f = Json::object();
        f.set("start", hexAddr(start));
        f.set("end", hexAddr(end));
        d.set("function", f);
    }
    else
        d.set("function", nullptr);
    d.set("loop", loopName(DbgGetLoopTypeAt(addr, 0)));
    d.set("argument", argTypeName(DbgGetArgTypeAt(addr)));
    d.set("bp", bpKindName(DbgGetBpxTypeAt(addr), DbgIsBpDisabled(addr)));
    unsigned int color = 0;
    d.set("color", DbgGetAddressColorAt(addr, &color) ? Json((unsigned long long)color) : Json());
    d.set("encoding", encodingName(DbgGetEncodeTypeAt(addr, 1)));
    res.data = d;
}

void viewXrefs(Session &, Request & req, Result & res)
{
    std::string text;
    duint addr = 0;
    if(!argText(req.args, "addr", text, true))
    {
        res.fail("E_BAD_ARG", "xrefs requires addr");
        return;
    }
    if(!evalExpr(res, text, "addr", addr))
        return;
    XREF_INFO info;
    memset(&info, 0, sizeof(info));
    bool have = DbgXrefGet(addr, &info);
    BridgeBuf<XREF_RECORD> guard;
    if(info.refcount > 0)
        guard.p = info.references;
    Json list = Json::array();
    if(have && info.references)
    {
        std::vector<XREF_RECORD> recs(info.references, info.references + info.refcount);
        std::sort(recs.begin(), recs.end(), [](const XREF_RECORD & a, const XREF_RECORD & b)
        {
            return a.addr < b.addr;
        });
        for(auto & r : recs)
        {
            Json j = Json::object();
            j.set("from", hexAddr(r.addr));
            j.set("type", r.type == XREF_CALL ? "call" : r.type == XREF_JMP ? "jmp" : "data");
            j.set("from_label", strOrNull(labelAt(r.addr)));
            j.set("text", decodeRow(r.addr, coreMemReader(), DisApi::core()).text);
            list.push(j);
        }
    }
    Json d = Json::object();
    d.set("addr", hexAddr(addr));
    d.set("count", (long long)list.items().size());
    d.set("xrefs", list);
    res.data = d;
}

namespace
{
bool enumPatches(std::vector<DBGPATCHINFO> & out)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    out.clear();
    if(!fn || !fn->PatchEnum)
        return false;
    size_t cb = 0;
    if(!fn->PatchEnum(nullptr, &cb))
        return false;
    if(!cb)
        return true;
    out.resize(cb / sizeof(DBGPATCHINFO));
    size_t cb2 = out.size() * sizeof(DBGPATCHINFO);
    if(!fn->PatchEnum(out.data(), &cb2))
    {
        out.clear();
        return false;
    }
    return true;
}
}

void viewPatches(Session &, Request &, Result & res)
{
    std::vector<DBGPATCHINFO> list;
    if(!enumPatches(list))
    {
        res.fail("E_COMMAND_FAILED", "the patch list is not available");
        return;
    }
    Json arr = Json::array();
    for(auto & p : list)
    {
        Json j = Json::object();
        j.set("module", p.mod);
        j.set("addr", hexAddr(p.addr));
        j.set("old", bytesToHex(&p.oldbyte, 1));
        j.set("new", bytesToHex(&p.newbyte, 1));
        arr.push(j);
    }
    Json d = Json::object();
    d.set("patches", arr);
    d.set("count", (long long)arr.items().size());
    res.data = d;
}

void viewPatch(Session &, Request & req, Result & res)
{
    std::string action;
    if(!argText(req.args, "action", action, false))
    {
        res.fail("E_BAD_ARG", "patch requires action (export|restore|restore_range)");
        return;
    }
    action = lower(action);
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn)
    {
        res.fail("E_UNSUPPORTED", "this core has no patch API");
        return;
    }
    auto forbid = [&](const char* key) -> bool
    {
        if(req.args.find(key))
        {
            res.fail("E_BAD_ARG", std::string("patch ") + action + " does not take " + key);
            return false;
        }
        return true;
    };
    auto exprArg = [&](const char* key, duint & out) -> bool
    {
        std::string t;
        if(!argText(req.args, key, t, true))
        {
            res.fail("E_BAD_ARG", std::string("patch ") + action + " requires " + key);
            return false;
        }
        return evalExpr(res, t, key, out);
    };
    Json d = Json::object();
    if(action == "export")
    {
        if(!forbid("addr") || !forbid("end"))
            return;
        std::string file, module;
        if(!argText(req.args, "file", file, false) || trim(file).empty() || file.find_first_of("\r\n") != std::string::npos)
        {
            res.fail("E_BAD_ARG", "patch export requires file (the output path)");
            return;
        }
        argText(req.args, "module", module, false);
        std::vector<DBGPATCHINFO> all, sel;
        if(!enumPatches(all) || all.empty())
        {
            res.fail("E_COMMAND_FAILED", "there are no patches to export");
            return;
        }
        // like the patch dialog: the patches of one module are written to one file
        std::set<std::string> modules;
        for(auto & p : all)
            modules.insert(lower(p.mod));
        std::string pick = module.empty() ? lower(all[0].mod) : lower(module);
        if(module.empty() && modules.size() > 1)
        {
            res.fail("E_BAD_ARG", "the patches belong to several modules; pass module");
            return;
        }
        for(auto & p : all)
            if(lower(p.mod) == pick)
                sel.push_back(p);
        if(sel.empty())
        {
            res.fail("E_BAD_ARG", "no patches in module " + module);
            return;
        }
        std::wstring wfile = wideOf(file);
        wchar_t full[MAX_PATH * 2];
        DWORD n = GetFullPathNameW(wfile.c_str(), (DWORD)(sizeof(full) / sizeof(full[0])), full, nullptr);
        std::string path = n && n < sizeof(full) / sizeof(full[0]) ? utf8Of(full) : file;
        char error[MAX_ERROR_SIZE] = "";
        int written = fn->PatchFile ? fn->PatchFile(sel.data(), (int)sel.size(), path.c_str(), error) : -1;
        if(written == -1)
        {
            res.fail("E_COMMAND_FAILED", std::string("failed to save the patched file: ") + error);
            return;
        }
        d.set("written", (long long)written);
        d.set("error", nullptr);
    }
    else if(action == "restore")
    {
        if(!forbid("file") || !forbid("end") || !forbid("module"))
            return;
        duint addr;
        if(!exprArg("addr", addr))
            return;
        bool ok = fn->PatchRestore && fn->PatchRestore(addr);
        if(!ok)
        {
            res.fail("E_COMMAND_FAILED", "no patch at " + hexAddr(addr));
            return;
        }
        d.set("restored", 1);
        d.set("error", nullptr);
    }
    else if(action == "restore_range")
    {
        if(!forbid("file") || !forbid("module"))
            return;
        duint start, end;
        if(!exprArg("addr", start) || !exprArg("end", end))
            return;
        if(end < start)
        {
            res.fail("E_BAD_ARG", "end must not be below addr");
            return;
        }
        long long before = 0, after = 0;
        std::vector<DBGPATCHINFO> list;
        auto countIn = [&]() -> long long
        {
            long long c = 0;
            enumPatches(list);
            for(auto & p : list)
                if(p.addr >= start && p.addr <= end)
                    c++;
            return c;
        };
        before = countIn();
        if(fn->PatchRestoreRange)
            fn->PatchRestoreRange(start, end);
        after = countIn();
        d.set("restored", before - after);
        d.set("error", nullptr);
    }
    else
    {
        res.fail("E_BAD_ARG", "action must be export, restore or restore_range");
        return;
    }
    res.data = d;
}

void viewWatch(Session &, Request &, Result & res)
{
    BridgeList<WATCHINFO> list;
    Json arr = Json::array();
    DbgGetWatchList(&list); // like the GUI: the return value of this call is not meaningful (the message handler returns 0)
    {
        static const char* const types[] = { "uint", "int", "float", "ascii", "unicode", "invalid" };
        static const char* const modes[] = { "disabled", "istrue", "isfalse", "changed", "unchanged" };
        for(int i = 0; i < list.Count(); i++)
        {
            const WATCHINFO & w = list[i];
            Json j = Json::object();
            j.set("id", (unsigned long long)w.id);
            j.set("name", w.WatchName);
            j.set("expression", w.Expression);
            j.set("type", (unsigned)w.varType < 6 ? types[w.varType] : "invalid");
            j.set("mode", (unsigned)w.watchdogMode < 5 ? modes[w.watchdogMode] : "disabled");
            j.set("value", hexAddr(w.value));
            j.set("triggered", w.watchdogTriggered);
            arr.push(j);
        }
    }
    Json d = Json::object();
    d.set("watches", arr);
    d.set("count", (long long)arr.items().size());
    res.data = d;
}
}
