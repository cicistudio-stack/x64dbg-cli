#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "host.h"
#include "util.h"
#include "views.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>

namespace cli
{
namespace
{
const char* priorityName(THREADPRIORITY p)
{
    switch(p)
    {
    case _PriorityIdle:
        return "Idle";
    case _PriorityLowest:
        return "Lowest";
    case _PriorityBelowNormal:
        return "BelowNormal";
    case _PriorityNormal:
        return "Normal";
    case _PriorityAboveNormal:
        return "AboveNormal";
    case _PriorityHighest:
        return "Highest";
    case _PriorityTimeCritical:
        return "TimeCritical";
    default:
        return "Unknown";
    }
}

const char* waitReasonName(THREADWAITREASON r)
{
    static const char* const n[] =
    {
        "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended", "UserRequest", "WrExecutive",
        "WrFreePage", "WrPageIn", "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest", "WrEventPair",
        "WrQueue", "WrLpcReceive", "WrLpcReply", "WrVirtualMemory", "WrPageOut", "WrRendezvous", "Spare2", "Spare3", "Spare4",
        "Spare5", "WrCalloutStack", "WrKernel", "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt",
        "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex", "WrRundown"
    };
    return (unsigned)r < sizeof(n) / sizeof(n[0]) ? n[r] : "Unknown";
}

unsigned long long fileTime(const FILETIME & ft)
{
    return ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

std::string isoTime(const FILETIME & ft)
{
    SYSTEMTIME st;
    if(fileTime(ft) == 0 || !FileTimeToSystemTime(&ft, &st))
        return std::string();
    char b[48];
    snprintf(b, sizeof(b), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return b;
}

// The user may name a thread priority or give an integer.
bool priorityValue(const std::string & value, std::string & out)
{
    static const char* const names[] = { "Normal", "AboveNormal", "TimeCritical", "Idle", "BelowNormal", "Highest", "Lowest" };
    for(auto n : names)
        if(lower(value) == lower(n))
        {
            out = n;
            return true;
        }
    bool neg = !value.empty() && value[0] == '-';
    long long v;
    if(!parseInteger(neg ? value.substr(1) : value, v))
        return false;
    out = (neg ? "-" : "") + hexArg(v);
    return true;
}
}

bool buildThreadLine(const std::string & action, bool hasTid, long long tid, bool hasValue, const std::string & value,
                     std::string & line, std::string & error)
{
    auto need = [&](const char* key, bool present, bool required, bool allowed) -> bool
    {
        if(required && !present)
        {
            error = std::string("thread ") + action + " requires " + key;
            return false;
        }
        if(!allowed && present)
        {
            error = std::string("thread ") + action + " does not take " + key;
            return false;
        }
        return true;
    };
    std::string t = hasTid ? hexArg(tid) : std::string();
    if(action == "switch" || action == "suspend" || action == "resume")
    {
        if(!need("tid", hasTid, true, true) || !need("value", hasValue, false, false))
            return false;
        line = (action == "switch" ? "switchthread " : action == "suspend" ? "suspendthread " : "resumethread ") + t;
        return true;
    }
    if(action == "suspend_all" || action == "resume_all")
    {
        if(!need("tid", hasTid, false, false) || !need("value", hasValue, false, false))
            return false;
        line = action == "suspend_all" ? "suspendallthreads" : "resumeallthreads";
        return true;
    }
    if(action == "kill")
    {
        if(!need("tid", hasTid, true, true))
            return false;
        long long code = 0;
        if(hasValue && !parseInteger(trim(value), code))
        {
            error = "thread kill: value must be the exit code (decimal or 0x hex)";
            return false;
        }
        line = "killthread " + t + "," + hexArg(code);
        return true;
    }
    if(action == "name")
    {
        if(!need("tid", hasTid, true, true) || !need("value", hasValue, true, true))
            return false;
        if(value.size() > 255 || value.find('\0') != std::string::npos || value.find('\r') != std::string::npos || value.find('\n') != std::string::npos)
        {
            error = "thread name: value must be 0..255 characters without NUL, CR or LF";
            return false;
        }
        line = "threadsetname " + t + ",\"" + commandEscape(value) + "\"";
        return true;
    }
    if(action == "priority")
    {
        if(!need("tid", hasTid, true, true) || !need("value", hasValue, true, true))
            return false;
        std::string p;
        if(!priorityValue(trim(value), p))
        {
            error = "thread priority: value must be Normal, AboveNormal, TimeCritical, Idle, BelowNormal, Highest, Lowest or an integer";
            return false;
        }
        line = "setthreadpriority " + t + "," + p;
        return true;
    }
    if(action == "create")
    {
        if(!need("tid", hasTid, false, false) || !need("value", hasValue, true, true))
            return false;
        line = "createthread " + trim(value);
        return true;
    }
    error = "unknown action '" + action + "' (switch, suspend, resume, suspend_all, resume_all, kill, name, priority, create)";
    return false;
}

void viewThreads(Session &, Request &, Result & res)
{
    THREADLIST list;
    memset(&list, 0, sizeof(list));
    DbgGetThreadList(&list);
    BridgeBuf<THREADALLINFO> guard;
    guard.p = list.list;
    const DBGFUNCTIONS* fn = DbgFunctions();
    Json arr = Json::array();
    unsigned long long currentTid = 0;
    // The cycle and time counters of a suspended thread still grow a little with every context query of the debugger.
    // While the debuggee stays paused, the values of the first read are reused, so that two renders agree (T46).
    struct Counters
    {
        FILETIME user, kernel;
        ULONG64 cycles;
    };
    static long long cachedSeq = -1;
    static std::map<DWORD, Counters> cache;
    {
        long long seq;
        Status st;
        {
            std::lock_guard<std::mutex> lk(host().mu);
            seq = host().stateSeq;
            st = host().reportedStatusLocked();
        }
        if(st != Status::Paused || seq != cachedSeq)
        {
            cache.clear();
            cachedSeq = st == Status::Paused ? seq : -1;
        }
    }
    for(int i = 0; i < list.count; i++)
    {
        THREADALLINFO t = list.list[i];
        if(cachedSeq >= 0)
        {
            auto hit = cache.find(t.BasicInfo.ThreadId);
            if(hit == cache.end())
                cache[t.BasicInfo.ThreadId] = Counters{ t.UserTime, t.KernelTime, t.Cycles };
            else
            {
                t.UserTime = hit->second.user;
                t.KernelTime = hit->second.kernel;
                t.Cycles = hit->second.cycles;
            }
        }
        bool cur = i == list.CurrentThread;
        if(cur)
            currentTid = t.BasicInfo.ThreadId;
        Json j = Json::object();
        j.set("index", t.BasicInfo.ThreadNumber);
        j.set("tid", (unsigned long long)t.BasicInfo.ThreadId);
        char name[MAX_THREAD_NAME_SIZE] = "";
        if(fn && fn->ThreadGetName && fn->ThreadGetName(t.BasicInfo.ThreadId, name) && name[0])
            j.set("name", name);
        else
            j.set("name", strOrNull(t.BasicInfo.threadName));
        j.set("handle", hexAddr((unsigned long long)(duint)t.BasicInfo.Handle));
        j.set("start", hexAddr(t.BasicInfo.ThreadStartAddress));
        j.set("teb", hexAddr(t.BasicInfo.ThreadLocalBase));
        j.set("cip", hexAddr(t.ThreadCip));
        j.set("cip_label", strOrNull(labelAt(t.ThreadCip)));
        j.set("suspend_count", (unsigned long long)t.SuspendCount);
        j.set("priority", priorityName(t.Priority));
        j.set("wait_reason", waitReasonName(t.WaitReason));
        j.set("last_error", hexN(t.LastError, 8));
        j.set("user_time_ms", (long long)(fileTime(t.UserTime) / 10000));
        j.set("kernel_time_ms", (long long)(fileTime(t.KernelTime) / 10000));
        j.set("cycles", std::to_string((unsigned long long)t.Cycles));
        j.set("creation_time", isoTime(t.CreationTime));
        j.set("is_current", cur);
        j.set("is_main", t.BasicInfo.ThreadNumber == 0);
        arr.push(j);
    }
    Json d = Json::object();
    d.set("current_tid", currentTid);
    d.set("threads", arr);
    res.data = d;
}

void viewThread(Session & s, Request & req, Result & res)
{
    std::string action;
    if(!argText(req.args, "action", action, false))
    {
        res.fail("E_BAD_ARG", "thread requires action");
        return;
    }
    action = lower(action);
    long long tid = 0;
    bool hasTid = argInt(req.args, "tid", tid);
    std::string value;
    bool hasValue = argText(req.args, "value", value, false);
    if(hasTid && (tid < 0 || tid > 0xffffffffLL))
    {
        res.fail("E_BAD_ARG", "tid must be a 32-bit thread id");
        return;
    }
    std::string line, error;
    if(!buildThreadLine(action, hasTid, tid, hasValue, value, line, error))
    {
        res.fail("E_BAD_ARG", error);
        return;
    }
    s.execLine(req, res, line);
}

void viewModules(Session &, Request & req, Result & res)
{
    std::string filter;
    argText(req.args, "filter", filter, false);
    std::string lowFilter = lower(filter);
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(fn && fn->RefreshModuleList)
        fn->RefreshModuleList();
    std::vector<std::pair<unsigned long long, std::string>> mods;
    {
        std::lock_guard<std::mutex> lk(host().mu);
        mods = host().modules;
    }
    std::sort(mods.begin(), mods.end());
    bool ok = false;
    duint mainBase = DbgEval("mod.main()", &ok);
    if(!ok)
        mainBase = 0;
    Json arr = Json::array();
    for(auto & m : mods)
    {
        if(!lowFilter.empty() && lower(m.second).find(lowFilter) == std::string::npos)
            continue;
        duint base = (duint)m.first;
        Json j = Json::object();
        j.set("name", m.second);
        j.set("base", hexAddr(base));
        j.set("size", (unsigned long long)(fn && fn->ModSizeFromAddr ? fn->ModSizeFromAddr(base) : 0));
        char path[MAX_PATH * 2] = "";
        if(fn && fn->ModPathFromAddr)
            fn->ModPathFromAddr(base, path, (int)sizeof(path));
        j.set("path", path);
        char expr[64];
        snprintf(expr, sizeof(expr), "mod.entry(0x%llx)", (unsigned long long)base);
        bool eok = false;
        duint entry = DbgEval(expr, &eok);
        j.set("entry", hexAddr(eok ? entry : 0));
        MODULEPARTY party = fn && fn->ModGetParty ? fn->ModGetParty(base) : mod_user;
        j.set("party", party == mod_system ? "system" : "user");
        MODULESYMBOLSTATUS ss = fn && fn->ModSymbolStatus ? fn->ModSymbolStatus(base) : MODSYMUNLOADED;
        j.set("symbols", ss == MODSYMLOADED ? "loaded" : ss == MODSYMLOADING ? "loading" : "unloaded");
        j.set("is_main", mainBase && base == mainBase);
        arr.push(j);
    }
    Json d = Json::object();
    d.set("modules", arr);
    d.set("count", (long long)arr.items().size());
    res.data = d;
}

namespace
{
struct SymCtx
{
    std::string pattern; // lowercase
    bool glob = false;
    int typeMask = 7;
    std::string module;
    long long skip = 0;
    long long limit = 0;
    Json out = Json::array();
    long long seen = 0;
    bool full = false;
};

bool globMatch(const char* p, const char* s)
{
    // case-folded '*' and '?' wildcards; the whole text must match
    const char* star = nullptr;
    const char* mark = nullptr;
    while(*s)
    {
        if(*p == '*')
        {
            star = p++;
            mark = s;
        }
        else if(*p == '?' || *p == *s)
        {
            p++;
            s++;
        }
        else if(star)
        {
            p = star + 1;
            s = ++mark;
        }
        else
            return false;
    }
    while(*p == '*')
        p++;
    return *p == 0;
}

bool symCallback(const SYMBOLPTR* sp, void* user)
{
    SymCtx* c = (SymCtx*)user;
    if(c->full)
        return false;
    SYMBOLINFOCPP info;
    DbgGetSymbolInfo(sp, &info);
    if(!(c->typeMask & (1 << info.type)))
        return true;
    std::string dec = info.decoratedSymbol ? info.decoratedSymbol : "";
    std::string und = info.undecoratedSymbol ? info.undecoratedSymbol : "";
    if(!c->pattern.empty())
    {
        std::string a = lower(dec), b = lower(und);
        bool hit = c->glob ? (globMatch(c->pattern.c_str(), a.c_str()) || globMatch(c->pattern.c_str(), b.c_str()))
                   : (a.find(c->pattern) != std::string::npos || b.find(c->pattern) != std::string::npos);
        if(!hit)
            return true;
    }
    if(c->seen++ < c->skip)
        return true;
    Json j = Json::object();
    j.set("addr", hexAddr(info.addr));
    j.set("name", und.empty() ? dec : und);
    j.set("decorated", strOrNull(dec));
    j.set("type", info.type == sym_import ? "import" : info.type == sym_export ? "export" : "symbol");
    j.set("module", c->module);
    j.set("ordinal", info.ordinal ? Json((unsigned long long)info.ordinal) : Json());
    c->out.push(j);
    if((long long)c->out.items().size() >= c->limit)
    {
        c->full = true;
        return false;
    }
    return true;
}
}

void viewSym(Session &, Request & req, Result & res)
{
    std::string addrText;
    if(argText(req.args, "addr", addrText, true))
    {
        duint addr = 0;
        if(!evalExpr(res, addrText, "addr", addr))
            return;
        const DBGFUNCTIONS* fn = DbgFunctions();
        Json r = Json::object();
        r.set("addr", hexAddr(addr));
        r.set("label", strOrNull(labelAt(addr)));
        char mod[MAX_MODULE_SIZE] = "";
        bool haveMod = fn && fn->ModNameFromAddr && fn->ModNameFromAddr(addr, mod, true) && mod[0];
        r.set("module", haveMod ? Json(mod) : Json());
        SYMBOLINFOCPP info;
        std::string symbol;
        long long offset = 0;
        if(DbgGetSymbolInfoAt(addr, &info))
        {
            if(info.undecoratedSymbol && info.undecoratedSymbol[0])
                symbol = info.undecoratedSymbol;
            else if(info.decoratedSymbol)
                symbol = info.decoratedSymbol;
            offset = (long long)(addr - info.addr);
        }
        else if(haveMod && fn->ModBaseFromAddr)
            offset = (long long)(addr - fn->ModBaseFromAddr(addr));
        r.set("offset", offset);
        r.set("symbol", strOrNull(symbol));
        Json d = Json::object();
        d.set("resolved", r);
        res.data = d;
        return;
    }
    SymCtx c;
    std::string pat;
    argText(req.args, "pattern", pat, false);
    c.pattern = lower(trim(pat));
    c.glob = c.pattern.find_first_of("*?") != std::string::npos;
    std::string type = "all";
    argText(req.args, "type", type, false);
    type = lower(type);
    if(type == "all")
        c.typeMask = 7;
    else if(type == "import")
        c.typeMask = 1;
    else if(type == "export")
        c.typeMask = 2;
    else if(type == "symbol")
        c.typeMask = 4;
    else
    {
        res.fail("E_BAD_ARG", "type must be all, import, export or symbol");
        return;
    }
    long long limit = 200, offset = 0;
    argInt(req.args, "limit", limit);
    argInt(req.args, "offset", offset);
    if(limit < 1 || limit > 1000000 || offset < 0)
    {
        res.fail("E_BAD_ARG", "limit must be in 1..1000000 and offset >= 0");
        return;
    }
    c.skip = offset;
    c.limit = limit;
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(fn && fn->RefreshModuleList)
        fn->RefreshModuleList();
    std::vector<std::pair<unsigned long long, std::string>> mods;
    {
        std::lock_guard<std::mutex> lk(host().mu);
        mods = host().modules;
    }
    std::string moduleFilter;
    argText(req.args, "module", moduleFilter, false);
    std::string lowModule = lower(trim(moduleFilter));
    bool any = false;
    for(auto & m : mods)
    {
        if(!lowModule.empty())
        {
            std::string n = lower(m.second);
            std::string stem = n.substr(0, n.rfind('.'));
            if(n != lowModule && stem != lowModule)
                continue;
        }
        any = true;
        c.module = m.second;
        DbgSymbolEnum((duint)m.first, symCallback, &c);
        if(c.full)
            break;
    }
    if(!lowModule.empty() && !any)
    {
        res.fail("E_BAD_ARG", "no such module: " + moduleFilter);
        return;
    }
    Json d = Json::object();
    d.set("symbols", c.out);
    d.set("count", (long long)c.out.items().size());
    res.data = d;
}

void viewProcess(Session &, Request &, Result & res)
{
    Host & h = host();
    const DBGFUNCTIONS* fn = DbgFunctions();
    duint pid = DbgGetProcessId();
    std::string path, name;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        if(h.procValid)
        {
            path = h.procPath;
            name = h.procName;
        }
    }
    bool ok = false;
    duint mainBase = DbgEval("mod.main()", &ok);
    if(!ok)
        mainBase = 0;
    if(path.empty() && mainBase && fn && fn->ModPathFromAddr)
    {
        char p[MAX_PATH * 2] = "";
        fn->ModPathFromAddr(mainBase, p, (int)sizeof(p));
        path = p;
    }
    if(name.empty())
    {
        size_t sl = path.find_last_of("\\/");
        name = sl == std::string::npos ? path : path.substr(sl + 1);
    }
    Json d = Json::object();
    d.set("pid", (unsigned long long)pid);
    d.set("path", path);
    d.set("name", name);
    std::string cmdline;
    bool haveCmd = false;
    if(fn && fn->GetCmdline)
    {
        size_t cap = 0;
        fn->GetCmdline(nullptr, &cap);
        if(cap > 0 && cap < (1 << 20))
        {
            std::vector<char> buf(cap + 2, 0);
            size_t n = cap;
            if(fn->GetCmdline(buf.data(), &n))
            {
                cmdline = buf.data();
                haveCmd = true;
            }
        }
    }
    d.set("cmdline", haveCmd ? Json(cmdline) : Json());
    d.set("base", hexAddr(mainBase));
    bool eok = false;
    duint entry = DbgEval("mod.entry(mod.main())", &eok);
    d.set("entry", hexAddr(eok ? entry : 0));
    d.set("peb", hexAddr(DbgGetPebAddress((DWORD)pid)));
    d.set("teb", hexAddr(DbgGetTebAddress((DWORD)activeThreadId())));
    // the debuggee's own elevation: the core does not publish it, so read the token (null when access is denied)
    Json elevated;
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if(proc)
    {
        HANDLE token = nullptr;
        if(OpenProcessToken(proc, TOKEN_QUERY, &token))
        {
            TOKEN_ELEVATION te = {};
            DWORD got = 0;
            if(GetTokenInformation(token, TokenElevation, &te, sizeof(te), &got))
                elevated = Json(te.TokenIsElevated != 0);
            CloseHandle(token);
        }
        CloseHandle(proc);
    }
    d.set("elevated", elevated);
    d.set("debugger_elevated", fn && fn->IsProcessElevated ? fn->IsProcessElevated() : false);
    res.data = d;
}
}
