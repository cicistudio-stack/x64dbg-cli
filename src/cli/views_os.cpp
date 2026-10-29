#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "util.h"
#include "views.h"

#include <cstring>

namespace cli
{
void viewSeh(Session &, Request &, Result & res)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn || !fn->GetSEHChain)
    {
        res.fail("E_UNSUPPORTED", "this core has no SEH chain API");
        return;
    }
    DBGSEHCHAIN chain;
    memset(&chain, 0, sizeof(chain));
    fn->GetSEHChain(&chain);
    BridgeBuf<DBGSEHRECORD> guard;
    if(chain.total > 0)
        guard.p = chain.records;
    Json list = Json::array();
    for(duint i = 0; i < chain.total && chain.records; i++)
    {
        Json r = Json::object();
        r.set("addr", hexAddr(chain.records[i].addr));
        r.set("handler", hexAddr(chain.records[i].handler));
        r.set("handler_label", strOrNull(labelAt(chain.records[i].handler)));
        list.push(r);
    }
    Json d = Json::object();
    d.set("chain", list);
    res.data = d;
}

void viewHandles(Session &, Request & req, Result & res)
{
    long long limit, offset;
    if(!listWindow(req, res, limit, offset))
        return;
    const DBGFUNCTIONS* fn = DbgFunctions();
    BridgeList<HANDLEINFO> handles;
    if(!fn || !fn->EnumHandles || !fn->EnumHandles(&handles))
    {
        res.fail("E_COMMAND_FAILED", "the handle list is not available");
        return;
    }
    Json list = Json::array();
    int total = handles.Count();
    for(int i = (int)offset; i < total && (long long)list.items().size() < limit; i++)
    {
        const HANDLEINFO & h = handles[i];
        char name[MAX_STRING_SIZE] = "";
        char type[MAX_STRING_SIZE] = "";
        bool haveName = fn->GetHandleName && fn->GetHandleName(h.Handle, name, sizeof(name), type, sizeof(type));
        Json j = Json::object();
        j.set("handle", hexAddr(h.Handle));
        j.set("type", type);
        j.set("type_number", (long long)h.TypeNumber);
        j.set("name", haveName && name[0] ? Json(name) : Json());
        j.set("access", hexN(h.GrantedAccess, 8));
        list.push(j);
    }
    Json d = Json::object();
    d.set("handles", list);
    d.set("count", (long long)list.items().size());
    res.data = d;
}

void viewWindows(Session &, Request & req, Result & res)
{
    long long limit, offset;
    if(!listWindow(req, res, limit, offset))
        return;
    const DBGFUNCTIONS* fn = DbgFunctions();
    BridgeList<WINDOW_INFO> windows;
    if(!fn || !fn->EnumWindows || !fn->EnumWindows(&windows))
    {
        res.fail("E_COMMAND_FAILED", "the window list is not available");
        return;
    }
    Json list = Json::array();
    int total = windows.Count();
    for(int i = (int)offset; i < total && (long long)list.items().size() < limit; i++)
    {
        const WINDOW_INFO & w = windows[i];
        char tname[MAX_THREAD_NAME_SIZE] = "";
        bool haveName = fn->ThreadGetName && fn->ThreadGetName(w.threadId, tname) && tname[0];
        Json j = Json::object();
        j.set("handle", hexAddr(w.handle));
        j.set("parent", hexAddr(w.parent));
        j.set("tid", (unsigned long long)w.threadId);
        j.set("thread_name", haveName ? Json(tname) : Json());
        j.set("style", hexN(w.style, 8));
        j.set("style_ex", hexN(w.styleEx, 8));
        j.set("wndproc", hexAddr(w.wndProc));
        j.set("enabled", w.enabled);
        Json rect = Json::object();
        rect.set("left", (long long)w.position.left);
        rect.set("top", (long long)w.position.top);
        rect.set("right", (long long)w.position.right);
        rect.set("bottom", (long long)w.position.bottom);
        j.set("rect", rect);
        j.set("title", w.windowTitle);
        j.set("class", w.windowClass);
        list.push(j);
    }
    Json d = Json::object();
    d.set("windows", list);
    d.set("count", (long long)list.items().size());
    res.data = d;
}

void viewTcp(Session &, Request &, Result & res)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    BridgeList<TCPCONNECTIONINFO> conns;
    Json list = Json::array();
    // like the GUI: a failing enumeration is an empty table
    if(fn && fn->EnumTcpConnections && fn->EnumTcpConnections(&conns))
    {
        for(int i = 0; i < conns.Count(); i++)
        {
            const TCPCONNECTIONINFO & c = conns[i];
            Json j = Json::object();
            j.set("local", c.LocalAddress);
            j.set("local_port", (long long)c.LocalPort);
            j.set("remote", c.RemoteAddress);
            j.set("remote_port", (long long)c.RemotePort);
            j.set("state", c.StateText);
            list.push(j);
        }
    }
    Json d = Json::object();
    d.set("connections", list);
    d.set("count", (long long)list.items().size());
    res.data = d;
}

void viewHeaps(Session &, Request &, Result & res)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    BridgeList<HEAPINFO> heaps;
    Json list = Json::array();
    // HandlesEnumHeaps is a stub in this core (the Toolhelp implementation is commented out), so the GUI's Heaps tab is empty too
    if(!fn || !fn->EnumHeaps || !fn->EnumHeaps(&heaps))
        res.warnings.push_back("heaps_not_enumerated_by_core");
    else
    {
        for(int i = 0; i < heaps.Count(); i++)
        {
            const HEAPINFO & h = heaps[i];
            Json j = Json::object();
            j.set("addr", hexAddr(h.addr));
            j.set("size", (unsigned long long)h.size);
            j.set("flags", hexN(h.flags, 8));
            list.push(j);
        }
    }
    Json d = Json::object();
    d.set("heaps", list);
    d.set("count", (long long)list.items().size());
    res.data = d;
}

// The fixed list of HandlesView.cpp (PrivilegeString).
static const char* const kPrivileges[] =
{
    "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege",
    "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
    "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege",
    "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
    "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
    "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege",
    "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
    "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
    "SeUndockPrivilege", "SeUnsolicitedInputPrivilege"
};

void viewPrivileges(Session &, Request &, Result & res)
{
    Json list = Json::array();
    for(const char* name : kPrivileges)
    {
        // exactly what the GUI does: the native command sets $result (0 absent, 1 disabled, 2 and 3 enabled)
        std::string line = std::string(" GetPrivilegeState \"") + name + "\"";
        DbgCmdExecDirect(line.c_str());
        bool ok = false;
        duint v = DbgEval("$result", &ok);
        Json j = Json::object();
        j.set("name", name);
        j.set("state", !ok ? "unknown" : v == 1 ? "disabled" : (v == 2 || v == 3) ? "enabled" : "unknown");
        list.push(j);
    }
    Json d = Json::object();
    d.set("privileges", list);
    res.data = d;
}

void viewPs(Session &, Request &, Result & res)
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    DBGPROCESSINFO* entries = nullptr;
    int count = 0;
    if(!fn || !fn->GetProcessList || !fn->GetProcessList(&entries, &count))
    {
        res.fail("E_COMMAND_FAILED", "the process list is not available");
        return;
    }
    Json list = Json::array();
    for(int i = 0; i < count && entries; i++)
    {
        Json j = Json::object();
        j.set("pid", (unsigned long long)entries[i].dwProcessId);
        j.set("exe", entries[i].szExeFile);
        j.set("title", entries[i].szExeMainWindowTitle);
        j.set("args", entries[i].szExeArgs);
        list.push(j);
    }
    if(entries)
        BridgeFree(entries);
    Json d = Json::object();
    d.set("processes", list);
    d.set("count", (long long)list.items().size());
    res.data = d;
}
}
