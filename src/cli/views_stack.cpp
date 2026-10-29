#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "util.h"
#include "views.h"

#include <cstring>

namespace cli
{
void viewStack(Session &, Request & req, Result & res)
{
    long long count = 32;
    argInt(req.args, "count", count);
    if(count < 1 || count > 4096)
    {
        res.fail("E_BAD_ARG", "count must be in 1..4096 (the maximum is 4096)");
        return;
    }
    bool live = isLive();
    duint csp = 0, cbp = 0;
    bool haveCsp = false, haveCbp = false;
    if(!live)
    {
        csp = DbgEval("csp", &haveCsp);
        cbp = DbgEval("cbp", &haveCbp);
    }
    duint base = 0;
    std::string addrText;
    if(argText(req.args, "addr", addrText, true))
    {
        if(!evalExpr(res, addrText, "addr", base))
            return;
    }
    else
    {
        if(!haveCsp)
        {
            res.fail("E_RUNNING", "the stack pointer is unknown while the debuggee runs; pass addr");
            return;
        }
        base = csp;
    }
    duint ref = haveCsp ? csp : base;
    Json rows = Json::array();
    for(long long i = 0; i < count; i++)
    {
        duint slot = base + (duint)(i * (long long)sizeof(duint));
        duint value = 0;
        if(!DbgMemRead(slot, &value, sizeof(value)))
        {
            if(i == 0)
            {
                res.fail("E_MEMORY", "cannot read the stack at " + hexAddr(slot));
                return;
            }
            break;
        }
        Json r = Json::object();
        r.set("addr", hexAddr(slot));
        r.set("offset", (long long)(slot - ref));
        r.set("value", hexAddr(value));
        STACK_COMMENT sc;
        memset(&sc, 0, sizeof(sc));
        r.set("comment", DbgStackCommentGet(slot, &sc) && sc.comment[0] ? Json(sc.comment) : Json());
        r.set("label", strOrNull(labelAt(value)));
        r.set("is_csp", haveCsp && slot == csp);
        r.set("is_cbp", haveCbp && slot == cbp);
        rows.push(r);
    }
    Json d = Json::object();
    d.set("csp", haveCsp ? Json(hexAddr(csp)) : Json());
    d.set("cbp", haveCbp ? Json(hexAddr(cbp)) : Json());
    d.set("live", live);
    d.set("rows", rows);
    res.data = d;
}

void viewCallStack(Session &, Request & req, Result & res)
{
    std::string which = "current";
    argText(req.args, "thread", which, false);
    which = lower(trim(which));
    bool all = which == "all", current = which == "current";
    long long wantTid = 0;
    if(!all && !current && !parseInteger(which, wantTid))
    {
        res.fail("E_BAD_ARG", "thread must be \"current\", \"all\" or a thread id");
        return;
    }
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn || !fn->GetCallStackByThread)
    {
        res.fail("E_UNSUPPORTED", "this core has no call stack API");
        return;
    }
    THREADLIST list;
    memset(&list, 0, sizeof(list));
    DbgGetThreadList(&list);
    BridgeBuf<THREADALLINFO> guard;
    guard.p = list.list;
    Json threads = Json::array();
    bool found = false;
    for(int i = 0; i < list.count; i++)
    {
        const THREADALLINFO & t = list.list[i];
        bool pick = all || (current && i == list.CurrentThread) || (!all && !current && t.BasicInfo.ThreadId == (DWORD)wantTid);
        if(!pick)
            continue;
        found = true;
        DBGCALLSTACK cs;
        memset(&cs, 0, sizeof(cs));
        fn->GetCallStackByThread(t.BasicInfo.Handle, &cs);
        BridgeBuf<DBGCALLSTACKENTRY> eg;
        if(cs.total > 0)
            eg.p = cs.entries;
        Json frames = Json::array();
        for(int k = 0; k < cs.total; k++)
        {
            const DBGCALLSTACKENTRY & e = cs.entries[k];
            Json f = Json::object();
            f.set("index", k);
            f.set("addr", hexAddr(e.addr));
            f.set("from", hexAddr(e.from));
            f.set("to", hexAddr(e.to));
            f.set("comment", e.comment);
            duint modBase = fn->ModBaseFromAddr ? fn->ModBaseFromAddr(e.to) : 0;
            MODULEPARTY party = fn->ModGetParty ? fn->ModGetParty(modBase) : mod_user;
            f.set("party", party == mod_system ? "system" : "user");
            f.set("from_label", e.from ? strOrNull(labelAt(e.from)) : Json());
            f.set("to_label", strOrNull(labelAt(e.to)));
            frames.push(f);
        }
        Json th = Json::object();
        th.set("tid", (unsigned long long)t.BasicInfo.ThreadId);
        th.set("frames", frames);
        threads.push(th);
    }
    if(!found)
    {
        res.fail("E_BAD_ARG", "no such thread: " + which);
        return;
    }
    Json d = Json::object();
    d.set("threads", threads);
    res.data = d;
}
}
