#include "events.h"
#include "util.h"

#include <algorithm>
#include <cstdlib>
#include <set>

namespace cli
{
unsigned long long parseHexAddr(const std::string & s)
{
    if(s.size() < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
        return 0;
    return strtoull(s.c_str() + 2, nullptr, 16);
}

static bool inSet(const std::set<std::string> & set, const std::string & name)
{
    return set.count(name) != 0;
}

bool isFinisher(const std::string & n)
{
    static const std::set<std::string> s =
    {
        "stepout", "estepout", "runtousercode", "runtoparty", "traceintoconditional", "traceoverconditional",
        "traceintobeyondtracecoverage", "traceoverbeyondtracecoverage", "traceintointotracecoverage", "traceoverintotracecoverage"
    };
    return inSet(s, n);
}

bool isResumeClass(const std::string & n)
{
    static const std::set<std::string> s =
    {
        "run", "erun", "serun", "stepinto", "estepinto", "sestepinto", "stepover", "estepover", "sestepover",
        "stepout", "estepout", "stepuser", "stepsystem", "runtoparty", "runtousercode",
        "traceintoconditional", "traceoverconditional", "traceintobeyondtracecoverage", "traceoverbeyondtracecoverage",
        "traceintointotracecoverage", "traceoverintotracecoverage", "loadlib", "freelib"
    };
    return inSet(s, n);
}

bool isStepGuard(const std::string & n)
{
    static const std::set<std::string> s =
    {
        "stepinto", "estepinto", "sestepinto", "stepover", "estepover", "sestepover", "stepout", "estepout",
        "stepuser", "stepsystem", "skip", "instrundo", "loadlib", "freelib"
    };
    return inSet(s, n);
}

bool isCountForm(const std::string & n)
{
    static const std::set<std::string> s =
    {
        "stepinto", "estepinto", "sestepinto", "stepover", "estepover", "sestepover", "stepout", "estepout"
    };
    return inSet(s, n);
}

static std::string typeOf(const Json & ev)
{
    const Json* t = ev.find("type");
    return t ? t->asString() : std::string();
}

static long long seqOf(const Json & ev)
{
    const Json* t = ev.find("seq");
    return t ? t->asInt() : 0;
}

static std::string strOf(const Json & ev, const char* key)
{
    const Json* t = ev.find(key);
    return t && t->isString() ? t->asString() : std::string();
}

static Json makeStop(const char* reason)
{
    Json s = Json::object();
    s.set("reason", reason);
    return s;
}

bool windowHasCause(const AttribInput & in)
{
    static const std::set<std::string> bookkeeping =
    {
        "pause_requested", "warning", "prompt", "dialog_dismissed", "log_overflow", "late_result", "plugin_widget",
        "trace_file", "table_updated", "events_dropped", "resumed", "paused"
    };
    for(auto & ev : in.window)
    {
        std::string t = typeOf(ev);
        if(bookkeeping.count(t))
            continue;
        if(t == "thread_created" && !in.threadStart)
            continue;
        if(t == "thread_exited" && !in.threadEnd)
            continue;
        if(t == "module_loaded" && !in.dllLoad)
            continue;
        if(t == "module_unloaded" && !in.dllUnload)
            continue;
        if(t == "debug_string" && !in.debugStrings)
            continue;
        return true;
    }
    return false;
}

Json attribute(const AttribInput & in)
{
    static const std::set<std::string> bookkeeping =
    {
        "pause_requested", "warning", "prompt", "dialog_dismissed", "log_overflow", "late_result", "plugin_widget",
        "trace_file", "table_updated", "events_dropped", "resumed", "paused"
    };

    // exception notice inside the window?
    bool noticeInWindow = in.lastExcValid && in.lastExcStamp > in.lastRunningSeq && in.lastExcStamp < in.pausedSeq;

    // step 1: the window without bookkeeping events
    const Json* p = nullptr; // last pause_requested
    std::vector<const Json*> w;
    for(auto & ev : in.window)
    {
        std::string t = typeOf(ev);
        if(t == "pause_requested")
            p = &ev;
        if(bookkeeping.count(t))
            continue;
        if(t == "thread_created" && !in.threadStart)
            continue;
        if(t == "thread_exited" && !in.threadEnd)
            continue;
        if(t == "module_loaded" && !in.dllLoad)
            continue;
        if(t == "module_unloaded" && !in.dllUnload)
            continue;
        if(t == "debug_string" && !in.debugStrings)
            continue;
        w.push_back(&ev);
    }
    const Json* e = w.empty() ? nullptr : w.back();

    // step 1b: drop stale non-breaking hits from the end
    auto guardOk = [&](const Json & ev) -> bool
    {
        if(typeOf(ev) != "breakpoint_hit")
            return true;
        std::string kind = strOf(ev, "bp_type");
        unsigned long long addr = parseHexAddr(strOf(ev, "addr"));
        if(kind == "normal")
            return addr == in.cip;
        if(kind == "exception")
            return noticeInWindow && in.lastExcCode == addr;
        return true;
    };
    size_t keep = w.size();
    while(keep > 0 && typeOf(*w[keep - 1]) == "breakpoint_hit" && !guardOk(*w[keep - 1]))
        keep--;
    const Json* estar = keep ? w[keep - 1] : nullptr;

    // step 1a: trailing cause
    if(!in.trailing.empty())
    {
        const Json & t = in.trailing.front();
        if(typeOf(t) == "exception")
        {
            Json s = makeStop("exception");
            Json ex = Json::object();
            ex.set("code", strOf(t, "code"));
            ex.set("address", strOf(t, "address"));
            s.set("exception", ex);
            return s;
        }
        return makeStop("step");
    }

    // step 2
    if(p && (!estar || seqOf(*p) > seqOf(*estar)))
        return makeStop("pause");

    auto hintOf = [&]() -> Json
    {
        Json h = Json::array();
        for(auto * ev : w)
            h.push(typeOf(*ev));
        return h;
    };

    // step 3
    if(!e)
    {
        Json s = makeStop("unknown");
        const std::string & n = in.lastResumeName;
        // step 5: helper-command refinement
        if(n == "loadlib")
            return makeStop("loadlib");
        if(n == "freelib")
            return makeStop("freelib");
        // step 5b: finisher refinement
        if(isFinisher(n))
        {
            if(n == "stepout" || n == "estepout")
                return makeStop("step");
            if(n == "runtousercode" || n == "runtoparty")
                return makeStop("run_to_user");
            return makeStop("trace_end");
        }
        s.set("hint", hintOf());
        return s;
    }

    // step 4
    std::string t = typeOf(*e);
    Json s;
    if(t == "exception")
    {
        s = makeStop("exception");
        Json ex = Json::object();
        ex.set("code", strOf(*e, "code"));
        ex.set("address", strOf(*e, "address"));
        s.set("exception", ex);
    }
    else if(t == "system_breakpoint")
        s = makeStop("system_breakpoint");
    else if(t == "stepped")
        s = makeStop("step");
    else if(t == "breakpoint_hit")
    {
        if(guardOk(*e))
        {
            s = makeStop("breakpoint");
            s.set("bp", strOf(*e, "addr"));
            if(strOf(*e, "bp_type") == "exception")
            {
                Json ex = Json::object();
                ex.set("code", strOf(*e, "addr"));
                ex.set("address", hexAddr(in.cip));
                s.set("exception", ex);
            }
        }
        else
        {
            s = makeStop("unknown");
            s.set("hint", hintOf());
        }
    }
    else if(t == "module_loaded")
        s = makeStop(in.lastResumeName == "loadlib" ? "loadlib" : "dll_load");
    else if(t == "module_unloaded")
        s = makeStop(in.lastResumeName == "freelib" ? "freelib" : "dll_unload");
    else if(t == "thread_created")
        s = makeStop("thread_start");
    else if(t == "thread_exited")
        s = makeStop("thread_end");
    else if(t == "debug_string")
        s = makeStop("debug_string");
    else
    {
        s = makeStop("unknown");
        s.set("hint", hintOf());
    }
    return s;
}
}
