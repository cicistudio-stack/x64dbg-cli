#include "protocol.h"
#include "util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <set>

namespace cli
{
const std::vector<OpSpec> & allOps()
{
    static const std::vector<OpSpec> ops =
    {
        { "status", "M1", "any", "status", {}, "", false, true },
        { "help", "M1", "any", "help [topic]", { { "topic", 's' } }, "topic", false, false },
        { "commands", "M1", "any", "commands [prefix]", { { "prefix", 's' } }, "prefix", false, false },
        { "wait", "M1", "any", "wait   (use the request field timeout_ms)", {}, "", false, false },
        { "interrupt", "M1", "any", "interrupt", {}, "", false, true },
        { "quit", "M1", "any", "quit [--detach]", { { "detach", 'b' } }, "", false, true },
        { "log", "M1", "any", "log [--from n] [--tail n] [--clear]", { { "from", 'i' }, { "tail", 'i' }, { "clear", 'b' } }, "", false, false },
        { "events", "M1", "any", "events [--since seq] [--limit n]", { { "since", 'i' }, { "limit", 'i' } }, "since", false, false },
        { "eval", "M1", "any", "eval <expression>", { { "expr", 's' } }, "expr", true, false },
        { "table", "M1", "any", "table [--id n] [--offset n] [--limit n]", { { "id", 'i' }, { "offset", 'i' }, { "limit", 'i' } }, "id", false, false },
        { "native", "M1", "any", "native [--timeout_ms n] [--wait m] [--on_timeout m] ... -- <native line>", { { "cmd", 's' } }, "", false, false },
        // ---- M2: structured views
        { "process", "M2", "debugging", "process", {}, "", false, false },
        {
            "regs", "M2", "paused", "regs [groups]   (groups: gpr,flags,seg,dbg,fpu,mmx,xmm,ymm,zmm,opmask,all; default gpr,flags,seg)",
            { { "groups", 's' } }, "groups", false, false
        },
        { "setreg", "M2", "paused", "setreg <reg> <value>", { { "reg", 's' }, { "value", 's' } }, "reg,value", false, false },
        {
            "dis", "M2", "debugging", "dis [addr] [-n count] [--until addr] [--back n] [--bytes true|false]",
            { { "addr", 'a' }, { "count", 'i' }, { "until", 'a' }, { "back", 'i' }, { "bytes", 'b' } }, "addr", false, false, "count"
        },
        {
            "mem", "M2", "debugging", "mem <addr> [-n size] [--format hex|ascii|utf16|int8..uint64|hex8..hex64|float|double|half|ldouble|ptr] [--cols n]",
            { { "addr", 'a' }, { "size", 'i' }, { "format", 's' }, { "cols", 'i' } }, "addr", false, false, "size"
        },
        {
            "memwrite", "M2", "debugging", "memwrite <addr> (--hex h | --ascii s | --utf16 s | --file path) [--patch true|false]",
            { { "addr", 'a' }, { "hex", 's' }, { "ascii", 's' }, { "utf16", 's' }, { "file", 's' }, { "patch", 'b' } }, "addr", false, false
        },
        { "memmap", "M2", "debugging", "memmap [filter]", { { "filter", 's' } }, "filter", false, false },
        {
            "stack", "M2", "paused", "stack [addr] [-n count]   (with an addr the debuggee may be running)",
            { { "addr", 'a' }, { "count", 'i' } }, "addr", false, false, "count"
        },
        { "callstack", "M2", "paused", "callstack [current|<tid>|all]", { { "thread", 'x' } }, "thread", false, false },
        { "bps", "M2", "any", "bps [all|sw|hw|mem|dll|exception]", { { "kind", 's' } }, "kind", false, false },
        {
            "bp", "M2", "debugging", "bp <add|delete|enable|disable|reset_hits> [target|id] [--kind k] [--once] [--name n] [--condition e] [--log t] ...",
            {
                { "action", 's' }, { "id", 's' }, { "kind", 's' }, { "target", 's' }, { "all", 'b' }, { "once", 'b' }, { "name", 's' },
                { "condition", 's' }, { "log", 's' }, { "log_condition", 's' }, { "command", 's' }, { "command_condition", 's' },
                { "silent", 'b' }, { "fast_resume", 'b' }, { "hw_type", 's' }, { "size", 'i' }, { "mem_type", 's' }, { "restore", 'b' },
                { "dll_event", 's' }, { "chance", 's' }
            }, "action,target", false, false
        },
        { "threads", "M2", "debugging", "threads", {}, "", false, false },
        {
            "thread", "M2", "debugging", "thread <switch|suspend|resume|suspend_all|resume_all|kill|name|priority|create> [tid] [--value v]",
            { { "action", 's' }, { "tid", 'i' }, { "value", 's' } }, "action,tid", false, false
        },
        { "modules", "M2", "debugging", "modules [filter]", { { "filter", 's' } }, "filter", false, false },
        {
            "sym", "M2", "debugging", "sym [pattern] [--module m] [--type all|import|export|symbol] [--addr a] [--limit n] [--offset n]",
            { { "pattern", 's' }, { "module", 's' }, { "type", 's' }, { "addr", 'a' }, { "limit", 'i' }, { "offset", 'i' } }, "pattern", false, false
        },
        // ---- M2: run-control wrappers
        { "init", "M2", "any", "init <file> [--args text] [--cwd dir]", { { "file", 's' }, { "args", 's' }, { "cwd", 's' } }, "file", false, false },
        { "run", "M2", "any", "run", {}, "", false, false },
        { "stepin", "M2", "any", "stepin [count]", { { "count", 'i' } }, "count", false, false },
        { "stepover", "M2", "any", "stepover [count]", { { "count", 'i' } }, "count", false, false },
        { "stepout", "M2", "any", "stepout [count]", { { "count", 'i' } }, "count", false, false },
        { "runto", "M2", "any", "runto <addr>", { { "addr", 'a' } }, "addr", false, false },
        { "pause", "M2", "any", "pause", {}, "", false, true },
        { "stop", "M2", "any", "stop", {}, "", false, true },
        { "restart", "M2", "any", "restart", {}, "", false, false },
        { "attach", "M2", "any", "attach <pid> [--pause]", { { "pid", 'i' }, { "pause", 'b' } }, "pid", false, false },
        { "detach", "M2", "any", "detach", {}, "", false, false },
        { "skip", "M2", "any", "skip [count]", { { "count", 'i' } }, "count", false, false },
        // ---- M3: remaining GUI-parity views
        { "seh", "M3", "paused", "seh", {}, "", false, false },
        { "handles", "M3", "debugging", "handles [--limit n] [--offset n]", { { "limit", 'i' }, { "offset", 'i' } }, "", false, false },
        { "windows", "M3", "debugging", "windows [--limit n] [--offset n]", { { "limit", 'i' }, { "offset", 'i' } }, "", false, false },
        { "tcp", "M3", "debugging", "tcp", {}, "", false, false },
        { "heaps", "M3", "debugging", "heaps", {}, "", false, false },
        { "privileges", "M3", "debugging", "privileges", {}, "", false, false },
        { "ps", "M3", "any", "ps", {}, "", false, false },
        { "labels", "M3", "debugging", "labels   (table of the native labellist)", {}, "", false, false },
        { "comments", "M3", "debugging", "comments   (table of the native commentlist)", {}, "", false, false },
        { "bookmarks", "M3", "debugging", "bookmarks   (table of the native bookmarklist)", {}, "", false, false },
        { "functions", "M3", "debugging", "functions   (table of the native functionlist)", {}, "", false, false },
        { "arguments", "M3", "debugging", "arguments   (table of the native argumentlist)", {}, "", false, false },
        { "loops", "M3", "debugging", "loops   (table of the native looplist)", {}, "", false, false },
        { "addrinfo", "M3", "debugging", "addrinfo <addr>", { { "addr", 'a' } }, "addr", false, false },
        { "xrefs", "M3", "debugging", "xrefs <addr>", { { "addr", 'a' } }, "addr", false, false },
        { "patches", "M3", "debugging", "patches", {}, "", false, false },
        {
            "patch", "M3", "debugging", "patch <export|restore|restore_range> [file] [--addr a] [--end a] [--module m]",
            { { "action", 's' }, { "file", 's' }, { "addr", 'a' }, { "end", 'a' }, { "module", 's' } }, "action,file", false, false
        },
        { "strings", "M3", "debugging", "strings [addr [size]]   (native strref)", { { "addr", 'a' }, { "size", 'a' } }, "addr,size", false, false },
        { "calls", "M3", "debugging", "calls [addr [size]]   (native modcallfind)", { { "addr", 'a' }, { "size", 'a' } }, "addr,size", false, false },
        { "ptrs", "M3", "debugging", "ptrs [addr [size]]   (native reffunctionpointer)", { { "addr", 'a' }, { "size", 'a' } }, "addr,size", false, false },
        { "watch", "M3", "debugging", "watch", {}, "", false, false },
        {
            "trace", "M3", "debugging", "trace <info|set_type|reset|disable|start|stop> [addr] [--type bit|byte|word] [--file path]",
            { { "action", 's' }, { "addr", 'a' }, { "type", 's' }, { "file", 's' } }, "action,addr", false, false
        },
        {
            "script", "M3", "any", "script <load|unload|run|step|abort|state|lines|bp_toggle|bp_get|set_ip|exec|cmd> [file] [--line n] [--command c]",
            { { "action", 's' }, { "file", 's' }, { "line", 'i' }, { "command", 's' } }, "action,file", false, false
        },
        { "types", "M3", "any", "types", {}, "", false, false },
        { "struct", "M3", "debugging", "struct <type> <addr>", { { "type", 's' }, { "addr", 'a' } }, "type,addr", false, false },
        { "cfg", "M3", "debugging", "cfg [entry]", { { "entry", 'a' } }, "entry", false, false },
        {
            "notes", "M3", "any", "notes [get|set] [global|debuggee] [text]",
            { { "action", 's' }, { "scope", 's' }, { "text", 's' } }, "action,scope,text", false, false
        },
        {
            "source", "M3", "debugging", "source [addr] [--file f --line n] [--context n]",
            { { "addr", 'a' }, { "file", 's' }, { "line", 'i' }, { "context", 'i' } }, "addr", false, false
        },
        { "nav", "M3", "any", "nav", {}, "", false, false },
        {
            "callargs", "M3", "paused", "callargs [count] [--convention auto|x64]",
            { { "count", 'i' }, { "convention", 's' } }, "count", false, false
        },
        { "locals", "M3", "paused", "locals [base]", { { "base", 's' } }, "base", false, false },
        { "infobox", "M3", "debugging", "infobox [addr]", { { "addr", 'a' } }, "addr", false, false },
        { "menu", "M3", "any", "menu [list|click] [id]", { { "action", 's' }, { "id", 'i' } }, "action,id", false, false },
        {
            "config", "M3", "any", "config <get|set|init_script> [section] [key] [value]",
            { { "action", 's' }, { "section", 's' }, { "key", 's' }, { "value", 's' } }, "action,section,key,value", false, false
        },
        { "constants", "M3", "any", "constants", {}, "", false, false },
        { "errors", "M3", "any", "errors", {}, "", false, false },
        { "exceptions", "M3", "any", "exceptions", {}, "", false, false },
        { "format", "M3", "any", "format <template>   (for example: format rax={rax})", { { "template", 's' } }, "template", true, false },
        {
            "asm", "M3", "debugging", "asm <addr> <instruction> [--fill_nops true|false]",
            { { "addr", 'a' }, { "text", 's' }, { "fill_nops", 'b' } }, "addr,text", false, false
        },
        { "animate", "M3", "paused", "animate <command>   (for example: animate StepInto)", { { "command", 's' } }, "command", true, false },
        { "favourites", "M3", "any", "favourites", {}, "", false, false },
        {
            "module", "M3", "debugging", "module <set_party|loadlib|freelib|symdownload|symload|symunload> [module] [--path p] [--party user|system]",
            { { "action", 's' }, { "module", 'x' }, { "path", 's' }, { "party", 's' } }, "action,module", false, false
        },
    };
    return ops;
}

const OpSpec* findOp(const std::string & name)
{
    for(auto & o : allOps())
        if(name == o.name)
            return &o;
    return nullptr;
}

static int editDistance(const std::string & a, const std::string & b)
{
    std::vector<int> prev(b.size() + 1), cur(b.size() + 1);
    for(size_t j = 0; j <= b.size(); j++)
        prev[j] = (int)j;
    for(size_t i = 1; i <= a.size(); i++)
    {
        cur[0] = (int)i;
        for(size_t j = 1; j <= b.size(); j++)
            cur[j] = std::min({ prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] != b[j - 1]) });
        prev.swap(cur);
    }
    return prev[b.size()];
}

static Json suggestOps(const std::string & name)
{
    Json arr = Json::array();
    std::string n = lower(name);
    for(auto & o : allOps())
    {
        std::string on = o.name;
        if(editDistance(n, on) <= 2 || on.find(n) != std::string::npos || (n.size() >= 2 && on.compare(0, 2, n, 0, 2) == 0))
            arr.push(on);
    }
    return arr;
}

Json makeErrorObject(const std::string & code, const std::string & message, const Json & detail)
{
    Json e = Json::object();
    e.set("code", code);
    e.set("message", message);
    e.set("detail", detail);
    return e;
}

bool isOptionKey(const std::string & key)
{
    static const std::set<std::string> keys =
    {
        "timeout_ms", "wait", "on_timeout", "max_output", "max_response_bytes", "max_rows", "max_events",
        "settle_ms", "pause_settle_ms", "vars", "stop_on_error"
    };
    return keys.count(key) != 0;
}

static bool intField(const Json & v, long long lo, long long hi, const char* name, long long & out, std::string & msg)
{
    if(!v.isInt() || v.asInt() < lo || v.asInt() > hi)
    {
        msg = std::string(name) + " must be an integer in " + std::to_string(lo) + ".." + std::to_string(hi);
        return false;
    }
    out = v.asInt();
    return true;
}

static bool validVarName(const std::string & s)
{
    if(s.size() < 2 || s[0] != '$')
        return false;
    if(!(isalpha((unsigned char)s[1]) || s[1] == '_'))
        return false;
    for(size_t i = 2; i < s.size(); i++)
        if(!(isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '.'))
            return false;
    return true;
}

bool applyOption(ReqOptions & o, const std::string & key, const Json & v, std::string & msg)
{
    if(key == "timeout_ms")
        return intField(v, 0, 3600000, "timeout_ms", o.timeoutMs, msg);
    if(key == "settle_ms")
        return intField(v, 0, 60000, "settle_ms", o.settleMs, msg);
    if(key == "pause_settle_ms")
        return intField(v, 100, 60000, "pause_settle_ms", o.pauseSettleMs, msg);
    if(key == "max_output")
        return intField(v, 1024, 16777216, "max_output", o.maxOutput, msg);
    if(key == "max_events")
        return intField(v, 0, 100000, "max_events", o.maxEvents, msg);
    if(key == "max_rows")
        return intField(v, 1, 1000000, "max_rows", o.maxRows, msg);
    if(key == "max_response_bytes")
        return intField(v, 65536, 33554432, "max_response_bytes", o.maxResponseBytes, msg);
    if(key == "wait")
    {
        if(!v.isString() || (v.asString() != "auto" && v.asString() != "never" && v.asString() != "always"))
        {
            msg = "wait must be \"auto\", \"never\" or \"always\"";
            return false;
        }
        o.wait = v.asString();
        return true;
    }
    if(key == "on_timeout")
    {
        if(!v.isString() || (v.asString() != "keep" && v.asString() != "pause" && v.asString() != "stop"))
        {
            msg = "on_timeout must be \"keep\", \"pause\" or \"stop\"";
            return false;
        }
        o.onTimeout = v.asString();
        return true;
    }
    if(key == "stop_on_error")
    {
        if(!v.isBool())
        {
            msg = "stop_on_error must be a boolean";
            return false;
        }
        o.stopOnError = v.asBool();
        return true;
    }
    if(key == "vars")
    {
        if(!v.isArray() || v.items().size() > 16)
        {
            msg = "vars must be an array of at most 16 variable names";
            return false;
        }
        std::vector<std::string> list;
        for(auto & it : v.items())
        {
            if(!it.isString() || !validVarName(it.asString()))
            {
                msg = "vars entries must start with '$' (for example \"$result\")";
                return false;
            }
            list.push_back(it.asString());
        }
        o.vars = list;
        return true;
    }
    msg = "unknown request option " + key;
    return false;
}

// Converts the text of an option value into the Json the validator expects.
static bool optionFromText(const std::string & key, const std::string & text, Json & out, std::string & msg)
{
    if(key == "wait" || key == "on_timeout")
    {
        out = Json(text);
        return true;
    }
    if(key == "vars")
    {
        Json arr = Json::array();
        size_t pos = 0;
        while(pos <= text.size())
        {
            size_t c = text.find(',', pos);
            std::string n = trim(text.substr(pos, c == std::string::npos ? std::string::npos : c - pos));
            if(!n.empty())
                arr.push(n);
            if(c == std::string::npos)
                break;
            pos = c + 1;
        }
        out = arr;
        return true;
    }
    long long n;
    if(!parseInteger(text, n))
    {
        msg = key + " expects an integer, got '" + text + "'";
        return false;
    }
    out = Json(n);
    return true;
}

static void finishEcho(Request & r, const Json & argsOrNull)
{
    r.echo = Json::object();
    if(r.isOp)
    {
        r.echo.set("op", r.op);
        if(argsOrNull.isObject())
            r.echo.set("args", argsOrNull);
    }
    else
        r.echo.set("cmd", r.cmd);
}

static bool validateArgs(const OpSpec & spec, const Json & args, std::string & msg)
{
    for(auto & m : args.members())
    {
        if(isOptionKey(m.first))
        {
            msg = "request option '" + m.first + "' is a top-level field, not an argument";
            return false;
        }
        const ArgSpec* found = nullptr;
        for(auto & a : spec.args)
            if(m.first == a.name)
                found = &a;
        if(!found)
        {
            msg = "unknown argument '" + m.first + "' for op " + spec.name + " (usage: " + spec.usage + ")";
            return false;
        }
        bool ok = (found->type == 'i' && m.second.isInt()) || (found->type == 's' && m.second.isString()) ||
                  (found->type == 'b' && m.second.isBool()) ||
                  (found->type == 'a' && (m.second.isString() || (m.second.isInt() && m.second.asInt() >= 0 && m.second.asInt() <= (1LL << 53)))) ||
                  (found->type == 'x' && (m.second.isString() || m.second.isInt()));
        if(!ok)
        {
            msg = "argument '" + m.first + "' has the wrong type";
            return false;
        }
    }
    return true;
}

bool parseJsonRequest(const std::string & line, RequestPtr & out, ParseError & err)
{
    Json j;
    std::string perr;
    if(!Json::parse(line, j, perr))
    {
        err.code = "E_PARSE";
        err.message = "invalid JSON: " + perr;
        return false;
    }
    if(!j.isObject())
    {
        err.code = "E_PARSE";
        err.message = "request must be a JSON object";
        return false;
    }
    auto req = std::make_shared<Request>();
    const Json* id = j.find("id");
    if(id && !id->isNull())
    {
        if(id->isInt() || (id->isString() && id->asString().size() <= 128))
        {
            req->id = *id;
            err.id = *id;
        }
        else
        {
            err.code = "E_PARSE";
            err.message = "id must be a string (<= 128 characters) or an integer";
            return false;
        }
    }
    static const std::set<std::string> known = { "id", "cmd", "op", "args", "batch" };
    for(auto & m : j.members())
    {
        if(!known.count(m.first) && !isOptionKey(m.first))
        {
            err.code = "E_BAD_ARG";
            err.message = "unknown request field '" + m.first + "'";
            return false;
        }
    }
    int kinds = (j.find("cmd") ? 1 : 0) + (j.find("op") ? 1 : 0) + (j.find("batch") ? 1 : 0);
    if(kinds != 1)
    {
        err.code = "E_PARSE";
        err.message = "exactly one of cmd, op, batch is required";
        return false;
    }
    for(auto & m : j.members())
    {
        if(isOptionKey(m.first))
        {
            std::string msg;
            if(!applyOption(req->opt, m.first, m.second, msg))
            {
                err.code = "E_BAD_ARG";
                err.message = msg;
                return false;
            }
        }
    }
    if(const Json* c = j.find("cmd"))
    {
        if(!c->isString() || trim(c->asString()).empty())
        {
            err.code = "E_BAD_ARG";
            err.message = "cmd must be a non-empty string";
            return false;
        }
        req->cmd = c->asString();
        finishEcho(*req, Json());
    }
    else if(const Json* b = j.find("batch"))
    {
        if(!b->isArray() || b->items().empty() || b->items().size() > 256)
        {
            err.code = "E_BAD_ARG";
            err.message = "batch must be an array of 1..256 requests";
            return false;
        }
        req->isBatch = true;
        req->raw = j;
        req->echo = Json::object();
    }
    else
    {
        const Json* o = j.find("op");
        if(!o->isString())
        {
            err.code = "E_BAD_ARG";
            err.message = "op must be a string";
            return false;
        }
        const OpSpec* spec = findOp(o->asString());
        if(!spec)
        {
            err.code = "E_UNKNOWN_OP";
            err.message = "unknown op '" + o->asString() + "'";
            Json d = Json::object();
            d.set("suggest", suggestOps(o->asString()));
            err.detail = d;
            return false;
        }
        const Json* a = j.find("args");
        Json args = Json::object();
        if(a)
        {
            if(!a->isObject())
            {
                err.code = "E_BAD_ARG";
                err.message = "args must be an object";
                return false;
            }
            args = *a;
        }
        std::string msg;
        if(!validateArgs(*spec, args, msg))
        {
            err.code = "E_BAD_ARG";
            err.message = msg;
            return false;
        }
        req->isOp = true;
        req->op = spec->name;
        req->args = args;
        if(req->op == "native")
        {
            const Json* c = args.find("cmd");
            if(!c || trim(c->asString()).empty())
            {
                err.code = "E_BAD_ARG";
                err.message = "native requires args.cmd";
                return false;
            }
            req->cmd = c->asString();
        }
        finishEcho(*req, a ? args : Json());
    }
    out = req;
    return true;
}

bool parseNativeBang(const std::string & rest, Request & req, std::string & message)
{
    size_t i = 0;
    auto skipWs = [&]()
    {
        while(i < rest.size() && (rest[i] == ' ' || rest[i] == '\t'))
            i++;
    };
    auto token = [&]() -> std::string
    {
        skipWs();
        size_t b = i;
        while(i < rest.size() && rest[i] != ' ' && rest[i] != '\t')
            i++;
        return rest.substr(b, i - b);
    };
    bool sawSeparator = false;
    while(true)
    {
        std::string t = token();
        if(t.empty())
            break;
        if(t == "--")
        {
            sawSeparator = true;
            if(i < rest.size())
                i++; // exactly one separator character
            break;
        }
        if(t.size() < 3 || t[0] != '-' || t[1] != '-')
        {
            message = "expected --key value pairs before '--', got '" + t + "'";
            return false;
        }
        std::string key = t.substr(2);
        if(!isOptionKey(key))
        {
            message = "unknown option --" + key;
            return false;
        }
        Json value;
        if(key == "stop_on_error")
            value = Json(true);
        else
        {
            std::string v = token();
            if(v.empty())
            {
                message = "option --" + key + " needs a value";
                return false;
            }
            if(!optionFromText(key, v, value, message))
                return false;
        }
        if(!applyOption(req.opt, key, value, message))
            return false;
    }
    if(!sawSeparator)
    {
        message = "missing -- separator (usage: !native [--timeout_ms n] ... -- <native line>)";
        return false;
    }
    std::string tail = rest.substr(std::min(i, rest.size()));
    if(trim(tail).empty())
    {
        message = "empty native line after --";
        return false;
    }
    req.cmd = tail;
    return true;
}

bool parseTextLine(const std::string & rawLine, const std::string & idString, RequestPtr & out, ParseError & err, bool & skip)
{
    skip = false;
    std::string line = trim(rawLine);
    if(line.empty() || line[0] == '#')
    {
        skip = true;
        return true;
    }
    auto req = std::make_shared<Request>();
    req->textId = idString;
    req->id = Json(idString);
    if(startsWith(line, "!!"))
    {
        req->cmd = line.substr(1);
        finishEcho(*req, Json());
        out = req;
        return true;
    }
    if(line[0] != '!')
    {
        req->cmd = line;
        finishEcho(*req, Json());
        out = req;
        return true;
    }
    // op line
    size_t sp = line.find_first_of(" \t");
    std::string name = line.substr(1, sp == std::string::npos ? std::string::npos : sp - 1);
    std::string rest = sp == std::string::npos ? std::string() : line.substr(sp + 1);
    const OpSpec* spec = findOp(lower(name));
    if(!spec)
    {
        err.code = "E_UNKNOWN_OP";
        err.message = "unknown op '" + name + "'; to run a native line that starts with '!' use '!!'";
        Json d = Json::object();
        d.set("suggest", suggestOps(name));
        err.detail = d;
        return false;
    }
    req->isOp = true;
    req->op = spec->name;
    if(req->op == "native")
    {
        std::string msg;
        if(!parseNativeBang(rest, *req, msg))
        {
            err.code = "E_BAD_ARG";
            err.message = msg;
            return false;
        }
        Json a = Json::object();
        a.set("cmd", req->cmd);
        req->args = a;
        finishEcho(*req, a);
        out = req;
        return true;
    }
    Json args = Json::object();
    std::string restTrim = trim(rest);
    if(spec->restOfLine && spec->positional[0] && !restTrim.empty() && !startsWith(restTrim, "--"))
    {
        args.set(spec->positional, restTrim);
    }
    else
    {
        std::vector<std::string> toks;
        std::string terr;
        if(!tokenize(rest, toks, terr))
        {
            err.code = "E_BAD_ARG";
            err.message = terr;
            return false;
        }
        std::vector<std::string> positional;
        for(size_t i = 0; i < toks.size(); i++)
        {
            const std::string & t = toks[i];
            bool isOpt = (t.size() > 2 && t[0] == '-' && t[1] == '-') || (t.size() == 2 && t[0] == '-' && isalpha((unsigned char)t[1]));
            if(!isOpt)
            {
                positional.push_back(t);
                continue;
            }
            std::string key = t[1] == '-' ? t.substr(2) : t.substr(1);
            if(t[1] != '-' && key == "n" && spec->nShort[0])
                key = spec->nShort;
            if(isOptionKey(key))
            {
                Json value;
                std::string msg;
                if(key == "stop_on_error")
                    value = Json(true);
                else
                {
                    if(i + 1 >= toks.size())
                    {
                        err.code = "E_BAD_ARG";
                        err.message = "option --" + key + " needs a value";
                        return false;
                    }
                    if(!optionFromText(key, toks[++i], value, msg))
                    {
                        err.code = "E_BAD_ARG";
                        err.message = msg;
                        return false;
                    }
                }
                if(!applyOption(req->opt, key, value, msg))
                {
                    err.code = "E_BAD_ARG";
                    err.message = msg;
                    return false;
                }
                continue;
            }
            const ArgSpec* found = nullptr;
            for(auto & a : spec->args)
                if(key == a.name)
                    found = &a;
            if(!found)
            {
                err.code = "E_BAD_ARG";
                err.message = "unknown option --" + key + " for op " + spec->name + " (usage: " + spec->usage + ")";
                return false;
            }
            if(found->type == 'b')
            {
                bool flag = true;
                if(i + 1 < toks.size() && (toks[i + 1] == "true" || toks[i + 1] == "false"))
                    flag = toks[++i] == "true";
                args.set(key, flag);
            }
            else
            {
                if(i + 1 >= toks.size())
                {
                    err.code = "E_BAD_ARG";
                    err.message = "option --" + key + " needs a value";
                    return false;
                }
                const std::string & v = toks[++i];
                if(found->type == 'i')
                {
                    long long n;
                    if(!parseInteger(v, n))
                    {
                        err.code = "E_BAD_ARG";
                        err.message = "argument '" + key + "' expects an integer, got '" + v + "'";
                        return false;
                    }
                    args.set(key, n);
                }
                else
                    args.set(key, v);
            }
        }
        if(!positional.empty())
        {
            if(!spec->positional[0])
            {
                err.code = "E_BAD_ARG";
                err.message = std::string("op ") + spec->name + " takes no positional arguments (usage: " + spec->usage + ")";
                return false;
            }
            // "a,b": the first token goes to a, the remaining tokens (joined by a space) to b.
            std::vector<std::string> keys;
            {
                std::string list = spec->positional;
                size_t pos = 0;
                while(pos <= list.size())
                {
                    size_t c = list.find(',', pos);
                    keys.push_back(list.substr(pos, c == std::string::npos ? std::string::npos : c - pos));
                    if(c == std::string::npos)
                        break;
                    pos = c + 1;
                }
            }
            size_t at = 0;
            for(size_t k = 0; k < keys.size() && at < positional.size(); k++)
            {
                std::string joined;
                size_t take = k + 1 == keys.size() ? positional.size() - at : 1;
                for(size_t q = 0; q < take; q++)
                    joined += (q ? " " : "") + positional[at + q];
                at += take;
                char type = 's';
                for(auto & a : spec->args)
                    if(keys[k] == a.name)
                        type = a.type;
                if(args.find(keys[k]))
                {
                    err.code = "E_BAD_ARG";
                    err.message = "argument '" + keys[k] + "' is given twice";
                    return false;
                }
                if(type == 'i')
                {
                    long long n;
                    if(!parseInteger(joined, n))
                    {
                        err.code = "E_BAD_ARG";
                        err.message = "argument '" + keys[k] + "' expects an integer, got '" + joined + "'";
                        return false;
                    }
                    args.set(keys[k], n);
                }
                else
                    args.set(keys[k], joined);
            }
        }
    }
    std::string msg;
    if(!validateArgs(*spec, args, msg))
    {
        err.code = "E_BAD_ARG";
        err.message = msg;
        return false;
    }
    req->args = args;
    finishEcho(*req, args.size() ? args : Json());
    out = req;
    return true;
}

// ------------------------------------------------------------------ renderers

std::string renderJsonLine(const Json & obj)
{
    std::string s = obj.dump();
    s += '\n';
    return s;
}

std::string renderEventJson(const Json & event)
{
    Json o = Json::object();
    o.set("type", "event");
    o.set("v", kProtocolVersion);
    o.set("event", event);
    return renderJsonLine(o);
}

std::string renderEventText(const Json & event)
{
    const Json* seq = event.find("seq");
    const Json* type = event.find("type");
    std::string s = "@@EVENT " + std::to_string(seq ? seq->asInt() : 0) + " " + (type ? type->asString() : std::string()) + " " + event.dump() + "\n";
    return s;
}

std::string renderFatal(bool jsonMode, const std::string & code, const std::string & message)
{
    if(jsonMode)
    {
        Json o = Json::object();
        o.set("type", "fatal");
        o.set("v", kProtocolVersion);
        o.set("code", code);
        o.set("message", message);
        return renderJsonLine(o);
    }
    return "@@FATAL " + code + " " + escapeControlText(message) + "\n";
}

std::string renderReady(bool jsonMode, const Json & hello)
{
    if(jsonMode)
        return renderJsonLine(hello);
    return "@@READY x64dbg-cli 1 x64\n";
}

static void appendBody(std::string & out, const std::string & text)
{
    if(text.empty())
        return;
    std::string esc = escapeControlText(text);
    size_t pos = 0;
    while(pos < esc.size())
    {
        size_t nl = esc.find('\n', pos);
        std::string l = esc.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if(startsWith(l, "@@"))
            out += ' ';
        out += l;
        out += '\n';
        if(nl == std::string::npos)
            break;
        pos = nl + 1;
    }
}

// ------------------------------------------------------------------ text form of `data` (design 9.1, rules i to vi)

static std::string escValue(const std::string & s)
{
    std::string o;
    for(unsigned char c : s)
    {
        if(c == '\t')
            o += "\\t";
        else if(c == '\n')
            o += "\\n";
        else if(c == '\r')
            o += "\\r";
        else if(c < 0x20 || c == 0x7f)
        {
            char b[8];
            snprintf(b, sizeof(b), "\\x%02x", c);
            o += b;
        }
        else
            o += (char)c;
    }
    return o;
}

static std::string scalarText(const Json & v)
{
    switch(v.type())
    {
    case Json::Null:
        return "-";
    case Json::Bool:
        return v.asBool() ? "true" : "false";
    case Json::Int:
        return std::to_string(v.asInt());
    case Json::Real:
        return v.dump();
    case Json::String:
        return escValue(v.asString());
    default:
        return v.dump();
    }
}

// Header of an empty array of objects (rule iv: "an empty array prints the header line only"). Keys follow the schema files.
static const char* emptyHeader(const std::string & op, const std::string & key)
{
    static const struct
    {
        const char* op;
        const char* key;
        const char* header;
    } table[] =
    {
        { "threads", "threads", "index\ttid\tname\thandle\tstart\tteb\tcip\tcip_label\tsuspend_count\tpriority\twait_reason\tlast_error\tuser_time_ms\tkernel_time_ms\tcycles\tcreation_time\tis_current\tis_main" },
        { "modules", "modules", "name\tbase\tsize\tpath\tentry\tparty\tsymbols\tis_main" },
        { "memmap", "pages", "base\tsize\tstate\ttype\tprotect\talloc_base\talloc_protect\tinfo\tmodule\tsection" },
        { "bps", "breakpoints", "id\tkind\taddr\tlabel\tmodule\tname\tenabled\tactive\tsingleshoot\tsilent\tfast_resume\thit_count\tbreak_condition\tlog_text\tlog_condition\tcommand_text\tcommand_condition\tlog_file" },
        { "stack", "rows", "addr\toffset\tvalue\tcomment\tlabel\tis_csp\tis_cbp" },
        { "sym", "symbols", "addr\tname\tdecorated\ttype\tmodule\tordinal" },
        { "mem", "rows", "addr\thex\tascii" },
        { "mem", "items", "addr\tvalue\tlabel" },
        { "mem", "unreadable", "addr\tsize" },
        { "callstack", "frames", "index\taddr\tfrom\tto\tcomment\tparty\tfrom_label\tto_label" },
        { "dis", "instructions", "addr\tsize\tbytes\ttext\tkind\tis_cip" },
        { "events", "events", "seq\ttype" },
        { "seh", "chain", "addr\thandler\thandler_label" },
        { "handles", "handles", "handle\ttype\ttype_number\tname\taccess" },
        { "windows", "windows", "handle\tparent\ttid\tthread_name\tstyle\tstyle_ex\twndproc\tenabled\trect\ttitle\tclass" },
        { "tcp", "connections", "local\tlocal_port\tremote\tremote_port\tstate" },
        { "heaps", "heaps", "addr\tsize\tflags" },
        { "ps", "processes", "pid\texe\ttitle\targs" },
        { "xrefs", "xrefs", "from\ttype\tfrom_label\ttext" },
        { "patches", "patches", "module\taddr\told\tnew" },
        { "watch", "watches", "id\tname\texpression\ttype\tmode\tvalue\ttriggered" },
        { "constants", "items", "name\tvalue" },
        { "errors", "items", "name\tvalue" },
        { "exceptions", "items", "name\tvalue" },
        { "menu", "menus", "id\tparent\tplugin\tname\tkind\tchecked\tvisible\thotkey" },
        { "commands", "commands", "canonical\tnames\tdebug_only" },
        { "help", "ops", "name\tmilestone\tprecondition\tusage" },
    };
    for(auto & t : table)
        if(op == t.op && key == t.key)
            return t.header;
    return nullptr;
}

static std::string renderTable(const Json & t);

static void renderMembers(std::string & out, const std::string & op, const Json & obj, int indent)
{
    std::string pad((size_t)indent, ' ');
    for(auto & m : obj.members())
    {
        const Json & v = m.second;
        if(v.isObject() && m.first == "table" && v.find("columns") && v.find("rows") && v.find("id") && v.find("name") && v.find("total_rows"))
        {
            // a captured reference table (labels, comments, strings, ...): same text form as the `tables` of a response
            out += renderTable(v);
        }
        else if(v.isObject())
        {
            out += pad + m.first + ":\n";
            renderMembers(out, op, v, indent + 2);
        }
        else if(v.isArray())
        {
            const char* hdr = emptyHeader(op, m.first);
            bool objects = !v.items().empty() && v.items()[0].isObject();
            if(objects || (v.items().empty() && hdr))
            {
                out += pad + m.first + ":\n";
                std::vector<std::string> keys;
                if(objects)
                    for(auto & k : v.items()[0].members())
                        keys.push_back(k.first);
                std::string header;
                if(objects)
                {
                    for(auto & k : keys)
                        header += (header.empty() ? "" : "\t") + k;
                }
                else
                    header = hdr;
                out += pad + header + "\n";
                for(auto & e : v.items())
                {
                    std::string row;
                    for(size_t k = 0; k < keys.size(); k++)
                    {
                        const Json* c = e.isObject() ? e.find(keys[k]) : nullptr;
                        std::string cell = !c ? "-" : (c->isObject() || c->isArray()) ? c->dump() : scalarText(*c);
                        row += (k ? "\t" : "") + cell;
                    }
                    out += pad + row + "\n";
                }
            }
            else
            {
                std::string line;
                for(auto & e : v.items())
                {
                    std::string t = (e.isObject() || e.isArray()) ? e.dump() : scalarText(e);
                    if(e.isString() && (t.empty() || t.find(' ') != std::string::npos))
                    {
                        std::string q;
                        for(char c : t)
                            q += (c == '"' ? "\\\"" : std::string(1, c));
                        t = "\"" + q + "\"";
                    }
                    line += (line.empty() ? "" : " ") + t;
                }
                out += pad + m.first + ":" + (line.empty() ? "" : " " + line) + "\n";
            }
        }
        else
            out += pad + m.first + ": " + scalarText(v) + "\n";
    }
}

static std::string spacedBytes(const std::string & hex)
{
    std::string o;
    for(size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        if(i)
            o += ' ';
        o += hex.substr(i, 2);
    }
    return o;
}

static std::string renderDis(const Json & data)
{
    std::string out;
    const Json* rows = data.find("instructions");
    if(!rows)
        return out;
    for(auto & r : rows->items())
    {
        auto str = [&](const char* k) -> std::string
        {
            const Json* v = r.find(k);
            return v && v->isString() ? v->asString() : std::string();
        };
        const Json* cip = r.find("is_cip");
        bool isCip = cip && cip->asBool();
        std::string bp = str("bp");
        std::string addr = str("addr");
        if(addr.size() > 2)
            addr = addr.substr(2);
        std::string line = std::string(isCip ? "=>" : "  ") + ((!bp.empty() && bp != "none") ? "*" : " ") + addr + "  ";
        if(r.find("bytes"))
        {
            std::string b = spacedBytes(str("bytes"));
            line += b + std::string(b.size() < 24 ? 24 - b.size() : 0, ' ') + "  ";
        }
        std::string text = str("text");
        line += text;
        std::string note = str("comment");
        if(note.empty())
        {
            const Json* br = r.find("branch");
            if(br && br->isObject() && br->find("target_label") && br->find("target_label")->isString())
                note = br->find("target_label")->asString();
        }
        if(!note.empty())
            line += std::string(text.size() < 32 ? 32 - text.size() : 0, ' ') + " ; " + note;
        out += escValue(line) + "\n";
    }
    const Json* why = data.find("truncated_reason");
    if(why && why->isString())
        out += "; truncated: " + why->asString() + "\n";
    return out;
}

std::string renderDataText(const std::string & op, const Json & data)
{
    std::string out;
    if(data.isNull())
        return out;
    if(op == "dis" && data.isObject())
        return renderDis(data);
    if(data.isObject())
        renderMembers(out, op, data, 0);
    else
        out = scalarText(data) + "\n";
    return out;
}

static std::string renderTable(const Json & t)
{
    std::string s;
    s += "table " + std::to_string(t.find("id")->asInt()) + " \"" + t.find("name")->asString() + "\" rows " +
         std::to_string(t.find("rows")->items().size()) + "/" + std::to_string(t.find("total_rows")->asInt()) + "\n";
    std::string hdr;
    for(auto & c : t.find("columns")->items())
        hdr += (hdr.empty() ? "" : "\t") + c.asString();
    s += hdr + "\n";
    for(auto & r : t.find("rows")->items())
    {
        std::string row;
        bool first = true;
        for(auto & c : r.items())
        {
            if(!first)
                row += '\t';
            first = false;
            row += c.asString();
        }
        s += row + "\n";
    }
    return s;
}

std::string renderTextResponse(const Json & r, const std::string & id)
{
    std::string out;
    bool ok = r.find("ok") && r.find("ok")->asBool();
    appendBody(out, r.find("output") ? r.find("output")->asString() : std::string());
    const Json* data = r.find("data");
    const std::string op = r.find("op") ? r.find("op")->asString() : std::string();
    if(data && !data->isNull())
    {
        if(op == "log" && data->find("text"))
            appendBody(out, data->find("text")->asString());
        else
            appendBody(out, renderDataText(op, *data));
    }
    if(const Json* tables = r.find("tables"))
        for(auto & t : tables->items())
            appendBody(out, renderTable(t));
    if(const Json* vars = r.find("vars"))
        for(auto & m : vars->members())
            appendBody(out, "var " + m.first + " = " + (m.second.isString() ? m.second.asString() : std::string("null")));
    if(const Json* w = r.find("warnings"))
        for(auto & x : w->items())
            appendBody(out, "warning: " + x.asString());
    if(const Json* evs = r.find("events"))
        for(auto & e : evs->items())
            out += renderEventText(e);
    std::string code;
    if(!ok)
    {
        const Json* e = r.find("error");
        if(e && e->isObject())
        {
            code = e->find("code")->asString();
            appendBody(out, "error: " + code + ": " + e->find("message")->asString());
        }
    }
    const Json* st = r.find("state");
    std::string status = st && st->find("status") ? st->find("status")->asString() : "none";
    std::string cip = "-";
    long long seq = 0;
    if(st)
    {
        const Json* c = st->find("cip");
        if(c && c->isString())
            cip = c->asString();
        if(st->find("seq"))
            seq = st->find("seq")->asInt();
    }
    out += "@@END " + id + (ok ? " ok" : " fail") + " state=" + status + " cip=" + cip + " seq=" + std::to_string(seq);
    if(const Json* w = r.find("wait"))
    {
        const Json* reason = w->find("reason");
        if(reason && reason->asString() != "none")
            out += " wait=" + reason->asString();
    }
    if(!code.empty())
        out += " code=" + code;
    out += "\n";
    return out;
}
}
