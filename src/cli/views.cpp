#include "views.h"

#include "host.h"
#include "util.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace cli
{
const ViewEntry* findView(const std::string & name)
{
    static const ViewEntry table[] =
    {
        { "process", viewProcess, false },
        { "regs", viewRegs, false },
        { "setreg", viewSetReg, false },
        { "dis", viewDis, false },
        { "mem", viewMem, false },
        { "memwrite", viewMemWrite, false },
        { "memmap", viewMemMap, false },
        { "stack", viewStack, false },
        { "callstack", viewCallStack, false },
        { "bps", viewBps, false },
        { "bp", viewBp, false },
        { "threads", viewThreads, false },
        { "thread", viewThread, false },
        { "modules", viewModules, false },
        { "sym", viewSym, false },
        { "init", viewInit, true },
        { "run", viewRun, true },
        { "stepin", viewStepIn, true },
        { "stepover", viewStepOver, true },
        { "stepout", viewStepOut, true },
        { "runto", viewRunTo, true },
        { "restart", viewRestart, true },
        { "attach", viewAttach, true },
        { "detach", viewDetach, true },
        { "skip", viewSkip, true },
        // ---- M3
        { "seh", viewSeh, false },
        { "handles", viewHandles, false },
        { "windows", viewWindows, false },
        { "tcp", viewTcp, false },
        { "heaps", viewHeaps, false },
        { "privileges", viewPrivileges, false },
        { "ps", viewPs, false },
        { "labels", viewLabels, false },
        { "comments", viewComments, false },
        { "bookmarks", viewBookmarks, false },
        { "functions", viewFunctions, false },
        { "arguments", viewArguments, false },
        { "loops", viewLoops, false },
        { "addrinfo", viewAddrInfo, false },
        { "xrefs", viewXrefs, false },
        { "patches", viewPatches, false },
        { "patch", viewPatch, false },
        { "strings", viewStrings, false },
        { "calls", viewCalls, false },
        { "ptrs", viewPtrs, false },
        { "watch", viewWatch, false },
        { "trace", viewTrace, false },
        { "script", viewScript, true },
        { "types", viewTypes, false },
        { "struct", viewStruct, false },
        { "cfg", viewCfg, false },
        { "notes", viewNotes, false },
        { "source", viewSource, false },
        { "nav", viewNav, false },
        { "callargs", viewCallArgs, false },
        { "locals", viewLocals, false },
        { "infobox", viewInfoBox, false },
        { "menu", viewMenu, false },
        { "config", viewConfig, false },
        { "constants", viewConstants, false },
        { "errors", viewErrors, false },
        { "exceptions", viewExceptions, false },
        { "format", viewFormat, false },
        { "asm", viewAsm, false },
        { "animate", viewAnimate, false },
        { "favourites", viewFavourites, false },
        { "module", viewModule, true },
    };
    for(auto & e : table)
        if(name == e.name)
            return &e;
    return nullptr;
}

std::string hexN(unsigned long long v, int digits)
{
    char buf[40];
    snprintf(buf, sizeof(buf), "0x%0*llx", digits, v);
    return buf;
}

std::string bytesToHex(const unsigned char* p, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for(size_t i = 0; i < n; i++)
    {
        s += digits[p[i] >> 4];
        s += digits[p[i] & 15];
    }
    return s;
}

bool parseHexBytes(const std::string & text, std::vector<unsigned char> & out, std::string & err, size_t maxBytes)
{
    out.clear();
    int pending = -1;
    for(char c : text)
    {
        if(c == ' ')
        {
            if(pending >= 0)
            {
                err = "hex digits must come in pairs (a blank may only separate byte pairs)";
                return false;
            }
            continue;
        }
        int d;
        if(c >= '0' && c <= '9')
            d = c - '0';
        else if(c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
        else if(c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
        else
        {
            err = "hex contains a character that is not a hex digit";
            return false;
        }
        if(pending < 0)
            pending = d;
        else
        {
            out.push_back((unsigned char)(pending * 16 + d));
            pending = -1;
            if(out.size() > maxBytes)
            {
                err = "more than " + std::to_string(maxBytes) + " bytes";
                return false;
            }
        }
    }
    if(pending >= 0)
    {
        err = "odd number of hex digits";
        return false;
    }
    if(out.empty())
    {
        err = "no bytes given";
        return false;
    }
    return true;
}

Json strOrNull(const std::string & s)
{
    return s.empty() ? Json() : Json(s);
}

bool argText(const Json & args, const char* key, std::string & out, bool intAsHex)
{
    const Json* v = args.find(key);
    if(!v || v->isNull())
        return false;
    if(v->isString())
        out = v->asString();
    else if(v->isInt())
        out = intAsHex ? hexArg(v->asInt()) : std::to_string(v->asInt());
    else
        return false;
    return true;
}

bool argInt(const Json & args, const char* key, long long & out)
{
    const Json* v = args.find(key);
    if(!v || !v->isInt())
        return false;
    out = v->asInt();
    return true;
}

bool argBool(const Json & args, const char* key, bool def)
{
    const Json* v = args.find(key);
    return v && v->isBool() ? v->asBool() : def;
}

bool evalExpr(Result & res, const std::string & expr, const char* what, duint & out)
{
    std::string t = trim(expr);
    if(t.empty() || t.size() > 1023)
    {
        res.fail("E_BAD_ARG", std::string(what) + " must be an expression of 1..1023 bytes");
        return false;
    }
    bool ok = false;
    if(DbgIsValidExpression(t.c_str()))
        out = DbgEval(t.c_str(), &ok);
    if(!ok)
    {
        res.fail("E_BAD_ARG", std::string("cannot evaluate ") + what + ": " + t);
        return false;
    }
    return true;
}

Json takeLastTable(Request & req)
{
    Host & h = host();
    int limitId;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        limitId = h.tableCounter;
    }
    int dropped = 0;
    std::vector<RefTable> list = h.tablesBetween(req.tableCursor, limitId, &dropped);
    req.tableCursor = limitId;
    if(!list.empty())
        return tableToJson(list.back(), 0, (size_t)req.opt.maxRows);
    Json t = Json::object();
    t.set("id", 0);
    t.set("name", "");
    t.set("columns", Json::array());
    t.set("rows", Json::array());
    t.set("total_rows", 0);
    t.set("truncated", false);
    t.set("actions", Json::array());
    return t;
}

bool listWindow(Request & req, Result & res, long long & limit, long long & offset)
{
    limit = 5000;
    offset = 0;
    argInt(req.args, "limit", limit);
    argInt(req.args, "offset", offset);
    if(limit < 1 || limit > 1000000 || offset < 0)
    {
        res.fail("E_BAD_ARG", "limit must be in 1..1000000 and offset >= 0");
        return false;
    }
    return true;
}

bool isLive()
{
    if(!DbgIsDebugging())
        return false;
    Status st;
    {
        std::lock_guard<std::mutex> lk(host().mu);
        st = host().reportedStatusLocked();
    }
    return st == Status::Running || st == Status::Starting || DbgIsRunning();
}

static std::string shortest(double v, bool isFloat)
{
    if(std::isnan(v))
        return "nan";
    if(std::isinf(v))
        return v < 0 ? "-inf" : "inf";
    char buf[64];
    for(int prec = 1; prec <= 17; prec++)
    {
        snprintf(buf, sizeof(buf), "%.*g", prec, v);
        double back = strtod(buf, nullptr);
        if(isFloat ? ((float)back == (float)v) : (back == v))
            return buf;
    }
    snprintf(buf, sizeof(buf), "%.17g", v);
    return buf;
}

std::string shortestDouble(double v)
{
    return shortest(v, false);
}

std::string shortestFloat(float v)
{
    return shortest((double)v, true);
}

double halfToDouble(unsigned short h)
{
    int sign = (h >> 15) & 1;
    int exp = (h >> 10) & 0x1f;
    int mant = h & 0x3ff;
    double v;
    if(exp == 0)
        v = std::ldexp((double)mant, -24);
    else if(exp == 31)
        v = mant ? NAN : INFINITY;
    else
        v = std::ldexp((double)(mant | 0x400), exp - 25);
    return sign ? -v : v;
}

double extendedToDouble(const unsigned char* p)
{
    unsigned long long mant;
    memcpy(&mant, p, 8);
    unsigned short se;
    memcpy(&se, p + 8, 2);
    int sign = (se >> 15) & 1;
    int exp = se & 0x7fff;
    double v;
    if(exp == 0x7fff)
        v = (mant << 1) ? NAN : INFINITY;
    else if(exp == 0 && mant == 0)
        v = 0.0;
    else
        v = std::ldexp((double)mant, (exp ? exp : 1) - 16383 - 63);
    return sign ? -v : v;
}

std::string labelAt(duint addr)
{
    char buf[MAX_LABEL_SIZE] = "";
    if(DbgGetLabelAt(addr, SEG_DEFAULT, buf) && buf[0])
        return buf;
    return std::string();
}

unsigned long long activeThreadId()
{
    HANDLE h = DbgGetThreadHandle();
    DWORD tid = h ? GetThreadId(h) : 0;
    return tid ? tid : DbgGetThreadId();
}

std::string moduleAt(duint addr)
{
    char buf[MAX_MODULE_SIZE] = "";
    if(DbgGetModuleAt(addr, buf) && buf[0])
        return buf;
    return std::string();
}
}
