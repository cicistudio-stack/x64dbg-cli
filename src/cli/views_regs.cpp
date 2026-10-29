#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "util.h"
#include "views.h"

#include <cctype>
#include <cstring>
#include <memory>
#include <regex>
#include <set>

namespace cli
{
static bool cpuHasAvx512()
{
#ifndef PF_AVX512F_INSTRUCTIONS_AVAILABLE
#define PF_AVX512F_INSTRUCTIONS_AVAILABLE 41
#endif
    return IsProcessorFeaturePresent(PF_AVX512F_INSTRUCTIONS_AVAILABLE) != FALSE;
}

// Most significant byte first, like the register display of the GUI.
static std::string bigEndianHex(const void* data, size_t n)
{
    const unsigned char* p = (const unsigned char*)data;
    std::string s;
    static const char digits[] = "0123456789abcdef";
    for(size_t i = n; i-- > 0;)
    {
        s += digits[p[i] >> 4];
        s += digits[p[i] & 15];
    }
    return s;
}

static Json errorName(const char* key, DWORD code)
{
    const DBGFUNCTIONS* f = DbgFunctions();
    char fmt[64], out[128] = "";
    snprintf(fmt, sizeof(fmt), "{%s@%X}", key, code);
    if(f && f->StringFormatInline && f->StringFormatInline(fmt, sizeof(out), out) && out[0])
        return Json(out);
    return Json();
}

void viewRegs(Session &, Request & req, Result & res)
{
    static const char* const allGroups[] = { "gpr", "flags", "seg", "dbg", "fpu", "mmx", "xmm", "ymm", "zmm", "opmask" };
    std::string spec = "gpr,flags,seg";
    std::string given;
    if(argText(req.args, "groups", given, false) && !trim(given).empty())
        spec = given;
    std::set<std::string> want;
    bool wantAll = false;
    size_t pos = 0;
    while(pos <= spec.size())
    {
        size_t c = spec.find(',', pos);
        std::string g = lower(trim(spec.substr(pos, c == std::string::npos ? std::string::npos : c - pos)));
        if(!g.empty())
        {
            bool known = g == "all";
            for(auto n : allGroups)
                known = known || g == n;
            if(!known)
            {
                res.fail("E_BAD_ARG", "unknown register group '" + g + "' (gpr, flags, seg, dbg, fpu, mmx, xmm, ymm, zmm, opmask, all)");
                return;
            }
            if(g == "all")
                wantAll = true;
            else
                want.insert(g);
        }
        if(c == std::string::npos)
            break;
        pos = c + 1;
    }
    bool avx512 = cpuHasAvx512();
    if(wantAll)
        for(auto n : allGroups)
            if(avx512 || (std::string(n) != "zmm" && std::string(n) != "opmask"))
                want.insert(n);
    if(!avx512 && (want.count("zmm") || want.count("opmask")))
    {
        res.fail("E_UNSUPPORTED", "this CPU does not report AVX-512; the groups zmm and opmask are not available");
        return;
    }

    std::unique_ptr<REGDUMP_AVX512> dump(new REGDUMP_AVX512());
    memset(dump.get(), 0, sizeof(REGDUMP_AVX512));
    if(!DbgGetRegDumpEx(dump.get(), sizeof(REGDUMP_AVX512)))
    {
        res.fail("E_COMMAND_FAILED", "the register dump is not available");
        return;
    }
    const REGISTERCONTEXT_AVX512 & c = dump->regcontext;
    Json d = Json::object();
    d.set("thread", activeThreadId());
    if(want.count("gpr"))
    {
        Json g = Json::object();
        g.set("rax", hexAddr(c.cax));
        g.set("rbx", hexAddr(c.cbx));
        g.set("rcx", hexAddr(c.ccx));
        g.set("rdx", hexAddr(c.cdx));
        g.set("rsp", hexAddr(c.csp));
        g.set("rbp", hexAddr(c.cbp));
        g.set("rsi", hexAddr(c.csi));
        g.set("rdi", hexAddr(c.cdi));
        g.set("r8", hexAddr(c.r8));
        g.set("r9", hexAddr(c.r9));
        g.set("r10", hexAddr(c.r10));
        g.set("r11", hexAddr(c.r11));
        g.set("r12", hexAddr(c.r12));
        g.set("r13", hexAddr(c.r13));
        g.set("r14", hexAddr(c.r14));
        g.set("r15", hexAddr(c.r15));
        g.set("rip", hexAddr(c.cip));
        d.set("gpr", g);
    }
    if(want.count("flags"))
    {
        Json f = Json::object();
        f.set("eflags", hexAddr(c.eflags));
        const struct
        {
            const char* name;
            int bit;
        } bits[] = { { "cf", 0 }, { "pf", 2 }, { "af", 4 }, { "zf", 6 }, { "sf", 7 }, { "tf", 8 }, { "if", 9 }, { "df", 10 }, { "of", 11 } };
        for(auto & b : bits)
            f.set(b.name, (int)((c.eflags >> b.bit) & 1));
        d.set("flags", f);
    }
    if(want.count("seg"))
    {
        Json s = Json::object();
        s.set("cs", hexN(c.cs, 4));
        s.set("ds", hexN(c.ds, 4));
        s.set("es", hexN(c.es, 4));
        s.set("fs", hexN(c.fs, 4));
        s.set("gs", hexN(c.gs, 4));
        s.set("ss", hexN(c.ss, 4));
        d.set("seg", s);
    }
    if(want.count("dbg"))
    {
        Json r = Json::object();
        r.set("dr0", hexAddr(c.dr0));
        r.set("dr1", hexAddr(c.dr1));
        r.set("dr2", hexAddr(c.dr2));
        r.set("dr3", hexAddr(c.dr3));
        r.set("dr6", hexAddr(c.dr6));
        r.set("dr7", hexAddr(c.dr7));
        d.set("dbg", r);
    }
    // x87 stack layout as in RegistersView: ST(k) is RegisterArea[k]; the tag of ST(k) is the tag of physical register (TOP + k) & 7
    unsigned top = (c.x87fpu.StatusWord >> 11) & 7;
    if(want.count("fpu"))
    {
        Json f = Json::object();
        f.set("control", hexN(c.x87fpu.ControlWord, 4));
        f.set("status", hexN(c.x87fpu.StatusWord, 4));
        f.set("tag", hexN(c.x87fpu.TagWord, 4));
        f.set("top", (int)top);
        f.set("mxcsr", hexN(c.MxCsr, 8));
        Json st = Json::array();
        static const char* const tags[] = { "valid", "zero", "special", "empty" };
        for(unsigned k = 0; k < 8; k++)
        {
            const unsigned char* raw = c.RegisterArea + 10 * k;
            Json e = Json::object();
            e.set("name", "st" + std::to_string(k));
            e.set("hex", bigEndianHex(raw, 10));
            e.set("tag", tags[(c.x87fpu.TagWord >> (((top + k) & 7) * 2)) & 3]);
            e.set("value", shortestDouble(extendedToDouble(raw)));
            st.push(e);
        }
        f.set("st", st);
        d.set("fpu", f);
    }
    if(want.count("mmx"))
    {
        // MMX registers alias the x87 registers: MMi is the low 64 bits of the register that RegistersView calls x87ri
        unsigned pos0 = (8 - top) % 8;
        Json m = Json::array();
        for(unsigned i = 0; i < 8; i++)
        {
            unsigned long long v;
            memcpy(&v, c.RegisterArea + 10 * ((pos0 + i) % 8), 8);
            m.push(hexAddr(v));
        }
        d.set("mmx", m);
    }
    auto vec = [&](const char* name, int count, size_t bytes)
    {
        Json a = Json::array();
        for(int i = 0; i < count; i++)
        {
            Json e = Json::object();
            e.set("name", std::string(name) + std::to_string(i));
            e.set("hex", bigEndianHex((const unsigned char*)&c.ZmmRegisters[i], bytes));
            a.push(e);
        }
        return a;
    };
    if(want.count("xmm"))
        d.set("xmm", vec("xmm", 16, 16));
    if(want.count("ymm"))
        d.set("ymm", vec("ymm", 16, 32));
    if(want.count("zmm"))
        d.set("zmm", vec("zmm", 32, 64));
    if(want.count("opmask"))
    {
        Json m = Json::array();
        for(int i = 0; i < 8; i++)
            m.push(hexAddr(c.Opmask[i]));
        d.set("opmask", m);
    }
    Json le = Json::object();
    le.set("code", hexN(dump->lastError, 8));
    le.set("name", errorName("winerrorname", dump->lastError));
    d.set("last_error", le);
    Json ls = Json::object();
    ls.set("code", hexN(dump->lastStatus, 8));
    ls.set("name", errorName("ntstatusname", dump->lastStatus));
    d.set("last_status", ls);
    res.data = d;
}

void viewSetReg(Session & s, Request & req, Result & res)
{
    std::string reg, value;
    if(!argText(req.args, "reg", reg, false) || !argText(req.args, "value", value, false))
    {
        res.fail("E_BAD_ARG", "setreg requires reg and value (usage: setreg <reg> <value>)");
        return;
    }
    reg = lower(trim(reg));
    static const std::regex ok("^(r[a-z0-9]+|e[a-z]{2}|[a-d][lhx]|[cdefgs]s|dr[0-7]|[cpazstdo]f|if|eflags)$");
    if(!std::regex_match(reg, ok))
    {
        res.fail("E_UNSUPPORTED", "register '" + reg + "' cannot be set here (general purpose, segment, debug and flag registers only)");
        return;
    }
    duint v = 0;
    if(!evalExpr(res, value, "value", v))
        return;
    // the value is evaluated here and handed to the core as a number, so no expression text is spliced into the line
    if(!s.execLine(req, res, "mov " + reg + "," + hexArg((long long)v)))
        return;
    bool good = false;
    duint now = DbgEval(reg.c_str(), &good);
    if(!good)
    {
        res.fail("E_COMMAND_FAILED", "cannot read " + reg + " back");
        return;
    }
    Json d = Json::object();
    d.set("reg", reg);
    d.set("value", hexAddr(now));
    res.data = d;
}
}
