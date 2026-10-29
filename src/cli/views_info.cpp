#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"
#include "../zydis_wrapper/zydis_wrapper.h"

#include "disasm_row.h"
#include "host.h"
#include "util.h"
#include "views.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <regex>
#include <set>

namespace cli
{
namespace
{
bool runningNow()
{
    return DbgIsDebugging() && DbgIsRunning();
}

duint evalOr0(const std::string & expr)
{
    bool ok = false;
    duint v = DbgEval(expr.c_str(), &ok);
    return ok ? v : 0;
}
}

// ------------------------------------------------------------------ callargs

void viewCallArgs(Session &, Request & req, Result & res)
{
    long long count = 5; // the GUI default for "x64 fastcall": 4 registers + 1 stack argument
    argInt(req.args, "count", count);
    if(count < 0 || count > 64)
    {
        res.fail("E_BAD_ARG", "count must be in 0..64");
        return;
    }
    std::string conv = "auto";
    argText(req.args, "convention", conv, false);
    conv = lower(conv);
    if(conv != "auto" && conv != "x64")
    {
        res.fail("E_BAD_ARG", "convention must be auto or x64 (the other conventions exist only in the 32-bit build)");
        return;
    }
    duint cip = 0;
    bool ok = false;
    cip = DbgEval("cip", &ok);
    if(!ok)
    {
        res.fail("E_COMMAND_FAILED", "cip is not available");
        return;
    }
    BASIC_INSTRUCTION_INFO bi;
    memset(&bi, 0, sizeof(bi));
    DbgDisasmFastAt(cip, &bi);
    // CPUArgumentWidget: stack arguments start behind the 0x20 byte shadow space; once the call ran, the return address sits on top
    duint stackOffset = 0x20 + (bi.call ? 0 : sizeof(duint));
    static const char* const regs[] = { "rcx", "rdx", "r8", "r9" };
    Json list = Json::array();
    for(long long i = 0; i < count; i++)
    {
        std::string location, expr;
        if(i < 4)
        {
            location = regs[i];
            expr = location;
        }
        else
        {
            duint off = stackOffset + (duint)(i - 4) * sizeof(duint);
            location = "[csp+" + hexArg((long long)off) + "]";
            expr = location;
        }
        duint v = evalOr0(expr);
        Json j = Json::object();
        j.set("index", i + 1);
        j.set("location", location);
        j.set("value", hexAddr(v));
        j.set("label", strOrNull(labelAt(v)));
        list.push(j);
    }
    Json d = Json::object();
    d.set("convention", "x64 fastcall");
    d.set("args", list);
    res.data = d;
}

// ------------------------------------------------------------------ locals

namespace
{
struct BaseReg
{
    const char* name;
    ZydisRegister reg;
};

const BaseReg kBases[] =
{
    { "rax", ZYDIS_REGISTER_RAX }, { "rbx", ZYDIS_REGISTER_RBX }, { "rcx", ZYDIS_REGISTER_RCX }, { "rdx", ZYDIS_REGISTER_RDX },
    { "rbp", ZYDIS_REGISTER_RBP }, { "rsp", ZYDIS_REGISTER_RSP }, { "rsi", ZYDIS_REGISTER_RSI }, { "rdi", ZYDIS_REGISTER_RDI },
    { "r8", ZYDIS_REGISTER_R8 }, { "r9", ZYDIS_REGISTER_R9 }, { "r10", ZYDIS_REGISTER_R10 }, { "r11", ZYDIS_REGISTER_R11 },
    { "r12", ZYDIS_REGISTER_R12 }, { "r13", ZYDIS_REGISTER_R13 }, { "r14", ZYDIS_REGISTER_R14 }, { "r15", ZYDIS_REGISTER_R15 }
};

bool isCodeType(ENCODETYPE t)
{
    return t == enc_unknown || t == enc_code || t == enc_junk || t == enc_middle;
}
}

void viewLocals(Session &, Request & req, Result & res)
{
    std::string base = "rbp";
    argText(req.args, "base", base, false);
    base = lower(base);
    const BaseReg* br = nullptr;
    for(auto & b : kBases)
        if(base == b.name)
            br = &b;
    if(!br)
    {
        res.fail("E_BAD_ARG", "base must be one of rax rbx rcx rdx rbp rsp rsi rdi r8..r15");
        return;
    }
    bool ok = false;
    duint cip = DbgEval("cip", &ok);
    duint start = 0, end = 0;
    Json d = Json::object();
    if(!ok || !DbgFunctionGet(cip, &start, &end))
    {
        d.set("function", nullptr);
        d.set("base", base);
        d.set("locals", Json::array());
        res.data = d;
        return;
    }
    std::vector<unsigned char> buffer((size_t)(end - start + 16));
    if(!DbgMemRead(start, buffer.data(), buffer.size()))
    {
        res.fail("E_MEMORY", "cannot read the function at " + hexAddr(start));
        return;
    }
    std::set<long long> offsets;
    Zydis dis;
    duint address = start;
    while(address < end)
    {
        ENCODETYPE ct = DbgGetEncodeTypeAt(address, 1);
        if(!isCodeType(ct)) // data bytes are skipped
        {
            duint step = DbgGetEncodeSizeAt(address, 1);
            address += step ? step : 1;
            continue;
        }
        dis.Disassemble(address, buffer.data() + (address - start), (size_t)(end + 16 - address));
        if(dis.Size() == 0)
        {
            address++;
            continue;
        }
        if(dis.IsNop()) // junk instructions are skipped
        {
            address += dis.Size();
            continue;
        }
        for(int i = 0; i < dis.OpCount(); i++)
        {
            if(dis[i].type != ZYDIS_OPERAND_TYPE_MEMORY)
                continue;
            if(dis[i].mem.base == ZYDIS_REGISTER_NONE) // global variable
                continue;
            if(dis[i].mem.index != ZYDIS_REGISTER_NONE) // indexed array
                continue;
            if(dis[i].mem.base == br->reg)
                offsets.insert((long long)dis[i].mem.disp.value);
        }
        address += dis.Size();
    }
    Json f = Json::object();
    f.set("start", hexAddr(start));
    f.set("end", hexAddr(end));
    d.set("function", f);
    d.set("base", base);
    duint baseValue = evalOr0(base);
    Json list = Json::array();
    for(auto it = offsets.rbegin(); it != offsets.rend(); ++it) // sorted descending like the GUI
    {
        long long j = *it;
        char hexpart[32];
        snprintf(hexpart, sizeof(hexpart), "%llx", (unsigned long long)(j < 0 ? -j : j));
        std::string expr = "[" + base + (j < 0 ? "-0x" : "+0x") + hexpart + "]";
        std::string name;
        if(base == "rbp")
            name = j < 0 ? "Local" + std::to_string(-j / 8) : "Arg" + std::to_string(j / 8 - 1);
        else
            name = (j < 0 ? "_" + base + "_" + hexpart : base + "_" + hexpart);
        duint v = DbgIsValidExpression(expr.c_str()) ? DbgValFromString(expr.c_str()) : 0;
        Json l = Json::object();
        l.set("name", name);
        l.set("expr", expr);
        l.set("offset", j);
        l.set("addr", hexAddr(baseValue + (duint)j));
        l.set("value", hexAddr(v));
        l.set("label", strOrNull(labelAt(v)));
        list.push(l);
    }
    d.set("locals", list);
    res.data = d;
}

// ------------------------------------------------------------------ infobox

void viewInfoBox(Session &, Request & req, Result & res)
{
    duint addr = 0;
    std::string text;
    if(argText(req.args, "addr", text, true))
    {
        if(!evalExpr(res, text, "addr", addr))
            return;
    }
    else
    {
        if(runningNow())
        {
            res.fail("E_RUNNING", "infobox without addr uses cip; pause first or pass addr");
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
    bool haveCip = false;
    duint cip = runningNow() ? 0 : DbgEval("cip", &haveCip);
    DisRow row = decodeRow(addr, coreMemReader(), DisApi::core());
    Json d = Json::object();
    d.set("addr", hexAddr(addr));
    if(row.kind == "branch" && row.truncatedReason.empty())
    {
        std::string t = lower(row.text);
        bool call = t.compare(0, 4, "call") == 0;
        bool conditional = false;
        if(!call)
        {
            char expr[64];
            snprintf(expr, sizeof(expr), "dis.iscond(0x%llx)", (unsigned long long)addr);
            bool ok = false;
            duint v = DbgEval(expr, &ok);
            conditional = ok && v != 0 && (t[0] == 'j' || t.compare(0, 4, "loop") == 0 || t.compare(0, 6, "xbegin") == 0);
        }
        Json j = Json::object();
        j.set("conditional", conditional);
        j.set("taken", haveCip && cip == addr && conditional ? Json(DbgIsJumpGoingToExecute(addr)) : Json());
        d.set("jump", j);
    }
    else
        d.set("jump", nullptr);
    Json operands = Json::array();
    if(row.truncatedReason.empty() && !row.tail)
    {
        DISASM_INSTR di;
        memset(&di, 0, sizeof(di));
        DbgDisasmAt(addr, &di);
        for(int i = 0; i < di.argcount && i < 3; i++)
        {
            const DISASM_ARG & a = di.arg[i];
            bool mem = a.type == arg_memory;
            duint target = mem ? a.memvalue : a.value;
            char str[MAX_STRING_SIZE] = "";
            Json o = Json::object();
            o.set("index", i);
            o.set("text", a.mnemonic);
            o.set("value", hexAddr(a.value));
            o.set("mem_value", mem ? Json(hexAddr(a.memvalue)) : Json());
            o.set("string", DbgGetStringAt(target, str) && str[0] ? Json(str) : Json());
            o.set("label", strOrNull(labelAt(target)));
            operands.push(o);
        }
    }
    d.set("operands", operands);
    const DBGFUNCTIONS* fn = DbgFunctions();
    Json loc = Json::object();
    loc.set("label", strOrNull(labelAt(addr)));
    char mod[MAX_MODULE_SIZE] = "";
    bool haveMod = fn && fn->ModNameFromAddr && fn->ModNameFromAddr(addr, mod, true) && mod[0];
    loc.set("module", haveMod ? Json(mod) : Json());
    char section[MAX_SECTION_SIZE] = "";
    loc.set("section", fn && fn->SectionFromAddr && fn->SectionFromAddr(addr, section) && section[0] ? Json(section) : Json());
    duint modBase = haveMod && fn->ModBaseFromAddr ? fn->ModBaseFromAddr(addr) : 0;
    loc.set("rva", modBase ? Json((unsigned long long)(addr - modBase)) : Json());
    duint fo = modBase && fn->VaToFileOffset ? fn->VaToFileOffset(addr) : 0;
    loc.set("file_offset", fo ? Json((unsigned long long)fo) : Json());
    d.set("location", loc);
    char comment[MAX_COMMENT_SIZE] = "";
    std::string c;
    if(DbgGetCommentAt(addr, comment))
        c = comment[0] == '\1' ? comment + 1 : comment;
    d.set("comment", strOrNull(c));
    char srcFile[MAX_PATH * 2] = "";
    int srcLine = 0;
    if(fn && fn->GetSourceFromAddr && fn->GetSourceFromAddr(addr, srcFile, &srcLine) && srcFile[0])
    {
        Json s = Json::object();
        s.set("file", srcFile);
        s.set("line", srcLine);
        d.set("source", s);
    }
    else
        d.set("source", nullptr);
    res.data = d;
}

// ------------------------------------------------------------------ menu

void viewMenu(Session &, Request & req, Result & res)
{
    std::string action = "list";
    argText(req.args, "action", action, false);
    action = lower(action);
    long long id = 0;
    bool hasId = argInt(req.args, "id", id);
    Host & h = host();
    if(action == "click")
    {
        if(!hasId)
        {
            res.fail("E_BAD_ARG", "menu click requires id");
            return;
        }
        bool entry = false;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            for(auto & m : h.menus)
                if(m.handle == id && m.isEntry && !m.separator)
                    entry = true;
        }
        if(!entry)
        {
            res.fail("E_BAD_ARG", "id " + std::to_string(id) + " is not a menu entry (see menu list)");
            return;
        }
        DbgMenuEntryClicked((int)id);
        Json d = Json::object();
        d.set("menus", Json::array());
        res.data = d;
        return;
    }
    if(action != "list")
    {
        res.fail("E_BAD_ARG", "action must be list or click");
        return;
    }
    if(hasId)
    {
        res.fail("E_BAD_ARG", "menu list does not take id");
        return;
    }
    std::vector<MenuItem> items;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        items = h.menus;
    }
    std::map<int, int> parentOf;
    for(auto & m : items)
        parentOf[m.handle] = m.parent;
    Json arr = Json::array();
    for(auto & m : items)
    {
        int root = m.parent;
        for(int guard = 0; guard < 64 && parentOf.count(root); guard++)
            root = parentOf[root];
        Json j = Json::object();
        j.set("id", m.handle);
        j.set("parent", m.parent);
        j.set("plugin", root);
        j.set("name", m.title);
        j.set("kind", m.separator ? "separator" : m.isEntry ? "entry" : "menu");
        j.set("checked", m.checked);
        j.set("visible", m.visible);
        j.set("hotkey", strOrNull(m.hotkey));
        arr.push(j);
    }
    Json d = Json::object();
    d.set("menus", arr);
    res.data = d;
}

// ------------------------------------------------------------------ config

void viewConfig(Session &, Request & req, Result & res)
{
    std::string action;
    if(!argText(req.args, "action", action, false))
    {
        res.fail("E_BAD_ARG", "config requires action (get|set|init_script)");
        return;
    }
    action = lower(action);
    std::string section, key, value;
    bool hasSection = argText(req.args, "section", section, false);
    bool hasKey = argText(req.args, "key", key, false);
    bool hasValue = argText(req.args, "value", value, false);
    static const std::regex nameRe("^[A-Za-z0-9_ .-]{1,64}$");
    auto checkName = [&](const std::string & s, const char* what) -> bool
    {
        if(!std::regex_match(s, nameRe))
        {
            res.fail("E_BAD_ARG", std::string(what) + " must match ^[A-Za-z0-9_ .-]{1,64}$");
            return false;
        }
        return true;
    };
    auto checkValue = [&]() -> bool
    {
        if(value.size() > 65535 || value.find_first_of(std::string("\r\n\0", 3)) != std::string::npos)
        {
            res.fail("E_BAD_ARG", "value must be at most 65535 bytes without NUL, CR or LF");
            return false;
        }
        return true;
    };
    Json d = Json::object();
    if(action == "get" || action == "set")
    {
        if(!hasSection || !hasKey)
        {
            res.fail("E_BAD_ARG", "config " + action + " requires section and key");
            return;
        }
        if(!checkName(section, "section") || !checkName(key, "key"))
            return;
        if(action == "get")
        {
            if(hasValue)
            {
                res.fail("E_BAD_ARG", "config get does not take value");
                return;
            }
            std::vector<char> buf(MAX_SETTING_SIZE + 1, 0);
            bool found = BridgeSettingGet(section.c_str(), key.c_str(), buf.data());
            d.set("value", found ? Json(std::string(buf.data())) : Json());
        }
        else
        {
            if(!hasValue)
            {
                res.fail("E_BAD_ARG", "config set requires value");
                return;
            }
            if(!checkValue())
                return;
            if(!BridgeSettingSet(section.c_str(), key.c_str(), value.c_str()))
            {
                res.fail("E_COMMAND_FAILED", "the setting could not be stored");
                return;
            }
            DbgSettingsUpdated(); // what the native config command does; without it the engine does not apply the value
            d.set("value", value);
        }
        d.set("section", section);
        d.set("key", key);
    }
    else if(action == "init_script")
    {
        if(hasSection || hasKey)
        {
            res.fail("E_BAD_ARG", "config init_script does not take section or key");
            return;
        }
        const DBGFUNCTIONS* fn = DbgFunctions();
        if(!fn || !fn->DbgGetDebuggeeInitScript || !fn->DbgSetDebuggeeInitScript)
        {
            res.fail("E_UNSUPPORTED", "this core has no initialization script API");
            return;
        }
        if(hasValue)
        {
            if(!checkValue())
                return;
            fn->DbgSetDebuggeeInitScript(value.c_str());
        }
        const char* cur = fn->DbgGetDebuggeeInitScript();
        d.set("section", nullptr);
        d.set("key", nullptr);
        d.set("value", cur && cur[0] ? Json(cur) : Json());
    }
    else
    {
        res.fail("E_BAD_ARG", "action must be get, set or init_script");
        return;
    }
    res.data = d;
}

// ------------------------------------------------------------------ constants, errors, exceptions

namespace
{
void constantList(Result & res, void (*DBGFUNCTIONS::*which)(ListInfo*))
{
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn || !(fn->*which))
    {
        res.fail("E_UNSUPPORTED", "this core has no such list");
        return;
    }
    BridgeList<CONSTANTINFO> list;
    (fn->*which)(&list);
    std::vector<std::pair<std::string, unsigned long long>> items;
    for(int i = 0; i < list.Count(); i++)
        items.emplace_back(list[i].name ? list[i].name : "", (unsigned long long)list[i].value);
    std::sort(items.begin(), items.end());
    Json arr = Json::array();
    for(auto & it : items)
    {
        Json j = Json::object();
        j.set("name", it.first);
        j.set("value", hexAddr(it.second));
        arr.push(j);
    }
    Json d = Json::object();
    d.set("items", arr);
    d.set("count", (long long)arr.items().size());
    res.data = d;
}
}

void viewConstants(Session &, Request &, Result & res)
{
    constantList(res, &DBGFUNCTIONS::EnumConstants);
}

void viewErrors(Session &, Request &, Result & res)
{
    constantList(res, &DBGFUNCTIONS::EnumErrorCodes);
}

void viewExceptions(Session &, Request &, Result & res)
{
    constantList(res, &DBGFUNCTIONS::EnumExceptions);
}

// ------------------------------------------------------------------ format, asm, animate

void viewFormat(Session &, Request & req, Result & res)
{
    std::string tmpl;
    if(!argText(req.args, "template", tmpl, false))
    {
        res.fail("E_BAD_ARG", "format requires template");
        return;
    }
    if(tmpl.size() > 1023)
    {
        res.fail("E_TOO_LONG", "template is longer than 1023 bytes");
        return;
    }
    const DBGFUNCTIONS* fn = DbgFunctions();
    std::vector<char> buf(65536, 0);
    if(!fn || !fn->StringFormatInline || !fn->StringFormatInline(tmpl.c_str(), buf.size(), buf.data()))
    {
        res.fail("E_COMMAND_FAILED", "the template could not be formatted");
        return;
    }
    if(strlen(buf.data()) >= buf.size() - 1)
    {
        res.fail("E_TOO_LONG", "the formatted text fills the 65536-byte buffer");
        return;
    }
    Json d = Json::object();
    d.set("text", std::string(buf.data()));
    res.data = d;
}

void viewAsm(Session &, Request & req, Result & res)
{
    std::string addrText, text;
    if(!argText(req.args, "addr", addrText, true) || !argText(req.args, "text", text, false))
    {
        res.fail("E_BAD_ARG", "asm requires addr and text");
        return;
    }
    if(trim(text).empty() || text.size() > 255 || text.find_first_of("\r\n") != std::string::npos)
    {
        res.fail("E_BAD_ARG", "text must be one instruction of at most 255 bytes");
        return;
    }
    duint addr = 0;
    if(!evalExpr(res, addrText, "addr", addr))
        return;
    bool fill = argBool(req.args, "fill_nops", true);
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn || !fn->AssembleAtEx || !fn->Assemble)
    {
        res.fail("E_UNSUPPORTED", "this core has no assembler API");
        return;
    }
    unsigned char bytes[16] = {};
    int size = 0;
    char error[MAX_ERROR_SIZE] = "";
    if(!fn->Assemble(addr, bytes, &size, text.c_str(), error) || size <= 0 || size > 16)
    {
        res.fail("E_COMMAND_FAILED", std::string("assembler: ") + (error[0] ? error : "failed"));
        return;
    }
    error[0] = 0;
    if(!fn->AssembleAtEx(addr, text.c_str(), error, fill))
    {
        res.fail("E_COMMAND_FAILED", std::string("assembler: ") + (error[0] ? error : "failed"));
        return;
    }
    Json d = Json::object();
    d.set("addr", hexAddr(addr));
    d.set("size", size);
    d.set("bytes", bytesToHex(bytes, (size_t)size));
    res.data = d;
}

void viewAnimate(Session &, Request & req, Result & res)
{
    std::string command;
    if(!argText(req.args, "command", command, false) || trim(command).empty() || command.find_first_of("\r\n") != std::string::npos)
    {
        res.fail("E_BAD_ARG", "animate requires command (one native command line, for example StepInto)");
        return;
    }
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(!fn || !fn->AnimateCommand || !fn->AnimateCommand(command.c_str()))
    {
        res.fail("E_COMMAND_FAILED", "the animation could not be started");
        return;
    }
    res.data = Json();
}

// ------------------------------------------------------------------ favourites

void viewFavourites(Session &, Request &, Result & res)
{
    Host & h = host();
    Json tools = Json::array(), cmds = Json::array();
    {
        std::lock_guard<std::mutex> lk(h.mu);
        for(auto & t : h.favouriteTools)
        {
            Json j = Json::object();
            j.set("path", t.first);
            j.set("description", t.second);
            tools.push(j);
        }
        for(auto & c : h.favouriteCommands)
        {
            Json j = Json::object();
            j.set("command", c.first);
            j.set("shortcut", c.second);
            cmds.push(j);
        }
    }
    Json d = Json::object();
    d.set("tools", tools);
    d.set("commands", cmds);
    res.data = d;
}

// ------------------------------------------------------------------ module

void viewModule(Session & s, Request & req, Result & res)
{
    std::string action;
    if(!argText(req.args, "action", action, false))
    {
        res.fail("E_BAD_ARG", "module requires action (set_party|loadlib|freelib|symdownload|symload|symunload)");
        return;
    }
    action = lower(action);
    struct Rule
    {
        const char* action;
        const char* required;
        const char* optional;
    } rules[] =
    {
        { "set_party", "module party", "" },
        { "loadlib", "module", "" },
        { "freelib", "module", "" },
        { "symdownload", "", "module" },
        { "symload", "module path", "" },
        { "symunload", "module", "" },
    };
    const Rule* rule = nullptr;
    for(auto & r : rules)
        if(action == r.action)
            rule = &r;
    if(!rule)
    {
        res.fail("E_BAD_ARG", "action must be set_party, loadlib, freelib, symdownload, symload or symunload");
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
        if(!listed(rule->required, m.first) && !listed(rule->optional, m.first))
        {
            res.fail("E_BAD_ARG", "module " + action + " does not take " + m.first);
            return;
        }
    }
    std::string module, path, party;
    bool hasModule = argText(req.args, "module", module, true);
    bool hasPath = argText(req.args, "path", path, false);
    bool hasParty = argText(req.args, "party", party, false);
    for(const char* k : { "module", "path", "party" })
    {
        bool has = std::string(k) == "module" ? hasModule : std::string(k) == "path" ? hasPath : hasParty;
        if(listed(rule->required, k) && !has)
        {
            res.fail("E_BAD_ARG", "module " + action + " requires " + k);
            return;
        }
    }
    auto oneLine = [&](const std::string & v, const char* what) -> bool
    {
        if(trim(v).empty() || v.find_first_of(std::string("\r\n\0", 3)) != std::string::npos)
        {
            res.fail("E_BAD_ARG", std::string(what) + " must be a non-empty single line");
            return false;
        }
        return true;
    };
    if(hasModule && !oneLine(module, "module"))
        return;
    if(hasPath && !oneLine(path, "path"))
        return;
    const DBGFUNCTIONS* fn = DbgFunctions();
    if(action == "set_party")
    {
        std::string p = lower(party);
        if(p != "user" && p != "system")
        {
            res.fail("E_BAD_ARG", "party must be user or system");
            return;
        }
        duint addr = 0;
        if(!evalExpr(res, module, "module", addr))
            return;
        duint base = fn && fn->ModBaseFromAddr ? fn->ModBaseFromAddr(addr) : 0;
        if(!base)
        {
            res.fail("E_BAD_ARG", "module does not point into a loaded module: " + module);
            return;
        }
        fn->ModSetParty(base, p == "system" ? mod_system : mod_user);
        res.data = Json();
        return;
    }
    std::string line;
    if(action == "loadlib")
        line = "loadlib \"" + commandEscape(module) + "\"";
    else if(action == "freelib")
    {
        if(module.find_first_of(",;\"") != std::string::npos)
        {
            res.fail("E_BAD_ARG", "module must be one address expression");
            return;
        }
        line = "freelib " + trim(module);
    }
    else if(action == "symdownload")
        line = hasModule ? "symdownload \"" + commandEscape(module) + "\"" : "symdownload";
    else if(action == "symload")
        line = "symload \"" + commandEscape(module) + "\",\"" + commandEscape(path) + "\"";
    else
        line = "symunload \"" + commandEscape(module) + "\"";
    s.execLine(req, res, line);
    res.data = Json();
}
}
