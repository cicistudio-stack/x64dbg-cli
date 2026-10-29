#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "util.h"
#include "views.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace cli
{
namespace
{
struct Format
{
    const char* name;
    int elem; // bytes per item, 0 = no items (hex)
};

const Format kFormats[] =
{
    { "hex", 0 }, { "ascii", 1 }, { "utf16", 2 }, { "int8", 1 }, { "int16", 2 }, { "int32", 4 }, { "int64", 8 },
    { "uint8", 1 }, { "uint16", 2 }, { "uint32", 4 }, { "uint64", 8 }, { "hex8", 1 }, { "hex16", 2 }, { "hex32", 4 }, { "hex64", 8 },
    { "float", 4 }, { "double", 8 }, { "half", 2 }, { "ldouble", 10 }, { "ptr", 8 }
};

std::string unicodeEscape(unsigned v, int digits)
{
    char b[16];
    snprintf(b, sizeof(b), "\\u%0*x", digits, v);
    return b;
}

std::string charValue(unsigned v, bool wide)
{
    if(v >= 0x20 && v < 0x7f)
        return std::string(1, (char)v);
    if(!wide || v < 0xa0 || (v >= 0xd800 && v < 0xe000))
        return unicodeEscape(v, 4);
    wchar_t w = (wchar_t)v;
    char u8[8] = {};
    int n = WideCharToMultiByte(CP_UTF8, 0, &w, 1, u8, sizeof(u8), nullptr, nullptr);
    return n > 0 ? std::string(u8, (size_t)n) : unicodeEscape(v, 4);
}

std::string itemText(const std::string & fmt, const unsigned char* p)
{
    char b[48];
    if(fmt == "ascii")
        return charValue(p[0], false);
    if(fmt == "utf16")
        return charValue((unsigned)(p[0] | (p[1] << 8)), true);
    if(fmt == "int8")
        return std::to_string((int)(signed char)p[0]);
    if(fmt == "uint8")
        return std::to_string((int)p[0]);
    if(fmt == "int16" || fmt == "uint16" || fmt == "hex16")
    {
        unsigned short v;
        memcpy(&v, p, 2);
        if(fmt == "int16")
            return std::to_string((int)(short)v);
        if(fmt == "uint16")
            return std::to_string((unsigned)v);
        return hexN(v, 4);
    }
    if(fmt == "int32" || fmt == "uint32" || fmt == "hex32")
    {
        unsigned v;
        memcpy(&v, p, 4);
        if(fmt == "int32")
            return std::to_string((int)v);
        if(fmt == "uint32")
            return std::to_string(v);
        return hexN(v, 8);
    }
    if(fmt == "int64" || fmt == "uint64" || fmt == "hex64" || fmt == "ptr")
    {
        unsigned long long v;
        memcpy(&v, p, 8);
        if(fmt == "int64")
            return std::to_string((long long)v);
        if(fmt == "uint64")
            return std::to_string(v);
        return hexN(v, 16);
    }
    if(fmt == "hex8")
        return hexN(p[0], 2);
    if(fmt == "float")
    {
        float f;
        memcpy(&f, p, 4);
        return shortestFloat(f);
    }
    if(fmt == "double")
    {
        double f;
        memcpy(&f, p, 8);
        return shortestDouble(f);
    }
    if(fmt == "half")
    {
        unsigned short h;
        memcpy(&h, p, 2);
        return shortestFloat((float)halfToDouble(h));
    }
    if(fmt == "ldouble")
        return shortestDouble(extendedToDouble(p));
    snprintf(b, sizeof(b), "?");
    return b;
}
}

void viewMem(Session &, Request & req, Result & res)
{
    std::string addrText;
    if(!argText(req.args, "addr", addrText, true))
    {
        res.fail("E_BAD_ARG", "mem requires addr (usage: mem <addr> [-n size] [--format f] [--cols n])");
        return;
    }
    duint addr = 0;
    if(!evalExpr(res, addrText, "addr", addr))
        return;
    long long size = 256, cols = 16;
    argInt(req.args, "size", size);
    argInt(req.args, "cols", cols);
    if(size < 1 || size > 1048576)
    {
        res.fail("E_BAD_ARG", "size must be in 1..1048576 (the maximum is 1 MiB)");
        return;
    }
    if(cols < 1 || cols > 64)
    {
        res.fail("E_BAD_ARG", "cols must be in 1..64");
        return;
    }
    std::string fmt = "hex";
    argText(req.args, "format", fmt, false);
    fmt = lower(fmt);
    const Format* f = nullptr;
    for(auto & e : kFormats)
        if(fmt == e.name)
            f = &e;
    if(!f)
    {
        res.fail("E_BAD_ARG", "unknown format '" + fmt + "' (hex, ascii, utf16, int8..int64, uint8..uint64, hex8..hex64, float, double, half, ldouble, ptr)");
        return;
    }
    // about 7 JSON bytes per data byte, about 52 bytes of row overhead per `cols` data bytes and about 48 per item
    // (design 9.4), plus 4 KiB for the envelope: clamp to max_response_bytes
    long long perByte = 7 + 52 / cols + 1 + (f->elem ? 48 / f->elem + 1 : 0);
    long long maxSize = std::max<long long>(1, (req.opt.maxResponseBytes - 4096) / perByte);
    bool truncated = false;
    if(size > maxSize)
    {
        size = maxSize;
        truncated = true;
    }
    bool live = isLive();

    std::vector<unsigned char> buf((size_t)size, 0);
    std::vector<char> bad((size_t)size, 0);
    Json unreadable = Json::array();
    if(!DbgMemRead(addr, buf.data(), (duint)size))
    {
        // page by page
        size_t done = 0;
        size_t badStart = 0;
        bool inBad = false;
        auto closeBad = [&](size_t end)
        {
            if(!inBad)
                return;
            Json u = Json::object();
            u.set("addr", hexAddr(addr + badStart));
            u.set("size", (long long)(end - badStart));
            unreadable.push(u);
            inBad = false;
        };
        while(done < (size_t)size)
        {
            duint cur = addr + done;
            size_t chunk = (size_t)std::min<unsigned long long>(size - done, 0x1000 - (cur & 0xfff));
            bool ok = DbgMemIsValidReadPtr(cur) && DbgMemRead(cur, buf.data() + done, (duint)chunk);
            if(ok)
                closeBad(done);
            else
            {
                memset(buf.data() + done, 0, chunk);
                memset(bad.data() + done, 1, chunk);
                if(!inBad)
                {
                    inBad = true;
                    badStart = done;
                }
            }
            done += chunk;
        }
        closeBad((size_t)size);
        if(std::all_of(bad.begin(), bad.end(), [](char c) { return c != 0; }))
        {
            res.fail("E_MEMORY", "cannot read memory at " + hexAddr(addr));
            return;
        }
    }

    Json d = Json::object();
    d.set("addr", hexAddr(addr));
    d.set("size", (long long)size);
    d.set("format", fmt);
    d.set("live", live);
    d.set("module", strOrNull(moduleAt(addr)));
    char section[MAX_SECTION_SIZE] = "";
    const DBGFUNCTIONS* fn = DbgFunctions();
    d.set("section", fn && fn->SectionFromAddr && fn->SectionFromAddr(addr, section) && section[0] ? Json(section) : Json());
    d.set("label", strOrNull(labelAt(addr)));
    d.set("hex", bytesToHex(buf.data(), buf.size()));
    std::string ascii;
    for(unsigned char c : buf)
        ascii += (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    d.set("ascii", ascii);
    Json rows = Json::array();
    for(size_t off = 0; off < buf.size(); off += (size_t)cols)
    {
        size_t n = std::min<size_t>((size_t)cols, buf.size() - off);
        std::string hex;
        for(size_t i = 0; i < n; i++)
            hex += (i ? " " : "") + bytesToHex(&buf[off + i], 1);
        Json r = Json::object();
        r.set("addr", hexAddr(addr + off));
        r.set("hex", hex);
        r.set("ascii", ascii.substr(off, n));
        rows.push(r);
    }
    d.set("rows", rows);
    Json items = Json::array();
    if(f->elem)
    {
        for(size_t off = 0; off + (size_t)f->elem <= buf.size(); off += (size_t)f->elem)
        {
            bool skip = false;
            for(int k = 0; k < f->elem; k++)
                skip = skip || bad[off + (size_t)k];
            if(skip)
                continue;
            Json it = Json::object();
            it.set("addr", hexAddr(addr + off));
            it.set("value", itemText(fmt, &buf[off]));
            if(fmt == "ptr")
            {
                unsigned long long v;
                memcpy(&v, &buf[off], 8);
                it.set("label", strOrNull(labelAt((duint)v)));
            }
            items.push(it);
        }
    }
    d.set("items", items);
    d.set("unreadable", unreadable);
    d.set("truncated", truncated);
    d.set("next_addr", truncated ? Json(hexAddr(addr + (duint)size)) : Json());
    res.data = d;
}

void viewMemWrite(Session &, Request & req, Result & res)
{
    std::string addrText;
    if(!argText(req.args, "addr", addrText, true))
    {
        res.fail("E_BAD_ARG", "memwrite requires addr");
        return;
    }
    int sources = 0;
    for(const char* k : { "hex", "ascii", "utf16", "file" })
        if(req.args.find(k))
            sources++;
    if(sources != 1)
    {
        res.fail("E_BAD_ARG", "give exactly one of hex, ascii, utf16, file");
        return;
    }
    duint addr = 0;
    if(!evalExpr(res, addrText, "addr", addr))
        return;
    const size_t inlineMax = 64 * 1024;
    std::vector<unsigned char> data;
    std::string text, err;
    if(argText(req.args, "hex", text, false))
    {
        if(!parseHexBytes(text, data, err, inlineMax))
        {
            res.fail("E_BAD_ARG", "hex: " + err);
            return;
        }
    }
    else if(argText(req.args, "ascii", text, false))
    {
        for(unsigned char c : text)
            if(c >= 0x80)
            {
                res.fail("E_BAD_ARG", "ascii must contain only characters below 0x80 (use utf16 or hex)");
                return;
            }
        data.assign(text.begin(), text.end());
        if(data.empty() || data.size() > inlineMax)
        {
            res.fail("E_BAD_ARG", "ascii must be 1.." + std::to_string(inlineMax) + " bytes");
            return;
        }
    }
    else if(argText(req.args, "utf16", text, false))
    {
        std::wstring w = wideOf(text);
        if(w.empty() || w.size() * 2 > inlineMax)
        {
            res.fail("E_BAD_ARG", "utf16 must be 1.." + std::to_string(inlineMax / 2) + " characters");
            return;
        }
        data.resize(w.size() * 2);
        memcpy(data.data(), w.data(), data.size());
    }
    bool patch = argBool(req.args, "patch", true);
    const DBGFUNCTIONS* fn = DbgFunctions();
    auto write = [&](duint va, const unsigned char* p, size_t n) -> bool
    {
        if(patch)
            return fn && fn->MemPatch && fn->MemPatch(va, p, (duint)n);
        return DbgMemWrite(va, p, (duint)n);
    };
    unsigned long long written = 0;
    if(!argText(req.args, "file", text, false))
    {
        if(!write(addr, data.data(), data.size()))
        {
            res.fail("E_MEMORY", "cannot write " + std::to_string(data.size()) + " bytes at " + hexAddr(addr));
            return;
        }
        written = data.size();
    }
    else
    {
        std::ifstream in(wideOf(text), std::ios::binary);
        if(!in)
        {
            res.fail("E_BAD_ARG", "cannot open file " + text);
            return;
        }
        in.seekg(0, std::ios::end);
        std::streamoff len = in.tellg();
        in.seekg(0, std::ios::beg);
        if(len <= 0 || len > 16 * 1024 * 1024)
        {
            res.fail("E_BAD_ARG", "the file must be 1 byte to 16 MiB");
            return;
        }
        std::vector<unsigned char> chunk(64 * 1024);
        while(written < (unsigned long long)len)
        {
            size_t n = (size_t)std::min<unsigned long long>(chunk.size(), (unsigned long long)len - written);
            in.read((char*)chunk.data(), (std::streamsize)n);
            if((size_t)in.gcount() != n || !write(addr + (duint)written, chunk.data(), n))
            {
                res.fail("E_MEMORY", "write failed after " + std::to_string(written) + " bytes at " + hexAddr(addr + (duint)written));
                return;
            }
            written += n;
        }
    }
    Json d = Json::object();
    d.set("addr", hexAddr(addr));
    d.set("written", written);
    d.set("patched", patch);
    res.data = d;
}

void viewMemMap(Session &, Request & req, Result & res)
{
    std::string filter;
    argText(req.args, "filter", filter, true);
    std::string lowFilter = lower(filter);
    bool haveAddr = false;
    duint filterAddr = 0;
    if(!filter.empty() && DbgIsValidExpression(filter.c_str()))
        filterAddr = DbgEval(filter.c_str(), &haveAddr);
    MEMMAP map;
    memset(&map, 0, sizeof(map));
    if(!DbgMemMap(&map))
    {
        res.fail("E_COMMAND_FAILED", "the memory map is not available");
        return;
    }
    BridgeBuf<MEMPAGE> guard;
    guard.p = map.page;
    const DBGFUNCTIONS* fn = DbgFunctions();
    Json pages = Json::array();
    for(int i = 0; i < map.count; i++)
    {
        const MEMPAGE & pg = map.page[i];
        duint base = (duint)pg.mbi.BaseAddress;
        duint size = (duint)pg.mbi.RegionSize;
        if(!filter.empty())
        {
            bool match = lower(pg.info).find(lowFilter) != std::string::npos || lower(moduleAt(base)).find(lowFilter) != std::string::npos;
            if(haveAddr && filterAddr >= base && filterAddr < base + size)
                match = true;
            if(!match)
                continue;
        }
        Json p = Json::object();
        p.set("base", hexAddr(base));
        p.set("size", (unsigned long long)size);
        p.set("state", pg.mbi.State == MEM_COMMIT ? "commit" : pg.mbi.State == MEM_RESERVE ? "reserve" : "free");
        p.set("type", pg.mbi.Type == MEM_IMAGE ? "image" : pg.mbi.Type == MEM_MAPPED ? "mapped" : "private");
        char rights[RIGHTS_STRING_SIZE + 4] = "";
        if(fn && fn->PageRightsToString)
            fn->PageRightsToString(pg.mbi.Protect, rights);
        p.set("protect", rights);
        p.set("alloc_base", hexAddr((duint)pg.mbi.AllocationBase));
        char arights[RIGHTS_STRING_SIZE + 4] = "";
        if(fn && fn->PageRightsToString)
            fn->PageRightsToString(pg.mbi.AllocationProtect, arights);
        p.set("alloc_protect", arights);
        p.set("info", pg.info);
        p.set("module", strOrNull(moduleAt(base)));
        char section[MAX_SECTION_SIZE] = "";
        p.set("section", fn && fn->SectionFromAddr && fn->SectionFromAddr(base, section) && section[0] ? Json(section) : Json());
        pages.push(p);
    }
    Json d = Json::object();
    d.set("pages", pages);
    d.set("count", (long long)pages.items().size());
    res.data = d;
}
}
