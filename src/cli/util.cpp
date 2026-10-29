#include "util.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <Windows.h>

namespace cli
{
std::string hexAddr(unsigned long long v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%016llx", v);
    return buf;
}

std::string hexArg(long long v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return buf;
}

std::string trim(const std::string & s)
{
    size_t b = 0, e = s.size();
    while(b < e && (s[b] == ' ' || s[b] == '\t'))
        b++;
    while(e > b && (s[e - 1] == ' ' || s[e - 1] == '\t'))
        e--;
    return s.substr(b, e - b);
}

std::string lower(const std::string & s)
{
    std::string r = s;
    for(auto & c : r)
        c = (char)tolower((unsigned char)c);
    return r;
}

bool startsWith(const std::string & s, const char* prefix)
{
    return s.compare(0, strlen(prefix), prefix) == 0;
}

std::vector<std::string> splitSemicolon(const std::string & s)
{
    std::vector<std::string> out;
    bool inquote = false, inescape = false;
    std::string cur;
    for(char ch : s)
    {
        switch(ch)
        {
        case '"':
            if(!inescape)
                inquote = !inquote;
            inescape = false;
            break;
        case '\\':
            inescape = !inescape;
            break;
        default:
            inescape = false;
        }
        if(ch == ';' && !inquote)
        {
            if(!cur.empty())
                out.push_back(cur);
            cur.clear();
        }
        else
            cur.push_back(ch);
    }
    if(!cur.empty())
        out.push_back(cur);
    return out;
}

bool tokenize(const std::string & s, std::vector<std::string> & out, std::string & error)
{
    out.clear();
    std::string cur;
    bool have = false, inquote = false;
    for(size_t i = 0; i < s.size(); i++)
    {
        char c = s[i];
        if(c == '\\' && i + 1 < s.size() && s[i + 1] == '"')
        {
            cur += '"';
            have = true;
            i++;
            continue;
        }
        if(c == '"')
        {
            inquote = !inquote;
            have = true;
            continue;
        }
        if(!inquote && (c == ' ' || c == '\t'))
        {
            if(have)
                out.push_back(cur);
            cur.clear();
            have = false;
            continue;
        }
        cur += c;
        have = true;
    }
    if(inquote)
    {
        error = "unterminated double quote";
        return false;
    }
    if(have)
        out.push_back(cur);
    return true;
}

std::string stripHtml(const std::string & s)
{
    std::string out;
    out.reserve(s.size());
    for(size_t i = 0; i < s.size();)
    {
        char c = s[i];
        if(c == '<' && i + 1 < s.size() && (isalpha((unsigned char)s[i + 1]) || s[i + 1] == '/' || s[i + 1] == '!'))
        {
            size_t e = s.find('>', i);
            if(e != std::string::npos)
            {
                std::string tag = lower(s.substr(i + 1, e - i - 1));
                if(tag == "br" || tag == "br/" || tag == "br /" || tag == "/p" || tag == "/div")
                    out += '\n';
                i = e + 1;
                continue;
            }
        }
        if(c == '&')
        {
            static const struct
            {
                const char* ent;
                const char* rep;
            } ents[] =
            {
                { "&lt;", "<" }, { "&gt;", ">" }, { "&amp;", "&" }, { "&quot;", "\"" }, { "&nbsp;", " " }
            };
            bool done = false;
            for(auto & e : ents)
            {
                size_t n = strlen(e.ent);
                if(s.compare(i, n, e.ent) == 0)
                {
                    out += e.rep;
                    i += n;
                    done = true;
                    break;
                }
            }
            if(done)
                continue;
        }
        out += c;
        i++;
    }
    return out;
}

std::string escapeControlText(const std::string & s)
{
    std::string out;
    out.reserve(s.size());
    for(size_t i = 0; i < s.size(); i++)
    {
        unsigned char c = (unsigned char)s[i];
        if(c == '\r' && i + 1 < s.size() && s[i + 1] == '\n')
            continue;
        if((c < 0x20 && c != '\n' && c != '\t') || c == 0x7f)
        {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\x%02x", c);
            out += buf;
        }
        else
            out += (char)c;
    }
    return out;
}

std::string joinTargetArgs(const std::vector<std::string> & args)
{
    std::string out;
    for(size_t k = 0; k < args.size(); k++)
    {
        const std::string & a = args[k];
        if(k)
            out += ' ';
        bool plain = !a.empty() && a.find_first_of(" \t\"") == std::string::npos;
        if(plain)
        {
            out += a;
            continue;
        }
        out += '"';
        size_t bs = 0;
        for(char c : a)
        {
            if(c == '\\')
            {
                bs++;
                continue;
            }
            if(c == '"')
            {
                out.append(bs * 2 + 1, '\\');
                out += '"';
            }
            else
            {
                out.append(bs, '\\');
                out += c;
            }
            bs = 0;
        }
        out.append(bs * 2, '\\');
        out += '"';
    }
    return out;
}

bool parseInteger(const std::string & s, long long & out)
{
    if(s.empty())
        return false;
    int base = 10;
    size_t i = 0;
    if(s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        base = 16;
        i = 2;
    }
    for(size_t k = i; k < s.size(); k++)
        if(!(base == 16 ? isxdigit((unsigned char)s[k]) : isdigit((unsigned char)s[k])))
            return false;
    if(s.size() - i > (base == 16 ? 15u : 18u))
        return false;
    out = strtoll(s.c_str() + i, nullptr, base);
    return true;
}

std::string firstWord(const std::string & segment)
{
    std::string t = trim(segment);
    size_t e = t.find_first_of(" \t,");
    return e == std::string::npos ? t : t.substr(0, e);
}

std::string commandEscape(const std::string & s)
{
    std::string out;
    size_t bs = 0;
    for(char c : s)
    {
        if(c == '\\')
        {
            bs++;
            continue;
        }
        if(c == '"' || c == '{')
        {
            out.append(bs * 2, '\\');
            out += '\\';
            out += c;
        }
        else
        {
            out.append(bs, '\\');
            out += c;
        }
        bs = 0;
    }
    out.append(bs * 2, '\\');
    return out;
}

std::string utf8Of(const wchar_t* w)
{
    if(!w)
        return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if(n <= 1)
        return std::string();
    std::string r(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &r[0], n, nullptr, nullptr);
    return r;
}

std::wstring wideOf(const std::string & s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if(n <= 0)
        return std::wstring();
    std::wstring r(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &r[0], n);
    return r;
}
}
