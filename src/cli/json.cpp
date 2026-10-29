#include "json.h"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace cli
{
// Returns the length of the valid UTF-8 sequence at s[i], or 0 when invalid.
static size_t utf8SeqLen(const std::string & s, size_t i)
{
    unsigned char c = (unsigned char)s[i];
    size_t n = s.size() - i;
    if(c < 0x80)
        return 1;
    if(c >= 0xC2 && c <= 0xDF)
    {
        if(n >= 2 && ((unsigned char)s[i + 1] & 0xC0) == 0x80)
            return 2;
        return 0;
    }
    if(c >= 0xE0 && c <= 0xEF)
    {
        if(n < 3)
            return 0;
        unsigned char c1 = (unsigned char)s[i + 1], c2 = (unsigned char)s[i + 2];
        if((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80)
            return 0;
        if(c == 0xE0 && c1 < 0xA0)
            return 0;
        if(c == 0xED && c1 >= 0xA0)
            return 0;
        return 3;
    }
    if(c >= 0xF0 && c <= 0xF4)
    {
        if(n < 4)
            return 0;
        unsigned char c1 = (unsigned char)s[i + 1], c2 = (unsigned char)s[i + 2], c3 = (unsigned char)s[i + 3];
        if((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80)
            return 0;
        if(c == 0xF0 && c1 < 0x90)
            return 0;
        if(c == 0xF4 && c1 >= 0x90)
            return 0;
        return 4;
    }
    return 0;
}

std::string sanitizeUtf8(const std::string & s)
{
    std::string out;
    out.reserve(s.size());
    for(size_t i = 0; i < s.size();)
    {
        size_t len = utf8SeqLen(s, i);
        if(len == 0)
        {
            out += "\xEF\xBF\xBD";
            i++;
        }
        else
        {
            out.append(s, i, len);
            i += len;
        }
    }
    return out;
}

void jsonQuote(const std::string & s, std::string & out)
{
    out += '"';
    for(size_t i = 0; i < s.size();)
    {
        unsigned char c = (unsigned char)s[i];
        if(c >= 0x80)
        {
            size_t len = utf8SeqLen(s, i);
            if(len == 0)
            {
                out += "\xEF\xBF\xBD";
                i++;
            }
            else
            {
                out.append(s, i, len);
                i += len;
            }
            continue;
        }
        i++;
        switch(c)
        {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if(c < 0x20 || c == 0x7f)
            {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else
                out += (char)c;
        }
    }
    out += '"';
}

Json & Json::set(const std::string & key, Json value)
{
    if(type_ != Object)
    {
        *this = Json::object();
    }
    for(auto & m : members_)
    {
        if(m.first == key)
        {
            m.second = std::move(value);
            return *this;
        }
    }
    members_.emplace_back(key, std::move(value));
    return *this;
}

const Json* Json::find(const std::string & key) const
{
    for(auto & m : members_)
        if(m.first == key)
            return &m.second;
    return nullptr;
}

Json* Json::find(const std::string & key)
{
    for(auto & m : members_)
        if(m.first == key)
            return &m.second;
    return nullptr;
}

bool Json::erase(const std::string & key)
{
    for(size_t i = 0; i < members_.size(); i++)
    {
        if(members_[i].first == key)
        {
            members_.erase(members_.begin() + i);
            return true;
        }
    }
    return false;
}

Json & Json::push(Json value)
{
    if(type_ != Array)
        *this = Json::array();
    items_.push_back(std::move(value));
    return *this;
}

void Json::dumpTo(std::string & out) const
{
    switch(type_)
    {
    case Null:
        out += "null";
        break;
    case Bool:
        out += i_ ? "true" : "false";
        break;
    case Int:
        out += std::to_string(i_);
        break;
    case Real:
    {
        if(std::isfinite(d_))
        {
            char buf[40];
            snprintf(buf, sizeof(buf), "%.15g", d_);
            out += buf;
        }
        else
            out += "null";
    }
    break;
    case String:
        jsonQuote(s_, out);
        break;
    case Array:
    {
        out += '[';
        bool first = true;
        for(auto & v : items_)
        {
            if(!first)
                out += ',';
            first = false;
            v.dumpTo(out);
        }
        out += ']';
    }
    break;
    case Object:
    {
        out += '{';
        bool first = true;
        for(auto & m : members_)
        {
            if(!first)
                out += ',';
            first = false;
            jsonQuote(m.first, out);
            out += ':';
            m.second.dumpTo(out);
        }
        out += '}';
    }
    break;
    }
}

std::string Json::dump() const
{
    std::string out;
    dumpTo(out);
    return out;
}

namespace
{
struct Parser
{
    const std::string & s;
    size_t pos = 0;
    int maxDepth;
    std::string err;

    Parser(const std::string & text, int depth) : s(text), maxDepth(depth) {}

    bool fail(const std::string & msg)
    {
        if(err.empty())
            err = msg + " at position " + std::to_string(pos);
        return false;
    }

    void ws()
    {
        while(pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\r' || s[pos] == '\n'))
            pos++;
    }

    static void appendUtf8(std::string & out, unsigned cp)
    {
        if(cp < 0x80)
            out += (char)cp;
        else if(cp < 0x800)
        {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        }
        else if(cp < 0x10000)
        {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
        else
        {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }

    bool hex4(unsigned & v)
    {
        if(pos + 4 > s.size())
            return fail("bad \\u escape");
        v = 0;
        for(int k = 0; k < 4; k++)
        {
            char c = s[pos++];
            v <<= 4;
            if(c >= '0' && c <= '9')
                v |= c - '0';
            else if(c >= 'a' && c <= 'f')
                v |= c - 'a' + 10;
            else if(c >= 'A' && c <= 'F')
                v |= c - 'A' + 10;
            else
                return fail("bad \\u escape");
        }
        return true;
    }

    bool str(std::string & out)
    {
        // s[pos] == '"'
        pos++;
        std::string raw;
        while(true)
        {
            if(pos >= s.size())
                return fail("unterminated string");
            char c = s[pos++];
            if(c == '"')
                break;
            if((unsigned char)c < 0x20)
                return fail("control character in string");
            if(c != '\\')
            {
                raw += c;
                continue;
            }
            if(pos >= s.size())
                return fail("unterminated escape");
            char e = s[pos++];
            switch(e)
            {
            case '"':
                raw += '"';
                break;
            case '\\':
                raw += '\\';
                break;
            case '/':
                raw += '/';
                break;
            case 'b':
                raw += '\b';
                break;
            case 'f':
                raw += '\f';
                break;
            case 'n':
                raw += '\n';
                break;
            case 'r':
                raw += '\r';
                break;
            case 't':
                raw += '\t';
                break;
            case 'u':
            {
                unsigned cp;
                if(!hex4(cp))
                    return false;
                if(cp >= 0xD800 && cp < 0xDC00)
                {
                    unsigned lo = 0;
                    if(pos + 1 < s.size() && s[pos] == '\\' && s[pos + 1] == 'u')
                    {
                        pos += 2;
                        if(!hex4(lo))
                            return false;
                        if(lo >= 0xDC00 && lo < 0xE000)
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        else
                            cp = 0xFFFD;
                    }
                    else
                        cp = 0xFFFD;
                }
                else if(cp >= 0xDC00 && cp < 0xE000)
                    cp = 0xFFFD;
                appendUtf8(raw, cp);
            }
            break;
            default:
                return fail("bad escape");
            }
        }
        out = sanitizeUtf8(raw);
        return true;
    }

    bool value(Json & out, int depth)
    {
        ws();
        if(pos >= s.size())
            return fail("unexpected end of input");
        char c = s[pos];
        if(c == '{' || c == '[')
        {
            if(depth >= maxDepth)
                return fail("nesting too deep");
            if(c == '{')
                return object(out, depth + 1);
            return array(out, depth + 1);
        }
        if(c == '"')
        {
            std::string t;
            if(!str(t))
                return false;
            out = Json(std::move(t));
            return true;
        }
        if(s.compare(pos, 4, "true") == 0)
        {
            pos += 4;
            out = Json(true);
            return true;
        }
        if(s.compare(pos, 5, "false") == 0)
        {
            pos += 5;
            out = Json(false);
            return true;
        }
        if(s.compare(pos, 4, "null") == 0)
        {
            pos += 4;
            out = Json();
            return true;
        }
        if(c == '-' || (c >= '0' && c <= '9'))
            return number(out);
        return fail("unexpected character");
    }

    bool number(Json & out)
    {
        size_t start = pos;
        if(s[pos] == '-')
            pos++;
        size_t digits = 0;
        while(pos < s.size() && s[pos] >= '0' && s[pos] <= '9')
        {
            pos++;
            digits++;
        }
        if(digits == 0)
            return fail("bad number");
        bool real = false;
        if(pos < s.size() && s[pos] == '.')
        {
            real = true;
            pos++;
            size_t fd = 0;
            while(pos < s.size() && s[pos] >= '0' && s[pos] <= '9')
            {
                pos++;
                fd++;
            }
            if(fd == 0)
                return fail("bad number");
        }
        if(pos < s.size() && (s[pos] == 'e' || s[pos] == 'E'))
        {
            real = true;
            pos++;
            if(pos < s.size() && (s[pos] == '+' || s[pos] == '-'))
                pos++;
            size_t ed = 0;
            while(pos < s.size() && s[pos] >= '0' && s[pos] <= '9')
            {
                pos++;
                ed++;
            }
            if(ed == 0)
                return fail("bad number");
        }
        std::string text = s.substr(start, pos - start);
        if(!real)
        {
            errno = 0;
            char* end = nullptr;
            long long v = strtoll(text.c_str(), &end, 10);
            if(errno == ERANGE)
            {
                out = Json(strtod(text.c_str(), nullptr));
                return true;
            }
            out = Json(v);
            return true;
        }
        out = Json(strtod(text.c_str(), nullptr));
        return true;
    }

    bool array(Json & out, int depth)
    {
        pos++;
        out = Json::array();
        ws();
        if(pos < s.size() && s[pos] == ']')
        {
            pos++;
            return true;
        }
        while(true)
        {
            Json v;
            if(!value(v, depth))
                return false;
            out.push(std::move(v));
            ws();
            if(pos >= s.size())
                return fail("unterminated array");
            if(s[pos] == ',')
            {
                pos++;
                continue;
            }
            if(s[pos] == ']')
            {
                pos++;
                return true;
            }
            return fail("expected , or ]");
        }
    }

    bool object(Json & out, int depth)
    {
        pos++;
        out = Json::object();
        ws();
        if(pos < s.size() && s[pos] == '}')
        {
            pos++;
            return true;
        }
        while(true)
        {
            ws();
            if(pos >= s.size() || s[pos] != '"')
                return fail("expected object key");
            std::string key;
            if(!str(key))
                return false;
            if(out.find(key))
                return fail("duplicate key \"" + key + "\"");
            ws();
            if(pos >= s.size() || s[pos] != ':')
                return fail("expected :");
            pos++;
            Json v;
            if(!value(v, depth))
                return false;
            out.set(key, std::move(v));
            ws();
            if(pos >= s.size())
                return fail("unterminated object");
            if(s[pos] == ',')
            {
                pos++;
                continue;
            }
            if(s[pos] == '}')
            {
                pos++;
                return true;
            }
            return fail("expected , or }");
        }
    }
};
}

bool Json::parse(const std::string & text, Json & out, std::string & error, int maxDepth)
{
    Parser p(text, maxDepth);
    Json v;
    if(!p.value(v, 0))
    {
        error = p.err;
        return false;
    }
    p.ws();
    if(p.pos != text.size())
    {
        p.fail("trailing characters");
        error = p.err;
        return false;
    }
    out = std::move(v);
    return true;
}
}
