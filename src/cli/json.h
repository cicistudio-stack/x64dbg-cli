#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace cli
{
// Minimal JSON value with insertion-ordered objects (the protocol needs a stable key order).
class Json
{
public:
    enum Type
    {
        Null,
        Bool,
        Int,
        Real,
        String,
        Array,
        Object
    };

    Json() {}
    Json(std::nullptr_t) {}
    Json(bool b) : type_(Bool), i_(b ? 1 : 0) {}
    Json(int v) : type_(Int), i_(v) {}
    Json(unsigned v) : type_(Int), i_(v) {}
    Json(long v) : type_(Int), i_(v) {}
    Json(unsigned long v) : type_(Int), i_((long long)v) {}
    Json(long long v) : type_(Int), i_(v) {}
    Json(unsigned long long v) : type_(Int), i_((long long)v) {}
    Json(double v) : type_(Real), d_(v) {}
    Json(const char* s) : type_(s ? String : Null), s_(s ? s : "") {}
    Json(const std::string & s) : type_(String), s_(s) {}
    Json(std::string && s) : type_(String), s_(std::move(s)) {}

    static Json array()
    {
        Json j;
        j.type_ = Array;
        return j;
    }
    static Json object()
    {
        Json j;
        j.type_ = Object;
        return j;
    }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Null; }
    bool isBool() const { return type_ == Bool; }
    bool isInt() const { return type_ == Int; }
    bool isNumber() const { return type_ == Int || type_ == Real; }
    bool isString() const { return type_ == String; }
    bool isArray() const { return type_ == Array; }
    bool isObject() const { return type_ == Object; }

    bool asBool() const { return i_ != 0; }
    long long asInt() const { return type_ == Real ? (long long)d_ : i_; }
    double asReal() const { return type_ == Real ? d_ : (double)i_; }
    const std::string & asString() const { return s_; }

    // Objects. set() replaces an existing key in place, otherwise appends.
    Json & set(const std::string & key, Json value);
    const Json* find(const std::string & key) const;
    Json* find(const std::string & key);
    bool erase(const std::string & key);
    const std::vector<std::pair<std::string, Json>> & members() const { return members_; }

    // Arrays.
    Json & push(Json value);
    const std::vector<Json> & items() const { return items_; }
    std::vector<Json> & items() { return items_; }
    size_t size() const { return type_ == Array ? items_.size() : members_.size(); }

    // Compact single-line text (no trailing newline). Invalid UTF-8 becomes U+FFFD, control bytes are escaped.
    std::string dump() const;
    void dumpTo(std::string & out) const;

    // Parses one JSON value. Depth is limited to maxDepth, duplicate keys and trailing garbage are errors.
    static bool parse(const std::string & text, Json & out, std::string & error, int maxDepth = 32);

private:
    Type type_ = Null;
    long long i_ = 0;
    double d_ = 0;
    std::string s_;
    std::vector<Json> items_;
    std::vector<std::pair<std::string, Json>> members_;
};

// Replaces invalid UTF-8 sequences by U+FFFD.
std::string sanitizeUtf8(const std::string & s);
// Appends the JSON string literal (with quotes) for s.
void jsonQuote(const std::string & s, std::string & out);
}
