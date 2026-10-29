#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "json.h"

namespace cli
{
static const int kProtocolVersion = 1;
static const char* const kVersion = "0.1.0";

struct ReqOptions
{
    long long timeoutMs = -1; // -1: session default (--timeout)
    std::string wait = "auto";
    std::string onTimeout = "keep";
    long long maxOutput = -1; // -1: session default (--max-output)
    long long maxResponseBytes = 16 << 20;
    long long maxRows = 5000;
    long long maxEvents = 500;
    long long settleMs = 2000;
    long long pauseSettleMs = 8000;
    std::vector<std::string> vars;
    bool stopOnError = false;
};

struct ParseError
{
    std::string code;
    std::string message;
    Json detail;
    Json id; // when known
};

struct Request
{
    Json id;            // null, int or string (JSON mode / startup items)
    std::string textId; // text mode id (decimal counter or s<n>)
    bool isOp = false;
    std::string op;
    Json args;          // object (structured ops)
    std::string cmd;    // native line (for cmd requests and for op "native")
    bool isBatch = false;
    Json echo;          // the members echoed in the response: cmd, or op + args
    ReqOptions opt;
    bool startup = false;
    std::shared_ptr<ParseError> preError; // startup item that failed to parse: answered with this error
    Json raw;           // the whole request object of a batch (batch-level options are the defaults of its elements)

    // runtime
    std::atomic<bool> responded{ false };
    std::atomic<bool> abandoned{ false };
    std::atomic<int> completed{ 0 };
    std::chrono::steady_clock::time_point started;
    int tableCursor = 0;
    unsigned long long logStart = 0;
};
typedef std::shared_ptr<Request> RequestPtr;

struct ArgSpec
{
    const char* name;
    // 'i' integer, 's' string, 'b' boolean, 'a' address-like (string, or integer in 0..2^53), 'x' string or integer
    char type;
};

struct OpSpec
{
    const char* name;
    const char* milestone;
    const char* precondition; // any|debugging|paused
    const char* usage;
    std::vector<ArgSpec> args;
    const char* positional; // key filled by positional text arguments ("" = none); "a,b": first token to a, the rest to b
    bool restOfLine;        // positional takes the rest of the line verbatim
    bool oob;               // answered by the Control thread
    const char* nShort = ""; // key that the text option -n stands for (count or size)
};

const std::vector<OpSpec> & allOps();
const OpSpec* findOp(const std::string & name);

// JSON line -> Request. On failure fills err (code E_PARSE / E_BAD_ARG / E_TOO_LONG ...).
bool parseJsonRequest(const std::string & line, RequestPtr & out, ParseError & err);
// Text line (rule of design 8.2). skip is set for empty and '#' lines. idString is the id assigned by the reader.
bool parseTextLine(const std::string & line, const std::string & idString, RequestPtr & out, ParseError & err, bool & skip);
// Applies one request option (timeout_ms, wait, ...). Returns false with message on a bad value.
bool applyOption(ReqOptions & o, const std::string & key, const Json & value, std::string & message);
bool isOptionKey(const std::string & key);
// The `!native` line parser (design 8.2): --key value pairs up to "--", then the verbatim tail.
bool parseNativeBang(const std::string & rest, Request & req, std::string & message);

// Text form of the `data` of an op (design 9.1, rules i to vi; `dis` has its own renderer). Ends with '\n' unless empty.
std::string renderDataText(const std::string & op, const Json & data);

// Renderers. All return whole messages ending with '\n'.
std::string renderJsonLine(const Json & obj);
std::string renderTextResponse(const Json & response, const std::string & id);
std::string renderEventJson(const Json & event);
std::string renderEventText(const Json & event);
std::string renderFatal(bool jsonMode, const std::string & code, const std::string & message);
std::string renderReady(bool jsonMode, const Json & hello);

// Error response skeleton helpers.
Json makeErrorObject(const std::string & code, const std::string & message, const Json & detail = Json());
}
