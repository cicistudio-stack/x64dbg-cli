// Pure unit tests (no core loaded): `x64dbg-cli.exe --selftest`.
#include "events.h"
#include "host.h"
#include "json.h"
#include "options.h"
#include "protocol.h"
#include "session.h"
#include "util.h"
#include "views.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

using namespace cli;

namespace
{
int gFailures = 0;
int gChecks = 0;
std::string gCase;

void check(bool cond, const char* expr, int line)
{
    gChecks++;
    if(!cond)
    {
        gFailures++;
        printf("  FAIL %s:%d: %s\n", gCase.c_str(), line, expr);
    }
}
#define CHECK(x) check((x), #x, __LINE__)

struct TestCase
{
    const char* name;
    std::function<void()> fn;
};

Json ev(long long seq, const char* type)
{
    Json e = Json::object();
    e.set("seq", seq);
    e.set("type", type);
    return e;
}

Json bpEv(long long seq, const char* kind, unsigned long long addr)
{
    Json e = ev(seq, "breakpoint_hit");
    e.set("bp_type", kind);
    e.set("addr", hexAddr(addr));
    return e;
}

std::string reasonOf(const AttribInput & in)
{
    return attribute(in).find("reason")->asString();
}

// Feeds chunks to a fresh host and returns the ring text.
std::string feed(Host & h, const std::vector<std::pair<int, std::string>> & chunks)
{
    for(auto & c : chunks)
        h.onLogChunk(c.first, c.second);
    return h.slice(0, ~0ull).text;
}

std::vector<TestCase> cases()
{
    std::vector<TestCase> t;
    t.push_back({ "json round trip and key order", [] {
        Json j;
        std::string err;
        CHECK(Json::parse("{\"b\":1,\"a\":[true,null,\"x\\u00e9\\n\"],\"c\":{\"d\":-5}}", j, err));
        CHECK(j.dump() == "{\"b\":1,\"a\":[true,null,\"x\xc3\xa9\\n\"],\"c\":{\"d\":-5}}");
        CHECK(!Json::parse("{\"a\":1,\"a\":2}", j, err));
        CHECK(!Json::parse("{\"a\":1} x", j, err));
        CHECK(!Json::parse(std::string(40, '[') + std::string(40, ']'), j, err));
        CHECK(Json::parse(std::string(20, '[') + std::string(20, ']'), j, err));
        Json s("a\x01\x1b\x7f" "b\xff");
        CHECK(s.dump() == "\"a\\u0001\\u001b\\u007fb\xef\xbf\xbd\"");
        CHECK(Json((unsigned long long)3221225477ull).dump() == "3221225477");
    } });
    t.push_back({ "hex helpers", [] {
        CHECK(hexAddr(7) == "0x0000000000000007");
        CHECK(hexArg(255) == "0xff");
        long long n = 0;
        CHECK(parseInteger("0x10", n) && n == 16);
        CHECK(parseInteger("42", n) && n == 42);
        CHECK(!parseInteger("4x", n));
        CHECK(!parseInteger("", n));
    } });
    t.push_back({ "semicolon splitter", [] {
        auto v = splitSemicolon("a; b;;c");
        CHECK(v.size() == 3 && v[0] == "a" && v[1] == " b" && v[2] == "c");
        v = splitSemicolon("log \"x;y\"; sti");
        CHECK(v.size() == 2 && v[0] == "log \"x;y\"");
        v = splitSemicolon("log \\\"x;y");
        CHECK(v.size() == 2);
    } });
    t.push_back({ "tokenizer", [] {
        std::vector<std::string> v;
        std::string err;
        CHECK(tokenize("a \"b c\" C:\\tmp\\a.bin \\\"q", v, err));
        CHECK(v.size() == 4 && v[1] == "b c" && v[2] == "C:\\tmp\\a.bin" && v[3] == "\"q");
        CHECK(!tokenize("a \"b", v, err));
    } });
    t.push_back({ "html stripper and control escapes", [] {
        CHECK(stripHtml("Not <b>enough</b> &lt;args&gt;&amp;<br>x") == "Not enough <args>&\nx");
        CHECK(stripHtml("a < b") == "a < b");
        CHECK(escapeControlText("a\x1b" "b\r\nc\td\x01") == "a\\x1bb\nc\td\\x01");
    } });
    t.push_back({ "target argument builder and command escape", [] {
        CHECK(joinTargetArgs({ "a b", "c" }) == "\"a b\" c");
        CHECK(joinTargetArgs({}) == "");
        CHECK(joinTargetArgs({ "x\"y" }) == "\"x\\\"y\"");
        CHECK(joinTargetArgs({ "a b\\" }) == "\"a b\\\\\"");
        CHECK(joinTargetArgs({ "" }) == "\"\"");
        CHECK(commandEscape("C:\\tmp\\a.exe") == "C:\\tmp\\a.exe");
        CHECK(commandEscape("a\"b") == "a\\\"b");
        CHECK(commandEscape("x\\") == "x\\\\");
        CHECK(commandEscape("{rax}") == "\\{rax}");
    } });
    t.push_back({ "option parser", [] {
        Options o;
        std::string err;
        CHECK(parseArgs({ "--json", "t.exe", "--foo" }, o, err, false));
        CHECK(o.json && o.haveTarget && o.target == "t.exe" && o.targetArgs.size() == 1 && o.targetArgs[0] == "--foo");
        Options o2;
        CHECK(!parseArgs({ "--timeout=5" }, o2, err, false));
        Options o3;
        CHECK(parseArgs({ "--", "--odd.exe" }, o3, err, false) && o3.target == "--odd.exe");
        Options o4;
        CHECK(!parseArgs({ "--exec" }, o4, err, false));
        Options o5;
        CHECK(!parseArgs({ "--timeout", "3600001" }, o5, err, false));
        CHECK(!parseArgs({ "--attach", "0x10" }, o5, err, false));
        CHECK(!parseArgs({ "--userdir", "rel" }, o5, err, false));
        CHECK(!parseArgs({ "--test-crash", "seh" }, o5, err, false));
        Options o6;
        CHECK(parseArgs({ "--exec", "a; b", "--script", "f.txt", "--keep-going" }, o6, err, false));
        CHECK(o6.startup.size() == 2 && o6.oneShot() && o6.keepGoing);
        Options o7;
        CHECK(parseArgs({ "--exec", "a", "--interactive" }, o7, err, false) && !o7.oneShot());
    } });
    t.push_back({ "text line grammar", [] {
        RequestPtr r;
        ParseError e;
        bool skip = false;
        CHECK(parseTextLine("!eval 1+1", "1", r, e, skip) && r->isOp && r->op == "eval");
        CHECK(r->args.find("expr")->asString() == "1+1");
        CHECK(parseTextLine("!!rax", "2", r, e, skip) && !r->isOp && r->cmd == "!rax");
        CHECK(!parseTextLine("!nosuch", "3", r, e, skip) && e.code == "E_UNKNOWN_OP" && e.message.find("'!!'") != std::string::npos);
        CHECK(parseTextLine("# comment", "4", r, e, skip) && skip);
        CHECK(parseTextLine("   ", "5", r, e, skip) && skip);
        CHECK(parseTextLine("log a;b", "6", r, e, skip) && r->cmd == "log a;b");
        CHECK(parseTextLine("!native --timeout_ms 500 --wait always -- log \"a;b\" C:\\x", "7", r, e, skip));
        CHECK(r->cmd == "log \"a;b\" C:\\x" && r->opt.timeoutMs == 500 && r->opt.wait == "always");
        CHECK(!parseTextLine("!native run", "8", r, e, skip) && e.code == "E_BAD_ARG");
        CHECK(!parseTextLine("!native --bogus 1 -- run", "9", r, e, skip));
        CHECK(!parseTextLine("!native --timeout_ms 1 -- ", "10", r, e, skip));
        CHECK(parseTextLine("!log --tail 5 --clear", "11", r, e, skip) && r->args.find("tail")->asInt() == 5 && r->args.find("clear")->asBool());
        CHECK(parseTextLine("!events 7", "12", r, e, skip) && r->args.find("since")->asInt() == 7);
        CHECK(!parseTextLine("!eval", "13", r, e, skip) || r->args.find("expr") == nullptr);
    } });
    t.push_back({ "json request validation", [] {
        RequestPtr r;
        ParseError e;
        CHECK(parseJsonRequest("{\"id\":1,\"op\":\"eval\",\"args\":{\"expr\":\"1+2*3\"}}", r, e) && r->isOp);
        CHECK(r->echo.dump() == "{\"op\":\"eval\",\"args\":{\"expr\":\"1+2*3\"}}");
        CHECK(parseJsonRequest("{\"cmd\":\"run\",\"timeout_ms\":500,\"wait\":\"auto\",\"vars\":[\"$result\"]}", r, e) && r->opt.timeoutMs == 500);
        CHECK(!parseJsonRequest("{\"cmd\":\"run\",\"op\":\"status\"}", r, e) && e.code == "E_PARSE");
        CHECK(!parseJsonRequest("{\"cmd\":\"run\",\"vars\":[\"result\"]}", r, e) && e.code == "E_BAD_ARG");
        CHECK(!parseJsonRequest("{\"op\":\"eval\",\"args\":{\"expr\":1}}", r, e) && e.code == "E_BAD_ARG");
        CHECK(!parseJsonRequest("{\"op\":\"eval\",\"args\":{\"timeout_ms\":5}}", r, e) && e.code == "E_BAD_ARG");
        CHECK(!parseJsonRequest("{\"op\":\"nope\"}", r, e) && e.code == "E_UNKNOWN_OP");
        CHECK(!parseJsonRequest("{\"id\":1.5,\"cmd\":\"x\"}", r, e) && e.code == "E_PARSE");
        CHECK(!parseJsonRequest("[1]", r, e) && e.code == "E_PARSE");
        CHECK(!parseJsonRequest("{\"cmd\":\"x\",\"timeout\":5}", r, e) && e.code == "E_BAD_ARG");
        CHECK(parseJsonRequest("{\"op\":\"native\",\"args\":{\"cmd\":\"run\"}}", r, e) && r->cmd == "run");
    } });
    t.push_back({ "text renderer", [] {
        Json r = Json::object();
        r.set("ok", false);
        r.set("output", "@@END fake\nline\x1b");
        r.set("error", makeErrorObject("E_COMMAND_FAILED", "boom"));
        Json st = Json::object();
        st.set("status", "paused");
        st.set("cip", "0x0000000000401000");
        st.set("seq", 5);
        r.set("state", st);
        Json w = Json::object();
        w.set("reason", "paused");
        r.set("wait", w);
        std::string s = renderTextResponse(r, "9");
        CHECK(s == " @@END fake\nline\\x1b\nerror: E_COMMAND_FAILED: boom\n@@END 9 fail state=paused cip=0x0000000000401000 seq=5 wait=paused code=E_COMMAND_FAILED\n");
    } });
    t.push_back({ "barrier chunk handler", [] {
        Host h;
        std::string T5 = h.barrierMarker('T', 5), H5 = h.barrierMarker('H', 5), T6 = h.barrierMarker('T', 6);
        CHECK(feed(h, { { 0, "a\n" + T5 }, { 0, "\nb\n" } }) == "a\nb\n");
        Host h2;
        CHECK(feed(h2, { { 0, T5 + "\nX" } }) == "X");
        Host h3;
        CHECK(feed(h3, { { 0, "a" + T5 + "\n" + T6 + "\nb" } }) == "ab");
        Host h4;
        CHECK(feed(h4, { { 1, "Not enough <a href=\"u\">args</a>.\n" + H5 }, { 1, "\nb" } }) == "Not enough args.\nb");
        Host h5;
        h5.onLogChunk(0, "a\n" + T5);
        CHECK(h5.barrierSeenText == 5 && h5.barrierSeenHtml == 0 && !h5.barrierComplete(5));
        h5.onLogChunk(1, "err\n" + H5);
        CHECK(h5.barrierComplete(5));
        CHECK(h5.slice(0, ~0ull).text == "a\nerr\n");
        Host h6;
        CHECK(feed(h6, { { 0, "x" + H5 + "y" } }) == "x" + H5 + "y");
        CHECK(h6.barrierSeenHtml == 0);
        Host h7;
        h7.logEnabled = false;
        h7.onLogChunk(0, "drop me");
        h7.onLogChunk(0, T5);
        CHECK(h7.slice(0, ~0ull).text.empty() && h7.barrierSeenText == 5);
    } });
    t.push_back({ "event ring, cursor and drop notice", [] {
        Host h;
        h.eventRingSize = 3;
        for(int i = 0; i < 5; i++)
            h.pushEvent("warning");
        long long next = 0;
        bool dropped = false;
        auto evs = h.takeEvents(10, &next, &dropped);
        CHECK(dropped && evs.size() == 4 && evs[0].find("type")->asString() == "events_dropped");
        CHECK(evs[0].find("count")->asInt() == 2);
        CHECK(h.takeEvents(10, &next, &dropped).empty());
        h.pushEvent("paused");
        h.pushEvent("paused");
        evs = h.takeEvents(1, &next, &dropped);
        CHECK(evs.size() == 1 && next != 0);
        evs = h.takeEvents(5, &next, &dropped);
        CHECK(evs.size() == 1 && next == 0);
    } });
    t.push_back({ "state machine and reference tables", [] {
        Host h;
        h.onDebugState(0 /*initialized*/, false);
        CHECK(h.status == Status::Starting && h.initSeq == h.stateSeq);
        long long init = h.initSeq;
        h.onDebugState(2 /*running*/, false);
        CHECK(h.status == Status::Starting); // delayed duplicate ignored
        h.onDebugState(2, true);
        CHECK(h.status == Status::Running && h.stateSeq == init + 1);
        h.onDebugState(1 /*paused*/, true);
        CHECK(h.status == Status::Paused && h.lastPausedSeq > h.lastRunningSeq);
        h.beginLaunch();
        CHECK(h.reportedStatusLocked() == Status::Starting);
        h.onDebugState(3 /*stopped*/, false);
        CHECK(h.status == Status::Stopped && h.reportedStatusLocked() == Status::Starting);
        h.onDebugState(0, false);
        h.onDebugState(2, true);
        CHECK(h.reportedStatusLocked() == Status::Running);
        h.refInitialize("A");
        h.refAddColumn("c1");
        h.refAddColumn("c2");
        h.refSetRowCount(1);
        h.refSetCell(0, 1, "v");
        h.refInitialize("B");
        CHECK(h.tableCounter == 2 && h.tables.size() == 2);
        int dropped = 0;
        auto ts = h.tablesBetween(0, 2, &dropped);
        CHECK(ts.size() == 2 && ts[0].rows[0][1] == "v" && dropped == 0);
        for(int i = 0; i < 20; i++)
            h.refInitialize("X");
        ts = h.tablesBetween(0, h.tableCounter, &dropped);
        CHECK(ts.size() == 16 && dropped == 6);
        h.autoCompleteAdd("StepUser,StepUserInto");
        h.autoCompleteAdd("StepSystem,StepUserInto");
        CHECK(h.canonicalOf("STEPUSERINTO") == "StepUser" && h.canonicalOf("\x01") == "");
        h.autoCompleteAdd("pause");
        CHECK(h.canonicalOf("PAUSE") == "pause");
    } });
    t.push_back({ "line plan (steps 1 to 4 of 7.4)", [] {
        auto canon = [](const std::string & w) -> std::string
        {
            std::string l = lower(w);
            if(l == "restartadmin" || l == "runas")
                return "restartadmin";
            return l;
        };
        std::string lastExpandInput;
        auto expand = [&](const std::string & in, std::string & out, bool & tooLong) -> bool
        {
            lastExpandInput = in;
            tooLong = in == "BIG";
            out = in == "BIG" ? std::string(65535, 'a') : (in == "$sti" ? "$sti" : "log 2");
            return true;
        };
        LinePlan p = planNativeLine("  log a; $sti ", expand, canon);
        CHECK(p.ok && p.segments.size() == 2 && p.segments[1] == "$sti");
        p = planNativeLine("$log \"{1+1}\"", expand, canon);
        CHECK(p.ok && p.segments.size() == 1 && p.segments[0] == "log 2" && lastExpandInput == "log \"{1+1}\"");
        p = planNativeLine("$$sti", expand, canon);
        CHECK(p.ok && p.segments.size() == 1 && p.segments[0] == "$sti");
        p = planNativeLine("$BIG", expand, canon);
        CHECK(!p.ok && p.code == "E_TOO_LONG");
        p = planNativeLine(std::string(1023, 'a'), expand, canon);
        CHECK(p.ok);
        p = planNativeLine(std::string(1024, 'a'), expand, canon);
        CHECK(!p.ok && p.code == "E_TOO_LONG");
        p = planNativeLine("log x; restartadmin", expand, canon);
        CHECK(!p.ok && p.code == "E_UNSUPPORTED");
        p = planNativeLine("log x; $restartadmin", expand, canon);
        CHECK(p.ok);
        p = planNativeLine("set $v,1; $w=2", expand, canon);
        CHECK(p.ok && p.segments.size() == 2);
        p = planNativeLine("log a\nlog b", expand, canon);
        CHECK(!p.ok && p.code == "E_BAD_ARG");
        p = planNativeLine("  ;; ", expand, canon);
        CHECK(!p.ok);
    } });
    t.push_back({ "strings handed to the core (fake core, AC-25)", [] {
        auto canon = [](const std::string & w) -> std::string
        {
            std::string l = lower(w);
            return (l == "restartadmin" || l == "runas") ? "restartadmin" : l;
        };
        struct Run
        {
            LinePlan plan;
            std::vector<std::string> sent;
            size_t failedAt = (size_t)-1;
        };
        // Mirrors Session::runNativeLine: expansion through expandLine, planNativeLine, then coreLine per segment.
        // The fake core records every string and fails a string that carries a bare "$sti" command.
        auto run = [&](const std::string & line, const std::function<bool(const char*, size_t, char*)> & format)
        {
            Run r;
            auto expand = [&](const std::string & in, std::string & out, bool & tooLong) { return expandLine(format, in, out, tooLong); };
            r.plan = planNativeLine(line, expand, canon);
            if(!r.plan.ok)
                return r;
            for(size_t i = 0; i < r.plan.segments.size(); i++)
            {
                std::string s = coreLine(r.plan.segments[i]);
                r.sent.push_back(s);
                if(s == " $sti")
                {
                    r.failedAt = i;
                    break;
                }
            }
            return r;
        };
        auto copyFormat = [](const char* fmt, size_t n, char* out)
        {
            strncpy_s(out, n, fmt, _TRUNCATE);
            return true;
        };
        Run r = run("log a; $sti", copyFormat);
        CHECK(r.sent.size() == 2 && r.sent[0] == " log a" && r.sent[1] == " $sti" && r.failedAt == 1);
        r = run("$$sti", copyFormat);
        CHECK(r.sent.size() == 1 && r.sent[0] == " $sti");
        r = run("set $v,1; $w=2", copyFormat);
        CHECK(r.sent.size() == 2 && r.sent[0] == " set $v,1" && r.sent[1] == " $w=2" && r.failedAt == (size_t)-1);
        r = run(std::string(1023, 'a'), copyFormat);
        CHECK(r.plan.ok && r.sent.size() == 1 && r.sent[0].size() == 1024);
        r = run(std::string(1024, 'a'), copyFormat);
        CHECK(!r.plan.ok && r.plan.code == "E_TOO_LONG" && r.sent.empty());
        auto fillFormat = [](const char*, size_t n, char* out)
        {
            memset(out, 'a', n - 1);
            out[n - 1] = 0;
            return true;
        };
        r = run("$log x", fillFormat);
        CHECK(!r.plan.ok && r.plan.code == "E_TOO_LONG" && r.sent.empty());
        r = run("log x; $restartadmin", copyFormat);
        CHECK(r.plan.ok && r.sent.size() == 2 && r.sent[1] == " $restartadmin");
        r = run("log x; restartadmin", copyFormat);
        CHECK(!r.plan.ok && r.plan.code == "E_UNSUPPORTED" && r.sent.empty());
    } });
    t.push_back({ "pause-reason attribution (7.5)", [] {
        AttribInput in;
        in.cip = 0x401000;
        in.lastRunningSeq = 1;
        in.pausedSeq = 100;
        // [module_loaded, thread_created, paused] with ThreadStart -> thread_start
        in.threadStart = true;
        in.window = { ev(2, "module_loaded"), ev(3, "thread_created"), ev(100, "paused") };
        CHECK(reasonOf(in) == "thread_start");
        in.window = { ev(2, "thread_created"), ev(3, "module_loaded"), ev(100, "paused") };
        in.dllLoad = true;
        CHECK(reasonOf(in) == "dll_load");
        in.dllLoad = false;
        in.window = { ev(2, "module_loaded"), bpEv(3, "normal", 0x999), ev(100, "paused") };
        CHECK(reasonOf(in) == "unknown");
        in.window = { ev(2, "pause_requested"), ev(100, "paused") };
        CHECK(reasonOf(in) == "pause");
        in.window = { ev(100, "paused") };
        CHECK(reasonOf(in) == "unknown" && attribute(in).find("hint")->size() == 0);
        in.window = { ev(2, "exception"), ev(3, "pause_requested"), ev(100, "paused") };
        CHECK(reasonOf(in) == "pause");
        in.threadStart = false;
        in.window = { ev(2, "pause_requested"), ev(3, "thread_created"), ev(100, "paused") };
        CHECK(reasonOf(in) == "pause");
        in.window = { ev(2, "pause_requested"), bpEv(3, "normal", 0x999), bpEv(4, "normal", 0x998), ev(100, "paused") };
        CHECK(reasonOf(in) == "pause");
        in.window = { bpEv(3, "normal", 0x401000), ev(100, "paused") };
        Json s = attribute(in);
        CHECK(s.find("reason")->asString() == "breakpoint" && s.find("bp")->asString() == hexAddr(0x401000));
        in.window = { ev(2, "module_loaded"), bpEv(3, "dll", 0x1234), ev(100, "paused") };
        CHECK(reasonOf(in) == "breakpoint");
        // trailing events decide first
        in.window = { ev(2, "pause_requested"), ev(100, "paused") };
        in.trailing = { ev(101, "stepped") };
        CHECK(reasonOf(in) == "step");
        Json ex = ev(101, "exception");
        ex.set("code", "0x00000000c0000005");
        ex.set("address", "0x0000000000401000");
        in.trailing = { ex };
        s = attribute(in);
        CHECK(s.find("reason")->asString() == "exception" && s.find("exception")->find("code")->asString() == "0x00000000c0000005");
        in.trailing.clear();
        // finisher refinement
        in.window = { ev(100, "paused") };
        in.lastResumeName = "stepout";
        CHECK(reasonOf(in) == "step");
        in.lastResumeName = "runtousercode";
        CHECK(reasonOf(in) == "run_to_user");
        in.lastResumeName = "traceintoconditional";
        CHECK(reasonOf(in) == "trace_end");
        in.lastResumeName = "stepinto";
        CHECK(reasonOf(in) == "unknown");
        // exception breakpoint
        in.lastResumeName = "run";
        in.lastExcValid = true;
        in.lastExcCode = 0xc0000005;
        in.lastExcStamp = 50;
        in.window = { bpEv(60, "exception", 0xc0000005), ev(100, "paused") };
        s = attribute(in);
        CHECK(s.find("reason")->asString() == "breakpoint" && s.find("exception") != nullptr);
        in.lastExcValid = false;
        CHECK(reasonOf(in) == "unknown");
        CHECK(isFinisher("stepout") && !isFinisher("stepinto") && isResumeClass("loadlib") && isStepGuard("skip") && isCountForm("estepout"));
    } });
    t.push_back({ "M2 native-line builders (rule N)", [] {
        CHECK(buildStepLine("sti", true, 10) == "sti 0xa");
        CHECK(buildStepLine("sto", true, 0) == "sto 0x0");
        CHECK(buildStepLine("rtr", false, 0) == "rtr");
        CHECK(buildAttachLine(1234) == "attach .1234");
        CHECK(buildInitLine("C:\\a b\\t.exe", "", "") == "init \"C:\\a b\\t.exe\"");
        CHECK(buildInitLine("t.exe", "x \"y\"", "") == "init \"t.exe\",\"x \\\"y\\\"\"");
        CHECK(buildInitLine("t.exe", "", "C:\\w") == "init \"t.exe\",\"\",\"C:\\w\"");
        std::string line, err;
        CHECK(buildThreadLine("switch", true, 1234, false, "", line, err) && line == "switchthread 0x4d2");
        CHECK(buildThreadLine("suspend", true, 16, false, "", line, err) && line == "suspendthread 0x10");
        CHECK(buildThreadLine("kill", true, 7, true, "300", line, err) && line == "killthread 0x7,0x12c");
        CHECK(buildThreadLine("kill", true, 7, false, "", line, err) && line == "killthread 0x7,0x0");
        CHECK(buildThreadLine("priority", true, 9, true, "highest", line, err) && line == "setthreadpriority 0x9,Highest");
        CHECK(buildThreadLine("priority", true, 9, true, "-2", line, err) && line == "setthreadpriority 0x9,-0x2");
        CHECK(buildThreadLine("name", true, 9, true, "a\"b", line, err) && line == "threadsetname 0x9,\"a\\\"b\"");
        CHECK(buildThreadLine("suspend_all", false, 0, false, "", line, err) && line == "suspendallthreads");
        CHECK(buildThreadLine("create", false, 0, true, "0x401000", line, err) && line == "createthread 0x401000");
        // required and forbidden keys are named
        CHECK(!buildThreadLine("switch", false, 0, false, "", line, err) && err.find("requires tid") != std::string::npos);
        CHECK(!buildThreadLine("switch", true, 1, true, "x", line, err) && err.find("does not take value") != std::string::npos);
        CHECK(!buildThreadLine("suspend_all", true, 1, false, "", line, err) && err.find("does not take tid") != std::string::npos);
        CHECK(!buildThreadLine("create", true, 1, true, "0x1", line, err) && err.find("does not take tid") != std::string::npos);
        CHECK(!buildThreadLine("name", true, 1, false, "", line, err) && err.find("requires value") != std::string::npos);
        CHECK(!buildThreadLine("priority", true, 1, true, "bogus", line, err));
        CHECK(!buildThreadLine("nosuch", true, 1, false, "", line, err));
        CHECK(hexN(0x4d2, 4) == "0x04d2" && hexN(255, 8) == "0x000000ff");
        std::vector<unsigned char> bytes;
        std::string e;
        CHECK(parseHexBytes("90 90 c3", bytes, e, 16) && bytes.size() == 3 && bytes[2] == 0xc3);
        CHECK(parseHexBytes("9090C3", bytes, e, 16) && bytes.size() == 3);
        CHECK(!parseHexBytes("909", bytes, e, 16) && !parseHexBytes("9 0", bytes, e, 16) && !parseHexBytes("zz", bytes, e, 16) && !parseHexBytes("", bytes, e, 16));
        CHECK(!parseHexBytes("9090", bytes, e, 1));
        CHECK(shortestDouble(0.1) == "0.1" && shortestDouble(HUGE_VAL) == "inf" && shortestFloat(0.5f) == "0.5");
        CHECK(halfToDouble(0x3c00) == 1.0 && halfToDouble(0xc000) == -2.0);
        const unsigned char one[10] = { 0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f };
        CHECK(extendedToDouble(one) == 1.0);
    } });
    t.push_back({ "M2 op table and text-form arguments", [] {
        auto parse = [](const std::string & line, RequestPtr & req, ParseError & err) -> bool
        {
            bool skip = false;
            return parseTextLine(line, "1", req, err, skip);
        };
        RequestPtr r;
        ParseError err;
        CHECK(parse("!dis rip -n 5 --until rip+40 --back 2 --bytes false", r, err));
        CHECK(r && r->args.find("addr")->asString() == "rip" && r->args.find("count")->asInt() == 5 && r->args.find("until")->asString() == "rip+40");
        CHECK(r && r->args.find("back")->asInt() == 2 && r->args.find("bytes") && !r->args.find("bytes")->asBool());
        CHECK(parse("!mem rsp -n 32 --format hex64", r, err) && r->args.find("size")->asInt() == 32 && r->args.find("format")->asString() == "hex64");
        CHECK(parse("!mem rsp + 8", r, err) && r->args.find("addr")->asString() == "rsp + 8");
        CHECK(parse("!stack --addr 0x1000 -n 4", r, err) && r->args.find("addr")->asString() == "0x1000" && r->args.find("count")->asInt() == 4);
        CHECK(parse("!setreg rax 0x10", r, err) && r->args.find("reg")->asString() == "rax" && r->args.find("value")->asString() == "0x10");
        CHECK(parse("!setreg rax 1 + 2", r, err) && r->args.find("value")->asString() == "1 + 2");
        CHECK(parse("!thread switch 1234", r, err) && r->args.find("action")->asString() == "switch" && r->args.find("tid")->asInt() == 1234);
        CHECK(parse("!bp add kernel32.Sleep --once --kind sw", r, err) && r->args.find("target")->asString() == "kernel32.Sleep" && r->args.find("once")->asBool());
        CHECK(parse("!stepin 10", r, err) && r->args.find("count")->asInt() == 10);
        CHECK(parse("!attach 1234 --pause", r, err) && r->args.find("pid")->asInt() == 1234 && r->args.find("pause")->asBool());
        CHECK(parse("!run --timeout_ms 500", r, err) && r->opt.timeoutMs == 500 && r->args.size() == 0);
        CHECK(!parse("!stepin ten", r, err) && err.code == "E_BAD_ARG");
        CHECK(!parse("!run extra", r, err) && err.code == "E_BAD_ARG");
        CHECK(!parse("!regs --nosuch 1", r, err) && err.code == "E_BAD_ARG");
        // JSON: address-like keys take a string or a small integer, other keys are typed
        CHECK(parseJsonRequest("{\"op\":\"dis\",\"args\":{\"addr\":4096}}", r, err));
        CHECK(!parseJsonRequest("{\"op\":\"dis\",\"args\":{\"addr\":-1}}", r, err));
        CHECK(!parseJsonRequest("{\"op\":\"dis\",\"args\":{\"count\":\"4\"}}", r, err));
        CHECK(!parseJsonRequest("{\"op\":\"dis\",\"args\":{\"timeout_ms\":5}}", r, err));
        CHECK(parseJsonRequest("{\"op\":\"callstack\",\"args\":{\"thread\":1234}}", r, err));
        // every M2 op is registered with a milestone and a valid precondition
        int m2 = 0;
        for(auto & o : allOps())
        {
            std::string pre = o.precondition;
            CHECK(pre == "any" || pre == "debugging" || pre == "paused");
            if(std::string(o.milestone) == "M2")
                m2++;
        }
        CHECK(m2 == 27);
        CHECK(std::string(findOp("stack")->precondition) == "paused" && std::string(findOp("dis")->precondition) == "debugging");
        CHECK(findOp("pause")->oob && findOp("stop")->oob && !findOp("detach")->oob);
    } });
    t.push_back({ "M3 op table, text-form arguments and table rendering", [] {
        int m3 = 0;
        for(auto & o : allOps())
        {
            if(std::string(o.milestone) != "M3")
                continue;
            m3++;
            CHECK(findView(o.name) != nullptr); // every M3 op has a view function
        }
        CHECK(m3 == 42);
        RequestPtr r;
        ParseError err;
        CHECK(parseJsonRequest("{\"op\":\"handles\",\"args\":{\"limit\":3,\"offset\":2}}", r, err));
        CHECK(!parseJsonRequest("{\"op\":\"handles\",\"args\":{\"limit\":\"3\"}}", r, err) && err.code == "E_BAD_ARG");
        CHECK(!parseJsonRequest("{\"op\":\"ps\",\"args\":{\"limit\":3}}", r, err) && err.code == "E_BAD_ARG");
        bool skip = false;
        CHECK(parseTextLine("!patch export out.exe --module testprog.exe", "1", r, err, skip) && r->args.find("action")->asString() == "export" &&
              r->args.find("file")->asString() == "out.exe" && r->args.find("module")->asString() == "testprog.exe");
        CHECK(parseTextLine("!asm 0x401000 mov eax, 1", "2", r, err, skip) && r->args.find("addr")->asString() == "0x401000" && r->args.find("text")->asString() == "mov eax, 1");
        CHECK(parseTextLine("!format rax={rax} rbx={rbx}", "3", r, err, skip) && r->args.find("template")->asString() == "rax={rax} rbx={rbx}");
        CHECK(parseTextLine("!script run --line 3", "4", r, err, skip) && r->args.find("line")->asInt() == 3);
        CHECK(parseTextLine("!notes set global hello world", "5", r, err, skip) && r->args.find("text")->asString() == "hello world");
        CHECK(parseTextLine("!trace set_type --type byte", "6", r, err, skip) && r->args.find("type")->asString() == "byte");
        CHECK(std::string(findOp("seh")->precondition) == "paused" && std::string(findOp("ps")->precondition) == "any" && std::string(findOp("handles")->precondition) == "debugging");
        // a captured table inside data is printed like the tables of a response
        Json t1 = Json::object();
        t1.set("id", 4);
        t1.set("name", "Labels");
        Json cols = Json::array();
        cols.push("Address");
        cols.push("Label");
        t1.set("columns", cols);
        Json rows = Json::array();
        Json row = Json::array();
        row.push("00401000");
        row.push("start");
        rows.push(row);
        t1.set("rows", rows);
        t1.set("total_rows", 1);
        Json d = Json::object();
        d.set("table", t1);
        CHECK(renderDataText("labels", d) == "table 4 \"Labels\" rows 1/1\nAddress\tLabel\n00401000\tstart\n");
        // an empty list of a known M3 op prints its header line only
        Json d2 = Json::object();
        d2.set("handles", Json::array());
        d2.set("count", 0);
        CHECK(renderDataText("handles", d2) == "handles:\nhandle\ttype\ttype_number\tname\taccess\ncount: 0\n");
    } });
    t.push_back({ "M2 text rendering of data (design 9.1 rules i to vi)", [] {
        Json d = Json::object();
        d.set("zeta", 1);
        d.set("alpha", Json());
        d.set("flag", true);
        Json inner = Json::object();
        inner.set("b", "x");
        inner.set("a", 2);
        d.set("nested", inner);
        Json arr = Json::array();
        arr.push("one");
        arr.push("two words");
        arr.push("");
        d.set("list", arr);
        std::string t = renderDataText("x", d);
        CHECK(t == "zeta: 1\nalpha: -\nflag: true\nnested:\n  b: x\n  a: 2\nlist: one \"two words\" \"\"\n");
        // array of objects: header with the keys of the first element, tab separated rows, nested values as compact JSON
        Json rows = Json::array();
        Json r1 = Json::object();
        r1.set("k", "a\tb");
        r1.set("n", Json());
        Json sub = Json::object();
        sub.set("x", 1);
        r1.set("o", sub);
        rows.push(r1);
        Json r2 = Json::object();
        r2.set("k", "c\nd\x01");
        r2.set("n", 5);
        r2.set("o", Json::array());
        rows.push(r2);
        Json d2 = Json::object();
        d2.set("rows", rows);
        t = renderDataText("x", d2);
        CHECK(t == "rows:\nk\tn\to\na\\tb\t-\t{\"x\":1}\nc\\nd\\x01\t5\t[]\n");
        // an empty array of a known list prints the header line only
        Json d3 = Json::object();
        d3.set("threads", Json::array());
        t = renderDataText("threads", d3);
        CHECK(t.compare(0, 9, "threads:\n") == 0 && t.find("index\ttid\tname") == 9 && t.back() == '\n' && std::count(t.begin(), t.end(), '\n') == 2);
        // deterministic: two renders of the same data are identical
        CHECK(renderDataText("x", d2) == renderDataText("x", d2));
        // dis has its own renderer
        Json ins = Json::object();
        ins.set("addr", "0x00007ff6a1b21000");
        ins.set("bytes", "e812345678");
        ins.set("text", "call 0x00007ffb12345678");
        ins.set("is_cip", true);
        ins.set("bp", "normal");
        ins.set("comment", Json());
        Json br = Json::object();
        br.set("target_label", "kernel32.CreateFileW");
        ins.set("branch", br);
        Json list = Json::array();
        list.push(ins);
        Json dd = Json::object();
        dd.set("instructions", list);
        t = renderDataText("dis", dd);
        CHECK(t.compare(0, 4, "=>*0") == 0 && t.find("e8 12 34 56 78") != std::string::npos && t.find("; kernel32.CreateFileW") != std::string::npos);
        CHECK(renderDataText("x", Json()).empty());
    } });
    return t;
}
}

int runSelfTest()
{
    int failedCases = 0;
    for(auto & c : cases())
    {
        gCase = c.name;
        int before = gFailures;
        c.fn();
        bool ok = gFailures == before;
        printf("%s %s\n", ok ? "ok  " : "FAIL", c.name);
        if(!ok)
            failedCases++;
    }
    printf("%d checks, %d failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
