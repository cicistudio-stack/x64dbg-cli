#include "../bridge/bridgemain.h"
#include "../dbg/_dbgfunctions.h"

#include "app.h"
#include "io.h"
#include "session.h"
#include "util.h"
#include "views.h"

#include <algorithm>
#include <climits>
#include <cstring>

using std::chrono::milliseconds;
using std::chrono::steady_clock;

namespace cli
{
static Session* gSession = nullptr;

Session* session()
{
    return gSession;
}

void setSession(Session* s)
{
    gSession = s;
}

static long long nowMs()
{
    return std::chrono::duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count() + 1;
}

static const int kStoppedTailMs = 200;
static const int kEofDrainMaxMs = 60000;

// Marks the time spent inside one blocking core call (design 8.4, stuck clock).
struct CoreCall
{
    Session & s;
    CoreCall(Session & session, long long limitMs) : s(session)
    {
        s.coreCallLimitMs_ = limitMs;
        s.coreCallSinceMs_ = nowMs();
    }
    ~CoreCall() { s.coreCallSinceMs_ = 0; }
};

// ------------------------------------------------------------------ line handling (design 7.4)

LinePlan planNativeLine(const std::string & line,
                        const std::function<bool(const std::string &, std::string &, bool &)> & expand,
                        const std::function<std::string(const std::string &)> & canonical)
{
    LinePlan p;
    auto fail = [&](const char* code, const std::string & msg)
    {
        p.ok = false;
        p.code = code;
        p.message = msg;
        p.segments.clear();
        return p;
    };
    std::string text = trim(line);
    if(text.empty())
        return fail("E_BAD_ARG", "empty command");
    if(text[0] == '$')
    {
        size_t i = 1;
        while(i < text.size() && text[i] == ' ')
            i++;
        std::string expanded;
        bool tooLong = false;
        if(!expand(text.substr(i), expanded, tooLong))
            return fail("E_COMMAND_FAILED", "cannot expand the line (StringFormatInline failed)");
        if(tooLong)
            return fail("E_TOO_LONG", "expanded line exceeds 65535 bytes");
        text = expanded;
    }
    for(auto & s : splitSemicolon(text))
    {
        std::string t = trim(s);
        if(!t.empty())
            p.segments.push_back(t);
    }
    if(p.segments.empty())
        return fail("E_BAD_ARG", "no command in line");
    for(auto & seg : p.segments)
    {
        if(seg.size() > 1023)
            return fail("E_TOO_LONG", "command segment is " + std::to_string(seg.size()) +
                        " bytes; the limit is 1023 (split the work or use scriptexec <file>)");
        if(seg.find('\0') != std::string::npos || seg.find('\r') != std::string::npos || seg.find('\n') != std::string::npos)
            return fail("E_BAD_ARG", "command contains a NUL, CR or LF character");
        if(lower(canonical(firstWord(seg))) == "restartadmin")
            return fail("E_UNSUPPORTED", "restartadmin is not available in x64dbg-cli");
    }
    return p;
}

std::string coreLine(const std::string & segment)
{
    return " " + segment;
}

bool expandLine(const std::function<bool(const char*, size_t, char*)> & format, const std::string & text, std::string & out, bool & tooLong)
{
    std::vector<char> buf(65536, 0);
    bool ok = format(text.c_str(), buf.size(), buf.data());
    tooLong = strnlen(buf.data(), buf.size()) >= 65535;
    out = buf.data();
    return ok;
}

bool runBarrier(Host & h, int barrierMs, const std::function<bool(const std::string &)> & exec, unsigned long long* endOffset)
{
    long long token = h.nextBarrier();
    exec("log \"" + h.barrierMarker('T', token) + "\"");
    exec("htmllog \"" + h.barrierMarker('H', token) + "\"");
    std::unique_lock<std::mutex> lk(h.mu);
    bool ok = h.cv.wait_for(lk, milliseconds(barrierMs), [&] { return h.barrierComplete(token); });
    *endOffset = ok ? std::max(h.markerOffset[0], h.markerOffset[1]) : h.logEndLocked();
    return ok;
}

// ------------------------------------------------------------------ construction and threads

Session::Session(const Options & options, const std::string & userDirectory) : opt(options), userDir(userDirectory)
{
    trailMs_ = opt.testTrailMs >= 0 ? opt.testTrailMs : 50;
}

Session::~Session()
{
}

Json Session::buildHello()
{
    Json h = Json::object();
    h.set("type", "hello");
    h.set("v", kProtocolVersion);
    h.set("tool", "x64dbg-cli");
    h.set("version", kVersion);
    h.set("arch", "x64");
    h.set("pid", (unsigned long long)GetCurrentProcessId());
    h.set("userdir", userDir);
    Json cap = Json::object();
    bool ok;
    {
        std::lock_guard<std::mutex> lk(host().mu);
        ok = host().callbacksOk;
    }
    cap.set("events", ok ? "full" : "degraded");
    DEBUG_ENGINE eng = DbgGetDebugEngine();
    cap.set("engine", eng == DebugEngineTitanEngine ? "titan" : eng == DebugEngineGleeBug ? "gleebug" : "static");
    Json ops = Json::array();
    for(auto & o : allOps())
        ops.push(o.name);
    cap.set("ops", ops);
    cap.set("native_commands", (unsigned long long)host().commandCount());
    Json oob = Json::array();
    for(const char* n : { "pause", "stop", "status", "interrupt", "quit" })
        oob.push(n);
    cap.set("oob", oob);
    h.set("capabilities", cap);
    return h;
}

void Session::start()
{
    execThread_ = std::thread([this] { executorMain(); });
    ctrlThread_ = std::thread([this] { controlMain(); });
    guardThread_ = std::thread([this] { guardMain(); });
}

void Session::startReader()
{
    bool expected = readerDone_.load();
    if(!expected || readerThread_.joinable())
        return;
    readerDone_ = false;
    readerThread_ = std::thread([this] { readerMain(); });
}

void Session::queueStartupRaw(const std::string & line)
{
    ParseError err;
    RequestPtr req;
    bool skip = false;
    std::string id = "s" + std::to_string(++startupCounter_);
    if(!parseTextLine(line, id, req, err, skip))
    {
        req = std::make_shared<Request>();
        req->textId = id;
        req->echo = Json::object();
        req->echo.set("cmd", line);
        req->preError = std::make_shared<ParseError>(err);
    }
    else if(skip)
    {
        startupCounter_--;
        return;
    }
    req->id = Json(id);
    req->startup = true;
    startupTotal_++;
    std::lock_guard<std::mutex> lk(mu_);
    execQ_.push_back(req);
    qcv_.notify_all();
}

void Session::queueStartup(const std::vector<std::string> & lines, bool)
{
    for(auto & l : lines)
        queueStartupRaw(l);
    if(startupTotal_ == 0)
        startupDone_ = true;
}

void Session::requestShutdown(const char* reason)
{
    if(shutdown_.exchange(true))
        return;
    shutdownReason_ = reason;
    io::diag(std::string("shutdown requested: ") + reason);
    host().requestShutdown();
    std::thread([this] { watchdogMain(); }).detach();
    host().postJob([]()
    {
        return false;
    });
    qcv_.notify_all();
}

void Session::watchdogMain()
{
    for(int i = 0; i < 300; i++)
    {
        Sleep(100);
        if(hardKill_.load())
            return;
    }
    fatalExit("E_SHUTDOWN_HANG", "shutdown did not finish within 30 s");
}

void Session::fatalExit(const std::string & code, const std::string & message)
{
    io::writeFatal(renderFatal(opt.json, code, message));
    TerminateProcess(GetCurrentProcess(), 70);
}

// ------------------------------------------------------------------ small helpers

long long Session::effectiveTimeout(const Request & req) const
{
    return req.opt.timeoutMs >= 0 ? req.opt.timeoutMs : opt.timeoutMs;
}

long long Session::maxOutputOf(const Request & req) const
{
    return req.opt.maxOutput >= 0 ? req.opt.maxOutput : opt.maxOutput;
}

bool Session::execNative(Request & req, const std::string & segment, const std::string & lowerCanon)
{
    long long limit = std::max<long long>(opt.stuckMs, effectiveTimeout(req) + 5000);
    bool isPause = lowerCanon == "pause";
    std::unique_lock<std::mutex> oob(oobMu_, std::defer_lock);
    if(isPause)
    {
        oob.lock();
        host().pushEvent("pause_requested");
        host().setLastResumeName("");
    }
    CoreCall cc(*this, limit);
    return DbgCmdExecDirect(coreLine(segment).c_str());
}

// ------------------------------------------------------------------ response building

Json Session::stateJson(const Result & res, bool executorThread)
{
    Host & h = host();
    Status st;
    long long seq;
    unsigned long long pid;
    bool exitValid;
    unsigned exitCode;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        st = h.reportedStatusLocked();
        seq = h.stateSeq;
        pid = h.pid;
        exitValid = h.exitCodeValid;
        exitCode = h.exitCode;
    }
    bool dbg = DbgIsDebugging();
    Json s = Json::object();
    s.set("status", statusName(st));
    s.set("debugging", dbg);
    if(dbg && pid)
        s.set("pid", pid);
    else if(dbg)
        s.set("pid", (unsigned long long)DbgGetProcessId());
    else
        s.set("pid", nullptr);
    bool paused = st == Status::Paused && dbg;
    s.set("tid", paused && executorThread ? Json(activeThreadId()) : Json());
    if(paused)
    {
        bool ok = false;
        duint cip = DbgEval("cip", &ok);
        if(ok)
        {
            s.set("cip", hexAddr(cip));
            char label[MAX_LABEL_SIZE] = "";
            if(DbgGetLabelAt(cip, SEG_DEFAULT, label) && label[0])
                s.set("cip_label", label);
            else
                s.set("cip_label", nullptr);
            char mod[MAX_MODULE_SIZE] = "";
            const DBGFUNCTIONS* f = DbgFunctions();
            if(f && f->ModNameFromAddr && f->ModNameFromAddr(cip, mod, true) && mod[0])
                s.set("module", mod);
            else
                s.set("module", nullptr);
        }
        else
        {
            s.set("cip", nullptr);
            s.set("cip_label", nullptr);
            s.set("module", nullptr);
        }
    }
    else
    {
        s.set("cip", nullptr);
        s.set("cip_label", nullptr);
        s.set("module", nullptr);
    }
    s.set("seq", seq);
    if(st == Status::Stopped && exitValid)
        s.set("exit_code", (unsigned long long)exitCode);
    else
        s.set("exit_code", nullptr);
    s.set("stop", res.hasStop ? res.stop : Json());
    return s;
}

Json tableToJson(const RefTable & t, size_t offset, size_t limit)
{
    Json j = Json::object();
    j.set("id", t.id);
    j.set("name", t.name);
    Json cols = Json::array();
    for(auto & c : t.columns)
        cols.push(c);
    j.set("columns", cols);
    Json rows = Json::array();
    size_t end = std::min(t.rows.size(), offset + limit);
    for(size_t i = offset; i < end; i++)
    {
        Json r = Json::array();
        for(auto & c : t.rows[i])
            r.push(c);
        rows.push(r);
    }
    j.set("rows", rows);
    j.set("total_rows", t.totalRows);
    j.set("truncated", (long long)(end - std::min(offset, end)) < t.totalRows - (long long)offset);
    Json actions = Json::array();
    for(auto & a : t.actions)
    {
        Json x = Json::object();
        x.set("title", a.first);
        x.set("command", a.second);
        actions.push(x);
    }
    j.set("actions", actions);
    return j;
}

void Session::resolveEvents(std::vector<Json> & events)
{
    for(auto & ev : events)
    {
        const Json* t = ev.find("type");
        if(!t || t->asString() != "debug_string")
            continue;
        const Json* addr = ev.find("_addr");
        if(!addr)
            continue;
        unsigned long long a = (unsigned long long)addr->asInt();
        unsigned long long len = ev.find("_len") ? (unsigned long long)ev.find("_len")->asInt() : 0;
        bool uni = ev.find("_uni") && ev.find("_uni")->asInt() != 0;
        std::string text;
        if(a && len)
        {
            size_t bytes = (size_t)std::min<unsigned long long>(len * (uni ? 2 : 1), 4096);
            std::vector<char> buf(bytes + 2, 0);
            if(DbgMemRead(a, buf.data(), bytes))
            {
                if(uni)
                    text = utf8Of((const wchar_t*)buf.data());
                else
                    text = std::string(buf.data(), strnlen(buf.data(), bytes));
            }
        }
        ev.set("text", text);
        ev.erase("_addr");
        ev.erase("_len");
        ev.erase("_uni");
    }
}

Json Session::buildResponse(Request & req, Result & res, bool oob)
{
    Host & h = host();
    Json r = Json::object();
    r.set("type", "response");
    r.set("v", kProtocolVersion);
    r.set("id", req.id);
    if(req.echo.isObject())
        for(auto & m : req.echo.members())
            r.set(m.first, m.second);
    r.set("ok", res.ok);
    r.set("error", res.ok ? Json() : makeErrorObject(res.code, res.message, res.detail));
    r.set("output", res.output);
    r.set("data", res.data);
    Json tables = Json::array();
    for(auto & t : res.tables)
        tables.push(t);
    r.set("tables", tables);
    r.set("vars", res.vars);
    r.set("state", stateJson(res, !oob));
    Json w = Json::object();
    w.set("waited", res.wait.waited);
    w.set("reason", res.wait.reason);
    w.set("timed_out", res.wait.timedOut);
    w.set("elapsed_ms", res.wait.elapsedMs);
    r.set("wait", w);
    Json events = Json::array();
    long long nextUndelivered = 0;
    if(!oob)
    {
        bool dropped = false;
        std::vector<Json> evs;
        {
            std::lock_guard<std::mutex> lk(mu_);
            evs = h.takeEvents((size_t)req.opt.maxEvents, &nextUndelivered, &dropped);
        }
        resolveEvents(evs);
        for(auto & e : evs)
            events.push(e);
        if(nextUndelivered)
            res.warnings.push_back("events_truncated");
    }
    r.set("events", events);
    if(!oob && nextUndelivered)
        r.set("events_next_seq", nextUndelivered);
    Json warnings = Json::array();
    for(auto & x : res.warnings)
        warnings.push(x);
    r.set("warnings", warnings);
    if(res.hasResults)
        r.set("results", res.results);
    r.set("truncated", res.truncated);
    Json meta = Json::object();
    meta.set("elapsed_ms", (long long)std::chrono::duration_cast<milliseconds>(steady_clock::now() - req.started).count());
    meta.set("log_end", h.logEnd());
    r.set("meta", meta);
    return r;
}

void Session::send(Request & req, const Json & response)
{
    if(req.responded.exchange(true))
        return;
    std::string msg;
    if(opt.json)
        msg = renderJsonLine(response);
    else
        msg = renderTextResponse(response, req.textId.empty() ? std::to_string(req.id.isInt() ? req.id.asInt() : 0) : req.textId);
    long long cap = req.opt.maxResponseBytes;
    if(cap > 0 && (long long)msg.size() > cap)
    {
        Json d = Json::object();
        d.set("bytes", (long long)msg.size());
        Result r;
        r.fail("E_TOO_LONG", "response exceeds max_response_bytes", d);
        Json resp = Json::object();
        resp.set("type", "response");
        resp.set("v", kProtocolVersion);
        resp.set("id", req.id);
        if(req.echo.isObject())
            for(auto & m : req.echo.members())
                resp.set(m.first, m.second);
        resp.set("ok", false);
        resp.set("error", makeErrorObject(r.code, r.message, r.detail));
        resp.set("output", "");
        resp.set("data", nullptr);
        resp.set("tables", Json::array());
        resp.set("vars", Json::object());
        const Json* st = response.find("state");
        resp.set("state", st ? *st : Json::object());
        resp.set("wait", *response.find("wait"));
        resp.set("events", Json::array());
        resp.set("warnings", Json::array());
        resp.set("truncated", false);
        resp.set("meta", *response.find("meta"));
        msg = opt.json ? renderJsonLine(resp) : renderTextResponse(resp, req.textId);
    }
    io::writeProtocol(std::move(msg));
}

void Session::sendError(Request & req, const std::string & code, const std::string & message, const Json & detail)
{
    Result res;
    res.fail(code, message, detail);
    req.started = steady_clock::now();
    Json resp = buildResponse(req, res, true);
    send(req, resp);
}

// ------------------------------------------------------------------ Reader and routing

void Session::readerMain()
{
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &readerHandle_, 0, FALSE, DUPLICATE_SAME_ACCESS);
    io::LineReader reader;
    reader.shouldStop = [this] { return host().shuttingDownA.load(); };
    bool console = io::stdinIsConsole() && !opt.json;
    unsigned seedState = GetTickCount();
    reader.beforeRead = [&]
    {
        if(opt.testReaderDelay > 0)
        {
            seedState = seedState * 1103515245u + 12345u;
            Sleep((seedState >> 16) % (unsigned)(opt.testReaderDelay + 1));
        }
        if(console)
            io::writeProtocol("x64dbg> ");
    };
    while(true)
    {
        std::string line;
        auto r = reader.read(line);
        if(r == io::LineReader::Cancelled)
            break;
        if(r == io::LineReader::Eof)
        {
            host().setEof();
            std::lock_guard<std::mutex> lk(mu_);
            if(!active_ && execQ_.empty() && oobQ_.empty())
                requestShutdown("eof");
            break;
        }
        if(host().shuttingDownA.load())
        {
            // new input after shutdown started is answered with E_SHUTDOWN
        }
        RequestPtr req;
        ParseError err;
        if(r == io::LineReader::TooLong)
        {
            req = std::make_shared<Request>();
            req->echo = Json::object();
            req->textId = std::to_string(++idCounter_);
            req->started = steady_clock::now();
            sendError(*req, "E_TOO_LONG", "request line exceeds 1 MiB");
            continue;
        }
        if(opt.json)
        {
            if(trim(line).empty())
                continue;
            if(!parseJsonRequest(line, req, err))
            {
                Request e;
                e.id = err.id;
                e.textId = std::to_string(++idCounter_);
                e.echo = Json::object();
                sendError(e, err.code, err.message, err.detail);
                continue;
            }
            req->textId = std::to_string(++idCounter_);
        }
        else
        {
            bool skip = false;
            std::string id = std::to_string(++idCounter_);
            if(!parseTextLine(line, id, req, err, skip))
            {
                Request e;
                e.textId = id;
                e.id = Json(id);
                e.echo = Json::object();
                sendError(e, err.code, err.message, err.detail);
                continue;
            }
            if(skip)
            {
                idCounter_--;
                continue;
            }
        }
        submit(req);
    }
    readerDone_ = true;
}

bool Session::isOobRequest(const Request & req)
{
    if(req.isOp && req.op != "native")
    {
        const OpSpec* s = findOp(req.op);
        return s && s->oob;
    }
    if(req.isBatch)
        return false;
    std::string text = trim(req.cmd);
    if(text.empty() || text[0] == '$')
        return false;
    auto segs = splitSemicolon(text);
    if(segs.size() != 1)
        return false;
    std::string c = lower(host().canonicalOf(firstWord(segs[0])));
    return c == "pause" || c == "stopdebug";
}

void Session::submit(RequestPtr req)
{
    req->started = steady_clock::now();
    if(shutdown_.load())
    {
        sendError(*req, "E_SHUTDOWN", "the CLI is shutting down");
        return;
    }
    bool oob = isOobRequest(*req);
    bool busy = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if(oob)
            oobQ_.push_back(req);
        else if(execQ_.size() >= 256)
            busy = true;
        else
            execQ_.push_back(req);
    }
    if(busy)
    {
        sendError(*req, "E_BUSY", "executor queue is full (256 requests)");
        return;
    }
    qcv_.notify_all();
}

// ------------------------------------------------------------------ Executor

void Session::executorMain()
{
    while(true)
    {
        RequestPtr req;
        {
            std::unique_lock<std::mutex> lk(mu_);
            qcv_.wait(lk, [this] { return !execQ_.empty() || stopping_.load(); });
            if(execQ_.empty())
            {
                if(stopping_.load())
                    break;
                continue;
            }
            req = execQ_.front();
            execQ_.pop_front();
            active_ = req;
        }
        try
        {
            process(req);
        }
        catch(...)
        {
        }
        bool idleEof = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            active_.reset();
            idleEof = host().eof && execQ_.empty() && oobQ_.empty();
        }
        host().notifyAll();
        if(idleEof)
            requestShutdown("eof");
    }
    execDone_ = true;
}

void Session::process(RequestPtr reqp)
{
    Request & req = *reqp;
    Host & h = host();
    if(req.startup && startupAbort_)
    {
        noteStartupAnswered(req, Json());
        return;
    }
    req.started = steady_clock::now();
    {
        std::lock_guard<std::mutex> lk(h.mu);
        req.tableCursor = h.tableCounter;
        req.logStart = std::max(h.logEndLocked(), h.requestFloor);
    }
    Result res;
    res.promptsBefore = 0;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        res.promptsBefore = h.promptsSeen.size();
    }
    try
    {
        dispatch(req, res);
        finalize(req, res);
    }
    catch(const std::exception & e)
    {
        res.fail("E_INTERNAL", e.what(), Json());
    }
    catch(...)
    {
        res.fail("E_INTERNAL", "unknown exception", Json());
    }
    {
        // keep the time-wasted counter and process info up to date for the OOB status op
        h.timeWastedMs = DbgIsDebugging() ? (unsigned long long)DbgGetTimeWastedCounter() : 0;
        refreshProcessInfo();
    }
    if(req.responded.load())
    {
        // the Guard already answered with E_TIMEOUT: the result is dropped (design 8.4)
        Json f = Json::object();
        f.set("message", "late result of request " + (req.id.isString() ? req.id.asString() : req.id.dump()) + " dropped");
        h.pushEvent("late_result", f);
        noteStartupAnswered(req, Json());
        return;
    }
    Json resp = buildResponse(req, res, false);
    send(req, resp);
    noteStartupAnswered(req, resp);
}

void Session::noteStartupAnswered(Request & req, const Json & response)
{
    if(!req.startup)
        return;
    int fail = 0;
    if(response.isObject())
    {
        const Json* ok = response.find("ok");
        const Json* w = response.find("wait");
        if(ok && !ok->asBool())
            fail = 1;
        else if(w && w->find("timed_out") && w->find("timed_out")->asBool())
            fail = 4;
    }
    bool done = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        startupAnswered_++;
        if(fail)
        {
            startupFail_ = fail;
            if(!opt.keepGoing && !opt.interactive)
                startupAbort_ = true;
        }
        done = startupAnswered_ >= startupTotal_ || startupAbort_;
        if(startupAbort_)
        {
            // drop the remaining startup items silently
            for(auto it = execQ_.begin(); it != execQ_.end();)
            {
                if((*it)->startup)
                {
                    startupAnswered_++;
                    it = execQ_.erase(it);
                }
                else
                    ++it;
            }
        }
    }
    if(!done)
        return;
    startupDone_ = true;
    if(opt.oneShot())
    {
        exitCode_ = startupFail_;
        requestShutdown("done");
    }
    else
        startReader();
}

void Session::refreshProcessInfo()
{
    Host & h = host();
    bool stale;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        stale = h.processStale;
    }
    if(!stale || !DbgIsDebugging())
        return;
    bool ok = false;
    duint entry = DbgEval("mod.entry(mod.main())", &ok);
    if(ok)
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.procEntry = entry;
        h.procEntryValid = true;
        h.processStale = false;
    }
}

void Session::dispatch(Request & req, Result & res)
{
    if(req.preError)
    {
        res.fail(req.preError->code, req.preError->message, req.preError->detail);
        return;
    }
    if(req.isBatch)
    {
        runBatch(req, res);
        return;
    }
    if(req.isOp && req.op != "native")
    {
        runOp(req, res);
        return;
    }
    runNativeLine(req, res);
}

// ------------------------------------------------------------------ native lines

void Session::runNativeLine(Request & req, Result & res)
{
    Host & h = host();
    auto expand = [&](const std::string & text, std::string & out, bool & tooLong) -> bool
    {
        CoreCall cc(*this, std::max<long long>(opt.stuckMs, 5000));
        return expandLine([](const char* fmt, size_t n, char* dest)
        {
            const DBGFUNCTIONS* f = DbgFunctions();
            return f && f->StringFormatInline && f->StringFormatInline(fmt, n, dest);
        }, text, out, tooLong);
    };
    auto canon = [&](const std::string & w) { return h.canonicalOf(w); };
    LinePlan plan = planNativeLine(req.cmd, expand, canon);
    if(!plan.ok)
    {
        res.fail(plan.code, plan.message);
        return;
    }
    res.barrierNeeded = true;
    for(auto & seg : plan.segments)
    {
        if(h.shuttingDownA.load())
        {
            res.wait.reason = "shutdown";
            break;
        }
        SegOutcome o = runSegment(req, res, seg);
        if(req.abandoned.load())
            break;
        req.completed++;
        if(o == SegOutcome::Stop)
            break;
    }
}

Session::SegOutcome Session::runSegment(Request & req, Result & res, const std::string & seg)
{
    Host & h = host();
    std::string canon = h.canonicalOf(firstWord(seg));
    std::string lc = lower(canon);
    enum Cls
    {
        Other,
        Resume,
        Init,
        Attach,
        StopCls
    } cls = Other;
    if(lc == "initdebug")
        cls = Init;
    else if(lc == "attachdebugger")
        cls = Attach;
    else if(lc == "stopdebug" || lc == "detachdebugger")
        cls = StopCls;
    else if(isResumeClass(lc))
        cls = Resume;
    const bool never = req.opt.wait == "never";
    const bool always = req.opt.wait == "always";
    const long long timeoutMs = effectiveTimeout(req);
    res.wait = WaitInfo();

    // running guard (design 7.4)
    {
        bool hasArg = trim(seg).size() > firstWord(seg).size();
        bool guarded = isStepGuard(lc) || ((lc == "run" || lc == "serun") && hasArg);
        if(guarded && DbgIsDebugging() && DbgIsRunning())
        {
            bool zero = false;
            if(isCountForm(lc) && hasArg)
            {
                std::string rest = trim(trim(seg).substr(firstWord(seg).size()));
                // first argument: up to the first comma
                std::string a = trim(rest.substr(0, rest.find(',')));
                bool ok = false;
                duint v = DbgEval(a.c_str(), &ok);
                zero = ok && v == 0;
            }
            if(zero)
            {
                res.wait.reason = "already_running";
                return SegOutcome::Done;
            }
            Status st;
            {
                std::lock_guard<std::mutex> lk(h.mu);
                st = h.reportedStatusLocked();
            }
            if(st == Status::Starting)
                res.fail("E_RUNNING", "session is starting; use wait first");
            else
                res.fail("E_RUNNING", "debuggee is running; use pause first (" + canon + " would arm stepping state in the core)");
            return SegOutcome::Stop;
        }
    }

    long long s0;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        s0 = h.stateSeq;
    }
    if(cls == Resume)
        h.setLastResumeName(lc);
    else if(cls == Init || cls == Attach || cls == StopCls)
        h.setLastResumeName("");
    if(cls == Init || cls == Attach)
        h.beginLaunch();
    long long startedMs = nowMs();

    bool ok = execNative(req, seg, lc);
    if(req.abandoned.load())
        return SegOutcome::Stop;

    // generic repair step: a command may resume without a state message
    if(ok)
    {
        bool same;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            same = h.stateSeq == s0;
        }
        if(same && DbgIsDebugging() && DbgIsRunning() && h.synthesizeRunningIf(s0))
            res.warnings.push_back("resumed_without_state_message");
    }

    if(!ok)
    {
        if(cls == Init || cls == Attach)
            h.endLaunch();
        res.ok = false;
        res.pending = Result::PendingCommandFailed;
        res.failSegment = seg;
        return SegOutcome::Stop;
    }

    if(never || timeoutMs == 0 || (cls == Other && !always))
    {
        res.wait.elapsedMs = nowMs() - startedMs;
        if((cls == Init || cls == Attach) && !sessionStarted(s0, cls == Attach ? 3000 : 500))
        {
            h.endLaunch();
            res.ok = false;
            res.pending = Result::PendingInitNoSession;
        }
        return res.ok ? SegOutcome::Done : SegOutcome::Stop;
    }

    if(cls == Resume || cls == Other)
    {
        bool same;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            same = h.stateSeq == s0;
        }
        if(same)
        {
            res.wait.reason = DbgIsRunning() ? "already_running" : "not_resumed";
            res.wait.elapsedMs = nowMs() - startedMs;
            return SegOutcome::Done;
        }
        WaitOut out = waitLoop(req, WaitKind::Resume, s0, -1, timeoutMs, 0, res);
        return applyWaitOutcome(req, res, out, startedMs, lc);
    }
    if(cls == Init || cls == Attach)
    {
        if(!sessionStarted(s0, cls == Attach ? 3000 : 500))
        {
            h.endLaunch();
            res.ok = false;
            res.pending = Result::PendingInitNoSession;
            return SegOutcome::Stop;
        }
        WaitKind kind = cls == Init ? (always ? WaitKind::InitAlways : WaitKind::Init)
                        : (always ? WaitKind::AttachAlways : WaitKind::Attach);
        long long tmo = timeoutMs;
        if(cls == Attach && !always)
            tmo = std::min<long long>(tmo, 10000);
        WaitOut out = waitLoop(req, kind, s0, -1, tmo, req.opt.settleMs, res);
        SegOutcome o = applyWaitOutcome(req, res, out, startedMs, lc);
        if(DbgIsDebugging())
            refreshProcessInfo();
        return o;
    }
    // Stop class
    WaitOut out = waitLoop(req, WaitKind::Stop, s0, -1, std::min<long long>(timeoutMs, 15000), 0, res);
    return applyWaitOutcome(req, res, out, startedMs, lc);
}

// ------------------------------------------------------------------ waiting

// A launch or attach has produced a session once the core reports debugging or announced "initialized".
// An attach starts its debug loop asynchronously, so the evidence may arrive a moment after the command returned.
bool Session::sessionStarted(long long s0, int waitMs)
{
    Host & h = host();
    long long until = nowMs() + waitMs;
    while(true)
    {
        if(DbgIsDebugging())
            return true;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            if(h.initSeq > s0)
                return true;
        }
        if(nowMs() >= until || h.shuttingDownA.load())
            return false;
        Sleep(10);
    }
}

bool Session::confirmPaused(Request &, long long deadlineMs)
{
    auto spinStart = steady_clock::now();
    bool warned = false;
    while(true)
    {
        if(!DbgIsDebugging() || !DbgIsRunning())
            return true;
        if(host().shuttingDownA.load() || nowMs() >= deadlineMs)
            return false;
        auto spent = std::chrono::duration_cast<milliseconds>(steady_clock::now() - spinStart).count();
        (void)warned;
        Sleep(spent < 500 ? 2 : 20);
    }
}

Session::WaitOut Session::waitLoop(Request & req, WaitKind kind, long long s0, long long launchS0, long long timeoutMs, long long settleMs, Result & res)
{
    Host & h = host();
    auto start = steady_clock::now();
    auto deadline = start + milliseconds(timeoutMs);
    WaitOut out;
    bool holds = false, warned = false;
    steady_clock::time_point holdSince, lastRepeat;
    long long settleSeq = -1;
    steady_clock::time_point settleSince;
    bool breakAfterTick = false;

    std::unique_lock<std::mutex> lk(h.mu);
    h.waitersPending++;
    for(;;)
    {
        Status st = h.status;
        bool done = false;
        const char* reason = "paused";
        switch(kind)
        {
        case WaitKind::Resume:
            done = (st == Status::Paused || st == Status::Stopped) && h.stateSeq > s0;
            reason = st == Status::Paused ? "paused" : "stopped";
            break;
        case WaitKind::Init:
        case WaitKind::InitAlways:
            done = h.initSeq > s0 && (st == Status::Paused || st == Status::Stopped) && h.stateSeq > h.initSeq;
            reason = st == Status::Paused ? "paused" : "stopped";
            break;
        case WaitKind::Attach:
            done = h.initSeq > s0 && (st == Status::Running || st == Status::Paused || st == Status::Stopped) && h.stateSeq > h.initSeq;
            reason = st == Status::Paused ? "paused" : st == Status::Running ? "running" : "stopped";
            break;
        case WaitKind::AttachAlways:
            done = h.initSeq > s0 && (st == Status::Paused || st == Status::Stopped) && h.stateSeq > h.initSeq;
            reason = st == Status::Paused ? "paused" : "stopped";
            break;
        case WaitKind::Stop:
            done = st == Status::Stopped;
            reason = "stopped";
            break;
        case WaitKind::WaitOp:
            done = (st == Status::Paused || st == Status::Stopped) && h.stateSeq > s0 && (launchS0 < 0 || h.initSeq > launchS0);
            reason = st == Status::Paused ? "paused" : "stopped";
            break;
        }
        if(done)
        {
            out.reason = reason;
            out.pausedSeq = h.lastPausedSeq;
            break;
        }
        if(h.interruptRequested)
        {
            h.interruptRequested = false;
            out.reason = "interrupted";
            break;
        }
        if(h.shuttingDown)
        {
            out.reason = "shutdown";
            break;
        }
        auto now = steady_clock::now();
        if(h.eof && now >= std::max(start, h.eofAt) + milliseconds(opt.eofWaitMs))
        {
            out.reason = "shutdown";
            break;
        }
        if(now >= deadline)
        {
            out.reason = "timeout";
            out.timedOut = true;
            break;
        }
        if(kind == WaitKind::Init && h.initSeq > s0 && st == Status::Running && h.stateSeq > h.initSeq)
        {
            if(settleSeq != h.stateSeq)
            {
                settleSeq = h.stateSeq;
                settleSince = now;
            }
            else if(now - settleSince >= milliseconds(settleMs))
            {
                out.reason = "running";
                break;
            }
        }
        bool pollRunning = st == Status::Running;
        bool initFallback = kind == WaitKind::Init && h.initSeq <= s0 && now - start >= milliseconds(2000);
        long long lrs = h.lastRunningSeq;
        lk.unlock();
        if(pollRunning)
        {
            bool dbg = DbgIsDebugging();
            bool run = dbg ? DbgIsRunning() : true;
            if(dbg && !run)
            {
                if(!holds)
                {
                    holds = true;
                    holdSince = now;
                    lastRepeat = now;
                }
                auto dur = std::chrono::duration_cast<milliseconds>(now - holdSince).count();
                if(dur >= 500 && !warned)
                {
                    warned = true;
                    Json f = Json::object();
                    f.set("message", "paused_state_unconfirmed");
                    h.pushEvent("warning", f);
                    res.warnings.push_back("paused_state_unconfirmed");
                }
                if(dur >= 5000)
                {
                    bool cause = false;
                    for(auto & ev : h.eventWindow(lrs, LLONG_MAX))
                    {
                        std::string t = ev.find("type")->asString();
                        if(t == "breakpoint_hit" || t == "system_breakpoint" || t == "exception")
                            cause = true;
                    }
                    if(!cause)
                    {
                        h.synthesizePaused("unknown");
                        res.warnings.push_back("paused_without_state_message");
                    }
                    else if(now - lastRepeat >= milliseconds(5000))
                    {
                        lastRepeat = now;
                        res.warnings.push_back("paused_state_unconfirmed");
                    }
                }
            }
            else
            {
                holds = false;
                warned = false;
            }
        }
        if(initFallback && DbgIsDebugging())
        {
            res.warnings.push_back("init_state_unconfirmed");
            breakAfterTick = true;
        }
        lk.lock();
        if(breakAfterTick)
        {
            out.reason = "running";
            break;
        }
        h.cv.wait_until(lk, std::min(deadline, steady_clock::now() + milliseconds(100)));
    }
    h.waitersPending--;
    if(out.timedOut && holds)
        res.warnings.push_back("core_run_lock_held");
    return out;
}

Session::SegOutcome Session::applyWaitOutcome(Request & req, Result & res, const WaitOut & out, long long startedMs, const std::string &)
{
    Host & h = host();
    res.wait.waited = true;
    res.wait.reason = out.reason;
    res.wait.timedOut = out.timedOut;
    long long pausedSeq = out.pausedSeq;
    bool stoppedReason = out.reason == "stopped";
    if(out.reason == "paused")
    {
        long long deadline = nowMs() + 5000;
        if(!confirmPaused(req, deadline))
        {
            res.wait.reason = "timeout";
            res.wait.timedOut = true;
        }
        else
            finishPaused(req, res, pausedSeq);
    }
    else if(stoppedReason)
        stoppedTail(req, res);

    if(out.timedOut)
    {
        if(req.opt.onTimeout == "pause")
        {
            if(pauseWithRetry(req, res, req.opt.pauseSettleMs))
            {
                Status st;
                long long ps;
                {
                    std::lock_guard<std::mutex> lk(h.mu);
                    st = h.status;
                    ps = h.lastPausedSeq;
                }
                if(st == Status::Paused)
                    finishPaused(req, res, ps);
                else if(st == Status::Stopped)
                    stoppedTail(req, res);
            }
            // the pause result must not turn the wait into a failure: the request itself succeeded
            res.ok = true;
            res.code.clear();
            res.message.clear();
            res.wait.waited = true;
            res.wait.reason = "timeout";
            res.wait.timedOut = true;
        }
        else if(req.opt.onTimeout == "stop")
        {
            Result tmp;
            doStop(req, tmp, 15000);
            stoppedTail(req, res);
        }
    }
    res.wait.elapsedMs = nowMs() - startedMs;
    if(res.wait.reason == "timeout" || res.wait.reason == "interrupted" || res.wait.reason == "shutdown")
        return SegOutcome::Stop;
    return SegOutcome::Done;
}

AttribInput Session::makeAttrib(long long pausedSeq)
{
    Host & h = host();
    AttribInput in;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        in.pausedSeq = pausedSeq;
        in.lastRunningSeq = h.pausedRunningSeq;
        in.lastExcValid = h.lastException.valid;
        in.lastExcCode = h.lastException.code;
        in.lastExcStamp = h.lastException.stamp;
        in.lastResumeName = h.lastResumeName;
        for(auto & ev : h.events)
        {
            long long s = ev.find("seq")->asInt();
            if(s > in.lastRunningSeq && s <= pausedSeq)
                in.window.push_back(ev);
        }
        for(auto & ev : h.events)
        {
            long long s = ev.find("seq")->asInt();
            if(s <= pausedSeq)
                continue;
            const std::string t = ev.find("type")->asString();
            if(t == "resumed")
                break;
            if(t == "stepped" || t == "exception")
                in.trailing.push_back(ev);
        }
    }
    bool ok = false;
    in.cip = DbgEval("cip", &ok);
    auto flag = [](const char* key) -> bool
    {
        duint v = 0;
        return BridgeSettingGetUint("Events", key, &v) && v != 0;
    };
    in.threadStart = flag("ThreadStart");
    in.threadEnd = flag("ThreadEnd");
    in.dllLoad = flag("DllLoad") || flag("DllLoadSystem");
    in.dllUnload = flag("DllUnload") || flag("DllUnloadSystem");
    in.debugStrings = flag("DebugStrings");
    return in;
}

void Session::finishPaused(Request &, Result & res, long long pausedSeq)
{
    Host & h = host();
    AttribInput in = makeAttrib(pausedSeq);
    Json stop = attribute(in);
    std::string reason = stop.find("reason")->asString();
    bool skip = !in.trailing.empty() || reason == "breakpoint" || reason == "system_breakpoint";
    if(!skip)
    {
        bool notice = in.lastExcValid && in.lastExcStamp > in.lastRunningSeq && in.lastExcStamp < pausedSeq;
        if(!windowHasCause(in) && !notice && isFinisher(in.lastResumeName))
            skip = true;
    }
    if(!skip && trailMs_ > 0 && !h.shuttingDownA.load())
    {
        auto until = steady_clock::now() + milliseconds(trailMs_);
        std::unique_lock<std::mutex> lk(h.mu);
        while(!h.shuttingDown)
        {
            bool found = false, resumed = false;
            for(auto & ev : h.events)
            {
                if(ev.find("seq")->asInt() <= pausedSeq)
                    continue;
                const std::string t = ev.find("type")->asString();
                if(t == "resumed")
                {
                    resumed = true;
                    break;
                }
                if(t == "stepped" || t == "exception")
                {
                    found = true;
                    break;
                }
            }
            if(found || resumed || steady_clock::now() >= until)
                break;
            h.cv.wait_until(lk, until);
        }
        lk.unlock();
        in = makeAttrib(pausedSeq);
        stop = attribute(in);
    }
    res.stop = stop;
    res.hasStop = true;
}

void Session::stoppedTail(Request & req, Result &)
{
    Host & h = host();
    auto until = steady_clock::now() + milliseconds(kStoppedTailMs);
    while(steady_clock::now() < until && !h.shuttingDownA.load())
    {
        if(h.ringHasLineSince(req.logStart, "Debugging stopped!"))
            return;
        Sleep(5);
    }
}

bool Session::pauseWithRetry(Request & req, Result & res, long long settleMs)
{
    Host & h = host();
    long long s0;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        s0 = h.stateSeq;
    }
    bool ok = execNative(req, "pause", "pause");
    // execNative took and released oobMu_ itself (it holds it for the duration of the call only)
    if(!ok && DbgIsDebugging())
    {
        // cbGenericBreakpoint holds the run lock while it evaluates a breakpoint condition, so the core briefly
        // answers "Program is not running" for a debuggee that is logically running (design 3.6). While the cached
        // state says running, repeat the call for a short time instead of reporting a failure.
        long long until = nowMs() + 1500;
        while(!ok && nowMs() < until && !h.shuttingDownA.load())
        {
            Status st;
            {
                std::lock_guard<std::mutex> lk(h.mu);
                st = h.status;
            }
            if(st != Status::Running)
                break;
            Sleep(25);
            std::lock_guard<std::mutex> g(oobMu_);
            CoreCall cc(*this, std::max<long long>(opt.stuckMs, 5000));
            ok = DbgCmdExecDirect(" pause");
        }
    }
    if(!ok)
    {
        if(!DbgIsDebugging())
            res.fail("E_NOT_DEBUGGING", "Not debugging! pause needs a debug session");
        else
            res.fail("E_COMMAND_FAILED", "Program is not running");
        return false;
    }
    auto start = steady_clock::now();
    auto deadline = start + milliseconds(settleMs);
    auto lastPause = start;
    duint eventsAtPause = DbgFunctions()->GetDbgEvents ? DbgFunctions()->GetDbgEvents() : 0;
    std::unique_lock<std::mutex> lk(h.mu);
    for(;;)
    {
        if((h.status == Status::Paused || h.status == Status::Stopped) && h.stateSeq > s0)
            break;
        auto now = steady_clock::now();
        if(h.shuttingDown || now >= deadline)
        {
            res.wait.timedOut = true;
            res.wait.reason = "timeout";
            lk.unlock();
            return false;
        }
        // The core's own fallback (a break-in thread) needs 2 s without any debug event. When events keep arriving (a hot
        // breakpoint with a false condition) the INT3 of the first request may sit at a stale address, so ask again sooner.
        bool retryDue = now - lastPause >= milliseconds(2200);
        if(!retryDue && h.status == Status::Running && now - lastPause >= milliseconds(300))
        {
            lk.unlock();
            duint ev = DbgFunctions()->GetDbgEvents ? DbgFunctions()->GetDbgEvents() : 0;
            lk.lock();
            retryDue = ev != eventsAtPause;
        }
        if(h.status == Status::Running && retryDue)
        {
            lk.unlock();
            if(DbgIsDebugging() && DbgIsRunning())
            {
                std::string w = "pause_retry";
                execNative(req, "pause", "pause");
                Json f = Json::object();
                f.set("message", w);
                h.pushEvent("warning", f);
                res.warnings.push_back(w);
            }
            lastPause = steady_clock::now();
            eventsAtPause = DbgFunctions()->GetDbgEvents ? DbgFunctions()->GetDbgEvents() : 0;
            lk.lock();
            continue;
        }
        h.cv.wait_until(lk, std::min(deadline, now + milliseconds(100)));
    }
    lk.unlock();
    confirmPaused(req, nowMs() + 2000);
    res.wait.waited = true;
    res.wait.reason = "paused";
    res.wait.timedOut = false;
    return true;
}

bool Session::doStop(Request & req, Result & res, long long timeoutMs)
{
    Host & h = host();
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto okp = std::make_shared<std::atomic<bool>>(false);
    long long limit = std::max<long long>(opt.stuckMs, effectiveTimeout(req) + 5000);
    (void)limit;
    std::thread([done, okp]
    {
        okp->store(DbgCmdExecDirect(" stop"));
        done->store(true);
    }).detach();
    long long tmo = std::min<long long>(timeoutMs, 15000);
    long long until = nowMs() + tmo;
    while(!done->load() && nowMs() < until)
        Sleep(5);
    if(!done->load())
    {
        Json d = Json::object();
        d.set("busy", true);
        res.fail("E_TIMEOUT", "stop did not finish in time", d);
        return false;
    }
    if(!okp->load())
    {
        if(!DbgIsDebugging())
            res.fail("E_NOT_DEBUGGING", "stop needs a debug session (init or attach first)");
        else
            res.fail("E_COMMAND_FAILED", "stop failed");
        return false;
    }
    std::unique_lock<std::mutex> lk(h.mu);
    h.cv.wait_until(lk, steady_clock::now() + milliseconds(std::max<long long>(until - nowMs(), 100)), [&] { return h.status == Status::Stopped; });
    bool stopped = h.status == Status::Stopped;
    lk.unlock();
    if(stopped)
    {
        res.wait.waited = true;
        res.wait.reason = "stopped";
        stoppedTail(req, res);
    }
    return true;
}

// ------------------------------------------------------------------ finalisation

void Session::finalize(Request & req, Result & res)
{
    Host & h = host();
    unsigned long long endOffset = 0;
    if(res.barrierNeeded)
    {
        bool shuttingDown = h.shuttingDownA.load();
        if(!shuttingDown)
        {
            auto exec = [&](const std::string & line) -> bool
            {
                CoreCall cc(*this, std::max<long long>(opt.stuckMs, 5000));
                return DbgCmdExecDirect((" " + line).c_str());
            };
            int ms = opt.testBarrierMs > 0 ? opt.testBarrierMs : 3000;
            if(!runBarrier(h, ms, exec, &endOffset))
            {
                res.warnings.push_back("barrier_timeout");
                io::diag("barrier timeout");
            }
        }
        else
            endOffset = h.logEnd();
        LogSlice s = h.slice(req.logStart, endOffset);
        if(s.truncated)
        {
            res.truncated = true;
            Json f = Json::object();
            f.set("message", "log ring overflow: the start of the request window was dropped");
            h.pushEvent("log_overflow", f);
        }
        res.output = s.text;
        if(!res.output.empty() && res.output.back() == '\n')
            res.output.pop_back();
        if(!res.output.empty() && res.output.back() == '\r')
            res.output.pop_back();

        int limitId;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            limitId = h.tableCounter;
        }
        int dropped = 0;
        for(auto & t : h.tablesBetween(req.tableCursor, limitId, &dropped))
            res.tables.push_back(tableToJson(t, 0, (size_t)req.opt.maxRows));
        if(dropped)
            res.warnings.push_back("tables_dropped=" + std::to_string(dropped));
    }

    // deferred failure mapping (needs the output of the window)
    auto lastLines = [&](int n) -> std::string
    {
        std::vector<std::string> lines;
        size_t pos = 0;
        while(pos <= res.output.size())
        {
            size_t nl = res.output.find('\n', pos);
            std::string l = trim(res.output.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
            if(!l.empty())
                lines.push_back(l);
            if(nl == std::string::npos)
                break;
            pos = nl + 1;
        }
        std::string out;
        for(size_t i = lines.size() > (size_t)n ? lines.size() - n : 0; i < lines.size(); i++)
            out += (out.empty() ? "" : "\n") + lines[i];
        return out;
    };
    if(res.pending == Result::PendingCommandFailed)
    {
        res.ok = false;
        if(res.output.find("is debug-only") != std::string::npos && !DbgIsDebugging())
        {
            res.code = "E_NOT_DEBUGGING";
            res.message = firstWord(res.failSegment) + " needs a debug session (init or attach first)";
        }
        else
        {
            res.code = "E_COMMAND_FAILED";
            std::string m = lastLines(3);
            res.message = m.empty() ? "command returned failure" : m;
        }
    }
    else if(res.pending == Result::PendingInitNoSession)
    {
        res.ok = false;
        res.code = "E_COMMAND_FAILED";
        std::string cause;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            if(h.promptsSeen.size() > res.promptsBefore)
                cause = h.promptsSeen.back();
        }
        if(cause.empty())
            cause = lastLines(1);
        res.message = "init did not start a debug session: " + cause;
    }

    // vars
    if(!req.opt.vars.empty())
    {
        for(auto & v : req.opt.vars)
        {
            bool ok = false;
            duint val = DbgEval(v.c_str(), &ok);
            res.vars.set(v, ok ? Json(hexAddr(val)) : Json());
        }
    }

    // max_output
    long long cap = maxOutputOf(req);
    if((long long)res.output.size() > cap)
    {
        size_t cut = (size_t)cap;
        while(cut > 0 && ((unsigned char)res.output[cut] & 0xC0) == 0x80)
            cut--;
        res.output.resize(cut);
        res.truncated = true;
        res.warnings.push_back("output_truncated_next=" + std::to_string(req.logStart + cut));
    }
}

// ------------------------------------------------------------------ ops

// Precondition model of design 9.1: any | debugging | paused (stack with an addr needs only a session).
bool Session::checkPrecondition(const OpSpec & spec, Request & req, Result & res)
{
    std::string pre = spec.precondition;
    if(std::string(spec.name) == "stack")
        pre = req.args.find("addr") ? "debugging" : "paused";
    if(pre == "any")
        return true;
    if(!DbgIsDebugging())
    {
        res.fail("E_NOT_DEBUGGING", std::string(spec.name) + " needs a debug session (init or attach first)");
        return false;
    }
    if(pre == "paused")
    {
        Status st;
        {
            std::lock_guard<std::mutex> lk(host().mu);
            st = host().reportedStatusLocked();
        }
        if(st == Status::Starting)
        {
            res.fail("E_RUNNING", "session is starting; use wait");
            return false;
        }
        if(st == Status::Running || DbgIsRunning())
        {
            res.fail("E_RUNNING", std::string(spec.name) + " needs a paused debuggee; use pause first");
            return false;
        }
    }
    return true;
}

void Session::runViewOp(Request & req, Result & res)
{
    const ViewEntry* v = findView(req.op);
    if(!v)
    {
        res.fail("E_UNKNOWN_OP", "unknown op '" + req.op + "'");
        return;
    }
    if(v->wrapper)
    {
        v->fn(*this, req, res);
        return;
    }
    CoreCall cc(*this, std::max<long long>(opt.stuckMs, effectiveTimeout(req) + 5000));
    v->fn(*this, req, res);
}

bool Session::execLine(Request & req, Result & res, const std::string & line)
{
    std::string saved = req.cmd;
    req.cmd = line;
    runNativeLine(req, res);
    req.cmd = saved;
    return res.ok;
}

void Session::pauseIfRunning(Request & req, Result & res)
{
    Host & h = host();
    Status st;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        st = h.status;
    }
    if(st != Status::Running)
        return;
    if(pauseWithRetry(req, res, req.opt.pauseSettleMs))
    {
        long long ps;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            st = h.status;
            ps = h.lastPausedSeq;
        }
        if(st == Status::Paused)
            finishPaused(req, res, ps);
        else if(st == Status::Stopped)
            stoppedTail(req, res);
        return;
    }
    // the attach itself succeeded; a pause that did not work is reported as a warning
    res.warnings.push_back("pause_failed: " + (res.message.empty() ? std::string("timeout") : res.message));
    res.ok = true;
    res.code.clear();
    res.message.clear();
}

void Session::runPauseStop(Request & req, Result & res, bool isPause)
{
    long long startedMs = nowMs();
    if(isPause)
    {
        pauseWithRetry(req, res, req.opt.pauseSettleMs);
        res.wait.waited = res.ok;
    }
    else
        doStop(req, res, effectiveTimeout(req));
    res.wait.elapsedMs = nowMs() - startedMs;
}

void Session::beginRequest(Request & req, Result & res)
{
    Host & h = host();
    req.started = steady_clock::now();
    std::lock_guard<std::mutex> lk(h.mu);
    req.tableCursor = h.tableCounter;
    req.logStart = std::max(h.logEndLocked(), h.requestFloor);
    res.promptsBefore = h.promptsSeen.size();
}

// batch (design 8.3, 8.7): the elements run in order on this executor turn.
void Session::runBatch(Request & req, Result & res)
{
    const Json* b = req.raw.find("batch");
    std::vector<RequestPtr> subs;
    for(size_t i = 0; b && i < b->items().size(); i++)
    {
        const Json & e = b->items()[i];
        std::string where = "batch element " + std::to_string(i) + ": ";
        if(!e.isObject())
        {
            res.fail("E_BAD_ARG", where + "must be an object");
            return;
        }
        if(e.find("batch"))
        {
            res.fail("E_BAD_ARG", where + "nested batch is not allowed");
            return;
        }
        const Json* op = e.find("op");
        if(op && op->isString() && (op->asString() == "interrupt" || op->asString() == "quit"))
        {
            res.fail("E_BAD_ARG", where + "op " + op->asString() + " is not allowed in a batch");
            return;
        }
        Json merged = Json::object();
        for(auto & m : e.members())
            merged.set(m.first, m.second);
        for(auto & m : req.raw.members())
            if(isOptionKey(m.first) && m.first != "stop_on_error" && !merged.find(m.first))
                merged.set(m.first, m.second);
        RequestPtr sub;
        ParseError err;
        if(!parseJsonRequest(merged.dump(), sub, err))
        {
            res.fail("E_BAD_ARG", where + err.message);
            return;
        }
        sub->textId = req.textId + "." + std::to_string(i);
        subs.push_back(sub);
    }
    req.opt.vars.clear(); // the batch-level vars are the defaults of the elements
    res.hasResults = true;
    bool allOk = true;
    std::string firstCode, firstMsg;
    size_t firstIndex = 0;
    for(size_t i = 0; i < subs.size(); i++)
    {
        if(req.abandoned.load() || host().shuttingDownA.load())
            break;
        Request & sub = *subs[i];
        Result sres;
        beginRequest(sub, sres);
        try
        {
            dispatch(sub, sres);
            finalize(sub, sres);
        }
        catch(const std::exception & e)
        {
            sres.fail("E_INTERNAL", e.what());
        }
        Json resp = buildResponse(sub, sres, false);
        resp.erase("type");
        resp.erase("v");
        res.results.push(resp);
        res.wait = sres.wait;
        res.stop = sres.stop;
        res.hasStop = sres.hasStop;
        if(!sres.ok)
        {
            if(allOk)
            {
                firstCode = sres.code;
                firstMsg = sres.message;
                firstIndex = i;
            }
            allOk = false;
            if(req.opt.stopOnError)
                break;
        }
    }
    if(!allOk)
        res.fail(firstCode, "batch element " + std::to_string(firstIndex) + " failed: " + firstMsg);
}

void Session::runOp(Request & req, Result & res)
{
    const std::string & op = req.op;
    if(const OpSpec* spec = findOp(op))
        if(!checkPrecondition(*spec, req, res))
            return;
    if(op == "pause" || op == "stop")
    {
        runPauseStop(req, res, op == "pause");
        return;
    }
    const OpSpec* spec = findOp(op);
    if(spec && (std::string(spec->milestone) == "M2" || std::string(spec->milestone) == "M3"))
    {
        runViewOp(req, res);
        return;
    }
    if(op == "status")
        opStatus(req, res, true);
    else if(op == "wait")
        opWait(req, res);
    else if(op == "interrupt")
    {
        bool was = false;
        host().interrupt(was);
        Json d = Json::object();
        d.set("interrupted", was);
        res.data = d;
    }
    else if(op == "quit")
    {
        const Json* det = req.args.find("detach");
        if(det && det->asBool())
            pendingDetach_ = true;
        Json d = Json::object();
        d.set("shutting_down", true);
        res.data = d;
    }
    else if(op == "log")
        opLog(req, res);
    else if(op == "events")
        opEvents(req, res);
    else if(op == "eval")
        opEval(req, res);
    else if(op == "table")
        opTable(req, res);
    else if(op == "help")
        opHelp(req, res);
    else if(op == "commands")
        opCommands(req, res);
    else
        res.fail("E_UNKNOWN_OP", "unknown op '" + op + "'");
}

void Session::opStatus(Request &, Result & res, bool executorThread)
{
    Host & h = host();
    Json d = Json::object();
    {
        std::lock_guard<std::mutex> lk(h.mu);
        if(h.procValid)
        {
            Json p = Json::object();
            p.set("path", h.procPath);
            p.set("name", h.procName);
            p.set("base", hexAddr(h.procBase));
            p.set("entry", h.procEntryValid ? Json(hexAddr(h.procEntry)) : Json());
            d.set("process", p);
        }
        else
            d.set("process", nullptr);
    }
    Status st;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        st = h.status;
    }
    (void)executorThread;
    if(st == Status::Paused && DbgIsDebugging())
    {
        bool ok = false;
        duint csp = DbgEval("csp", &ok);
        d.set("csp", ok ? Json(hexAddr(csp)) : Json());
    }
    else
        d.set("csp", nullptr);
    {
        std::lock_guard<std::mutex> lk(h.mu);
        if(h.lastExceptionEvent.isObject())
        {
            Json e = Json::object();
            e.set("code", *h.lastExceptionEvent.find("code"));
            e.set("name", *h.lastExceptionEvent.find("name"));
            e.set("address", *h.lastExceptionEvent.find("address"));
            e.set("first_chance", *h.lastExceptionEvent.find("first_chance"));
            d.set("last_exception", e);
        }
        else
            d.set("last_exception", nullptr);
        if(!h.events.empty())
        {
            const Json & e = h.events.back();
            Json le = Json::object();
            le.set("seq", *e.find("seq"));
            le.set("type", *e.find("type"));
            d.set("last_event", le);
        }
        else
            d.set("last_event", nullptr);
        d.set("time_wasted_ms", (unsigned long long)h.timeWastedMs);
    }
    DEBUG_ENGINE eng = DbgGetDebugEngine();
    d.set("engine", eng == DebugEngineTitanEngine ? "titan" : eng == DebugEngineGleeBug ? "gleebug" : "static");
    d.set("userdir", userDir);
    Json cli = Json::object();
    cli.set("version", kVersion);
    cli.set("protocol", kProtocolVersion);
    d.set("cli", cli);
    {
        std::lock_guard<std::mutex> lk(h.mu);
        d.set("ref_progress", h.refProgress >= 0 ? Json(h.refProgress) : Json());
    }
    res.data = d;
}

void Session::opWait(Request & req, Result & res)
{
    Host & h = host();
    Status st;
    long long s0, launchS0 = -1;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        st = h.reportedStatusLocked();
        s0 = h.stateSeq;
        if(h.launchPending)
            launchS0 = h.launchS0;
    }
    if(st != Status::Starting && st != Status::Running)
    {
        res.wait.reason = "not_running";
        return;
    }
    long long startedMs = nowMs();
    WaitOut out = waitLoop(req, WaitKind::WaitOp, s0, launchS0, effectiveTimeout(req), 0, res);
    if(out.reason == "paused" || out.reason == "stopped")
    {
        // a launch is complete once its first stop is reached
        std::lock_guard<std::mutex> lk(h.mu);
        if(h.launchPending && h.initSeq > h.launchS0)
            h.launchPending = false;
    }
    applyWaitOutcome(req, res, out, startedMs, "");
}

void Session::opLog(Request & req, Result & res)
{
    Host & h = host();
    const Json* from = req.args.find("from");
    const Json* tail = req.args.find("tail");
    const Json* clear = req.args.find("clear");
    LogSlice s;
    if(tail)
    {
        if(tail->asInt() < 1 || tail->asInt() > 100000)
        {
            res.fail("E_BAD_ARG", "tail must be in 1..100000");
            return;
        }
        s = h.tail((int)tail->asInt());
    }
    else
    {
        unsigned long long f = from ? (unsigned long long)std::max<long long>(from->asInt(), 0) : 0;
        s = h.slice(f, ~0ull);
    }
    Json d = Json::object();
    d.set("text", s.text);
    d.set("from", s.from);
    d.set("next", s.next);
    d.set("truncated", s.truncated);
    res.data = d;
    if(clear && clear->asBool())
        h.clearRing();
}

void Session::opEvents(Request & req, Result & res)
{
    Host & h = host();
    const Json* since = req.args.find("since");
    const Json* limit = req.args.find("limit");
    long long lim = limit ? limit->asInt() : 500;
    if(lim < 1 || lim > 100000)
    {
        res.fail("E_BAD_ARG", "limit must be in 1..100000");
        return;
    }
    long long sn = since ? since->asInt() : 0;
    std::vector<Json> evs = h.eventsSince(sn - 1, (size_t)lim);
    resolveEvents(evs);
    Json arr = Json::array();
    long long next = sn;
    for(auto & e : evs)
    {
        next = e.find("seq")->asInt() + 1;
        arr.push(e);
    }
    Json d = Json::object();
    d.set("events", arr);
    d.set("next_seq", next);
    res.data = d;
}

void Session::opEval(Request & req, Result & res)
{
    const Json* e = req.args.find("expr");
    std::string expr = e ? e->asString() : std::string();
    if(trim(expr).empty())
    {
        res.fail("E_BAD_ARG", "eval requires a non-empty expression");
        return;
    }
    if(expr.size() > 1023)
    {
        res.fail("E_TOO_LONG", "expression is longer than 1023 bytes");
        return;
    }
    long long limit = std::max<long long>(opt.stuckMs, effectiveTimeout(req) + 5000);
    CoreCall cc(*this, limit);
    bool valid = DbgIsValidExpression(expr.c_str());
    bool ok = false;
    duint v = 0;
    if(valid)
        v = DbgEval(expr.c_str(), &ok);
    if(!valid || !ok)
    {
        res.fail("E_BAD_ARG", "cannot evaluate: " + expr);
        return;
    }
    Json d = Json::object();
    d.set("expr", expr);
    d.set("value", hexAddr(v));
    d.set("unsigned", std::to_string((unsigned long long)v));
    d.set("signed", std::to_string((long long)v));
    char label[MAX_LABEL_SIZE] = "";
    char str[MAX_STRING_SIZE] = "";
    if(DbgIsDebugging() && v)
    {
        d.set("label", DbgGetLabelAt(v, SEG_DEFAULT, label) && label[0] ? Json(label) : Json());
        d.set("string", DbgGetStringAt(v, str) && str[0] ? Json(str) : Json());
    }
    else
    {
        d.set("label", nullptr);
        d.set("string", nullptr);
    }
    res.data = d;
}

void Session::opTable(Request & req, Result & res)
{
    Host & h = host();
    const Json* id = req.args.find("id");
    const Json* off = req.args.find("offset");
    const Json* lim = req.args.find("limit");
    long long offset = off ? off->asInt() : 0;
    long long limit = lim ? lim->asInt() : 200;
    if(offset < 0 || limit < 1 || limit > 1000000)
    {
        res.fail("E_BAD_ARG", "offset must be >= 0 and limit in 1..1000000");
        return;
    }
    RefTable t;
    bool evicted = false;
    if(!h.tableById(id ? (int)id->asInt() : 0, t, id == nullptr, &evicted))
    {
        if(evicted)
            res.fail("E_BAD_ARG", "table " + std::to_string(id->asInt()) + " was evicted");
        else
            res.fail("E_BAD_ARG", id ? "unknown table id " + std::to_string(id->asInt()) : std::string("no table has been produced yet"));
        return;
    }
    size_t stored;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        stored = h.tables.size();
    }
    Json d = Json::object();
    d.set("id", t.id);
    d.set("stored", (unsigned long long)stored);
    d.set("table", tableToJson(t, (size_t)offset, (size_t)limit));
    res.data = d;
}

void Session::opHelp(Request & req, Result & res)
{
    const Json* topic = req.args.find("topic");
    Json ops = Json::array();
    for(auto & o : allOps())
    {
        if(topic && lower(topic->asString()) != o.name)
            continue;
        Json x = Json::object();
        x.set("name", o.name);
        x.set("milestone", o.milestone);
        x.set("precondition", o.precondition);
        x.set("usage", o.usage);
        ops.push(x);
    }
    if(topic && ops.items().empty())
    {
        res.fail("E_BAD_ARG", "unknown help topic '" + topic->asString() + "'");
        return;
    }
    Json d = Json::object();
    d.set("ops", ops);
    res.data = d;
}

void Session::opCommands(Request & req, Result & res)
{
    Host & h = host();
    const Json* prefix = req.args.find("prefix");
    std::string p = prefix ? lower(prefix->asString()) : std::string();
    Json arr = Json::array();
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lk(h.mu);
        for(auto & names : h.commandNames)
        {
            bool match = p.empty();
            for(auto & n : names)
                if(!p.empty() && lower(n).compare(0, p.size(), p) == 0)
                    match = true;
            if(!match)
                continue;
            Json c = Json::object();
            c.set("canonical", names[0]);
            Json ns = Json::array();
            for(auto & n : names)
                ns.push(n);
            c.set("names", ns);
            c.set("debug_only", nullptr);
            arr.push(c);
            count++;
        }
    }
    Json d = Json::object();
    d.set("commands", arr);
    d.set("count", (unsigned long long)count);
    res.data = d;
}

// ------------------------------------------------------------------ Control thread (out-of-band requests)

void Session::controlMain()
{
    while(true)
    {
        RequestPtr req;
        {
            std::unique_lock<std::mutex> lk(mu_);
            qcv_.wait(lk, [this] { return !oobQ_.empty() || stopping_.load(); });
            if(oobQ_.empty())
            {
                if(stopping_.load())
                    break;
                continue;
            }
            req = oobQ_.front();
            oobQ_.pop_front();
        }
        try
        {
            handleOob(req);
        }
        catch(...)
        {
        }
    }
    ctrlDone_ = true;
}

void Session::handleOob(RequestPtr reqp)
{
    Request & req = *reqp;
    Host & h = host();
    Result res;
    bool quit = false;
    if(req.isOp && req.op == "status")
        opStatus(req, res, false);
    else if(req.isOp && req.op == "interrupt")
    {
        bool was = false;
        h.interrupt(was);
        Json d = Json::object();
        d.set("interrupted", was);
        res.data = d;
    }
    else if(req.isOp && req.op == "quit")
    {
        const Json* det = req.args.find("detach");
        if(det && det->asBool())
            pendingDetach_ = true;
        Json d = Json::object();
        d.set("shutting_down", true);
        res.data = d;
        quit = true;
    }
    else if(req.isOp && (req.op == "pause" || req.op == "stop"))
        runPauseStop(req, res, req.op == "pause");
    else
    {
        std::string text = trim(req.cmd);
        std::string c = lower(h.canonicalOf(firstWord(splitSemicolon(text).empty() ? text : trim(splitSemicolon(text)[0]))));
        runPauseStop(req, res, c == "pause");
    }
    Json resp = buildResponse(req, res, true);
    send(req, resp);
    if(quit)
        requestShutdown("quit");
}

// ------------------------------------------------------------------ Guard thread: emitter, stuck detection, dialogs

void Session::emitterTick()
{
    Host & h = host();
    std::lock_guard<std::mutex> lk(mu_);
    if(active_ || !execQ_.empty())
        return;
    bool pending;
    {
        std::lock_guard<std::mutex> hl(h.mu);
        pending = h.hasUndeliveredLocked();
    }
    if(!pending)
        return;
    long long next = 0;
    bool dropped = false;
    std::vector<Json> evs = h.takeEvents(200, &next, &dropped);
    resolveEvents(evs);
    for(auto & e : evs)
        io::writeProtocol(opt.json ? renderEventJson(e) : renderEventText(e));
}

static BOOL CALLBACK collectDialogs(HWND hwnd, LPARAM lp)
{
    auto list = (std::vector<HWND>*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if(pid != GetCurrentProcessId() || !IsWindowVisible(hwnd))
        return TRUE;
    wchar_t cls[64] = L"";
    GetClassNameW(hwnd, cls, 64);
    if(wcscmp(cls, L"#32770") == 0)
        list->push_back(hwnd);
    return TRUE;
}

static BOOL CALLBACK firstStatic(HWND hwnd, LPARAM lp)
{
    auto out = (std::wstring*)lp;
    wchar_t cls[32] = L"";
    GetClassNameW(hwnd, cls, 32);
    if(_wcsicmp(cls, L"Static") == 0)
    {
        wchar_t text[1024] = L"";
        GetWindowTextW(hwnd, text, 1024);
        if(text[0])
        {
            *out = text;
            return FALSE;
        }
    }
    return TRUE;
}

void Session::dialogGuardTick()
{
    std::vector<HWND> dialogs;
    EnumWindows(collectDialogs, (LPARAM)&dialogs);
    for(auto it = seenDialogs_.begin(); it != seenDialogs_.end();)
    {
        if(!IsWindow(*it))
            it = seenDialogs_.erase(it);
        else
            ++it;
    }
    for(HWND d : dialogs)
    {
        if(seenDialogs_.count(d))
            continue;
        seenDialogs_.insert(d);
        wchar_t title[256] = L"";
        GetWindowTextW(d, title, 256);
        std::wstring text;
        EnumChildWindows(d, firstStatic, (LPARAM)&text);
        Json f = Json::object();
        f.set("title", utf8Of(title));
        f.set("text", utf8Of(text.c_str()));
        host().pushEvent("dialog_dismissed", f);
        int choice = 0;
        for(int id : { IDNO, IDCANCEL, IDOK })
        {
            if(GetDlgItem(d, id))
            {
                choice = id;
                break;
            }
        }
        if(choice)
            PostMessageW(d, WM_COMMAND, choice, 0);
        else
            PostMessageW(d, WM_CLOSE, 0, 0);
    }
}

void Session::guardMain()
{
    Host & h = host();
    auto lastSlow = steady_clock::now();
    while(!stopping_.load())
    {
        {
            std::unique_lock<std::mutex> lk(h.mu);
            h.cv.wait_for(lk, milliseconds(100));
        }
        if(stopping_.load())
            break;
        try
        {
            emitterTick();
        }
        catch(...)
        {
        }
        auto now = steady_clock::now();
        if(now - lastSlow < milliseconds(250))
            continue;
        lastSlow = now;
        try
        {
            dialogGuardTick();
        }
        catch(...)
        {
        }
        // stuck core call
        long long since = coreCallSinceMs_.load();
        long long limit = coreCallLimitMs_.load();
        if(since != 0 && limit > 0 && nowMs() - since > limit)
        {
            RequestPtr r;
            {
                std::lock_guard<std::mutex> lk(mu_);
                r = active_;
            }
            if(r && !r->responded.load())
            {
                Json d = Json::object();
                d.set("busy", true);
                d.set("limit_ms", limit);
                d.set("completed", r->completed.load());
                Result res;
                res.fail("E_TIMEOUT", "a core call blocked for more than " + std::to_string(limit) + " ms", d);
                Json resp = buildResponse(*r, res, true);
                r->abandoned = true;
                send(*r, resp);
            }
        }
        // EOF: escalate when the drain takes too long
        bool eof;
        steady_clock::time_point eofAt;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            eof = h.eof;
            eofAt = h.eofAt;
        }
        if(eof && !shutdown_.load())
        {
            auto sinceEof = std::chrono::duration_cast<milliseconds>(now - eofAt).count();
            bool coreStuck = since != 0 && nowMs() - std::max<long long>(since, nowMs() - sinceEof) > opt.eofWaitMs;
            if(sinceEof > kEofDrainMaxMs || coreStuck)
                requestShutdown("eof-drain");
        }
    }
    guardDone_ = true;
}

// ------------------------------------------------------------------ shutdown (design 6.5)

static bool waitFlag(std::atomic<bool> & flag, int ms)
{
    long long until = nowMs() + ms;
    while(!flag.load() && nowMs() < until)
        Sleep(5);
    return flag.load();
}

bool Session::quiesce()
{
    Host & h = host();
    bool safe = true;
    std::vector<RequestPtr> pending;
    {
        std::lock_guard<std::mutex> lk(mu_);
        stopping_ = true;
        for(auto & r : execQ_)
            pending.push_back(r);
        for(auto & r : oobQ_)
            pending.push_back(r);
        execQ_.clear();
        oobQ_.clear();
    }
    qcv_.notify_all();
    h.notifyAll();
    for(auto & r : pending)
    {
        if(r->startup)
            continue;
        if(!r->responded.load())
        {
            r->started = steady_clock::now();
            sendError(*r, "E_SHUTDOWN", "the CLI is shutting down");
        }
    }
    // 2a
    bool execOk = waitFlag(execDone_, 5000);
    bool ctrlOk = waitFlag(ctrlDone_, 5000);
    if(!execOk || !ctrlOk)
    {
        // 2b: ask the core to end the session so that blocking calls (scriptcmd, ...) return
        auto helperDone = std::make_shared<std::atomic<bool>>(false);
        bool detach = opt.detachOnExit || pendingDetach_;
        std::thread([helperDone, detach]
        {
            DbgCmdExecDirect(detach ? " DetachDebugger" : " StopDebug");
            helperDone->store(true);
        }).detach();
        long long until = nowMs() + 5000;
        while(!helperDone->load() && nowMs() < until)
            Sleep(10);
        execOk = waitFlag(execDone_, 5000);
        ctrlOk = waitFlag(ctrlDone_, 5000);
        safe = execOk && ctrlOk;
    }
    if(execThread_.joinable())
    {
        if(execDone_.load())
            execThread_.join();
        else
            execThread_.detach();
    }
    if(ctrlThread_.joinable())
    {
        if(ctrlDone_.load())
            ctrlThread_.join();
        else
            ctrlThread_.detach();
    }
    // 2c: reader
    if(readerThread_.joinable())
    {
        long long until = nowMs() + 2000;
        while(!readerDone_.load() && nowMs() < until)
        {
            if(readerHandle_)
                CancelSynchronousIo(readerHandle_);
            Sleep(100);
        }
        if(readerDone_.load())
            readerThread_.join();
        else
            readerThread_.detach();
    }
    // 2d: guard and output
    if(guardThread_.joinable())
    {
        waitFlag(guardDone_, 1000);
        if(guardDone_.load())
            guardThread_.join();
        else
            guardThread_.detach();
    }
    if(!io::drain(2000))
    {
        outputLost_ = true;
        exitCode_ = 70;
    }
    if(io::outputLost())
    {
        outputLost_ = true;
        exitCode_ = 70;
    }
    hardKill_ = false;
    return safe;
}
}
