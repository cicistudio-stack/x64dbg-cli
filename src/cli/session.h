#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <Windows.h>

#include "events.h"
#include "host.h"
#include "options.h"
#include "protocol.h"

namespace cli
{
struct WaitInfo
{
    bool waited = false;
    std::string reason = "none";
    bool timedOut = false;
    long long elapsedMs = 0;
};

// Outcome of one request, before it is turned into a response envelope.
struct Result
{
    bool ok = true;
    std::string code;
    std::string message;
    Json detail;
    std::string output;
    Json data;
    WaitInfo wait;
    std::vector<std::string> warnings;
    bool truncated = false;
    Json stop;
    bool hasStop = false;
    std::vector<Json> tables;
    Json vars = Json::object();
    Json results = Json::array(); // batch: the element responses
    bool hasResults = false;
    // finalisation inputs
    bool barrierNeeded = false;
    enum Pending
    {
        PendingNone,
        PendingCommandFailed,
        PendingInitNoSession
    } pending = PendingNone;
    std::string failSegment;
    std::string initCause;
    size_t promptsBefore = 0;
    bool tooLongOverride = false;

    void fail(const std::string & c, const std::string & m, const Json & d = Json())
    {
        ok = false;
        code = c;
        message = m;
        detail = d;
    }
};

// Steps 1 to 4 of the "Line handling" rule of design 7.4: expansion, split, validation.
struct LinePlan
{
    bool ok = true;
    std::string code;
    std::string message;
    std::vector<std::string> segments;
};

// expand(text, out, tooLong): expands a leading-$ line once. canonical(word) returns the canonical name or "".
LinePlan planNativeLine(const std::string & line,
                        const std::function<bool(const std::string &, std::string &, bool &)> & expand,
                        const std::function<std::string(const std::string &)> & canonical);

// The only text the CLI hands to DbgCmdExecDirect for a segment: one leading space (7.4, step 7), so that a segment
// that starts with '$' is not read as a script-variable assignment by the core.
std::string coreLine(const std::string & segment);

// Leading-$ expansion through StringFormatInline (a 65536-byte buffer); tooLong is set when the buffer was filled.
bool expandLine(const std::function<bool(const char*, size_t, char*)> & format, const std::string & text, std::string & out, bool & tooLong);

// The completion barrier of 7.1 steps 3 to 5. exec(line) runs a native command line.
// Returns false on barrier timeout. endOffset receives the end of the request window.
bool runBarrier(Host & h, int barrierMs, const std::function<bool(const std::string &)> & exec, unsigned long long* endOffset);

class Session
{
public:
    explicit Session(const Options & options, const std::string & userDir);
    ~Session();

    Json buildHello();
    void start();       // Executor, Control and Guard threads
    void startReader(); // session mode only
    void queueStartup(const std::vector<std::string> & lines, bool targetItems);
    void queueStartupRaw(const std::string & line);
    void requestShutdown(const char* reason);
    bool shuttingDown() const { return shutdown_.load(); }

    // Quiesce step of 6.5 (steps 2a to 2d). Returns true when no CLI thread is inside the core any more.
    bool quiesce();
    void fatalExit(const std::string & code, const std::string & message);
    int exitCode() const { return exitCode_.load(); }
    void setExitCode(int c) { exitCode_ = c; }
    bool startupDone() const { return startupDone_.load(); }
    bool detachRequested() const { return opt.detachOnExit || pendingDetach_; }

    // Support for the structured views (views_*.cpp), called on the Executor thread.
    // Runs a native line (7.4 line handling, waiting and capture) as part of an op. Returns res.ok.
    bool execLine(Request & req, Result & res, const std::string & line);
    // attach --pause: pauses a running debuggee and fills the stop information.
    void pauseIfRunning(Request & req, Result & res);
    long long timeoutOf(const Request & req) const { return effectiveTimeout(req); }

    const Options & opt;
    std::string userDir;

private:
    friend struct CoreCall;
    struct SegmentState;

    // threads
    void executorMain();
    void controlMain();
    void guardMain();
    void readerMain();
    void watchdogMain();

    // dispatch
    void submit(RequestPtr req);
    bool isOobRequest(const Request & req);
    void process(RequestPtr req);
    void handleOob(RequestPtr req);
    void dispatch(Request & req, Result & res);
    void runOp(Request & req, Result & res);
    bool checkPrecondition(const OpSpec & spec, Request & req, Result & res);
    void runViewOp(Request & req, Result & res);
    void runPauseStop(Request & req, Result & res, bool isPause);
    void runBatch(Request & req, Result & res);
    void beginRequest(Request & req, Result & res);
    void runNativeLine(Request & req, Result & res);
    enum class SegOutcome
    {
        Done,
        Stop
    };
    SegOutcome runSegment(Request & req, Result & res, const std::string & segment);
    bool execNative(Request & req, const std::string & segment, const std::string & lowerCanon);

    // waiting
    enum class WaitKind
    {
        Resume,
        Init,
        InitAlways,
        Attach,
        AttachAlways,
        Stop,
        WaitOp
    };
    struct WaitOut
    {
        std::string reason;
        bool timedOut = false;
        long long pausedSeq = 0;
    };
    WaitOut waitLoop(Request & req, WaitKind kind, long long s0, long long launchS0, long long timeoutMs, long long settleMs, Result & res);
    bool confirmPaused(Request & req, long long deadlineMs);
    bool sessionStarted(long long s0, int waitMs);
    SegOutcome applyWaitOutcome(Request & req, Result & res, const WaitOut & out, long long startedMs, const std::string & lowerCanon);
    void finishPaused(Request & req, Result & res, long long pausedSeq);
    void stoppedTail(Request & req, Result & res);
    AttribInput makeAttrib(long long pausedSeq);
    bool pauseWithRetry(Request & req, Result & res, long long settleMs);
    bool doStop(Request & req, Result & res, long long timeoutMs);

    // ops
    void opStatus(Request & req, Result & res, bool executorThread);
    void opWait(Request & req, Result & res);
    void opLog(Request & req, Result & res);
    void opEvents(Request & req, Result & res);
    void opEval(Request & req, Result & res);
    void opTable(Request & req, Result & res);
    void opHelp(Request & req, Result & res);
    void opCommands(Request & req, Result & res);

    // responses
    void finalize(Request & req, Result & res);
    Json buildResponse(Request & req, Result & res, bool oob);
    Json stateJson(const Result & res, bool executorThread);
    void send(Request & req, const Json & response);
    void sendError(Request & req, const std::string & code, const std::string & message, const Json & detail = Json());
    void resolveEvents(std::vector<Json> & events);
    void refreshProcessInfo();
    long long effectiveTimeout(const Request & req) const;
    long long maxOutputOf(const Request & req) const;
    void emitterTick();
    void dialogGuardTick();
    void noteStartupAnswered(Request & req, const Json & response);

    // state
    std::mutex mu_;
    std::condition_variable qcv_;
    std::deque<RequestPtr> execQ_, oobQ_;
    RequestPtr active_;
    std::thread execThread_, ctrlThread_, guardThread_, readerThread_;
    std::atomic<bool> execDone_{ false }, ctrlDone_{ false }, guardDone_{ false }, readerDone_{ true };
    std::atomic<bool> stopping_{ false };
    std::atomic<bool> shutdown_{ false };
    std::atomic<bool> hardKill_{ false };
    std::atomic<int> exitCode_{ 0 };
    std::atomic<bool> outputLost_{ false };
    std::mutex oobMu_;
    std::atomic<long long> coreCallSinceMs_{ 0 };
    std::atomic<long long> coreCallLimitMs_{ 0 };
    std::atomic<long long> idCounter_{ 0 };
    HANDLE readerHandle_ = nullptr;
    std::string shutdownReason_;
    bool pendingDetach_ = false;
    int trailMs_ = 50;

    // one-shot bookkeeping
    std::atomic<bool> startupDone_{ false };
    size_t startupTotal_ = 0;
    size_t startupAnswered_ = 0;
    int startupFail_ = 0; // 0 ok, 1 command failed, 4 timeout (last failing step)
    bool startupAbort_ = false;
    int startupCounter_ = 0;
    std::set<HWND> seenDialogs_;
    bool readerAfterStartup_ = false;
};

// JSON form of a captured reference table (rows offset..offset+limit).
Json tableToJson(const RefTable & t, size_t offset, size_t limit);

Session* session();
void setSession(Session* s);
}
