#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "json.h"

namespace cli
{
enum class Status
{
    None,
    Starting,
    Running,
    Paused,
    Stopped
};

const char* statusName(Status s);

struct RefTable
{
    int id = 0;
    std::string name;
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;
    long long totalRows = 0;
    bool storeTruncated = false;
    std::vector<std::pair<std::string, std::string>> actions;
    size_t bytes = 0;
};

struct MenuItem
{
    int handle = 0;
    int parent = 0;
    bool isEntry = false;
    bool separator = false;
    bool visible = true;
    bool checked = false;
    std::string title;
    std::string hotkey;
};

// Result of the log ring slice.
struct LogSlice
{
    std::string text;
    unsigned long long from = 0;
    unsigned long long next = 0;
    bool truncated = false;
};

// All state that the Bridge GUI messages and the plugin callbacks produce. Every field is guarded by `mu`
// and every predicate input is followed by a notify (rule L0). No core call is ever made under `mu` (L1).
class Host
{
public:
    Host();

    std::mutex mu;
    std::condition_variable cv;

    // ---- configuration (set once before the debugger starts)
    std::string nonce;
    int barrierMs = 3000;
    std::string dropBarrier; // "", "text" or "html" (test option)
    bool anticheatYes = false;
    bool msgynYes = false;
    bool foreground = false;
    int verbose = 0;
    size_t eventRingSize = 10000;

    // ---- log ring
    std::string ring;
    unsigned long long ringBase = 0;
    bool logEnabled = true;
    unsigned long long requestFloor = 0;
    bool logOverflowRaised = false;
    unsigned long long logEndLocked() const { return ringBase + ring.size(); }
    unsigned long long logEnd();
    // Entry point of GUI_ADD_MSG_TO_LOG (channel 0) and GUI_ADD_MSG_TO_LOG_HTML (channel 1).
    void onLogChunk(int channel, const std::string & chunk);
    void appendLogLine(const std::string & line); // host-generated line, newline added
    LogSlice slice(unsigned long long from, unsigned long long to);
    LogSlice tail(int lines);
    void clearRing();
    bool ringHasLineSince(unsigned long long from, const char* line);
    bool setMirror(const std::string & path);
    void stopMirror();

    // Barrier (7.1). nextBarrier() returns the new token; the markers are text for log/htmllog.
    long long nextBarrier();
    std::string barrierMarker(char letter, long long token) const;
    long long barrierSeenText = 0, barrierSeenHtml = 0;
    unsigned long long markerOffset[2] = { 0, 0 };
    bool barrierComplete(long long token) const { return barrierSeenText >= token && barrierSeenHtml >= token; }

    // ---- state machine (7.2)
    Status status = Status::None;
    long long stateSeq = 0;
    long long initSeq = 0;
    bool launchPending = false;
    long long launchS0 = 0;
    long long lastRunningSeq = 0;
    long long lastPausedSeq = 0;
    long long pausedRunningSeq = 0; // lastRunningSeq at the time of the last paused event
    unsigned long long pid = 0;
    bool exitCodeValid = false;
    unsigned exitCode = 0;
    struct LastException
    {
        bool valid = false;
        unsigned code = 0;
        long long stamp = 0;
    } lastException;
    Json lastExceptionEvent; // the last "exception" event (or null)
    std::string lastResumeName;
    std::string procPath, procName;
    unsigned long long procBase = 0;
    bool procValid = false;
    unsigned long long procEntry = 0;
    bool procEntryValid = false;
    bool processStale = false;
    unsigned long long timeWastedMs = 0;
    int refProgress = -1;
    // Reported status (starting while a launch is pending, 7.2).
    Status reportedStatusLocked() const;
    void onDebugState(int state, bool fast);
    void setStatusLocked(Status s, const char* pauseReason); // used by the fallback rules of 7.2/7.4
    bool synthesizeRunningIf(long long s0); // repair step of 7.4: true when a synthetic running was recorded
    void synthesizePaused(const char* reason);
    void beginLaunch(); // sets launchPending/launchS0 (Init, Attach)
    void endLaunch();
    void setLastResumeName(const std::string & name);

    int waitersPending = 0;
    bool interruptRequested = false;
    bool shuttingDown = false;
    std::atomic<bool> shuttingDownA{ false };
    bool eof = false;
    std::chrono::steady_clock::time_point eofAt;
    void requestShutdown();
    void setEof();
    void interrupt(bool & wasWaiting);
    void notifyAll();

    // ---- events (7.5, 6.6)
    std::deque<Json> events;
    long long nextSeq = 0;
    long long emitCursor = 0; // last delivered seq
    long long pendingLost = 0;
    long long stampSeq(); // takes a number from the event counter without a ring entry
    long long pushEvent(const std::string & type, Json fields = Json::object());
    long long pushEventLocked(const std::string & type, Json fields);
    // Copies up to max events with seq > emitCursor and advances the cursor. nextSeq output: first undelivered.
    std::vector<Json> takeEvents(size_t max, long long* firstUndelivered, bool* hadDropped);
    bool hasUndeliveredLocked() const;
    std::vector<Json> eventsSince(long long since, size_t limit);
    std::vector<Json> eventWindow(long long afterSeq, long long uptoSeq);
    long long lastEventSeqLocked() const;

    // ---- reference tables (7.1a)
    std::vector<RefTable> tables;
    int tableCounter = 0;
    size_t tableBytes = 0;
    int evictedUpTo = 0;
    int tablesDroppedSinceCursor = 0;
    void refInitialize(const std::string & name);
    void refAddColumn(const std::string & title);
    void refSetRowCount(int rows);
    void refSetCell(int row, int col, const std::string & text);
    void refAddCommand(const std::string & title, const std::string & command);
    std::string refGetCell(int row, int col);
    int refRowCount();
    std::vector<RefTable> tablesBetween(int cursorExclusive, int limitInclusive, int * dropped);
    bool tableById(int id, RefTable & out, bool newest, bool* evicted);

    // ---- native command registry (3.4)
    std::map<std::string, std::string> aliasToCanon;
    std::vector<std::vector<std::string>> commandNames;
    void autoCompleteAdd(const std::string & names);
    void autoCompleteDel(const std::string & names);
    void autoCompleteClear();
    std::string canonicalOf(const std::string & word);
    size_t commandCount();

    // ---- other GUI state
    struct ScriptLang
    {
        int id;
        std::string name;
        bool (*execute)(const char*);
    };
    std::vector<ScriptLang> scriptLangs;
    std::vector<std::string> scriptLines;
    int scriptIp = 0;
    long long scriptIpSeq = 0;
    std::string scriptTitle;
    std::map<int, std::string> scriptInfo;
    std::vector<std::string> scriptMessages, scriptErrors; // GUI_SCRIPT_MESSAGE / GUI_SCRIPT_ERROR texts (script op)
    std::string globalNotes, debuggeeNotes;
    struct Nav
    {
        unsigned long long disasm = 0, cip = 0, dump = 0, stack = 0, csp = 0, graph = 0, memmap = 0, symmod = 0, threads = 0;
    } nav;
    std::map<int, unsigned long long> dumpTabs;
    std::vector<std::pair<unsigned long long, std::string>> modules;
    std::string windowTitle;
    std::vector<std::string> recentFiles;
    std::vector<MenuItem> menus;
    int menuCounter = 1000;
    std::vector<std::pair<std::string, std::string>> favouriteTools, favouriteCommands;
    std::vector<std::pair<std::string, unsigned long long>> sourceFiles;
    std::string traceFile;
    int typeNodeCounter = 0;
    std::vector<std::string> promptsSeen;

    std::atomic<bool> dbgStopped{ false }; // after DbgExit: ignore messages
    bool callbacksOk = false; // plugin callbacks registered (events "full" vs "degraded")
    std::map<unsigned long long, std::string> moduleNames; // base -> name, from module_loaded events
    // Registers the plugin callbacks through x64dbg.dll's exported _plugin_registercallback (3.9).
    bool registerPluginCallbacks();

    // Main-thread job queue (GUI_EXECUTE_ON_GUI_THREAD, shutdown wake-up).
    void postJob(std::function<bool()> job);
    // Runs jobs until one returns false. Called on the main thread.
    void pumpJobs();
    unsigned mainThreadId = 0;

private:
    std::deque<std::function<bool()>> jobs_;
    std::mutex jobMu_;
    std::condition_variable jobCv_;
    bool swallowNl_[2] = { false, false };
    void appendTextLocked(int channel, const std::string & text, std::string & mirror);
    void trimRingLocked();
    void emitOverflowLocked();
    void evictTablesLocked();
    // mirror file
    std::mutex mirrorMu_;
    void* mirror_ = nullptr; // FILE*
    void writeMirror(const std::string & text);
};

Host & host();
}
