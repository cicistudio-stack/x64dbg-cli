#include "../bridge/bridgemain.h"
#include "../dbg/_plugins.h"

#include "host.h"
#include "util.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace cli
{
static const size_t kRingCap = 8u << 20;
static const size_t kRingTrim = 1u << 20;
static const long long kMaxStoredRows = 1000000;
static const size_t kMaxTableBytes = 256u << 20;
static const size_t kMaxTables = 16;

const char* statusName(Status s)
{
    switch(s)
    {
    case Status::None:
        return "none";
    case Status::Starting:
        return "starting";
    case Status::Running:
        return "running";
    case Status::Paused:
        return "paused";
    case Status::Stopped:
        return "stopped";
    }
    return "none";
}

Host & host()
{
    static Host h;
    return h;
}

Host::Host()
{
    char buf[16];
    unsigned v = (unsigned)GetTickCount() ^ (unsigned)(GetCurrentProcessId() << 7) ^ 0x5a17c3e1u;
    snprintf(buf, sizeof(buf), "%08x", v);
    nonce = buf;
}

void Host::notifyAll()
{
    cv.notify_all();
}

// ------------------------------------------------------------------ log ring

unsigned long long Host::logEnd()
{
    std::lock_guard<std::mutex> lk(mu);
    return logEndLocked();
}

std::string Host::barrierMarker(char letter, long long token) const
{
    return "@@x64dbg-cli-barrier:" + nonce + ":" + letter + std::to_string(token) + "@@";
}

long long Host::nextBarrier()
{
    static std::atomic<long long> counter{ 0 };
    return ++counter;
}

void Host::trimRingLocked()
{
    if(ring.size() > kRingCap + kRingTrim)
    {
        size_t cut = ring.size() - kRingCap;
        ring.erase(0, cut);
        ringBase += cut;
        logOverflowRaised = false;
    }
}

void Host::appendTextLocked(int channel, const std::string & text, std::string & mirror)
{
    (void)channel;
    if(text.empty() || !logEnabled)
        return;
    ring += text;
    mirror += text;
    trimRingLocked();
}

void Host::onLogChunk(int channel, const std::string & input)
{
    std::string mirror;
    {
        std::lock_guard<std::mutex> lk(mu);
        std::string chunk = input;
        // (a) swallow the newline that follows a barrier marker
        if(swallowNl_[channel])
        {
            if(!chunk.empty() && chunk[0] == '\n')
                chunk.erase(0, 1);
            swallowNl_[channel] = false;
        }
        const std::string prefix = "@@x64dbg-cli-barrier:" + nonce + ":";
        size_t searchFrom = 0;
        std::string pendingText; // text before the current search point, not yet appended
        while(true)
        {
            size_t m = chunk.find(prefix, searchFrom);
            bool consumed = false;
            if(m != std::string::npos)
            {
                size_t p = m + prefix.size();
                if(p < chunk.size() && (chunk[p] == 'T' || chunk[p] == 'H'))
                {
                    char letter = chunk[p];
                    size_t q = p + 1;
                    long long n = 0;
                    size_t digits = 0;
                    while(q < chunk.size() && chunk[q] >= '0' && chunk[q] <= '9' && digits < 18)
                    {
                        n = n * 10 + (chunk[q] - '0');
                        q++;
                        digits++;
                    }
                    if(digits && q + 2 <= chunk.size() && chunk.compare(q, 2, "@@") == 0)
                    {
                        int markerChannel = letter == 'T' ? 0 : 1;
                        if(markerChannel == channel)
                        {
                            std::string before = chunk.substr(0, m);
                            if(channel == 1)
                                before = stripHtml(before);
                            appendTextLocked(channel, pendingText + before, mirror);
                            pendingText.clear();
                            bool dropped = (dropBarrier == "text" && channel == 0) || (dropBarrier == "html" && channel == 1);
                            if(!dropped)
                            {
                                if(channel == 0)
                                    barrierSeenText = std::max(barrierSeenText, n);
                                else
                                    barrierSeenHtml = std::max(barrierSeenHtml, n);
                            }
                            markerOffset[channel] = logEndLocked();
                            swallowNl_[channel] = true;
                            chunk.erase(0, q + 2);
                            if(!chunk.empty())
                            {
                                if(chunk[0] == '\n')
                                    chunk.erase(0, 1);
                                swallowNl_[channel] = false;
                            }
                            searchFrom = 0;
                            consumed = true;
                        }
                        else
                        {
                            // marker with the wrong channel letter is ordinary text
                            searchFrom = q + 2;
                            consumed = true;
                        }
                    }
                }
                if(!consumed)
                    searchFrom = m + 1;
                if(chunk.empty())
                    break;
                continue;
            }
            // no (more) markers
            std::string rest = chunk;
            if(channel == 1)
                rest = stripHtml(rest);
            appendTextLocked(channel, pendingText + rest, mirror);
            break;
        }
    }
    cv.notify_all();
    if(!mirror.empty())
        writeMirror(mirror);
}

void Host::appendLogLine(const std::string & line)
{
    std::string mirror;
    {
        std::lock_guard<std::mutex> lk(mu);
        appendTextLocked(0, line + "\n", mirror);
    }
    cv.notify_all();
    if(!mirror.empty())
        writeMirror(mirror);
}

LogSlice Host::slice(unsigned long long from, unsigned long long to)
{
    std::lock_guard<std::mutex> lk(mu);
    LogSlice r;
    unsigned long long end = logEndLocked();
    if(to > end)
        to = end;
    if(from < ringBase)
    {
        r.truncated = true;
        from = ringBase;
    }
    if(to < from)
        to = from;
    r.from = from;
    r.next = end;
    r.text = ring.substr((size_t)(from - ringBase), (size_t)(to - from));
    return r;
}

LogSlice Host::tail(int lines)
{
    std::lock_guard<std::mutex> lk(mu);
    LogSlice r;
    size_t pos = ring.size();
    int seen = 0;
    if(pos > 0 && ring[pos - 1] == '\n')
        pos--;
    while(pos > 0 && seen < lines)
    {
        size_t nl = ring.rfind('\n', pos - 1);
        seen++;
        if(nl == std::string::npos)
        {
            pos = 0;
            break;
        }
        pos = nl;
        if(seen >= lines)
        {
            pos = nl + 1;
            break;
        }
    }
    if(seen < lines)
        pos = 0;
    r.from = ringBase + pos;
    r.next = logEndLocked();
    r.text = ring.substr(pos);
    return r;
}

void Host::clearRing()
{
    std::lock_guard<std::mutex> lk(mu);
    ringBase += ring.size();
    ring.clear();
}

bool Host::ringHasLineSince(unsigned long long from, const char* line)
{
    std::lock_guard<std::mutex> lk(mu);
    if(from < ringBase)
        from = ringBase;
    if(from >= logEndLocked())
        return false;
    std::string text = ring.substr((size_t)(from - ringBase));
    size_t pos = 0;
    while(pos <= text.size())
    {
        size_t nl = text.find('\n', pos);
        std::string l = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if(!l.empty() && l.back() == '\r')
            l.pop_back();
        if(l == line)
            return true;
        if(nl == std::string::npos)
            break;
        pos = nl + 1;
    }
    return false;
}

bool Host::setMirror(const std::string & path)
{
    stopMirror();
    FILE* f = nullptr;
    if(_wfopen_s(&f, wideOf(path).c_str(), L"ab") != 0 || !f)
        return false;
    std::lock_guard<std::mutex> lk(mirrorMu_);
    mirror_ = f;
    return true;
}

void Host::stopMirror()
{
    std::lock_guard<std::mutex> lk(mirrorMu_);
    if(mirror_)
    {
        fclose((FILE*)mirror_);
        mirror_ = nullptr;
    }
}

void Host::writeMirror(const std::string & text)
{
    std::lock_guard<std::mutex> lk(mirrorMu_);
    if(mirror_)
    {
        fwrite(text.data(), 1, text.size(), (FILE*)mirror_);
        fflush((FILE*)mirror_);
    }
}

// ------------------------------------------------------------------ events

long long Host::stampSeq()
{
    std::lock_guard<std::mutex> lk(mu);
    return ++nextSeq;
}

long long Host::pushEventLocked(const std::string & type, Json fields)
{
    Json ev = Json::object();
    long long seq = ++nextSeq;
    ev.set("seq", seq);
    ev.set("type", type);
    if(fields.isObject())
        for(auto & m : fields.members())
            ev.set(m.first, m.second);
    events.push_back(std::move(ev));
    while(events.size() > eventRingSize)
    {
        if(events.front().find("seq")->asInt() > emitCursor)
            pendingLost++;
        events.pop_front();
    }
    return seq;
}

long long Host::pushEvent(const std::string & type, Json fields)
{
    long long seq;
    {
        std::lock_guard<std::mutex> lk(mu);
        seq = pushEventLocked(type, std::move(fields));
    }
    cv.notify_all();
    return seq;
}

bool Host::hasUndeliveredLocked() const
{
    if(pendingLost > 0)
        return true;
    return !events.empty() && events.back().find("seq")->asInt() > emitCursor;
}

std::vector<Json> Host::takeEvents(size_t max, long long* firstUndelivered, bool* hadDropped)
{
    std::lock_guard<std::mutex> lk(mu);
    std::vector<Json> out;
    if(hadDropped)
        *hadDropped = false;
    if(firstUndelivered)
        *firstUndelivered = 0;
    if(pendingLost > 0)
    {
        Json ev = Json::object();
        ev.set("seq", ++nextSeq);
        ev.set("type", "events_dropped");
        ev.set("count", pendingLost);
        pendingLost = 0;
        out.push_back(std::move(ev));
        if(hadDropped)
            *hadDropped = true;
    }
    size_t taken = 0;
    for(auto & ev : events)
    {
        long long s = ev.find("seq")->asInt();
        if(s <= emitCursor)
            continue;
        if(taken >= max)
        {
            if(firstUndelivered)
                *firstUndelivered = s;
            break;
        }
        out.push_back(ev);
        emitCursor = s;
        taken++;
    }
    return out;
}

std::vector<Json> Host::eventsSince(long long since, size_t limit)
{
    std::lock_guard<std::mutex> lk(mu);
    std::vector<Json> out;
    for(auto & ev : events)
    {
        if(ev.find("seq")->asInt() > since)
        {
            out.push_back(ev);
            if(out.size() >= limit)
                break;
        }
    }
    return out;
}

std::vector<Json> Host::eventWindow(long long afterSeq, long long uptoSeq)
{
    std::lock_guard<std::mutex> lk(mu);
    std::vector<Json> out;
    for(auto & ev : events)
    {
        long long s = ev.find("seq")->asInt();
        if(s > afterSeq && s <= uptoSeq)
            out.push_back(ev);
    }
    return out;
}

long long Host::lastEventSeqLocked() const
{
    return events.empty() ? 0 : events.back().find("seq")->asInt();
}

// ------------------------------------------------------------------ state machine

Status Host::reportedStatusLocked() const
{
    if(launchPending && initSeq <= launchS0)
        return Status::Starting;
    return status;
}

void Host::onDebugState(int state, bool fast)
{
    {
        std::lock_guard<std::mutex> lk(mu);
        switch(state)
        {
        case initialized:
        {
            status = Status::Starting;
            ++stateSeq;
            initSeq = stateSeq;
            lastRunningSeq = ++nextSeq;
            exitCodeValid = false;
            exitCode = 0;
            lastException = LastException();
            lastExceptionEvent = Json();
            procValid = false;
            procEntryValid = false;
            pid = 0;
            lastResumeName.clear();
        }
        break;
        case running:
        {
            if(!fast)
                return;
            status = Status::Running;
            ++stateSeq;
            Json f = Json::object();
            lastRunningSeq = pushEventLocked("resumed", f);
            if(launchPending && initSeq > launchS0 && stateSeq > initSeq)
                launchPending = false;
        }
        break;
        case paused:
        {
            if(!fast)
                return;
            status = Status::Paused;
            ++stateSeq;
            Json f = Json::object();
            f.set("reason", "debugger");
            lastPausedSeq = pushEventLocked("paused", f);
            pausedRunningSeq = lastRunningSeq;
            if(launchPending && initSeq > launchS0 && stateSeq > initSeq)
                launchPending = false;
        }
        break;
        case stopped:
        {
            status = Status::Stopped;
            ++stateSeq;
            if(!callbacksOk)
                pushEventLocked("session_stopped", Json::object());
            if(launchPending && initSeq > launchS0 && stateSeq > initSeq)
                launchPending = false;
        }
        break;
        }
    }
    cv.notify_all();
}

void Host::synthesizePaused(const char* reason)
{
    {
        std::lock_guard<std::mutex> lk(mu);
        status = Status::Paused;
        ++stateSeq;
        Json f = Json::object();
        f.set("reason", reason);
        lastPausedSeq = pushEventLocked("paused", f);
        pausedRunningSeq = lastRunningSeq;
    }
    cv.notify_all();
}

bool Host::synthesizeRunningIf(long long s0)
{
    bool done = false;
    {
        std::lock_guard<std::mutex> lk(mu);
        if(stateSeq == s0 && status == Status::Paused)
        {
            status = Status::Running;
            ++stateSeq;
            Json f = Json::object();
            f.set("synthetic", true);
            lastRunningSeq = pushEventLocked("resumed", f);
            done = true;
        }
    }
    if(done)
        cv.notify_all();
    return done;
}

void Host::beginLaunch()
{
    {
        std::lock_guard<std::mutex> lk(mu);
        launchPending = true;
        launchS0 = stateSeq;
    }
    cv.notify_all();
}

void Host::endLaunch()
{
    {
        std::lock_guard<std::mutex> lk(mu);
        launchPending = false;
    }
    cv.notify_all();
}

void Host::setLastResumeName(const std::string & name)
{
    {
        std::lock_guard<std::mutex> lk(mu);
        lastResumeName = name;
    }
    cv.notify_all();
}

void Host::requestShutdown()
{
    {
        std::lock_guard<std::mutex> lk(mu);
        shuttingDown = true;
        shuttingDownA = true;
    }
    cv.notify_all();
}

void Host::setEof()
{
    {
        std::lock_guard<std::mutex> lk(mu);
        if(!eof)
        {
            eof = true;
            eofAt = std::chrono::steady_clock::now();
        }
    }
    cv.notify_all();
}

void Host::interrupt(bool & wasWaiting)
{
    {
        std::lock_guard<std::mutex> lk(mu);
        wasWaiting = waitersPending > 0;
        if(wasWaiting)
            interruptRequested = true;
    }
    cv.notify_all();
}

// ------------------------------------------------------------------ reference tables

void Host::refInitialize(const std::string & name)
{
    {
        std::lock_guard<std::mutex> lk(mu);
        RefTable t;
        t.id = ++tableCounter;
        t.name = name;
        tables.push_back(std::move(t));
        while(tables.size() > kMaxTables)
        {
            tableBytes -= std::min(tableBytes, tables.front().bytes);
            evictedUpTo = tables.front().id;
            tables.erase(tables.begin());
        }
    }
    cv.notify_all();
}

void Host::refAddColumn(const std::string & title)
{
    std::lock_guard<std::mutex> lk(mu);
    if(tables.empty())
        return;
    tables.back().columns.push_back(title);
}

void Host::refSetRowCount(int rows)
{
    std::lock_guard<std::mutex> lk(mu);
    if(tables.empty() || rows < 0)
        return;
    RefTable & t = tables.back();
    t.totalRows = rows;
    long long keep = std::min<long long>(rows, kMaxStoredRows);
    if(rows > kMaxStoredRows)
        t.storeTruncated = true;
    if((long long)t.rows.size() < keep)
        t.rows.resize((size_t)keep, std::vector<std::string>(t.columns.size()));
    else if((long long)t.rows.size() > keep)
        t.rows.resize((size_t)keep);
}

void Host::refSetCell(int row, int col, const std::string & text)
{
    std::lock_guard<std::mutex> lk(mu);
    if(tables.empty() || row < 0 || col < 0)
        return;
    RefTable & t = tables.back();
    if((size_t)row >= t.rows.size() || col > 4096)
        return;
    if(tableBytes + text.size() > kMaxTableBytes)
    {
        t.storeTruncated = true;
        return;
    }
    auto & r = t.rows[row];
    if((size_t)col >= r.size())
        r.resize(col + 1);
    tableBytes -= std::min(tableBytes, r[col].size());
    t.bytes -= std::min(t.bytes, r[col].size());
    r[col] = text;
    tableBytes += text.size();
    t.bytes += text.size();
}

void Host::refAddCommand(const std::string & title, const std::string & command)
{
    std::lock_guard<std::mutex> lk(mu);
    if(tables.empty())
        return;
    tables.back().actions.emplace_back(title, command);
}

std::string Host::refGetCell(int row, int col)
{
    std::lock_guard<std::mutex> lk(mu);
    if(tables.empty() || row < 0 || col < 0)
        return std::string();
    RefTable & t = tables.back();
    if((size_t)row >= t.rows.size() || (size_t)col >= t.rows[row].size())
        return std::string();
    return t.rows[row][col];
}

int Host::refRowCount()
{
    std::lock_guard<std::mutex> lk(mu);
    return tables.empty() ? 0 : (int)tables.back().totalRows;
}

std::vector<RefTable> Host::tablesBetween(int cursorExclusive, int limitInclusive, int* dropped)
{
    std::lock_guard<std::mutex> lk(mu);
    std::vector<RefTable> out;
    for(auto & t : tables)
        if(t.id > cursorExclusive && t.id <= limitInclusive)
            out.push_back(t);
    if(dropped)
        *dropped = std::max(0, (limitInclusive - cursorExclusive) - (int)out.size());
    return out;
}

bool Host::tableById(int id, RefTable & out, bool newest, bool* evicted)
{
    std::lock_guard<std::mutex> lk(mu);
    if(evicted)
        *evicted = false;
    if(newest)
    {
        if(tables.empty())
            return false;
        out = tables.back();
        return true;
    }
    for(auto & t : tables)
    {
        if(t.id == id)
        {
            out = t;
            return true;
        }
    }
    if(evicted && id > 0 && id <= evictedUpTo)
        *evicted = true;
    return false;
}

// ------------------------------------------------------------------ command registry

void Host::autoCompleteAdd(const std::string & names)
{
    std::lock_guard<std::mutex> lk(mu);
    std::vector<std::string> list;
    size_t pos = 0;
    while(pos <= names.size())
    {
        size_t c = names.find(',', pos);
        std::string n = trim(names.substr(pos, c == std::string::npos ? std::string::npos : c - pos));
        if(!n.empty())
            list.push_back(n);
        if(c == std::string::npos)
            break;
        pos = c + 1;
    }
    if(list.empty())
        return;
    for(auto & n : list)
        aliasToCanon.emplace(lower(n), list[0]);
    commandNames.push_back(list);
}

void Host::autoCompleteDel(const std::string & names)
{
    std::lock_guard<std::mutex> lk(mu);
    std::string first = names.substr(0, names.find(','));
    for(size_t i = 0; i < commandNames.size(); i++)
    {
        if(commandNames[i][0] == first)
        {
            for(auto & n : commandNames[i])
            {
                auto it = aliasToCanon.find(lower(n));
                if(it != aliasToCanon.end() && it->second == first)
                    aliasToCanon.erase(it);
            }
            commandNames.erase(commandNames.begin() + i);
            break;
        }
    }
}

void Host::autoCompleteClear()
{
    std::lock_guard<std::mutex> lk(mu);
    aliasToCanon.clear();
    commandNames.clear();
}

std::string Host::canonicalOf(const std::string & word)
{
    std::lock_guard<std::mutex> lk(mu);
    auto it = aliasToCanon.find(lower(word));
    return it == aliasToCanon.end() ? std::string() : it->second;
}

size_t Host::commandCount()
{
    std::lock_guard<std::mutex> lk(mu);
    return commandNames.size();
}

// ------------------------------------------------------------------ job queue

void Host::postJob(std::function<bool()> job)
{
    {
        std::lock_guard<std::mutex> lk(jobMu_);
        jobs_.push_back(std::move(job));
    }
    jobCv_.notify_all();
}

void Host::pumpJobs()
{
    while(true)
    {
        std::function<bool()> job;
        {
            std::unique_lock<std::mutex> lk(jobMu_);
            jobCv_.wait(lk, [this] { return !jobs_.empty(); });
            job = std::move(jobs_.front());
            jobs_.pop_front();
        }
        if(!job())
            return;
    }
}

// ------------------------------------------------------------------ plugin callbacks (events)

static const char* bpKindName(BPXTYPE t)
{
    switch(t)
    {
    case bp_normal:
        return "normal";
    case bp_hardware:
        return "hardware";
    case bp_memory:
        return "memory";
    case bp_dll:
        return "dll";
    case bp_exception:
        return "exception";
    default:
        return "normal";
    }
}

static void pluginCallback(CBTYPE type, void* info)
{
    Host & h = host();
    Json f = Json::object();
    switch(type)
    {
    case CB_INITDEBUG:
    {
        auto p = (PLUG_CB_INITDEBUG*)info;
        f.set("path", p && p->szFileName ? p->szFileName : "");
        h.pushEvent("session_started", f);
    }
    break;
    case CB_STOPDEBUG:
        h.pushEvent("session_stopped", f);
        break;
    case CB_CREATEPROCESS:
    {
        auto p = (PLUG_CB_CREATEPROCESS*)info;
        unsigned long long base = p && p->CreateProcessInfo ? (unsigned long long)p->CreateProcessInfo->lpBaseOfImage : 0;
        unsigned long long pid = p && p->fdProcessInfo ? p->fdProcessInfo->dwProcessId : 0;
        std::string path = p && p->DebugFileName ? p->DebugFileName : "";
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.pid = pid;
            h.procPath = path;
            size_t sl = path.find_last_of("\\/");
            h.procName = sl == std::string::npos ? path : path.substr(sl + 1);
            h.procBase = base;
            h.procValid = true;
            h.processStale = true;
        }
        f.set("pid", pid);
        f.set("base", hexAddr(base));
        f.set("path", path);
        h.pushEvent("process_created", f);
    }
    break;
    case CB_EXITPROCESS:
    {
        auto p = (PLUG_CB_EXITPROCESS*)info;
        unsigned code = p && p->ExitProcess ? p->ExitProcess->dwExitCode : 0;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.exitCode = code;
            h.exitCodeValid = true;
        }
        f.set("exit_code", (unsigned long long)code);
        h.pushEvent("process_exited", f);
    }
    break;
    case CB_CREATETHREAD:
    {
        auto p = (PLUG_CB_CREATETHREAD*)info;
        f.set("tid", p ? (unsigned long long)p->dwThreadId : 0ull);
        f.set("start", hexAddr(p && p->CreateThread ? (unsigned long long)p->CreateThread->lpStartAddress : 0));
        h.pushEvent("thread_created", f);
    }
    break;
    case CB_EXITTHREAD:
    {
        auto p = (PLUG_CB_EXITTHREAD*)info;
        f.set("tid", p ? (unsigned long long)p->dwThreadId : 0ull);
        f.set("exit_code", p && p->ExitThread ? (unsigned long long)p->ExitThread->dwExitCode : 0ull);
        h.pushEvent("thread_exited", f);
    }
    break;
    case CB_SYSTEMBREAKPOINT:
        h.pushEvent("system_breakpoint", f);
        break;
    case CB_LOADDLL:
    {
        auto p = (PLUG_CB_LOADDLL*)info;
        unsigned long long base = p && p->LoadDll ? (unsigned long long)p->LoadDll->lpBaseOfDll : 0;
        std::string name = p && p->modname ? p->modname : "";
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.moduleNames[base] = name;
        }
        f.set("name", name);
        f.set("base", hexAddr(base));
        h.pushEvent("module_loaded", f);
    }
    break;
    case CB_UNLOADDLL:
    {
        auto p = (PLUG_CB_UNLOADDLL*)info;
        unsigned long long base = p && p->UnloadDll ? (unsigned long long)p->UnloadDll->lpBaseOfDll : 0;
        std::string name;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            auto it = h.moduleNames.find(base);
            if(it != h.moduleNames.end())
            {
                name = it->second;
                h.moduleNames.erase(it);
            }
        }
        f.set("name", name);
        f.set("base", hexAddr(base));
        h.pushEvent("module_unloaded", f);
    }
    break;
    case CB_OUTPUTDEBUGSTRING:
    {
        auto p = (PLUG_CB_OUTPUTDEBUGSTRING*)info;
        if(p && p->DebugString)
        {
            // The text is read from the debuggee when the response is built (rule L3: no core calls here).
            f.set("text", "");
            f.set("_addr", (unsigned long long)p->DebugString->lpDebugStringData);
            f.set("_len", (unsigned long long)p->DebugString->nDebugStringLength);
            f.set("_uni", (unsigned long long)p->DebugString->fUnicode);
        }
        else
            f.set("text", "");
        h.pushEvent("debug_string", f);
    }
    break;
    case CB_EXCEPTION:
    {
        auto p = (PLUG_CB_EXCEPTION*)info;
        if(p && p->Exception)
        {
            f.set("code", hexAddr(p->Exception->ExceptionRecord.ExceptionCode));
            f.set("address", hexAddr((unsigned long long)p->Exception->ExceptionRecord.ExceptionAddress));
            f.set("first_chance", p->Exception->dwFirstChance != 0);
            f.set("name", nullptr);
            long long seq = h.pushEvent("exception", f);
            std::lock_guard<std::mutex> lk(h.mu);
            Json copy = f;
            copy.set("seq", seq);
            h.lastExceptionEvent = copy;
        }
    }
    break;
    case CB_BREAKPOINT:
    {
        auto p = (PLUG_CB_BREAKPOINT*)info;
        if(p && p->breakpoint)
        {
            f.set("bp_type", bpKindName(p->breakpoint->type));
            f.set("addr", hexAddr(p->breakpoint->addr));
            f.set("name", p->breakpoint->name);
            f.set("hit_count", (unsigned long long)p->breakpoint->hitCount);
            if(p->breakpoint->mod[0])
                f.set("module", p->breakpoint->mod);
            else
                f.set("module", nullptr);
            h.pushEvent("breakpoint_hit", f);
        }
    }
    break;
    case CB_PAUSEDEBUG:
    {
        bool need = false;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            need = h.status == Status::Running || h.status == Status::Starting;
        }
        if(need)
            h.onDebugState(paused, true);
    }
    break;
    case CB_STEPPED:
        h.pushEvent("stepped", f);
        break;
    case CB_ATTACH:
    {
        auto p = (PLUG_CB_ATTACH*)info;
        f.set("pid", p ? (unsigned long long)p->dwProcessId : 0ull);
        h.pushEvent("attached", f);
    }
    break;
    case CB_DETACH:
    {
        unsigned long long pid;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            pid = h.pid;
        }
        f.set("pid", pid);
        h.pushEvent("detached", f);
    }
    break;
    default:
        break;
    }
}

bool Host::registerPluginCallbacks()
{
    HMODULE dbg = GetModuleHandleW(L"x64dbg.dll");
    if(!dbg)
        dbg = GetModuleHandleW(L"x32dbg.dll");
    if(!dbg)
        return false;
    typedef void (*RegFn)(int, CBTYPE, CBPLUGIN);
    RegFn reg = (RegFn)GetProcAddress(dbg, "_plugin_registercallback");
    if(!reg)
        return false;
    static const CBTYPE types[] =
    {
        CB_INITDEBUG, CB_STOPDEBUG, CB_CREATEPROCESS, CB_EXITPROCESS, CB_CREATETHREAD, CB_EXITTHREAD,
        CB_SYSTEMBREAKPOINT, CB_LOADDLL, CB_UNLOADDLL, CB_OUTPUTDEBUGSTRING, CB_EXCEPTION, CB_BREAKPOINT,
        CB_PAUSEDEBUG, CB_STEPPED, CB_ATTACH, CB_DETACH
    };
    for(CBTYPE t : types)
        reg(0x7C110001, t, pluginCallback);
    {
        std::lock_guard<std::mutex> lk(mu);
        callbacksOk = true;
    }
    return true;
}
}
