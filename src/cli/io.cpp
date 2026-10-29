#include "io.h"

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <thread>

namespace cli
{
namespace io
{
static HANDLE hIn = nullptr;
static HANDLE hOut = nullptr;
static HANDLE hErr = nullptr;
static bool gVerbose = false;
static UINT oldOutCp = 0, oldInCp = 0;

static std::mutex qmu;
static std::condition_variable qcv;
static std::deque<std::string> queue;
static size_t pending = 0;
static bool writerBusy = false;
static std::atomic<bool> lost{ false };
static std::atomic<bool> stopWriter{ false };
static std::function<void(const char*)> fatalCb;
static std::thread writerThread;
static const size_t kQueueLimit = 64u << 20;

static HANDLE dupStd(DWORD which)
{
    HANDLE h = GetStdHandle(which);
    if(!h || h == INVALID_HANDLE_VALUE)
        return nullptr;
    HANDLE d = nullptr;
    if(!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return nullptr;
    return d;
}

void init(bool verbose)
{
    gVerbose = verbose;
    hIn = dupStd(STD_INPUT_HANDLE);
    hOut = dupStd(STD_OUTPUT_HANDLE);
    hErr = dupStd(STD_ERROR_HANDLE);

    DWORD mode;
    if(hOut && GetConsoleMode(hOut, &mode))
    {
        oldOutCp = GetConsoleOutputCP();
        SetConsoleOutputCP(CP_UTF8);
    }
    if(hIn && GetConsoleMode(hIn, &mode))
    {
        oldInCp = GetConsoleCP();
        SetConsoleCP(CP_UTF8);
    }

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE nulIn = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    HANDLE nulOut = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    if(nulIn != INVALID_HANDLE_VALUE)
        SetStdHandle(STD_INPUT_HANDLE, nulIn);
    if(nulOut != INVALID_HANDLE_VALUE)
    {
        SetStdHandle(STD_OUTPUT_HANDLE, nulOut);
        SetStdHandle(STD_ERROR_HANDLE, nulOut);
    }
    FILE* f = nullptr;
    freopen_s(&f, "NUL", "w", stdout);
    freopen_s(&f, "NUL", "w", stderr);
    freopen_s(&f, "NUL", "r", stdin);
}

void restore()
{
    if(oldOutCp)
        SetConsoleOutputCP(oldOutCp);
    if(oldInCp)
        SetConsoleCP(oldInCp);
}

bool verbose()
{
    return gVerbose;
}

void diag(const std::string & text, bool force)
{
    if((!gVerbose && !force) || !hErr)
        return;
    std::string line = force ? "x64dbg-cli: " + text + "\n" : "[x64dbg-cli] " + text + "\n";
    DWORD written = 0;
    WriteFile(hErr, line.data(), (DWORD)line.size(), &written, nullptr);
}

static void writerMain()
{
    while(true)
    {
        std::string msg;
        {
            std::unique_lock<std::mutex> lk(qmu);
            qcv.wait(lk, [] { return !queue.empty() || stopWriter.load(); });
            if(queue.empty())
                return;
            msg = std::move(queue.front());
            queue.pop_front();
            writerBusy = true;
        }
        bool ok = hOut != nullptr;
        size_t off = 0;
        while(ok && off < msg.size())
        {
            DWORD written = 0;
            if(!WriteFile(hOut, msg.data() + off, (DWORD)(msg.size() - off), &written, nullptr))
            {
                ok = false;
                break;
            }
            off += written;
        }
        {
            std::lock_guard<std::mutex> lk(qmu);
            pending -= msg.size();
            writerBusy = false;
        }
        qcv.notify_all();
        if(!ok)
        {
            lost = true;
            if(fatalCb)
                fatalCb("E_BROKEN_PIPE");
            std::lock_guard<std::mutex> lk(qmu);
            queue.clear();
            pending = 0;
        }
    }
}

void startWriter(std::function<void(const char*)> onFatal)
{
    fatalCb = std::move(onFatal);
    writerThread = std::thread(writerMain);
    writerThread.detach();
}

bool writeProtocol(std::string message)
{
    {
        std::lock_guard<std::mutex> lk(qmu);
        if(lost)
            return false;
        if(pending + message.size() > kQueueLimit)
        {
            lost = true;
            std::function<void(const char*)> cb = fatalCb;
            queue.clear();
            pending = 0;
            // call outside would be nicer, but the callback is lightweight and non-blocking by contract
            if(cb)
                std::thread([cb] { cb("E_OUTPUT_STALLED"); }).detach();
            return false;
        }
        pending += message.size();
        queue.push_back(std::move(message));
    }
    qcv.notify_all();
    return true;
}

void writeFatal(const std::string & line)
{
    {
        std::lock_guard<std::mutex> lk(qmu);
        pending += line.size();
        queue.push_front(line);
    }
    qcv.notify_all();
    drain(250);
}

bool drain(int ms)
{
    std::unique_lock<std::mutex> lk(qmu);
    return qcv.wait_for(lk, std::chrono::milliseconds(ms), [] { return (queue.empty() && !writerBusy) || lost.load(); }) && queue.empty() && !writerBusy;
}

bool outputLost()
{
    return lost.load();
}

size_t pendingBytes()
{
    std::lock_guard<std::mutex> lk(qmu);
    return pending;
}

bool stdinIsConsole()
{
    DWORD mode;
    return hIn && GetConsoleMode(hIn, &mode);
}

LineReader::Result LineReader::read(std::string & line, size_t maxBytes)
{
    while(true)
    {
        size_t nl = buf_.find('\n');
        if(nl != std::string::npos)
        {
            std::string l = buf_.substr(0, nl);
            buf_.erase(0, nl + 1);
            if(!l.empty() && l.back() == '\r')
                l.pop_back();
            if(discarding_)
            {
                discarding_ = false;
                line.clear();
                return TooLong;
            }
            if(l.size() > maxBytes)
            {
                line.clear();
                return TooLong;
            }
            if(first_)
            {
                first_ = false;
                if(l.compare(0, 3, "\xEF\xBB\xBF") == 0)
                    l.erase(0, 3);
            }
            line = std::move(l);
            return Line;
        }
        if(buf_.size() > maxBytes)
        {
            buf_.clear();
            discarding_ = true;
        }
        if(eof_)
        {
            if(discarding_)
            {
                discarding_ = false;
                line.clear();
                return TooLong;
            }
            if(!buf_.empty())
            {
                line = std::move(buf_);
                buf_.clear();
                if(!line.empty() && line.back() == '\r')
                    line.pop_back();
                if(first_ && line.compare(0, 3, "\xEF\xBB\xBF") == 0)
                    line.erase(0, 3);
                first_ = false;
                return Line;
            }
            return Eof;
        }
        if(shouldStop && shouldStop())
            return Cancelled;
        if(beforeRead)
            beforeRead();
        if(!hIn)
        {
            eof_ = true;
            continue;
        }
        char tmp[65536];
        DWORD got = 0;
        BOOL ok = ReadFile(hIn, tmp, sizeof(tmp), &got, nullptr);
        if(shouldStop && shouldStop())
            return Cancelled;
        if(!ok || got == 0)
        {
            DWORD err = ok ? 0 : GetLastError();
            if(err == ERROR_OPERATION_ABORTED)
            {
                if(shouldStop && shouldStop())
                    return Cancelled;
                continue;
            }
            eof_ = true;
            continue;
        }
        if(discarding_)
        {
            // keep only data after the next newline
            const char* p = (const char*)memchr(tmp, '\n', got);
            if(p)
                buf_.assign(p, tmp + got - p);
            continue;
        }
        buf_.append(tmp, got);
    }
}
}
}
