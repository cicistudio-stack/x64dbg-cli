#include "../bridge/bridgemain.h"

#include "app.h"
#include "io.h"
#include "json.h"
#include "options.h"
#include "protocol.h"
#include "session.h"
#include "util.h"

#include <Windows.h>
#include <shellapi.h>
#include <mmsystem.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

int runSelfTest(); // selftest.cpp

namespace cli
{
static Options gOptions;
static std::string gUserDirUtf8;
static std::wstring gUserDirW;
static std::vector<std::string> gStartupLines;
static std::string gTargetLine;
static std::atomic<int> gExit{ 0 };
static bool gNoConsoleChanged = false;
static std::string gNoConsolePrevious;
static bool gNoConsoleHadPrevious = false;
static HANDLE gLockHandle = INVALID_HANDLE_VALUE;

// ------------------------------------------------------------------ crash handlers (design 6.5)

[[noreturn]] static void crashExit()
{
    io::writeFatal(renderFatal(gOptions.json, "E_CRASH", "internal error in x64dbg-cli or the core"));
    TerminateProcess(GetCurrentProcess(), 70);
    for(;;)
        Sleep(1000);
}

static LONG WINAPI unhandledFilter(EXCEPTION_POINTERS*)
{
    crashExit();
}

static void invalidParameterHandler(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, uintptr_t)
{
    crashExit();
}

static void pureCallHandler()
{
    crashExit();
}

static void abortHandler(int)
{
    crashExit();
}

static void installCrashHandlers()
{
    SetUnhandledExceptionFilter(unhandledFilter);
    _set_invalid_parameter_handler(invalidParameterHandler);
    _set_purecall_handler(pureCallHandler);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    signal(SIGABRT, abortHandler);
}

static BOOL WINAPI consoleCtrlHandler(DWORD type)
{
    switch(type)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if(Session* s = session())
            s->requestShutdown("console control");
        return TRUE;
    default:
        return FALSE;
    }
}

void requestShutdown(const char* reason)
{
    if(Session* s = session())
        s->requestShutdown(reason);
}

// ------------------------------------------------------------------ startup helpers

static std::string win32ErrorText(DWORD err)
{
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err, 0, (LPWSTR)&buf, 0, nullptr);
    std::string s = buf ? trim(utf8Of(buf)) : "error " + std::to_string(err);
    if(buf)
        LocalFree(buf);
    return s;
}

static bool readScript(const std::string & path, std::vector<std::string> & lines, std::string & error)
{
    HANDLE f = CreateFileW(wideOf(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(f == INVALID_HANDLE_VALUE)
    {
        error = "cannot read script " + path + ": " + win32ErrorText(GetLastError());
        return false;
    }
    LARGE_INTEGER size;
    if(!GetFileSizeEx(f, &size))
    {
        error = "cannot read script " + path + ": " + win32ErrorText(GetLastError());
        CloseHandle(f);
        return false;
    }
    if(size.QuadPart > (16 << 20))
    {
        error = "script " + path + " is larger than 16 MiB";
        CloseHandle(f);
        return false;
    }
    std::string data((size_t)size.QuadPart, '\0');
    size_t off = 0;
    while(off < data.size())
    {
        DWORD got = 0;
        if(!ReadFile(f, &data[off], (DWORD)(data.size() - off), &got, nullptr) || got == 0)
        {
            error = "cannot read script " + path + ": " + win32ErrorText(GetLastError());
            CloseHandle(f);
            return false;
        }
        off += got;
    }
    CloseHandle(f);
    data = sanitizeUtf8(data);
    if(data.compare(0, 3, "\xEF\xBB\xBF") == 0)
        data.erase(0, 3);
    size_t pos = 0;
    while(pos < data.size())
    {
        size_t nl = data.find('\n', pos);
        std::string l = data.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if(!l.empty() && l.back() == '\r')
            l.pop_back();
        lines.push_back(l);
        if(nl == std::string::npos)
            break;
        pos = nl + 1;
    }
    return true;
}

// Rule S of design 8.1: split on ';' outside quotes, except for items that start with '$'.
static void addStartupText(const std::string & item, std::vector<std::string> & out)
{
    std::string t = trim(item);
    if(t.empty())
        return;
    if(t[0] == '$')
    {
        out.push_back(t);
        return;
    }
    for(auto & s : splitSemicolon(t))
    {
        std::string x = trim(s);
        if(!x.empty())
            out.push_back(x);
    }
}

static bool isAbsoluteDrivePath(const std::string & p)
{
    return p.size() >= 4 && isalpha((unsigned char)p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/');
}

static std::vector<std::string> wideArgs()
{
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> out;
    for(int i = 1; i < argc; i++)
        out.push_back(utf8Of(argv[i]));
    if(argv)
        LocalFree(argv);
    return out;
}

static void truncateCommandLine()
{
    wchar_t* cl = GetCommandLineW();
    if(!cl)
        return;
    size_t i = 0;
    if(cl[0] == L'"')
    {
        i = 1;
        while(cl[i] && cl[i] != L'"')
            i++;
        if(cl[i])
            i++;
    }
    else
    {
        while(cl[i] && cl[i] != L' ' && cl[i] != L'\t')
            i++;
    }
    cl[i] = L'\0';
}

static int usageError(const std::string & message)
{
    io::diag(message + "\nTry 'x64dbg-cli.exe --help'.", true);
    return 2;
}

static std::wstring exeDirectory()
{
    wchar_t path[MAX_PATH] = L"";
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* slash = wcsrchr(path, L'\\');
    if(slash)
        *slash = L'\0';
    return path;
}

static void restoreNoConsoleWindow()
{
    if(!gNoConsoleChanged)
        return;
    gNoConsoleChanged = false;
    BridgeSettingSet("Engine", "NoConsoleWindow", gNoConsoleHadPrevious ? gNoConsolePrevious.c_str() : "0");
}

[[noreturn]] static void testCrashThread(const std::string & kind)
{
    Sleep(2000);
    if(kind == "seh")
        *(volatile int*)nullptr = 1;
    else if(kind == "invalid-param")
    {
        char b[1];
        strcpy_s(b, sizeof(b), "ab");
    }
    else
        abort();
    for(;;)
        Sleep(1000);
}

// ------------------------------------------------------------------ the "GUI side": runs inside BridgeStart

int guiMain()
{
    Host & h = host();
    Options & opt = gOptions;
    h.mainThreadId = GetCurrentThreadId();
    h.verbose = opt.verbose;
    h.msgynYes = opt.msgynYes;
    h.anticheatYes = opt.anticheatYes;
    h.foreground = opt.foreground;
    h.eventRingSize = (size_t)opt.testEventRing;
    h.dropBarrier = opt.testDropBarrier;
    if(opt.testBarrierMs > 0)
        h.barrierMs = opt.testBarrierMs;
    if(!opt.logFile.empty() && !h.setMirror(opt.logFile))
        io::diag("cannot open log file " + opt.logFile, true);

    Session session(opt, gUserDirUtf8);
    setSession(&session);
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);

    const char* err = DbgInitBlocking();
    if(err)
    {
        io::diag(std::string("core initialisation failed: ") + err, true);
        gExit = 3;
        return 3;
    }
    h.registerPluginCallbacks();

    // startup log drain: the init text must not land in the window of the first request
    if(!opt.testNoStartupBarrier)
    {
        unsigned long long end = 0;
        bool ok = runBarrier(h, h.barrierMs, [](const std::string & line)
        {
            return DbgCmdExecDirect((" " + line).c_str());
        }, &end);
        if(!ok)
        {
            Json f = Json::object();
            f.set("message", "barrier_timeout_startup");
            h.pushEvent("warning", f);
        }
    }
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.requestFloor = h.logEndLocked();
    }

    io::writeProtocol(renderReady(opt.json, session.buildHello()));
    if(!opt.testCrash.empty())
    {
        std::string kind = opt.testCrash;
        std::thread([kind] { testCrashThread(kind); }).detach();
    }
    if(opt.selftestStrayPrint)
        std::thread([] { printf("stray print from a core-side thread\n"); fflush(stdout); }).detach();

    session.start();
    if(opt.haveStartupItem())
    {
        std::vector<std::string> lines;
        if(!gTargetLine.empty())
            lines.push_back(gTargetLine);
        for(auto & l : gStartupLines)
            lines.push_back(l);
        session.queueStartup(lines, false);
        if(opt.oneShot() && session.startupDone())
            session.requestShutdown("done");
        else if(opt.interactive && session.startupDone())
            session.startReader();
    }
    else
        session.startReader();

    h.pumpJobs();

    // ---- shutdown (design 6.5)
    bool safe = session.quiesce();
    if(!safe)
    {
        restoreNoConsoleWindow();
        BridgeSettingFlush();
        h.stopMirror();
        session.fatalExit("E_SHUTDOWN_HANG", "a core thread did not leave the core during shutdown");
    }
    if(session.detachRequested() && DbgIsDebugging())
    {
        auto done = std::make_shared<std::atomic<bool>>(false);
        std::thread([done]
        {
            // The core detaches reliably only from a paused debuggee (a detach while it runs ends with the debuggee
            // killed by DbgExit), so pause it first. A pause can need a second request after 2.2 s (design 7.4).
            for(int attempt = 0; attempt < 3 && DbgIsDebugging() && DbgIsRunning(); attempt++)
            {
                DbgCmdExecDirect(" pause");
                for(int i = 0; i < 230 && DbgIsDebugging() && DbgIsRunning(); i++)
                    Sleep(10);
            }
            DbgCmdExecDirect(" DetachDebugger");
            done->store(true);
        }).detach();
        for(int i = 0; i < 1000 && !done->load(); i++)
            Sleep(10);
    }
    DbgExit();
    h.dbgStopped = true;
    h.stopMirror();
    restoreNoConsoleWindow();
    gExit = session.exitCode();
    SetConsoleCtrlHandler(consoleCtrlHandler, FALSE);
    setSession(nullptr);
    // The Session object lives on this stack frame; its threads have been joined or detached.
    io::drain(500);
    if(gExit.load() == 70)
    {
        CloseHandle(gLockHandle);
        TerminateProcess(GetCurrentProcess(), 70);
    }
    return 0;
}

static int cliMain()
{
    SetErrorMode(SEM_FAILCRITICALERRORS);
    std::vector<std::string> args = wideArgs();
    const char* testEnv = getenv("X64DBG_CLI_TEST");
    bool allowTest = testEnv && std::string(testEnv) == "1";
    Options & opt = gOptions;
    std::string error;
    if(!parseArgs(args, opt, error, allowTest))
    {
        fprintf(stderr, "x64dbg-cli: %s\nTry 'x64dbg-cli.exe --help'.\n", error.c_str());
        return 2;
    }
    if(opt.help)
    {
        printf("%s", usageText().c_str());
        return 0;
    }
    if(opt.version)
    {
        printf("x64dbg-cli %s (protocol %d)\n", kVersion, kProtocolVersion);
        return 0;
    }
    if(opt.selftest)
        return runSelfTest();

    // scripts are read before the core is loaded (relative paths mean the caller's directory)
    std::vector<std::string> startup;
    for(auto & spec : opt.startup)
    {
        if(!spec.isScript)
        {
            addStartupText(spec.text, startup);
            continue;
        }
        std::vector<std::string> lines;
        if(!readScript(spec.text, lines, error))
        {
            fprintf(stderr, "x64dbg-cli: %s\n", error.c_str());
            return 2;
        }
        for(auto & l : lines)
        {
            std::string t = trim(l);
            if(t.empty() || t[0] == '#')
                continue;
            addStartupText(t, startup);
        }
    }
    gStartupLines = startup;
    if(opt.haveTarget)
    {
        std::string line = "init \"" + commandEscape(opt.target) + "\"";
        if(!opt.targetArgs.empty())
            line += ", \"" + commandEscape(joinTargetArgs(opt.targetArgs)) + "\"";
        if(line.size() > 1023)
        {
            fprintf(stderr, "x64dbg-cli: target arguments too long\n");
            return 2;
        }
        gTargetLine = line;
    }
    else if(opt.attachPid)
        gTargetLine = "attach ." + std::to_string(opt.attachPid);

    SetErrorMode(SEM_FAILCRITICALERRORS);
    installCrashHandlers();
    timeBeginPeriod(1);
    io::init(opt.verbose > 0);
    io::startWriter([](const char* code)
    {
        io::diag(std::string("output channel lost: ") + code);
        gExit = 70;
        if(Session* s = session())
            s->requestShutdown(code);
        else
            TerminateProcess(GetCurrentProcess(), 70);
    });

    // user directory and lock file
    std::wstring dir;
    if(!opt.userDir.empty())
        dir = wideOf(opt.userDir);
    else
        dir = exeDirectory() + L"\\x64dbg-cli";
    DWORD attr = GetFileAttributesW(dir.c_str());
    if(attr == INVALID_FILE_ATTRIBUTES)
    {
        if(!CreateDirectoryW(dir.c_str(), nullptr))
        {
            io::diag("cannot create user directory " + utf8Of(dir.c_str()) + ": " + win32ErrorText(GetLastError()) +
                     "; pass --userdir <writable absolute path>", true);
            return 2;
        }
    }
    else if(!(attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        io::diag("cannot create user directory " + utf8Of(dir.c_str()) + ": a file with that name exists", true);
        return 2;
    }
    std::wstring lockPath = dir + L"\\x64dbg-cli.lock";
    gLockHandle = CreateFileW(lockPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if(gLockHandle == INVALID_HANDLE_VALUE)
    {
        io::diag("user directory " + utf8Of(dir.c_str()) + " is in use by another x64dbg-cli process; start this instance with --userdir <other dir>", true);
        return 2;
    }
    gUserDirW = dir;
    gUserDirUtf8 = utf8Of(dir.c_str());

    truncateCommandLine();
    BRIDGE_CONFIG config = {};
    config.hGuiModule = GetModuleHandleW(nullptr);
    config.szUserDirectory = gUserDirW.c_str();
    const wchar_t* bridgeError = BridgeInit(&config);
    if(bridgeError)
    {
        io::diag("BridgeInit failed: " + utf8Of(bridgeError), true);
        return 3;
    }
    SetCurrentDirectoryW(BridgeWorkingDirectory());
    if(opt.noConsoleWindow)
    {
        char prev[MAX_SETTING_SIZE] = "";
        gNoConsoleHadPrevious = BridgeSettingGet("Engine", "NoConsoleWindow", prev);
        gNoConsolePrevious = prev;
        BridgeSettingSet("Engine", "NoConsoleWindow", "1");
        gNoConsoleChanged = true;
    }
    bridgeError = BridgeStart();
    if(bridgeError)
    {
        io::diag("BridgeStart failed: " + utf8Of(bridgeError), true);
        return 3;
    }
    return gExit.load();
}
}

int main()
{
    int code = cli::cliMain();
    fflush(nullptr);
    cli::io::drain(500);
    cli::io::restore();
    // Skip the CRT/DLL shutdown: the detached writer thread and the core's threads must not run static destructors.
    TerminateProcess(GetCurrentProcess(), (UINT)code);
    return code;
}
