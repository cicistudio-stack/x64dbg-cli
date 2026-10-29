#include "options.h"
#include "util.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace cli
{
std::string usageText()
{
    return
        "usage: x64dbg-cli.exe [options] [--] [target.exe [target args...]]\n"
        "\n"
        "  --json                 JSON-lines protocol on stdin/stdout (default: text REPL)\n"
        "  --exec <cmds>          run commands (separated by ';') then exit; repeatable\n"
        "  --script <file>        run a file with one command per line then exit\n"
        "  --interactive          stay in the session after --exec/--script/target/--attach\n"
        "  --attach <pid>         attach to a process (decimal pid)\n"
        "  --timeout <ms>         default wait timeout (default 30000, 0..3600000)\n"
        "  --eof-wait <ms>        wait cap after stdin EOF (default 5000, 0..60000)\n"
        "  --stuck-ms <ms>        blocking core call limit floor (default 35000, 5000..3600000)\n"
        "  --keep-going           one-shot: continue after a failing command\n"
        "  --userdir <X:\\path>    settings/database directory (default <exe dir>\\x64dbg-cli)\n"
        "  --no-console-window    debuggee console apps get no window\n"
        "  --msgyn yes|no         answer to msgyn prompts (default no)\n"
        "  --anticheat yes|no     answer to the interfering-driver prompt (default no)\n"
        "  --detach-on-exit       detach instead of killing the debuggee at shutdown\n"
        "  --foreground           let the core bring the console window to the front\n"
        "  --log-file <path>      mirror the core log to a file\n"
        "  --max-output <bytes>   per-response output cap (default 262144)\n"
        "  -v, -vv                diagnostics on stderr\n"
        "  --selftest, --version, --help\n"
        "\n"
        "Exit codes: 0 ok, 1 command failed, 2 usage error, 3 core init failed, 4 wait timeout (one-shot), 70 fatal.\n";
}

static bool parseRange(const std::string & name, const std::string & value, long long lo, long long hi, long long & out, std::string & error)
{
    long long v = 0;
    bool ok = !value.empty();
    for(char c : value)
        if(c < '0' || c > '9')
            ok = false;
    if(ok && value.size() <= 12)
        v = strtoll(value.c_str(), nullptr, 10);
    else
        ok = false;
    if(!ok || v < lo || v > hi)
    {
        error = name + " expects an integer in " + std::to_string(lo) + ".." + std::to_string(hi) + ", got '" + value + "'";
        return false;
    }
    out = v;
    return true;
}

static bool isDrivePath(const std::string & p)
{
    return p.size() >= 4 && isalpha((unsigned char)p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/');
}

bool parseArgs(const std::vector<std::string> & args, Options & opt, std::string & error, bool allowTest)
{
    size_t i = 0;
    for(; i < args.size(); i++)
    {
        const std::string & a = args[i];
        if(a == "--")
        {
            i++;
            break;
        }
        if(a.empty() || a[0] != '-')
            break;
        auto needValue = [&](std::string & value) -> bool
        {
            if(i + 1 >= args.size())
            {
                error = "option " + a + " needs a value";
                return false;
            }
            value = args[++i];
            return true;
        };
        std::string v;
        long long n = 0;
        if(a == "--json")
            opt.json = true;
        else if(a == "--interactive")
            opt.interactive = true;
        else if(a == "--keep-going")
            opt.keepGoing = true;
        else if(a == "--no-console-window")
            opt.noConsoleWindow = true;
        else if(a == "--detach-on-exit")
            opt.detachOnExit = true;
        else if(a == "--foreground")
            opt.foreground = true;
        else if(a == "--selftest")
            opt.selftest = true;
        else if(a == "--version")
            opt.version = true;
        else if(a == "--help" || a == "-h")
            opt.help = true;
        else if(a == "-v")
            opt.verbose = std::max(opt.verbose, 1);
        else if(a == "-vv")
            opt.verbose = 2;
        else if(a == "--exec")
        {
            if(!needValue(v))
                return false;
            opt.startup.push_back({ false, v });
        }
        else if(a == "--script")
        {
            if(!needValue(v))
                return false;
            opt.startup.push_back({ true, v });
        }
        else if(a == "--attach")
        {
            if(!needValue(v) || !parseRange("--attach", v, 1, 4294967295LL, n, error))
                return false;
            opt.attachPid = (unsigned long long)n;
        }
        else if(a == "--timeout")
        {
            if(!needValue(v) || !parseRange("--timeout", v, 0, 3600000, opt.timeoutMs, error))
                return false;
        }
        else if(a == "--eof-wait")
        {
            if(!needValue(v) || !parseRange("--eof-wait", v, 0, 60000, opt.eofWaitMs, error))
                return false;
        }
        else if(a == "--stuck-ms")
        {
            if(!needValue(v) || !parseRange("--stuck-ms", v, 5000, 3600000, opt.stuckMs, error))
                return false;
        }
        else if(a == "--max-output")
        {
            if(!needValue(v) || !parseRange("--max-output", v, 1024, 16777216, opt.maxOutput, error))
                return false;
        }
        else if(a == "--userdir")
        {
            if(!needValue(v))
                return false;
            if(!isDrivePath(v))
            {
                error = "--userdir must be an absolute path like X:\\dir, got '" + v + "'";
                return false;
            }
            opt.userDir = v;
        }
        else if(a == "--log-file")
        {
            if(!needValue(v))
                return false;
            if(!isDrivePath(v) && !(v.size() > 2 && v[0] == '\\' && v[1] == '\\'))
            {
                error = "--log-file must be an absolute path, got '" + v + "'";
                return false;
            }
            opt.logFile = v;
        }
        else if(a == "--msgyn" || a == "--anticheat")
        {
            if(!needValue(v))
                return false;
            if(v != "yes" && v != "no")
            {
                error = a + " expects yes or no, got '" + v + "'";
                return false;
            }
            (a == "--msgyn" ? opt.msgynYes : opt.anticheatYes) = (v == "yes");
        }
        else if(allowTest && a == "--test-reader-delay")
        {
            if(!needValue(v) || !parseRange(a, v, 0, 10000, n, error))
                return false;
            opt.testReaderDelay = (int)n;
        }
        else if(allowTest && a == "--test-event-ring")
        {
            if(!needValue(v) || !parseRange(a, v, 1, 1000000, n, error))
                return false;
            opt.testEventRing = (int)n;
        }
        else if(allowTest && a == "--test-trail-ms")
        {
            if(!needValue(v) || !parseRange(a, v, 0, 1000, n, error))
                return false;
            opt.testTrailMs = (int)n;
        }
        else if(allowTest && a == "--test-barrier-ms")
        {
            if(!needValue(v) || !parseRange(a, v, 100, 60000, n, error))
                return false;
            opt.testBarrierMs = (int)n;
        }
        else if(allowTest && a == "--test-crash")
        {
            if(!needValue(v))
                return false;
            if(v != "seh" && v != "invalid-param" && v != "abort")
            {
                error = "--test-crash expects seh, invalid-param or abort";
                return false;
            }
            opt.testCrash = v;
        }
        else if(allowTest && a == "--test-drop-barrier")
        {
            if(!needValue(v))
                return false;
            if(v != "text" && v != "html")
            {
                error = "--test-drop-barrier expects text or html";
                return false;
            }
            opt.testDropBarrier = v;
        }
        else if(allowTest && a == "--test-no-startup-barrier")
            opt.testNoStartupBarrier = true;
        else if(allowTest && a == "--selftest-stray-print")
            opt.selftestStrayPrint = true;
        else
        {
            error = (a.find('=') != std::string::npos ? "unsupported option form (use '--opt value'): " : "unknown option: ") + a;
            return false;
        }
    }
    if(i < args.size())
    {
        opt.haveTarget = true;
        opt.target = args[i];
        for(size_t k = i + 1; k < args.size(); k++)
            opt.targetArgs.push_back(args[k]);
    }
    if(opt.haveTarget && opt.attachPid)
    {
        error = "a target and --attach cannot be combined";
        return false;
    }
    return true;
}
}
