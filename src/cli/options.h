#pragma once

#include <string>
#include <utility>
#include <vector>

namespace cli
{
struct StartupSpec
{
    bool isScript = false; // false: an --exec item, true: a --script file path
    std::string text;
};

struct Options
{
    bool json = false;
    bool interactive = false;
    bool keepGoing = false;
    bool noConsoleWindow = false;
    bool detachOnExit = false;
    bool foreground = false;
    bool selftest = false;
    bool help = false;
    bool version = false;
    bool msgynYes = false;
    bool anticheatYes = false;
    int verbose = 0;

    std::vector<StartupSpec> startup; // --exec / --script in command-line order
    std::string target;               // positional target ("" = none)
    bool haveTarget = false;
    std::vector<std::string> targetArgs;
    unsigned long long attachPid = 0;

    long long timeoutMs = 30000;
    long long eofWaitMs = 5000;
    long long stuckMs = 35000;
    long long maxOutput = 262144;
    std::string userDir;
    std::string logFile;

    // Hidden test options (only accepted when X64DBG_CLI_TEST=1).
    int testReaderDelay = 0;
    int testEventRing = 10000;
    std::string testCrash;
    int testTrailMs = -1;
    int testBarrierMs = -1;
    std::string testDropBarrier;
    bool testNoStartupBarrier = false;
    bool selftestStrayPrint = false;

    bool haveStartupItem() const { return haveTarget || attachPid != 0 || !startup.empty(); }
    // One-shot: any startup item and no --interactive. stdin is never read.
    bool oneShot() const { return haveStartupItem() && !interactive; }
};

// args exclude argv[0]. Returns false and fills error on a usage error (exit code 2).
bool parseArgs(const std::vector<std::string> & args, Options & opt, std::string & error, bool allowTestOptions);
std::string usageText();
}
