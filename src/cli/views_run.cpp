#include "util.h"
#include "views.h"

namespace cli
{
namespace
{
// `restart` repeats the last init of this session (design 9.3).
std::string gLastFile, gLastArgs, gLastCwd;
bool gHaveInit = false;

bool cleanArg(Result & res, const char* what, const std::string & s)
{
    if(s.find('\0') != std::string::npos || s.find('\r') != std::string::npos || s.find('\n') != std::string::npos)
    {
        res.fail("E_BAD_ARG", std::string(what) + " must not contain NUL, CR or LF");
        return false;
    }
    return true;
}

bool countArg(Request & req, Result & res, bool & has, long long & count)
{
    count = 0;
    has = argInt(req.args, "count", count);
    if(has && (count < 0 || count > 1000000))
    {
        res.fail("E_BAD_ARG", "count must be in 0..1000000");
        return false;
    }
    return true;
}

void step(Session & s, Request & req, Result & res, const char* command)
{
    bool has;
    long long count;
    if(!countArg(req, res, has, count))
        return;
    s.execLine(req, res, buildStepLine(command, has, count));
}
}

std::string buildStepLine(const char* command, bool hasCount, long long count)
{
    // rule N: the core reads the count as an expression, so it is emitted in hex (sti 10 would step 16 times)
    return hasCount ? std::string(command) + " " + hexArg(count) : std::string(command);
}

std::string buildAttachLine(long long pid)
{
    // the '.' prefix makes the core read the pid as decimal
    return "attach ." + std::to_string(pid);
}

std::string buildInitLine(const std::string & file, const std::string & args, const std::string & cwd)
{
    std::string line = "init \"" + commandEscape(file) + "\"";
    if(!args.empty() || !cwd.empty())
        line += ",\"" + commandEscape(args) + "\"";
    if(!cwd.empty())
        line += ",\"" + commandEscape(cwd) + "\"";
    return line;
}

void viewInit(Session & s, Request & req, Result & res)
{
    std::string file, args, cwd;
    if(!argText(req.args, "file", file, false) || trim(file).empty())
    {
        res.fail("E_BAD_ARG", "init requires file (usage: init <file> [--args text] [--cwd dir])");
        return;
    }
    argText(req.args, "args", args, false);
    argText(req.args, "cwd", cwd, false);
    if(!cleanArg(res, "file", file) || !cleanArg(res, "args", args) || !cleanArg(res, "cwd", cwd))
        return;
    if(s.execLine(req, res, buildInitLine(file, args, cwd)))
    {
        gLastFile = file;
        gLastArgs = args;
        gLastCwd = cwd;
        gHaveInit = true;
    }
}

void viewRestart(Session & s, Request & req, Result & res)
{
    if(!gHaveInit)
    {
        res.fail("E_BAD_ARG", "restart has nothing to repeat: no init has been run through this CLI yet");
        return;
    }
    std::string line = buildInitLine(gLastFile, gLastArgs, gLastCwd);
    if(DbgIsDebugging())
        line = "stop; " + line;
    s.execLine(req, res, line);
}

void viewRun(Session & s, Request & req, Result & res)
{
    s.execLine(req, res, "run");
}

void viewStepIn(Session & s, Request & req, Result & res)
{
    step(s, req, res, "sti");
}

void viewStepOver(Session & s, Request & req, Result & res)
{
    step(s, req, res, "sto");
}

void viewStepOut(Session & s, Request & req, Result & res)
{
    step(s, req, res, "rtr");
}

void viewSkip(Session & s, Request & req, Result & res)
{
    step(s, req, res, "skip");
}

void viewRunTo(Session & s, Request & req, Result & res)
{
    std::string text;
    if(!argText(req.args, "addr", text, true))
    {
        res.fail("E_BAD_ARG", "runto requires addr");
        return;
    }
    duint addr = 0;
    if(!evalExpr(res, text, "addr", addr))
        return;
    s.execLine(req, res, "run " + hexArg((long long)addr));
}

void viewAttach(Session & s, Request & req, Result & res)
{
    long long pid = 0;
    if(!argInt(req.args, "pid", pid) || pid < 1 || pid > 0xffffffffLL)
    {
        res.fail("E_BAD_ARG", "attach requires pid (a decimal process id)");
        return;
    }
    if(!s.execLine(req, res, buildAttachLine(pid)))
        return;
    if(argBool(req.args, "pause", false))
        s.pauseIfRunning(req, res);
}

void viewDetach(Session & s, Request & req, Result & res)
{
    s.execLine(req, res, "detach");
}
}
