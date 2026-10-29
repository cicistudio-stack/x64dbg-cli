#pragma once

#include "../bridge/bridgemain.h"

#include <string>
#include <vector>

#include "json.h"
#include "protocol.h"
#include "session.h"

namespace cli
{
// The structured view ops of design 9.3 and 9.4 (milestone M2). Every function runs on the Executor thread; the
// precondition (any, debugging, paused) has been checked by Session before the call.
typedef void (*ViewFn)(Session &, Request &, Result &);

struct ViewEntry
{
    const char* name;
    ViewFn fn;
    bool wrapper; // run-control wrapper: runs native lines with waiting, so the stuck clock is managed per core call
};

const ViewEntry* findView(const std::string & name);

void viewProcess(Session &, Request &, Result &);
void viewRegs(Session &, Request &, Result &);
void viewSetReg(Session &, Request &, Result &);
void viewDis(Session &, Request &, Result &);
void viewMem(Session &, Request &, Result &);
void viewMemWrite(Session &, Request &, Result &);
void viewMemMap(Session &, Request &, Result &);
void viewStack(Session &, Request &, Result &);
void viewCallStack(Session &, Request &, Result &);
void viewBps(Session &, Request &, Result &);
void viewBp(Session &, Request &, Result &);
void viewThreads(Session &, Request &, Result &);
void viewThread(Session &, Request &, Result &);
void viewModules(Session &, Request &, Result &);
void viewSym(Session &, Request &, Result &);
void viewInit(Session &, Request &, Result &);
void viewRun(Session &, Request &, Result &);
void viewStepIn(Session &, Request &, Result &);
void viewStepOver(Session &, Request &, Result &);
void viewStepOut(Session &, Request &, Result &);
void viewRunTo(Session &, Request &, Result &);
void viewRestart(Session &, Request &, Result &);
void viewAttach(Session &, Request &, Result &);
void viewDetach(Session &, Request &, Result &);
void viewSkip(Session &, Request &, Result &);

// ---- M3: remaining GUI-parity views
// views_os.cpp
void viewSeh(Session &, Request &, Result &);
void viewHandles(Session &, Request &, Result &);
void viewWindows(Session &, Request &, Result &);
void viewTcp(Session &, Request &, Result &);
void viewHeaps(Session &, Request &, Result &);
void viewPrivileges(Session &, Request &, Result &);
void viewPs(Session &, Request &, Result &);
// views_db.cpp
void viewLabels(Session &, Request &, Result &);
void viewComments(Session &, Request &, Result &);
void viewBookmarks(Session &, Request &, Result &);
void viewFunctions(Session &, Request &, Result &);
void viewArguments(Session &, Request &, Result &);
void viewLoops(Session &, Request &, Result &);
void viewAddrInfo(Session &, Request &, Result &);
void viewXrefs(Session &, Request &, Result &);
void viewPatches(Session &, Request &, Result &);
void viewPatch(Session &, Request &, Result &);
void viewStrings(Session &, Request &, Result &);
void viewCalls(Session &, Request &, Result &);
void viewPtrs(Session &, Request &, Result &);
void viewWatch(Session &, Request &, Result &);
// views_misc.cpp
void viewTrace(Session &, Request &, Result &);
void viewScript(Session &, Request &, Result &);
void viewTypes(Session &, Request &, Result &);
void viewStruct(Session &, Request &, Result &);
void viewCfg(Session &, Request &, Result &);
void viewNotes(Session &, Request &, Result &);
void viewSource(Session &, Request &, Result &);
void viewNav(Session &, Request &, Result &);
// views_info.cpp
void viewCallArgs(Session &, Request &, Result &);
void viewLocals(Session &, Request &, Result &);
void viewInfoBox(Session &, Request &, Result &);
void viewMenu(Session &, Request &, Result &);
void viewConfig(Session &, Request &, Result &);
void viewConstants(Session &, Request &, Result &);
void viewErrors(Session &, Request &, Result &);
void viewExceptions(Session &, Request &, Result &);
void viewFormat(Session &, Request &, Result &);
void viewAsm(Session &, Request &, Result &);
void viewAnimate(Session &, Request &, Result &);
void viewFavourites(Session &, Request &, Result &);
void viewModule(Session &, Request &, Result &);

// Name helpers of the disassembly rows (views_disasm.cpp), shared with addrinfo / cfg.
const char* funcName(FUNCTYPE t);
const char* loopName(LOOPTYPE t);
const char* argTypeName(ARGTYPE t);
const char* encodingName(ENCODETYPE t);

// ---- helpers shared by the views (views.cpp)

// "0x" + lowercase hex padded to the given number of digits.
std::string hexN(unsigned long long v, int digits);
// Lowercase hex of n bytes, no separators.
std::string bytesToHex(const unsigned char* p, size_t n);
// Decodes pairs of hex digits (ASCII blanks allowed between pairs). False with err on odd length / bad digit / over maxBytes.
bool parseHexBytes(const std::string & text, std::vector<unsigned char> & out, std::string & err, size_t maxBytes);
Json strOrNull(const std::string & s);

// Reads args[key] as text. A JSON integer becomes "0x<hex>" (address-like keys) or its decimal text.
bool argText(const Json & args, const char* key, std::string & out, bool intAsHex);
bool argInt(const Json & args, const char* key, long long & out);
bool argBool(const Json & args, const char* key, bool def);

// Evaluates an expression with the core. Fails the result with E_BAD_ARG when the expression is not valid.
bool evalExpr(Result & res, const std::string & expr, const char* what, duint & out);
// True while the debuggee runs or a launch is pending (memory ops then report live:true).
bool isLive();

// Shortest decimal text that reads back as the same value ("nan", "inf", "-inf").
std::string shortestDouble(double v);
std::string shortestFloat(float v);
double halfToDouble(unsigned short h);
// x87 80-bit extended value (10 bytes, little endian) as a double (precision beyond 53 bits is lost).
double extendedToDouble(const unsigned char* p10);

std::string labelAt(duint addr);
std::string moduleAt(duint addr);
// Id of the thread whose registers the views show (the one switchthread selected). DbgGetThreadId() is only the debug-event thread.
unsigned long long activeThreadId();

// Moves the reference tables that the native command(s) of this request produced out of the response `tables` into the
// result of an op (the finalisation step then adds nothing for them). Returns the newest table or an empty one.
Json takeLastTable(Request & req);

// limit / offset arguments of the list ops: defaults 5000 / 0, limit in 1..1000000.
bool listWindow(Request & req, Result & res, long long & limit, long long & offset);

// Frees a Bridge-allocated buffer exactly once.
template<class T>
struct BridgeBuf
{
    T* p = nullptr;
    BridgeBuf() {}
    BridgeBuf(const BridgeBuf &) = delete;
    BridgeBuf & operator=(const BridgeBuf &) = delete;
    ~BridgeBuf()
    {
        if(p)
            BridgeFree(p);
    }
};

// ---- native line builders (views_run.cpp, views_threads.cpp); pure functions, covered by --selftest.
// Rule N (design 9.1): every number spliced into a native line is hexadecimal, except the pid of attach.
std::string buildStepLine(const char* command, bool hasCount, long long count);   // "sti 0xa"
std::string buildAttachLine(long long pid);                                      // "attach .1234"
std::string buildInitLine(const std::string & file, const std::string & args, const std::string & cwd);
bool buildThreadLine(const std::string & action, bool hasTid, long long tid, bool hasValue, const std::string & value,
                     std::string & line, std::string & error);
}
