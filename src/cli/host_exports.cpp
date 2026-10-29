#include "../bridge/bridgemain.h"
#include "../bridge/bridgegraph.h"

#include "app.h"
#include "disasm_row.h"
#include "host.h"
#include "io.h"
#include "util.h"

#include "../headless/tostring.h"

#include <cstdio>
#include <cstring>

using namespace cli;

static const char* kBarrierPrefix = "@@x64dbg-cli-barrier:";

static char* bridgeString(const std::string & s)
{
    char* r = (char*)BridgeAlloc(s.size() + 1);
    memcpy(r, s.c_str(), s.size() + 1);
    return r;
}

static std::string str(void* p)
{
    return p ? std::string((const char*)p) : std::string();
}

static MenuItem* findMenu(Host & h, int handle)
{
    for(auto & m : h.menus)
        if(m.handle == handle)
            return &m;
    return nullptr;
}

static void removeMenuTree(Host & h, int handle)
{
    for(size_t i = 0; i < h.menus.size();)
    {
        if(h.menus[i].handle == handle)
        {
            h.menus.erase(h.menus.begin() + i);
            continue;
        }
        i++;
    }
    std::vector<int> children;
    for(auto & m : h.menus)
        if(m.parent == handle)
            children.push_back(m.handle);
    for(int c : children)
        removeMenuTree(h, c);
}

static int askMsgyn(Host & h, const std::string & text)
{
    int answer;
    if(startsWith(text, "Drivers known to interfere with x64dbg's operation"))
        answer = h.anticheatYes ? 1 : 0;
    else if(startsWith(text, "The script has been running for a while. Would you like to terminate it now?"))
        answer = 0;
    else
        answer = h.msgynYes ? 1 : 0;
    Json f = Json::object();
    f.set("kind", "msgyn");
    f.set("text", text);
    f.set("answer", answer);
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.promptsSeen.push_back(text);
    }
    h.pushEvent("prompt", f);
    return answer;
}

extern "C" __declspec(dllexport) int _gui_guiinit(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    return cli::guiMain();
}

extern "C" __declspec(dllexport) const char* _gui_translate_text(const char* source)
{
    return source;
}

extern "C" __declspec(dllexport) void* _gui_sendmessage(GUIMSG type, void* param1, void* param2)
{
    Host & h = host();
    if(h.dbgStopped.load())
        return nullptr;

    switch(type)
    {
    // ---- log
    case GUI_ADD_MSG_TO_LOG:
        if(param1)
            h.onLogChunk(0, (const char*)param1);
        break;
    case GUI_ADD_MSG_TO_LOG_HTML:
        if(param1)
            h.onLogChunk(1, (const char*)param1);
        break;
    case GUI_CLEAR_LOG:
    case GUI_FLUSH_LOG:
        break;
    case GUI_SET_LOG_ENABLED:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.logEnabled = (param1 != nullptr);
    }
    break;
    case GUI_IS_LOG_ENABLED:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        return (void*)(duint)h.logEnabled;
    }
    case GUI_SAVE_LOG:
    {
        if(!param1)
            break;
        LogSlice s = h.slice(0, ~0ull);
        FILE* f = nullptr;
        if(_wfopen_s(&f, wideOf((const char*)param1).c_str(), L"wb") == 0 && f)
        {
            fwrite(s.text.data(), 1, s.text.size(), f);
            fclose(f);
        }
    }
    break;
    case GUI_REDIRECT_LOG:
        h.setMirror(str(param1));
        break;
    case GUI_STOP_REDIRECT_LOG:
        h.stopMirror();
        break;
    case GUI_ADD_MSG_TO_STATUSBAR:
        if(param1)
            h.appendLogLine("[STATUS] " + trim(str(param1)));
        break;
    case GUI_ADD_INFO_LINE:
        if(param1)
            h.appendLogLine("[INFO] " + trim(str(param1)));
        break;
    case GUI_DISPLAY_WARNING:
        h.appendLogLine("[WARNING] " + str(param1) + (param2 ? ": " + str(param2) : std::string()));
        break;
    case GUI_SYMBOL_LOG_ADD:
        if(param1)
            h.onLogChunk(0, "[SYMBOL] " + str(param1));
        break;
    case GUI_SYMBOL_LOG_CLEAR:
    case GUI_SYMBOL_SET_PROGRESS:
    case GUI_SYMBOL_REFRESH_CURRENT:
    case GUI_INVALIDATE_SYMBOL_SOURCE:
        break;

    // ---- state
    case GUI_SET_DEBUG_STATE:
        h.onDebugState((int)(duint)param1, param2 != nullptr);
        break;
    case GUI_UPDATE_WINDOW_TITLE:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.windowTitle = str(param1);
    }
    break;
    case GUI_ADD_RECENT_FILE:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.recentFiles.push_back(str(param1));
    }
    break;
    case GUI_SET_LAST_EXCEPTION:
    {
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.lastException.valid = true;
            h.lastException.code = (unsigned)(duint)param1;
            h.lastException.stamp = ++h.nextSeq;
        }
        h.notifyAll();
    }
    break;
    case GUI_GET_WINDOW_HANDLE:
        return h.foreground ? (void*)GetConsoleWindow() : nullptr;
    case GUI_GET_MAIN_THREAD_ID:
        return (void*)(duint)h.mainThreadId;
    case GUI_CLOSE_APPLICATION:
        cli::requestShutdown("core");
        break;
    case GUI_UPDATE_TIME_WASTED_COUNTER:
    case GUI_PROCESS_EVENTS:
        break;
    case GUI_EXECUTE_ON_GUI_THREAD:
    {
        GUICALLBACKEX cb = (GUICALLBACKEX)param1;
        void* ud = param2;
        if(GetCurrentThreadId() == h.mainThreadId)
            cb(ud);
        else
            h.postJob([cb, ud]()
        {
            cb(ud);
            return true;
        });
    }
    break;

    // ---- views refresh: the CLI pulls fresh data on request
    case GUI_UPDATE_REGISTER_VIEW:
    case GUI_UPDATE_DISASSEMBLY_VIEW:
    case GUI_UPDATE_BREAKPOINTS_VIEW:
    case GUI_UPDATE_DUMP_VIEW:
    case GUI_UPDATE_THREAD_VIEW:
    case GUI_UPDATE_SIDEBAR:
    case GUI_REPAINT_TABLE_VIEW:
    case GUI_UPDATE_PATCHES:
    case GUI_UPDATE_CALLSTACK:
    case GUI_UPDATE_SEHCHAIN:
    case GUI_UPDATE_MEMORY_VIEW:
    case GUI_UPDATE_ARGUMENT_VIEW:
    case GUI_UPDATE_WATCH_VIEW:
    case GUI_UPDATE_GRAPH_VIEW:
    case GUI_UPDATE_TRACE_BROWSER:
    case GUI_UPDATE_TYPE_WIDGET:
    case GUI_TYPE_LIST_UPDATED:
        break;

    // ---- navigation / selection
    case GUI_DISASSEMBLE_AT:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.nav.disasm = (duint)param1;
        h.nav.cip = (duint)param2;
    }
    break;
    case GUI_DUMP_AT:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.nav.dump = (duint)param1;
    }
    break;
    case GUI_DUMP_AT_N:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.dumpTabs[(int)(duint)param1] = (duint)param2;
    }
    break;
    case GUI_STACK_DUMP_AT:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.nav.stack = (duint)param1;
        h.nav.csp = (duint)param2;
    }
    break;
    case GUI_GRAPH_AT:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.nav.graph = (duint)param1;
    }
    return nullptr;
    case GUI_SELECT_IN_MEMORY_MAP:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.nav.memmap = (duint)param1;
    }
    break;
    case GUI_SELECT_IN_SYMBOLS_TAB:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.nav.symmod = (duint)param1;
    }
    break;
    case GUI_FOCUS_VIEW:
    case GUI_FOLD_DISASSEMBLY:
    case GUI_GOTO_TRACE:
    case GUI_SHOW_CPU:
    case GUI_SHOW_THREADS:
    case GUI_SHOW_REF:
    case GUI_SHOW_TRACE:
    case GUI_SHOW_STRUCT:
        break;
    case GUI_SELECTION_GET:
    case GUI_SELECTION_SET:
    {
        if(!DbgIsDebugging())
            return (void*)false;
        int w = (int)(duint)param1;
        SELECTIONDATA* sel = (SELECTIONDATA*)param2;
        if(!sel)
            return (void*)false;
        std::lock_guard<std::mutex> lk(h.mu);
        duint* slot = nullptr;
        switch(w)
        {
        case GUI_DISASSEMBLY:
            slot = &h.nav.disasm;
            break;
        case GUI_DUMP:
            slot = &h.nav.dump;
            break;
        case GUI_STACK:
            slot = &h.nav.stack;
            break;
        case GUI_GRAPH:
            slot = &h.nav.graph;
            break;
        case GUI_MEMMAP:
            slot = &h.nav.memmap;
            break;
        case GUI_SYMMOD:
            slot = &h.nav.symmod;
            break;
        case GUI_THREADS:
            slot = &h.nav.threads;
            break;
        default:
            return (void*)false;
        }
        if(type == GUI_SELECTION_GET)
            sel->start = sel->end = *slot;
        else
            *slot = sel->start;
        return (void*)true;
    }
    case GUI_GET_ACTIVE_VIEW:
    {
        ACTIVEVIEW* av = (ACTIVEVIEW*)param1;
        if(av)
        {
            memset(av, 0, sizeof(*av));
            strcpy_s(av->title, "CPU");
            strcpy_s(av->className, "x64dbg-cli");
        }
    }
    break;

    // ---- reference tables
    case GUI_REF_INITIALIZE:
        h.refInitialize(str(param1));
        break;
    case GUI_REF_DELETEALLCOLUMNS:
        h.refInitialize("References");
        break;
    case GUI_REF_ADDCOLUMN:
        h.refAddColumn(str(param2));
        break;
    case GUI_REF_SETROWCOUNT:
        h.refSetRowCount((int)(duint)param1);
        break;
    case GUI_REF_SETCELLCONTENT:
    {
        CELLINFO* ci = (CELLINFO*)param1;
        if(ci)
            h.refSetCell(ci->row, ci->col, ci->str ? ci->str : "");
    }
    break;
    case GUI_REF_ADDCOMMAND:
        h.refAddCommand(str(param1), str(param2));
        break;
    case GUI_REF_GETROWCOUNT:
    case GUI_REF_SEARCH_GETROWCOUNT:
        return (void*)(duint)h.refRowCount();
    case GUI_REF_GETCELLCONTENT:
    case GUI_REF_SEARCH_GETCELLCONTENT:
        return bridgeString(h.refGetCell((int)(duint)param1, (int)(duint)param2));
    case GUI_REF_RELOADDATA:
    case GUI_REF_SETSINGLESELECTION:
    case GUI_REF_SETCURRENTTASKPROGRESS:
    case GUI_REF_SETSEARCHSTARTCOL:
        break;
    case GUI_REF_SETPROGRESS:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.refProgress = (int)(duint)param1;
    }
    break;

    // ---- disassembly text for reference tables
    case GUI_GET_DISASSEMBLY:
        return disasmText((duint)param1, (char*)param2, GUI_MAX_DISASSEMBLY_SIZE) ? (void*)1 : nullptr;

    // ---- modules
    case GUI_SYMBOL_UPDATE_MODULE_LIST:
    {
        int count = (int)(duint)param1;
        SYMBOLMODULEINFO* mods = (SYMBOLMODULEINFO*)param2;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.modules.clear();
            for(int i = 0; mods && i < count; i++)
                h.modules.emplace_back(mods[i].base, mods[i].name);
        }
        if(mods)
            BridgeFree(mods);
    }
    break;

    // ---- scripts
    case GUI_SCRIPT_ADD:
    {
        int count = (int)(duint)param1;
        const char** lines = (const char**)param2;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            for(int i = 0; lines && i < count; i++)
                h.scriptLines.push_back(lines[i] ? lines[i] : "");
        }
        if(lines)
            BridgeFree(lines);
    }
    break;
    case GUI_SCRIPT_CLEAR:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.scriptLines.clear();
        h.scriptInfo.clear();
    }
    break;
    case GUI_SCRIPT_SETIP:
    {
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.scriptIp = (int)(duint)param1;
            h.scriptIpSeq++;
        }
        h.notifyAll();
    }
    break;
    case GUI_SCRIPT_SETTITLE:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.scriptTitle = str(param1);
    }
    break;
    case GUI_SCRIPT_SETINFOLINE:
    {
        std::string t = str(param2);
        if(t.compare(0, strlen(kBarrierPrefix), kBarrierPrefix) == 0)
            break;
        std::lock_guard<std::mutex> lk(h.mu);
        h.scriptInfo[(int)(duint)param1] = t;
    }
    break;
    case GUI_SCRIPT_ENABLEHIGHLIGHTING:
        break;
    case GUI_SCRIPT_ERROR:
    {
        std::string text = str(param2);
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.scriptErrors.push_back("line " + std::to_string((int)(duint)param1) + ": " + text);
        }
        h.appendLogLine("[SCRIPT ERROR line " + std::to_string((int)(duint)param1) + "] " + text);
    }
    break;
    case GUI_SCRIPT_MESSAGE:
    {
        std::string text = str(param1);
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.scriptMessages.push_back(text);
        }
        h.appendLogLine("[MSG] " + text);
    }
    break;
    case GUI_SCRIPT_MSGYN:
        return (void*)(duint)askMsgyn(h, str(param1));
    case GUI_GETLINE_WINDOW:
    {
        Json f = Json::object();
        f.set("kind", "getline");
        f.set("text", str(param1));
        f.set("answer", nullptr);
        h.pushEvent("prompt", f);
    }
    return (void*)false;
    case GUI_REGISTER_SCRIPT_LANG:
    {
        SCRIPTTYPEINFO* info = (SCRIPTTYPEINFO*)param1;
        if(info)
        {
            std::lock_guard<std::mutex> lk(h.mu);
            info->id = (int)h.scriptLangs.size();
            h.scriptLangs.push_back({ info->id, info->name, info->execute });
        }
    }
    break;
    case GUI_UNREGISTER_SCRIPT_LANG:
    {
        int id = (int)(duint)param1;
        if(id != 0)
        {
            std::lock_guard<std::mutex> lk(h.mu);
            for(size_t i = 0; i < h.scriptLangs.size(); i++)
            {
                if(h.scriptLangs[i].id == id)
                {
                    h.scriptLangs[i].execute = nullptr;
                    h.scriptLangs[i].name = "<unregistered>";
                    break;
                }
            }
        }
    }
    break;

    // ---- notes
    case GUI_SET_GLOBAL_NOTES:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.globalNotes = str(param1);
    }
    break;
    case GUI_SET_DEBUGGEE_NOTES:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.debuggeeNotes = str(param1);
    }
    break;
    case GUI_GET_GLOBAL_NOTES:
    case GUI_GET_DEBUGGEE_NOTES:
    {
        std::string notes;
        {
            std::lock_guard<std::mutex> lk(h.mu);
            notes = type == GUI_GET_GLOBAL_NOTES ? h.globalNotes : h.debuggeeNotes;
        }
        if(param1)
            *(char**)param1 = notes.empty() ? nullptr : bridgeString(notes);
    }
    break;

    // ---- menus and plugins
    case GUI_MENU_ADD:
    case GUI_MENU_ADD_ENTRY:
    case GUI_MENU_ADD_SEPARATOR:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        MenuItem m;
        m.handle = ++h.menuCounter;
        m.parent = (int)(duint)param1;
        m.isEntry = type != GUI_MENU_ADD;
        m.separator = type == GUI_MENU_ADD_SEPARATOR;
        if(!m.separator)
            m.title = str(param2);
        h.menus.push_back(m);
        return (void*)(duint)m.handle;
    }
    case GUI_MENU_CLEAR:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        int parent = (int)(duint)param1;
        std::vector<int> children;
        for(auto & m : h.menus)
            if(m.parent == parent)
                children.push_back(m.handle);
        for(int c : children)
            removeMenuTree(h, c);
    }
    break;
    case GUI_MENU_REMOVE:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        removeMenuTree(h, (int)(duint)param1);
    }
    break;
    case GUI_MENU_SET_ICON:
    case GUI_MENU_SET_ENTRY_ICON:
        break;
    case GUI_MENU_SET_ENTRY_CHECKED:
    case GUI_MENU_SET_VISIBLE:
    case GUI_MENU_SET_ENTRY_VISIBLE:
    case GUI_MENU_SET_NAME:
    case GUI_MENU_SET_ENTRY_NAME:
    case GUI_MENU_SET_ENTRY_HOTKEY:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        MenuItem* m = findMenu(h, (int)(duint)param1);
        if(m)
        {
            if(type == GUI_MENU_SET_ENTRY_CHECKED)
                m->checked = param2 != nullptr;
            else if(type == GUI_MENU_SET_VISIBLE || type == GUI_MENU_SET_ENTRY_VISIBLE)
                m->visible = param2 != nullptr;
            else if(type == GUI_MENU_SET_ENTRY_HOTKEY)
                m->hotkey = str(param2);
            else
                m->title = str(param2);
        }
    }
    break;
    case GUI_AUTOCOMPLETE_ADDCMD:
        if(param1)
            h.autoCompleteAdd((const char*)param1);
        break;
    case GUI_AUTOCOMPLETE_DELCMD:
        if(param1)
            h.autoCompleteDel((const char*)param1);
        break;
    case GUI_AUTOCOMPLETE_CLEARALL:
        h.autoCompleteClear();
        break;
    case GUI_ADD_FAVOURITE_TOOL:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.favouriteTools.emplace_back(str(param1), str(param2));
    }
    break;
    case GUI_ADD_FAVOURITE_COMMAND:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.favouriteCommands.emplace_back(str(param1), str(param2));
    }
    break;
    case GUI_SET_FAVOURITE_TOOL_SHORTCUT:
        break;

    // ---- graph, types, source, trace
    case GUI_LOAD_GRAPH:
        if(param1)
            BridgeCFGraph::Free((const BridgeCFGraphList*)param1);
        return (void*)true;
    case GUI_GET_CURRENT_GRAPH:
        if(param1)
            memset(param1, 0, sizeof(BridgeCFGraphList));
        break;
    case GUI_TYPE_ADDNODE:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        return (void*)(duint)(++h.typeNodeCounter);
    }
    case GUI_TYPE_CLEAR:
    case GUI_TYPE_VISIT:
        break;
    case GUI_LOAD_SOURCE_FILE:
    {
        std::lock_guard<std::mutex> lk(h.mu);
        h.sourceFiles.emplace_back(str(param1), (duint)param2);
    }
    break;
    case GUI_OPEN_TRACE_FILE:
    {
        std::string path = str(param1);
        {
            std::lock_guard<std::mutex> lk(h.mu);
            h.traceFile = path;
        }
        Json f = Json::object();
        f.set("path", path);
        h.pushEvent("trace_file", f);
    }
    break;

    // ---- plugin widgets
    case GUI_ADD_QWIDGET_TAB:
    case GUI_SHOW_QWIDGET_TAB:
    case GUI_CLOSE_QWIDGET_TAB:
    {
        Json f = Json::object();
        f.set("message", "plugin widget not supported");
        h.pushEvent("plugin_widget", f);
    }
    break;
    case GUI_IS_DEBUGGER_FOCUSED_UNUSED:
        return (void*)false;

    default:
        if(h.verbose >= 2)
            io::diag(std::string("unhandled GUI message ") + guimsg2str(type));
        break;
    }
    return nullptr;
}
