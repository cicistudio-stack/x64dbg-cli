# x64dbg-cli

> 给 AI 工具用：可直接粘贴的系统提示词见 [ai-system-prompt.md](ai-system-prompt.md)。
> For AI tools: a ready-to-paste system prompt is in [ai-system-prompt.md](ai-system-prompt.md).

`x64dbg-cli.exe` turns the x64dbg debugger into a command line tool for AI tools and scripts. It has no Qt or GUI dependency.
It loads `x64bridge.dll` / `x64dbg.dll`, plays the role of the GUI (it receives every `GUI_*` message from the core), and offers

1. the whole native x64dbg command language over stdin/stdout (breakpoints, run control, memory, searches, scripts, ...), with the
   output of each command captured and returned with the response, and with waiting for commands that resume the debuggee;
2. 80 structured **ops** that return the data of every GUI pane as JSON (registers, live disassembly, memory, stack, call stack,
   breakpoints, threads, modules, symbols, handles, windows, TCP connections, SEH chain, labels, comments, bookmarks, functions,
   xrefs, patches, string/call/pointer searches, watch, trace coverage, scripts, types, control flow graphs, notes, source lines, ...);
3. a JSON-lines protocol (`--json`) and a plain text mode, both with an end-of-response marker, typed events and bounded waits.

The goal of the project is: everything the GUI can show, the CLI shows through commands. [parity-matrix.md](parity-matrix.md)
lists every GUI action, pane and context-menu entry with the command that replaces it, and the few explicit gaps with reasons.

| Document | Content |
|---|---|
| this file | usage, protocol, command overview, parity summary, AI integration, real transcripts |
| [command-reference.md](command-reference.md) | every op: usage, precondition, schema of `args` and `data` (generated from the binary) |
| [native-commands.md](native-commands.md) | the 348 native commands with aliases and summaries (generated) |
| [parity-matrix.md](parity-matrix.md), [parity-matrix.csv](parity-matrix.csv) | GUI-to-CLI parity matrix with gaps and reasons (generated and checked) |
| [agent-guide.md](agent-guide.md) | short guide for agents and for wrapping the CLI as MCP tools |
| [examples/client.py](examples/client.py) | a complete Python client and demo session |

## Build

64-bit, from the repository root (this is what produced the transcripts below):

```
.agents\tasks\build-x64.bat        (vcvars64, cmake -B build64 -G Ninja -DCMAKE_BUILD_TYPE=Release ..., cmake --build build64)
```

The output is `bin\x64\x64dbg-cli.exe` next to `x64dbg.exe`; it needs the DLLs of that folder (`x64bridge.dll`, `x64dbg.dll`, ...).
Self test without a core: `x64dbg-cli.exe --selftest`.

## Usage

```
x64dbg-cli.exe [options] [--] [target.exe [target args...]]
```

| Option | Meaning |
|---|---|
| `--json` | JSON-lines protocol (default: text REPL) |
| `--exec "a; b"` | run commands, then exit (repeatable) |
| `--script file` | run a file with one command per line, then exit |
| `--interactive` | stay in the session after `--exec` / `--script` / target / `--attach` |
| `--attach pid` | `attach .<pid>` (decimal pid) |
| `--timeout ms` | default wait timeout (30000) |
| `--userdir X:\dir` | settings/database directory (default `<exe dir>\x64dbg-cli`); one process per directory |
| `--keep-going` | one-shot: continue after a failing command |
| `--msgyn yes\|no`, `--anticheat yes\|no` | answers for prompts that have no human (default no) |
| `--eof-wait ms`, `--stuck-ms ms`, `--max-output bytes`, `--log-file path`, `--detach-on-exit`, `--foreground`, `-v`, `-vv` | see `--help` |

Exit codes: `0` ok, `1` a command failed, `2` usage error, `3` core initialisation failed, `4` a wait timed out
(one-shot), `70` fatal (crash, shutdown hang, lost output).

One-shot mode (any of target, `--attach`, `--exec`, `--script` without `--interactive`) never reads stdin.
A session (no startup item, or `--interactive`) reads one request per line from stdin until EOF or `quit`.
At EOF queued requests are still answered and waits end at most `--eof-wait` ms later with `wait.reason: "shutdown"`.

Fresh installs of x64dbg stop twice before the first line of user code: at the system breakpoint and at the entry
breakpoint (and again for TLS callbacks). A client that wants to reach a breakpoint of its own simply repeats `run` until
`state.stop.bp` is its breakpoint (`examples/client.py` does that), or turns the extra stops off in the settings
(`config set Events EntryBreakpoint 0`, `config set Events TlsCallbacks 0`).

## Text mode

* First line `@@READY x64dbg-cli 1 x64`.
* A line starting with `!` names an op (`!eval 1+1`, `!log --tail 20`); `!!x` sends the native line `!x`.
  Every other line is a native x64dbg command line (`bp kernel32.Sleep`, `run`, `findall rip,90`). `#` starts a comment line.
* Each response is a body followed by one terminator line:
  `@@END <id> ok|fail state=<none|starting|running|paused|stopped> cip=<0x...|-> seq=<n> [wait=<reason>] [code=<E_...>]`.
  Failures put `error: <CODE>: <message>` before it. Events delivered with a response (and unsolicited events while idle)
  are `@@EVENT <seq> <type> <json>` lines. Body lines that start with `@@` get one leading space; control bytes
  are shown as `\xNN`.
* Request options for one native line: `!native --timeout_ms 5000 --on_timeout pause -- run`.

Text rendering of an op result (`data`): an object prints `key: value` lines in schema order (`-` for null); a nested object prints
`key:` and indents its lines by two spaces; an array of scalars is one line; an array of objects is a tab separated header line plus
one line per element; a captured table (labels, strings, ...) prints like the `tables` of a response (`table <id> "<name>" rows n/m`,
a tab separated header and the rows). `\t`, `\n`, `\r` are escaped and other control bytes are `\xNN`. `dis` has its own layout:
`=>` marks `cip`, `*` a breakpoint, `;` the comment or the label of the branch target.

## JSON-lines protocol (version 1)

One UTF-8 JSON object per line in both directions, no ESC bytes, no other output on stdout (the CLI isolates the process stdout from
stray prints). Lines are limited to 1 MiB on input (`E_TOO_LONG`); a native line is limited to 1023 bytes.

**Hello.** The first line is written when the core is ready (within a few seconds):

```json
{"type":"hello","v":1,"tool":"x64dbg-cli","version":"0.1.0","arch":"x64","pid":9448,"userdir":"...","capabilities":{"events":"full","engine":"titan","ops":["status","help",...],"native_commands":348,"oob":["pause","stop","status","interrupt","quit"]}}
```

**Request.** Exactly one of `cmd` (a native line, always native), `op` (+ optional `args` object), `batch` (an array of requests).
`id` (integer or string) is echoed back. Options are top-level fields only, never keys of `args`:

| Option | Values | Meaning |
|---|---|---|
| `timeout_ms` | int, 0 = do not wait | wait limit of this request (default `--timeout`) |
| `wait` | `auto` (default) `never` `always` | wait for resuming commands (`auto`), never, or also for commands that do not resume |
| `on_timeout` | `keep` (default) `pause` `stop` | what to do with the debuggee when the wait times out |
| `max_output`, `max_response_bytes`, `max_rows`, `max_events` | int | caps for output text, the whole response, table rows, events per response |
| `settle_ms`, `pause_settle_ms` | int | launch / pause settling time |
| `vars` | `["$result", "$a"]` | read script variables after the command (`vars` in the response) |
| `stop_on_error` | bool | batch: stop after the first failing element |

```json
{"id":7,"cmd":"run","timeout_ms":10000,"on_timeout":"keep"}
{"id":8,"op":"eval","args":{"expr":"rsp"}}
{"id":9,"batch":[{"cmd":"bp kernel32.CreateFileW"},{"cmd":"run"},{"op":"regs","args":{"groups":"gpr"}}],"stop_on_error":true}
```

**Response.** One line per request, same `id`:

```json
{"type":"response","v":1,"id":7,"cmd":"run","ok":true,"error":null,"output":"INT3 breakpoint at ...",
 "data":null,"tables":[],"vars":{},
 "state":{"status":"paused","debugging":true,"pid":4242,"tid":5120,"cip":"0x00007ffb12345678","cip_label":"CreateFileW",
          "module":"kernel32.dll","seq":14,"exit_code":null,"stop":{"reason":"breakpoint","bp":"0x00007ffb12345678"}},
 "wait":{"waited":true,"reason":"paused","timed_out":false,"elapsed_ms":210},
 "events":[{"seq":33,"type":"breakpoint_hit","bp_type":"normal","addr":"0x00007ffb12345678","name":"","hit_count":1,"module":"kernel32.dll"}],
 "warnings":[],"truncated":false,"meta":{"elapsed_ms":212,"log_end":18344}}
```

* `ok`/`error`: `error` is `{code, message, detail}`. Codes: `E_PARSE E_UNKNOWN_OP E_BAD_ARG E_TOO_LONG E_NOT_DEBUGGING E_RUNNING
  E_COMMAND_FAILED E_MEMORY E_TIMEOUT E_BUSY E_UNSUPPORTED E_SHUTDOWN E_INTERNAL`.
* `output`: the log text of exactly this command (the CLI uses a completion barrier, so a late log line never leaks into the next response).
* `data`: the result of an op (schema per op in [command-reference.md](command-reference.md)); `null` for native lines.
* `tables`: reference-view tables the command produced (`findall`, `reffind`, `strref`, `labellist`, ...): `{id, name, columns, rows, total_rows,
  truncated, actions}`. Re-read or page one with `{"op":"table","args":{"id":3,"offset":100,"limit":100}}`.
* `state`: `status` (`none|starting|running|paused|stopped`), process ids, `cip`, `cip_label`, `module`, `seq` (state counter),
  `exit_code`, and `stop` (why the debuggee paused: `breakpoint exception system_breakpoint step run_to_user trace_end dll_load dll_unload
  thread_start thread_end debug_string loadlib freelib pause unknown`, plus `bp` and `exception{code,address}` where they apply).
* `wait`: `waited`, `reason` (`paused stopped running timeout interrupted shutdown not_resumed already_running not_running none`), `timed_out`, `elapsed_ms`.
* `events`: typed events since the previous response (each event is delivered exactly once, in a response or as an unsolicited `event` line):
  `session_started process_created process_exited session_stopped system_breakpoint stepped pause_requested thread_created thread_exited
  module_loaded module_unloaded breakpoint_hit exception debug_string paused resumed attached detached prompt dialog_dismissed warning
  log_overflow late_result trace_file table_updated events_dropped`.
* `results`: for `batch`, the element responses (without `type` and `v`).

**Unsolicited lines.** While no request is active the CLI writes `{"type":"event","v":1,"event":{...}}` for events; on a fatal internal
error one `{"type":"fatal","v":1,"code":...,"message":...}` line and exit code 70.

**Out of band.** `status`, `pause`, `stop`, `interrupt`, `quit` are answered immediately by a control thread, also while another
request waits (`run` pending, then `{"op":"pause"}`: both are answered). `{"op":"interrupt"}` ends the wait of the running request without
touching the debuggee.

### Run control and waiting

Commands that resume the debuggee (`run`, `sti`, `sto`, `rtr`, `rtu`, trace commands, `init`, `attach`, `loadlib`, ...) block until the
debuggee pauses or stops, `timeout_ms` expires (the debuggee keeps running, `wait.timed_out: true`), the wait is
interrupted (`{"op":"interrupt"}`) or stdin ends. `state.stop.reason` tells why the debuggee paused. Step commands and `skip` are
refused with `E_RUNNING` while the debuggee runs (the core would arm stepping state); use `pause` first. A launch whose
wait ended early (`timeout_ms: 1`) is continued with `{"op":"wait"}`. A debuggee that exits ends the wait with `state.status: "stopped"`
and `state.exit_code`.

## Commands

Three layers, all through the same request format:

* **Native commands** (`cmd`): every command of the x64dbg command bar. [native-commands.md](native-commands.md) lists all 348 with aliases and summaries.
* **Ops**: structured, typed results; the 80 ops are listed below and documented in [command-reference.md](command-reference.md).
  Text form `!name args`: the first positional token is the main argument, `-n N` stands for `count` (`dis`, `stack`) or `size` (`mem`), other keys are
  `--key value`; a boolean flag takes an optional `true|false`. Address-like arguments are x64dbg expressions (`rip`, `rsp+8`,
  `kernel32.CreateFileW`, `0x401000`, `[rsp]`); a bare number is hexadecimal. Numbers handed to the core are always sent in hex
  (`stepin count:10` runs `sti 0xa`; `sti 10` would step 16 times).
* **Pane tables** captured from the GUI reference-view messages: any native that fills the References pane (`findall`, `findallmem`, `findasm`,
  `reffind`, `reffindrange`, `strref`, `modcallfind`, `reffunctionpointer`, `labellist`, `functionlist`, `varlist`, ...) returns its table in `tables`.

Preconditions: `any` (no session needed), `debugging` (a session exists), `paused` (registers needed). A violation answers `E_NOT_DEBUGGING`
or `E_RUNNING`. While a launch is pending (`state.status: "starting"`) `paused` ops answer `E_RUNNING` with the message `session is
starting; use wait`. Memory ops (`mem`, `dis <addr>`, `stack --addr`, `sym`, `modules`, `trace` with an address, ...) also work while the debuggee runs.

| Group | Ops |
|---|---|
| Session and utility | `status` `help` `commands` `wait` `interrupt` `quit` `log` `events` `eval` `table` `native` |
| Run control | `init` `run` `stepin` `stepover` `stepout` `runto` `pause` `stop` `restart` `attach` `detach` `skip` |
| CPU and memory | `process` `regs` `setreg` `dis` `mem` `memwrite` `memmap` `stack` `callstack` `callargs` `locals` `infobox` `cfg` |
| Breakpoints, threads, modules | `bps` `bp` `threads` `thread` `modules` `module` `sym` |
| Operating system | `seh` `handles` `windows` `tcp` `heaps` `privileges` `ps` |
| Database and analysis | `labels` `comments` `bookmarks` `functions` `arguments` `loops` `addrinfo` `xrefs` `patches` `patch` `strings` `calls` `ptrs` `watch` |
| Trace, scripts, types, source | `trace` `script` `types` `struct` `source` `notes` `nav` |
| Settings and helpers | `config` `constants` `errors` `exceptions` `format` `asm` `animate` `favourites` `menu` |

### Notes on individual ops

* `bp add` builds the native commands (`bp`, `bph`, `bpm`, `bpdll`, `SetExceptionBPX`, then the `SetBreakpoint*` setters):
  `{"op":"bp","args":{"action":"add","kind":"hw","target":"rsp","hw_type":"w","size":4,"condition":"rax==1","log":"hit {rip}"}}`.
  `delete`, `enable`, `disable`, `reset_hits` take an `id` from `bps` (or `kind` + `target`, or `all`). Memory breakpoints cover a whole region.
* Table ops (`labels comments bookmarks functions arguments loops strings calls ptrs`) return the captured table as `data.table`
  (columns as the core prints them). Mutations are native: `lbl`, `cmt`, `bookmark`, `functionadd`, `argumentadd`, `loopadd`, `lbldel`, ...
  `strings`/`calls`/`ptrs` search the region of `addr` (default: the region containing `cip`).
* `xrefs` reads the database. Fill it first with the native `analxrefs` (or `analyse`) while the module is current: `disasm <addr>` then `analxrefs`.
* `addrinfo` gathers label, comment, bookmark, module, function range, loop / argument type, breakpoint kind, colour and data encoding of one address.
* `patches` / `patch`: `memwrite` and `asm` record patches; `patch export --file out.exe` writes the patched copy of the module (one module per
  file, `--module` picks it), `restore --addr`, `restore_range --addr --end`.
* `trace`: `info` (record type of the region, hit count and byte type of an address), `set_type bit|byte|word` (all pages of the memory region, then
  `traceexecute cip`, exactly the GUI's coverage actions), `reset`, `disable`, `start --file` / `stop` (run trace recording). The core refuses to change
  a record type on pages that already have one (`E_INTERNAL` naming the page): `disable` first.
* `script` actions: `load unload run step abort state lines bp_toggle bp_get set_ip exec cmd`. `run` blocks until the script ends or hits a script
  breakpoint and returns `data.finished` (true = ran to its end; also true after the script command `error`); script output and errors of
  `run`/`exec`/`cmd` are in `output`. `step` waits for the next script position (`wait.reason: "paused"`, `data.ip`). `run --line n` sets the script
  breakpoint on `n` first (it stays set, like the GUI's "Run until selection").
* `struct --type T --addr A` visits a type defined with `AddStruct`/`AddMember`/`ParseTypes`/`LoadTypes` and returns the member tree with values.
* `source` needs a PDB with line information (`--addr`, or `--file` + `--line`); the CLI reads the source file itself.
* `locals` / `callargs` / `infobox` reproduce the data of the GUI Locals, Arguments and Info box panes.
* `animate "StepInto;AnimateWait"` repeats a command every 50 ms until `pause` (the GUI animate actions).
* `config get|set --section S --key K [--value V]` reads and writes settings (`set` also applies them); `config init_script` is the system breakpoint script.
* `module` has the actions of the Symbols view: `set_party`, `loadlib`, `freelib`, `symdownload`, `symload`, `symunload`.
* `batch` runs 1..256 requests on one executor turn; options on the batch are the defaults of its elements. Nested batches, `interrupt` and `quit` are rejected.

## Parity with the GUI

[parity-matrix.md](parity-matrix.md) has one row per `<action>` of the `.ui` files (105), per GUI pane class (all classes of `Gui`, `Tracer`
and `BasicView`) and per context-menu entry, each with the command that replaces it. Summary of the 265 rows:
every action/pane is **Full** (an op returns the same data), **Native** (the native command produces it; output arrives in `output`/`tables`),
**Part** (same data, less presentation, reason given) or **UI** (colours, layout, clipboard, dialogs: no data). What is verified, by whom:

| Check | What it proves |
|---|---|
| `python src/cli/tests/gen_parity.py --check` | the matrix files are the generated ones; every `.ui` action id and every class of `Gui`, `Tracer`, `BasicView` has a row; every `!op` and every native command a row names exists in the binary; every op is called by an acceptance script; every native has a smoke line |
| `python src/cli/tests/check_matrix.py` | the same coverage plus rule N (the 29 `makeCommandAction(ui->actionX, "cmd")` statements of `MainWindow.cpp` are named by the `cli` cell of `actionX`, aliases resolved through the binary's `commands` op), rule M at class level (the scan of `src/gui/Src` finds 585 context-menu labels in 38 classes, every class has a `menu` row and the row's count equals the scan), every gap id documented here; `--negative` runs five broken copies that must fail |
| `python src/cli/tests/check_matrix.py --run` | executes the 109 distinct native targets of the matrix once each against a live debuggee (`src/cli/tests/native_smoke.csv`: `ok` = succeeded, `usage` = registered and reached, rejected the bare call, `skip` = not run, reason given; `symdownload` is the only skip) |

The **Built** and **Exercised** columns of the matrix state exactly this: `Built = yes` means the named ops and commands exist in the binary;
`Exercised` names the check that runs the row (`ops` = an acceptance script calls every named op, `smoke:ok|usage|skip` = the native's smoke line).
The menu rows are grouped per class (110 rows for 585 labels); the label-by-label expansion of the original design was not built (deviations item 49).

Explicit gaps (data the GUI shows that the CLI does not provide):

| Gap | What | Why |
|---|---|---|
| G2 | **Trace browser** (`.trace64` file reader panes: Trace, TraceDump, TraceStack, TraceRegisters, TraceInfoBox, TraceXref) | The reader is Qt code; scheduled as milestone M4, **not implemented**. Substitutes: run trace recording (`trace start/stop`), conditional trace commands, `TraceSetLog`, trace coverage (`trace`). |
| G1 | Graph layout and drawing | presentation; `cfg` returns blocks and edges |
| G3 | Themes, colours, fonts, shortcuts, layout and tabs, highlighting | presentation only, no debugger data (`dis` carries bookmark/bp/function/loop data, `addrinfo` the colour) |
| G5 | Running favourite tools | launches external programs from a menu; `favourites` lists them, favourite commands run as native commands |
| G6 | About, update checker, donate, blog, FAQ, manual, bug report | not debugger data (this documentation replaces them) |
| G10 | Interactive dialogs (`msgyn`, line input, message boxes) | no human at the console; dialogs are answered with the safe negative button and reported as `dialog_dismissed` events |
| G11 | Screenshots, clipboard operations ("Copy ..."), column selection | UI mechanics; the client copies values from the JSON |
| G16 | Menu entries that act on the agent host's desktop or shell (Browse in Explorer, open a web page, Focus on Window, open source file) | no debugger data; the data is in `modules`, `windows` (window handle) and `source` (file name) |
| G4 | Scylla | needs its own GUI window |
| G8 | Debuggee stdin/stdout capture | Titan starts the debuggee with its own console; modifying the third-party engine is out of scope (`debug_string` events and `--no-console-window`) |
| G13 | `restartadmin` | would orphan the pipes; start the CLI elevated |
| G15 | Writing XMM/YMM/ZMM/x87 registers | reading is complete; `setreg` answers `E_UNSUPPORTED` |
| G17 | Bulk "set breakpoint on all ..." loops | the client loops (`batch` does 256 per round trip) |
| G18 | Generate crash dump of the debugger | it would crash the CLI; `minidump` dumps the debuggee |
| G19, G20 | Codepage text dumps, register undo history | the client decodes `mem` bytes / keeps the previous `regs` |

Things that look like gaps but are properties of the core and the platform: `seh` is empty on x64 (the GUI tab is empty too), `heaps` is empty
(the core's enumeration is a stub, reported as the warning `heaps_not_enumerated_by_core`), `privileges` reports `unknown` for privileges that are
not in the token. See "Deviations found while implementing" in the parity matrix.

## AI tool integration

A client needs only a pipe to the process and a JSON parser. The minimal loop (run from the repository root; `test_docs.py` executes this block):

```python run
import json, subprocess
p = subprocess.Popen([r"bin\x64\x64dbg-cli.exe", "--json"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8")
hello = json.loads(p.stdout.readline())                       # {"type":"hello",...}
def call(req):
    p.stdin.write(json.dumps(req) + "\n"); p.stdin.flush()
    while True:
        o = json.loads(p.stdout.readline())
        if o["type"] == "response" and o["id"] == req["id"]:
            return o                                           # events may arrive in between: o["type"] == "event"
r = call({"id": 1, "op": "init", "args": {"file": r"bin\x64\tests\cli_target.exe", "args": "call"}})
r = call({"id": 2, "cmd": "bp kernel32.Sleep"})
for i in range(3, 8):                                          # the first stop can be the entry breakpoint: run again
    r = call({"id": i, "cmd": "run", "timeout_ms": 20000})
    if r["state"]["status"] != "paused" or r["state"]["cip_label"] == "Sleep":
        break
print(r["state"]["status"], r["state"]["stop"], r["state"]["cip_label"])
```

[examples/client.py](examples/client.py) is the complete version (reader thread, events, error handling) with a demo session that sets a breakpoint, runs to it,
reads registers, live disassembly, stack and call stack, steps, and shows the disassembly follow `cip`. Typical flows:

| Goal | Requests |
|---|---|
| Start and break | `init`, `bp`/`bp add`, `run` (repeat until `state.stop.bp` matches) |
| Where am I? | `regs`, `dis` (without address: live at `cip`), `stack`, `callstack`, `threads` |
| Step and watch | `stepin`/`stepover`/`stepout`, then `dis`; `animate` + `pause` for continuous stepping |
| Inspect memory | `mem`, `memmap`, `sym --addr`, `addrinfo`, `struct`, `strings` |
| Search | native `findall`, `findallmem`, `reffind`, `findasm`; results are in `tables` |
| Annotate | native `lbl`, `cmt`, `bookmark`; read back with `labels`, `comments`, `bookmarks`, `addrinfo` |
| Patch | `memwrite`, `asm`, then `patches`, `patch export` |
| Scripts | `script load`, `script run` / `step`, `script state` |
| Never hang | give every resuming command a `timeout_ms`; use `pause` (out of band) and `interrupt` |

An MCP server can expose each op as a tool (name = op, input schema = the `args` line of its schema file, output = `data`); see
[agent-guide.md](agent-guide.md). The CLI itself contains no MCP server.

## Real transcripts

All transcripts are raw protocol logs of real runs (`>` request, `<` response/event) stored in `.agents/tasks/cli/transcripts/`;
the excerpts below are shortened (`...`). Debuggee: `testprog.exe` (compiled with `cl /Zi /Od`, `.agents/tasks/cli/testprog`) and `cli_target.exe`.

### 1. Labels, comments, xrefs, strings, handles, TCP (JSON) — `m3-readme-views.jsonl`

```transcript m3-readme-views.jsonl
> {"op":"init","args":{"file":"...\\testprog.exe"},"id":1}
> {"op":"bp","args":{"action":"add","target":"testprog.compute"},"id":2}
> {"op":"run","id":3}                                     < ok, state.status "paused", state.stop {"reason":"breakpoint"}
> {"cmd":"lbl testprog.compute+0x20,loop_head","id":5}
> {"op":"labels","id":7}
< {"ok":true,"output":"1 label(s) listed in Reference View","data":{"table":{"id":1,"name":"Labels","columns":["Address","Disassembly","Label"],
   "rows":[["00007FF6B1421040","jmp 0x00007FF6B142104C","loop_head"]],"total_rows":1,"truncated":false,"actions":[{"title":"Delete","command":"labeldel $0"}]}},...}
> {"op":"addrinfo","args":{"addr":"testprog.compute+0x20"},"id":8}
< {"data":{"addr":"0x00007ff6b1421040","label":"loop_head","comment":"startoftheloop","bookmark":false,"module":"testprog","function":null,
   "loop":"none","argument":"none","bp":"none","color":null,"encoding":"code"},...}
> {"cmd":"analxrefs","id":9}
< {"ok":true,"output":"Starting xref analysis...\n570 xrefs found in 16ms!",...}
> {"op":"xrefs","args":{"addr":"testprog.leaf"},"id":10}
< {"data":{"addr":"0x00007ff6b1421000","count":1,"xrefs":[{"from":"0x00007ff6b142105e","type":"call","from_label":null,"text":"call 0x00007FF6B1421000"}]},...}
> {"op":"handles","args":{"limit":4},"id":12}
< {"data":{"handles":[{"handle":"0x0000000000000004","type":"Event","type_number":21,"name":null,"access":"0x001f0003"},...],"count":4},...}
> {"op":"tcp","id":13}
< {"data":{"connections":[{"local":"127.0.0.1","local_port":11382,"remote":"0.0.0.0","remote_port":0,"state":"LISTEN"}],"count":1},...}
```

### 2. Script with a script breakpoint, step, run to the end — `m3-readme-script.jsonl`

```transcript m3-readme-script.jsonl
> {"op":"script","args":{"action":"load","file":"...\\readme_script.txt"},"id":4}       (three `log "script line N"` lines; the engine appends `ret`)
< {"data":{"lines":[{"n":1,"text":"log \"script line 1\"","type":"command"},...,{"n":4,"text":"ret","type":"command"}],"title":"","ip":1,"messages":[],"errors":[]}}
> {"op":"script","args":{"action":"bp_toggle","line":2},"id":5}              < {"data":{"bp":true}}
> {"op":"script","args":{"action":"run"},"id":6}
< {"ok":true,"output":"script line 1","data":{"finished":false,"ip":2},...}   (stopped at the script breakpoint)
> {"op":"script","args":{"action":"step"},"id":7}
< {"ok":true,"data":{"ip":3,"messages":[],"errors":[]},"wait":{"waited":true,"reason":"paused",...}}
> {"op":"script","args":{"action":"run"},"id":8}
< {"ok":true,"output":"script line 2\nscript line 3\nScript finished!","data":{"finished":true,"ip":1},...}
```

### 3. Trace coverage and struct visit — `m3-readme-trace.jsonl`

```transcript m3-readme-trace.jsonl
> {"op":"trace","args":{"action":"info"},"id":4}
< {"data":{"addr":"0x00007ff6b1421020","region":{"base":"0x00007ff6b1421000","size":8192},"pages":2,"record_type":"none","hit_count":0,"byte_type":"data_byte","recording":false}}
> {"op":"trace","args":{"action":"set_type","type":"byte"},"id":5}
> {"op":"stepin","id":6}   {"op":"stepin","id":7}
> {"op":"trace","args":{"action":"info"},"id":8}
< {"data":{"addr":"0x00007ff6b1421028",...,"record_type":"byte","hit_count":1,"byte_type":"instruction_heading","recording":false}}
> {"cmd":"AddStruct CLI_PAIR","id":9}  {"cmd":"AddMember CLI_PAIR,int,x","id":10}  {"cmd":"AddMember CLI_PAIR,int,y","id":11}
> {"op":"struct","args":{"type":"CLI_PAIR","addr":"testprog.g_pair"},"id":12}
< {"data":{"root":{"name":"struct CLI_PAIR ","type":"CLI_PAIR","offset":0,"size":7,"value":null,"children":[
   {"name":"int x","type":"int","offset":0,"size":4,"value":"0x0000000B, 11","children":[]},
   {"name":"int y","type":"int","offset":4,"size":4,"value":"0x00000016, 22","children":[]}]}}}
```

### 4. Text mode — `m3-text_views.jsonl`

```transcript m3-text_views.jsonl
@@READY x64dbg-cli 1 x64
> !init D:\...\testprog.exe
@@END 1 ok state=paused cip=0x00007ffa389226ca seq=3 wait=paused
> !handles --limit 3
handles:
handle	type	type_number	name	access
0x0000000000000004	Event	21	-	0x001f0003
0x0000000000000008	Event	21	-	0x001f0003
0x000000000000000c	Key	50	\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options	0x00000009
count: 3
@@END 5 ok state=paused cip=0x00007ff6b1421020 seq=5
> !xrefs testprog.leaf
addr: 0x00007ff6b1421000
count: 1
xrefs:
from	type	from_label	text
0x00007ff6b142105e	call	-	call 0x00007FF6B1421000
@@END 10 ok state=paused cip=0x00007ff6b1421020 seq=5
> !callargs 3
convention: x64 fastcall
args:
index	location	value	label
1	rcx	0x0000000000000005	-
2	rdx	0x0000000000000000	-
3	r8	0x7ffffffffffffffc	-
@@END 17 ok state=paused cip=0x00007ff6b1421020 seq=5
```

### 5. Breakpoint, registers, disassembly, stack (M2) — `m2-readme-1-breakpoint.jsonl`

```transcript m2-readme-1-breakpoint.jsonl
> {"op":"init","args":{"file":"...\\cli_target.exe","args":"call"},"id":1}
< ok, state.status "paused", state.stop {"reason":"system_breakpoint"}
> {"op":"bp","args":{"action":"add","target":"kernel32.Sleep","name":"sleep"},"id":2}
< {"breakpoint":{"id":"sw:0x00007ffa36e40e50","kind":"sw","addr":"0x00007ffa36e40e50","label":"Sleep","module":"kernel32.dll","name":"sleep","enabled":true,"hit_count":0,...}}
> {"op":"run","id":3}
< ok, state.status "paused", state.cip "0x00007ffa36e40e50", state.stop {"reason":"breakpoint","bp":"0x00007ffa36e40e50"}
> {"op":"dis","args":{"count":3},"id":5}
< {"start":"0x00007ffa36e40e50","cip":"0x00007ffa36e40e50","live":false,"count":3,"instructions":[{"addr":"0x00007ffa36e40e50","size":7,"bytes":"48ff25a1990500","text":"jmp qword ptr ds:[0x00007FFA36E9A7F8]","kind":"branch","is_cip":true,"label":"Sleep","bp":"normal","branch":{"target":"0x00007ffa35ec1860","target_label":"Sleep","call":false,"conditional":false,"taken":null},...}]}
> {"op":"stack","args":{"count":3},"id":6}
< {"csp":"0x00000072d593f898","cbp":"0x0000000000000000","live":false,"rows":[{"addr":"0x00000072d593f898","offset":0,"value":"0x00007ff7a8dd106b","comment":"return to cli_target.main+4B from cli_target.marker_func","is_csp":true,...},...]}
```

More real runs (replayed by `test_docs.py` like the others): memory write and re-read in `m2-readme-2-memory.jsonl`, text mode in `m2-readme-3-text.jsonl` (and as plain text in `m2-readme-3-text.txt`).

```transcript m2-readme-2-memory.jsonl
> {"cmd":"alloc 1000","vars":["$result"],"id":2}
> {"op":"memwrite","args":{"addr":"$result","hex":"48 65 6c 6c 6f 00 90 c3"},"id":3}
> {"op":"mem","args":{"addr":"$result","size":8,"format":"uint8","cols":8},"id":4}
> {"op":"dis","args":{"addr":"$result+6","count":2},"id":5}
> {"batch":[{"op":"eval","args":{"expr":"rsp"}},{"op":"threads"}],"id":8}
```

```transcript m2-readme-3-text.jsonl
> !init ...\cli_target.exe --args call
> bp kernel32.Sleep
> run
> !regs --groups gpr
> !dis -n 4
> !stack -n 3
> !bps
> !stepin
> !stepout
```

The Python demo output (`m3-client-demo.txt`, produced by [examples/client.py](examples/client.py); `test_docs.py` runs the client and compares the lines modulo numbers):

```transcript m3-client-demo.txt
breakpoint: sw:0x00007ffa36e40e50
stopped: paused {'reason': 'breakpoint', 'bp': '0x00007ff7a8dd1830'} at mainCRTStartup
stopped: paused {'reason': 'breakpoint', 'bp': '0x00007ffa36e40e50'} at Sleep
rip = 0x00007ffa36e40e50  rsp = 0x000000875fcff7d8
  =>0x00007ffa36e40e50  jmp qword ptr ds:[0x00007FFA36E9A7F8]
  stack 0x000000875fcff7d8 -> 0x00007ff7a8dd106b  return to cli_target.main+4B from cli_target.marker_func
call stack: kernel32.Sleep <- cli_target.main+4B <- cli_target.__scrt_common_main_seh+10F
after stepout: 0x00007ffa35e8ba1a ret (is_cip=True)
```

## Notes and limits

* The core sets `$result` to 0 after `loadlib` / `freelib` in this build (`headless.exe` shows the same). Read the base from `modules`.
* `skip` moves the instruction pointer without running the instruction; it can derail the debuggee.
* Native lines are limited to 1023 bytes per segment. A leading `$` expands `{...}` once before the line is split on `;`.
* `restartadmin` is refused. Dialogs raised by the core are answered with the safe negative button and reported as `dialog_dismissed` events.
* When stdin closes while the debuggee runs, the debuggee is killed at shutdown unless `--detach-on-exit` is given. The same holds for `stop`/`quit` of an
  attached process (it is killed, not detached): use `detach`, `{"op":"quit","args":{"detach":true}}` or `--detach-on-exit` to leave it running.
* Hardware breakpoints set at the system breakpoint are gone when the debuggee reaches its entry point (the loader resets the debug registers of the initial
  thread; `regs --groups dbg` shows `dr7` 0). Set them from a stop in user code (entry breakpoint or a software breakpoint). Memory breakpoints are not affected.
* A memory breakpoint added with `restore` false (the default, like the GUI's plain "Memory, Access/Write") is single-shot: the first hit removes it. Pass
  `"restore":true` for a persistent one. Deleting a *disabled* memory breakpoint removes it but the core's `bpmc` still logs `RemoveMemoryBPX` and the op answers
  `E_COMMAND_FAILED`; check `bps`.
* A stop on an exception breakpoint reports `stop.reason: "breakpoint"` with `stop.exception {code, address}` but raises no `exception` event and leaves
  `status.last_exception` unchanged (the core does not raise its exception callback for it). Without an exception breakpoint a first-chance exception stops
  with `stop.reason: "exception"` and sets both. A DLL breakpoint stops with `stop.reason: "breakpoint"` (`breakpoint_hit` with `bp_type: "dll"`); the core also
  arms a `DllMain (<dll>)` entry breakpoint, so the next `run` stops there once. `stop.reason: "dll_load"` needs `Events/DllLoad` (user DLLs) or
  `Events/DllLoadSystem` (system DLLs) set to 1.
* The native line `pause` inside a batch, a `;` chain or a one-shot `--exec` item does not wait for the pause (class Other, design 7.4); the op `pause` and a
  `{"cmd":"pause"}` request on its own do. Use `!pause` / `{"op":"pause"}` before reading registers.
* While one request waits, further requests queue behind it (only `status`, `pause`, `stop`, `interrupt`, `quit` are answered at once). The `E_RUNNING` guards
  therefore show up after the wait ended with the debuggee still running (`timeout_ms` expired, or `interrupt`).
* The size of a struct built with `AddStruct`/`AddMember` is reported by the core one bit short (`struct` shows `size: 7` for two `int` members); the member
  offsets and values are right.
* The natives `analyse`, `analxrefs`, `strref`, ... use the disassembly selection, which the core announces a few milliseconds after a pause; run
  `disasm <addr>` first (the `strings`, `calls`, `ptrs` ops default to `cip` instead).
* `findasm "<asm>", <addr>, <size>` with an explicit size made the core raise an exception in one test run (answered with `E_CRASH`, exit 70); omit the size
  (`findasm "push rbp", <addr>`) or use `findall`.
* Tests: `x64dbg-cli.exe --selftest`; `python src/cli/tests/m1_acceptance.py`, `m1_gate.py`, `m2_acceptance.py`, `m3_acceptance.py`; schema check of every op:
  `python src/cli/tests/test_schema.py`; parity: `python src/cli/tests/check_matrix.py [--run | --negative]`; docs: `python src/cli/tests/test_docs.py`
  (checks sections, links and the counts, regenerates / checks `command-reference.md`, `native-commands.md`, `parity-matrix.md`, runs `examples/client.py`,
  replays every `transcript` block of this file against a fresh debuggee and runs the tagged Python loop).
