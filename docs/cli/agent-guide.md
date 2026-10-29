# Agent guide: driving x64dbg-cli from an AI tool

This is documentation only; the CLI contains no MCP server. It shows how an agent runtime (or a thin MCP server) can use the protocol of
[README.md](README.md). A working client is in [examples/client.py](examples/client.py).

## Process model

* Start one `x64dbg-cli.exe --json --userdir <private dir>` per debugging task. The user directory holds the settings and the databases and
  is locked: one process per directory.
* Read the `hello` line, then send one request per line and match responses by `id`. Events that arrive in between are part of the protocol, not errors.
* Never write to the process before `hello`. Close stdin (or send `{"op":"quit"}`) to end the session; the CLI stops the debuggee and exits 0.
* Run as the same user and integrity level as the target. Attaching to an elevated process needs an elevated CLI.

## Rules that keep an agent out of trouble

1. **Always set a timeout on anything that resumes the debuggee**: `{"cmd":"run","timeout_ms":20000}`. A timeout leaves the debuggee running and the response says
   `wait.timed_out:true`; follow with `{"op":"pause"}` (answered at once, also while another request waits) or `{"op":"interrupt"}` (ends the pending wait only).
2. **Look at `state.status` and `state.stop.reason` of every response** instead of assuming. `paused` + `breakpoint` + `bp` tells which breakpoint fired;
   `stopped` + `exit_code` means the process ended; `running` means the wait ended early.
3. **Preconditions are checked for you.** `E_NOT_DEBUGGING` = `init`/`attach` first. `E_RUNNING` = the op needs a paused debuggee (`pause`) — except memory
   reads, which work on a running debuggee and say `live:true`.
4. **Addresses are strings** (`"0x00007ffb12345678"`), expressions are accepted wherever an address is expected (`rsp+8`, `kernel32.Sleep`, `[rsp]`). A bare number is hex.
5. **Use ops for data, natives for actions that have no op.** Ops give typed JSON; natives give log text in `output` and tables in `tables`. Mutations of the
   database (`lbl`, `cmt`, `bookmark`, `functionadd`, ...) are natives, their read-back is an op (`labels`, `comments`, `addrinfo`, ...).
6. **Large outputs are bounded.** Use `limit`/`offset`, `-n`, `max_rows`, `max_output`; `truncated:true` and `next_addr`/`output_truncated_next` tell how to continue.
7. **Do not parse `output` when an op exists.** The log text of the core is for humans and changes with translations; `data` is stable and schema-checked.
8. After `init` the debuggee is paused at the system breakpoint. With default settings it stops again at the entry breakpoint (and TLS callbacks).
   Repeat `run` until `state.stop.bp` is yours, or set `Events/EntryBreakpoint` and `Events/TlsCallbacks` to 0 with `config set`.
9. **Hardware breakpoints need a stop in user code.** Set `hw` breakpoints after the entry breakpoint (or any software breakpoint), not at the system breakpoint:
   the loader clears the debug registers of the initial thread. Memory breakpoints are single-shot unless `"restore":true`. Use `{"op":"pause"}`, not the native `pause`,
   inside batches and one-shot item lists, because only the op waits for the pause.
10. **`stop`/`quit` kill an attached process.** To leave it running use `{"op":"detach"}`, `{"op":"quit","args":{"detach":true}}` or start the CLI with `--detach-on-exit`.

## A debugging loop

```
init            {"op":"init","args":{"file":"C:\\target.exe","args":"--flag"}}
break           {"op":"bp","args":{"action":"add","target":"kernel32.CreateFileW","condition":"[rdx]==0x74007300"}}
go              {"cmd":"run","timeout_ms":30000}                         -> stop.reason "breakpoint"
look            {"op":"regs"}  {"op":"dis","args":{"count":10}}  {"op":"stack","args":{"count":16}}  {"op":"callstack"}
step            {"op":"stepover"}  then  {"op":"dis","args":{"count":1}}   (live: always starts at the new cip)
inspect         {"op":"mem","args":{"addr":"rcx","size":64,"format":"utf16"}}  {"op":"addrinfo","args":{"addr":"rip"}}
annotate        {"cmd":"lbl rip,open_file"}  {"cmd":"cmt rip,opens the log"}  {"op":"labels"}
search          {"cmd":"findall rip,e8 ?? ?? ?? ??"}                      -> tables[0]
finish          {"op":"stop"}  {"op":"quit"}
```

## Mapping to MCP tools

One generic tool is enough, and a typed tool per op is better for models:

| MCP tool | Maps to | Input schema |
|---|---|---|
| `x64dbg_command` | `{"cmd": line, ...options}` | `{line: string, timeout_ms?: int, on_timeout?: "keep"\|"pause"\|"stop"}` |
| `x64dbg_<op>` (80 of them) | `{"op": "<op>", "args": {...}}` | the `args:` line of `src/cli/schema/<op>.schema` (also printed in [command-reference.md](command-reference.md)) |
| `x64dbg_pause`, `x64dbg_interrupt` | out-of-band ops | `{}` |

The tool result is the response object, trimmed to what the model needs (`ok`, `error`, `data`, `output`, `tables`, `state`, `wait`, `events`). Keep `state` — it is the
cheapest way for the model to know whether the debuggee is running.

Sketch (not shipped):

```python
from client import Cli

cli = Cli(r"bin\x64\x64dbg-cli.exe")

def tool(name, args):
    if name == "x64dbg_command":
        r = cli.call({"cmd": args["line"], "timeout_ms": args.get("timeout_ms", 30000)})
    else:
        r = cli.call({"op": name.removeprefix("x64dbg_"), "args": args})
    keep = ("ok", "error", "data", "output", "tables", "state", "wait", "events", "warnings", "truncated")
    return {k: r[k] for k in keep if r.get(k) not in (None, [], {}, "")}
```

Generate the tool list from the binary: the `hello` line has `capabilities.ops`; `{"op":"help"}` has name, precondition and usage of each op; the schema files describe
`args` and `data`.

## Text mode for humans and shells

`x64dbg-cli.exe --interactive target.exe args` starts the target and keeps a text REPL (`!regs`, `!dis -n 5`, `bp kernel32.Sleep`, `run`); every response ends with an `@@END` line, so a
script can read until it. One-shot use (no `--interactive`: stdin is never read, the startup items answer with the ids `s1`, `s2`, ..., exit code 1 if a command failed):

```
x64dbg-cli.exe --exec "init \"C:\t.exe\", \"call\"" --exec "bp kernel32.Sleep" --exec "run" --exec "run" --exec "!regs --groups gpr"
```
