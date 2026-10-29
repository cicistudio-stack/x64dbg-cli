#!/usr/bin/env python3
"""Generates docs/cli/command-reference.md and docs/cli/native-commands.md from the running x64dbg-cli.exe (the `help` and
`commands` ops, i.e. the real command tables), the schema files and docs/commands/**/*.md. Standard library only.
Usage: python src/cli/tests/gen_docs.py            writes both files
       python src/cli/tests/gen_docs.py --check    exits 1 when a file differs from what the binary would generate
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
EXE = os.path.join(ROOT, 'bin', 'x64', 'x64dbg-cli.exe')
DOCS = os.path.join(ROOT, 'docs', 'cli')
SCHEMA = os.path.join(ROOT, 'src', 'cli', 'schema')
CMDDOCS = os.path.join(ROOT, 'docs', 'commands')
# One sentence per op: what it wraps. generate() fails when an op of the binary has no entry, so the reference cannot go stale.
NOTES = {
    'status': 'Debugger state, process info, last event, CLI info. Answered out of band (also while another request waits).',
    'help': 'Lists the ops, or the usage of one op.',
    'commands': 'Lists the native commands (collected from the core\'s autocomplete registrations), optionally by prefix.',
    'wait': 'Waits (request field `timeout_ms`) for a pending launch / resume to end.',
    'interrupt': 'Ends the wait of the running request without stopping the debuggee. Out of band.',
    'quit': 'Orderly shutdown (optionally detaching). Out of band.',
    'log': 'Reads the log ring (`--from`, `--tail`, `--clear`).',
    'events': 'Reads typed events by sequence number.',
    'eval': 'Evaluates an expression (`DbgEval`), with label and string.',
    'table': 'Re-reads a captured reference table by id, with paging.',
    'native': 'Runs a native x64dbg command line with explicit request options.',
    'process': 'PID, path, command line, PEB/TEB, entry, elevation of the debuggee.',
    'regs': '`DbgGetRegDumpEx`: general purpose, flags, segment, debug, x87, MMX, XMM, YMM, ZMM, opmask registers.',
    'setreg': 'Writes a register (`DbgValToString`).',
    'dis': 'Disassembly with the annotations of the GUI disassembler (`DbgDisasmAt` plus a Zydis tail decode); live at `cip` without `addr`.',
    'mem': 'Memory dump in 20 formats (`DbgMemRead`).',
    'memwrite': 'Writes hex / ASCII / UTF-16 / file bytes and records patches.',
    'memmap': 'Memory map (`DbgMemMap`).',
    'stack': 'Raw stack slots with comments (`DbgStackCommentGet`).',
    'callstack': 'Call stack of a thread (`GetCallStackByThread`).',
    'bps': 'All breakpoints (`DbgGetBpList`, `BpRef*`).',
    'bp': 'Adds, deletes, enables, disables breakpoints of every kind and resets hit counts.',
    'threads': 'Thread list (`DbgGetThreadList`) with times and cycle counts.',
    'thread': 'Thread control: switch, suspend, resume, kill, name, priority, create.',
    'modules': 'Module list with base, size, path, entry, party, symbol state.',
    'sym': 'Symbol search and address resolution (`DbgSymbolEnum`, `DbgGetSymbolInfoAt`).',
    'init': 'Starts a debuggee (`init`) and waits for the system breakpoint.',
    'run': 'Resumes (`run`) and waits for the next pause.',
    'stepin': 'Step into (`sti`), count in hex on the wire.',
    'stepover': 'Step over (`sto`).',
    'stepout': 'Execute till return (`rtr`).',
    'runto': 'Run to an address with a single-shot breakpoint (`run <addr>`).',
    'pause': 'Pauses the debuggee. Out of band.',
    'stop': 'Stops the debuggee (`stop`). Out of band.',
    'restart': 'Stops and repeats the last `init` of this CLI.',
    'attach': 'Attaches to a process (`attach .<pid>`), optionally pausing it.',
    'detach': 'Detaches (`detach`).',
    'skip': 'Skips instructions (`skip`).',
    'seh': 'SEH chain of the active thread (`GetSEHChain`). The x64 chain is empty by design of the OS (x64 uses table based unwinding).',
    'handles': 'Handle list of the debuggee with type and object name (`EnumHandles`, `GetHandleName`).',
    'windows': 'Windows of the debuggee threads (`EnumWindows`).',
    'tcp': 'TCP connections of the debuggee (`EnumTcpConnections`).',
    'heaps': 'Heap list (`EnumHeaps`). The core\'s enumeration is a stub, so the list is empty and a warning says so (same as the GUI tab).',
    'privileges': 'Token privileges of the debuggee (`GetPrivilegeState` for the fixed list of the GUI). `unknown` = not in the token.',
    'ps': 'Process list of the attach dialog (`GetProcessList`); `exe` is the full path.',
    'labels': 'Captured table of the native `labellist`.',
    'comments': 'Captured table of the native `commentlist`.',
    'bookmarks': 'Captured table of the native `bookmarklist`.',
    'functions': 'Captured table of the native `functionlist`.',
    'arguments': 'Captured table of the native `argumentlist`.',
    'loops': 'Captured table of the native `looplist`.',
    'addrinfo': 'Everything the database knows about one address: label, comment, bookmark, function, loop, argument, breakpoint, colour, encoding.',
    'xrefs': 'Cross references to an address (`DbgXrefGet`); fill the database first with the native `analxrefs` or `analyse`.',
    'patches': 'Patch list (`PatchEnum`).',
    'patch': 'Exports patches to a file (`PatchFile`), restores one patch or a range (`PatchRestore`, `PatchRestoreRange`).',
    'strings': 'Native `strref` (Find Strings) as a table; default region = the one containing `cip`.',
    'calls': 'Native `modcallfind` (Find Intermodular Calls) as a table.',
    'ptrs': 'Native `reffunctionpointer` (Find function pointers) as a table.',
    'watch': 'Watch list (`DbgGetWatchList`); add / delete with the native `AddWatch` / `DelWatch`.',
    'trace': 'Trace coverage (`SetTraceRecordType`, `GetTraceRecordHitCount`) and run trace recording (`StartTraceRecording`).',
    'script': 'Script engine: load, run, step, breakpoints, `exec`, `cmd`, with the GUI_SCRIPT_* mirror (lines, ip, messages, errors).',
    'types': 'Defined structs (`EnumStructs`); define new ones with the native `AddStruct` / `AddMember` / `ParseTypes`.',
    'struct': 'Visits a type at an address (`DbgTypeVisit`) and returns the member tree with values.',
    'cfg': 'Control flow graph blocks of a function (`DbgAnalyzeFunction`). No layout.',
    'notes': 'Global and debuggee notes (host store, saved by the core).',
    'source': 'Source lines of an address or a file/line (`GetSourceFromAddr`, `GetAddrFromLineEx`); needs a PDB with line info.',
    'nav': 'The view positions the core announced (`GUI_DISASSEMBLE_AT`, `GUI_DUMP_AT`, ...), title, recent files.',
    'callargs': 'Arguments at `cip` by the x64 calling convention (the GUI Arguments widget).',
    'locals': 'Local variables / arguments found by scanning the operands of the current function (the GUI Locals view).',
    'infobox': 'The data of the CPU info box for an instruction: jump, operands, location, comment, source line.',
    'menu': 'Plugin menus registered through the GUI_MENU_* messages; `click` runs an entry.',
    'config': 'Settings (`BridgeSettingGet/Set` plus `DbgSettingsUpdated`) and the debuggee init script.',
    'constants': 'The constants known to expressions (`EnumConstants`).',
    'errors': 'Windows error codes (`EnumErrorCodes`).',
    'exceptions': 'Exception codes (`EnumExceptions`).',
    'format': 'String format expression (`StringFormatInline`), for example `rax={rax}`.',
    'asm': 'Assembles an instruction into memory (`Assemble` + `AssembleAtEx`), recording a patch.',
    'animate': 'Repeats a command every 50 ms until `pause` (`AnimateCommand`), e.g. `StepInto;AnimateWait`.',
    'favourites': 'Favourite tools and commands registered by plugins / settings.',
    'module': 'Module actions of the Symbols view: party, loadlib, freelib, symbol download / load / unload.',
}
CATEGORIES = [
    ('Session and utility', 'status help commands wait interrupt quit log events eval table native'),
    ('Run control', 'init run stepin stepover stepout runto pause stop restart attach detach skip'),
    ('CPU and memory views', 'process regs setreg dis mem memwrite memmap stack callstack callargs locals infobox cfg'),
    ('Breakpoints, threads, modules, symbols', 'bps bp threads thread modules module sym'),
    ('Operating system views', 'seh handles windows tcp heaps privileges ps'),
    ('Database and analysis views', 'labels comments bookmarks functions arguments loops addrinfo xrefs patches patch strings calls ptrs watch'),
    ('Trace, scripts, types, source', 'trace script types struct source notes nav'),
    ('Settings, helpers, plugins', 'config constants errors exceptions format asm animate favourites menu'),
]
class Client:
    def __init__(self):
        self.ud = tempfile.mkdtemp(prefix='clidoc_')
        self.p = subprocess.Popen([EXE, '--json', '--userdir', self.ud], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        self.hello = json.loads(self.p.stdout.readline().decode('utf-8'))
    def request(self, obj):
        self.p.stdin.write((json.dumps(obj) + '\n').encode('utf-8'))
        self.p.stdin.flush()
        while True:
            line = self.p.stdout.readline().decode('utf-8')
            if not line:
                raise RuntimeError('CLI closed stdout')
            o = json.loads(line)
            if o.get('type') == 'response' and o.get('id') == obj['id']:
                return o
    def close(self):
        try:
            self.request({'id': 'q', 'op': 'quit'})
        except Exception:
            pass
        try:
            self.p.wait(timeout=30)
        except Exception:
            self.p.kill()
        shutil.rmtree(self.ud, ignore_errors=True)
def schema_text(op):
    """args / data lines of the schema file that lists the op in its first line."""
    for fn in sorted(os.listdir(SCHEMA)):
        if not fn.endswith('.schema'):
            continue
        text = open(os.path.join(SCHEMA, fn), encoding='ascii').read().replace('\r\n', '\n')
        first = text.split('\n', 1)[0]
        if first.startswith('schema ') and op in first.split()[1:]:
            return text.split('\n', 1)[1].rstrip('\n')
    return None
def command_docs():
    """lower-case command name -> (category, summary) from docs/commands/<category>/*.md."""
    out = {}
    for cat in sorted(os.listdir(CMDDOCS)):
        d = os.path.join(CMDDOCS, cat)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith('.md'):
                continue
            lines = open(os.path.join(d, fn), encoding='utf-8', errors='replace').read().splitlines()
            if not lines or not lines[0].startswith('# '):
                continue
            names = [n.strip().lower() for n in lines[0][2:].strip().split('/')]
            summary = ''
            for l in lines[1:]:
                l = l.strip()
                if l and not l.startswith('#'):
                    summary = l
                    break
            summary = summary.replace('|', '\\|')
            for n in names:
                out.setdefault(n, (cat, summary))
    return out
def gen_reference(c):
    r = c.request({'id': 1, 'op': 'help'})
    ops = r['data']['ops']
    names = [o['name'] for o in ops]
    missing = [n for n in names if n not in NOTES]
    if missing:
        raise SystemExit('gen_docs.py: no NOTES entry for op(s): %s' % ', '.join(missing))
    grouped = [n for _, g in CATEGORIES for n in g.split()]
    stray = [n for n in names if n not in grouped]
    if stray:
        raise SystemExit('gen_docs.py: op(s) without a category: %s' % ', '.join(stray))
    by = {o['name']: o for o in ops}
    out = ['# x64dbg-cli command reference', '',
           'Generated by `python src/cli/tests/gen_docs.py` from the `help` op of the built `x64dbg-cli.exe` (%d ops), the schema files' % len(ops),
           'in `src/cli/schema` and the notes kept in that script. `--check` fails when this file is out of date.', '',
           'Every op is also available in text mode as `!op args` (first positional token = main argument, other keys as `--key value`, ',
           'see README). Request options (`timeout_ms`, `wait`, `on_timeout`, `max_output`, ...) are top-level request fields, never keys of `args`.',
           'Schema notation: `?` optional key, `(a|b)` alternatives, `addr` = `"0x" + 16 lowercase hex digits`, `u32` = `"0x" + 8 hex digits`,',
           '`hex` = lowercase hex bytes, `table` = captured reference table (see README).', '']
    out.append('| Op | Milestone | Precondition | Usage |')
    out.append('|---|---|---|---|')
    for cat, g in CATEGORIES:
        for n in g.split():
            o = by[n]
            out.append('| [`%s`](#%s) | %s | %s | `%s` |' % (n, n, o['milestone'], o['precondition'], o['usage'].replace('|', '\\|')))
    out.append('')
    for cat, g in CATEGORIES:
        out += ['## ' + cat, '']
        for n in g.split():
            o = by[n]
            out += ['### %s' % n, '', NOTES[n], '',
                    '* Precondition: `%s` (`any` = no session needed, `debugging` = a session exists, `paused` = registers are readable). Milestone %s.' % (o['precondition'], o['milestone']),
                    '* Text form: `!%s`' % o['usage'].replace('`', "'"), '']
            s = schema_text(n)
            if s:
                out += ['```', s, '```', '']
    return '\n'.join(out).rstrip('\n') + '\n'
def gen_native(c):
    total = c.request({'id': 'ct', 'op': 'commands'})['data']
    cmds = total['commands']
    seen = {}
    for e in cmds:
        seen[e['canonical']] = e
    docs = command_docs()
    out = ['# Native commands reachable through `cmd` / `!native`', '',
           'Generated by `python src/cli/tests/gen_docs.py` from the `commands` op of the built `x64dbg-cli.exe` (%d commands; the core registers them' % len(seen),
           'with `dbgcmdnew`) and the summaries of `docs/commands/**/*.md`. Every one of them runs through the pass-through layer: output',
           'is captured per command, tables land in `tables`, and commands that resume the debuggee wait for the next pause.',
           'Commands that need a session answer `E_NOT_DEBUGGING` without one (the core does not publish that flag to the host, so it is not listed).', '',
           '| Command | Aliases | Category | Summary |', '|---|---|---|---|']
    for canon in sorted(seen, key=lambda s: s.lower()):
        e = seen[canon]
        aliases = [n for n in e['names'] if n.lower() != canon.lower()]
        cat, summary = ('', '')
        for n in [canon] + aliases:
            if n.lower() in docs:
                cat, summary = docs[n.lower()]
                break
        out.append('| `%s` | %s | %s | %s |' % (canon, ' '.join('`%s`' % a for a in aliases), cat, summary))
    return '\n'.join(out) + '\n', len(seen), total
def main():
    check = '--check' in sys.argv
    c = Client()
    try:
        ref = gen_reference(c)
        nat, count, total = gen_native(c)
        if total.get('count') is not None and total['count'] != count:
            print('warning: commands op count %s != %s collected' % (total['count'], count))
    finally:
        c.close()
    files = {'command-reference.md': ref, 'native-commands.md': nat}
    bad = 0
    for name, text in files.items():
        path = os.path.join(DOCS, name)
        data = text.replace('\n', '\r\n').encode('utf-8')
        if check:
            cur = open(path, 'rb').read() if os.path.exists(path) else b''
            if cur != data:
                print('%s is out of date' % name)
                bad += 1
            else:
                print('%s up to date' % name)
        else:
            with open(path, 'wb') as f:
                f.write(data)
            print('wrote', path, len(data), 'bytes')
    return 1 if bad else 0
if __name__ == '__main__':
    sys.exit(main())
