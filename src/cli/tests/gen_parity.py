#!/usr/bin/env python3
"""Builds docs/cli/parity-matrix.md and docs/cli/parity-matrix.csv from the parity tables of the design (section 11 of
.agents/tasks/cli/design.md), then verifies every row against the built binary and the GUI sources:

* every `!op` named by a row that is not Gap / UI must be an op of the built x64dbg-cli.exe (`help`);
* every action id of the .ui files and every class base name of src/gui/Src/Gui, Tracer and BasicView must have a row.

Rows whose first cell is empty continue the class of the previous row (context-menu groups). The "Built" column is computed,
the "Notes" column carries the deviations that were found while implementing (OVERRIDES).
Usage: python src/cli/tests/gen_parity.py [--check]   (--check: exit 1 when the checked-in files differ or a row fails)
Standard library only.
"""
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_matrix  # noqa: E402
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
DESIGN = os.path.join(ROOT, '.agents', 'tasks', 'cli', 'design.md')
OUT_MD = os.path.join(ROOT, 'docs', 'cli', 'parity-matrix.md')
OUT_CSV = os.path.join(ROOT, 'docs', 'cli', 'parity-matrix.csv')
EXE = os.path.join(ROOT, 'bin', 'x64', 'x64dbg-cli.exe')
GUI = os.path.join(ROOT, 'src', 'gui', 'Src')
# Deviations found while implementing M3 (id -> note). The status column of the design is kept unless a note says otherwise.
OVERRIDES = {
    'actionSEHChain': 'x64: the OS chain (TEB ExceptionList) is empty, as in the GUI tab; the op returns an empty list.',
    'actionHandles': '`!heaps` is empty because the core enumeration is a stub (the GUI tab is empty too); the call returns a warning `heaps_not_enumerated_by_core`.',
    'actionSource': 'File text is read by the CLI; file + line lookup uses `GetAddrFromLineEx` per module (`GetAddrFromLine` is a stub in the core).',
    'actionGraph': 'Entry defaults to the graph position announced by the core, else `cip` (the last-graph cache of the design is not kept).',
    'actionManual': 'Generated: docs/cli/native-commands.md (the debug-only flag is not published by the core, so it is not listed).',
    'actionSettings': 'Settings keys are read/written as ini sections; the dialog layout is UI.',
    'actionStrings': 'Without addr the search starts at `cip` (the disassembly selection is only updated asynchronously after a pause).',
    'actionTrace': 'Not implemented: milestone M4 (trace-file reader) is outside this run; recording is `!trace start` / `stop`.',
}
# UI rows of the design that name no gap id: the pane only shows a preview / is an input helper for another action
GAP_FIX = {'DisassemblyPopup': 'G3', 'BrowseDialog': 'G10'}
def read_design():
    return open(DESIGN, encoding='utf-8').read().replace('\r\n', '\n')
def section_lines(text, start, end):
    i = text.index(start)
    j = text.index(end, i + len(start))
    return text[i:j].split('\n')
def split_row(line):
    cells = re.split(r'(?<!\\)\|', line.strip())
    cells = cells[1:-1] if line.strip().endswith('|') else cells[1:]
    return [c.strip().replace('\\|', '|') for c in cells]
def table(lines):
    rows = []
    for l in lines:
        if l.startswith('|') and not re.match(r'^\|[-| ]+\|$', l):
            rows.append(split_row(l))
    return rows[1:]  # drop the header
def strip_ticks(s):
    return s.strip().strip('`').strip()
def parse_status(s):
    m = re.match(r'^([A-Za-z]+)(.*)$', s.strip())
    status = m.group(1) if m else s
    gaps = ' '.join(re.findall(r'G\d+', s))
    return status, gaps, s.strip()
def gui_actions():
    ids = []
    for dp, dn, fn in os.walk(GUI):
        for f in fn:
            if f.endswith('.ui'):
                base = f[:-3]
                for m in re.finditer(r'<action name="([^"]+)"', open(os.path.join(dp, f), encoding='utf-8', errors='replace').read()):
                    ids.append(m.group(1) if base == 'MainWindow' else '%s:%s' % (base, m.group(1)))
    return sorted(set(ids))
def gui_classes():
    names = set()
    for sub in ('Gui', 'Tracer', 'BasicView'):
        d = os.path.join(GUI, sub)
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith('.cpp') or f.endswith('.h'):
                    names.add(f.rsplit('.', 1)[0])
    return sorted(names)
def ops_of_binary():
    ud = tempfile.mkdtemp(prefix='cliparity_')
    p = subprocess.Popen([EXE, '--json', '--userdir', ud], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    hello = json.loads(p.stdout.readline().decode('utf-8'))
    try:
        p.stdin.write(b'{"id":"q","op":"quit"}\n')
        p.stdin.flush()
        p.wait(timeout=30)
    except Exception:
        p.kill()
    shutil.rmtree(ud, ignore_errors=True)
    return set(hello['capabilities']['ops'])
def built(cli, status, ops, names):
    if status in ('UI',):
        return 'n/a'
    toks = re.findall(r'`!([a-z_]+)', cli)
    toks = [t for t in toks if t not in ('help',)]
    if status == 'Gap':
        return 'gap'
    missing = sorted({t for t in toks if t not in ops})
    for tok in check_matrix.spans_of(cli):
        if check_matrix.classify(tok, ops, names)[0] == 'unknown':
            missing.append(tok)
    return 'yes' if not missing else 'MISSING: ' + ', '.join(missing)
def acceptance_ops(ops):
    """Ops that an acceptance script calls (static scan of op('name'), 'op': 'name' and !name)."""
    src = ''
    for f in ('m1_acceptance.py', 'm1_gate.py', 'm2_acceptance.py', 'm3_acceptance.py'):
        src += open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f), encoding='utf-8').read()
    return {o for o in ops if re.search(r'op\(\s*[\'"]%s[\'"]|[\'"]op[\'"]\s*:\s*[\'"]%s[\'"]|![\'"]?%s\b' % (o, o, o), src)}
def exercised(cli, status, ops, names, smoke, acc_ops):
    """What runs the row: `ops` = every named op is called by an acceptance script; `smoke:<expect>` = the native's line of native_smoke.csv."""
    if status == 'UI':
        return 'n/a'
    if status == 'Gap':
        return 'gap'
    parts = []
    toks = sorted({t for t in re.findall(r'`!([a-z_]+)', cli) if t != 'help'})
    if toks:
        parts.append('ops' if all(t in acc_ops for t in toks) else 'ops NOT RUN: ' + ', '.join(t for t in toks if t not in acc_ops))
    exp = set()
    for tok in check_matrix.spans_of(cli):
        kind, val = check_matrix.classify(tok, ops, names)
        if kind == 'native':
            exp.add(smoke.get(val, 'NO SMOKE LINE').split(':')[0])
    if exp:
        parts.append('smoke:' + '/'.join(sorted(exp)))
    return '; '.join(parts) if parts else '-'
def main():
    text = read_design()
    ops, names = check_matrix.binary_info()
    smoke = {names.get(n.lower(), n): e for n, _a, e in check_matrix.load_smoke(check_matrix.SMOKE_DEFAULT)}
    acc_ops = acceptance_ops(ops)
    rows = []   # kind, id, gui_label, cli, milestone, status, gap_id, built, note
    actions = table(section_lines(text, '### 11.1 Main window actions', '### 11.2 Panes and widgets'))
    for a in actions:
        status, gaps, raw = parse_status(a[4])
        rows.append(['action', a[0], a[1], a[2], a[3], status, gaps, built(a[2], status, ops, names), OVERRIDES.get(a[0], '')])
    for a in table(section_lines(text, '### 11.1b Actions of the other `.ui` files', '### 11.2b Classes')):
        status, gaps, raw = parse_status(a[4])
        rows.append(['action', a[0], a[1], a[2], a[3], status, gaps, built(a[2], status, ops, names), OVERRIDES.get(a[0], '')])
    classes = table(section_lines(text, '### 11.2 Panes and widgets', '### 11.1b Actions of the other')) + \
        table(section_lines(text, '### 11.2b Classes of', '### 11.3 Context-menu action groups'))
    for c in classes:
        status, gaps, raw = parse_status(c[4])
        if status == 'UI' and not gaps:
            gaps = GAP_FIX.get(c[0].split(',')[0].strip(), 'G3')
        rows.append(['class', c[0], c[1], c[2], c[3], status, gaps, built(c[2], status, ops, names), OVERRIDES.get(c[0].split(',')[0].strip(), '')])
    menus = []
    for a in table(section_lines(text, '### 11.3 Context-menu action groups', '### 11.3b Context-menu actions')):
        menus.append(['menu', a[0], a[1], a[2], a[3], a[4]])
    cur = ''
    for a in table(section_lines(text, '### 11.3b Context-menu actions', '### 11.4 Gaps and why')):
        if a[0]:
            cur = a[0]
        menus.append(['menu', cur, a[1], a[2], a[3], a[4]])
    for m in menus:
        status, gaps, raw = parse_status(m[5])
        rows.append(['menu', m[1], m[2], m[3], m[4], status, gaps, built(m[3], status, ops, names), ''])
    gaps_tbl = table(section_lines(text, '### 11.4 Gaps and why', '### 11.5 Matrix artifacts'))
    # ---- verification
    problems = []
    for r in rows:   # r[9]: what exercises the row
        r.append(exercised(r[3], r[5], ops, names, smoke, acc_ops))
        if 'NOT RUN' in r[9] or 'NO SMOKE' in r[9]:
            problems.append('%s %s: %s' % (r[0], r[1], r[9]))
    have_actions = {r[1] for r in rows if r[0] == 'action'}
    for aid in gui_actions():
        if aid not in have_actions:
            problems.append('action id without a row: ' + aid)
    have_classes = set()
    for r in rows:
        if r[0] == 'class':
            for n in re.split(r',\s*', r[1]):
                have_classes.add(n.strip())
    for cname in gui_classes():
        if cname not in have_classes and not cname.startswith('ui_'):
            problems.append('class without a row: ' + cname)
    for r in rows:
        if r[7].startswith('MISSING'):
            problems.append('%s %s: %s' % (r[0], r[1], r[7]))
        if r[5] in ('Gap', 'UI') and not r[6] and r[0] != 'menu':
            problems.append('%s %s: status %s without a gap id' % (r[0], r[1], r[5]))
    # ---- csv
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(['kind', 'id', 'gui_label', 'cli', 'milestone', 'status', 'gap_id', 'built', 'note', 'exercised'])
    for r in rows:
        w.writerow(r)
    csv_text = buf.getvalue()
    # ---- markdown
    counts = {}
    for r in rows:
        counts[(r[0], r[5])] = counts.get((r[0], r[5]), 0) + 1
    def cnt(kind):
        return {s: counts.get((kind, s), 0) for s in ('Full', 'Part', 'Native', 'UI', 'Gap')}
    md = ['# GUI-to-CLI parity matrix', '',
          'Generated by `python src/cli/tests/gen_parity.py` from the parity tables of the design and verified against the built `x64dbg-cli.exe`',
          'and the GUI sources: every `.ui` action id and every class of `src/gui/Src/Gui`, `Tracer` and `BasicView` has a row, and every `!op` named by',
          'a row that is not `Gap` or `UI` is an op of the binary (column **Built**). The machine readable form is `parity-matrix.csv`.', '',
          '**Status legend.** `Full` = the CLI returns the same information as the GUI pane or action. `Part` = same data source, less presentation',
          '(see the note / gap). `Native` = available through the pass-through command language only (the pane\'s data is produced by that native',
          'command and arrives in `output` / `tables`). `UI` = presentation or input helper that shows no debugger data. `Gap` = data the GUI shows that',
          'the CLI does not provide (reasons below). **M** = earliest milestone at which the row is reachable (native commands work from M1).',
          '**Built**: `yes` = every `!op` the row names is an op of this build and every native command it names is a command or alias of this build (checked by `check_matrix.py` against the `commands` op); `gap` / `n/a` = nothing to build.',
          '**Exercised**: `ops` = every named op is called by an acceptance script (`m1_acceptance.py`, `m1_gate.py`, `m2_acceptance.py`, `m3_acceptance.py`; static scan of the op names); `smoke:ok` / `smoke:usage` / `smoke:skip` = the expectation of the native\'s line in `src/cli/tests/native_smoke.csv`, executed once by `python src/cli/tests/check_matrix.py --run` (`ok` = the command succeeded, `usage` = it is registered and reached and rejected the call, e.g. no arguments or nothing to act on, `skip` = not run, the reason is in the file). Rows whose native commands are not in the smoke file or whose ops no script calls fail `gen_parity.py --check`.', '',
          '## Summary', '', '| Kind | Rows | Full | Part | Native | UI | Gap |', '|---|---|---|---|---|---|---|']
    for kind in ('action', 'class', 'menu'):
        c = cnt(kind)
        md.append('| %s | %d | %d | %d | %d | %d | %d |' % (kind, sum(1 for r in rows if r[0] == kind), c['Full'], c['Part'], c['Native'], c['UI'], c['Gap']))
    md += ['', 'The only data the GUI shows and the CLI does not provide: the **trace browser** (`.trace64` reader panes, gap G2, milestone M4, not part of this', 'run), the graph layout (G1), Scylla (G4), debuggee console capture (G8), writing vector / x87 registers (G15), the register undo history (G20),',
           'and the bulk loops G17. Everything else is either implemented as an op, available as a native command, or presentation.', '']
    def emit(title, kind, header):
        md.extend(['## ' + title, '', header, '', '| Id | GUI label | CLI | M | Status | Built | Exercised | Notes |', '|---|---|---|---|---|---|---|---|'])
        for r in rows:
            if r[0] == kind:
                st = r[5] + (' (%s)' % r[6] if r[6] else '')
                md.append('| %s | %s | %s | %s | %s | %s | %s | %s |' % (r[1], r[2].replace('|', '\\|'), r[3].replace('|', '\\|'), r[4], st, r[7], r[9], r[8].replace('|', '\\|')))
        md.append('')
    emit('Main window actions (all `<action>` ids of the .ui files)', 'action', 'One row per action id: the 103 ids of `MainWindow.ui`, plus `CPUWidget:actionGoto` and `TraceWidget:actionGoto`.')
    emit('Panes and widgets (all classes of Gui, Tracer and BasicView)', 'class', 'One row per group of source classes (file base names).')
    md += ['## Context-menu entries', '',
           'Every entry of a context menu or toolbar that creates a `QAction` / `QMenu` with a translatable label is covered by one of the rows below',
           '(entries of the same class with the same mapping are grouped in one row). "Stateless navigation" means the GUI entry only moves a view to an',
           'address; the CLI passes the address to the view op, so nothing is lost. Clipboard entries (`Copy ...`) are UI (G11): the data is in the JSON response.', '',
           '| Class | Entries | CLI | M | Status | Built | Exercised |', '|---|---|---|---|---|---|---|']
    for r in rows:
        if r[0] == 'menu':
            st = r[5] + (' (%s)' % r[6] if r[6] else '')
            md.append('| %s | %s | %s | %s | %s | %s | %s |' % (r[1], r[2].replace('|', '\\|'), r[3].replace('|', '\\|'), r[4], st, r[7], r[9]))
    md += ['', '## Gaps and why', '', '| ID | Gap | Reason | Substitute |', '|---|---|---|---|']
    for g in gaps_tbl:
        if g[0] == 'G7':
            continue
        sub = g[3]
        if g[0] == 'G12':
            sub = '`docs/cli/native-commands.md` is generated from `docs/commands` and the commands the binary registers (`python src/cli/tests/gen_docs.py`); the debug-only flag is not published by the core and is not listed. `!commands` lists the names at runtime.'
        if g[0] == 'G2':
            sub = 'Not implemented in this run (milestone M4 is separate work). Substitutes: `!trace start` / `stop` (run trace recording), the conditional trace natives, `TraceSetLog`, and the coverage data of `!trace`.'
        md.append('| %s | %s | %s | %s |' % (g[0], g[1].replace('|', '\\|'), g[2].replace('|', '\\|'), sub.replace('|', '\\|')))
    md += ['', '## Deviations found while implementing', '',
           '* `!seh` is empty on x64: the chain is the TEB `ExceptionList`, which x64 does not use (the GUI tab is empty as well).',
           '* `!heaps` is empty: `HandlesEnumHeaps` is a stub in the core (its Toolhelp implementation is commented out); the op reports the warning `heaps_not_enumerated_by_core`.',
           '* `!privileges`: `unknown` means the privilege is not in the token (the GUI shows the same word).',
           '* `!source` by file and line uses `GetAddrFromLineEx` (the core\'s `GetAddrFromLine` always returns 0). Source lines need a PDB with line info.',
           '* `!cfg` without `entry` uses the graph position announced by the core, else `cip`; the GUI\'s "last graph" cache is not kept.',
           '* `!callargs` knows only the x64 calling convention (`auto` / `x64`) in this 64-bit build.',
           '* `!strings`, `!calls`, `!ptrs` without `addr` search the region at `cip`: the natives use the disassembly selection, which the core announces asynchronously after a pause.',
           '* `!patch export` takes the patches of one module (the patch dialog does the same); several modules need the `module` argument.',
           '* `!nav` selections are single addresses (the core announces the start only).',
           '* `GetAddrFromLine`, `HandlesEnumHeaps` are core stubs; see the notes above. No core file was changed for them.']
    md_text = '\n'.join(md) + '\n'
    check = '--check' in sys.argv
    status = 0
    for path, data in ((OUT_MD, md_text), (OUT_CSV, csv_text)):
        raw = data.replace('\n', '\r\n').encode('utf-8')
        if check:
            cur = open(path, 'rb').read() if os.path.exists(path) else b''
            if cur != raw:
                print(os.path.basename(path), 'is out of date')
                status = 1
        else:
            with open(path, 'wb') as f:
                f.write(raw)
            print('wrote', path, len(raw), 'bytes')
    print('%d rows (%d action, %d class, %d menu), %d problem(s)' % (len(rows), sum(1 for r in rows if r[0] == 'action'), sum(1 for r in rows if r[0] == 'class'), sum(1 for r in rows if r[0] == 'menu'), len(problems)))
    for p in problems:
        print('  PROBLEM', p)
    return 1 if (problems or status) else 0
if __name__ == '__main__':
    sys.exit(main())
