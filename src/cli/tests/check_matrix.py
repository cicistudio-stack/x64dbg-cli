#!/usr/bin/env python3
"""Checks docs/cli/parity-matrix.csv against the GUI sources and the built x64dbg-cli.exe (AC-16, T27, T28).

Checks of the plain run (all of them must pass, exit 0; 1 = problems):
  A. every <action> id of the .ui files and every class of src/gui/Src/{Gui,Tracer,BasicView} has a row;
  B. every `!op` named by a row that is not Gap / UI is an op of the binary, and every other backticked word is either a native command (or
     alias) of the binary's `commands` op, a wildcard that matches commands, an op name, or listed in NOT_COMMANDS with a reason;
  C. every distinct native target (canonical command name) has exactly one line in src/cli/tests/native_smoke.csv (`name,args,expect`) and
     every line names a target of the matrix;
  D. rule N: the 29 `makeCommandAction(ui->actionX, "command")` statements of MainWindow.cpp are named by the `cli` cell of the row of
     actionX (the command or one of its aliases, plus a literal word argument such as `bak`), unless that row is Gap / UI;
  E. rule M (class level): the scan of src/gui/Src (scan_menus.py) finds >= 575 labels, every class with labels is covered by a `menu` row,
     and the number in parentheses of that row equals the labels found for the class;
  F. every gap id used by a row is documented in docs/cli/README.md.
Other modes:
  --targets    print the distinct native targets and their smoke lines
  --run        execute every smoke line once against a live debuggee (testprog.exe); expect ok | usage | skip:<reason>
  --negative   run the negative tests on copies of the inputs; each must exit 1
Options: --csv FILE, --smoke FILE (used by the negative tests).
Standard library only.
"""
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
sys.path.insert(0, HERE)
import gen_parity  # noqa: E402
import scan_menus  # noqa: E402

CSV_DEFAULT = os.path.join(ROOT, 'docs', 'cli', 'parity-matrix.csv')
SMOKE_DEFAULT = os.path.join(HERE, 'native_smoke.csv')
README = os.path.join(ROOT, 'docs', 'cli', 'README.md')
MAINWINDOW = os.path.join(ROOT, 'src', 'gui', 'Src', 'Gui', 'MainWindow.cpp')
EXE = os.path.join(ROOT, 'bin', 'x64', 'x64dbg-cli.exe')
PROG = os.path.join(ROOT, '.agents', 'tasks', 'cli', 'testprog', 'testprog.exe')
MIN_LABELS = 575
# Backticked words in the `cli` cell that are not commands. Anything else that is not a command, alias, op or wildcard fails check B.
NOT_COMMANDS = {
    # words of the response or of the arguments of an op
    'text': 'format name of `!mem`', 'uint': 'format name of `!mem`', 'hex': 'format name of `!eval`', 'label': 'field of a response',
    'name': 'argument name', 'value': 'argument name', 'start': 'argument name', 'end': 'argument name', 'addr': 'argument name',
    'limit': 'argument name', 'offset': 'argument name', 'branch': 'field of a `!dis` instruction', 'state': 'field of a response',
    'output': 'field of every response', 'tables': 'field of every response', 'To': 'GUI label word', 'bak': 'literal argument of `dbload bak`',
    'function.start': 'expression', 'DataByte..DataMiddle': 'range of the Data* commands, each is listed on its own',
    # names inside the cores or the GUI that are not commands
    'SetTraceRecordType': 'DbgFunctions entry; reached through `!trace set_type`', 'ModSetParty': 'DbgFunctions entry; reached through `!module set_party`',
    'CommonActions::setHwBpAt': 'GUI function name', 'setNewOriginHereActionSlot': 'GUI function name',
    'docs': 'directory name', 'commands': 'response field / `!commands` listing', 'batch': 'request form {"batch":[...]}, not an op',
}
STATUS_FREE = ('Gap', 'UI')


def load_rows(path):
    with open(path, encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))


def binary_info():
    """Return (ops set, {lower-case name or alias: canonical name}) from the built x64dbg-cli.exe."""
    ud = tempfile.mkdtemp(prefix='climatrix_')
    p = subprocess.Popen([EXE, '--json', '--userdir', ud], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    hello = json.loads(p.stdout.readline().decode('utf-8'))
    p.stdin.write(b'{"id":1,"op":"commands"}\n')
    p.stdin.flush()
    resp = json.loads(p.stdout.readline().decode('utf-8'))
    try:
        p.stdin.write(b'{"id":"q","op":"quit"}\n')
        p.stdin.flush()
        p.wait(timeout=30)
    except Exception:
        p.kill()
    shutil.rmtree(ud, ignore_errors=True)
    names = {}
    for c in resp['data']['commands']:
        for n in c['names']:
            names[n.lower()] = c['canonical']
    return set(hello['capabilities']['ops']), names


def spans_of(cell):
    """Words of a `cli` cell that are claimed to be native commands: first word of every backticked part, split at ' / ' and ','."""
    out = []
    for span in re.findall(r'`([^`]+)`', cell):
        if span.startswith('!'):
            continue
        for part in re.split(r'\s*/\s*|\s*,\s*', span):
            tok = part.strip().split(' ')[0].strip()
            if tok:
                out.append(tok)
    return out


def classify(tok, ops, names):
    """Return ('native', canonical) | ('ignore', reason) | ('unknown', tok)."""
    low = tok.lower()
    if low in names:
        return 'native', names[low]
    if tok.endswith('*') or '*' in tok:
        pat = re.compile('^' + re.escape(tok).replace('\\*', '.*') + '$', re.I)
        if any(pat.match(n) for n in names):
            return 'ignore', 'wildcard'
        return 'unknown', tok
    if tok in ops:
        return 'ignore', 'op name'
    if tok in NOT_COMMANDS:
        return 'ignore', NOT_COMMANDS[tok]
    if not re.match(r'^[A-Za-z]', tok) or re.search(r'[:<>\[\]()=.]', tok):
        return 'ignore', 'not a word'
    return 'unknown', tok


def native_targets(rows, ops, names):
    """Return ({canonical: [row ids]}, [problem])."""
    targets = {}
    problems = []
    for r in rows:
        if r['status'] in STATUS_FREE:
            continue
        for tok in spans_of(r['cli']):
            kind, val = classify(tok, ops, names)
            if kind == 'native':
                targets.setdefault(val, []).append(r['id'])
            elif kind == 'unknown':
                problems.append('%s %s: `%s` is not a command, alias or op of the binary (add it to NOT_COMMANDS only if it is prose)' % (r['kind'], r['id'], tok))
        for op in re.findall(r'`!([a-z_]+)', r['cli']):
            if op not in ops and op != 'help':
                problems.append('%s %s: `!%s` is not an op of the binary' % (r['kind'], r['id'], op))
    return targets, problems


def load_smoke(path):
    out = []
    with open(path, encoding='utf-8', newline='') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if not line or line.startswith('#'):
                continue
            row = next(csv.reader([line]))
            if row == ['name', 'args', 'expect']:
                continue
            if len(row) != 3:
                raise ValueError('bad native_smoke.csv line: ' + line)
            out.append(row)
    return out


def check_smoke(targets, smoke, names):
    problems = []
    seen = {}
    for name, _args, expect in smoke:
        low = name.lower()
        if low not in names:
            problems.append('native_smoke.csv: `%s` is not a command of the binary' % name)
            continue
        canon = names[low]
        if canon in seen:
            problems.append('native_smoke.csv: `%s` appears twice' % canon)
        seen[canon] = expect
        if not (expect in ('ok', 'usage') or (expect.startswith('skip:') and len(expect) > 5)):
            problems.append('native_smoke.csv: `%s` has the invalid expectation `%s`' % (name, expect))
        if canon not in targets:
            problems.append('native_smoke.csv: `%s` is not a native target of the matrix' % name)
    for canon in sorted(targets, key=str.lower):
        if canon not in seen:
            problems.append('native target `%s` (rows %s) has no line in native_smoke.csv' % (canon, ', '.join(targets[canon][:3])))
    return problems


def rule_n(rows, names):
    problems = []
    text = open(MAINWINDOW, encoding='utf-8', errors='replace').read()
    stmts = re.findall(r'makeCommandAction\(\s*ui->(\w+)\s*,\s*"([^"]*)"\s*\)\s*;', text)
    by_id = {r['id']: r for r in rows if r['kind'] == 'action'}
    if len(stmts) != 29:
        problems.append('rule N: found %d makeCommandAction(ui->action, "...") statements in MainWindow.cpp, expected 29' % len(stmts))
    aliases = {}
    for n, c in names.items():
        aliases.setdefault(c, set()).add(n)
    for aid, cmd in stmts:
        row = by_id.get(aid)
        if row is None:
            problems.append('rule N: %s (command "%s") has no action row' % (aid, cmd))
            continue
        if row['status'] in STATUS_FREE:
            continue
        words = cmd.split()
        canon = names.get(words[0].lower())
        if canon is None:
            problems.append('rule N: %s binds "%s", which is not a command of the binary' % (aid, cmd))
            continue
        alts = '|'.join(re.escape(a) for a in sorted(aliases[canon], key=len, reverse=True))
        lit = words[1] if len(words) > 1 and re.fullmatch(r'[A-Za-z]+', words[1]) else ''
        pat = r'(?<![\w!])(?:%s)(?![\w])' % alts
        if lit:
            pat += r'\s+' + re.escape(lit) + r'\b'
        if not re.search(pat, row['cli'], re.I):
            problems.append('rule N: the cli cell of %s must contain `%s` (or an alias): %s' % (aid, ' '.join([words[0]] + ([lit] if lit else [])), row['cli'][:80]))
    return problems, len(stmts)


def menu_counts(cell):
    """Parse the class cell of a menu row: [(class names, expected label count or None)]."""
    pairs = re.findall(r'(\w+) \((\d+)\)', cell)
    if len(pairs) >= 2 and not re.search(r'\d+ \+ \d+', cell):
        return [([n], int(c)) for n, c in pairs]
    m = re.search(r'\(([^)]*)\)', cell)
    names = [n.strip() for n in cell.split('(')[0].split(',') if n.strip()]
    if not m:
        return [(names, None)]
    inner = m.group(1)
    sm = re.search(r'(\d+(?:\s*\+\s*\d+)*)', inner.split(';')[-1] if ';' in inner and re.search(r'\d+\s*(\+|$)', inner.split(';')[-1]) else inner)
    if not sm:
        return [(names, None)]
    return [(names, sum(int(x) for x in re.split(r'\s*\+\s*', sm.group(1))))]


MENU_ALIASES = {'Disassembly': 'CPUDisassembly', 'Dump': 'CPUDump', 'Stack': 'CPUStack', 'Registers': 'CPURegistersView', 'Info box': 'CPUInfoBox'}


def rule_m(rows):
    problems = []
    found = scan_menus.scan()
    total = sum(len(v) for v in found.values())
    if total < MIN_LABELS:
        problems.append('rule M: the scan found %d menu labels, expected at least %d' % (total, MIN_LABELS))
    covered = {}
    cells = []
    for r in rows:
        if r['kind'] == 'menu' and r['id'] not in cells:
            cells.append(r['id'])
    for cell in cells:
        if cell in MENU_ALIASES:
            covered[MENU_ALIASES[cell]] = None
            continue
        for names, count in menu_counts(cell):
            for n in names:
                covered.setdefault(n, None)
            if count is not None:
                got = sum(len(found.get(n, [])) for n in names)
                if got != count:
                    problems.append('rule M: menu rows "%s" say %d entries, the scan of %s finds %d' % (cell[:60], count, ', '.join(names), got))
    for cls, labels in found.items():
        if cls not in covered:
            problems.append('rule M: class %s has %d context-menu labels and no `menu` row (for example "%s")' % (cls, len(labels), labels[0]))
    return problems, total, len(found)


def check_gaps(rows):
    text = open(README, encoding='utf-8').read()
    problems = []
    ids = set()
    for r in rows:
        ids.update(re.findall(r'G\d+', r['gap_id']))
    for g in sorted(ids, key=lambda s: int(s[1:])):
        if not re.search(r'\b%s\b' % g, text):
            problems.append('gap %s is used by a row and not documented in docs/cli/README.md' % g)
    return problems


def check(csv_path, smoke_path, quiet=False):
    rows = load_rows(csv_path)
    ops, names = binary_info()
    problems = []
    have_actions = {r['id'] for r in rows if r['kind'] == 'action'}
    for aid in gen_parity.gui_actions():
        if aid not in have_actions:
            problems.append('action id without a row: ' + aid)
    have_classes = set()
    for r in rows:
        if r['kind'] == 'class':
            have_classes.update(n.strip() for n in re.split(r',\s*', r['id']))
    for cname in gen_parity.gui_classes():
        if cname not in have_classes and not cname.startswith('ui_'):
            problems.append('class without a row: ' + cname)
    targets, p = native_targets(rows, ops, names)
    problems += p
    problems += check_smoke(targets, load_smoke(smoke_path), names)
    pn, nstmt = rule_n(rows, names)
    problems += pn
    pm, nlabels, nclasses = rule_m(rows)
    problems += pm
    problems += check_gaps(rows)
    if not quiet:
        print('%d rows, %d native targets, %d smoke lines, %d makeCommandAction statements, %d menu labels in %d classes' %
              (len(rows), len(targets), len(load_smoke(smoke_path)), nstmt, nlabels, nclasses))
        for p in problems:
            print('  PROBLEM', p)
        print('matrix check: %s (%d problem(s))' % ('FAILED' if problems else 'ok', len(problems)))
    return problems


def negative():
    """Five copies that must fail: a removed action row, a removed menu group, a wrong rule-N cell, an invented command, a removed smoke line."""
    rows = load_rows(CSV_DEFAULT)
    smoke_text = open(SMOKE_DEFAULT, encoding='utf-8', newline='').read()
    fields = list(rows[0].keys())
    cases = []

    def write_csv(d, rs, name):
        p = os.path.join(d, name)
        with open(p, 'w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fields, lineterminator='\n')
            w.writeheader()
            w.writerows(rs)
        return p
    with tempfile.TemporaryDirectory() as d:
        # (1) remove the row of an action id
        c1 = [r for r in rows if r['id'] != 'actionBookmarks']
        cases.append(('remove the row of actionBookmarks', write_csv(d, c1, 'c1.csv'), SMOKE_DEFAULT, 'action id without a row: actionBookmarks'))
        # (2) change the cli cell of actionDbrecovery to `dbload`
        c2 = [dict(r, cli='`dbload`') if r['id'] == 'actionDbrecovery' else r for r in rows]
        cases.append(('actionDbrecovery names `dbload` only', write_csv(d, c2, 'c2.csv'), SMOKE_DEFAULT, 'rule N: the cli cell of actionDbrecovery'))
        # (3) remove the menu rows of LogView
        c3 = [r for r in rows if not (r['kind'] == 'menu' and r['id'].startswith('LogView'))]
        cases.append(('remove the LogView menu rows', write_csv(d, c3, 'c3.csv'), SMOKE_DEFAULT, 'rule M: class LogView'))
        # (4) a Full row names a command that does not exist
        c4 = [dict(r, cli=r['cli'] + ' / `NoSuchCommandXyz`') if r['id'] == 'actionStepOver' else r for r in rows]
        cases.append(('invented native command in a Full row', write_csv(d, c4, 'c4.csv'), SMOKE_DEFAULT, 'NoSuchCommandXyz'))
        # (5) remove one smoke line
        s5 = os.path.join(d, 's5.csv')
        lines = smoke_text.split('\n')
        victim = next(l for l in lines if l.lower().startswith('imageinfo,'))
        with open(s5, 'w', encoding='utf-8', newline='') as f:
            f.write('\n'.join(l for l in lines if l != victim))
        cases.append(('remove the smoke line of imageinfo', CSV_DEFAULT, s5, 'native target `imageinfo`'))
        bad = 0
        for name, cpath, spath, expect in cases:
            r = subprocess.run([sys.executable, os.path.abspath(__file__), '--csv', cpath, '--smoke', spath], capture_output=True, text=True)
            hit = r.returncode == 1 and expect in r.stdout
            print('negative test (%s): exit %d, %s' % (name, r.returncode, 'names "%s"' % expect if hit else 'MISSING expected message'))
            if not hit:
                bad += 1
                print(r.stdout[-600:])
    print('negative tests: %d of %d failed as expected' % (len(cases) - bad, len(cases)))
    return 1 if bad else 0


def run_smoke(smoke_path):
    sys.path.insert(0, HERE)
    from m1_acceptance import Cli
    smoke = load_smoke(smoke_path)
    ops, names = binary_info()
    c = Cli('m3-native-smoke')
    c.hello()
    counter = [0]
    state = {'ok': False, 'cip': None}

    def req(obj, timeout=60):
        counter[0] += 1
        obj = dict(obj)
        obj['id'] = counter[0]
        return c.request(obj, timeout)

    def session():
        req({'cmd': 'stop'}, 30)
        r = req({'op': 'init', 'args': {'file': PROG}})
        if not (isinstance(r, dict) and r.get('ok')):
            raise RuntimeError('init failed: %r' % (r,))
        r = req({'op': 'bp', 'args': {'action': 'add', 'target': 'testprog.compute'}})
        r = req({'op': 'run'})
        if not (isinstance(r, dict) and r.get('ok') and r['state']['status'] == 'paused'):
            raise RuntimeError('run to compute failed: %r' % (r,))
        state['cip'] = r['state']['cip']
        state['ok'] = True
        req({'cmd': 'disasm testprog.compute'})
    results = []
    fails = 0
    tmp = tempfile.mkdtemp(prefix='clismoke_')
    with open(os.path.join(tmp, 'smoke_script.txt'), 'w') as f:
        f.write('log smoke script\nret\n')
    with open(os.path.join(tmp, 'smoke_types.h'), 'w') as f:
        f.write('struct SMOKE_T { int a; int b; };\n')
    try:
        for name, args, expect in smoke:
            if expect.startswith('skip:'):
                results.append((name, expect, 'skipped'))
                print('  SKIP %-34s %s' % (name, expect[5:]))
                continue
            if not state['ok']:
                session()
            args = args.replace('{tmp}', tmp).replace('{prog}', os.path.splitext(PROG)[0] + '.pdb')
            line = args[1:] if args.startswith('=') else (name + ' ' + args).strip()
            pid_before = (req({'op': 'status'}, 30) or {}).get('state', {}).get('pid')
            r = req({'cmd': line, 'timeout_ms': 15000}, 60)
            st = r.get('state', {}) if isinstance(r, dict) else {}
            if isinstance(r, dict) and st.get('status') == 'running':
                r2 = req({'op': 'pause'}, 30)
                st = r2.get('state', {}) if isinstance(r2, dict) else {}
            got = 'timeout' if not isinstance(r, dict) else ('ok' if r.get('ok') else ('usage' if (r.get('error') or {}).get('code') == 'E_COMMAND_FAILED' else 'error:' + str((r.get('error') or {}).get('code'))))
            good = got == expect
            if not good:
                fails += 1
            msg = '' if good else ((r.get('error') or {}).get('message', '') if isinstance(r, dict) else str(r))[:120]
            print('  %s %-34s expect %-6s got %-6s %s' % ('PASS' if good else 'FAIL', line[:34], expect, got, msg))
            results.append((name, expect, got))
            if st.get('status') != 'paused' or st.get('cip') != state['cip']:
                state['ok'] = False
            if not st.get('debugging') and pid_before:   # detach leaves the debuggee running: no orphan may remain
                subprocess.run(['taskkill', '/f', '/pid', str(pid_before)], capture_output=True)
        req({'cmd': 'stop'}, 30)
    finally:
        rc = c.quit()
        shutil.rmtree(tmp, ignore_errors=True)
    print('smoke: %d lines, %d ok/usage as expected, %d skipped, %d failed; CLI exit %s' % (
        len(smoke), sum(1 for x in results if x[2] not in ('skipped',) and x[1] == x[2]), sum(1 for x in results if x[2] == 'skipped'), fails, rc))
    return 1 if fails or rc != 0 else 0


def main():
    argv = sys.argv[1:]
    csv_path, smoke_path = CSV_DEFAULT, SMOKE_DEFAULT
    if '--csv' in argv:
        csv_path = argv[argv.index('--csv') + 1]
    if '--smoke' in argv:
        smoke_path = argv[argv.index('--smoke') + 1]
    if '--negative' in argv:
        return negative()
    if '--targets' in argv:
        rows = load_rows(csv_path)
        ops, names = binary_info()
        targets, _p = native_targets(rows, ops, names)
        smoke = {names.get(n.lower(), n): (a, e) for n, a, e in load_smoke(smoke_path)}
        for t in sorted(targets, key=str.lower):
            print('%-34s %-8s %s' % (t, smoke.get(t, ('', 'NONE'))[1], ','.join(targets[t][:3])))
        print('%d distinct native targets' % len(targets))
        return 0
    if '--run' in argv:
        return run_smoke(smoke_path)
    return 1 if check(csv_path, smoke_path) else 0


if __name__ == '__main__':
    sys.exit(main())
