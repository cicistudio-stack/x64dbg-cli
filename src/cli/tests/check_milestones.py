#!/usr/bin/env python3
"""Consistency check between the milestone tags of docs/cli/milestones.md (the shipped extract of the design).

Compares three sources inside the document:
  1. the [Mn] brackets of the acceptance criteria (design 2.4),
  2. the M column of the test table (design 12.2),
  3. the machine-readable gate lines of design 14, written as
         - `M1.ac = 1-12,17-23,25`
         - `M1.tests = T0-T20,T30`
Every AC / test must be in the gate of exactly the milestones named by its tag, and every gate entry must exist.
Fourth check: every `!op` token and every "op":"op" token inside an AC or a test row must name an op whose
milestone in the op index (design 9.1) is not later than the milestone of that AC / test.

Usage: check_milestones.py [path]               default input: docs/cli/milestones.md
       check_milestones.py --selftest-negative  runs the two negative copies (AC-34 in the M1 gate; an M2 op in T4)
Exit code 0 = consistent, 1 = mismatch, 2 = usage.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
DEFAULT = os.path.join(ROOT, 'docs', 'cli', 'milestones.md')


def expand_ac(spec):
    out = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r'(\d+)-(\d+)', part)
        if m:
            out.update(range(int(m.group(1)), int(m.group(2)) + 1))
        elif part.isdigit():
            out.add(int(part))
        else:
            raise ValueError('bad AC item %r' % part)
    return out


def tkey(t):
    m = re.fullmatch(r'T(\d+)([a-z]?)', t)
    return (int(m.group(1)), m.group(2))


def expand_tests(spec, all_tests):
    out = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r'(T\d+[a-z]?)-(T\d+[a-z]?)', part)
        if m:
            lo, hi = tkey(m.group(1)), tkey(m.group(2))
            out.update(t for t in all_tests if lo <= tkey(t) <= hi)
        elif re.fullmatch(r'T\d+[a-z]?', part):
            out.add(part)
        else:
            raise ValueError('bad test item %r' % part)
    return out


def op_index(text):
    """Return {op: 'Mn'} from the 'Op index (milestone, precondition)' table of design 9.1."""
    sec = text.split('Op index (milestone, precondition):')[1].split('\n### ')[0]
    ops = {}
    for m in re.finditer(r'^\| (M\d) \| (.*) \|$', sec, re.M):
        ms, cell = m.group(1), m.group(2)
        w = re.search(r'wrappers `([a-z ]+)`', cell)
        if w:
            for o in w.group(1).split():
                ops.setdefault(o, ms)
            cell = cell.replace(w.group(0), '')
        for o in re.findall(r'`([a-z_]+)`', cell):
            ops.setdefault(o, ms)
    return ops


OP_TOKEN = re.compile(r'(?<![!\w])!([a-z][a-z0-9_]*)|"op"\s*:\s*"([a-z][a-z0-9_]*)"')


def check_ops(text, ac_tags, t_tags):
    ops = op_index(text)
    errors = []
    if not ops:
        return ['could not parse the op index of design 9.1']
    rows = []
    for m in re.finditer(r'^\d+\. \*\*AC-(\d+) [^\n]*$', text, re.M):
        n = int(m.group(1))
        if n in ac_tags:
            rows.append(('AC-%d' % n, min(ac_tags[n]), m.group(0)))
    for m in re.finditer(r'^\| (T\d+[a-z]?) \| (M\d)\+? \|[^\n]*$', text, re.M):
        rows.append((m.group(1), m.group(2), m.group(0)))
    for name, ms, line in rows:
        for m in OP_TOKEN.finditer(line):
            op = m.group(1) or m.group(2)
            if op in ops and ops[op] > ms:
                errors.append('%s (%s) uses op %s of milestone %s' % (name, ms, op, ops[op]))
    return errors


def check(path):
    with open(path, encoding='utf-8') as f:
        text = f.read().replace('\r\n', '\n')
    ac_tags = {}
    for m in re.finditer(r'^\d+\. \*\*AC-(\d+) [^*\n]*?\[(M\d(?:/M\d)*)\][^*\n]*\*\*', text, re.M):
        ac_tags[int(m.group(1))] = set(m.group(2).split('/'))
    t_tags = {}
    for m in re.finditer(r'^\| (T\d+[a-z]?) \| (M\d)\+? \|', text, re.M):
        t_tags[m.group(1)] = {m.group(2)}
    gates = {}
    for m in re.finditer(r'^- `(M\d)\.(ac|tests) = ([^`]*)`', text, re.M):
        gates[(m.group(1), m.group(2))] = m.group(3)
    errors = []
    if not ac_tags or not t_tags or not gates:
        errors.append('could not parse: %d ACs, %d tests, %d gate lines' % (len(ac_tags), len(t_tags), len(gates)))
    milestones = sorted({k[0] for k in gates} | {'M1', 'M2', 'M3', 'M4'})
    for ms in milestones:
        for kind in ('ac', 'tests'):
            if (ms, kind) not in gates:
                errors.append('missing gate line %s.%s' % (ms, kind))
    if not errors:
        for ms in milestones:
            gate_ac = expand_ac(gates[(ms, 'ac')]) if gates[(ms, 'ac')].strip() != 'none' else set()
            gate_t = expand_tests(gates[(ms, 'tests')], t_tags.keys()) if gates[(ms, 'tests')].strip() != 'none' else set()
            for n in sorted(gate_ac - set(ac_tags)):
                errors.append('%s.ac lists AC-%d which does not exist' % (ms, n))
            for t in sorted(gate_t - set(t_tags), key=tkey):
                errors.append('%s.tests lists %s which does not exist' % (ms, t))
            for n, tags in sorted(ac_tags.items()):
                if (ms in tags) != (n in gate_ac):
                    errors.append('AC-%d is tagged %s but %s the %s gate' % (n, '/'.join(sorted(tags)), 'missing from' if ms in tags else 'listed in', ms))
            for t, tags in sorted(t_tags.items(), key=lambda kv: tkey(kv[0])):
                if (ms in tags) != (t in gate_t):
                    errors.append('%s is tagged %s but %s the %s gate' % (t, '/'.join(sorted(tags)), 'missing from' if ms in tags else 'listed in', ms))
    errors.extend(check_ops(text, ac_tags, t_tags))
    for e in errors:
        print('FAIL:', e)
    if not errors:
        print('OK: %d acceptance criteria, %d tests, %d gate lines consistent' % (len(ac_tags), len(t_tags), len(gates)))
    return 1 if errors else 0


def negative():
    """Two temp copies must fail with the expected message; the real file is not touched."""
    with open(DEFAULT, encoding='utf-8') as f:
        text = f.read()
    copy1 = re.sub(r'(- `M1\.ac = [^`]*)`', r'\1,34`', text, count=1)
    copy2 = re.sub(r'(?m)^(\| T4 \| M1 \|[^\n]*)$', r'\1 !regs', text, count=1)
    bad = 0
    for name, body, expect in (('AC-34 in the M1 gate', copy1, 'AC-34'), ('M2 op regs in T4', copy2, 'T4 (M1) uses op regs of milestone M2')):
        assert body != text, 'negative copy was not modified: ' + name
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'milestones.md')
            with open(p, 'w', encoding='utf-8', newline='\n') as f:
                f.write(body)
            r = subprocess.run([sys.executable, os.path.abspath(__file__), p], capture_output=True, text=True)
        hit = r.returncode == 1 and expect in r.stdout
        print('negative copy (%s): exit %d, %s' % (name, r.returncode, 'names "%s"' % expect if hit else 'MISSING expected message'))
        if not hit:
            bad += 1
    return 1 if bad else 0


if __name__ == '__main__':
    if '--selftest-negative' in sys.argv:
        sys.exit(negative())
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if len(args) > 1:
        print(__doc__)
        sys.exit(2)
    sys.exit(check(args[0] if args else DEFAULT))
