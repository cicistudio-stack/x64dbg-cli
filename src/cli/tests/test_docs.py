#!/usr/bin/env python3
"""Checks the docs of x64dbg-cli (docs/cli): required sections, links, transcript files, op coverage, generated files up to date,
that the shipped example client works, and (T29) that the README examples are real:

* every fenced block tagged `transcript <file>` has requests that exist in the stored transcript and response keys that occur in it;
* every stored transcript named by such a block is replayed against the built binary with a fresh debuggee and compared with the stored
  responses: `ok`, `error.code`, `state.status` and the key / type structure of `data` modulo ids, addresses, pids and list lengths
  (text mode: the `@@END` status of every request and the `key:` lines of the ops);
* the block tagged `python run` is executed unchanged from the repository root;
* the block tagged `transcript m3-client-demo.txt` is a subsequence of the output of examples/client.py, modulo numbers.
Standard library only. Usage: python src/cli/tests/test_docs.py        exit 0 when every check passed
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import m1_acceptance as acc  # noqa: E402
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
DOCS = os.path.join(ROOT, 'docs', 'cli')
TRANSCRIPTS = os.path.join(ROOT, '.agents', 'tasks', 'cli', 'transcripts')
EXE = os.path.join(ROOT, 'bin', 'x64', 'x64dbg-cli.exe')
TARGET = os.path.join(ROOT, 'bin', 'x64', 'tests', 'cli_target.exe')
RESULTS = []
def ck(name, cond, detail=''):
    RESULTS.append((name, bool(cond), detail))
    print(('  PASS ' if cond else '  FAIL ') + name + ('' if cond else '  -> ' + str(detail)[:600]))
def read(name):
    return open(os.path.join(DOCS, name), encoding='utf-8').read().replace('\r\n', '\n')
# ------------------------------------------------------------------ helpers for T29
def fence_blocks(text):
    """Return [(tag, argument, body)] for every fenced block with an info string."""
    return [(m.group(1), (m.group(2) or '').strip(), m.group(3)) for m in re.finditer(r'(?ms)^```(\w+)[ \t]*([^\n]*)\n(.*?)^```[ \t]*$', text)]
def fix_paths(s):
    """Stored transcripts name files below the repository of the recording; map them to this checkout."""
    return re.sub(r'(?i)[a-z]:\\[^"\s]*?\\x64dbg-ai', lambda m: ROOT.replace('\\', '\\\\') if '\\\\' in m.group(0) else ROOT, s)
def load_transcript(name):
    reqs, resps, text = [], {}, ''
    with open(os.path.join(TRANSCRIPTS, name), encoding='utf-8') as f:
        text = f.read()
    for line in text.split('\n'):
        if line.startswith('> '):
            reqs.append(line[2:])
        elif line.startswith('< {"type":"response"'):
            o = json.loads(line[2:])
            resps[json.dumps(o.get('id'))] = o
    return reqs, resps, text
def kind(v):
    if isinstance(v, bool):
        return 'bool'
    if isinstance(v, (int, float)):
        return 'number'
    return type(v).__name__
def shape_diff(a, b, path='data'):
    """Differences in key / type structure; None matches anything, empty lists match any list, only the first list element is compared."""
    if a is None or b is None:
        return []
    if isinstance(a, dict) and isinstance(b, dict):
        if set(a) != set(b):
            return ['%s: keys %s != %s' % (path, sorted(a), sorted(b))]
        out = []
        for k in a:
            out += shape_diff(a[k], b[k], path + '.' + k)
        return out
    if isinstance(a, list) and isinstance(b, list):
        return [] if not a or not b else shape_diff(a[0], b[0], path + '[0]')
    return [] if kind(a) == kind(b) else ['%s: %s != %s' % (path, kind(a), kind(b))]
def resp_diff(old, new):
    if not isinstance(new, dict):
        return ['no response (%r)' % (new,)]
    out = []
    if old.get('ok') != new.get('ok'):
        out.append('ok %r != %r' % (old.get('ok'), new.get('ok')))
    if (old.get('error') or {}).get('code') != (new.get('error') or {}).get('code'):
        out.append('error.code %r != %r' % ((old.get('error') or {}).get('code'), (new.get('error') or {}).get('code')))
    if (old.get('state') or {}).get('status') != (new.get('state') or {}).get('status'):
        out.append('state.status %r != %r' % ((old.get('state') or {}).get('status'), (new.get('state') or {}).get('status')))
    out += shape_diff(old.get('data'), new.get('data'))
    if 'results' in old or 'results' in new:
        o, n = old.get('results') or [], new.get('results') or []
        if len(o) != len(n):
            out.append('results: %d != %d entries' % (len(o), len(n)))
        for i, (x, y) in enumerate(zip(o, n)):
            out += ['results[%d] %s' % (i, d) for d in resp_diff(x, y)]
    return out
def replay_json(name):
    reqs, resps, _ = load_transcript(name)
    diffs = []
    old = acc.TRANSCRIPTS
    tmp = tempfile.mkdtemp(prefix='cli_replay_')
    acc.TRANSCRIPTS = tmp
    c = acc.Cli('replay-' + os.path.splitext(name)[0])
    try:
        h = c.hello()
        if not isinstance(h, dict):
            return ['no hello line']
        for raw in reqs:
            req = json.loads(fix_paths(raw))
            rid = req.get('id')
            c.send(req)
            if req.get('op') == 'quit':
                break
            new = c.wait_response(rid, 120)
            time.sleep(0.3)   # the core announces selections (disasm) asynchronously
            stored = resps.get(json.dumps(rid))
            if stored is not None:
                diffs += ['request %s: %s' % (json.dumps(rid), d) for d in resp_diff(stored, new)]
            elif not isinstance(new, dict):
                diffs.append('request %s: no response' % json.dumps(rid))
        try:
            rc = c.p.wait(timeout=40)
        except subprocess.TimeoutExpired:
            rc = 'did not exit'
        if rc != 0:
            diffs.append('exit code %r' % (rc,))
    finally:
        c.p.kill() if c.p.poll() is None else None
        c.close()
        acc.TRANSCRIPTS = old
        shutil.rmtree(tmp, ignore_errors=True)
    return diffs
KEYLINE = re.compile(r'^([A-Za-z_][\w ]*):( |$)|^table \d+ "')
def text_blocks(lines):
    """Split a text-mode transcript into [(request, status, keylines)]. lines are the raw stored / live lines without the '< ' prefix."""
    blocks = []
    cur = None
    for l in lines:
        if l.startswith('> '):
            cur = [l[2:], None, []]
            blocks.append(cur)
        elif cur is not None:
            if l.startswith('@@END'):
                cur[1] = l.split()[2] if len(l.split()) > 2 else '?'
            elif not l.startswith('@@EVENT') and cur[0].startswith('!') and KEYLINE.match(l):
                cur[2].append(l.split(':')[0] if not l.startswith('table') else 'table')
    return blocks
def replay_text(name):
    _, _, text = load_transcript(name)
    stored_lines = [l[2:] if l.startswith('< ') else l for l in text.split('\n') if l]
    stored = text_blocks([fix_paths(l) for l in stored_lines])
    old = acc.TRANSCRIPTS
    tmp = tempfile.mkdtemp(prefix='cli_replay_')
    acc.TRANSCRIPTS = tmp
    c = acc.Cli('replay-' + os.path.splitext(name)[0], json_mode=False)
    live = []
    diffs = []
    try:
        ready = c.next_line(40)
        if not (ready or '').startswith('@@READY'):
            return ['no @@READY line: %r' % (ready,)]
        for req, status, keys in stored:
            live.append('> ' + req)
            c.send_raw(req + '\n')
            end = time.time() + 120
            while time.time() < end:
                l = c.next_line(5)
                if l == 'TIMEOUT':
                    continue
                if l is None:
                    break
                live.append(l)
                if l.startswith('@@END'):
                    break
            time.sleep(0.3)
        try:
            rc = c.p.wait(timeout=(40 if stored and stored[-1][0].strip() == '!quit' else 1))
        except subprocess.TimeoutExpired:
            rc = None
        got = text_blocks(live)
        for (req, st, keys), (_r, st2, keys2) in zip(stored, got):
            if st2 is None:
                diffs.append('%r: no @@END' % req)
            elif st != st2:
                diffs.append('%r: @@END %s != %s' % (req, st, st2))
            if keys != keys2:
                diffs.append('%r: key lines %s != %s' % (req, keys, keys2))
        if len(got) < len(stored):
            diffs.append('only %d of %d requests answered' % (len(got), len(stored)))
        if rc not in (0, None):
            diffs.append('exit code %r' % (rc,))
    finally:
        c.p.kill() if c.p.poll() is None else None
        c.close()
        acc.TRANSCRIPTS = old
        shutil.rmtree(tmp, ignore_errors=True)
    return diffs
def parse_requests(body):
    """JSON objects after '> ' in a README block (several per line allowed, trailing prose ignored)."""
    dec = json.JSONDecoder()
    out = []
    for line in body.split('\n'):
        if not line.startswith('> '):
            continue
        s = line[2:]
        while s:
            s = s.lstrip()
            try:
                obj, end = dec.raw_decode(s)
            except ValueError:
                break
            if not isinstance(obj, dict):
                break
            out.append(obj)
            s = s[end:]
    return out
def has_dots(v):
    return isinstance(v, str) and '...' in v
def request_matches(doc, stored):
    """The README request is the stored one (ids ignored); values with '...' are abbreviations and always match."""
    for k, v in doc.items():
        if k == 'id':
            continue
        if k not in stored:
            return False
        if isinstance(v, dict) and isinstance(stored[k], dict):
            if not request_matches(v, stored[k]):
                return False
        elif isinstance(v, list) and isinstance(stored[k], list):
            if len(v) != len(stored[k]) or not all((request_matches(a, b) if isinstance(a, dict) and isinstance(b, dict) else a == b) for a, b in zip(v, stored[k])):
                return False
        elif not has_dots(v) and v != stored[k]:
            return False
    return True
def check_fence(tag_file, body):
    """Return the problems of one README block against its stored transcript."""
    problems = []
    if tag_file.endswith('.txt'):
        return problems
    reqs, resps, text = load_transcript(tag_file)
    if '@@READY' in text or any(l.startswith('> !') for l in body.split('\n')):   # text mode block
        stored = [fix_paths(r).strip() for r in reqs]
        for line in body.split('\n'):
            if line.startswith('> '):
                pat = re.compile('^' + re.escape(line[2:].strip()).replace('\\.\\.\\.', '.*') + '$', re.I)
                if not any(pat.match(s) for s in stored):
                    problems.append('request not in the stored transcript: ' + line[:80])
        return problems
    stored_reqs = [json.loads(fix_paths(r)) for r in reqs]
    for doc in parse_requests(body):
        if not any(request_matches(doc, s) for s in stored_reqs):
            problems.append('request not in the stored transcript: ' + json.dumps(doc)[:100])
    stored_keys = set(re.findall(r'"(\w+)":', text))
    shown = set()
    for line in body.split('\n'):
        if not line.startswith('> '):
            shown |= set(re.findall(r'"(\w+)":', line))
        elif '<' in line:
            shown |= set(re.findall(r'"(\w+)":', line.split(' < ', 1)[1] if ' < ' in line else ''))
    for k in sorted(shown - stored_keys):
        problems.append('response key "%s" does not occur in the stored transcript' % k)
    return problems
def norm_numbers(s):
    return re.sub(r'\b\d+\b', 'N', re.sub(r'0x[0-9a-fA-F]+', '0xH', s))
def main():
    readme = read('README.md')
    guide = read('agent-guide.md')
    # ---- sections of FR-8
    for h in ('## Usage', '## Text mode', '## JSON-lines protocol', '## Commands', '## Parity with the GUI', '## AI tool integration', '## Real transcripts', '## Build'):
        ck('README has the section "%s"' % h, re.search(r'(?m)^' + re.escape(h), readme) is not None)
    ck('README documents the explicit gaps and names the trace browser as not implemented', 'G2' in readme and 'not implemented' in readme.lower() and 'Trace browser' in readme)
    # ---- links
    bad = []
    for doc, text in (('README.md', readme), ('agent-guide.md', guide)):
        for m in re.finditer(r'\]\(([^)#]+)\)', text):
            target = m.group(1)
            if '://' in target:
                continue
            if not os.path.exists(os.path.join(DOCS, target)):
                bad.append((doc, target))
    ck('every relative link of README and agent-guide resolves', not bad, bad)
    # ---- transcripts named in the README exist and consist of valid JSON lines
    names = sorted(set(re.findall(r'`((?:m\d)-[\w.-]+\.(?:jsonl|txt))`', readme)))
    missing = [n for n in names if not os.path.exists(os.path.join(TRANSCRIPTS, n))]
    ck('README names %d transcript files and all exist' % len(names), len(names) >= 6 and not missing, missing)
    badjson = []
    for n in names:
        if n.endswith('.jsonl') and 'text' not in n:  # text mode transcripts are not JSON
            for line in open(os.path.join(TRANSCRIPTS, n), encoding='utf-8'):
                if line.startswith('< '):
                    try:
                        json.loads(line[2:])
                    except ValueError:
                        if not line[2:].startswith('@@'):
                            badjson.append((n, line[:60]))
    ck('every response line of the named JSON transcripts parses', not badjson, badjson[:3])
    # ---- op coverage and counts
    p = subprocess.Popen([EXE, '--json', '--userdir', os.path.join(os.environ.get('TEMP', '.'), 'clitest_docs')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    hello = json.loads(p.stdout.readline().decode('utf-8'))
    p.stdin.write(b'{"id":"q","op":"quit"}\n')
    p.stdin.flush()
    p.wait(timeout=30)
    ops = hello['capabilities']['ops']
    ck('README mentions every op (%d) in backticks' % len(ops), all('`%s`' % o in readme for o in ops), [o for o in ops if '`%s`' % o not in readme])
    counts = set()
    for m in re.finditer(r'(\d+) structured \*\*ops\*\*|the (\d+) ops are listed|x64dbg_<op>` \((\d+) of them\)', readme + guide):
        counts.update(int(g) for g in m.groups() if g)
    ck('op counts quoted in the docs equal the binary (%d)' % len(ops), counts == {len(ops)}, (counts, len(ops)))
    ck('native command count quoted in the README equals the binary (%d)' % hello['capabilities']['native_commands'], ('%d native commands' % hello['capabilities']['native_commands']) in readme or ('the %d native' % hello['capabilities']['native_commands']) in readme, hello['capabilities']['native_commands'])
    # ---- generated files
    for script in ('gen_docs.py', 'gen_parity.py'):
        r = subprocess.run([sys.executable, '-B', os.path.join(HERE, script), '--check'], capture_output=True, text=True)
        ck('%s --check: generated files are up to date' % script, r.returncode == 0, (r.stdout + r.stderr)[-400:])
    # ---- the shipped example client works
    r = subprocess.run([sys.executable, '-B', os.path.join(DOCS, 'examples', 'client.py'), EXE, TARGET, 'call'], capture_output=True, text=True, timeout=180)
    out = r.stdout
    ck('examples/client.py runs the demo session (exit 0)', r.returncode == 0, (out + r.stderr)[-500:])
    ck('demo: stops at the Sleep breakpoint, shows registers, live disassembly, stack, call stack, and the disassembly after stepout',
       'stopped: paused' in out and 'rip = 0x' in out and '=>0x' in out and 'stack 0x' in out and 'call stack: kernel32.Sleep' in out and 'after stepout:' in out and '(is_cip=True)' in out, out[-500:])
    # ---- T29: the tagged blocks of the README
    blocks = fence_blocks(readme)
    tagged = [(arg, body) for tag, arg, body in blocks if tag == 'transcript']
    files = []
    for arg, body in tagged:
        if arg not in files:
            files.append(arg)
    ck('README has %d blocks tagged `transcript <file>` for %d stored transcripts' % (len(tagged), len(files)), len(tagged) >= 8 and len(files) >= 8, files)
    heads = re.findall(r'(?m)^### \d+\. .*`((?:m\d)-[\w.-]+\.(?:jsonl|txt))`\s*$', readme)
    ck('every "### n." heading of "Real transcripts" names a tagged transcript', heads and all(h in files for h in heads), [h for h in heads if h not in files])
    for arg, body in tagged:
        ck('block %s: its requests and response keys exist in the stored transcript' % arg, not check_fence(arg, body) if os.path.exists(os.path.join(TRANSCRIPTS, arg)) else False, check_fence(arg, body)[:3] if os.path.exists(os.path.join(TRANSCRIPTS, arg)) else 'missing file')
    demo = [body for arg, body in tagged if arg == 'm3-client-demo.txt']
    if demo:
        actual = [norm_numbers(l.strip()) for l in out.split('\n') if l.strip()]
        shown = [norm_numbers(l.strip()) for l in demo[0].split('\n') if l.strip()]
        i = 0
        for l in actual:
            if i < len(shown) and l == shown[i]:
                i += 1
        ck('demo output block of the README is a subsequence of the live output of client.py (modulo numbers)', i == len(shown), shown[i:i + 2])
    stored_demo = open(os.path.join(TRANSCRIPTS, 'm3-client-demo.txt'), encoding='utf-8').read().split('\n')
    ck('stored m3-client-demo.txt has the same lines as the live output (modulo numbers)', [norm_numbers(l.strip()) for l in stored_demo if l.strip()] == [norm_numbers(l.strip()) for l in out.split('\n') if l.strip()])
    for f in files:
        if f.endswith('.jsonl'):
            text_mode = '@@READY' in open(os.path.join(TRANSCRIPTS, f), encoding='utf-8').read()
            t0 = time.time()
            d = replay_text(f) if text_mode else replay_json(f)
            ck('replay %s (%s mode) against a fresh debuggee matches the stored responses (%.0f s)' % (f, 'text' if text_mode else 'json', time.time() - t0), not d, d[:4])
    # ---- the Python loop of the README runs unchanged
    py = [body for tag, arg, body in blocks if tag == 'python' and arg == 'run']
    ck('README has one python block tagged `run`', len(py) == 1)
    if py:
        ud = tempfile.mkdtemp(prefix='cli_readme_')
        src = py[0].replace('"--json"]', '"--json", "--userdir", r"%s"]' % ud, 1) + '\np.stdin.close(); p.wait(timeout=60)\n'
        f = os.path.join(ud, 'readme_loop.py')
        open(f, 'w', encoding='utf-8').write(src)
        r = subprocess.run([sys.executable, '-B', f], cwd=ROOT, capture_output=True, text=True, timeout=180)
        shutil.rmtree(ud, ignore_errors=True)
        ck('README python loop: runs from the repository root, prints the stop at Sleep', r.returncode == 0 and r.stdout.startswith('paused') and 'Sleep' in r.stdout, (r.stdout + r.stderr)[-400:])
    # ---- negative controls: the comparisons really detect drift
    ck('negative control: a renamed data key, a changed error code and a changed type are reported',
       resp_diff({'ok': True, 'data': {'a': 1}}, {'ok': True, 'data': {'b': 1}}) and resp_diff({'ok': False, 'error': {'code': 'E_A'}}, {'ok': False, 'error': {'code': 'E_B'}})
       and resp_diff({'ok': True, 'data': {'a': 1}}, {'ok': True, 'data': {'a': 'x'}}) and not resp_diff({'ok': True, 'data': {'a': [1, 2]}}, {'ok': True, 'data': {'a': []}}))
    one = next((body for arg, body in tagged if arg == 'm3-readme-views.jsonl'), '')
    ck('negative control: a README block with a changed request or an unknown response key fails the stored-transcript check',
       bool(check_fence('m3-readme-views.jsonl', one.replace('"op":"tcp"', '"op":"tcpx"'))) and bool(check_fence('m3-readme-views.jsonl', one.replace('"connections"', '"conns"'))))
    left = subprocess.run(['tasklist', '/fo', 'csv', '/nh'], capture_output=True, text=True).stdout.lower()
    ck('no orphan cli_target.exe / testprog.exe / x64dbg-cli.exe process remains', not any(n in left for n in ('cli_target.exe', 'testprog.exe', 'x64dbg-cli.exe')), [n for n in ('cli_target.exe', 'testprog.exe', 'x64dbg-cli.exe') if n in left])
    failed = [r for r in RESULTS if not r[1]]
    print('\n%d checks, %d failed' % (len(RESULTS), len(failed)))
    return 1 if failed else 0
if __name__ == '__main__':
    sys.exit(main())
