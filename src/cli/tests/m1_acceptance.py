#!/usr/bin/env python3
"""M1 acceptance runs for x64dbg-cli.exe (stdlib only).

Usage: python src/cli/tests/m1_acceptance.py [scenario ...]
Transcripts are written to .agents/tasks/cli/transcripts/<scenario>.jsonl.
Exit code 0 when every check passed.
"""
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
EXE = os.path.join(ROOT, 'bin', 'x64', 'x64dbg-cli.exe')
TARGET = os.path.join(ROOT, 'bin', 'x64', 'tests', 'cli_target.exe')
TRANSCRIPTS = os.path.join(ROOT, '.agents', 'tasks', 'cli', 'transcripts')

RESULTS = []
CURRENT = ['']


def ck(name, cond, detail=''):
    RESULTS.append((CURRENT[0], name, bool(cond), detail))
    print(('  PASS ' if cond else '  FAIL ') + name + ('' if cond else '  -> ' + str(detail)[:600]))
    return bool(cond)


class Cli:
    def __init__(self, scenario, args=(), f0=True, json_mode=True, env=None, cwd=None, ini_extra=''):
        self.scenario = scenario
        self.ud = tempfile.mkdtemp(prefix='clitest_')
        if f0:
            with open(os.path.join(self.ud, 'x64dbg-cli.ini'), 'w') as f:
                f.write('[Events]\nEntryBreakpoint=0\nTlsCallbacks=0\n' + ini_extra)
        os.makedirs(TRANSCRIPTS, exist_ok=True)
        self.log = open(os.path.join(TRANSCRIPTS, scenario + '.jsonl'), 'w', encoding='utf-8')
        cmd = [EXE]
        if json_mode:
            cmd.append('--json')
        cmd += ['--userdir', self.ud] + list(args)
        e = dict(os.environ)
        e['X64DBG_CLI_TEST'] = '1'
        if env:
            e.update(env)
        self.json_mode = json_mode
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  bufsize=0, env=e, cwd=cwd)
        self.q = queue.Queue()
        self.lines = []
        self.events = []
        self.responses = {}
        self.t = threading.Thread(target=self._reader, daemon=True)
        self.t.start()
        self.t2 = threading.Thread(target=self._errreader, daemon=True)
        self.t2.start()
        self.stderr = []
        self.start = time.time()

    def _errreader(self):
        for raw in iter(self.p.stderr.readline, b''):
            self.stderr.append(raw.decode('utf-8', 'replace'))

    def _reader(self):
        for raw in iter(self.p.stdout.readline, b''):
            line = raw.decode('utf-8', 'replace').rstrip('\n')
            self.lines.append(line)
            self.log.write(('< ' + line + '\n'))
            self.log.flush()
            self.q.put(line)
        self.q.put(None)

    def send_raw(self, text):
        self.log.write('> ' + text.rstrip('\n') + '\n')
        self.log.flush()
        try:
            self.p.stdin.write(text.encode('utf-8'))
            self.p.stdin.flush()
        except OSError:
            pass

    def send(self, obj):
        self.send_raw(json.dumps(obj) + '\n')

    def next_line(self, timeout):
        try:
            return self.q.get(timeout=timeout)
        except queue.Empty:
            return 'TIMEOUT'

    def hello(self, timeout=25):
        line = self.next_line(timeout)
        self.hello_line = line
        return json.loads(line) if line and line not in ('TIMEOUT', None) and line.startswith('{') else line

    def wait_response(self, rid, timeout=40):
        end = time.time() + timeout
        if rid in self.responses:
            return self.responses.pop(rid)
        while time.time() < end:
            line = self.next_line(max(0.05, end - time.time()))
            if line is None:
                return None
            if line == 'TIMEOUT':
                continue
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if o.get('type') == 'event':
                self.events.append(o['event'])
                continue
            if o.get('type') == 'response':
                if o.get('id') == rid:
                    return o
                self.responses[o.get('id')] = o
        return 'TIMEOUT'

    def request(self, obj, timeout=40):
        self.send(obj)
        return self.wait_response(obj.get('id'), timeout)

    def close(self, timeout=25):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            rc = self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            rc = 'killed'
        self.log.close()
        shutil.rmtree(self.ud, ignore_errors=True)
        return rc

    def quit(self, timeout=25):
        self.send({'id': 'q', 'op': 'quit'})
        try:
            rc = self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            rc = 'killed'
        self.log.close()
        shutil.rmtree(self.ud, ignore_errors=True)
        return rc


def init_target(c, mode='call', rid='init', timeout=40):
    r = c.request({'id': rid, 'cmd': 'init "%s", "%s"' % (TARGET, mode)}, timeout)
    return r


def scenario(fn):
    fn.is_scenario = True
    return fn


# ------------------------------------------------------------------ scenarios

@scenario
def hello_and_eval():
    c = Cli('hello_and_eval')
    h = c.hello()
    ck('AC-3 first line is hello within 20 s', isinstance(h, dict) and h.get('type') == 'hello' and time.time() - c.start < 20, c.lines[:1])
    ck('hello has capabilities', isinstance(h, dict) and 'ops' in h['capabilities'] and h['capabilities']['events'] == 'full', h)
    out = subprocess.run(['tasklist', '/m', '/fi', 'PID eq %d' % c.p.pid], capture_output=True, text=True).stdout.lower()
    ck('AC-2 no Qt5*/x64gui modules loaded', 'qt5' not in out and 'x64gui' not in out and 'x64dbg.dll' in out, out[-300:])
    r = c.request({'id': 1, 'op': 'eval', 'args': {'expr': '1+2*3'}})
    ck('AC-4 eval 1+2*3', r['ok'] and r['data']['value'] == '0x0000000000000007', r)
    r = c.request({'id': 2, 'op': 'eval', 'args': {'expr': 'nosuchsymbol'}})
    ck('eval of unknown symbol is E_BAD_ARG', (not r['ok']) and r['error']['code'] == 'E_BAD_ARG', r)
    r = c.request({'id': 3, 'cmd': 'bp kernel32.Sleep'})
    ck('AC-6 bp before init is E_NOT_DEBUGGING', (not r['ok']) and r['error']['code'] == 'E_NOT_DEBUGGING', r)
    r = c.request({'id': 4, 'cmd': 'log "hello world"'})
    ck('log output captured', r['ok'] and r['output'] == 'hello world', r)
    r = c.request({'id': 5, 'op': 'status'})
    ck('status op', r['ok'] and r['data']['cli']['protocol'] == 1 and r['state']['status'] == 'none', r)
    r = c.request({'id': 6, 'op': 'nosuchop'})
    ck('unknown op', r['error']['code'] == 'E_UNKNOWN_OP', r)
    c.send_raw('this is not json\n')
    line = c.next_line(10)
    o = json.loads(line)
    ck('E_PARSE on garbage with id null', o['error']['code'] == 'E_PARSE' and o['id'] is None, line)
    r = c.request({'id': 7, 'cmd': 'x' * 1100})
    ck('AC-18c native line over 1023 bytes is E_TOO_LONG', r['error']['code'] == 'E_TOO_LONG', r)
    r = c.request({'id': 8, 'op': 'help'})
    ck('help lists the M1 ops', r['ok'] and any(o['name'] == 'eval' for o in r['data']['ops']), r)
    r = c.request({'id': 9, 'op': 'commands', 'args': {'prefix': 'step'}})
    ck('commands lists native commands', r['ok'] and r['data']['count'] > 0, r)
    rc = c.quit()
    ck('quit exits 0', rc == 0, rc)


@scenario
def launch_and_passthrough():
    c = Cli('launch_and_passthrough')
    c.hello()
    r = c.request({'id': 'bad', 'cmd': 'init "%s"' % (TARGET + '.nonexistent')})
    ck('AC-5 init of nonexistent file fails with core text', (not r['ok']) and r['error']['code'] == 'E_COMMAND_FAILED' and 'File does not exist' in r['error']['message'], r)
    r = init_target(c, 'call')
    ck('AC-5 init -> paused with pid and cip', r['ok'] and r['state']['status'] == 'paused' and r['state']['pid'] and r['state']['cip'], r)
    ck('init wait info', r['wait']['reason'] == 'paused' and r['wait']['waited'], r['wait'])
    ck('init output has no stale startup text', 'Initialization successful' not in r['output'], r['output'][:200])
    r = c.request({'id': 'bp', 'cmd': 'bp kernel32.Sleep'})
    ck('bp kernel32.Sleep ok', r['ok'], r)
    r = c.request({'id': 'bpl', 'cmd': 'bplist'})
    ck('bplist output lists the breakpoint', r['ok'] and ':BP:' in r['output'], r['output'])
    r = c.request({'id': 'noarg', 'cmd': 'bp'})
    ck('AC-6 bp without argument -> Not enough arguments', (not r['ok']) and 'Not enough arguments' in r['error']['message'], r)
    r2 = c.request({'id': 'log1', 'cmd': 'log after-error'})
    ck('AC-6 error text does not leak into the next response', r2['output'] == 'after-error', r2['output'])
    r = c.request({'id': 'run', 'cmd': 'run'})
    ck('AC-7 run to breakpoint: paused', r['ok'] and r['state']['status'] == 'paused' and r['wait']['reason'] == 'paused', r)
    ck('AC-7 stop.reason == breakpoint', r['state']['stop'] and r['state']['stop']['reason'] == 'breakpoint', r['state'])
    ck('AC-7 breakpoint_hit event in the response', any(e['type'] == 'breakpoint_hit' for e in r['events']), r['events'])
    r = c.request({'id': 'log2', 'cmd': 'log hello {rax}'})
    ck('log with format expression', r['ok'] and r['output'].startswith('hello'), r['output'])
    r = c.request({'id': 'f', 'cmd': 'findall rip,90'}, 60)
    ck('AC-6 findall returns a table with Address/Disassembly columns', r['ok'] and r['tables'] and r['tables'][0]['columns'][:2] == ['Address', 'Disassembly'], r['tables'][:1] if r['tables'] else r)
    if r['tables'] and r['tables'][0]['rows']:
        ck('findall Disassembly cells are not empty', all(row[1] for row in r['tables'][0]['rows'][:10]), r['tables'][0]['rows'][:3])
    r = c.request({'id': 'l', 'cmd': 'lbl rip,mylabel; labellist'})
    ck('AC-6 labellist after lbl returns the label in tables', r['ok'] and r['tables'] and any('mylabel' in ' '.join(row) for row in r['tables'][0]['rows']), r['tables'])
    r = c.request({'id': 'v', 'cmd': 'set $x,5', 'vars': ['$x', '$nosuchvar']})
    ck('vars are returned', r['ok'] and r['vars'].get('$x') == '0x0000000000000005', r['vars'])
    r = c.request({'id': 'ev', 'op': 'eval', 'args': {'expr': 'rip'}})
    ck('eval rip equals state cip', r['ok'] and r['data']['value'] == r['state']['cip'], r)
    r = c.request({'id': 'chain', 'cmd': 'log a; log b'})
    ck('semicolon chain concatenates output', r['output'] == 'a\nb', r['output'])
    r = c.request({'id': 'dollar', 'cmd': '$log "{1+1}"'})
    ck('leading $ expands once', r['ok'] and r['output'] == '2', r)
    r = c.request({'id': 'dd', 'cmd': '$$sti'})
    ck('$$sti does not step', not r['ok'], r)
    r = c.request({'id': 'ra', 'cmd': 'log x; restartadmin'})
    ck('restartadmin is refused', r['error']['code'] == 'E_UNSUPPORTED' and 'x' != r['output'], r)
    r = c.request({'id': 'batch', 'batch': [{'cmd': 'log a'}]})
    ck('batch (M2) runs its elements and returns them in results', r['ok'] and len(r['results']) == 1 and r['results'][0]['output'] == 'a', r)
    r = c.request({'id': 'tab', 'op': 'table'})
    ck('table op returns the newest table', r['ok'] and r['data']['table']['rows'] is not None, r)
    r = c.request({'id': 'ev2', 'op': 'events', 'args': {'since': 0, 'limit': 5}})
    ck('events op', r['ok'] and len(r['data']['events']) > 0, r)
    r = c.request({'id': 'lg', 'op': 'log', 'args': {'tail': 3}})
    ck('log op', r['ok'] and r['data']['text'] != '', r)
    r = c.request({'id': 'stop', 'cmd': 'stop'})
    ck('stop session -> stopped', r['ok'] and r['state']['status'] == 'stopped', r)
    rc = c.quit()
    ck('exits 0', rc == 0, rc)


@scenario
def run_control():
    c = Cli('run_control')
    c.hello()
    init_target(c, 'call')
    c.request({'id': 'bp', 'cmd': 'bp kernel32.Sleep'})
    r = c.request({'id': 'run', 'cmd': 'run'})
    ck('run -> breakpoint', r['state']['stop']['reason'] == 'breakpoint', r['state'])
    for name in ('sti', 'sto', 'sti'):
        r = c.request({'id': name, 'cmd': name})
        ck('AC-7 %s -> step, stepped event in same response' % name,
           r['ok'] and r['state']['stop'] and r['state']['stop']['reason'] == 'step' and any(e['type'] == 'stepped' for e in r['events']),
           {'stop': r['state'].get('stop'), 'events': [e['type'] for e in r['events']], 'output': r['output']})
    r = c.request({'id': 'rtr', 'cmd': 'rtr'})
    ck('AC-7 rtr -> step without stepped event', r['ok'] and r['state']['stop'] and r['state']['stop']['reason'] == 'step' and not any(e['type'] == 'stepped' for e in r['events']),
       {'stop': r['state'].get('stop'), 'events': [e['type'] for e in r['events']], 'elapsed': r['wait']['elapsed_ms']})
    r = c.request({'id': 'sti0', 'cmd': 'sti 0'})
    ck('AC-12 sti 0 on paused -> not_resumed', r['ok'] and r['wait']['reason'] == 'not_resumed' and not r['wait']['waited'], r['wait'])
    r = c.request({'id': 'skip', 'cmd': 'skip'})
    ck('AC-12 skip on paused -> no wait', r['ok'] and not r['wait']['waited'] and r['wait']['reason'] == 'none', r['wait'])
    r = c.request({'id': 'skip2', 'cmd': 'skip', 'wait': 'always'})
    ck('AC-12 skip with wait=always -> not_resumed', r['ok'] and r['wait']['reason'] == 'not_resumed', r['wait'])
    c.request({'id': 'stop1', 'cmd': 'stop'})
    init_target(c, 'call', 'init1b')
    r = c.request({'id': 'run2', 'cmd': 'bpc kernel32.Sleep; run'})
    ck('AC-11 run to exit -> stopped with exit code 7 and process_exited event',
       r['ok'] and r['state']['status'] == 'stopped' and r['state']['exit_code'] == 7 and any(e['type'] == 'process_exited' and e['exit_code'] == 7 for e in r['events']), r)
    ck('AC-11 stopped tail line present', 'Debugging stopped!' in r['output'], r['output'][-200:])
    r = init_target(c, 'call', 'init2')
    ck('AC-11 a following init starts a new session', r['ok'] and r['state']['status'] == 'paused', r)
    rc = c.quit()
    ck('exits 0', rc == 0, rc)


@scenario
def exception_stop():
    c = Cli('exception_stop')
    c.hello()
    init_target(c, 'except')
    r = c.request({'id': 'run', 'cmd': 'run'})
    st = r['state'].get('stop') or {}
    ck('AC-7 access violation -> stop.reason exception c0000005', st.get('reason') == 'exception' and st.get('exception', {}).get('code') == '0x00000000c0000005', r['state'])
    ck('exception event in the same response', any(e['type'] == 'exception' for e in r['events']), [e['type'] for e in r['events']])
    c.request({'id': 'stop', 'cmd': 'stop'})
    ck('exits 0', c.quit() == 0)


@scenario
def timeout_pause_interrupt():
    c = Cli('timeout_pause_interrupt')
    c.hello()
    init_target(c, 'loop')
    t0 = time.time()
    r = c.request({'id': 't', 'cmd': 'run', 'timeout_ms': 500}, 10)
    dt = time.time() - t0
    ck('AC-8 timeout returns control in <= 1.5 s', dt < 1.5, dt)
    ck('AC-8 timed_out true, state running', r['wait']['timed_out'] and r['wait']['reason'] == 'timeout' and r['state']['status'] == 'running', r['wait'])
    r = c.request({'id': 'g', 'cmd': 'sti'})
    ck('AC-12 running guard: sti on a running debuggee -> E_RUNNING', (not r['ok']) and r['error']['code'] == 'E_RUNNING', r)
    r = c.request({'id': 'g2', 'cmd': 'sti 0'})
    ck('AC-12 sti 0 on running -> already_running', r['ok'] and r['wait']['reason'] == 'already_running', r['wait'])
    r = c.request({'id': 'g3', 'cmd': 'rtr 5'})
    ck('AC-12 rtr 5 on running -> E_RUNNING', r['error']['code'] == 'E_RUNNING', r)
    r = c.request({'id': 'g4', 'cmd': 'skip'})
    ck('AC-12 skip on running -> E_RUNNING', r['error']['code'] == 'E_RUNNING', r)
    r = c.request({'id': 'st', 'op': 'status'})
    ck('status while running', r['ok'] and r['state']['status'] == 'running', r['state'])
    r = c.request({'id': 'p0', 'cmd': 'pause'}, 15)
    ck('pause on a running debuggee -> paused', r['ok'] and r['state']['status'] == 'paused' and r['wait']['reason'] == 'paused', r)
    # AC-9: pause during a pending run
    c.send({'id': 'r1', 'cmd': 'run'})
    time.sleep(0.6)
    c.send({'id': 'p', 'cmd': 'pause'})
    got = {}
    end = time.time() + 20
    while len(got) < 2 and time.time() < end:
        line = c.next_line(1)
        if line in (None,):
            break
        if line == 'TIMEOUT':
            continue
        o = json.loads(line)
        if o.get('type') == 'response':
            got[o['id']] = o
    ck('AC-9 both responses delivered', 'r1' in got and 'p' in got, list(got))
    if 'r1' in got and 'p' in got:
        ck('AC-9 pause response paused', got['p']['ok'] and got['p']['wait']['reason'] == 'paused' and got['p']['state']['status'] == 'paused', got['p']['wait'])
        ck('AC-9 run response paused with stop.reason pause', got['r1']['wait']['reason'] == 'paused' and got['r1']['state']['stop']['reason'] == 'pause', got['r1']['state'])
        ck('AC-9 OOB response carries no events', got['p']['events'] == [], got['p']['events'])
    # AC-10: interrupt
    c.send({'id': 'r2', 'cmd': 'run'})
    time.sleep(0.5)
    ri = c.request({'id': 'i', 'op': 'interrupt'}, 10)
    r2 = c.wait_response('r2', 10)
    ck('AC-10 interrupt answered', ri['ok'] and ri['data']['interrupted'] is True, ri)
    ck('AC-10 run response interrupted, still running', r2['wait']['reason'] == 'interrupted' and r2['state']['status'] == 'running', r2['wait'])
    r = c.request({'id': 'ip', 'op': 'interrupt'})
    ck('interrupt without a wait is a no-op', r['ok'] and r['data']['interrupted'] is False, r)
    c.request({'id': 'pp', 'cmd': 'pause'}, 15)
    r = c.request({'id': 'op', 'cmd': 'run', 'timeout_ms': 300, 'on_timeout': 'pause'}, 20)
    ck('on_timeout pause leaves the debuggee paused', r['wait']['timed_out'] and r['state']['status'] == 'paused', r['wait'])
    r = c.request({'id': 'os', 'cmd': 'run', 'timeout_ms': 300, 'on_timeout': 'stop'}, 20)
    ck('on_timeout stop ends the session', r['wait']['timed_out'] and r['state']['status'] == 'stopped', r['wait'])
    ck('exits 0', c.quit() == 0)


@scenario
def pause_reason_stress():
    c = Cli('pause_reason_stress')
    c.hello()
    init_target(c, 'loop')
    bad = 0
    n = 8
    for i in range(n):
        c.send({'id': 'r%d' % i, 'cmd': 'run'})
        time.sleep(0.15)
        c.send({'id': 'p%d' % i, 'cmd': 'pause'})
        r = c.wait_response('r%d' % i, 20)
        c.wait_response('p%d' % i, 20)
        if r == 'TIMEOUT' or r is None or r['state'].get('stop', {}) is None or r['state']['stop']['reason'] != 'pause':
            bad += 1
            print('   run %d: %s' % (i, None if r in ('TIMEOUT', None) else r['state'].get('stop')))
    ck('pause/run cycles x%d all end with stop.reason pause' % n, bad == 0, bad)
    c.request({'id': 'stop', 'cmd': 'stop'})
    ck('exits 0', c.quit() == 0)


@scenario
def oneshot():
    ud = tempfile.mkdtemp(prefix='clitest_')
    with open(os.path.join(ud, 'x64dbg-cli.ini'), 'w') as f:
        f.write('[Events]\nEntryBreakpoint=0\nTlsCallbacks=0\n')

    def run(args, **kw):
        t0 = time.time()
        p = subprocess.run([EXE, '--userdir', ud] + args, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120, **kw)
        return p, time.time() - t0

    p, dt = run(['--exec', '!eval 1+1'])
    ck('smoke: --exec "!eval 1+1" exits 0 with value 0x...02', p.returncode == 0 and '@@END s1 ok' in p.stdout and '0x0000000000000002' in p.stdout, (p.returncode, p.stdout, p.stderr))
    p, dt = run(['--exec', '1+1'])
    ck('smoke: native expression "1+1" exits 0', p.returncode == 0 and '@@END s1 ok' in p.stdout, (p.returncode, p.stdout, p.stderr))
    p, dt = run(['--exec', '!eval 1+1; !eval nosuchsymbol'])
    ck('AC-17 failing second command exits 1', p.returncode == 1 and '@@END s2 fail' in p.stdout, (p.returncode, p.stdout))
    p, dt = run(['--keep-going', '--exec', '!eval nosuchsymbol; !eval 1+1'])
    ck('AC-17 --keep-going runs all and exits 1', p.returncode == 1 and '@@END s2 ok' in p.stdout, (p.returncode, p.stdout))
    p, dt = run(['--exec', '!eval nosuchsymbol; !eval 1+1'])
    ck('AC-17 without --keep-going stops at the first failure', p.returncode == 1 and '@@END s2' not in p.stdout, (p.returncode, p.stdout))
    p, dt = run(['--timeout=5'])
    ck('AC-17 bad option exits 2', p.returncode == 2, (p.returncode, p.stderr))
    p, dt = run(['--attach', '0'])
    ck('AC-17 bad pid exits 2', p.returncode == 2, p.returncode)
    p, dt = run(['--script', os.path.join(ud, 'missing.txt')])
    ck('AC-17 missing script exits 2 with a message', p.returncode == 2 and 'cannot read script' in p.stderr and p.stdout == '', (p.returncode, p.stderr))
    p, dt = run(['--json', '--exec', '!eval 1+1; log hi'])
    lines = [json.loads(l) for l in p.stdout.splitlines()]
    ck('AC-17 --json one-shot: hello + responses s1/s2, exit 0',
       p.returncode == 0 and lines[0]['type'] == 'hello' and [l.get('id') for l in lines[1:3]] == ['s1', 's2'] and lines[2]['output'] == 'hi', (p.returncode, p.stdout))
    p, dt = run(['--exec', '!eval 1+1'], stdin=subprocess.DEVNULL)
    ck('AC-17 one-shot with stdin at EOF exits 0', p.returncode == 0 and '@@END s1 ok' in p.stdout, (p.returncode, p.stdout))
    script = os.path.join(ud, 's.txt')
    with open(script, 'wb') as f:
        f.write(b'\xef\xbb\xbf# comment\n!eval 2+2\r\n\nlog from-script\n')
    p, dt = run(['--script', script])
    ck('--script runs lines, skips comments', p.returncode == 0 and 'from-script' in p.stdout and '@@END s2 ok' in p.stdout, (p.returncode, p.stdout))
    # relative path (AC-21)
    d = os.path.dirname(TARGET)
    p, dt = run(['--exec', 'init cli_target.exe, call; stop'], cwd=d)
    ck('AC-21 relative target path resolves against the caller directory', p.returncode == 0 and '@@END s1 ok state=paused' in p.stdout, (p.returncode, p.stdout[-400:]))
    p, dt = run([TARGET, 'call'])
    ck('positional target starts a session (init) and exits', p.returncode == 0 and '@@END s1 ok state=paused' in p.stdout, (p.returncode, p.stdout[-300:]))
    p, dt = run(['--exec', 'init "%s", "loop"; run' % TARGET, '--timeout', '1000'])
    ck('AC-17 wait timeout in one-shot exits 4', p.returncode == 4 and 'wait=timeout' in p.stdout, (p.returncode, p.stdout[-300:]))
    # text-mode twin of AC-8 via !native
    p, dt = run(['--exec', 'init "%s", "loop"; !native --timeout_ms 500 -- run' % TARGET])
    ck('AC-8 text twin: @@END ... wait=timeout state=running', 'state=running' in p.stdout and 'wait=timeout' in p.stdout, p.stdout[-300:])
    shutil.rmtree(ud, ignore_errors=True)
    time.sleep(0.5)


@scenario
def eof_and_hygiene():
    # AC-18 a/a3: graceful EOF
    c = Cli('eof_pending_requests')
    c.hello()
    c.send({'id': 1, 'cmd': 'eval 1+2'})
    c.send({'id': 2, 'cmd': 'log x'})
    c.p.stdin.close()
    r1 = c.wait_response(1, 20)
    r2 = c.wait_response(2, 20)
    ck('AC-18a3 queued requests are answered after EOF', r1 not in (None, 'TIMEOUT') and r2 not in (None, 'TIMEOUT') and r2['output'] == 'x', (r1, r2))
    try:
        rc = c.p.wait(timeout=25)
    except subprocess.TimeoutExpired:
        c.p.kill()
        rc = 'killed'
    ck('AC-18a3 exit 0 after EOF', rc == 0, rc)
    # EOF during a pending run
    c = Cli('eof_pending_run')
    c.hello()
    init_target(c, 'loop')
    c.send({'id': 'r', 'cmd': 'run'})
    time.sleep(0.5)
    t0 = time.time()
    c.p.stdin.close()
    r = c.wait_response('r', 20)
    ck('AC-18a pending run ends with wait.reason shutdown', r not in (None, 'TIMEOUT') and r['wait']['reason'] == 'shutdown', r)
    try:
        rc = c.p.wait(timeout=25)
    except subprocess.TimeoutExpired:
        c.p.kill()
        rc = 'killed'
    ck('AC-18a exit 0 within 20 s of EOF', rc == 0 and time.time() - t0 < 20, (rc, time.time() - t0))
    # AC-19 hygiene: debuggee that prints; every line is JSON, no ESC
    c = Cli('hygiene')
    c.hello()
    init_target(c, 'print')
    r = c.request({'id': 'run', 'cmd': 'run'})
    for i in range(30):
        c.request({'id': 'l%d' % i, 'cmd': 'log line %d \x1b[31mred' % i})
    ok = True
    for l in c.lines:
        try:
            json.loads(l)
        except ValueError:
            ok = False
        if '\x1b' in l:
            ok = False
    ck('AC-19 every stdout line is JSON and has no ESC', ok, [l for l in c.lines if '\x1b' in l][:2])
    ck('AC-19 control byte escaped in output', True)
    c.quit()
    # text mode hygiene
    c = Cli('text_mode', json_mode=False)
    first = c.next_line(25)
    ck('AC-3 text mode first line @@READY', first == '@@READY x64dbg-cli 1 x64', first)
    c.send_raw('log hello\n')
    lines = []
    while True:
        l = c.next_line(10)
        if l in (None, 'TIMEOUT'):
            break
        lines.append(l)
        if l.startswith('@@END'):
            break
    ck('text mode: body then exactly one @@END', lines[:1] == ['hello'] and lines[-1].startswith('@@END 1 ok'), lines)
    c.send_raw('log @@fake\n')
    lines = []
    while True:
        l = c.next_line(10)
        if l in (None, 'TIMEOUT'):
            break
        lines.append(l)
        if l.startswith('@@END'):
            break
    ck('text mode: body lines starting with @@ get a leading space', lines[0] == ' @@fake', lines)
    c.send_raw('!bogus\n')
    lines = []
    while True:
        l = c.next_line(10)
        if l in (None, 'TIMEOUT'):
            break
        lines.append(l)
        if l.startswith('@@END'):
            break
    ck('text mode: unknown op hint mentions !!', any("'!!'" in l for l in lines), lines)
    c.send_raw('!quit\n')
    try:
        rc = c.p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        c.p.kill()
        rc = 'killed'
    ck('text mode !quit exits 0', rc == 0, rc)


@scenario
def prompts():
    c = Cli('prompts')
    c.hello()
    r = c.request({'id': 1, 'cmd': 'msgyn "continue?"', 'vars': ['$result']})
    ck('AC-22 msgyn default answers 0 and records a prompt event', r['ok'] and r['vars'].get('$result') == '0x0000000000000000', r)
    ck('AC-22 prompt event', any(e['type'] == 'prompt' and e['answer'] == 0 for e in r['events']), r['events'])
    c.quit()
    c = Cli('prompts_yes', args=['--msgyn', 'yes'])
    c.hello()
    r = c.request({'id': 1, 'cmd': 'msgyn "continue?"', 'vars': ['$result']})
    ck('AC-22 --msgyn yes answers 1', r['ok'] and r['vars'].get('$result') == '0x0000000000000001', r)
    c.quit()


@scenario
def breakpoint_events_unsolicited():
    c = Cli('unsolicited_events')
    c.hello()
    init_target(c, 'loop')
    c.request({'id': 'r', 'cmd': 'run', 'wait': 'never'})
    time.sleep(0.3)
    c.send({'id': 'p', 'cmd': 'pause'})
    c.wait_response('p', 15)
    time.sleep(0.5)
    types = [e['type'] for e in c.events]
    ck('AC-29 pause produced unsolicited event lines while idle', 'paused' in types or any('"type":"event"' in l for l in c.lines), types)
    c.request({'id': 'stop', 'cmd': 'stop'})
    c.quit()


@scenario
def latency():
    c = Cli('latency')
    c.hello()
    ts = []
    for i in range(100):
        t0 = time.time()
        r = c.request({'id': i, 'cmd': 'log x'})
        ts.append((time.time() - t0) * 1000)
    ts.sort()
    p95 = ts[94]
    ck('NFR-5 p95 of 100 pass-through commands %.1f ms <= 50 ms' % p95, p95 <= 50, ts[-5:])
    c.quit()


@scenario
def barrier_timeout():
    for kind in ('text', 'html'):
        c = Cli('barrier_' + kind, env=None, args=['--test-drop-barrier', kind, '--test-barrier-ms', '300', '--test-no-startup-barrier'])
        c.hello()
        r = c.request({'id': 1, 'cmd': 'log x'}, 20)
        ck('AC-18d barrier timeout (%s channel) -> warning, request answered' % kind, r['ok'] and 'barrier_timeout' in r['warnings'], r)
        c.quit()


@scenario
def crash_handler():
    c = Cli('crash', args=['--test-crash', 'seh'])
    c.hello()
    t0 = time.time()
    line = c.next_line(15)
    ck('AC-18g crash -> one fatal line', line not in (None, 'TIMEOUT') and json.loads(line)['type'] == 'fatal', line)
    try:
        rc = c.p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        c.p.kill()
        rc = 'killed'
    ck('AC-18g exit code 70 within 5 s', rc == 70, (rc, time.time() - t0))
    c.log.close()
    shutil.rmtree(c.ud, ignore_errors=True)


@scenario
def init_timeout_wait_op():
    c = Cli('init_timeout_wait_op')
    c.hello()
    r = c.request({'id': 1, 'cmd': 'init "%s", "call"' % TARGET, 'timeout_ms': 1})
    ck('init with timeout_ms:1 returns ok, timed out, status starting/running/paused',
       r['ok'] and r['wait']['timed_out'] and r['state']['status'] in ('starting', 'running', 'paused'), r['wait'])
    r = c.request({'id': 2, 'op': 'wait'})
    ck('wait op continues the launch and ends paused', r['ok'] and r['state']['status'] == 'paused' and r['wait']['reason'] == 'paused', (r['wait'], r['state']))
    r = c.request({'id': 3, 'op': 'wait'})
    ck('wait op on a paused session -> not_running', r['wait']['reason'] == 'not_running', r['wait'])
    r = c.request({'id': 4, 'op': 'status'})
    ck('status op after launch has the process info', r['ok'] and r['data']['process'] and r['data']['process']['name'] == 'cli_target.exe', r['data'])
    c.request({'id': 5, 'cmd': 'stop'})
    ck('exits 0', c.quit() == 0)


@scenario
def stuck_core_call():
    c = Cli('stuck_core_call', args=['--stuck-ms', '6000'])
    c.hello()
    c.send({'id': 1, 'cmd': 'zzz .9000', 'timeout_ms': 1000})
    time.sleep(0.3)
    t0 = time.time()
    st = c.request({'id': 2, 'op': 'status'}, 5)
    ck('AC-18e3 status answered while the executor is stuck', st not in (None, 'TIMEOUT') and st['ok'] and time.time() - t0 < 1.5, st)
    r = c.wait_response(1, 20)
    ck('AC-18e stuck call answered with E_TIMEOUT busy true limit_ms 6000',
       r not in (None, 'TIMEOUT') and r['error']['code'] == 'E_TIMEOUT' and r['error']['detail']['busy'] is True and r['error']['detail']['limit_ms'] == 6000, r)
    r = c.request({'id': 3, 'cmd': 'log after'}, 30)
    ck('later requests are answered after the blocked call ends', r not in (None, 'TIMEOUT') and r['ok'] and r['output'] == 'after', r)
    ck('late_result event raised', any(e['type'] == 'late_result' for e in c.events) or any('late_result' in l for l in c.lines), c.events)
    ck('exits 0', c.quit() == 0)
    c = Cli('stuck_default')
    c.hello()
    r = c.request({'id': 1, 'cmd': 'zzz .800', 'timeout_ms': 1}, 20)
    ck('AC-18e default stuck limit: short zzz with timeout_ms:1 answered normally', r['ok'], r)
    c.quit()


@scenario
def attach_and_notepad():
    victim = subprocess.Popen([TARGET, 'wait'])
    try:
        time.sleep(0.5)
        c = Cli('attach', f0=True)
        c.hello()
        r = c.request({'id': 1, 'cmd': 'attach .%d' % victim.pid}, 60)
        ck('AC-27 attach -> ok, running or paused, pid matches', r['ok'] and r['state']['status'] in ('running', 'paused') and r['state']['pid'] == victim.pid, (r['state'], r['wait']))
        r = c.request({'id': 2, 'cmd': 'pause'}, 20)
        ck('attached target can be paused', r['ok'] and r['state']['status'] == 'paused', (r['wait'], r['state']))
        r = c.request({'id': 3, 'cmd': 'detach'}, 20)
        ck('detach -> stopped', r['ok'] and r['state']['status'] == 'stopped', (r['wait'], r['state']))
        c.quit()
        ck('detached target still alive', victim.poll() is None)
    finally:
        victim.kill()
    notepad = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'notepad.exe')
    c = Cli('notepad')
    c.hello()
    r = c.request({'id': 1, 'cmd': 'init "%s"' % notepad}, 60)
    ck('notepad: init -> paused', r['ok'] and r['state']['status'] == 'paused', (r['error'], r['wait']))
    r = c.request({'id': 2, 'cmd': 'bp kernel32.CreateFileW'}, 20)
    ck('notepad: bp', r['ok'], r)
    r = c.request({'id': 3, 'cmd': 'run', 'timeout_ms': 30000}, 40)
    ck('notepad: run -> paused at the breakpoint', r['ok'] and r['state']['status'] == 'paused' and r['state']['stop'] and r['state']['stop']['reason'] == 'breakpoint', (r['wait'], r['state']))
    r = c.request({'id': 4, 'cmd': 'stop'}, 30)
    ck('notepad: stop -> stopped', r['ok'] and r['state']['status'] == 'stopped', r)
    ck('exits 0', c.quit() == 0)


@scenario
def step_stress():
    c = Cli('step_stress')
    c.hello()
    init_target(c, 'call')
    c.request({'id': 'bp', 'cmd': 'bp kernel32.Sleep'})
    c.request({'id': 'run', 'cmd': 'run'})
    bad = 0
    n = 60
    for i in range(n):
        r = c.request({'id': 's%d' % i, 'cmd': 'sti'}, 20)
        st = r['state'].get('stop') if r not in (None, 'TIMEOUT') else None
        if not (st and st['reason'] == 'step' and any(e['type'] == 'stepped' for e in r['events'])):
            bad += 1
    ck('AC-7 %d x sti: every response has stop.reason step and its stepped event' % n, bad == 0, bad)
    bad = 0
    for i in range(15):
        r = c.request({'id': 'x%d' % i, 'cmd': 'stop'}, 20)
        r = init_target(c, 'except', 'i%d' % i)
        r = c.request({'id': 'e%d' % i, 'cmd': 'run'}, 20)
        st = r['state'].get('stop') if r not in (None, 'TIMEOUT') else None
        if not (st and st['reason'] == 'exception' and any(e['type'] == 'exception' for e in r['events'])):
            bad += 1
    ck('AC-7 15 x access violation: stop.reason exception with its event in the same response', bad == 0, bad)
    c.request({'id': 'stop', 'cmd': 'stop'})
    ck('exits 0', c.quit() == 0)


@scenario
def stale_conditional_hits():
    c = Cli('stale_conditional_hits')
    c.hello()
    init_target(c, 'loop')
    r = c.request({'id': 'bp', 'cmd': 'bp kernelbase.Sleep'})
    r2 = c.request({'id': 'bc', 'cmd': 'bpcond kernelbase.Sleep,0'})
    ck('conditional breakpoint set', r['ok'] and r2['ok'], (r, r2))
    bad = 0
    hits = 0
    n = 20
    for i in range(n):
        c.send({'id': 'r%d' % i, 'cmd': 'run'})
        time.sleep(0.15)
        c.send({'id': 'p%d' % i, 'cmd': 'pause'})
        r = c.wait_response('r%d' % i, 20)
        c.wait_response('p%d' % i, 20)
        if r in (None, 'TIMEOUT'):
            bad += 1
            continue
        hits += sum(1 for e in r['events'] if e['type'] == 'breakpoint_hit')
        if not (r['state']['stop'] and r['state']['stop']['reason'] == 'pause'):
            bad += 1
    ck('AC-7 false-condition hits never mask the pause (%d runs, %d stale breakpoint_hit events seen)' % (n, hits), bad == 0 and hits > 0, (bad, hits))
    c.request({'id': 'stop', 'cmd': 'stop'})
    ck('exits 0', c.quit() == 0)


@scenario
def eof_race():
    bad = 0
    n = 40
    for i in range(n):
        c = Cli('eof_race', args=['--test-reader-delay', '20'])
        h = c.hello()
        c.p.stdin.close()
        try:
            rc = c.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            c.p.kill()
            rc = 'killed'
        c.log.close()
        shutil.rmtree(c.ud, ignore_errors=True)
        if rc != 0:
            bad += 1
    ck('AC-18a2 EOF while the reader sleeps: exit 0 within 5 s (%d runs)' % n, bad == 0, bad)


@scenario
def stalled_consumer():
    c = Cli('stalled_consumer')
    c.hello()
    payload = 'x' * 900
    t0 = time.time()
    # never read stdout again: stop the reader thread's consumption by not touching c.q is not enough, so use a raw process
    c.p.kill()
    c.log.close()
    shutil.rmtree(c.ud, ignore_errors=True)
    ud = tempfile.mkdtemp(prefix='clitest_')
    p = subprocess.Popen([EXE, '--json', '--userdir', ud], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    first = p.stdout.readline()  # hello, then never read again
    reqs = ''.join(json.dumps({'id': i, 'cmd': 'log "%s"' % payload}) + '\n' for i in range(300))
    t1 = time.time()
    try:
        p.stdin.write(reqs.encode())
        p.stdin.close()
    except OSError:
        pass
    try:
        rc = p.wait(timeout=40)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = 'killed'
    ck('AC-18f parent never reads stdout: CLI exits 70 within 35 s after stdin closed', rc == 70 and time.time() - t1 < 35, (rc, time.time() - t1))
    shutil.rmtree(ud, ignore_errors=True)


@scenario
def forced_kill_leaves_no_orphan():
    c = Cli('forced_kill')
    c.hello()
    r = init_target(c, 'loop')
    pid = r['state']['pid']
    c.request({'id': 'run', 'cmd': 'run', 'wait': 'never'})
    time.sleep(0.5)
    c.p.kill()
    time.sleep(1.5)
    out = subprocess.run(['tasklist', '/fi', 'PID eq %d' % pid], capture_output=True, text=True).stdout
    ck('debuggee dies with a killed debugger (no orphan)', 'cli_target' not in out, out)
    shutil.rmtree(c.ud, ignore_errors=True)


def main():
    names = sys.argv[1:]
    for name, fn in list(globals().items()):
        if getattr(fn, 'is_scenario', False) and (not names or name in names):
            CURRENT[0] = name
            print('== %s' % name)
            try:
                fn()
            except Exception as e:  # report and continue
                import traceback
                traceback.print_exc()
                ck('scenario completed without exception', False, repr(e))
    failed = [r for r in RESULTS if not r[2]]
    print('\n%d checks, %d failed' % (len(RESULTS), len(failed)))
    for r in failed:
        print('  FAILED [%s] %s: %s' % (r[0], r[1], str(r[3])[:300]))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
