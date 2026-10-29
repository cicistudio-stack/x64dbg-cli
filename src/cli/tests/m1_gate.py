#!/usr/bin/env python3
"""M1 gate scenarios that m1_acceptance.py does not cover (stdlib only).

Usage: python src/cli/tests/m1_gate.py [scenario ...]
Reuses the Cli harness class of m1_acceptance.py. Transcripts: .agents/tasks/cli/transcripts/<scenario>.jsonl
Exit code 0 when every check passed.
"""
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m1_acceptance as acc  # noqa: E402
from m1_acceptance import Cli, ck, init_target, scenario, EXE, TARGET, TRANSCRIPTS  # noqa: E402

ADMIN_TARGET = os.path.join(os.path.dirname(TARGET), 'cli_target_admin.exe')


def has_word(text, word):
    """True when word occurs in text as a whole token. The core writes `log` text and its newline as two chunks, so a
    concurrent debuggee log line (thread created/exit) can land between them; the text is intact, the line break is not."""
    return re.search(r'(?<![0-9A-Za-z])' + re.escape(word) + r'(?![0-9])', text) is not None


def event_seqs(responses, extra=()):
    seqs = []
    for r in responses:
        if isinstance(r, dict):
            seqs += [e['seq'] for e in r.get('events', [])]
    seqs += [e['seq'] for e in extra]
    return seqs


def pe_tls_callbacks(path):
    """Returns (has_tls_directory, number_of_tls_callbacks) read from the PE headers."""
    with open(path, 'rb') as f:
        d = f.read()
    e = struct.unpack_from('<I', d, 0x3c)[0]
    assert d[e:e + 4] == b'PE\0\0'
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsize = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    assert magic == 0x20b, 'x64 image expected'
    imagebase = struct.unpack_from('<Q', d, opt + 24)[0]
    dd = opt + 112
    rva, size = struct.unpack_from('<II', d, dd + 8 * 9)
    if rva == 0 or size == 0:
        return False, 0
    secs = []
    sec0 = opt + optsize
    for i in range(nsec):
        vsize, vaddr, rsize, raw = struct.unpack_from('<IIII', d, sec0 + 40 * i + 8)
        secs.append((vaddr, max(vsize, rsize), raw))

    def off(r):
        for va, sz, raw in secs:
            if va <= r < va + sz:
                return raw + r - va
        raise ValueError('rva not in a section')
    cb = struct.unpack_from('<Q', d, off(rva) + 24)[0]
    if cb == 0:
        return True, 0
    n = 0
    p = off(cb - imagebase)
    while struct.unpack_from('<Q', d, p + 8 * n)[0] != 0:
        n += 1
    return True, n


# ------------------------------------------------------------------ AC-20 / T12

@scenario
def soak_threads():
    c = Cli('soak_threads')
    c.hello()
    r = init_target(c, 'threads')
    ck('soak: init threads target -> paused', r and r['ok'] and r['state']['status'] == 'paused', r)
    r = c.request({'id': 'run0', 'cmd': 'run', 'wait': 'never'})
    ck('soak: run wait=never -> running', r['ok'] and r['state']['status'] == 'running', r)
    order = []
    responses = []
    bad = []
    pauses = 0
    t0 = time.time()
    for i in range(500):
        rid = 'c%d' % i
        r = c.request({'id': rid, 'cmd': 'log c%d' % i}, 30)
        if not isinstance(r, dict) or not r['ok'] or not has_word(r['output'], 'c%d' % i):
            bad.append((rid, r if not isinstance(r, dict) else (r['ok'], r['output'], r['error'])))
            break
        responses.append(r)
        order.append(rid)
        st = r['state']
        if st['status'] == 'paused' and st['cip'] is None:
            bad.append((rid, 'paused without cip'))
        if st['status'] == 'running' and st['cip'] is not None:
            bad.append((rid, 'running with cip'))
        if i % 25 == 24:
            p = c.request({'id': 'p%d' % i, 'cmd': 'pause'}, 30)
            responses.append(p)
            if not (p['ok'] and p['state']['status'] == 'paused' and (p['state']['stop'] is None or p['state']['stop']['reason'] == 'pause')):
                bad.append(('p%d' % i, p['state'] if isinstance(p, dict) else p))
                break
            s = c.request({'id': 's%d' % i, 'op': 'status'}, 30)
            if s['state']['status'] != 'paused':
                bad.append(('s%d' % i, s['state']))
            e = c.request({'id': 'e%d' % i, 'op': 'eval', 'args': {'expr': 'rip'}}, 30)
            if not (e['ok'] and e['data']['value'] == s['state']['cip'] == p['state']['cip']):
                bad.append(('e%d' % i, (e['data'], s['state']['cip'], p['state']['cip'])))
            rr = c.request({'id': 'r%d' % i, 'cmd': 'run', 'wait': 'never'}, 30)
            responses.append(rr)
            if not (rr['ok'] and rr['state']['status'] == 'running'):
                bad.append(('r%d' % i, rr['state']))
                break
            pauses += 1
    ck('AC-20: 500 pass-through commands with %d pause/run cycles, all consistent (%.1f s)' % (pauses, time.time() - t0), not bad and pauses == 20, bad[:3])
    seqs = []  # event seq values in the order they were written to stdout (responses and unsolicited lines)
    for line in c.lines:
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get('type') == 'response':
            seqs += [e['seq'] for e in o['events']]
        elif o.get('type') == 'event':
            seqs.append(o['event']['seq'])
    ck('AC-20: no duplicate event seq, strictly increasing in stream order (%d events)' % len(seqs), len(seqs) == len(set(seqs)) and seqs == sorted(seqs), (len(seqs), len(set(seqs))))
    ids = []
    for line in c.lines:
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get('type') == 'response':
            ids.append(o['id'])
    ck('AC-20: every response id appears exactly once, in request order', len(ids) == len(set(ids)) and [i for i in ids if str(i).startswith('c')] == order, (len(ids), len(set(ids))))
    warn = sorted({w for r in responses for w in r['warnings']})
    print('  info: warnings seen during the soak:', warn)
    # pipelined burst of 100 requests: answered in order, none lost
    c.send_raw(''.join(json.dumps({'id': 'b%d' % i, 'cmd': 'log b%d' % i}) + '\n' for i in range(100)))
    got = [c.wait_response('b%d' % i, 30) for i in range(100)]
    ck('AC-20: 100 pipelined requests answered, each with its own output', all(isinstance(g, dict) and g['ok'] and has_word(g['output'], 'b%d' % i) for i, g in enumerate(got)), [g for g in got if not isinstance(g, dict)][:1])
    r = c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    ck('soak: stop -> stopped', r['ok'] and r['state']['status'] == 'stopped', r['state'])
    rc = c.quit()
    ck('soak: exits 0', rc == 0, rc)


# ------------------------------------------------------------------ AC-30 / T17

@scenario
def overload_queue():
    c = Cli('overload_queue')
    c.hello()
    n = 300
    t0 = time.time()
    c.send_raw(''.join(json.dumps({'id': i, 'cmd': 'zzz .100'}) + '\n' for i in range(n)))
    # while the executor is busy the OOB ops stay responsive
    t1 = time.time()
    s = c.request({'id': 'st', 'op': 'status'}, 10)
    ck('AC-30: status answered while the queue is full (%.2f s)' % (time.time() - t1), isinstance(s, dict) and s['ok'] and time.time() - t1 < 3, s)
    t1 = time.time()
    p = c.request({'id': 'pz', 'cmd': 'pause'}, 10)
    ck('AC-30: pause answered meanwhile (%.2f s)' % (time.time() - t1), isinstance(p, dict) and time.time() - t1 < 5 and 'error' in p, p)
    got = {}
    for i in range(n):
        got[i] = c.wait_response(i, 90)
    busy = [i for i, g in got.items() if isinstance(g, dict) and not g['ok'] and g['error']['code'] == 'E_BUSY']
    okay = [i for i, g in got.items() if isinstance(g, dict) and g['ok']]
    other = [i for i, g in got.items() if not isinstance(g, dict) or (not g['ok'] and g['error']['code'] != 'E_BUSY')]
    ck('AC-30: requests beyond the 256-entry queue get E_BUSY (%d busy, %d accepted)' % (len(busy), len(okay)), len(busy) > 0 and len(okay) >= 256 and not other, (len(busy), len(okay), other[:3]))
    ck('AC-30: busy answers are the tail of the burst', busy == list(range(min(busy), n)) if busy else False, busy[:5])
    # order of the accepted answers in the stream
    ids = []
    for line in c.lines:
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get('type') == 'response' and isinstance(o.get('id'), int):
            ids.append(o['id'])
    acc_ids = [i for i in ids if i in set(okay)]
    ck('AC-30: all accepted requests were answered in order (%.1f s total)' % (time.time() - t0), acc_ids == sorted(acc_ids) and len(acc_ids) == len(okay), acc_ids[:5])
    r = c.request({'id': 'after', 'cmd': 'log still-alive'}, 30)
    ck('AC-30: the CLI answers normally afterwards', r['ok'] and r['output'] == 'still-alive', r)
    rc = c.quit()
    ck('AC-30: exits 0', rc == 0, rc)


@scenario
def stuck_clock():
    c = Cli('stuck_clock', args=['--stuck-ms', '6000'])
    c.hello()
    t0 = time.time()
    r = c.request({'id': 'seg3', 'cmd': 'zzz .4000; zzz .4000; zzz .4000', 'timeout_ms': 1000}, 60)
    ck('AC-18 e2: three 4 s segments (12 s total) under a 6 s limit are not cut (%.1f s)' % (time.time() - t0), isinstance(r, dict) and r['ok'], r['error'] if isinstance(r, dict) else r)
    t0 = time.time()
    r = c.request({'id': 'cut', 'cmd': 'zzz .8000; log zzafterzz', 'timeout_ms': 1000}, 60)
    ck('AC-18 e2: an 8 s call under the 6 s limit is cut with E_TIMEOUT busy (%.1f s)' % (time.time() - t0), isinstance(r, dict) and not r['ok'] and r['error']['code'] == 'E_TIMEOUT' and r['error']['detail'] and r['error']['detail'].get('busy') is True, r['error'] if isinstance(r, dict) else r)
    time.sleep(3)
    r = c.request({'id': 'lg', 'op': 'log', 'args': {'tail': 50}}, 30)
    ck('AC-18 e2: the remaining segment "log after" was not executed', r['ok'] and 'zzafterzz' not in r['data']['text'], r['data']['text'][-200:])
    # the legitimate waits of the design's batch case (batch itself is M2): a 20 s wait is not counted by the stuck clock.
    # A chain stops at the first wait that times out, so only the first `run` of `run; run` is a real wait.
    init_target(c, 'loop', 'iloop', 60)
    t0 = time.time()
    r = c.request({'id': 'twoRuns', 'cmd': 'run; run', 'timeout_ms': 20000, 'on_timeout': 'pause'}, 120)
    ck('AC-18 e2: a legitimate 20 s wait under a 6 s stuck limit is not cut (batch of two waits: M2) (%.1f s)' % (time.time() - t0), isinstance(r, dict) and not (not r['ok'] and r['error']['code'] == 'E_TIMEOUT'), r['error'] if isinstance(r, dict) else r)
    print('  info: run; run ->', (r['ok'], r['wait'], r['state']['status']) if isinstance(r, dict) else r, '(batch form is M2)')
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    rc = c.quit()
    ck('AC-18 e2: exits 0', rc == 0, rc)

    c = Cli('stuck_default')
    c.hello()
    for tmo in (1, 0):
        r = c.request({'id': 't%d' % tmo, 'cmd': 'zzz .8000', 'timeout_ms': tmo}, 60)
        ck('AC-18 e2: default stuck limit, zzz .8000 with timeout_ms:%d answered normally' % tmo, isinstance(r, dict) and r['ok'], r['error'] if isinstance(r, dict) else r)
    r = c.request({'id': 'ev', 'op': 'events', 'args': {'since': 0, 'limit': 500}}, 30)
    ck('AC-18 e2: no late_result event', all(e['type'] != 'late_result' for e in r['data']['events']), [e for e in r['data']['events'] if e['type'] == 'late_result'])
    rc = c.quit()
    c = Cli('stuck_timeout0', args=['--timeout', '0'])
    c.hello()
    r = c.request({'id': 'z', 'cmd': 'zzz .8000'}, 60)
    ck('AC-18 e2: a CLI started with --timeout 0 answers zzz .8000 normally', isinstance(r, dict) and r['ok'], r['error'] if isinstance(r, dict) else r)
    c.quit()


# ------------------------------------------------------------------ AC-32 / T32, AC-33 / T31

@scenario
def two_stop_f1():
    has_tls, callbacks = pe_tls_callbacks(TARGET)
    ck('AC-32: cli_target.exe has no TLS callbacks (TLS directory present: %s, callbacks: %d)' % (has_tls, callbacks), callbacks == 0, callbacks)
    c = Cli('two_stop_f1', f0=False)
    c.hello()
    r = init_target(c, 'call')
    ck('AC-32: init (F1 defaults) -> paused, stop.reason system_breakpoint', r['ok'] and r['state']['status'] == 'paused' and r['state']['stop'] and r['state']['stop']['reason'] == 'system_breakpoint', r['state'])
    ent = c.request({'id': 'ent', 'op': 'eval', 'args': {'expr': 'mod.entry(mod.main())'}})
    mk = c.request({'id': 'mk', 'op': 'eval', 'args': {'expr': 'cli_target.marker_func'}})
    ck('AC-32: entry and marker_func evaluate', ent['ok'] and mk['ok'], (ent, mk))
    r = c.request({'id': 'bp', 'cmd': 'bp cli_target.marker_func'})
    ck('AC-32: bp cli_target.marker_func ok', r['ok'], r)
    r1 = c.request({'id': 'r1', 'cmd': 'run'})
    st = r1['state']
    ck('AC-32: run 1 -> paused at the entry breakpoint (stop.bp == entry)', r1['ok'] and st['status'] == 'paused' and st['stop'] and st['stop']['reason'] == 'breakpoint' and st['stop'].get('bp') == ent['data']['value'], st)
    hits = [e for e in r1['events'] if e['type'] == 'breakpoint_hit']
    ck('AC-32: breakpoint_hit event is named "entry breakpoint"', any(e['name'] == 'entry breakpoint' for e in hits), hits)
    r2 = c.request({'id': 'r2', 'cmd': 'run'})
    st = r2['state']
    ck('AC-32: run 2 -> paused at marker_func (stop.bp == its address)', r2['ok'] and st['status'] == 'paused' and st['stop'] and st['stop']['reason'] == 'breakpoint' and st['stop'].get('bp') == mk['data']['value'], st)
    r3 = c.request({'id': 'r3', 'cmd': 'run'})
    st = r3['state']
    ck('AC-32: run 3 -> stopped with exit code 7', r3['ok'] and st['status'] == 'stopped' and st['exit_code'] == 7, st)
    rc = c.quit()
    ck('AC-32: exits 0', rc == 0, rc)


@scenario
def reinit_over_live_session():
    c = Cli('reinit_over_live_session')
    c.hello()
    r = init_target(c, 'loop', 'first', 60)
    pids = [r['state']['pid']]
    bad = []
    for i in range(50):
        r = c.request({'id': 'i%d' % i, 'cmd': 'init "%s", "loop"' % TARGET}, 60)
        if not isinstance(r, dict):
            bad.append((i, r))
            break
        st = r['state']
        if not (r['ok'] and st['status'] == 'paused' and st['pid'] and st['pid'] not in pids[-1:] and st['stop'] and st['stop']['reason'] == 'system_breakpoint'):
            bad.append((i, st, r['error']))
            break
        pids.append(st['pid'])
    ck('AC-33: 50 x init over a live paused session: paused, new pid, system_breakpoint, never stopped (%d done)' % (len(pids) - 1), not bad and len(pids) == 51, bad[:2])
    ck('AC-33: pids are all different from their predecessor', all(a != b for a, b in zip(pids, pids[1:])), pids[:5])
    r = c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    ck('AC-33: stop -> stopped', r['ok'] and r['state']['status'] == 'stopped', r['state'])
    rc = c.quit()
    ck('AC-33: exits 0', rc == 0, rc)
    time.sleep(1)
    out = subprocess.run(['tasklist', '/fi', 'IMAGENAME eq cli_target.exe'], capture_output=True, text=True, encoding='utf-8', errors='replace').stdout
    ck('AC-33: no orphan cli_target.exe after the re-init loop', 'cli_target.exe' not in out, out)


# ------------------------------------------------------------------ AC-35 / T35

@scenario
def slow_breakpoint_command():
    c = Cli('slow_breakpoint_command')
    c.hello()
    init_target(c, 'call')
    r = c.request({'id': 'bp', 'cmd': 'bp cli_target.marker_func'})
    r2 = c.request({'id': 'cmd', 'cmd': 'SetBreakpointCommand cli_target.marker_func, "zzz .1500"'})
    ck('AC-35: breakpoint with a 1.5 s command set', r['ok'] and r2['ok'], (r['error'], r2['error']))
    t0 = time.time()
    r = c.request({'id': 'run', 'cmd': 'run'}, 60)
    el = time.time() - t0
    ck('AC-35: run answers only after the breakpoint command finished (%.2f s >= 1.4 s)' % el, isinstance(r, dict) and r['ok'] and el >= 1.4, el)
    ck('AC-35: state paused at the breakpoint, stop.reason breakpoint', r['state']['status'] == 'paused' and r['state']['stop'] and r['state']['stop']['reason'] == 'breakpoint', r['state'])
    ck('AC-35: warning paused_without_state_message never appears', 'paused_without_state_message' not in r['warnings'], r['warnings'])
    print('  info: warnings on the slow-command run:', r['warnings'])
    s = c.request({'id': 'st', 'op': 'status'})
    ck('AC-35: a status after the run agrees (paused)', s['state']['status'] == 'paused', s['state'])
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()
    # variant without scriptcmd: breakpoint log text
    c = Cli('slow_breakpoint_log')
    c.hello()
    init_target(c, 'call')
    c.request({'id': 'bp', 'cmd': 'bp cli_target.marker_func'})
    r = c.request({'id': 'log', 'cmd': 'SetBreakpointLog cli_target.marker_func, "bplog-hit {rip}"'})
    ck('AC-35: SetBreakpointLog variant set', r['ok'], r['error'])
    r = c.request({'id': 'run', 'cmd': 'run'}, 60)
    ck('AC-35: log variant: run pauses and the breakpoint log text is in the output', r['ok'] and r['state']['status'] == 'paused' and 'bplog-hit' in r['output'], (r['state'], r['output'][-200:]))
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()


# ------------------------------------------------------------------ AC-36 / T36

@scenario
def event_cap():
    c = Cli('event_cap')
    c.hello()
    init_target(c, 'threads')
    t0 = time.time()
    r = c.request({'id': 'flood', 'cmd': 'run', 'timeout_ms': 14000, 'on_timeout': 'pause'}, 90)
    ck('AC-36: flood run ended (%.1f s)' % (time.time() - t0), isinstance(r, dict) and r['ok'], r['error'] if isinstance(r, dict) else r)
    n = len(r['events'])
    ck('AC-36: response carries at most max_events=500 events (%d) and the warning events_truncated' % n, n <= 500 and 'events_truncated' in r['warnings'], (n, r['warnings']))
    nxt = r.get('events_next_seq')
    ck('AC-36: events_next_seq present', isinstance(nxt, int), nxt)
    time.sleep(2)  # the rest may be delivered as unsolicited lines
    unsolicited = list(c.events)
    q = c.request({'id': 'rest', 'op': 'events', 'args': {'since': nxt or 0, 'limit': 100000}}, 60)
    rest = q['data']['events']
    total = n + len(rest)
    ck('AC-36: !events --since <events_next_seq> returns the rest (%d + %d = %d events pending in total)' % (n, len(rest), total), len(rest) > 0 and rest[0]['seq'] >= nxt, (len(rest), nxt))
    ck('AC-36: the flood really exceeded 5000 pending events (%d)' % total, total >= 5000, total)
    seqs = [e['seq'] for e in r['events']]
    ck('AC-36: no duplicate seq inside the response; the rest starts after the response', seqs == sorted(set(seqs)) and (not rest or rest[0]['seq'] > seqs[-1]), (seqs[:3], rest[:1]))
    dups = set(e['seq'] for e in unsolicited) & set(seqs)
    ck('AC-36: no event delivered twice (response vs unsolicited lines)', not dups, sorted(dups)[:5])
    # max_events 0
    r0 = c.request({'id': 'zero', 'cmd': 'run', 'timeout_ms': 1500, 'on_timeout': 'pause', 'max_events': 0}, 60)
    ck('AC-36: max_events 0 -> no events in the response, events_truncated warning', isinstance(r0, dict) and r0['events'] == [] and 'events_truncated' in r0['warnings'], (r0['events'][:1], r0['warnings']) if isinstance(r0, dict) else r0)
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()

    c = Cli('event_ring_wrap', args=['--test-event-ring', '64'])
    c.hello()
    init_target(c, 'threads')
    r = c.request({'id': 'flood', 'cmd': 'run', 'timeout_ms': 3000, 'on_timeout': 'pause'}, 60)
    ev = r['events']
    ck('AC-36: ring of 64 wrapped: events_dropped precedes the surviving events', ev and ev[0]['type'] == 'events_dropped' and ev[0]['count'] > 0, ev[:2])
    seqs = [e['seq'] for e in ev[1:]]
    ck('AC-36: surviving events have strictly increasing seq, no duplicates; the notice takes the next free seq (%d events)' % len(ev), seqs == sorted(set(seqs)) and ev[0]['seq'] > seqs[-1], [e['seq'] for e in ev[:4]])
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()


# ------------------------------------------------------------------ AC-37 / T40

@scenario
def table_ownership():
    c = Cli('table_ownership')
    c.hello()
    init_target(c, 'call')
    c.request({'id': 'l', 'cmd': 'lbl rip,tablelabel'})
    c.request({'id': 'c', 'cmd': 'cmt rip,tablecomment'})
    r = c.request({'id': 'two', 'cmd': 'labellist; commentlist'})
    ids = [t['id'] for t in r['tables']]
    ck('AC-37: labellist; commentlist -> two tables with consecutive ids in creation order', len(ids) == 2 and ids[1] == ids[0] + 1, ids)
    ck('AC-37: the label and the comment are in the tables', any('tablelabel' in ' '.join(row) for row in r['tables'][0]['rows']) and any('tablecomment' in ' '.join(row) for row in r['tables'][1]['rows']), [t['name'] for t in r['tables']])
    r2 = c.request({'id': 'none', 'cmd': 'log nothing'})
    ck('AC-37: a request that creates no table returns no tables', r2['tables'] == [], r2['tables'])
    r3 = c.request({'id': 'page', 'op': 'table', 'args': {'id': ids[0]}})
    ck('AC-37: !table --id <first> pages a table that was already delivered', r3['ok'] and r3['data']['id'] == ids[0] and any('tablelabel' in ' '.join(row) for row in r3['data']['table']['rows']), r3['data'] if r3['ok'] else r3['error'])
    r4 = c.request({'id': 'page2', 'op': 'table', 'args': {'id': ids[1], 'offset': 0, 'limit': 1}})
    ck('AC-37: paging with offset/limit', r4['ok'] and len(r4['data']['table']['rows']) <= 1, r4['data'] if r4['ok'] else r4['error'])
    r5 = c.request({'id': 'bad', 'op': 'table', 'args': {'id': 99999}})
    ck('AC-37: unknown table id -> E_BAD_ARG', not r5['ok'] and r5['error']['code'] == 'E_BAD_ARG', r5['error'])
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()


# ------------------------------------------------------------------ AC-28 / T18

@scenario
def max_output_and_logfile():
    d = tempfile.mkdtemp(prefix='cliscript_')
    script = os.path.join(d, 'gen.txt')
    lines = ['log "L%04d-%s"' % (i, 'x' * 90) for i in range(3000)]
    with open(script, 'w', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    logfile = os.path.join(d, 'mirror.log')
    c = Cli('max_output_and_logfile', args=['--log-file', logfile])
    c.hello()
    r = c.request({'id': 'big', 'cmd': 'scriptexec ' + script, 'max_output': 4096, 'timeout_ms': 60000}, 120)
    ck('AC-28: scriptexec of a 3000-line script is cut at max_output=4096 with truncated:true', isinstance(r, dict) and r['ok'] and r['truncated'] is True and len(r['output'].encode()) <= 4096, (r['ok'], r['truncated'], len(r['output'])) if isinstance(r, dict) else r)
    nxt = [int(w.split('=')[1]) for w in r['warnings'] if w.startswith('output_truncated_next=')]
    ck('AC-28: warning output_truncated_next=<offset>', len(nxt) == 1, r['warnings'])
    rest_chunks = []
    pos = nxt[0]
    for _ in range(100):
        q = c.request({'id': 'lg', 'op': 'log', 'args': {'from': pos}}, 60)
        if not q['ok']:
            break
        rest_chunks.append(q['data']['text'])
        if q['data']['next'] <= pos:
            break
        pos = q['data']['next']
        if not q['data']['truncated'] and pos >= q['meta']['log_end']:
            break
    whole = r['output'] + ''.join(rest_chunks)  # the cut is byte-exact, so plain concatenation must restore the log
    import re
    found = re.findall(r'L(\d{4})-x{90}', whole)
    ck('AC-28: !log --from <next> returns the remainder without loss (3000 distinct lines in order)', found[:3000] == ['%04d' % i for i in range(3000)] and len(set(found)) == 3000, (len(found), found[:3], found[-3:]))
    ck('AC-28: no barrier marker in the output or the log text', 'x64dbg-cli-barrier' not in whole, '')
    c.request({'id': 'x', 'cmd': 'log logfile-line-two'})
    rc = c.quit()
    ck('AC-28: exits 0', rc == 0, rc)
    try:
        with open(logfile, encoding='utf-8', errors='replace') as f:
            mirrored = f.read()
    except OSError as e:
        mirrored = ''
        ck('AC-28: --log-file exists', False, e)
    cnt = len(re.findall(r'L\d{4}-x{90}', mirrored))
    ck('AC-28: --log-file mirrors the core log (%d script lines + the later line), no barrier markers' % cnt, cnt == 3000 and 'logfile-line-two' in mirrored and 'x64dbg-cli-barrier' not in mirrored, (cnt, len(mirrored)))
    shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------ AC-18 b

@scenario
def request_too_long():
    c = Cli('request_too_long')
    c.hello()
    c.send_raw('{"id":"big","cmd":"' + 'a' * (1024 * 1024 + 100) + '"}\n')
    line = c.next_line(30)
    o = json.loads(line) if line not in ('TIMEOUT', None) else {}
    ck('AC-18 b: a request line over 1 MiB gets E_TOO_LONG', o.get('ok') is False and o.get('error', {}).get('code') == 'E_TOO_LONG', line[:300] if isinstance(line, str) else line)
    r = c.request({'id': 'next', 'op': 'eval', 'args': {'expr': '1+1'}})
    ck('AC-18 b: the next request still works', r['ok'] and r['data']['value'].endswith('2'), r)
    rc = c.quit()
    ck('AC-18 b: exits 0', rc == 0, rc)


# ------------------------------------------------------------------ AC-26 / T21a

def start_target(mode):
    return subprocess.Popen([TARGET, mode], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@scenario
def attach_pause_retry():
    t = start_target('wait')
    time.sleep(0.5)
    c = Cli('attach_pause_retry')
    c.hello()
    r = c.request({'id': 'att', 'cmd': 'attach .%d' % t.pid}, 60)
    ck('AC-26: attach .<pid> -> ok, wait.reason running', isinstance(r, dict) and r['ok'] and r['wait']['reason'] == 'running', (r['error'], r['wait'], r['state']['status']) if isinstance(r, dict) else r)
    t0 = time.time()
    p = c.request({'id': 'pz', 'cmd': 'pause'}, 30)
    el = time.time() - t0
    ck('AC-26: pause on the wait target answers paused within 8 s (%.1f s)' % el, isinstance(p, dict) and p['ok'] and p['state']['status'] == 'paused' and el < 8, p['state'] if isinstance(p, dict) else p)
    ck('AC-26: the pause response carries the pause_retry warning', 'pause_retry' in p['warnings'], p['warnings'])
    s = c.request({'id': 'st', 'op': 'status'})
    pr = s['data']['process']
    ck('AC-26: status shows process.path/name/base after the attach', pr and pr['name'].lower() == 'cli_target.exe' and pr['path'].lower().endswith('cli_target.exe') and pr['base'], pr)
    d = c.request({'id': 'det', 'cmd': 'detach'}, 30)
    ck('AC-26: detach -> stopped', d['ok'] and d['state']['status'] == 'stopped', d['state'])
    time.sleep(0.5)
    ck('AC-26: the target is still alive after detach', t.poll() is None, t.poll())
    c.quit()
    t.kill()
    t.wait()

    t = start_target('loop')
    time.sleep(0.5)
    c = Cli('attach_pause_loop')
    c.hello()
    r = c.request({'id': 'att', 'cmd': 'attach .%d' % t.pid}, 60)
    p = c.request({'id': 'pz', 'cmd': 'pause'}, 30)
    ck('AC-26: pause on the loop target answers paused without pause_retry', isinstance(p, dict) and p['ok'] and p['state']['status'] == 'paused' and 'pause_retry' not in p['warnings'], (p['state'], p['warnings']) if isinstance(p, dict) else p)
    c.request({'id': 'det', 'cmd': 'detach'}, 30)
    time.sleep(0.5)
    ck('AC-26: loop target alive after detach', t.poll() is None, t.poll())
    c.quit()
    t.kill()
    t.wait()

    # one-shot --attach <pid>
    t = start_target('loop')
    time.sleep(0.5)
    ud = tempfile.mkdtemp(prefix='clitest_')
    out = subprocess.run([EXE, '--json', '--userdir', ud, '--attach', str(t.pid), '--exec', 'log attached-ok'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90, env=dict(os.environ))
    lines = [json.loads(l) for l in out.stdout.splitlines() if l.startswith('{')]
    resp = [l for l in lines if l.get('type') == 'response']
    ck('AC-26: --attach <pid> one-shot queues attach then the next item (s1, s2), exit %d' % out.returncode, out.returncode == 0 and [r['id'] for r in resp] == ['s1', 's2'] and all(r['ok'] for r in resp), [(r['id'], r['ok'], r['error']) for r in resp])
    time.sleep(1)
    print('  info: target alive after one-shot --attach shutdown:', t.poll() is None)
    t.kill()
    t.wait()
    shutil.rmtree(ud, ignore_errors=True)


# ------------------------------------------------------------------ T2, T7, T8, T9, T11, T13: startup, exit codes, hygiene extras

@scenario
def startup_and_exit_codes():
    # T2 startup determinism: 20 fresh CLIs, "log first" sent at once after the hello line
    bad = []
    t0 = time.time()
    for i in range(20):
        c = Cli('startup_determinism')
        c.hello()
        r = c.request({'id': 'f', 'cmd': 'log first'}, 30)
        if not (isinstance(r, dict) and r['ok'] and r['output'] == 'first'):
            bad.append((i, r['output'] if isinstance(r, dict) else r))
        c.quit()
    ck('T2: 20 fresh starts, the first command after hello answers exactly "first" (%.0f s)' % (time.time() - t0), not bad, bad[:3])

    # AC-17 / T8: exit 3 when the core cannot be loaded (copy without x64dbg.dll)
    d = tempfile.mkdtemp(prefix='clino_core_')
    bindir = os.path.dirname(EXE)
    for name in os.listdir(bindir):
        low = name.lower()
        if low in ('x64dbg-cli.exe', 'x64bridge.dll', 'msvcp140.dll') or low.startswith('vcruntime140'):
            shutil.copy(os.path.join(bindir, name), d)
    ud = tempfile.mkdtemp(prefix='clitest_')
    p = subprocess.run([os.path.join(d, 'x64dbg-cli.exe'), '--json', '--userdir', ud], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90, stdin=subprocess.DEVNULL)
    ck('AC-17: a copy without x64dbg.dll exits 3 (core initialisation failed)', p.returncode == 3, (p.returncode, p.stderr[:200]))
    shutil.rmtree(d, ignore_errors=True)

    # startup input errors exit 2 before the core is touched
    cases = (('missing --script file', ['--script', 'C:\\no\\such\\script.txt']),
             ('--userdir that cannot be created', ['--userdir', 'Z:\\no\\such\\drive\\dir']),
             ('bad --attach pid', ['--attach', 'abc']),
             ('numeric option out of range', ['--timeout', '99999999']),
             ('unknown option', ['--no-such-option']))
    for label, args in cases:
        p = subprocess.run([EXE] + args, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60, stdin=subprocess.DEVNULL)
        ck('AC-17: %s exits 2 with one message on stderr' % label, p.returncode == 2 and p.stderr.strip() != '', (p.returncode, p.stderr[:200]))

    # T9: --eof-wait 0 with a pending run, and EOF while the CLI is idle
    c = Cli('eof_wait_zero', args=['--eof-wait', '0'])
    c.hello()
    init_target(c, 'loop')
    c.send({'id': 'run', 'cmd': 'run'})
    time.sleep(0.5)
    t0 = time.time()
    c.p.stdin.close()
    r = c.wait_response('run', 30)
    ck('T9: --eof-wait 0: the pending run ends at once with wait.reason shutdown (%.1f s)' % (time.time() - t0), isinstance(r, dict) and r['wait']['reason'] == 'shutdown', r['wait'] if isinstance(r, dict) else r)
    try:
        rc = c.p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        c.p.kill()
        rc = 'killed'
    ck('T9: --eof-wait 0: exit 0', rc == 0, rc)
    c.log.close()
    shutil.rmtree(c.ud, ignore_errors=True)

    # T13 positional arguments: x64dbg-cli.exe --json --userdir <tmp> cli_target.exe "a b" c, then getcommandline
    ud = tempfile.mkdtemp(prefix='clitest_')
    with open(os.path.join(ud, 'x64dbg-cli.ini'), 'w') as f:
        f.write('[Events]\nEntryBreakpoint=0\nTlsCallbacks=0\n')
    p = subprocess.Popen([EXE, '--json', '--userdir', ud, '--interactive', TARGET, 'a b', 'c'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = []
    got = None
    end = time.time() + 60
    p.stdin.write((json.dumps({'id': 'gc', 'cmd': 'getcommandline'}) + '\n').encode())
    p.stdin.flush()
    while time.time() < end:
        l = p.stdout.readline().decode('utf-8', 'replace')
        if not l:
            break
        o = json.loads(l)
        lines.append(o)
        if o.get('type') == 'response' and o.get('id') == 'gc':
            got = o
            break
    ck('T13: positional target starts a session (s1 paused) before the client request', any(o.get('id') == 's1' and o.get('state', {}).get('status') == 'paused' for o in lines), [o.get('id') for o in lines])
    ck('T13: getcommandline shows the quoted arguments "a b" c', got is not None and got['ok'] and '"a b" c' in got['output'], got['output'] if got else None)
    p.stdin.write((json.dumps({'id': 'q', 'op': 'quit'}) + '\n').encode())
    p.stdin.flush()
    try:
        rc = p.wait(timeout=60)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = 'killed'
    ck('T13: exits 0', rc == 0, rc)
    shutil.rmtree(ud, ignore_errors=True)

    # T11 / AC-19: a stray printf from a core-side thread never reaches the protocol stream
    c = Cli('stray_print', args=['--selftest-stray-print'])
    c.hello()
    r = c.request({'id': 'a', 'cmd': 'log after-stray'}, 30)
    time.sleep(1)
    c.quit()
    ck('T11: stray print injected: every stdout line is JSON and none contains the stray text', all(l.startswith('{') and 'stray print' not in l for l in c.lines), [l for l in c.lines if not l.startswith('{') or 'stray print' in l][:3])
    # print-mode debuggee writing to stdout
    c = Cli('print_debuggee')
    c.hello()
    init_target(c, 'print')
    r = c.request({'id': 'run', 'cmd': 'run'}, 60)
    time.sleep(0.5)
    c.request({'id': 'x', 'cmd': 'log done'}, 30)
    c.quit()
    ck('T11: debuggee that prints to stdout: all CLI stdout lines stay valid JSON', all(l.startswith('{') for l in c.lines) and not any('hello-from-debuggee' in l and not l.startswith('{') for l in c.lines), [l for l in c.lines if not l.startswith('{')][:2])

    # T11 text mode: pause sent during a long findall response; each block ends with exactly one @@END
    c = Cli('text_findall_pause', json_mode=False)
    c.next_line(25)
    text_command(c, 'init "%s", "loop"' % TARGET, 60)
    text_command(c, '!native --wait never -- run', 30)
    c.send_raw('findall ntdll.dll+1000,00\n')
    c.send_raw('pause\n')
    c.send_raw('log text-block-done\n')
    blocks = []
    cur = []
    end = time.time() + 60
    while time.time() < end and len(blocks) < 3:
        l = c.next_line(max(0.05, end - time.time()))
        if l is None:
            break
        if l == 'TIMEOUT':
            continue
        cur.append(l)
        if l.startswith('@@END'):
            blocks.append(cur)
            cur = []
    ids = [b[-1].split()[1] for b in blocks]
    ck('T11: three text blocks (findall, pause, log), each ends with exactly one @@END', len(blocks) == 3 and all(sum(1 for x in b if x.startswith('@@END')) == 1 for b in blocks) and len(set(ids)) == 3, [(len(b), b[-1][:60]) for b in blocks])
    big = max(blocks, key=len) if blocks else []
    found = [int(m.group(1)) for x in big for m in [re.match(r'^(\d+) occurrences found', x)] if m]
    rows = sum(1 for x in big if re.match(r'^[0-9A-F]{16}\t', x))
    others = [b for b in blocks if b is not big]
    ck('T11: the findall block is contiguous: all %d rows of its table are inside it; the pause and log answers are separate blocks (sizes %s)' % (rows, [len(b) for b in blocks]), len(blocks) == 3 and found and rows == found[0] and rows >= 100 and not any(x.startswith('@@END') for x in big[:-1]) and not any(re.match(r'^[0-9A-F]{16}\t', x) for b in others for x in b) and any('text-block-done' in x for b in others for x in b), (found, rows, [len(b) for b in blocks]))
    text_command(c, 'stop', 30)
    text_command(c, '!quit', 30)
    try:
        c.p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        c.p.kill()
    c.log.close()
    shutil.rmtree(c.ud, ignore_errors=True)

    # T7: sti; sti chain, !! escape, 2 MiB line
    c = Cli('error_cases')
    c.hello()
    init_target(c, 'call')
    r = c.request({'id': 'chain', 'cmd': 'sti; sti'}, 60)
    ck('T7: "sti; sti" runs two steps (two stepped events, state paused)', r['ok'] and r['state']['status'] == 'paused' and sum(1 for e in r['events'] if e['type'] == 'stepped') == 2, ([e['type'] for e in r['events']], r['error']))
    c.send_raw('{"id":"big2","cmd":"' + 'a' * (2 * 1024 * 1024) + '"}\n')
    line = c.next_line(30)
    o = json.loads(line) if line not in ('TIMEOUT', None) else {}
    ck('T7: a 2 MiB request line gets E_TOO_LONG', o.get('error', {}).get('code') == 'E_TOO_LONG', line[:200] if isinstance(line, str) else line)
    r = c.request({'id': 'ok', 'op': 'eval', 'args': {'expr': '3+4'}})
    ck('T7: the next request works', r['ok'] and r['data']['value'].endswith('7'), r)
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()
    c = Cli('error_cases_text', json_mode=False)
    c.next_line(25)
    body, end = text_command(c, '!!1+2', 30)
    ck('T7: text mode "!!1+2" runs the expression natively', end is not None and ' ok ' in end, (body, end))
    body, end = text_command(c, '!nosuchop', 30)
    ck('T7: text mode "!nosuchop" -> E_UNKNOWN_OP with the !! hint', end is not None and 'fail' in end and any("'!!'" in l for l in body), (body, end))
    text_command(c, '!quit', 30)
    c.log.close()
    shutil.rmtree(c.ud, ignore_errors=True)


# ------------------------------------------------------------------ T10: 100 repetitions (AC-7 cause events in the same response)

@scenario
def repeat_100():
    c = Cli('repeat_100')
    c.hello()
    init_target(c, 'loop')
    bad = []
    for i in range(100):
        r = c.request({'id': 's%d' % i, 'cmd': 'sti'}, 30)
        st = r['state'] if isinstance(r, dict) else None
        if not (st and st['status'] == 'paused' and st['stop'] and st['stop']['reason'] == 'step' and any(e['type'] == 'stepped' for e in r['events'])):
            bad.append((i, st))
    ck('T10: 100 x sti: stop.reason step and the stepped event in the response of the request that caused it', not bad, bad[:3])
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()

    c = Cli('repeat_100_exception')
    c.hello()
    bad = []
    t0 = time.time()
    for i in range(100):
        r = init_target(c, 'except', 'i%d' % i, 60)
        r = c.request({'id': 'r%d' % i, 'cmd': 'run'}, 60)
        st = r['state'] if isinstance(r, dict) else None
        ex = [e for e in r['events'] if e['type'] == 'exception'] if isinstance(r, dict) else []
        if not (st and st['status'] == 'paused' and st['stop'] and st['stop']['reason'] == 'exception' and st['stop']['exception']['code'] == '0x00000000c0000005' and ex and ex[0]['code'] == '0x00000000c0000005'):
            bad.append((i, st))
    ck('T10: 100 x access violation: stop.reason exception, code 0xc0000005, exception event in the same response (%.0f s)' % (time.time() - t0), not bad, bad[:3])
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()


# ------------------------------------------------------------------ AC-27 wait options (attach with wait=always, text twins)

def text_command(c, line, timeout=40):
    """Sends one text-mode line and returns (body lines, @@END line)."""
    c.send_raw(line + '\n')
    body = []
    end = time.time() + timeout
    while time.time() < end:
        l = c.next_line(max(0.05, end - time.time()))
        if l is None:
            return body, None
        if l == 'TIMEOUT':
            continue
        if l.startswith('@@END'):
            return body, l
        body.append(l)
    return body, None


@scenario
def wait_options():
    t = start_target('wait')
    time.sleep(0.5)
    c = Cli('wait_options_attach')
    c.hello()
    r = c.request({'id': 'att', 'cmd': 'attach .%d' % t.pid, 'wait': 'always', 'timeout_ms': 1500}, 60)
    ck('AC-27: attach wait=always timeout_ms=1500 on a wait target -> timed_out, still running', isinstance(r, dict) and r['ok'] and r['wait']['timed_out'] is True and r['state']['status'] == 'running', (r['wait'], r['state']['status']) if isinstance(r, dict) else r)
    c.request({'id': 'det', 'cmd': 'detach'}, 30)
    c.quit()
    t.kill()
    t.wait()

    # the same request while another session is live: the stopped message for the old session must not end the wait
    t = start_target('wait')
    time.sleep(0.5)
    c = Cli('wait_options_attach_live')
    c.hello()
    init_target(c, 'loop')
    r = c.request({'id': 'att', 'cmd': 'attach .%d' % t.pid, 'wait': 'always', 'timeout_ms': 1500}, 60)
    ck('AC-27: attach wait=always while another session is live -> timed_out, running', isinstance(r, dict) and r['ok'] and r['wait']['timed_out'] is True and r['state']['status'] == 'running', (r['wait'], r['state']['status'], r['error']) if isinstance(r, dict) else r)
    c.request({'id': 'det', 'cmd': 'detach'}, 30)
    c.quit()
    t.kill()
    t.wait()

    # text-mode twins
    for label, line, expect in (('on_timeout pause', '!native --timeout_ms 500 --on_timeout pause -- run', ('state=paused', 'wait=timeout')),
                                ('on_timeout stop', '!native --on_timeout stop --timeout_ms 500 -- run', ('state=stopped',)),
                                ('wait never', '!native --wait never -- run', ('state=running',))):
        c = Cli('wait_options_text_' + label.replace(' ', '_'), json_mode=False)
        ready = c.next_line(25)
        ck('AC-27: text mode ready line (%s)' % label, ready is not None and ready.startswith('@@READY'), ready)
        body, end = text_command(c, 'init "%s", "loop"' % TARGET, 60)
        body, end = text_command(c, line, 30)
        ck('AC-27: text twin "%s" -> %s' % (line, ' '.join(expect)), end is not None and all(e in end for e in expect), end)
        if label == 'wait never':
            ck('AC-27: wait never has no wait= reason other than none', end is not None and ('wait=' not in end or 'wait=none' in end), end)
        text_command(c, 'stop', 30)
        text_command(c, '!quit', 30)
        try:
            c.p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            c.p.kill()
        c.log.close()
        shutil.rmtree(c.ud, ignore_errors=True)


# ------------------------------------------------------------------ shutdown with detach (--detach-on-exit, quit detach)

@scenario
def shutdown_detach():
    for label, args, extra in (('default shutdown kills the attached target', {}, []),
                               ('quit {"detach":true} leaves it alive', {'detach': True}, []),
                               ('--detach-on-exit leaves it alive', {}, ['--detach-on-exit'])):
        t = start_target('loop')
        time.sleep(0.5)
        c = Cli('shutdown_detach', args=extra)
        c.hello()
        r = c.request({'id': 'att', 'cmd': 'attach .%d' % t.pid}, 60)
        ck('shutdown: attach ok (%s)' % label, isinstance(r, dict) and r['ok'], r['error'] if isinstance(r, dict) else r)
        time.sleep(0.5)
        c.send({'id': 'q', 'op': 'quit', 'args': args})
        try:
            rc = c.p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            c.p.kill()
            rc = 'killed'
        time.sleep(1)
        alive = t.poll() is None
        want_alive = bool(args.get('detach')) or bool(extra)
        ck('shutdown: %s (exit %s, target alive: %s)' % (label, rc, alive), rc == 0 and alive == want_alive, (rc, alive))
        t.kill()
        t.wait()
        c.log.close()
        shutil.rmtree(c.ud, ignore_errors=True)
    # one-shot form
    t = start_target('loop')
    time.sleep(0.5)
    ud = tempfile.mkdtemp(prefix='clitest_')
    out = subprocess.run([EXE, '--userdir', ud, '--attach', str(t.pid), '--detach-on-exit', '--exec', 'log x'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
    time.sleep(1)
    ck('shutdown: one-shot --attach <pid> --detach-on-exit leaves the target alive (exit %d)' % out.returncode, out.returncode == 0 and t.poll() is None, (out.returncode, t.poll()))
    t.kill()
    t.wait()
    shutil.rmtree(ud, ignore_errors=True)


# ------------------------------------------------------------------ T34

@scenario
def attribution_integration():
    c = Cli('attr_thread_start', ini_extra='ThreadStart=1\n')
    c.hello()
    init_target(c, 'threads')
    r = c.request({'id': 'run', 'cmd': 'run'}, 60)
    ck('T34: ThreadStart=1, threads mode: stop.reason thread_start', isinstance(r, dict) and r['state']['status'] == 'paused' and r['state']['stop'] and r['state']['stop']['reason'] == 'thread_start', r['state'] if isinstance(r, dict) else r)
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()

    c = Cli('attr_debug_string', ini_extra='DebugStrings=1\n')
    c.hello()
    init_target(c, 'ods')
    r = c.request({'id': 'run', 'cmd': 'run'}, 60)
    ck('T34: DebugStrings=1, ods mode: stop.reason debug_string', isinstance(r, dict) and r['state']['status'] == 'paused' and r['state']['stop'] and r['state']['stop']['reason'] == 'debug_string', r['state'] if isinstance(r, dict) else r)
    ck('T34: the debug_string event carries the text hello-ods', any(e['type'] == 'debug_string' and e['text'] == 'hello-ods' for e in r['events']), r['events'])
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()

    c = Cli('attr_dll_unload', ini_extra='DllUnloadSystem=1\n')
    c.hello()
    init_target(c, 'unload')
    r = c.request({'id': 'run', 'cmd': 'run'}, 60)
    ck('T34: DllUnloadSystem=1, unload mode: stop.reason dll_unload (never dll_load)', isinstance(r, dict) and r['state']['status'] == 'paused' and r['state']['stop'] and r['state']['stop']['reason'] == 'dll_unload', r['state'] if isinstance(r, dict) else r)
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()

    c = Cli('attr_pause_threads_default')
    c.hello()
    init_target(c, 'threads')
    bad = []
    for i in range(20):
        # a pending run carries the stop reason; the OOB pause answer does not (AC-9)
        c.send({'id': 'run%d' % i, 'cmd': 'run', 'timeout_ms': 30000})
        time.sleep(0.15)
        p = c.request({'id': 'p%d' % i, 'cmd': 'pause'}, 30)
        r = c.wait_response('run%d' % i, 30)
        st = r['state'] if isinstance(r, dict) else None
        if not (isinstance(p, dict) and p['state']['status'] == 'paused' and st and st['status'] == 'paused' and st['stop'] and st['stop']['reason'] == 'pause'):
            bad.append((i, st))
    ck('T34: default settings, threads mode, 20 x pause during run: stop.reason pause every time', not bad, bad[:3])
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()


# ------------------------------------------------------------------ T39

@scenario
def userdir_lock_and_noconsole():
    c = Cli('userdir_lock')
    c.hello()
    t0 = time.time()
    p = subprocess.run([EXE, '--json', '--userdir', c.ud], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60, stdin=subprocess.DEVNULL, env=dict(os.environ))
    ck('T39: a second CLI on the same --userdir exits 2 (%.1f s)' % (time.time() - t0), p.returncode == 2, (p.returncode, p.stderr[:200]))
    ck('T39: the exit comes with a message on stderr', 'userdir' in p.stderr.lower() or 'in use' in p.stderr.lower() or 'lock' in p.stderr.lower(), p.stderr[:300])
    ck('T39: the first CLI keeps working', c.request({'id': 'e', 'op': 'eval', 'args': {'expr': '2+2'}})['ok'], '')
    c.quit()

    # NoConsoleWindow restore: original value kept (0), or 0 when the key was absent
    for label, ini in (('present=0', '[Engine]\nNoConsoleWindow=0\n'), ('absent', '')):
        ud = tempfile.mkdtemp(prefix='clitest_')
        with open(os.path.join(ud, 'x64dbg-cli.ini'), 'w') as f:
            f.write(ini)
        p = subprocess.run([EXE, '--json', '--userdir', ud, '--no-console-window', '--exec', 'log noconsole'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60, stdin=subprocess.DEVNULL, env=dict(os.environ))
        with open(os.path.join(ud, 'x64dbg-cli.ini'), encoding='utf-8', errors='replace') as f:
            text = f.read()
        val = None
        sect = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('['):
                sect = line
            elif sect == '[Engine]' and line.lower().startswith('noconsolewindow'):
                val = line.split('=', 1)[1].strip()
        ck('T39: --no-console-window (%s): exit %d, ini NoConsoleWindow afterwards is %r (original 0 or absent -> 0)' % (label, p.returncode, val), p.returncode == 0 and val in ('0',), text[-200:])
        shutil.rmtree(ud, ignore_errors=True)


# ------------------------------------------------------------------ T15

@scenario
def unicode_roundtrip():
    d = os.path.join(tempfile.mkdtemp(prefix='cliuni_'), 't\u00e9st_\u76ee\u5f55_\u2603')
    os.makedirs(d)
    exe = os.path.join(d, 'cli_target.exe')
    shutil.copy(TARGET, exe)
    c = Cli('unicode_roundtrip')
    c.hello()
    # send the request once with escaped and once with raw UTF-8 text
    r = c.request({'id': 'init', 'cmd': 'init "%s", "call"' % exe}, 60)
    ck('T15: init of a debuggee in a non-ASCII directory -> paused', isinstance(r, dict) and r['ok'] and r['state']['status'] == 'paused', (r['error'], r['output'][-200:]) if isinstance(r, dict) else r)
    s = c.request({'id': 'st', 'op': 'status'})
    ck('T15: process.path round-trips exactly', s['data']['process'] and s['data']['process']['path'].lower() == exe.lower(), s['data']['process'])
    label = 'caf\u00e9_\u65e5\u672c\u8a9e_\u2713'
    c.send_raw(json.dumps({'id': 'lbl', 'cmd': 'lbl rip,"%s"; labellist' % label}, ensure_ascii=False) + '\n')
    r = c.wait_response('lbl', 30)
    rows = r['tables'][0]['rows'] if r['tables'] else []
    ck('T15: raw UTF-8 request: label text round-trips exactly in tables', any(label in ' '.join(row) for row in rows), rows[:2])
    c.send_raw(json.dumps({'id': 'lbl2', 'cmd': 'lbl rip+1,"%s"; labellist' % '\u00fcn\u00ef\u2603'}, ensure_ascii=True) + '\n')
    r = c.wait_response('lbl2', 30)
    rows = r['tables'][0]['rows'] if r['tables'] else []
    ck('T15: \\u-escaped request: label text round-trips exactly in tables', any('\u00fcn\u00ef\u2603' in ' '.join(row) for row in rows), rows[:2])
    r = c.request({'id': 'lg', 'cmd': 'log "h\u00e9llo \u2713"'})
    ck('T15: log output with non-ASCII text', r['output'] == 'h\u00e9llo \u2713', r['output'])
    ok = True
    for line in c.lines:
        try:
            line.encode('utf-8').decode('utf-8')
        except UnicodeError:
            ok = False
    ck('T15: every stdout line is valid UTF-8 without ESC', ok and not any('\x1b' in l for l in c.lines), '')
    c.request({'id': 'stop', 'cmd': 'stop'}, 30)
    c.quit()
    shutil.rmtree(os.path.dirname(d), ignore_errors=True)


# ------------------------------------------------------------------ T14

@scenario
def dialogs_and_prompts():
    # (1) msgyn default and --msgyn yes with vars:["$result"]
    c = Cli('t14_msgyn_default')
    c.hello()
    r = c.request({'id': 'm', 'cmd': 'msgyn "continue?"', 'vars': ['$result']})
    ck('T14: msgyn with the default policy -> $result 0 and a prompt event', r['ok'] and r['vars'].get('$result') == '0x0000000000000000' and any(e['type'] == 'prompt' for e in r['events']), (r['vars'], r['events']))
    c.quit()
    c = Cli('t14_msgyn_yes', args=['--msgyn', 'yes'])
    c.hello()
    r = c.request({'id': 'm', 'cmd': 'msgyn "continue?"', 'vars': ['$result']})
    ck('T14: --msgyn yes -> $result 1', r['ok'] and r['vars'].get('$result') == '0x0000000000000001', r['vars'])
    c.quit()

    # (2) the 30 s script question is answered "continue" regardless of --msgyn yes
    d = tempfile.mkdtemp(prefix='cliscript_')
    script = os.path.join(d, 'long.txt')
    with open(script, 'w', newline='\n') as f:
        f.write('mov $i, 0\nloop:\nzzz .100\nadd $i, 1\ncmp $i, 14a\njne loop\nlog "long-script-done"\n')
    c = Cli('t14_script_timeout', args=['--msgyn', 'yes', '--stuck-ms', '90000'])
    c.hello()
    t0 = time.time()
    r = c.request({'id': 'long', 'cmd': 'scriptexec ' + script, 'timeout_ms': 80000}, 120)
    el = time.time() - t0
    prompts = [e for e in r['events'] if e['type'] == 'prompt'] if isinstance(r, dict) else []
    ck('T14: a script running > 30 s raises the question and it is answered continue (%.1f s)' % el, isinstance(r, dict) and r['ok'] and el > 30 and any(e['text'] and e['text'].startswith('The script has been running for a while') and e['answer'] == 0 for e in prompts), (prompts, r['output'][-200:]) if isinstance(r, dict) else r)
    ck('T14: the script ran to the end (not terminated by the user)', isinstance(r, dict) and 'long-script-done' in r['output'] and 'terminated' not in r['output'], r['output'][-200:] if isinstance(r, dict) else r)
    c.quit()
    shutil.rmtree(d, ignore_errors=True)

    # (3) the elevation prompt of a requireAdministrator target is dismissed by the dialog guard
    c = Cli('t14_admin_dialog')
    c.hello()
    t0 = time.time()
    r = c.request({'id': 'adm', 'cmd': 'init "%s", "call"' % ADMIN_TARGET}, 90)
    el = time.time() - t0
    evs = [e for e in r['events'] if e['type'] == 'dialog_dismissed'] if isinstance(r, dict) else []
    ck('T14: init of cli_target_admin.exe from a non-elevated shell does not hang (%.1f s)' % el, isinstance(r, dict) and el < 30, r)
    ck('T14: the dialog guard dismissed the elevation prompt (dialog_dismissed event)', bool(evs) and 'requires elevation' in evs[0]['text'], evs)
    ck('T14: init reports a failure with the core text (ERROR_ELEVATION_REQUIRED)', isinstance(r, dict) and not r['ok'] and 'ELEVATION_REQUIRED' in r['error']['message'], r['error'] if isinstance(r, dict) else r)
    r = c.request({'id': 'after', 'op': 'eval', 'args': {'expr': '1+1'}})
    ck('T14: the CLI keeps working after the dismissed dialog', r['ok'], r)
    rc = c.quit()
    ck('T14: exits 0', rc == 0, rc)


def main():
    names = sys.argv[1:]
    for name, fn in list(globals().items()):
        if getattr(fn, 'is_scenario', False) and (not names or name in names):
            acc.CURRENT[0] = name
            print('== %s' % name)
            try:
                fn()
            except Exception as e:  # report and continue
                import traceback
                traceback.print_exc()
                ck('scenario completed without exception', False, repr(e))
    failed = [r for r in acc.RESULTS if not r[2]]
    print('\n%d checks, %d failed' % (len(acc.RESULTS), len(failed)))
    for r in failed:
        print('  FAILED [%s] %s: %s' % (r[0], r[1], str(r[3])[:300]))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
