#!/usr/bin/env python3
"""Validates the envelope types of design 8.3 (hello, response, event, unsolicited, fatal) on every JSON line.

Usage: python src/cli/tests/test_envelope.py [--no-live] [--no-transcripts]
  live:        starts x64dbg-cli.exe --json, runs a short session and validates every line it prints
  transcripts: validates every JSON line ("< " prefix) of .agents/tasks/cli/transcripts/*.jsonl, i.e. the responses
               of all other tests that were run before
Exit code 0 when every line is valid.
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m1_acceptance as acc  # noqa: E402
from schemalib import Schemas, SchemaError  # noqa: E402

ck = acc.ck


def validate_line(schemas, obj):
    t = obj.get('type') if isinstance(obj, dict) else None
    if t == 'hello':
        return schemas.validate('hello', obj)
    if t == 'response':
        errs = schemas.validate('response', obj)
        for i, ev in enumerate(obj.get('events', [])):
            errs += ['events[%d]: %s' % (i, e) for e in schemas.validate('event', ev)]
        if obj.get('op') and obj['op'] not in schemas.ops:
            errs.append('op %s has no schema file' % obj['op'])
        return errs
    if t == 'event':
        errs = schemas.validate('unsolicited', obj)
        return errs
    if t == 'fatal':
        return schemas.validate('fatal', obj)
    return ['unknown line type %r' % t]


def live(schemas):
    acc.CURRENT[0] = 'envelope_live'
    c = acc.Cli('envelope_live')
    h = c.hello()
    lines = []
    reqs = [
        {'id': 1, 'op': 'eval', 'args': {'expr': '1+1'}},
        {'id': 2, 'op': 'eval', 'args': {'expr': 'nosuchsymbol'}},
        {'id': 3, 'cmd': 'bp kernel32.Sleep'},
        {'id': 4, 'cmd': 'log hi'},
        {'id': 5, 'op': 'status'},
        {'id': 6, 'op': 'nosuchop'},
        {'id': 7, 'cmd': 'init "%s", "call"' % acc.TARGET},
        {'id': 8, 'cmd': 'bp kernel32.Sleep'},
        {'id': 9, 'cmd': 'run'},
        {'id': 10, 'cmd': 'sti'},
        {'id': 11, 'cmd': 'findall rip,90'},
        {'id': 12, 'cmd': 'run', 'timeout_ms': 300},
        {'id': 13, 'cmd': 'stop'},
        {'id': 14, 'cmd': 'bp'},
    ]
    resp = [h]
    for q in reqs:
        resp.append(c.request(q, 60))
    c.send_raw('not json\n')
    garbage = c.next_line(10)
    resp.append(json.loads(garbage))
    for o in c.events:
        resp.append({'type': 'event', 'v': 1, 'event': o})
    bad = 0
    for o in resp:
        errs = validate_line(schemas, o) if isinstance(o, dict) else ['not a response: %r' % (o,)]
        if errs:
            bad += 1
            ck('line %s %s matches the envelope schema' % (o.get('type') if isinstance(o, dict) else '?', o.get('id') if isinstance(o, dict) else ''), False, errs[:4])
    ck('live: %d lines (hello, responses, events) match the envelope schema' % len(resp), bad == 0, bad)
    rc = c.quit()
    ck('live: quit exits 0', rc == 0, rc)


def transcripts(schemas):
    acc.CURRENT[0] = 'envelope_transcripts'
    files = sorted(glob.glob(os.path.join(acc.TRANSCRIPTS, '*.jsonl')))
    total = 0
    bad = 0
    shown = 0
    for path in files:
        with open(path, encoding='utf-8', errors='replace') as f:
            text_lines = f.readlines()
        if any(l.startswith('< @@READY') for l in text_lines):
            continue  # text-mode transcript: its "{...}" lines are command output, not envelopes
        with open(path, encoding='utf-8', errors='replace') as f:
            for n, raw in enumerate(f, 1):
                if not raw.startswith('< {'):
                    continue
                try:
                    obj = json.loads(raw[2:])
                except ValueError:
                    bad += 1
                    total += 1
                    if shown < 15:
                        shown += 1
                        print('  FAIL %s:%d is not JSON' % (os.path.basename(path), n))
                    continue
                total += 1
                errs = validate_line(schemas, obj)
                if errs:
                    bad += 1
                    if shown < 15:
                        shown += 1
                        print('  FAIL %s:%d %s' % (os.path.basename(path), n, '; '.join(errs[:3])[:400]))
    ck('transcripts: %d JSON lines in %d files match the envelope schema' % (total, len(files)), bad == 0 and total > 0, '%d invalid' % bad)


if __name__ == '__main__':
    try:
        schemas = Schemas()
    except SchemaError as e:
        print('schema load failed:', e)
        sys.exit(1)
    if '--no-live' not in sys.argv:
        live(schemas)
    if '--no-transcripts' not in sys.argv:
        transcripts(schemas)
    failed = [r for r in acc.RESULTS if not r[2]]
    print('\n%d checks, %d failed' % (len(acc.RESULTS), len(failed)))
    sys.exit(1 if failed else 0)
