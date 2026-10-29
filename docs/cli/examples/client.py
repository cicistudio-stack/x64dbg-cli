#!/usr/bin/env python3
"""Minimal JSON-lines client for x64dbg-cli.exe (standard library only), and a demo that an AI tool can copy.

    python client.py <path\\to\\x64dbg-cli.exe> <target.exe> [target args]

The demo starts the debuggee, sets a breakpoint, runs to it, reads registers, live disassembly, the stack and the call stack, steps
once and shows that the disassembly follows the new instruction pointer, then stops the debuggee. Every request waits for its own
response by id; events that arrive in between are collected in `Cli.events`.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import queue


class Cli:
    def __init__(self, exe, userdir=None):
        self.userdir = userdir or tempfile.mkdtemp(prefix='x64dbg-cli-')
        self.p = subprocess.Popen([exe, '--json', '--userdir', self.userdir], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, bufsize=0)
        self.q = queue.Queue()
        self.events = []
        self.next_id = 0
        threading.Thread(target=self._reader, daemon=True).start()
        self.hello = self._take(lambda o: o.get('type') == 'hello', 30)

    def _reader(self):
        for raw in iter(self.p.stdout.readline, b''):
            try:
                self.q.put(json.loads(raw.decode('utf-8')))
            except ValueError:
                pass  # the protocol never sends anything but JSON lines; ignore garbage defensively
        self.q.put(None)

    def _take(self, pred, timeout):
        while True:
            o = self.q.get(timeout=timeout)
            if o is None:
                raise RuntimeError('x64dbg-cli.exe closed its output')
            if o.get('type') == 'event':
                self.events.append(o['event'])
            if pred(o):
                return o

    def call(self, request, timeout=120):
        """Sends one request ({'op': ..., 'args': ...} or {'cmd': ...}) and returns its response object."""
        self.next_id += 1
        request = dict(request, id=self.next_id)
        self.p.stdin.write((json.dumps(request) + '\n').encode('utf-8'))
        self.p.stdin.flush()
        rid = self.next_id
        return self._take(lambda o: o.get('type') == 'response' and o.get('id') == rid, timeout)

    def op(self, name, **args):
        return self.call({'op': name, 'args': args})

    def cmd(self, line, **options):
        return self.call(dict({'cmd': line}, **options))

    def close(self):
        try:
            self.call({'op': 'quit'}, 30)
        except Exception:
            pass
        try:
            self.p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.p.kill()


def need(r, what):
    if not r['ok']:
        raise SystemExit('%s failed: %s: %s' % (what, r['error']['code'], r['error']['message']))
    return r


def demo(exe, target, target_args):
    cli = Cli(exe)
    try:
        need(cli.op('init', file=target, args=' '.join(target_args)), 'init')
        r = need(cli.op('bp', action='add', target='kernel32.Sleep'), 'bp add')
        print('breakpoint:', r['data']['breakpoint']['id'])
        bp_addr = r['data']['breakpoint']['addr']
        for _ in range(5):  # with default settings the core also stops at the entry breakpoint (and TLS callbacks) first
            r = need(cli.op('run'), 'run')
            print('stopped:', r['state']['status'], r['state']['stop'], 'at', r['state']['cip_label'])
            if r['state']['stop'] and r['state']['stop'].get('bp') == bp_addr:
                break
        regs = need(cli.op('regs', groups='gpr'), 'regs')['data']['gpr']
        print('rip =', regs['rip'], ' rsp =', regs['rsp'])
        for row in need(cli.op('dis', count=3), 'dis')['data']['instructions']:
            print('  %s%s  %s' % ('=>' if row['is_cip'] else '  ', row['addr'], row['text']))
        for row in need(cli.op('stack', count=2), 'stack')['data']['rows']:
            print('  stack %s -> %s  %s' % (row['addr'], row['value'], row['comment'] or ''))
        frames = need(cli.op('callstack'), 'callstack')['data']['threads'][0]['frames']
        print('call stack:', ' <- '.join(f['comment'] for f in frames[:3]))
        need(cli.op('stepout'), 'stepout')
        first = need(cli.op('dis', count=1), 'dis after the step')['data']['instructions'][0]
        print('after stepout: %s %s (is_cip=%s)' % (first['addr'], first['text'], first['is_cip']))
        need(cli.op('stop'), 'stop')
    finally:
        cli.close()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    demo(sys.argv[1], os.path.abspath(sys.argv[2]), sys.argv[3:])
