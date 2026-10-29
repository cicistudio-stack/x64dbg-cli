#!/usr/bin/env python3
"""M2 acceptance runs for x64dbg-cli.exe: structured views, run-control wrappers, batch (stdlib only).

Usage: python src/cli/tests/m2_acceptance.py [scenario ...]
Transcripts: .agents/tasks/cli/transcripts/m2-<scenario>.jsonl. Every JSON response is validated as JSON and against
src/cli/schema/*.schema. Exit code 0 when every check passed.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m1_acceptance as acc  # noqa: E402
from m1_acceptance import Cli, ck, scenario, TARGET, EXE  # noqa: E402
from schemalib import Schemas  # noqa: E402

SCHEMAS = Schemas()
ADDR = re.compile(r'^0x[0-9a-f]{16}$')


class Sess:
    """A CLI process with request helpers that validate every response against the op schemas."""

    def __init__(self, name, **kw):
        self.name = name
        self.c = Cli(name, **kw)
        self.hello = self.c.hello()
        self.n = 0
        self.schema_checked = 0
        self.schema_errors = []

    def req(self, obj, timeout=60):
        self.n += 1
        obj = dict(obj)
        obj.setdefault('id', self.n)
        return self.c.request(obj, timeout)

    def op(self, name, args=None, timeout=60, **opt):
        obj = {'op': name}
        if args is not None:
            obj['args'] = args
        obj.update(opt)
        r = self.req(obj, timeout)
        if isinstance(r, dict):
            errs = []
            if r.get('ok'):
                if args is not None:
                    errs += SCHEMAS.validate_op(name, 'args', args)
                errs += SCHEMAS.validate_op(name, 'data', r.get('data'))
            self.schema_checked += 1
            if errs:
                self.schema_errors.append((name, args, errs[:3]))
        return r

    def cmd(self, line, timeout=60, **opt):
        obj = {'cmd': line}
        obj.update(opt)
        return self.req(obj, timeout)

    def ev(self, expr):
        r = self.op('eval', {'expr': expr})
        return r['data']['value'] if isinstance(r, dict) and r.get('ok') else None

    def init(self, mode='call', timeout=60):
        return self.op('init', {'file': TARGET, 'args': mode}, timeout)

    def finish(self, stop=True):
        if stop:
            self.req({'cmd': 'stop'}, 30)
        rc = self.c.quit()
        bad = []
        for line in self.c.lines:
            try:
                json.loads(line)
            except ValueError:
                bad.append(line[:80])
        ck('%s: every stdout line is valid JSON (%d lines)' % (self.name, len(self.c.lines)), not bad, bad[:2])
        ck('%s: %d op responses match their schemas' % (self.name, self.schema_checked), not self.schema_errors, self.schema_errors[:2])
        ck('%s: exits 0' % self.name, rc == 0, rc)
        return rc


def ok(r):
    return isinstance(r, dict) and r.get('ok') is True


def code(r):
    return r['error']['code'] if isinstance(r, dict) and r.get('error') else None


def procs(image):
    out = subprocess.run(['tasklist', '/fi', 'IMAGENAME eq ' + image, '/fo', 'csv', '/nh'], capture_output=True, text=True).stdout
    return [int(l.split('","')[1]) for l in out.splitlines() if image.lower() in l.lower()]


def hexbytes(row_hex):
    return bytes.fromhex(row_hex.replace(' ', ''))


# ------------------------------------------------------------------ main session (user request: the debugging walk)

@scenario
def session():
    s = Sess('m2-session')
    r = s.op('help')
    names = [o['name'] for o in r['data']['ops']]
    ck('help lists the M2 ops', all(n in names for n in ('regs', 'dis', 'mem', 'memmap', 'stack', 'callstack', 'bps', 'bp', 'threads', 'thread', 'modules', 'sym', 'process', 'init', 'run', 'stepin')), names)
    ck('hello announces the M2 ops', all(n in s.hello['capabilities']['ops'] for n in ('regs', 'dis', 'mem', 'init')), s.hello['capabilities']['ops'])
    r = s.init('call')
    ck('init op: ok, paused at the system breakpoint', ok(r) and r['state']['status'] == 'paused' and r['state']['stop']['reason'] == 'system_breakpoint', r['error'] if isinstance(r, dict) else r)
    pid = r['state']['pid']
    r = s.op('process')
    ck('process: pid, path, cmdline, entry, peb/teb, elevation fields', ok(r) and r['data']['pid'] == pid and r['data']['name'] == 'cli_target.exe' and 'call' in r['data']['cmdline'] and r['data']['elevated'] is False, r['data'] if ok(r) else r)
    r = s.op('bp', {'action': 'add', 'target': 'kernel32.Sleep'})
    ck('bp add: software breakpoint on kernel32.Sleep', ok(r) and r['data']['breakpoint']['kind'] == 'sw' and r['data']['breakpoint']['enabled'], r['error'] if isinstance(r, dict) else r)
    bp_addr = r['data']['breakpoint']['addr']
    r = s.op('run')
    ck('run op: paused at the breakpoint', ok(r) and r['state']['status'] == 'paused' and r['state']['stop']['reason'] == 'breakpoint' and r['state']['stop']['bp'] == bp_addr, r['state'] if isinstance(r, dict) else r)
    r = s.op('status')
    ck('status: state, pid, process name, module base, rip (state.cip), last event', ok(r) and r['data']['process']['name'] == 'cli_target.exe' and ADDR.match(r['data']['csp']) and ADDR.match(r['data']['process']['base']) and r['state']['pid'] == pid and r['state']['cip'] == bp_addr and r['data']['last_event']['type'] == 'paused', r['data'] if ok(r) else r)
    # registers
    r = s.op('regs', {'groups': 'gpr,flags,seg,dbg,fpu,mmx,xmm,ymm'})
    ck('regs: gpr/flags/seg/dbg/fpu/mmx/xmm/ymm groups', ok(r) and set(r['data']) >= {'gpr', 'flags', 'seg', 'dbg', 'fpu', 'mmx', 'xmm', 'ymm', 'last_error', 'last_status'} and len(r['data']['fpu']['st']) == 8 and len(r['data']['ymm']) == 16, list(r['data']) if ok(r) else r)
    rip = r['data']['gpr']['rip'] if ok(r) else None
    ck('regs: rip equals the breakpoint and state.cip', rip == bp_addr == r['state']['cip'], (rip, bp_addr))
    ck('regs: last_error names the error of the failed CreateFileW', r['data']['last_error']['name'] in ('ERROR_FILE_NOT_FOUND', 'ERROR_PATH_NOT_FOUND'), r['data']['last_error'])
    r2 = s.op('regs', {'groups': 'all'})
    ck('regs all: xmm/ymm present, zmm only when the CPU has AVX-512', ok(r2) and 'ymm' in r2['data'], list(r2['data']) if ok(r2) else r2)
    # disassembly at RIP
    r = s.op('dis', {'count': 6})
    rows = r['data']['instructions'] if ok(r) else []
    ck('dis at rip: 6 rows, first row is_cip with a breakpoint marker', ok(r) and len(rows) == 6 and rows[0]['is_cip'] and rows[0]['addr'] == rip and rows[0]['bp'] == 'normal' and not any(x['is_cip'] for x in rows[1:]), rows[:1])
    ck('dis: rows carry bytes, text, label, branch information', all(x['bytes'] and x['text'] for x in rows) and rows[0]['label'] == 'Sleep' and rows[0]['kind'] == 'branch' and rows[0]['branch']['target'], rows[0] if rows else r)
    r = s.op('dis', {'addr': 'rip', 'until': 'rip+8', 'bytes': False})
    ck('dis --until and bytes:false', ok(r) and all('bytes' not in x for x in r['data']['instructions']) and r['data']['instructions'][-1]['addr'] < '0x%016x' % (int(rip, 16) + 8), r['data'] if ok(r) else r)
    r = s.op('dis', {'addr': 'rip', 'count': 3, 'back': 2})
    ck('dis --back starts before rip and still reaches rip', ok(r) and int(r['data']['start'], 16) < int(rip, 16) and any(x['is_cip'] for x in r['data']['instructions']), r['data']['start'] if ok(r) else r)
    # stack, call stack
    r = s.op('stack', {'count': 8})
    csp = r['data']['csp'] if ok(r) else None
    ck('stack: 8 slots from csp, first row is_csp with offset 0', ok(r) and len(r['data']['rows']) == 8 and r['data']['rows'][0]['is_csp'] and r['data']['rows'][0]['offset'] == 0 and r['data']['rows'][0]['addr'] == csp and not r['data']['live'], r['data']['rows'][:1] if ok(r) else r)
    ck('stack: the first slot is the return address into cli_target', 'cli_target' in (r['data']['rows'][0]['comment'] or ''), r['data']['rows'][0])
    r = s.op('callstack')
    fr = r['data']['threads'][0]['frames'] if ok(r) else []
    ck('callstack: frames with return addresses, the first returns into cli_target', ok(r) and len(fr) >= 3 and 'cli_target' in fr[0]['comment'] + (fr[1]['comment']) and fr[0]['from'] == rip, fr[:2])
    r = s.op('callstack', {'thread': 'all'})
    ck('callstack all: every thread', ok(r) and len(r['data']['threads']) >= 2, r['data']['threads'][:1] if ok(r) else r)
    # memory
    r = s.op('mem', {'addr': 'rsp', 'size': 64, 'format': 'hex64'})
    ck('mem rsp 64 bytes as hex64: 8 items, 4 rows', ok(r) and r['data']['size'] == 64 and len(r['data']['items']) == 8 and len(r['data']['rows']) == 4 and len(r['data']['hex']) == 128, r['data']['items'][:2] if ok(r) else r)
    qword = int.from_bytes(bytes.fromhex(r['data']['hex'][:16]), 'little')
    ck('mem: the first qword equals eval [rsp]', int(s.ev('[rsp]'), 16) == qword)
    formats = ['hex', 'ascii', 'utf16', 'int8', 'int16', 'int32', 'int64', 'uint8', 'uint16', 'uint32', 'uint64', 'hex8', 'hex16', 'hex32', 'hex64', 'float', 'double', 'half', 'ldouble', 'ptr']
    bad = []
    for f in formats:
        r = s.op('mem', {'addr': 'rsp', 'size': 40, 'format': f, 'cols': 8})
        if not ok(r) or r['data']['format'] != f or (f != 'hex' and not r['data']['items']):
            bad.append((f, r['error'] if isinstance(r, dict) else r))
    ck('mem: all 20 formats return data', not bad, bad)
    r = s.op('mem', {'addr': 'rip', 'size': 16})
    ck('mem at rip: module, section, label', ok(r) and r['data']['module'] == 'kernel32' and r['data']['section'] == '.text' and r['data']['label'] == 'Sleep', r['data'] if ok(r) else r)
    # modules, threads, memory map, symbols
    r = s.op('modules')
    mods = r['data']['modules'] if ok(r) else []
    names = [m['name'].lower() for m in mods]
    ck('modules: cli_target (main), ntdll, kernel32 with size, path, entry', ok(r) and 'cli_target.exe' in names and 'ntdll.dll' in names and 'kernel32.dll' in names and all(m['size'] > 0 and m['path'] for m in mods) and sum(m['is_main'] for m in mods) == 1, names)
    r = s.op('modules', {'filter': 'kernel'})
    ck('modules --filter', ok(r) and r['data']['count'] == len(r['data']['modules']) >= 2 and all('kernel' in m['name'].lower() for m in r['data']['modules']), r['data']['count'] if ok(r) else r)
    r = s.op('threads')
    th = r['data']['threads'] if ok(r) else []
    ck('threads: list with a current main thread', ok(r) and len(th) >= 1 and sum(t['is_current'] for t in th) == 1 and r['data']['current_tid'] == r['state']['tid'] and any(t['is_main'] for t in th), th[:1])
    r = s.op('memmap')
    pages = r['data']['pages'] if ok(r) else []
    ck('memmap: pages with rights, types, modules', ok(r) and r['data']['count'] == len(pages) > 10 and any(p['type'] == 'image' and p['module'] for p in pages) and any(p['protect'].startswith('-R') for p in pages), len(pages))
    r = s.op('memmap', {'filter': 'kernel32'})
    ck('memmap --filter by module name (info or module)', ok(r) and r['data']['count'] > 1 and all('kernel32' in (p['info'] + str(p['module'])).lower() for p in r['data']['pages']), r['data']['count'] if ok(r) else r)
    r = s.op('bps')
    ck('bps: the breakpoint with hit count 1', ok(r) and r['data']['count'] == 1 and r['data']['breakpoints'][0]['id'] == 'sw:' + bp_addr and r['data']['breakpoints'][0]['hit_count'] == 1, r['data'] if ok(r) else r)
    r = s.cmd('bplist')
    ck('bplist (native) names the same address', ok(r) and bp_addr[2:].upper().lstrip('0') in r['output'].upper().replace('0X', ''), r['output'][:200] if ok(r) else r)
    r = s.op('sym', {'pattern': 'CreateFileW', 'module': 'kernel32', 'limit': 10})
    ck('sym search: exports of kernel32 matching CreateFileW', ok(r) and any(x['name'] == 'CreateFileW' and x['type'] == 'export' and x['ordinal'] for x in r['data']['symbols']), r['data'] if ok(r) else r)
    r = s.op('sym', {'addr': 'rip'})
    ck('sym addr -> name: Sleep, offset 0', ok(r) and r['data']['resolved']['label'] == 'Sleep' and r['data']['resolved']['offset'] == 0, r['data'] if ok(r) else r)
    r = s.op('sym', {'pattern': 'Sleep*', 'type': 'export', 'limit': 3, 'offset': 1})
    ck('sym glob, type filter, limit/offset', ok(r) and 1 <= len(r['data']['symbols']) <= 3 and all(x['type'] == 'export' for x in r['data']['symbols']), r['data'] if ok(r) else r)
    # eval, set register, patch memory and re-read
    r = s.op('eval', {'expr': 'rip'})
    ck('eval rip equals regs rip', ok(r) and r['data']['value'] == rip)
    r = s.op('setreg', {'reg': 'rax', 'value': '0x1122334455667788'})
    ck('setreg rax', ok(r) and r['data'] == {'reg': 'rax', 'value': '0x1122334455667788'}, r['error'] if isinstance(r, dict) else r)
    r = s.op('regs', {'groups': 'gpr'})
    ck('regs after setreg shows the new rax', ok(r) and r['data']['gpr']['rax'] == '0x1122334455667788')
    r = s.op('setreg', {'reg': 'eflags', 'value': '0x346'})
    r = s.op('regs', {'groups': 'flags'})
    ck('setreg eflags changes the flag bits', ok(r) and r['data']['flags']['zf'] == 1 and r['data']['flags']['pf'] == 1, r['data'] if ok(r) else r)
    ck('setreg rejects vector registers and bad values', code(s.op('setreg', {'reg': 'xmm0', 'value': '1'})) == 'E_UNSUPPORTED' and code(s.op('setreg', {'reg': 'rax', 'value': 'nosuchsymbol'})) == 'E_BAD_ARG')
    r = s.cmd('alloc 1000', vars=['$result'])
    area = r['vars']['$result'] if ok(r) else None
    ck('alloc a scratch page', ok(r) and area and area != '0x0000000000000000', r)
    r = s.op('memwrite', {'addr': area, 'hex': 'de ad be ef 01 02 03 04'})
    ck('memwrite hex (patched)', ok(r) and r['data'] == {'addr': area, 'written': 8, 'patched': True}, r['error'] if isinstance(r, dict) else r)
    r = s.op('mem', {'addr': area, 'size': 8})
    ck('re-read after patch', ok(r) and r['data']['hex'] == 'deadbeef01020304', r['data']['hex'] if ok(r) else r)
    r = s.op('memwrite', {'addr': area, 'ascii': 'AB', 'patch': False})
    r2 = s.op('mem', {'addr': area, 'size': 4})
    ck('memwrite ascii (not patched)', ok(r) and r['data']['patched'] is False and r2['data']['hex'] == '4142beef', r2['data']['hex'] if ok(r2) else r2)
    r = s.op('memwrite', {'addr': area + '+10', 'utf16': 'hi'})
    r2 = s.op('mem', {'addr': area + '+10', 'size': 4})
    ck('memwrite utf16', ok(r) and r2['data']['hex'] == '68006900', r2['data']['hex'] if ok(r2) else r2)
    tmp = os.path.join(tempfile.gettempdir(), 'm2_memwrite_file.bin')
    with open(tmp, 'wb') as f:
        f.write(bytes(range(1, 201)))
    r = s.op('memwrite', {'addr': area + '+100', 'file': tmp})
    r2 = s.op('mem', {'addr': area + '+100', 'size': 200})
    ck('memwrite --file writes the whole file', ok(r) and r['data']['written'] == 200 and ok(r2) and r2['data']['hex'] == bytes(range(1, 201)).hex(), r['error'] if isinstance(r, dict) and not ok(r) else r2)
    os.remove(tmp)
    ck('memwrite rejects two sources and bad hex', code(s.op('memwrite', {'addr': area, 'hex': '90', 'ascii': 'x'})) == 'E_BAD_ARG' and code(s.op('memwrite', {'addr': area, 'hex': '9'})) == 'E_BAD_ARG')
    # step in / over / out (AC-14)
    for name, op in (('step into', 'stepin'), ('step over', 'stepover')):
        before = s.op('eval', {'expr': 'rip'})['data']['value']
        r = s.op(op)
        d = s.op('dis', {'count': 3})
        ck('%s: stop.reason step, cip moved, dis starts at the new cip with is_cip' % name, ok(r) and r['state']['stop'] and r['state']['stop']['reason'] == 'step' and r['state']['cip'] != before and ok(d) and d['data']['instructions'][0]['is_cip'] and d['data']['instructions'][0]['addr'] == r['state']['cip'], (r['state'], d['data']['instructions'][0] if ok(d) else d))
    r = s.op('stepout')
    d = s.op('dis', {'count': 2})
    ck('step out: returns, dis starts at the new cip', ok(r) and r['state']['stop'] and r['state']['stop']['reason'] == 'step' and ok(d) and d['data']['instructions'][0]['is_cip'] and d['data']['instructions'][0]['addr'] == r['state']['cip'], (r['state'], d))
    # thread switch with a decimal tid (AC-38)
    r = s.op('threads')
    cur = r['data']['current_tid']
    other = [t for t in r['data']['threads'] if t['tid'] != cur and t['tid'] > 9]
    if other:
        r = s.op('thread', {'action': 'switch', 'tid': other[0]['tid']})
        ck('thread switch to a decimal tid makes it current (state.tid)', ok(r) and r['state']['tid'] == other[0]['tid'], r['state'] if isinstance(r, dict) else r)
        r = s.op('regs', {'groups': 'gpr'})
        ck('regs follows the thread switch', ok(r) and r['data']['thread'] == other[0]['tid'])
        r = s.op('thread', {'action': 'switch', 'tid': cur})
        ck('thread switch back', ok(r) and r['state']['tid'] == cur)
    else:
        ck('a second thread exists for the switch test', False, r['data']['threads'])
    r = s.op('thread', {'action': 'suspend', 'tid': cur})
    r2 = s.op('threads')
    ck('thread suspend increments the suspend count', ok(r) and [t for t in r2['data']['threads'] if t['tid'] == cur][0]['suspend_count'] >= 2, r)
    r = s.op('thread', {'action': 'resume', 'tid': cur})
    ck('thread name / priority', ok(s.op('thread', {'action': 'name', 'tid': cur, 'value': 'walker'})) and ok(s.op('thread', {'action': 'priority', 'tid': cur, 'value': 'AboveNormal'})))
    r = s.op('threads')
    t = [t for t in r['data']['threads'] if t['tid'] == cur][0]
    ck('thread name and priority are visible in threads', t['name'] == 'walker' and t['priority'] == 'AboveNormal', t)
    ck('thread rejects missing/forbidden keys', code(s.op('thread', {'action': 'switch'})) == 'E_BAD_ARG' and code(s.op('thread', {'action': 'suspend_all', 'tid': 1})) == 'E_BAD_ARG')
    r = s.op('stop')
    ck('stop op: stopped', ok(r) and r['state']['status'] == 'stopped', r['state'] if isinstance(r, dict) else r)
    s.finish(stop=False)


# ------------------------------------------------------------------ AC-13 cross-checks, T43

@scenario
def crosscheck():
    s = Sess('m2-crosscheck')
    s.init('call')
    s.op('bp', {'action': 'add', 'target': 'kernel32.Sleep'})
    r = s.op('run')
    ck('crosscheck: paused at the breakpoint', ok(r) and r['state']['status'] == 'paused')
    # regs rip == eval rip
    r = s.op('regs', {'groups': 'gpr'})
    ck('AC-13 regs rip equals eval rip', ok(r) and r['data']['gpr']['rip'] == s.ev('rip'))
    # dis text == log "{dis.text(rip)}"
    d = s.op('dis', {'count': 3})
    lg = s.cmd('log "{dis.text(rip)}"')
    ck('AC-13 first dis row text equals log "{dis.text(rip)}"', ok(d) and ok(lg) and d['data']['instructions'][0]['text'] == lg['output'], (d['data']['instructions'][0]['text'] if ok(d) else d, lg.get('output')))
    # AVX-512 instruction with masking and a memory operand (> 63 characters)
    r = s.cmd('alloc 1000', vars=['$result'])
    page = r['vars']['$result']
    base = int(page, 16)
    # vaddpd zmm17{k1}{z}, zmm18, zmmword ptr [r8+r9*8+0x12345678] (EVEX, 512 bit, masking and zeroing); the second candidate is shorter
    cand = [bytes.fromhex('6281edc1588cc878563412'), bytes.fromhex('62f1edc9588cd878563412')]
    text_len = 0
    blob = b''
    for c in cand:
        blob = c + c + c + b'\xc3'
        s.op('memwrite', {'addr': page, 'hex': blob.hex()})
        d = s.op('dis', {'addr': page, 'count': 4})
        if ok(d):
            text_len = max(len(x['text']) for x in d['data']['instructions'])
            if text_len > 63:
                break
    ck('AC-13 the AVX-512 listing has an instruction longer than 63 characters (%d)' % text_len, text_len > 63, d['data']['instructions'][0] if ok(d) else d)
    same = True
    detail = []
    for x in d['data']['instructions']:
        lg = s.cmd('log "{dis.text(%s)}"' % x['addr'])
        if not ok(lg) or lg['output'] != x['text']:
            same = False
            detail.append((x['addr'], x['text'], lg.get('output')))
    ck('AC-13 every row of the long-instruction listing equals {dis.text(addr)}', same, detail[:2])
    # mem rsp -n 32 equals DbgMemRead (compared through independent eval reads)
    m = s.op('mem', {'addr': 'rsp', 'size': 32})
    qs = [int(s.ev('[rsp+%x]' % (8 * i)), 16) for i in range(4)]
    want = b''.join(q.to_bytes(8, 'little') for q in qs).hex()
    ck('AC-13 mem rsp -n 32 equals the bytes the core reads', ok(m) and m['data']['hex'] == want, (m['data']['hex'] if ok(m) else m, want))
    # memmap
    mm = s.op('memmap')
    bases = [int(p['base'], 16) for p in mm['data']['pages']]
    ck('AC-13 memmap: count equals the pages, ascending bases', mm['data']['count'] == len(bases) and bases == sorted(bases))
    sample = mm['data']['pages'][:: max(1, len(bases) // 12)]
    wrong = []
    for p in sample:
        got = s.ev('mem.base(%s)' % p['base'])
        if p['state'] == 'commit' and got not in (p['base'], p['alloc_base']):
            wrong.append((p['base'], p['state'], p['alloc_base'], got))
    ck('AC-13 memmap sample (%d committed pages) agrees with mem.base()' % len(sample), not wrong, wrong[:3])
    # bps vs bplist
    s.op('bp', {'action': 'add', 'kind': 'hw', 'target': 'kernel32.CreateFileW', 'hw_type': 'x'})
    s.op('bp', {'action': 'add', 'kind': 'mem', 'target': page, 'mem_type': 'w'})
    s.op('bp', {'action': 'add', 'kind': 'dll', 'target': 'winhttp.dll'})
    s.op('bp', {'action': 'add', 'kind': 'exception', 'target': '0xc0000005'})
    b = s.op('bps')
    bl = s.cmd('bplist')
    listing = bl['output'].upper()
    seen = []
    for x in b['data']['breakpoints']:
        key = x['module'].upper() if x['kind'] == 'dll' else x['addr'][2:].upper().lstrip('0')
        seen.append((x['id'], key in listing))
    ck('AC-13 bps lists every breakpoint printed by bplist (%d)' % len(seen), len(seen) == 5 and all(v for _, v in seen), (seen, bl['output'][:300]))
    # T43: end of readable memory
    r = s.cmd('alloc 1000', vars=['$result'])
    p2 = r['vars']['$result']
    s.cmd('fill %s,90,1000' % p2)
    s.op('memwrite', {'addr': p2 + '+fff', 'hex': 'c3'})
    d = s.op('dis', {'addr': p2 + '+fe0', 'count': 32})
    rows = d['data']['instructions'] if ok(d) else []
    last = rows[-1] if rows else {}
    ck('T43 dis near the end of the page: every instruction down to ret, no truncated_reason', ok(d) and 'truncated_reason' not in d['data'] and last.get('text') == 'ret' and last.get('addr') == '0x%016x' % (int(p2, 16) + 0xfff) and last.get('tail') is True and all(x['text'] == 'nop' for x in rows[:-1]), (last, d['data'].get('truncated_reason') if ok(d) else d))
    ck('T43 the rows before the tail are not tail rows', ok(d) and not rows[0].get('tail'), rows[:1])
    fd = s.cmd('find %s,c3,1000' % p2, vars=['$result'])
    ck('memory search: find returns the address of the c3 byte in $result', ok(fd) and int(fd['vars']['$result'], 16) == int(p2, 16) + 0xfff, fd['vars'] if ok(fd) else fd)
    f = s.cmd('findall %s+fff,c3,1' % p2, timeout=60)
    cells = [row for t in f.get('tables', []) for row in t['rows']]
    ck('T43 findall shows ret for the last address', ok(f) and any('ret' in row[1].lower() for row in cells), cells[:3])
    # unreadable ranges
    d = s.op('mem', {'addr': p2 + '+ff0', 'size': 0x40})
    ck('mem across the end of the page reports the unreadable range', ok(d) and d['data']['unreadable'] == [{'addr': '0x%016x' % (int(p2, 16) + 0x1000), 'size': 0x30}], d['data']['unreadable'] if ok(d) else d)
    ck('mem at an unreadable address is E_MEMORY', code(s.op('mem', {'addr': '0x10', 'size': 8})) == 'E_MEMORY')
    ck('mem rejects bad size, cols, format and expression', code(s.op('mem', {'addr': 'rsp', 'size': 0})) == 'E_BAD_ARG' and code(s.op('mem', {'addr': 'rsp', 'cols': 65})) == 'E_BAD_ARG' and code(s.op('mem', {'addr': 'rsp', 'format': 'bogus'})) == 'E_BAD_ARG' and code(s.op('mem', {'addr': 'nosuchsymbol'})) == 'E_BAD_ARG')
    big = s.op('mem', {'addr': p2, 'size': 4096, 'format': 'uint8'}, max_response_bytes=65536)
    ck('mem clamps size to max_response_bytes with next_addr', ok(big) and big['data']['truncated'] and big['data']['next_addr'] == '0x%016x' % (int(p2, 16) + big['data']['size']) and big['data']['size'] < 4096, (big['data']['size'], big['data']['next_addr']) if ok(big) else big)
    fr = s.cmd('free %s' % p2)
    after = s.op('mem', {'addr': p2, 'size': 4})
    ck('alloc / free (native): the freed page is no longer readable', ok(fr) and code(after) == 'E_MEMORY', (fr.get('output'), after.get('error')))
    s.finish()


# ------------------------------------------------------------------ AC-15 state guards

@scenario
def guards():
    s = Sess('m2-guards')
    for op, args in (('regs', None), ('stack', None), ('setreg', {'reg': 'rax', 'value': '1'}), ('callstack', None)):
        r = s.op(op, args)
        ck('AC-15 %s without a session: E_NOT_DEBUGGING' % op, code(r) == 'E_NOT_DEBUGGING', r['error'] if isinstance(r, dict) else r)
    for op, args in (('mem', {'addr': '0x1000'}), ('dis', {'addr': '0x1000'}), ('threads', None), ('modules', None), ('memmap', None), ('process', None), ('sym', {'pattern': 'x'}), ('stack', {'addr': '0x1000'})):
        r = s.op(op, args)
        ck('%s without a session: E_NOT_DEBUGGING' % op, code(r) == 'E_NOT_DEBUGGING', r['error'] if isinstance(r, dict) else r)
    r = s.op('bps')
    ck('bps works without a session (empty list)', ok(r) and r['data'] == {'breakpoints': [], 'count': 0}, r['data'] if ok(r) else r)
    ck('pause/stop/detach/restart without a session', code(s.op('pause')) == 'E_NOT_DEBUGGING' and code(s.op('stop')) == 'E_NOT_DEBUGGING' and code(s.op('restart')) == 'E_BAD_ARG', None)
    r = s.op('init', {'file': TARGET + '.nonexistent'})
    ck('init of a missing file: E_COMMAND_FAILED with the core text', code(r) == 'E_COMMAND_FAILED' and 'File does not exist' in r['error']['message'], r['error'] if isinstance(r, dict) else r)
    ck('init without file is E_BAD_ARG', code(s.op('init', {})) == 'E_BAD_ARG')
    # starting rule: init with wait:never leaves the session starting
    r = s.op('init', {'file': TARGET, 'args': 'loop'}, wait='never')
    st = r['state']['status'] if ok(r) else None
    r1 = s.op('regs')
    r2 = s.op('mem', {'addr': '0x1000'})
    ck('starting: regs is E_RUNNING "session is starting; use wait"; memory ops are allowed', st in ('starting', 'running') and code(r1) == 'E_RUNNING' and (st != 'starting' or 'starting' in r1['error']['message']) and r2['error']['code'] != 'E_NOT_DEBUGGING', (st, r1['error'] if isinstance(r1, dict) else r1))
    r = s.req({'op': 'wait'}, 60)
    ck('wait completes the launch', ok(r) and r['state']['status'] == 'paused', r['state'] if isinstance(r, dict) else r)
    # running debuggee
    r = s.op('regs', {'groups': 'gpr'})
    rsp, rip = r['data']['gpr']['rsp'], r['data']['gpr']['rip']
    r = s.op('run', wait='never')
    ck('run wait:never -> running', ok(r) and r['state']['status'] == 'running', r['state'] if isinstance(r, dict) else r)
    for op, args in (('regs', None), ('stack', None), ('setreg', {'reg': 'rax', 'value': '1'}), ('callstack', None), ('dis', None)):
        r = s.op(op, args)
        ck('AC-15 %s on a running debuggee: E_RUNNING' % op, code(r) == 'E_RUNNING', r['error'] if isinstance(r, dict) else r)
    r = s.op('mem', {'addr': rsp, 'size': 16})
    ck('AC-15 mem on a running debuggee works with live:true', ok(r) and r['data']['live'] is True, r)
    r = s.op('dis', {'addr': rip, 'count': 2})
    ck('AC-15 dis <addr> on a running debuggee works with live:true, cip null', ok(r) and r['data']['live'] is True and r['data']['cip'] is None and not any(x['is_cip'] for x in r['data']['instructions']), r['data'] if ok(r) else r)
    r = s.op('stack', {'addr': rsp, 'count': 4})
    ck('AC-15 stack --addr on a running debuggee: live:true, csp and cbp null', ok(r) and r['data']['live'] is True and r['data']['csp'] is None and r['data']['cbp'] is None and not any(x['is_csp'] or x['is_cbp'] for x in r['data']['rows']) and r['data']['rows'][0]['offset'] == 0, r['data'] if ok(r) else r)
    for op, args in (('threads', None), ('modules', None), ('memmap', None), ('process', None), ('bps', None), ('sym', {'pattern': 'Sleep', 'module': 'kernel32', 'limit': 2})):
        r = s.op(op, args)
        ck('%s works on a running debuggee' % op, ok(r), r['error'] if isinstance(r, dict) else r)
    r = s.op('pause')
    ck('pause op: paused with stop.reason pause semantics (OOB)', ok(r) and r['state']['status'] == 'paused', r['state'] if isinstance(r, dict) else r)
    r = s.op('regs', {'groups': 'gpr'})
    ck('regs works again after the pause', ok(r))
    s.finish()


# ------------------------------------------------------------------ breakpoints of every kind (T24, T25, T22)

@scenario
def bp_kinds():
    s = Sess('m2-bp_kinds')
    s.init('call')
    base = s.ev('mod.main()')
    r = s.cmd('alloc 1000', vars=['$result'])
    page = r['vars']['$result']

    def entry(r):
        return r['data']['breakpoint'] if ok(r) else None

    # software breakpoint with every optional field
    r = s.op('bp', {'action': 'add', 'kind': 'sw', 'target': 'kernel32.Sleep', 'name': 'sleepbp', 'condition': 'rcx>=0', 'log': 'sleep {rcx}',
                    'log_condition': '1', 'command': 'log cmd-ran', 'command_condition': '1', 'silent': True, 'fast_resume': True})
    e = entry(r)
    sw = e['id'] if e else None
    ck('bp add sw with name, condition, log, command, silent, fast_resume', e and e['name'] == 'sleepbp' and e['break_condition'] == 'rcx>=0' and e['log_text'] == 'sleep {rcx}' and e['log_condition'] == '1' and e['command_text'] == 'log cmd-ran' and e['command_condition'] == '1' and e['silent'] and e['fast_resume'], r['error'] if isinstance(r, dict) and not ok(r) else e)
    r = s.op('bp', {'action': 'add', 'kind': 'sw', 'target': 'kernel32.CreateFileW', 'once': True})
    ck('bp add sw once -> singleshoot', entry(r) and entry(r)['singleshoot'], r['error'] if isinstance(r, dict) else r)
    sw_once = entry(r)['id']
    # hardware: type x/r/w, sizes
    hw_ids = []
    for i, (t, size) in enumerate((('x', 1), ('r', 2), ('w', 4))):
        r = s.op('bp', {'action': 'add', 'kind': 'hw', 'target': '%s+%x' % (page, 0x100 * i), 'hw_type': t, 'size': size})
        e = entry(r)
        want = {'x': 'execute', 'r': 'access', 'w': 'write'}[t]
        ck('bp add hw %s size %d -> hw.kind %s' % (t, size, want), e and e['hw']['kind'] == want and e['hw']['size'] == size, r['error'] if isinstance(r, dict) and not ok(r) else e)
        if e:
            hw_ids.append(e['id'])
    # memory breakpoints
    mem_ids = []
    for t, want in (('a', 'access'), ('r', 'read'), ('w', 'write'), ('x', 'execute')):
        r = s.op('bp', {'action': 'add', 'kind': 'mem', 'target': s.ev('%s' % base) if t == 'a' else page, 'mem_type': t})
        e = entry(r)
        ck('bp add mem %s -> mem.kind %s' % (t, want), e and e['mem']['kind'] == want, r['error'] if isinstance(r, dict) and not ok(r) else e)
        if e:
            mem_ids.append(e['id'])
            s.op('bp', {'action': 'delete', 'id': e['id']})
    # dll
    dll_ids = []
    for ev, want in (('load', 'load'), ('unload', 'unload'), ('all', 'all')):
        r = s.op('bp', {'action': 'add', 'kind': 'dll', 'target': 'winhttp%s.dll' % ev[0], 'dll_event': ev})
        e = entry(r)
        ck('bp add dll %s -> dll.event %s' % (ev, want), e and e['dll']['event'] == want and e['id'].startswith('dll:winhttp'), r['error'] if isinstance(r, dict) and not ok(r) else e)
        if e:
            dll_ids.append(e['id'])
    # exception
    ex_ids = []
    for chance, code_ in (('first', '0xc0000005'), ('second', '0xc0000094'), ('all', '0xc000001d')):
        r = s.op('bp', {'action': 'add', 'kind': 'exception', 'target': code_, 'chance': chance})
        e = entry(r)
        ck('bp add exception %s %s' % (chance, code_), e and e['exception']['chance'] == chance and e['exception']['code'] == '0x%016x' % int(code_, 16) and e['id'] == 'exception:0x%016x' % int(code_, 16), r['error'] if isinstance(r, dict) and not ok(r) else e)
        if e:
            ex_ids.append(e['id'])
    all_ids = [sw, sw_once] + hw_ids + dll_ids + ex_ids
    b = s.op('bps')
    got = [x['id'] for x in b['data']['breakpoints']]
    ck('bps lists all added breakpoints (%d)' % len(all_ids), set(all_ids) <= set(got) and b['data']['count'] == len(got), (sorted(all_ids), sorted(got)))
    for kind, n in (('sw', 2), ('hw', 3), ('dll', 3), ('exception', 3)):
        r = s.op('bps', {'kind': kind})
        ck('bps kind filter %s' % kind, ok(r) and r['data']['count'] == n and all(x['kind'] == kind for x in r['data']['breakpoints']), r['data']['count'] if ok(r) else r)
    # disable / enable / reset_hits / delete for every id
    for i in all_ids:
        r = s.op('bp', {'action': 'disable', 'id': i})
        d = entry(r)
        r2 = s.op('bp', {'action': 'enable', 'id': i})
        e = entry(r2)
        r3 = s.op('bp', {'action': 'reset_hits', 'id': i})
        ck('bp %s: disable -> enabled false, enable -> true, reset_hits ok' % i, d and d['enabled'] is False and e and e['enabled'] is True and ok(r3) and entry(r3)['hit_count'] == 0, (r['error'] if isinstance(r, dict) and not ok(r) else d, r2['error'] if isinstance(r2, dict) and not ok(r2) else e, r3['error'] if isinstance(r3, dict) and not ok(r3) else None))
    # text-form target as id, kind + target addressing
    r = s.op('bp', {'action': 'disable', 'kind': 'sw', 'target': 'kernel32.Sleep'})
    ck('bp disable by kind + target', ok(r) and entry(r)['id'] == sw and entry(r)['enabled'] is False, r['error'] if isinstance(r, dict) else r)
    r = s.op('bp', {'action': 'enable', 'all': True, 'kind': 'sw'})
    ck('bp enable all of one kind', ok(r) and r['data']['changed'] == 2, r['data'] if ok(r) else r)
    # native bplist sees them
    bl = s.cmd('bplist')
    ck('bplist output names the hardware and software breakpoints', ok(bl) and bl['output'].count('\n') >= 5, bl['output'][:200])
    # delete one by one (and the whole class with all)
    r = s.op('bp', {'action': 'delete', 'id': sw})
    ck('bp delete -> breakpoint null, deleted 1', ok(r) and r['data']['breakpoint'] is None and r['data']['deleted'] == 1, r['data'] if ok(r) else r)
    r = s.op('bp', {'action': 'delete', 'all': True, 'kind': 'hw'})
    ck('bp delete all hw -> deleted 3', ok(r) and r['data']['deleted'] == 3, r['data'] if ok(r) else r)
    r = s.op('bp', {'action': 'delete', 'all': True})
    ck('bp delete all', ok(r), r['error'] if isinstance(r, dict) else r)
    b = s.op('bps')
    ck('no breakpoints left', ok(b) and b['data']['count'] == 0, b['data'] if ok(b) else b)
    ck('bp errors: unknown action, unknown id, bad hw size, missing target',
       code(s.op('bp', {'action': 'frob'})) == 'E_BAD_ARG' and code(s.op('bp', {'action': 'delete', 'id': 'sw:0x1234'})) == 'E_BAD_ARG' and
       code(s.op('bp', {'action': 'add', 'kind': 'hw', 'target': page, 'size': 3})) == 'E_BAD_ARG' and code(s.op('bp', {'action': 'add'})) == 'E_BAD_ARG' and
       code(s.op('bp', {'action': 'delete', 'id': 'nonsense'})) == 'E_BAD_ARG')
    # a breakpoint added through the op really stops the debuggee, and is reported as breakpoint (AC-7 through the views)
    s.op('bp', {'action': 'add', 'target': 'kernel32.Sleep'})
    r = s.op('run')
    ck('a bp-op breakpoint stops the run', ok(r) and r['state']['stop']['reason'] == 'breakpoint', r['state'] if isinstance(r, dict) else r)
    r = s.op('bps')
    ck('hit count after the stop is 1', ok(r) and r['data']['breakpoints'][0]['hit_count'] == 1, r['data'] if ok(r) else r)
    s.op('bp', {'action': 'reset_hits', 'id': r['data']['breakpoints'][0]['id']})
    r = s.op('bps')
    ck('reset_hits sets the count to 0', ok(r) and r['data']['breakpoints'][0]['hit_count'] == 0)
    s.finish()


# ------------------------------------------------------------------ run-control wrappers, AC-38, AC-34, T42

@scenario
def wrappers():
    s = Sess('m2-wrappers')
    r = s.op('restart')
    ck('restart without a previous init is E_BAD_ARG', code(r) == 'E_BAD_ARG', r['error'] if isinstance(r, dict) else r)
    r = s.op('init', {'file': TARGET, 'args': 'loop'})
    pid1 = r['state']['pid']
    ck('init loop', ok(r) and r['state']['status'] == 'paused')
    r = s.op('restart')
    ck('T42 restart reuses the last init: new pid, paused at the system breakpoint', ok(r) and r['state']['status'] == 'paused' and r['state']['pid'] != pid1 and r['state']['stop']['reason'] == 'system_breakpoint', r['state'] if isinstance(r, dict) else r)
    ck('T42 the first debuggee is gone', pid1 not in procs('cli_target.exe'))
    r = s.op('process')
    ck('T42 the restarted process has the same command line', ok(r) and r['data']['cmdline'].endswith('loop'), r['data'] if ok(r) else r)
    s.op('bp', {'action': 'add', 'target': 'kernel32.Sleep'})
    r = s.op('run')
    ck('run to Sleep in the loop target', ok(r) and r['state']['stop']['reason'] == 'breakpoint')
    # AC-38: stepin --count 10 equals ten sti natives from the same point
    def at_sleep():
        r = s.op('run')
        return r['state']['stop'] and r['state']['stop']['bp']
    r = s.op('stepin', {'count': 10})
    cip_a = r['state']['cip']
    off_a = s.ev('%s-mod.base(%s)' % (cip_a, cip_a))
    ck('AC-38 stepin count:10 stopped after stepping', ok(r) and r['state']['stop']['reason'] == 'step', r['state'] if isinstance(r, dict) else r)
    at_sleep()
    for i in range(10):
        r = s.cmd('sti')
    cip_b = r['state']['cip']
    off_b = s.ev('%s-mod.base(%s)' % (cip_b, cip_b))
    ck('AC-38 ten sti natives end at the same cip as stepin --count 10 (%s)' % cip_a, cip_a == cip_b or off_a == off_b, (cip_a, cip_b, off_a, off_b))
    at_sleep()
    r = s.cmd('sti 10')
    ck('AC-38 the native "sti 10" steps 16 times (hex): why wrappers emit 0xa', ok(r))
    cip_c = r['state']['cip']
    at_sleep()
    r = s.op('stepin', {'count': 16})
    ck('AC-38 stepin count:16 equals native sti 10', r['state']['cip'] == cip_c, (r['state']['cip'], cip_c))
    # stepover, stepout, skip
    at_sleep()
    r = s.op('stepin')
    r = s.op('stepover', {'count': 2})
    ck('stepover count 2', ok(r) and r['state']['stop']['reason'] == 'step')
    r = s.op('stepout')
    ck('stepout (rtr)', ok(r) and r['state']['status'] == 'paused' and r['state']['stop']['reason'] == 'step', r['state'] if isinstance(r, dict) else r)
    rip0 = s.ev('rip')
    size0 = s.op('dis', {'count': 1})['data']['instructions'][0]['size']
    r = s.op('skip')
    ck('skip: no wait, cip moves past the instruction', ok(r) and r['wait']['waited'] is False and r['wait']['reason'] == 'none' and int(s.ev('rip'), 16) == int(rip0, 16) + size0, r['wait'] if isinstance(r, dict) else r)
    s.op('setreg', {'reg': 'rip', 'value': rip0})
    # runto
    r = s.op('runto', {'addr': 'kernel32.Sleep'})
    ck('runto kernel32.Sleep stops there', ok(r) and r['state']['status'] == 'paused' and r['state']['cip_label'] == 'Sleep', r['state'] if isinstance(r, dict) else r)
    # pause / run with wait:never / pause op
    r = s.op('run', wait='never')
    r = s.op('pause')
    ck('pause op after run wait:never', ok(r) and r['state']['status'] == 'paused', r['state'] if isinstance(r, dict) else r)
    ck('step ops reject bad count', code(s.op('stepin', {'count': -1})) == 'E_BAD_ARG' and code(s.op('stepin', {'count': 2000000})) == 'E_BAD_ARG')
    r = s.op('stop')
    ck('stop op', ok(r) and r['state']['status'] == 'stopped')
    # AC-34 loadlib / freelib
    r = s.init('call')
    s.op('bp', {'action': 'add', 'target': 'kernel32.Sleep'})
    r = s.op('run')
    ck('loadlib test: stopped at kernel32.Sleep in user code', ok(r) and r['state']['stop']['reason'] == 'breakpoint')
    r = s.cmd('loadlib winhttp.dll', vars=['$result'])
    ck('AC-34 loadlib winhttp.dll: waited, paused, stop.reason loadlib, module_loaded events in the response', ok(r) and r['wait']['waited'] and r['wait']['reason'] == 'paused' and r['state']['stop']['reason'] == 'loadlib' and any(e['type'] == 'module_loaded' and e['name'] == 'winhttp.dll' for e in r['events']), (r['wait'], r['state']['stop'], [e['type'] for e in r['events']]) if isinstance(r, dict) else r)
    m = s.op('modules', {'filter': 'winhttp'})
    base = m['data']['modules'][0]['base']
    ck('the module list shows the loaded winhttp.dll (the base the core reports in its log line)', ok(m) and m['data']['count'] == 1 and base[2:].lstrip('0').upper() in r['output'].upper(), (m['data'], r['output'][-200:]) if ok(m) else m)
    print('  info: the core sets $result to %s after loadlib (headless.exe shows the same, so it is core behaviour, not the CLI)' % r['vars']['$result'])
    r = s.cmd('freelib ' + base)
    ck('AC-34 freelib: paused, stop.reason freelib', ok(r) and r['wait']['reason'] == 'paused' and r['state']['stop']['reason'] == 'freelib', (r['wait'], r['state']['stop']) if isinstance(r, dict) else r)
    # thread switch with a decimal tid above 9 (AC-38)
    th = s.op('threads')['data']
    other = [t for t in th['threads'] if t['tid'] != th['current_tid'] and t['tid'] > 9]
    r = s.op('thread', {'action': 'switch', 'tid': other[0]['tid']})
    ck('AC-38 thread switch with decimal tid %d -> state.tid' % other[0]['tid'], ok(r) and r['state']['tid'] == other[0]['tid'], r['state'] if isinstance(r, dict) else r)
    s.finish()


# ------------------------------------------------------------------ batch (AC-28), AC-18 e2 batch form

@scenario
def batch():
    s = Sess('m2-batch')
    s.init('call')
    s.op('bp', {'action': 'add', 'target': 'kernel32.Sleep'})
    r = s.req({'batch': [{'cmd': 'run'}, {'op': 'regs', 'args': {'groups': 'gpr'}}, {'op': 'dis', 'args': {'count': 2}}], 'stop_on_error': True})
    res = r.get('results') if isinstance(r, dict) else None
    ck('batch: run, regs, dis in one response (design example)', ok(r) and res and len(res) == 3 and all(x['ok'] for x in res), r)
    ck('batch results are response bodies without type and v, each with its own state/events', res and 'type' not in res[0] and 'v' not in res[0] and res[0]['state']['status'] == 'paused' and res[0]['state']['stop']['reason'] == 'breakpoint' and res[1]['data']['gpr']['rip'] == res[0]['state']['cip'] and res[2]['data']['instructions'][0]['is_cip'], res[0] if res else r)
    ck('batch envelope: state of the last element, wait of the last element, data null', r['state']['status'] == 'paused' and r['data'] is None and r['events'] == [])
    r = s.req({'batch': [{'op': 'eval', 'args': {'expr': '1+1'}}, {'op': 'eval', 'args': {'expr': 'nosuchsymbol'}}, {'op': 'eval', 'args': {'expr': '2+2'}}], 'stop_on_error': True})
    res = r.get('results')
    ck('AC-28 batch stop_on_error stops at the first failing element and returns the earlier results', not r['ok'] and len(res) == 2 and res[0]['ok'] and not res[1]['ok'] and res[1]['error']['code'] == 'E_BAD_ARG', r['error'] if isinstance(r, dict) else r)
    ck('batch envelope error names the element', 'batch element 1' in r['error']['message'], r['error'])
    r = s.req({'batch': [{'op': 'eval', 'args': {'expr': '1+1'}}, {'op': 'eval', 'args': {'expr': 'nosuchsymbol'}}, {'op': 'eval', 'args': {'expr': '2+2'}}]})
    ck('batch without stop_on_error runs all elements; envelope ok false', not r['ok'] and len(r['results']) == 3 and r['results'][2]['data']['value'].endswith('4'), [x['ok'] for x in r['results']])
    r = s.req({'batch': [{'batch': [{'cmd': 'log x'}]}]})
    ck('nested batch is E_BAD_ARG naming the element and runs nothing', code(r) == 'E_BAD_ARG' and 'element 0' in r['error']['message'] and 'results' not in r or r.get('results') == [], r['error'] if isinstance(r, dict) else r)
    r = s.req({'batch': [{'cmd': 'log first'}, {'op': 'interrupt'}]})
    ck('interrupt/quit inside a batch are rejected before anything runs', code(r) == 'E_BAD_ARG' and 'interrupt' in r['error']['message'], r['error'] if isinstance(r, dict) else r)
    lg = s.op('log', {'tail': 20})
    ck('the rejected batch did not run its first element', 'first' not in lg['data']['text'])
    r = s.req({'batch': [{'cmd': 'log a; log b'}, {'op': 'bps'}, {'cmd': 'log c', 'vars': ['$result']}]})
    ck('batch mixes native lines and ops; element outputs stay separate', ok(r) and r['results'][0]['output'] == 'a\nb' and r['results'][2]['output'] == 'c' and '$result' in r['results'][2]['vars'], [x['output'] for x in r['results']] if ok(r) else r)
    r = s.req({'batch': [{'cmd': 'sti'}, {'op': 'dis', 'args': {'count': 1}}, {'cmd': 'sti'}, {'op': 'dis', 'args': {'count': 1}}]})
    ra = r['results']
    ck('batch: step, show disassembly, repeated (each dis starts at its step\'s cip)', ok(r) and ra[1]['data']['instructions'][0]['addr'] == ra[0]['state']['cip'] and ra[3]['data']['instructions'][0]['addr'] == ra[2]['state']['cip'] and ra[0]['state']['cip'] != ra[2]['state']['cip'], [x['state']['cip'] for x in ra] if ok(r) else r)
    s.op('bp', {'action': 'delete', 'all': True})
    s.finish()
    # batch-level options are the defaults of the elements: a 500 ms timeout on a loop target
    s = Sess('m2-batch_options')
    s.init('loop')
    t0 = time.time()
    r = s.req({'batch': [{'cmd': 'run', 'on_timeout': 'pause'}], 'timeout_ms': 500}, 30)
    ck('batch-level timeout_ms is the default of its elements (%.1f s)' % (time.time() - t0), ok(r) and r['results'][0]['wait']['timed_out'] is True and r['results'][0]['state']['status'] == 'paused' and time.time() - t0 < 10, r['results'][0]['wait'] if ok(r) else r)
    r = s.req({'batch': [{'cmd': 'run', 'timeout_ms': 300, 'on_timeout': 'pause'}], 'timeout_ms': 20000}, 30)
    ck('an element option overrides the batch-level one', ok(r) and r['results'][0]['wait']['elapsed_ms'] < 5000, r['results'][0]['wait'] if ok(r) else r)
    s.finish()


@scenario
def batch_stuck():
    # AC-18 e2: two legitimate 20 s waits in one batch under --stuck-ms 6000 are not cut
    s = Sess('m2-batch_stuck', args=['--stuck-ms', '6000'])
    s.init('loop', 60)
    t0 = time.time()
    r = s.req({'batch': [{'cmd': 'run', 'on_timeout': 'pause'}, {'cmd': 'run'}], 'timeout_ms': 20000}, 120)
    took = time.time() - t0
    ck('AC-18 e2 batch of two 20 s waits (%.0f s) is answered without E_TIMEOUT' % took, isinstance(r, dict) and code(r) != 'E_TIMEOUT' and r.get('results') and all(code(x) != 'E_TIMEOUT' for x in r['results']) and took > 35, (r['error'] if isinstance(r, dict) else r, took))
    ck('AC-18 e2 the first element paused on timeout, the second timed out and kept running', r['results'][0]['state']['status'] == 'paused' and r['results'][1]['wait']['timed_out'], [(x['state']['status'], x['wait']) for x in r['results']])
    s.req({'cmd': 'pause'}, 30)
    s.finish()


@scenario
def init_cwd():
    s = Sess('m2-init_cwd')
    cwd = tempfile.gettempdir()
    r = s.op('init', {'file': TARGET, 'args': 'call', 'cwd': cwd})
    ck('init with args and cwd: paused, command line carries the arguments', ok(r) and r['state']['status'] == 'paused' and ok(s.op('process')) and s.op('process')['data']['cmdline'].endswith('call'), r['error'] if isinstance(r, dict) else r)
    s.op('stop')
    r = s.op('init', {'file': TARGET, 'args': 'two words "quoted"'})
    ck('init with an argument string that has spaces and quotes', ok(r) and r['state']['status'] == 'paused' and s.op('process')['data']['cmdline'].endswith('two words "quoted"'), s.op('process')['data'].get('cmdline') if ok(r) else r)
    s.finish()


@scenario
def stale_hits():
    # T25: a false-condition breakpoint is hit all the time; 20 x (run pending, pause 100 ms later) end with stop.reason pause
    s = Sess('m2-stale_hits')
    s.init('loop')
    r = s.op('bp', {'action': 'add', 'target': 'kernelbase.Sleep', 'condition': '0'})
    ck('false-condition breakpoint added', ok(r) and r['data']['breakpoint']['break_condition'] == '0', r['error'] if isinstance(r, dict) else r)
    reasons = []
    for i in range(20):
        rid = 'run%d' % i
        s.c.send({'id': rid, 'op': 'run', 'timeout_ms': 30000})
        time.sleep(0.1)
        p = s.req({'op': 'pause'}, 30)
        rr = s.c.wait_response(rid, 40)
        reasons.append(rr['state']['stop']['reason'] if isinstance(rr, dict) and rr['state']['stop'] else (rr if not isinstance(rr, dict) else None))
        if not ok(p):
            reasons.append(('pause failed', p))
    ck('T25 stop.reason is pause in 20 of 20 repetitions', reasons == ['pause'] * 20, reasons)
    r = s.op('bps')
    ck('T25 the breakpoint was really hit during the repetitions (stale hits exist)', ok(r) and r['data']['breakpoints'][0]['hit_count'] > 0, r['data']['breakpoints'][0]['hit_count'] if ok(r) else r)
    s.finish()


# ------------------------------------------------------------------ text mode (T46) and attach (T21b)

@scenario
def text_views():
    c = Cli('m2-text_views', json_mode=False)
    line = c.next_line(25)
    ck('text mode ready line', line.startswith('@@READY'), line)

    def block(cmd, timeout=60):
        c.send_raw(cmd + '\n')
        lines = []
        end = time.time() + timeout
        while time.time() < end:
            l = c.next_line(5)
            if l in ('TIMEOUT',):
                continue
            if l is None:
                break
            lines.append(l)
            if l.startswith('@@END'):
                break
        return lines

    b = block('!init %s --args call' % TARGET)
    ck('text: !init -> @@END ok state=paused', b[-1].startswith('@@END') and ' ok ' in b[-1] and 'state=paused' in b[-1], b[-3:])
    block('bp kernel32.Sleep')
    b = block('run')
    ck('text: run -> paused', 'state=paused' in b[-1], b[-1])
    m1 = block('!modules')
    m2 = block('!modules')
    ck('T46 !modules renders byte-identically twice', m1[:-1] == m2[:-1] and len(m1) > 5, (len(m1), len(m2)))
    t1 = block('!threads')
    t2 = block('!threads')
    diff = [(a, b) for a, b in zip(t1[:-1], t2[:-1]) if a != b]
    ck('T46 !threads renders byte-identically twice', t1[:-1] == t2[:-1] and len(t1) > 3, diff[:2])
    hdr = m1.index('modules:') + 1
    header = m1[hdr].split('\t')
    rows = [l.split('\t') for l in m1[hdr + 1:] if '\t' in l]
    count = int([l for l in m1 if l.startswith('count: ')][0].split()[1])
    ck('T46 !modules text: header keys in schema order, one tab-separated row per module, count line', header == ['name', 'base', 'size', 'path', 'entry', 'party', 'symbols', 'is_main'] and len(rows) == count and all(len(r) == 8 for r in rows), (header, len(rows), count))
    kern = [r for r in rows if r[0].lower() == 'kernel32.dll'][0]
    ev = block('!eval kernel32')
    ck('T46 !modules base matches the core (!eval kernel32)', kern[1] in ' '.join(ev), (kern[1], ev[:2]))
    d = block('!dis -n 3')
    ck('text: !dis renders "=>" at cip with bytes, mnemonic and ";" notes', d[0].startswith('=>*') and re.match(r'^=>\*[0-9a-f]{16}  [0-9a-f ]+', d[0]) is not None and len(d) == 4, d)
    r = block('!regs')
    ck('text: !regs prints nested objects with indented keys', 'gpr:' in r and any(l.startswith('  rip: 0x') for l in r), r[:6])
    r = block('!stack -n 2')
    ck('text: !stack prints the rows as a tab table', any(l.startswith('addr\toffset') for l in r) and sum(1 for l in r if l.startswith('0x')) == 2, r)
    r = block('!mem rsp -n 16 --format uint32')
    ck('text: !mem with the -n shorthand and a format', any(l.startswith('format: uint32') for l in r) and sum(1 for l in r if re.match(r'^0x[0-9a-f]{16}\t\d+$', l)) == 4, r[:12])
    r = block('!bp add kernel32.CreateFileW --once --name x')
    ck('text: !bp add with flags', ' ok ' in r[-1] and any('singleshoot: true' in l for l in r), r[-6:])
    r = block('!thread suspend_all')
    ck('text: !thread suspend_all', ' ok ' in r[-1], r[-2:])
    r = block('!thread resume_all')
    r = block('!regs --groups nosuch')
    ck('text: bad group is a failed block with the code', ' fail ' in r[-1] and 'code=E_BAD_ARG' in r[-1], r[-2:])
    r = block('!stepin 3')
    ck('text: !stepin 3 -> state=paused', 'state=paused' in r[-1] and ' ok ' in r[-1], r[-1])
    r = block('!threads --nosuch 1')
    ck('text: unknown option is E_BAD_ARG', ' fail ' in r[-1], r[-1])
    r = block('!stop')
    ck('text: !stop -> stopped', 'state=stopped' in r[-1], r[-1])
    ck('text session exits 0 on EOF', c.close() == 0)


@scenario
def attach():
    victim = subprocess.Popen([TARGET, 'wait'])
    try:
        time.sleep(0.6)
        s = Sess('m2-attach')
        r = s.op('attach', {'pid': victim.pid}, wait='always', timeout_ms=1500)
        ck('attach op: running, pid matches', ok(r) and r['state']['pid'] == victim.pid and r['state']['status'] in ('running', 'paused'), r['state'] if isinstance(r, dict) else r)
        r = s.op('pause')
        ck('pause after attach', ok(r) and r['state']['status'] == 'paused', r['state'] if isinstance(r, dict) else r)
        r = s.op('regs', {'groups': 'gpr,flags'})
        ck('T21b regs after attach', ok(r) and ADDR.match(r['data']['gpr']['rip']) and r['data']['gpr']['rip'] == r['state']['cip'], r['error'] if isinstance(r, dict) else r)
        r = s.op('dis', {'count': 3})
        ck('dis after attach starts at cip', ok(r) and r['data']['instructions'][0]['is_cip'])
        r = s.op('detach')
        ck('detach op -> stopped; the target survives', ok(r) and r['state']['status'] == 'stopped', r['state'] if isinstance(r, dict) else r)
        s.finish(stop=False)
        ck('detached target still alive', victim.poll() is None)
        # attach with --pause
        s = Sess('m2-attach_pause')
        r = s.op('attach', {'pid': victim.pid, 'pause': True}, 60)
        ck('attach pause:true ends paused with registers readable', ok(r) and r['state']['status'] == 'paused' and ok(s.op('regs', {'groups': 'gpr'})), r['state'] if isinstance(r, dict) else r)
        r = s.op('detach')
        ck('detach again', ok(r) and r['state']['status'] == 'stopped')
        s.finish(stop=False)
        ck('target alive after the second detach', victim.poll() is None)
        s = Sess('m2-attach_args')
        ck('attach rejects a missing pid', code(s.op('attach', {})) == 'E_BAD_ARG')
        s.finish(stop=False)
    finally:
        victim.kill()


def main():
    names = sys.argv[1:]
    before = set(procs('cli_target.exe')) | set(procs('x64dbg-cli.exe'))
    for name, fn in list(globals().items()):
        if getattr(fn, 'is_scenario', False) and (not names or name in names):
            acc.CURRENT[0] = name
            print('== %s' % name)
            try:
                fn()
            except Exception as e:
                import traceback
                traceback.print_exc()
                ck('scenario completed without exception', False, repr(e))
    time.sleep(2)
    left = (set(procs('cli_target.exe')) | set(procs('x64dbg-cli.exe'))) - before
    ck('no orphan cli_target.exe / x64dbg-cli.exe processes remain', not left, sorted(left))
    failed = [r for r in acc.RESULTS if not r[2]]
    print('\n%d checks, %d failed' % (len(acc.RESULTS), len(failed)))
    for r in failed:
        print('  FAILED [%s] %s: %s' % (r[0], r[1], str(r[3])[:400]))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
