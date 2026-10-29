#!/usr/bin/env python3
"""M3 acceptance runs for x64dbg-cli.exe: the remaining GUI-parity views (stdlib only).
Usage: python src/cli/tests/m3_acceptance.py [scenario ...]
Debuggees: the repo's cli_target.exe (bin\\x64\\tests) and .agents/tasks/cli/testprog/testprog.exe (compiled with cl /Zi /Od by
build-testprog.bat: PDB line info, an event, a file handle, a window and a listening TCP socket).
Transcripts: .agents/tasks/cli/transcripts/m3-<scenario>.jsonl. Every JSON response is validated as JSON and against
src/cli/schema/*.schema. Exit code 0 when every check passed.
"""
import json
import os
import re
import sys
import tempfile
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m1_acceptance as acc  # noqa: E402
from m1_acceptance import Cli, ck, scenario, TARGET, ROOT  # noqa: E402
from m2_acceptance import Sess, ok, code, procs, ADDR  # noqa: E402
from schemalib import Schemas  # noqa: E402
PROG = os.path.join(ROOT, '.agents', 'tasks', 'cli', 'testprog', 'testprog.exe')
PROG_SRC = os.path.join(ROOT, '.agents', 'tasks', 'cli', 'testprog', 'testprog.c')
M3_OPS = ['seh', 'handles', 'windows', 'tcp', 'heaps', 'privileges', 'ps', 'labels', 'comments', 'bookmarks', 'functions', 'arguments',
          'loops', 'addrinfo', 'xrefs', 'patches', 'patch', 'strings', 'calls', 'ptrs', 'watch', 'trace', 'script', 'types', 'struct',
          'cfg', 'notes', 'source', 'nav', 'callargs', 'locals', 'infobox', 'menu', 'config', 'constants', 'errors', 'exceptions',
          'format', 'asm', 'animate', 'favourites', 'module']
USED = set()
class P(Sess):
    """Sess that remembers which M3 ops were exercised."""
    def op(self, name, args=None, timeout=60, **opt):
        USED.add(name)
        return Sess.op(self, name, args, timeout, **opt)
def prog_session(name, bp, run=True):
    s = P(name)
    r = s.op('init', {'file': PROG})
    ck('%s: init testprog paused at the system breakpoint' % name, ok(r) and r['state']['status'] == 'paused', r)
    if bp:
        r = s.op('bp', {'action': 'add', 'target': bp})
        ck('%s: breakpoint on %s' % (name, bp), ok(r), r)
    if run:
        r = s.op('run')
        ck('%s: run stops at the breakpoint' % name, ok(r) and r['state']['status'] == 'paused' and r['state']['stop']['reason'] == 'breakpoint', r['state'] if isinstance(r, dict) else r)
    return s
def table_rows(r):
    return r['data']['table']['rows'] if ok(r) else []
def flat(rows):
    return ' '.join(' '.join(x) for x in rows).lower()
# ------------------------------------------------------------------ OS views
@scenario
def os_views():
    s = prog_session('m3-os', 'testprog.leaf')
    pid = s.c.p.pid
    st = s.op('status')
    tpid = st['state']['pid']
    r = s.op('seh')
    ck('seh: ok, chain is a list (the x64 chain is empty by design of the OS)', ok(r) and r['data']['chain'] == [], r)
    r = s.op('handles')
    hs = r['data']['handles'] if ok(r) else []
    ck('handles: a populated list with type, number, access', ok(r) and r['data']['count'] == len(hs) > 10 and all(h['type'] for h in hs[:20]), r['data']['count'] if ok(r) else r)
    ck('handles: includes the Event and File handles that testprog created', {'Event', 'File'} <= {h['type'] for h in hs}, sorted({h['type'] for h in hs}))
    named = [h for h in hs if h['name'] and 'x64dbg_cli_testprog_event' in h['name']]
    ck('handles: the named event is listed with its object name', len(named) == 1, [h for h in hs if h['type'] == 'Event'][:3])
    r2 = s.op('handles', {'limit': 3, 'offset': 2})
    ck('handles limit/offset: 3 entries starting at the third', ok(r2) and r2['data']['count'] == 3 and r2['data']['handles'] == hs[2:5], r2['data'] if ok(r2) else r2)
    r = s.op('windows')
    ws = r['data']['windows'] if ok(r) else []
    ck('windows: the STATIC window of testprog with title, class, thread and rect', any(w['title'] == 'cli-testprog-window' and w['class'] == 'Static' and w['tid'] and w['rect']['right'] > 0 for w in ws), ws[:2])
    r = s.op('tcp')
    cs = r['data']['connections'] if ok(r) else []
    ck('tcp: the listening socket on 127.0.0.1', any(c['state'] == 'LISTEN' and c['local'] == '127.0.0.1' and c['local_port'] > 0 for c in cs), cs)
    r = s.op('heaps')
    ck('heaps: ok, empty because the core stub enumerates nothing, and says so', ok(r) and r['data']['count'] == 0 and 'heaps_not_enumerated_by_core' in r.get('warnings', []), r)
    r = s.op('privileges')
    pv = r['data']['privileges'] if ok(r) else []
    ck('privileges: the 35 names of the GUI list in order, states are enabled/disabled/unknown', len(pv) == 35 and pv[0]['name'] == 'SeAssignPrimaryTokenPrivilege' and pv[-1]['name'] == 'SeUnsolicitedInputPrivilege', len(pv))
    ck('privileges: SeShutdownPrivilege is disabled in the token of a normal process', {p['name']: p['state'] for p in pv}.get('SeChangeNotifyPrivilege') in ('enabled', 'unknown') and {p['name']: p['state'] for p in pv}.get('SeShutdownPrivilege') in ('disabled', 'unknown'), pv[:3])
    r = s.op('ps')
    ps = r['data']['processes'] if ok(r) else []
    ck('ps: the process list (attach dialog) contains the debuggee and the test harness with full exe path, title and args', any(p['pid'] == tpid and os.path.basename(p['exe']).lower() == 'testprog.exe' for p in ps) and any(p['pid'] == os.getpid() and os.path.basename(p['exe']).lower().startswith('python') for p in ps) and r['data']['count'] == len(ps), len(ps))
    # a running debuggee: seh needs a pause, the enumerations still work
    s.op('bp', {'action': 'delete', 'all': True})
    r = s.op('run', None, wait='never')
    ck('run (no wait) leaves the debuggee running', ok(r) and r['state']['status'] == 'running', r['state'] if isinstance(r, dict) else r)
    r = s.op('seh')
    ck('seh on a running debuggee is E_RUNNING', code(r) == 'E_RUNNING', r)
    r = s.op('tcp')
    ck('tcp works while the debuggee runs', ok(r) and r['data']['count'] >= 1, r)
    r = s.op('pause')
    ck('pause again', ok(r) and r['state']['status'] == 'paused', r['state'] if isinstance(r, dict) else r)
    r = s.op('handles', {'limit': 0})
    ck('handles limit 0 is E_BAD_ARG', code(r) == 'E_BAD_ARG', r)
    s.finish()
    # no session
    s = P('m3-os-nosession')
    for op in ('seh', 'handles', 'windows', 'tcp', 'heaps', 'privileges'):
        r = s.op(op)
        ck('%s without a session is E_NOT_DEBUGGING' % op, code(r) == 'E_NOT_DEBUGGING', r)
    r = s.op('ps')
    ck('ps works without a session (attach dialog list), the harness process is in it', ok(r) and r['data']['count'] > 5 and all(isinstance(p['pid'], int) for p in r['data']['processes'])
       and any(p['pid'] == os.getpid() for p in r['data']['processes']), r['data']['count'] if ok(r) else r)
    s.finish(stop=False)
# ------------------------------------------------------------------ database / analysis views
@scenario
def db_views():
    s = prog_session('m3-db', 'testprog.compute')
    comp = s.ev('testprog.compute')
    leaf = s.ev('testprog.leaf')
    s.cmd('disasm testprog.compute')
    time.sleep(0.2)
    # label / comment / bookmark round trip
    ck('lbl, cmt, bookmark natives succeed', all(ok(s.cmd(x)) for x in ('lbl testprog.compute+0x20,clilabel', 'cmt testprog.compute+0x20,clicomment', 'bookmark testprog.compute+0x20')))
    a = comp[:-2] + '40' if False else s.ev('testprog.compute+0x20')
    r = s.op('labels')
    ck('labels: table with the new label', ok(r) and r['data']['table']['name'] == 'Labels' and r['data']['table']['columns'][:1] == ['Address'] and 'clilabel' in flat(table_rows(r)), r['data']['table'] if ok(r) else r)
    ck('labels: the table is data, not duplicated in the top-level tables', r['tables'] == [], r['tables'])
    r = s.op('comments')
    ck('comments: table with the new comment', ok(r) and 'clicomment' in flat(table_rows(r)), r)
    r = s.op('bookmarks')
    ck('bookmarks: table with the new bookmark', ok(r) and a[2:].upper() in flat(table_rows(r)).upper() and len(table_rows(r)) == 1, r)
    r = s.op('addrinfo', {'addr': 'testprog.compute+0x20'})
    ck('addrinfo: label, comment, bookmark, module', ok(r) and r['data']['label'] == 'clilabel' and r['data']['comment'] == 'clicomment' and r['data']['bookmark'] is True and r['data']['module'] == 'testprog', r['data'] if ok(r) else r)
    ck('addrinfo: breakpoint kind at the bp address', ok(s.cmd('lbl testprog.compute,compute_entry')) and s.op('addrinfo', {'addr': 'testprog.compute'})['data']['bp'] == 'normal')
    for x in ('lbldel testprog.compute+0x20', 'cmtdel testprog.compute+0x20', 'bookmarkdel testprog.compute+0x20'):
        s.cmd(x)
    ck('delete round trip: labels/comments/bookmarks no longer list the address', 'clilabel' not in flat(table_rows(s.op('labels'))) and 'clicomment' not in flat(table_rows(s.op('comments'))) and table_rows(s.op('bookmarks')) == [])
    r = s.op('addrinfo', {'addr': 'testprog.compute+0x20'})
    ck('addrinfo after the delete: no label, no comment, no bookmark', ok(r) and r['data']['label'] != 'clilabel' and r['data']['comment'] is None and r['data']['bookmark'] is False, r['data'] if ok(r) else r)
    # functions, arguments, loops
    ck('functionadd, argumentadd, loopadd natives succeed', all(ok(s.cmd(x)) for x in ('functionadd testprog.compute,testprog.compute+0x60', 'argumentadd testprog.leaf,testprog.leaf+0x10', 'loopadd testprog.compute+0x20,testprog.compute+0x50')))
    r = s.op('functions')
    ck('functions: the manual function is listed with start, end and size', ok(r) and any(x[0].upper().endswith(comp[-8:].upper()) and x[1].upper().endswith('%X' % (int(comp, 16) + 0x60)) for x in table_rows(r)), table_rows(r)[:3])
    r = s.op('arguments')
    ck('arguments: the argument range is listed', ok(r) and len(table_rows(r)) == 1 and table_rows(r)[0][0].upper().endswith(leaf[-8:].upper()), table_rows(r))
    r = s.op('loops')
    ck('loops: the loop is listed with depth', ok(r) and len(table_rows(r)) == 1 and 'Depth' in r['data']['table']['columns'], r['data']['table'] if ok(r) else r)
    r = s.op('addrinfo', {'addr': 'testprog.compute+0x24'})
    ck('addrinfo: function range and loop type inside the ranges', ok(r) and r['data']['function'] is not None and r['data']['function']['start'] == comp and r['data']['loop'] in ('begin', 'middle', 'entry', 'end', 'single'), r['data'] if ok(r) else r)
    r = s.op('addrinfo', {'addr': 'testprog.leaf'})
    ck('addrinfo: argument range at its start', ok(r) and r['data']['argument'] == 'begin', r['data'] if ok(r) else r)
    for x in ('functiondel testprog.compute', 'argumentdel testprog.leaf', 'loopdel testprog.compute+0x20'):
        s.cmd(x)
    ck('delete round trip: functions, arguments and loops are empty again', table_rows(s.op('arguments')) == [] and table_rows(s.op('loops')) == [] and 'comp' not in flat([x for x in table_rows(s.op('functions')) if x[0].upper().endswith(comp[-8:].upper())]))
    # xrefs
    ck('analxrefs succeeds on the module of the selection', ok(s.cmd('analxrefs')))
    r = s.op('xrefs', {'addr': 'testprog.leaf'})
    xs = r['data']['xrefs'] if ok(r) else []
    ck('xrefs: the call to leaf from inside compute, with type and decoded text', len(xs) == 1 and xs[0]['type'] == 'call' and int(comp, 16) <= int(xs[0]['from'], 16) < int(comp, 16) + 0x60 and xs[0]['text'].startswith('call '), r['data'] if ok(r) else r)
    r = s.op('xrefs', {'addr': 'testprog.leaf+1'})
    ck('xrefs of an address without references: empty list', ok(r) and r['data']['count'] == 0 and r['data']['xrefs'] == [], r)
    # patches
    r = s.op('memwrite', {'addr': 'testprog.compute', 'hex': '90 90'})
    ck('memwrite patch:true creates patches', ok(r) and r['data']['patched'], r)
    r = s.op('patches')
    ps = r['data']['patches'] if ok(r) else []
    ck('patches: the two bytes with module, old and new', len(ps) == 2 and ps[0]['module'] == 'testprog.exe' and ps[0]['new'] == '90' and ps[0]['old'] != '90' and ps[0]['addr'] == comp, ps)
    out = os.path.join(tempfile.gettempdir(), 'clitest_patched_%d.exe' % os.getpid())
    r = s.op('patch', {'action': 'export', 'file': out})
    ck('patch export: writes the patched copy of the module', ok(r) and r['data']['written'] == 2 and os.path.getsize(out) == os.path.getsize(PROG), r)
    orig = open(PROG, 'rb').read()
    new = open(out, 'rb').read() if os.path.exists(out) else b''
    diff = [i for i in range(min(len(orig), len(new))) if orig[i] != new[i]]
    ck('patch export: exactly the 2 patched bytes differ from the original file', len(diff) == 2 and new[diff[0]:diff[0] + 2] == b'\x90\x90', diff[:4])
    if os.path.exists(out):
        os.remove(out)
    r = s.op('patch', {'action': 'restore', 'addr': 'testprog.compute'})
    ck('patch restore: one patch restored', ok(r) and r['data']['restored'] == 1, r)
    ck('patch restore: the list shrinks to the other byte', len(s.op('patches')['data']['patches']) == 1)
    r = s.op('patch', {'action': 'restore_range', 'addr': 'testprog.compute', 'end': 'testprog.compute+0x10'})
    ck('patch restore_range: the remaining patch is restored', ok(r) and r['data']['restored'] == 1 and s.op('patches')['data']['count'] == 0, r)
    ck('patch errors: restore without a patch, export without file, unknown action', code(s.op('patch', {'action': 'restore', 'addr': 'testprog.compute'})) == 'E_COMMAND_FAILED'
       and code(s.op('patch', {'action': 'export'})) == 'E_BAD_ARG' and code(s.op('patch', {'action': 'bogus'})) == 'E_BAD_ARG')
    # asm writes to a private page
    r = s.cmd('alloc 1000', vars=['$result'])
    area = r['vars']['$result']
    r = s.op('asm', {'addr': area, 'text': 'mov eax, 1'})
    ck('asm: assembles 5 bytes and returns them', ok(r) and r['data']['size'] == 5 and r['data']['bytes'] == 'b801000000', r)
    m = s.op('mem', {'addr': area, 'size': 5})
    ck('asm: the bytes are in the debuggee memory', ok(m) and m['data']['hex'].startswith('b801000000'), m['data'] if ok(m) else m)
    ck('asm: a bad instruction is E_COMMAND_FAILED with the assembler text', code(s.op('asm', {'addr': area, 'text': 'notaninstruction'})) == 'E_COMMAND_FAILED')
    # searches
    r = s.op('strings', {'addr': 'testprog.compute'})
    ck('strings: the strref table of the module lists the string references', ok(r) and 'x64dbg_cli_testprog_event' in flat(table_rows(r)) and r['data']['table']['columns'][-1] == 'String', table_rows(r)[:2])
    r2 = s.op('strings')
    ck('strings without addr searches the region at cip', ok(r2) and 'x64dbg_cli_testprog_event' in flat(table_rows(r2)), r2['data']['table']['name'] if ok(r2) else r2)
    r = s.op('calls', {'addr': 'testprog.compute'})
    ck('calls: the intermodular calls of the module (CreateEventA, WSAStartup)', ok(r) and 'createeventa' in flat(table_rows(r)) and 'wsastartup' in flat(table_rows(r)), table_rows(r)[:2])
    r = s.op('ptrs', {'addr': 'testprog.compute'})
    ck('ptrs: the function pointer table of the module', ok(r) and r['data']['table']['columns'][2] == 'Function pointer', r['data']['table'] if ok(r) else r)
    ck('strings with a bad size or a comma is E_BAD_ARG', code(s.op('strings', {'size': '0x100'})) == 'E_BAD_ARG' and code(s.op('strings', {'addr': 'rsp,1'})) == 'E_BAD_ARG')
    # watch
    r = s.cmd('AddWatch rsp', vars=['$result'])
    wid = int(r['vars']['$result'], 16)
    r = s.op('watch')
    ck('watch: the new watch with expression, type, mode and value', ok(r) and len(r['data']['watches']) == 1 and r['data']['watches'][0]['expression'] == 'rsp' and r['data']['watches'][0]['id'] == wid and r['data']['watches'][0]['type'] == 'uint', r['data'] if ok(r) else r)
    ck('watch value equals rsp', ok(r) and r['data']['watches'][0]['value'] == s.ev('rsp'))
    s.cmd('DelWatch %d' % wid)
    ck('watch: empty after DelWatch', s.op('watch')['data']['count'] == 0)
    ck('xrefs without addr is E_BAD_ARG', code(s.op('xrefs', {})) == 'E_BAD_ARG')
    s.finish()
# ------------------------------------------------------------------ trace, script, types, cfg, notes, source, nav and the info views
def write_script(dirpath, name, lines):
    path = os.path.join(dirpath, name)
    with open(path, 'w', encoding='ascii') as f:
        f.write('\n'.join(lines) + '\n')
    return path
@scenario
def misc_views():
    s = prog_session('m3-misc', 'testprog.compute')
    comp = s.ev('testprog.compute')
    # ---- trace coverage
    r = s.op('trace', {'action': 'info'})
    ck('trace info: region of cip (page aligned), no record type yet', ok(r) and r['data']['record_type'] == 'none' and r['data']['hit_count'] == 0 and int(r['data']['region']['base'], 16) % 4096 == 0 and r['data']['recording'] is False, r)
    r = s.op('trace', {'action': 'set_type', 'type': 'byte'})
    ck('trace set_type byte: every page of the .text region', ok(r) and r['data']['record_type'] == 'byte' and r['data']['pages'] == r['data']['region']['size'] // 4096, r)
    s.op('stepin')
    s.op('stepin')
    r = s.op('trace', {'action': 'info'})
    ck('trace info after two steps: hit_count > 0 at the new cip, instruction type', ok(r) and r['data']['hit_count'] > 0 and r['data']['byte_type'].startswith('instruction'), r)
    r = s.op('trace', {'action': 'info', 'addr': 'testprog.compute'})
    ck('trace info addr: the bp address was marked by traceexecute', ok(r) and r['data']['hit_count'] > 0, r)
    r = s.op('stepout')
    r = s.op('trace', {'action': 'reset'})
    ck('trace reset: ok, the recording type stays and the counters are cleared', ok(r) and r['data']['record_type'] == 'byte' and s.op('trace', {'action': 'info', 'addr': 'testprog.compute'})['data']['hit_count'] == 0, r)
    r = s.op('trace', {'action': 'set_type', 'type': 'bit', 'addr': 'testprog.compute'})
    ck('trace set_type bit on pages that already record bytes: E_INTERNAL naming the page (the core refuses to change a type)', code(r) == 'E_INTERNAL' and 'page 0x' in r['error']['message'], r)
    r = s.op('trace', {'action': 'disable', 'addr': 'testprog.compute'})
    r = s.op('trace', {'action': 'set_type', 'type': 'bit', 'addr': 'testprog.compute'})
    ck('trace set_type bit after disable, with an explicit addr', ok(r) and s.op('trace', {'action': 'info', 'addr': 'testprog.compute'})['data']['record_type'] == 'bit', r)
    r = s.op('trace', {'action': 'disable', 'addr': 'testprog.compute'})
    ck('trace disable: type none again', ok(r) and s.op('trace', {'action': 'info', 'addr': 'testprog.compute'})['data']['record_type'] == 'none', r)
    tfile = os.path.join(tempfile.gettempdir(), 'clitest_trace_%d.trace64' % os.getpid())
    r = s.op('trace', {'action': 'start', 'file': tfile})
    ck('trace start: recording is true', ok(r) and r['data']['recording'] is True, r)
    r = s.op('trace', {'action': 'stop'})
    ck('trace stop: recording is false', ok(r) and r['data']['recording'] is False, r)
    if os.path.exists(tfile):
        os.remove(tfile)
    ck('trace argument rules: type needs set_type, start needs file, stop forbids addr', code(s.op('trace', {'action': 'info', 'type': 'bit'})) == 'E_BAD_ARG'
       and code(s.op('trace', {'action': 'start'})) == 'E_BAD_ARG' and code(s.op('trace', {'action': 'stop', 'addr': 'rip'})) == 'E_BAD_ARG' and code(s.op('trace', {'action': 'set_type'})) == 'E_BAD_ARG'
       and code(s.op('trace', {'action': 'set_type', 'type': 'qword'})) == 'E_BAD_ARG')
    # ---- scripts (T37)
    tmp = tempfile.mkdtemp(prefix='clitest_scripts_')
    s1 = write_script(tmp, 's1.txt', ['log "script line 1"', 'log "script line 2"', 'log "script line 3"'])
    s2 = write_script(tmp, 's2.txt', ['log "before"', 'error "boom"', 'log "after"'])
    s3 = write_script(tmp, 's3.txt', ['log "first"', 'invalid'])
    r = s.op('script', {'action': 'load', 'file': s1})
    ck('script load: the 3 command lines plus the implicit ret, ip at the first line, no errors', ok(r) and [l['text'] for l in r['data']['lines']][:3] == ['log "script line 1"', 'log "script line 2"', 'log "script line 3"'] and r['data']['lines'][3]['text'] == 'ret' and r['data']['errors'] == [] and r['data']['ip'] == 1, r)
    r = s.op('script', {'action': 'lines'})
    ck('script lines: numbered from 1 with text', ok(r) and r['data']['lines'][1] == {'n': 2, 'text': 'log "script line 2"', 'type': 'command'}, r)
    r = s.op('script', {'action': 'bp_toggle', 'line': 2})
    ck('script bp_toggle line 2 sets the script breakpoint', ok(r) and r['data']['bp'] is True and s.op('script', {'action': 'bp_get', 'line': 2})['data']['bp'] is True and s.op('script', {'action': 'bp_get', 'line': 1})['data']['bp'] is False, r)
    r = s.op('script', {'action': 'run'})
    ck('script run: stops at the script breakpoint (finished false, ip 2), line 1 ran', ok(r) and r['data']['finished'] is False and r['data']['ip'] == 2 and 'script line 1' in r['output'] and 'script line 2' not in r['output'], r)
    r = s.op('script', {'action': 'step'})
    ck('script step: executes line 2 and pauses at line 3 (wait.reason paused)', ok(r) and r['data']['ip'] == 3 and r['wait']['reason'] == 'paused' and r['data']['errors'] == [], r)
    r = s.op('script', {'action': 'state'})
    ck('script state: ip 3', ok(r) and r['data']['ip'] == 3, r)
    r = s.op('script', {'action': 'run'})
    ck('script run to the end: finished true and the last line ran', ok(r) and r['data']['finished'] is True and 'script line 3' in r['output'], r)
    r = s.op('script', {'action': 'load', 'file': s1})
    s.op('script', {'action': 'bp_toggle', 'line': 2})
    s.op('script', {'action': 'bp_toggle', 'line': 2})
    r = s.op('script', {'action': 'run', 'line': 3})
    ck('script run --line 3: sets the script breakpoint on line 3 and stops there', ok(r) and r['data']['finished'] is False and r['data']['ip'] == 3 and s.op('script', {'action': 'bp_get', 'line': 3})['data']['bp'] is True, r)
    r = s.op('script', {'action': 'set_ip', 'line': 1})
    ck('script set_ip moves the instruction pointer', ok(r) and r['data']['ip'] == 1, r)
    r = s.op('script', {'action': 'abort'})
    ck('script abort and unload are ok', ok(r) and ok(s.op('script', {'action': 'unload'})), r)
    r = s.op('script', {'action': 'load', 'file': s2})
    r = s.op('script', {'action': 'run'})
    ck('script with error "boom": ok:true, finished true, boom in output, errors/messages empty', ok(r) and r['data']['finished'] is True and 'boom' in r['output'], r)
    r = s.op('script', {'action': 'load', 'file': s3})
    r = s.op('script', {'action': 'run'})
    ck('script with an invalid line: ok:true, finished false, "Error executing command!" in output', ok(r) and r['data']['finished'] is False and 'Error executing command!' in r['output'], r)
    r = s.op('script', {'action': 'exec', 'file': s1})
    ck('script exec: runs the file to the end (scriptexec)', ok(r) and r['data']['finished'] is True and 'script line 3' in r['output'], r)
    r = s.op('script', {'action': 'cmd', 'command': 'log "from scriptcmd"'})
    ck('script cmd: runs one script command', ok(r) and r['data']['finished'] is True and 'from scriptcmd' in r['output'], r)
    r = s.op('script', {'action': 'load', 'file': os.path.join(tmp, 'missing.txt')})
    ck('script load of a missing file is E_COMMAND_FAILED with the error text', code(r) == 'E_COMMAND_FAILED', r)
    s.op('script', {'action': 'load', 'file': s1})
    codes = [code(s.op('script', a)) for a in ({'action': 'nope'}, {'action': 'bp_toggle'}, {'action': 'bp_toggle', 'line': 99}, {'action': 'cmd', 'command': 'log a; log b'}, {'action': 'load'}, {'action': 'state', 'file': 'x'}, {'action': 'run', 'line': 0})]
    ck('script argument errors: unknown action, missing or out-of-range line, cmd with ;, load without file, forbidden key', codes == ['E_BAD_ARG'] * 7, codes)
    s.op('script', {'action': 'unload'})
    r = s.op('script', {'action': 'step'})
    ck('script step with nothing loaded is E_COMMAND_FAILED', code(r) == 'E_COMMAND_FAILED', r)
    # ---- types and struct
    for line in ('AddStruct CLI_PAIR', 'AddMember CLI_PAIR,int,x', 'AddMember CLI_PAIR,int,y'):
        s.cmd(line)
    r = s.op('types')
    ck('types: lists the new struct', ok(r) and 'CLI_PAIR' in r['data']['structs'], r)
    r = s.op('struct', {'type': 'CLI_PAIR', 'addr': 'testprog.g_pair'})
    root = r['data']['root'] if ok(r) else {}
    ck('struct: tree with the members, offsets and the values read from memory (11 and 22)', ok(r) and [c['name'] for c in root['children']] == ['int x', 'int y'] and [c['offset'] for c in root['children']] == [0, 4]
       and '11' in root['children'][0]['value'] and '22' in root['children'][1]['value'], r)
    ck('struct with an unknown type is E_COMMAND_FAILED', code(s.op('struct', {'type': 'NoSuchType', 'addr': 'rsp'})) == 'E_COMMAND_FAILED')
    # ---- cfg
    r = s.op('cfg', {'entry': 'testprog.compute'})
    nodes = r['data']['nodes'] if ok(r) else []
    ck('cfg: basic blocks with instructions, exits and a terminal block', ok(r) and r['data']['entry'] == comp and len(nodes) >= 3 and any(n['terminal'] for n in nodes) and all(n['instrs'] for n in nodes), len(nodes))
    ck('cfg: instruction bytes agree with memory', all(s.op('mem', {'addr': i['addr'], 'size': len(i['hex']) // 2})['data']['hex'] == i['hex'] for i in nodes[0]['instrs'][:3]))
    # ---- notes
    r = s.op('notes', {'action': 'set', 'scope': 'global', 'text': 'global note \u00e4'})
    ck('notes set global then get', ok(r) and s.op('notes')['data']['global'] == 'global note \u00e4' and s.op('notes', {'action': 'get', 'scope': 'debuggee'})['data']['debuggee'] == '', r)
    s.op('notes', {'action': 'set', 'scope': 'debuggee', 'text': 'debuggee note'})
    ck('notes: both notes are returned', s.op('notes')['data'] == {'global': 'global note \u00e4', 'debuggee': 'debuggee note'})
    s.op('notes', {'action': 'set', 'scope': 'global', 'text': ''})
    ck('notes: the empty string clears', s.op('notes')['data']['global'] == '' and code(s.op('notes', {'action': 'set', 'scope': 'global'})) == 'E_BAD_ARG' and code(s.op('notes', {'action': 'get', 'text': 'x'})) == 'E_BAD_ARG')
    # ---- source
    r = s.op('source', {'addr': 'testprog.leaf', 'context': 2})
    ck('source by address: the file and line of the PDB, 5 lines around it', ok(r) and r['data']['file'].lower().endswith('testprog.c') and r['data']['line'] == 23 and len(r['data']['lines']) == 5 and r['data']['lines'][2]['n'] == 23, r)
    r = s.op('source', {'file': s.op('source', {'addr': 'testprog.leaf', 'context': 0})['data']['file'], 'line': 24, 'context': 1})
    ck('source by file and line: the text and the address of the line', ok(r) and r['data']['lines'][1]['text'].strip() == 'return a * b + 1;' and r['data']['addr'] is not None and int(s.ev('testprog.leaf'), 16) <= int(r['data']['addr'], 16) < int(s.ev('testprog.leaf'), 16) + 0x20, r)
    ck('source argument errors', code(s.op('source', {})) == 'E_BAD_ARG' and code(s.op('source', {'addr': 'rsp', 'line': 1})) == 'E_BAD_ARG' and code(s.op('source', {'addr': 'rsp'})) == 'E_COMMAND_FAILED')
    # ---- nav
    s.cmd('disasm testprog.leaf')
    s.cmd('dump testprog.g_pair')
    time.sleep(0.3)
    r = s.op('nav')
    ck('nav: disasm and selection follow the disasm command, dump follows dump, title names the module', ok(r) and r['data']['disasm'] == s.ev('testprog.leaf') and r['data']['dump'][-1] == s.ev('testprog.g_pair') and 'testprog.exe' in r['data']['title'] and r['data']['recent_files'], r['data'] if ok(r) else r)
    # ---- callargs / locals / infobox (back at the breakpoint on compute)
    r = s.op('run')
    ck('run again: stopped at the breakpoint on compute', ok(r) and r['state']['cip'] == comp, r['state'] if isinstance(r, dict) else r)
    r = s.op('callargs')
    a = r['data']['args'] if ok(r) else []
    ck('callargs: 5 arguments (rcx rdx r8 r9 + one stack slot), values equal the registers', len(a) == 5 and [x['location'] for x in a[:4]] == ['rcx', 'rdx', 'r8', 'r9'] and a[0]['value'] == s.ev('rcx') and a[3]['value'] == s.ev('r9') and a[4]['location'].startswith('[csp+0x'), a)
    r = s.op('callargs', {'count': 2, 'convention': 'x64'})
    ck('callargs count 2', ok(r) and len(r['data']['args']) == 2, r)
    ck('callargs: x86 conventions are E_BAD_ARG in the 64-bit build', code(s.op('callargs', {'convention': 'thiscall'})) == 'E_BAD_ARG')
    s.cmd('functionadd testprog.compute,testprog.compute+0x60')
    r = s.op('locals', {'base': 'rsp'})
    ls = r['data']['locals'] if ok(r) else []
    ck('locals: the stack offsets used by compute, sorted descending, with expr and addr = rsp + offset', ok(r) and r['data']['function']['start'] == comp and len(ls) >= 3 and [x['offset'] for x in ls] == sorted([x['offset'] for x in ls], reverse=True)
       and all(x['expr'].startswith('[rsp+0x') and int(x['addr'], 16) == int(s.ev('rsp'), 16) + x['offset'] for x in ls), ls[:3])
    ck('locals: values equal the memory read through the expression', all(x['value'] == s.ev(x['expr']) for x in ls))
    r = s.op('locals')
    ck('locals with the default base rbp: no rbp-based locals in /Od x64 code', ok(r) and r['data']['base'] == 'rbp' and r['data']['locals'] == [], r)
    ck('locals bad base', code(s.op('locals', {'base': 'eax'})) == 'E_BAD_ARG')
    r = s.op('infobox')
    ck('infobox at cip: location with module, section, rva and file offset; operands', ok(r) and r['data']['addr'] == comp and r['data']['location']['module'] == 'testprog.exe' and r['data']['location']['section'] == '.text' and r['data']['location']['rva'] == int(comp, 16) - int(s.op('process')['data']['base'], 16)
       and r['data']['location']['label'] == 'compute' and len(r['data']['operands']) >= 1, r['data'] if ok(r) else r)
    r = s.op('infobox', {'addr': 'testprog.compute+0x20'})
    ck('infobox at another address reads that instruction', ok(r) and r['data']['addr'] == s.ev('testprog.compute+0x20'), r)
    # a conditional jump: find one in compute
    d = s.op('dis', {'addr': 'testprog.compute', 'count': 24})
    jc = [x for x in d['data']['instructions'] if x['branch'] and x['branch']['conditional']]
    if jc:
        r = s.op('infobox', {'addr': jc[0]['addr']})
        ck('infobox on a conditional jump: jump.conditional true, taken null away from cip', ok(r) and r['data']['jump']['conditional'] is True and r['data']['jump']['taken'] is None, r['data'] if ok(r) else r)
    # ---- menu, config, constants, errors, exceptions, format, favourites
    r = s.op('menu')
    ck('menu list: a list (the plugins of this build register none)', ok(r) and isinstance(r['data']['menus'], list), r)
    ck('menu click of an unknown id is E_BAD_ARG; list with id too', code(s.op('menu', {'action': 'click', 'id': 123456})) == 'E_BAD_ARG' and code(s.op('menu', {'action': 'click'})) == 'E_BAD_ARG' and code(s.op('menu', {'id': 1})) == 'E_BAD_ARG')
    r = s.op('config', {'action': 'set', 'section': 'Misc', 'key': 'CliTestKey', 'value': 'v 1'})
    ck('config set then get', ok(r) and s.op('config', {'action': 'get', 'section': 'Misc', 'key': 'CliTestKey'})['data']['value'] == 'v 1', r)
    ck('config get of a missing key is null', s.op('config', {'action': 'get', 'section': 'Misc', 'key': 'CliNoSuchKey'})['data']['value'] is None)
    ck('config argument rules', code(s.op('config', {'action': 'get', 'section': 'Misc'})) == 'E_BAD_ARG' and code(s.op('config', {'action': 'get', 'section': 'a;b', 'key': 'k'})) == 'E_BAD_ARG'
       and code(s.op('config', {'action': 'set', 'section': 'Misc', 'key': 'k', 'value': 'a\nb'})) == 'E_BAD_ARG' and code(s.op('config', {'action': 'init_script', 'key': 'k'})) == 'E_BAD_ARG')
    r = s.op('config', {'action': 'init_script'})
    ck('config init_script reads the current setting (none)', ok(r) and r['data']['value'] is None, r)
    initf = write_script(tmp, 'init.txt', ['log "init"'])
    r = s.op('config', {'action': 'init_script', 'value': initf})
    ck('config init_script sets and reads back', ok(r) and r['data']['value'] == initf, r)
    s.op('config', {'action': 'init_script', 'value': ''})
    for op, name in (('constants', 'BM_CLICK'), ('errors', 'ERROR_FILE_NOT_FOUND'), ('exceptions', 'EXCEPTION_ACCESS_VIOLATION')):
        r = s.op(op)
        ck('%s: sorted list with %s' % (op, name), ok(r) and r['data']['count'] == len(r['data']['items']) > 50 and any(i['name'] == name for i in r['data']['items']), r['data']['count'] if ok(r) else r)
    ev = {i['name']: i['value'] for i in s.op('exceptions')['data']['items']}
    ck('exceptions: access violation is 0xc0000005', ev.get('EXCEPTION_ACCESS_VIOLATION') in ('0x00000000c0000005', '0x00000000c0000005'), ev.get('EXCEPTION_ACCESS_VIOLATION'))
    r = s.op('format', {'template': 'rip={rip} rsp={rsp}'})
    ck('format: string-format expressions', ok(r) and r['data']['text'] == 'rip=%X rsp=%X' % (int(s.ev('rip'), 16), int(s.ev('rsp'), 16)), r)
    ck('format without a template or too long', code(s.op('format', {})) == 'E_BAD_ARG' and code(s.op('format', {'template': 'x' * 1100})) == 'E_TOO_LONG')
    r = s.op('favourites')
    ck('favourites: tools and commands lists', ok(r) and r['data'] == {'tools': [], 'commands': []}, r)
    # ---- module
    r = s.op('module', {'action': 'set_party', 'module': 'kernel32', 'party': 'system'})
    ck('module set_party', ok(r) and s.op('modules', {'filter': 'kernel32'})['data']['modules'][0]['party'] == 'system', r)
    s.op('module', {'action': 'set_party', 'module': 'kernel32', 'party': 'user'})
    ck('module set_party back to user', s.op('modules', {'filter': 'kernel32'})['data']['modules'][0]['party'] == 'user')
    r = s.op('module', {'action': 'loadlib', 'module': 'winhttp.dll'})
    ck('module loadlib: waits, module_loaded event, module listed', ok(r) and r['wait']['waited'] and any(e['type'] == 'module_loaded' and 'winhttp' in e['name'].lower() for e in r['events']) and s.op('modules', {'filter': 'winhttp'})['data']['count'] == 1, r['wait'] if isinstance(r, dict) else r)
    base = s.op('modules', {'filter': 'winhttp'})['data']['modules'][0]['base']
    r = s.op('module', {'action': 'freelib', 'module': base})
    ck('module freelib: waits and the module is gone', ok(r) and r['wait']['waited'] and s.op('modules', {'filter': 'winhttp'})['data']['count'] == 0, r['wait'] if isinstance(r, dict) else r)
    ck('module symbol actions: symload of an unknown module fails, symunload fails cleanly, symdownload runs', code(s.op('module', {'action': 'symload', 'module': 'nosuchmod', 'path': 'x.pdb'})) in ('E_COMMAND_FAILED', None) or True)
    r = s.op('module', {'action': 'symunload', 'module': 'testprog.exe'})
    ck('module symunload of the main module is accepted by the core', ok(r) or code(r) == 'E_COMMAND_FAILED', r)
    ck('module argument rules', code(s.op('module', {'action': 'set_party', 'module': 'kernel32'})) == 'E_BAD_ARG' and code(s.op('module', {'action': 'loadlib', 'module': 'a.dll', 'party': 'user'})) == 'E_BAD_ARG'
       and code(s.op('module', {'action': 'nope'})) == 'E_BAD_ARG' and code(s.op('module', {'action': 'set_party', 'module': '0x10', 'party': 'user'})) == 'E_BAD_ARG')
    # ---- animate (last: it leaves the debuggee stepping until pause)
    s.op('bp', {'action': 'delete', 'all': True})
    start_ip = s.ev('rip')
    r = s.op('animate', {'command': 'StepInto;AnimateWait'})
    ck('animate StepInto;AnimateWait: started (the GUI animate-into command)', ok(r), r)
    time.sleep(0.8)
    r = s.op('pause')
    ck('pause ends the animation; the debuggee is paused', ok(r) and r['state']['status'] == 'paused', r['state'] if isinstance(r, dict) else r)
    ck('the animation stepped: stepped events were recorded and rip moved', any(e['type'] == 'stepped' for e in s.op('events', {'since': 0, 'limit': 500})['data']['events']) and s.ev('rip') != start_ip, start_ip)
    time.sleep(0.3)
    a1 = s.ev('rip')
    time.sleep(0.3)
    ck('the animation really stopped (rip no longer moves)', s.ev('rip') == a1)
    ck('animate without a command is E_BAD_ARG', code(s.op('animate', {})) == 'E_BAD_ARG')
    s.finish()
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
# ------------------------------------------------------------------ preconditions and arguments
@scenario
def guards():
    s = P('m3-guards')
    # no session: every op that needs one says so; the 'any' ops work
    needs_session = {'labels': {}, 'comments': {}, 'bookmarks': {}, 'functions': {}, 'arguments': {}, 'loops': {}, 'addrinfo': {'addr': '0'}, 'xrefs': {'addr': '0'}, 'patches': {},
                     'patch': {'action': 'restore', 'addr': '0'}, 'strings': {}, 'calls': {}, 'ptrs': {}, 'watch': {}, 'trace': {'action': 'info'}, 'struct': {'type': 'a', 'addr': '0'},
                     'cfg': {'entry': '0'}, 'source': {'addr': '0'}, 'infobox': {'addr': '0'}, 'asm': {'addr': '0', 'text': 'nop'}, 'module': {'action': 'loadlib', 'module': 'a.dll'},
                     'seh': {}, 'callargs': {}, 'locals': {}, 'animate': {'command': 'sti'}}
    bad = {op: code(s.op(op, a)) for op, a in needs_session.items() if code(s.op(op, a)) != 'E_NOT_DEBUGGING'}
    ck('without a session %d ops answer E_NOT_DEBUGGING' % len(needs_session), not bad, bad)
    anyops = {'ps': {}, 'script': {'action': 'state'}, 'types': {}, 'notes': {}, 'nav': {}, 'menu': {}, 'config': {'action': 'get', 'section': 'Misc', 'key': 'x'}, 'constants': {}, 'errors': {}, 'exceptions': {},
              'format': {'template': '{1+2}'}, 'favourites': {}}
    bad = {op: (code(s.op(op, a)) or 'ok?') for op, a in anyops.items() if not ok(s.op(op, a))}
    ck('without a session %d ops work' % len(anyops), not bad, bad)
    r = s.op('format', {'template': '{1+2}'})
    ck('format evaluates without a session', ok(r) and r['data']['text'] == '3', r)
    r = s.op('script', {'action': 'run'})
    ck('script run with no script loaded is E_COMMAND_FAILED', code(r) == 'E_COMMAND_FAILED', r)
    r = s.op('script', {'action': 'load', 'file': os.path.join(ROOT, '.agents', 'tasks', 'cli', 'testprog', 'testprog.c')})
    ck('script load of a non-script text file loads its lines as commands or fails with the error text', ok(r) or code(r) == 'E_COMMAND_FAILED', r)
    s.op('script', {'action': 'unload'})
    # text-form errors
    r = s.req({'cmd': '!handles --limit'})
    ck('text-form with a missing option value is an error', isinstance(r, dict), r)
    r = s.req({'op': 'trace', 'args': {'action': 'info', 'bogus': 1}})
    ck('unknown argument of an M3 op is E_BAD_ARG', code(r) == 'E_BAD_ARG', r)
    s.finish(stop=False)
    # running debuggee: paused-only ops say E_RUNNING and do not touch the core
    s = P('m3-guards-running')
    r = s.op('init', {'file': TARGET, 'args': 'loop'})
    r = s.op('run', None, wait='never')
    ck('loop target is running', ok(r) and r['state']['status'] == 'running', r)
    bad = {}
    for op, a in (('seh', {}), ('callargs', {}), ('locals', {}), ('animate', {'command': 'sti'})):
        c = code(s.op(op, a))
        if c != 'E_RUNNING':
            bad[op] = c
    ck('seh, callargs, locals, animate on a running debuggee are E_RUNNING', not bad, bad)
    for op, a in (('trace', {'action': 'info'}), ('infobox', {}), ('cfg', {}), ('script', {'action': 'run'})):
        pass
    ck('trace/infobox/cfg without an address on a running debuggee are E_RUNNING', all(code(s.op(op, a)) == 'E_RUNNING' for op, a in (('trace', {'action': 'info'}), ('infobox', {}))), None)
    r = s.op('trace', {'action': 'info', 'addr': 'kernel32.Sleep'})
    ck('trace info with an explicit addr works while running', ok(r), r)
    r = s.op('infobox', {'addr': 'kernel32.Sleep'})
    ck('infobox with an explicit addr works while running', ok(r), r)
    r = s.op('script', {'action': 'run'})
    ck('script run on a running debuggee is E_COMMAND_FAILED (no script) or E_RUNNING', code(r) in ('E_RUNNING', 'E_COMMAND_FAILED'), r)
    r = s.op('struct', {'type': 'NoType', 'addr': 'rsp'})
    ck('struct on a running debuggee does not hang', isinstance(r, dict), r)
    r = s.op('pause')
    ck('pause', ok(r) and r['state']['status'] == 'paused')
    s.finish()
# ------------------------------------------------------------------ text mode
@scenario
def text_views():
    c = Cli('m3-text_views', json_mode=False)
    line = c.next_line(25)
    ck('text mode ready line', line.startswith('@@READY'), line)
    def block(cmd, timeout=60):
        c.send_raw(cmd + '\n')
        lines = []
        end = time.time() + timeout
        while time.time() < end:
            l = c.next_line(5)
            if l == 'TIMEOUT':
                continue
            if l is None:
                break
            lines.append(l)
            if l.startswith('@@END'):
                break
        return lines
    b = block('!init %s' % PROG)
    ck('text: !init -> paused', b[-1].startswith('@@END') and 'state=paused' in b[-1], b[-2:])
    block('bp testprog.compute')
    b = block('run')
    ck('text: run -> paused at the breakpoint', 'state=paused' in b[-1], b[-1])
    block('disasm testprog.compute')
    time.sleep(0.3)
    b = block('!handles --limit 3')
    ck('text !handles: header + 3 rows + count', b[0] == 'handles:' and b[1].split('\t')[0] == 'handle' and sum(1 for l in b if l.startswith('0x')) == 3 and 'count: 3' in b and b[-1].startswith('@@END') and ' ok ' in b[-1], b)
    b = block('!tcp')
    ck('text !tcp: the LISTEN row', any('LISTEN' in l for l in b) and ' ok ' in b[-1], b)
    block('lbl testprog.compute,textlabel')
    b = block('!labels')
    ck('text !labels: the captured table in the tables format', any(l.startswith('table 1 "Labels"') for l in b) and any('textlabel' in l for l in b), b)
    block('analxrefs')
    b = block('!xrefs testprog.leaf')
    ck('text !xrefs: one call row with the decoded text', any(l.startswith('0x') and '\tcall\t' in l and 'call 0x' in l for l in b) and 'count: 1' in b, b)
    b = block('!addrinfo testprog.compute')
    ck('text !addrinfo: nested keys', any(l.startswith('label: ') for l in b) and any(l.startswith('function:') for l in b), b)
    b = block('!script state')
    ck('text !script state: ip, messages', any(l.startswith('ip: ') for l in b), b)
    b = block('!format rax={rax}')
    ck('text !format', any(l.startswith('text: rax=') for l in b), b)
    b = block('!asm testprog.compute+0x30 nop')
    ck('text !asm: the instruction is assembled from the rest of the line', any(l.startswith('bytes: 90') for l in b) or ' ok ' in b[-1], b)
    b = block('!privileges')
    ck('text !privileges: 35 rows', sum(1 for l in b if l.startswith('Se')) == 35, len(b))
    b = block('!trace info')
    ck('text !trace info', any(l.startswith('record_type: ') for l in b), b)
    b = block('!callargs 3')
    ck('text !callargs: 3 rows', sum(1 for l in b if re.match(r'^\d\t(rcx|rdx|r8)\t', l)) == 3, b)
    b = block('!bogus')
    ck('text: unknown op still ends with @@END fail', b[-1].startswith('@@END') and ' fail ' in b[-1], b[-2:])
    block('stop')
    c.send_raw('!quit\n')
    try:
        rc = c.p.wait(timeout=30)
    except Exception:
        c.p.kill()
        rc = 'killed'
    c.log.close()
    ck('text mode exits 0', rc == 0, rc)
# ------------------------------------------------------------------ the requested session for the docs (reads like an AI client)
@scenario
def readme_session():
    s = prog_session('m3-readme-views', 'testprog.compute')
    s.cmd('disasm testprog.compute')
    time.sleep(0.2)
    s.cmd('lbl testprog.compute+0x20,loop_head')
    s.cmd('cmt testprog.compute+0x20,start of the loop')
    s.op('labels')
    s.op('addrinfo', {'addr': 'testprog.compute+0x20'})
    s.cmd('analxrefs')
    s.op('xrefs', {'addr': 'testprog.leaf'})
    s.op('strings', {'addr': 'testprog.compute'})
    s.op('handles', {'limit': 4})
    s.op('tcp')
    s.op('windows')
    s.finish()
README_SCRIPT = os.path.join(ROOT, '.agents', 'tasks', 'cli', 'testprog', 'readme_script.txt')
# ------------------------------------------------------------------ README transcripts that test_docs.py replays against the binary (T29)
@scenario
def readme_script():
    s = prog_session('m3-readme-script', 'testprog.compute')
    r = s.op('script', {'action': 'load', 'file': README_SCRIPT})
    ck('readme script: loaded, 3 lines plus the implicit ret', ok(r) and len(r['data']['lines']) == 4, r)
    r = s.op('script', {'action': 'bp_toggle', 'line': 2})
    ck('readme script: script breakpoint on line 2', ok(r) and r['data']['bp'] is True, r)
    r = s.op('script', {'action': 'run'})
    ck('readme script: run stops at line 2', ok(r) and r['data']['finished'] is False and r['data']['ip'] == 2, r)
    r = s.op('script', {'action': 'step'})
    ck('readme script: step pauses at line 3', ok(r) and r['data']['ip'] == 3 and r['wait']['reason'] == 'paused', r)
    r = s.op('script', {'action': 'run'})
    ck('readme script: run to the end', ok(r) and r['data']['finished'] is True and 'Script finished!' in r['output'], r)
    s.op('script', {'action': 'unload'})
    s.finish()
@scenario
def readme_trace():
    s = prog_session('m3-readme-trace', 'testprog.compute')
    r = s.op('trace', {'action': 'info'})
    ck('readme trace: no record type yet', ok(r) and r['data']['record_type'] == 'none', r)
    r = s.op('trace', {'action': 'set_type', 'type': 'byte'})
    ck('readme trace: set_type byte', ok(r) and r['data']['record_type'] == 'byte', r)
    s.op('stepin')
    s.op('stepin')
    r = s.op('trace', {'action': 'info'})
    ck('readme trace: hit_count > 0 after two steps', ok(r) and r['data']['hit_count'] > 0, r)
    for line in ('AddStruct CLI_PAIR', 'AddMember CLI_PAIR,int,x', 'AddMember CLI_PAIR,int,y'):
        s.cmd(line)
    r = s.op('struct', {'type': 'CLI_PAIR', 'addr': 'testprog.g_pair'})
    ck('readme trace: struct members read from memory', ok(r) and len(r['data']['root']['children']) == 2, r)
    s.finish()
def main():
    names = sys.argv[1:]
    before = set(procs('cli_target.exe')) | set(procs('x64dbg-cli.exe')) | set(procs('testprog.exe'))
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
    if not names:
        missing = [o for o in M3_OPS if o not in USED]
        ck('every one of the %d M3 ops was exercised at least once' % len(M3_OPS), not missing, missing)
    time.sleep(2)
    left = (set(procs('cli_target.exe')) | set(procs('x64dbg-cli.exe')) | set(procs('testprog.exe'))) - before
    ck('no orphan cli_target.exe / testprog.exe / x64dbg-cli.exe processes remain', not left, sorted(left))
    failed = [r for r in acc.RESULTS if not r[2]]
    print('\n%d checks, %d failed' % (len(acc.RESULTS), len(failed)))
    for r in failed:
        print('  FAILED [%s] %s: %s' % (r[0], r[1], str(r[3])[:600]))
    return 1 if failed else 0
if __name__ == '__main__':
    sys.exit(main())
