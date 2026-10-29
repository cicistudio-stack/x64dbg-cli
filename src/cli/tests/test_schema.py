#!/usr/bin/env python3
"""Runs the M1 ops through the real x64dbg-cli.exe and validates args and data against src/cli/schema/*.schema.

Usage: python src/cli/tests/test_schema.py        exit 0 when every check passed
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m1_acceptance as acc  # noqa: E402
from schemalib import Schemas, SchemaError  # noqa: E402

ck = acc.ck


def check_op(schemas, op, response, req_args=None):
    ck('%s: response is ok' % op, response not in (None, 'TIMEOUT') and response.get('ok'), response)
    if response in (None, 'TIMEOUT'):
        return
    if req_args is not None:
        errs = schemas.validate_op(op, 'args', req_args)
        ck('%s: args match the schema' % op, not errs, errs)
    errs = schemas.validate_op(op, 'data', response.get('data'))
    ck('%s: data matches the schema' % op, not errs, errs)


def run():
    acc.CURRENT[0] = 'schema'
    try:
        schemas = Schemas()
    except SchemaError as e:
        ck('schema files load (no duplicate or undefined names)', False, e)
        return
    ck('schema files load (no duplicate or undefined names)', True)
    c = acc.Cli('schema_ops')
    hello = c.hello()
    ops = hello['capabilities']['ops']
    missing = [o for o in ops if o not in schemas.ops]
    ck('every op announced in hello has a schema file', not missing, missing)
    errs = schemas.validate('hello', hello)
    ck('hello matches the envelope schema', not errs, errs)

    r = c.request({'id': 1, 'op': 'status'})
    check_op(schemas, 'status', r, {})
    r = c.request({'id': 2, 'op': 'eval', 'args': {'expr': '1+2*3'}})
    check_op(schemas, 'eval', r, {'expr': '1+2*3'})
    r = c.request({'id': 3, 'op': 'help'})
    check_op(schemas, 'help', r, {})
    r = c.request({'id': 4, 'op': 'commands', 'args': {'prefix': 'step'}})
    check_op(schemas, 'commands', r, {'prefix': 'step'})
    r = c.request({'id': 5, 'op': 'wait'})
    check_op(schemas, 'wait', r, {})
    r = c.request({'id': 6, 'op': 'interrupt'})
    check_op(schemas, 'interrupt', r, {})
    r = c.request({'id': 7, 'op': 'native', 'args': {'cmd': 'log hello'}})
    check_op(schemas, 'native', r, {'cmd': 'log hello'})
    r = c.request({'id': 8, 'op': 'log', 'args': {'tail': 5}})
    check_op(schemas, 'log', r, {'tail': 5})
    r = c.request({'id': 9, 'op': 'events', 'args': {'since': 0, 'limit': 50}})
    check_op(schemas, 'events', r, {'since': 0, 'limit': 50})

    r = acc.init_target(c, 'call')
    ck('init for the session views', r and r['ok'], r)
    r = c.request({'id': 10, 'op': 'status'})
    check_op(schemas, 'status', r, {})
    ck('status with a session has process info', r['data']['process'] is not None, r['data'])
    c.request({'id': 11, 'cmd': 'lbl rip,schematest; labellist'})
    r = c.request({'id': 12, 'op': 'table'})
    check_op(schemas, 'table', r, {})
    r = c.request({'id': 13, 'op': 'table', 'args': {'id': r['data']['id'], 'offset': 0, 'limit': 10}})
    check_op(schemas, 'table', r, {'id': r['data']['id'], 'offset': 0, 'limit': 10})
    r = c.request({'id': 14, 'op': 'wait'})
    check_op(schemas, 'wait', r, {})
    r = c.request({'id': 15, 'cmd': 'bp kernel32.Sleep'})
    r = c.request({'id': 16, 'cmd': 'run'})
    for ev in r['events']:
        errs = schemas.validate('event', ev)
        ck('event %s matches event.schema' % ev.get('type'), not errs, errs)
    r = c.request({'id': 17, 'op': 'events', 'args': {'since': 0, 'limit': 500}})
    check_op(schemas, 'events', r, {'since': 0, 'limit': 500})
    for ev in r['data']['events']:
        errs = schemas.validate('event', ev)
        if errs:
            ck('events op: event %s matches event.schema' % ev.get('type'), False, errs)
    # ---- M2 ops against the paused call-mode debuggee (stopped at the kernel32.Sleep breakpoint)
    n = [100]

    def m2(op, args=None, **opt):
        n[0] += 1
        req = {'id': n[0], 'op': op}
        if args is not None:
            req['args'] = args
        req.update(opt)
        return c.request(req, 60)
    for op, args in (('process', {}), ('regs', {'groups': 'gpr,flags,seg,dbg,fpu,mmx,xmm,ymm'}), ('regs', {'groups': 'all'}), ('regs', {}),
                     ('dis', {'count': 5}), ('dis', {'addr': 'rip', 'until': 'rip+10', 'bytes': False}), ('dis', {'count': 2, 'back': 1}),
                     ('mem', {'addr': 'rsp', 'size': 48}), ('mem', {'addr': 'rsp', 'size': 32, 'format': 'ptr'}),
                     ('mem', {'addr': 'rsp', 'size': 16, 'format': 'double', 'cols': 8}), ('mem', {'addr': 'rip', 'size': 12, 'format': 'ascii'}),
                     ('memmap', {}), ('memmap', {'filter': 'kernel32'}), ('stack', {'count': 6}), ('callstack', {}), ('callstack', {'thread': 'all'}),
                     ('bps', {}), ('threads', {}), ('modules', {}), ('modules', {'filter': 'ntdll'}),
                     ('sym', {'pattern': 'CreateFileW', 'module': 'kernel32', 'limit': 5}), ('sym', {'addr': 'rip'})):
        r = m2(op, args)
        check_op(schemas, op, r, args)
    r = m2('setreg', {'reg': 'rax', 'value': '0x42'})
    check_op(schemas, 'setreg', r, {'reg': 'rax', 'value': '0x42'})
    r = m2('bp', {'action': 'add', 'kind': 'sw', 'target': 'kernel32.CreateFileW', 'name': 'x', 'condition': '1'})
    check_op(schemas, 'bp', r, {'action': 'add', 'kind': 'sw', 'target': 'kernel32.CreateFileW', 'name': 'x', 'condition': '1'})
    for args in ({'action': 'add', 'kind': 'hw', 'target': 'rsp', 'hw_type': 'w', 'size': 4}, {'action': 'add', 'kind': 'mem', 'target': 'rsp', 'mem_type': 'r'},
                 {'action': 'add', 'kind': 'dll', 'target': 'winhttp.dll'}, {'action': 'add', 'kind': 'exception', 'target': '0xc0000005'}):
        r = m2('bp', args)
        check_op(schemas, 'bp', r, args)
    r = m2('bps', {})
    check_op(schemas, 'bps', r, {})
    for args in ({'action': 'disable', 'all': True}, {'action': 'enable', 'all': True}, {'action': 'reset_hits', 'all': True}, {'action': 'delete', 'all': True}):
        r = m2('bp', args)
        check_op(schemas, 'bp', r, args)
    r = c.request({'id': 150, 'cmd': 'alloc 1000', 'vars': ['$result']}, 30)
    area = r['vars']['$result']
    for args in ({'addr': area, 'hex': '90 90 c3'}, {'addr': area, 'ascii': 'abc', 'patch': False}, {'addr': area, 'utf16': 'xy'}):
        r = m2('memwrite', args)
        check_op(schemas, 'memwrite', r, args)
    th = m2('threads', {})['data']
    for args in ({'action': 'switch', 'tid': th['current_tid']}, {'action': 'suspend', 'tid': th['current_tid']}, {'action': 'resume', 'tid': th['current_tid']},
                 {'action': 'suspend_all'}, {'action': 'resume_all'}, {'action': 'name', 'tid': th['current_tid'], 'value': 'schema'},
                 {'action': 'priority', 'tid': th['current_tid'], 'value': 'Normal'}):
        r = m2('thread', args)
        check_op(schemas, 'thread', r, args)
    for op, args in (('stepin', {}), ('stepover', {'count': 1}), ('stepout', {})):
        r = m2(op, args)
        check_op(schemas, op, r, args)
    # the loop target keeps calling Sleep: run, runto, run without waiting, pause
    r = m2('init', {'file': acc.TARGET, 'args': 'loop'})
    check_op(schemas, 'init', r, {'file': acc.TARGET, 'args': 'loop'})
    r = m2('bp', {'action': 'add', 'target': 'kernelbase.Sleep'})
    r = m2('run')
    check_op(schemas, 'run', r, None)
    r = m2('runto', {'addr': 'kernelbase.Sleep'})
    check_op(schemas, 'runto', r, {'addr': 'kernelbase.Sleep'})
    m2('bp', {'action': 'delete', 'all': True})
    r = m2('run', None, wait='never')
    check_op(schemas, 'run', r, None)
    r = m2('pause')
    check_op(schemas, 'pause', r, None)
    r = m2('restart')
    check_op(schemas, 'restart', r, None) if r.get('ok') else ck('restart without a previous wrapper init is E_BAD_ARG', r['error']['code'] == 'E_BAD_ARG', r)
    r = m2('init', {'file': acc.TARGET, 'args': 'call'})
    check_op(schemas, 'init', r, {'file': acc.TARGET, 'args': 'call'})
    r = m2('restart')
    check_op(schemas, 'restart', r, None)
    r = m2('stop')
    check_op(schemas, 'stop', r, None)
    ck('every M2 op announced in hello has a schema file', all(o in schemas.ops for o in hello['capabilities']['ops']), [o for o in hello['capabilities']['ops'] if o not in schemas.ops])
    r = c.request({'id': 18, 'op': 'quit', 'args': {}})
    check_op(schemas, 'quit', r, {})
    try:
        rc = c.p.wait(timeout=30)
    except Exception:
        c.p.kill()
        rc = 'killed'
    ck('quit exits 0', rc == 0, rc)
    c.log.close()

    # negative controls: the validator must reject a renamed field and an unknown op
    bad = dict(r['data']) if r.get('data') else {}
    bad['unexpected'] = 1
    ck('negative: extra key in data is rejected', bool(schemas.validate_op('quit', 'data', bad)))
    ck('negative: op without a schema is rejected', bool(schemas.validate_op('nosuchop', 'data', {})))


if __name__ == '__main__':
    run()
    failed = [r for r in acc.RESULTS if not r[2]]
    print('\n%d checks, %d failed' % (len(acc.RESULTS), len(failed)))
    sys.exit(1 if failed else 0)
