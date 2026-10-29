#!/usr/bin/env python3
"""Loader and validator for the schema notation of design 9.6 (stdlib only).

Files: src/cli/schema/*.schema. common.schema is read first. The first line of an op file is
`schema <op> [<op> ...]`, followed by `args:` / `data:` / `typedef` lines. envelope.schema and event.schema hold
plain definitions (`name = type`).
"""
import os
import re

SCHEMA_DIR = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')), 'src', 'cli', 'schema')

TOKEN = re.compile(r'''
    \s*(?:
      (?P<opt>[A-Za-z_][\w]*\?:)
    | (?P<key>[A-Za-z_][\w]*:)
    | (?P<map><[A-Za-z_][\w]*>:)
    | (?P<str>"[^"]*")
    | (?P<id>[A-Za-z_][\w-]*)
    | (?P<sym>[{}\[\]()|,])
    )''', re.X)

ADDR = re.compile(r'^0x[0-9a-f]{16}$')
U16 = re.compile(r'^0x[0-9a-f]{4}$')
U32 = re.compile(r'^0x[0-9a-f]{8}$')
HEX = re.compile(r'^([0-9a-f]{2})*$')


class SchemaError(Exception):
    pass


def tokenize(text):
    pos = 0
    out = []
    text = text.rstrip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise SchemaError('cannot tokenize at: %r' % text[pos:pos + 40])
        pos = m.end()
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
    return out


class Parser:
    def __init__(self, tokens):
        self.t = tokens
        self.i = 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expect_sym(self, s):
        k, v = self.take()
        if k != 'sym' or v != s:
            raise SchemaError('expected %s got %r' % (s, v))

    def parse_type(self):
        """type := alt ('|' alt)* only inside parentheses; at top level a single term."""
        k, v = self.peek()
        if k == 'sym' and v == '(':
            self.take()
            alts = [self.parse_type()]
            while self.peek() == ('sym', '|'):
                self.take()
                alts.append(self.parse_type())
            self.expect_sym(')')
            return ('union', alts)
        if k == 'sym' and v == '[':
            self.take()
            inner = self.parse_type()
            self.expect_sym(']')
            return ('list', inner)
        if k == 'sym' and v == '{':
            return self.parse_object()
        if k == 'str':
            self.take()
            return ('lit', v[1:-1])
        if k == 'id':
            self.take()
            if v == 'enum' and self.peek() == ('sym', '('):
                self.take()
                names = []
                while True:
                    k2, v2 = self.take()
                    if k2 != 'id':
                        raise SchemaError('bad enum member %r' % (v2,))
                    names.append(v2)
                    k3, v3 = self.take()
                    if (k3, v3) == ('sym', ')'):
                        break
                    if (k3, v3) != ('sym', '|'):
                        raise SchemaError('bad enum separator %r' % (v3,))
                return ('enum', names)
            return ('name', v)
        raise SchemaError('unexpected token %r' % (v,))

    def parse_field_list(self, stop):
        """Fields separated by commas up to the token `stop` (not consumed)."""
        fields = []
        while True:
            k, v = self.peek()
            if (k, v) == ('sym', stop):
                break
            if k == 'sym' and v == '(':
                # choice group of field lists: (a:T, b:U | c:V)
                self.take()
                groups = [self.parse_field_list_until_bar()]
                while self.peek() == ('sym', '|'):
                    self.take()
                    groups.append(self.parse_field_list_until_bar())
                self.expect_sym(')')
                fields.append(('choice', groups))
            elif k in ('opt', 'key'):
                self.take()
                ty = self.parse_type()
                fields.append(('field', v[:-2] if k == 'opt' else v[:-1], k == 'opt', ty))
            elif k == 'map':
                self.take()
                ty = self.parse_type()
                fields.append(('map', v[1:-2], ty))
            else:
                raise SchemaError('unexpected %r in object' % (v,))
            if self.peek() == ('sym', ','):
                self.take()
        return fields

    def parse_field_list_until_bar(self):
        fields = []
        while True:
            k, v = self.peek()
            if k == 'sym' and v in ('|', ')'):
                break
            if k in ('opt', 'key'):
                self.take()
                ty = self.parse_type()
                fields.append(('field', v[:-2] if k == 'opt' else v[:-1], k == 'opt', ty))
            else:
                raise SchemaError('unexpected %r in choice' % (v,))
            if self.peek() == ('sym', ','):
                self.take()
        return fields

    def parse_object(self):
        self.expect_sym('{')
        fields = self.parse_field_list('}')
        self.expect_sym('}')
        return ('obj', fields)


def strip_comments(text):
    return '\n'.join(re.sub(r'//.*$', '', l) for l in text.split('\n'))


DEF = re.compile(r'(?:^|(?<=\s))(typedef\s+)?([A-Za-z][\w-]*)\s*=\s', re.S)


def parse_defs(text):
    """name = type definitions in text. Returns dict name -> type tree. Prose definitions (response-body) are skipped."""
    text = strip_comments(text)
    marks = []
    for m in DEF.finditer(text):
        marks.append((m.start(), m.end(), m.group(2)))
    out = {}
    for n, (s, e, name) in enumerate(marks):
        end = marks[n + 1][0] if n + 1 < len(marks) else len(text)
        body = text[e:end]
        if '-' in name or body.lstrip().startswith('(see '):
            continue  # prose placeholders: response-body, and event (defined in event.schema)
        p = Parser(tokenize(body))
        ty = p.parse_type()
        if p.i != len(p.t):
            raise SchemaError('trailing tokens in definition of %s: %r' % (name, p.t[p.i:p.i + 3]))
        if name in out:
            raise SchemaError('name defined twice: ' + name)
        out[name] = ty
    return out


class Schemas:
    def __init__(self, directory=SCHEMA_DIR):
        self.types = {}
        self.ops = {}      # op -> {'args': type|None, 'data': type|None, 'file': name}
        self.files = []
        order = sorted(os.listdir(directory), key=lambda n: (n != 'common.schema', n))
        for name in order:
            if not name.endswith('.schema'):
                continue
            self.files.append(name)
            with open(os.path.join(directory, name), encoding='utf-8') as f:
                text = f.read().replace('\r\n', '\n')
            if text.startswith('schema '):
                self._load_op(name, text)
            else:
                for k, v in parse_defs(text).items():
                    self._add_type(k, v)
        self._check_refs()

    def _add_type(self, name, ty):
        if name in self.types:
            raise SchemaError('type defined twice: ' + name)
        self.types[name] = ty

    def _load_op(self, fname, text):
        lines = text.split('\n')
        names = lines[0].split()[1:]
        body = strip_comments('\n'.join(lines[1:]))
        # split into args:/data:/typedef sections
        parts = re.split(r'(?m)^(?=(?:args|data):|typedef\s)', body)
        args = data = None
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if p.startswith('typedef'):
                for k, v in parse_defs(p).items():
                    self._add_type(k, v)
            else:
                key, _, rest = p.partition(':')
                pr = Parser(tokenize(rest))
                ty = pr.parse_type()
                if pr.i != len(pr.t):
                    raise SchemaError('%s: trailing tokens in %s' % (fname, key))
                if key == 'args':
                    args = ty
                else:
                    data = ty
        for n in names:
            if n in self.ops:
                raise SchemaError('op schema defined twice: ' + n)
            self.ops[n] = {'args': args, 'data': data, 'file': fname}

    def _walk(self, ty, f):
        f(ty)
        k = ty[0]
        if k == 'union':
            for a in ty[1]:
                self._walk(a, f)
        elif k == 'list':
            self._walk(ty[1], f)
        elif k == 'obj':
            for fld in ty[1]:
                if fld[0] == 'field':
                    self._walk(fld[3], f)
                elif fld[0] == 'map':
                    self._walk(fld[2], f)
                else:
                    for g in fld[1]:
                        for gf in g:
                            self._walk(gf[3], f)

    BASE = {'int', 'num', 'str', 'bool', 'bit', 'addr', 'u16', 'u32', 'hex', 'null', 'obj', 'any'}

    def _check_refs(self):
        missing = []

        def chk(ty):
            if ty[0] == 'name' and ty[1] not in self.BASE and ty[1] not in self.types and ty[1] != 'response-body':
                missing.append(ty[1])
        for t in list(self.types.values()):
            self._walk(t, chk)
        for o in self.ops.values():
            for key in ('args', 'data'):
                if o[key]:
                    self._walk(o[key], chk)
        if missing:
            raise SchemaError('undefined type names: ' + ', '.join(sorted(set(missing))))

    # ---------------------------------------------------------------- validation
    def check(self, ty, value, path, errs):
        k = ty[0]
        if k == 'name':
            n = ty[1]
            if n in self.types:
                self.check(self.types[n], value, path, errs)
            else:
                self.check_base(n, value, path, errs)
        elif k == 'lit':
            if value != ty[1]:
                errs.append('%s: expected %r got %r' % (path, ty[1], value))
        elif k == 'enum':
            if not isinstance(value, str) or value not in ty[1]:
                errs.append('%s: %r not in enum(%s)' % (path, value, '|'.join(ty[1])))
        elif k == 'list':
            if not isinstance(value, list):
                errs.append('%s: expected list got %s' % (path, type(value).__name__))
            else:
                for i, v in enumerate(value):
                    self.check(ty[1], v, '%s[%d]' % (path, i), errs)
        elif k == 'union':
            best = None
            for alt in ty[1]:
                e = []
                self.check(alt, value, path, e)
                if not e:
                    return
                if best is None or len(e) < len(best):
                    best = e
            errs.append('%s: matches no alternative of the union (closest: %s)' % (path, '; '.join(best[:3])))
        elif k == 'obj':
            self.check_obj(ty, value, path, errs)

    def check_base(self, n, v, path, errs):
        ok = True
        if n == 'int':
            ok = isinstance(v, int) and not isinstance(v, bool)
        elif n == 'num':
            ok = isinstance(v, (int, float)) and not isinstance(v, bool)
        elif n == 'str':
            ok = isinstance(v, str)
        elif n == 'bool':
            ok = isinstance(v, bool)
        elif n == 'bit':
            ok = v in (0, 1) and not isinstance(v, bool)
        elif n == 'addr':
            ok = isinstance(v, str) and bool(ADDR.match(v))
        elif n == 'u16':
            ok = isinstance(v, str) and bool(U16.match(v))
        elif n == 'u32':
            ok = isinstance(v, str) and bool(U32.match(v))
        elif n == 'hex':
            ok = isinstance(v, str) and bool(HEX.match(v))
        elif n == 'null':
            ok = v is None
        elif n == 'obj':
            ok = isinstance(v, dict)
        if not ok:
            errs.append('%s: expected %s got %r' % (path, n, v if not isinstance(v, (dict, list)) else type(v).__name__))

    def check_obj(self, ty, value, path, errs):
        if not isinstance(value, dict):
            errs.append('%s: expected object got %s' % (path, type(value).__name__))
            return
        # expand choice groups into alternative field lists
        variants = [[]]
        for fld in ty[1]:
            if fld[0] == 'choice':
                variants = [v + g for v in variants for g in fld[1]]
            else:
                variants = [v + [fld] for v in variants]
        best = None
        for fields in variants:
            e = []
            known = set()
            mapf = None
            for f in fields:
                if f[0] == 'map':
                    mapf = f
                    continue
                _, key, optional, fty = f
                known.add(key)
                if key not in value:
                    if not optional:
                        e.append('%s: missing key %s' % (path, key))
                    continue
                self.check(fty, value[key], path + '.' + key, e)
            for key in value:
                if key in known:
                    continue
                if mapf is not None:
                    self.check(mapf[2], value[key], path + '.' + key, e)
                else:
                    e.append('%s: unexpected key %s' % (path, key))
            if not e:
                return
            if best is None or len(e) < len(best):
                best = e
        errs.extend(best)

    def validate(self, type_name, value):
        errs = []
        self.check(('name', type_name), value, type_name, errs)
        return errs

    def validate_op(self, op, key, value):
        errs = []
        o = self.ops.get(op)
        if o is None:
            return ['no schema file for op ' + op]
        ty = o[key]
        if ty is None:
            return errs
        if ty == ('name', 'null'):
            if value is not None:
                errs.append('%s.%s: expected null' % (op, key))
            return errs
        self.check(ty, value, '%s.%s' % (op, key), errs)
        return errs


if __name__ == '__main__':
    s = Schemas()
    print('loaded %d files, %d types, %d ops' % (len(s.files), len(s.types), len(s.ops)))
