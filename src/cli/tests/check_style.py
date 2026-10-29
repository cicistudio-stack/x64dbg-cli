#!/usr/bin/env python3
"""Style checks for src/cli and src/tests/cli_target (.editorconfig: CRLF, spaces, no trailing whitespace).

python src/cli/tests/check_style.py          check
python src/cli/tests/check_style.py --fix    convert LF to CRLF and strip trailing whitespace
Allman braces are checked loosely: control statements, namespaces, types and function definitions must not
end with an opening brace.
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
AREAS = ['src/cli', 'src/tests/cli_target']
EXTS = ('.cpp', '.h', '.py')
BRACE = re.compile(r'^((if|for|while|switch|else|try|catch|do|struct|class|namespace|enum)\b.*|[\w:<>*&~ ]+\([^;{}]*\)( const)?)\s*\{$')


def files():
    for area in AREAS:
        for dirpath, dirs, names in os.walk(os.path.join(ROOT, area)):
            dirs[:] = [d for d in dirs if d != '__pycache__']
            for n in names:
                if n.endswith(EXTS):
                    yield os.path.join(dirpath, n)


def main():
    fix = '--fix' in sys.argv
    problems = 0
    for path in files():
        with open(path, 'rb') as f:
            raw = f.read()
        text = raw.decode('utf-8')
        lines = text.replace('\r\n', '\n').split('\n')
        rel = os.path.relpath(path, ROOT)
        fixed = [l.rstrip(' \t') for l in lines]
        new = '\r\n'.join(fixed).encode('utf-8')
        if fix:
            if new != raw:
                with open(path, 'wb') as f:
                    f.write(new)
            continue
        if b'\r\n' not in raw or re.search(rb'(?<!\r)\n', raw):
            print('%s: not CRLF' % rel)
            problems += 1
        if b'\t' in raw and path.endswith(('.cpp', '.h')):
            print('%s: contains tabs' % rel)
            problems += 1
        for i, l in enumerate(lines, 1):
            if l != l.rstrip(' \t'):
                print('%s:%d: trailing whitespace' % (rel, i))
                problems += 1
            if path.endswith(('.cpp', '.h')) and BRACE.match(l.strip()):
                print('%s:%d: opening brace must be on its own line (Allman)' % (rel, i))
                problems += 1
    if fix:
        print('fixed')
        return 0
    print('style check: %s (%d problem(s))' % ('FAILED' if problems else 'ok', problems))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
