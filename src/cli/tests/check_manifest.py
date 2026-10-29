#!/usr/bin/env python3
"""Guards the untracked upstream trees and the additive-change rule (design AC-1).

python src/cli/tests/check_manifest.py --write   write .agents/tasks/cli/untracked-manifest.sha256
python src/cli/tests/check_manifest.py           verify the manifest and the git diff/status rules
python src/cli/tests/check_manifest.py --selftest-negative   a changed hash must fail (exit 1)
"""
import hashlib
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
MANIFEST = os.path.join(ROOT, '.agents', 'tasks', 'cli', 'untracked-manifest.sha256')
TREES = ['src/dbg/btparser', 'src/third_party/TitanEngine', 'src/third_party/GleeBug', 'deps']
ALLOWED_TRACKED = ['src/dbg/console.cpp', 'cmake.toml', 'CMakeLists.txt', 'src/tests/CMakeLists.txt']
ALLOWED_TRACKED_PREFIXES = ['src/cli/', 'src/tests/cli_target/', 'docs/']
ALLOWED_UNTRACKED_PREFIXES = ['.agents/', 'src/cli/', 'src/tests/cli_target/', 'docs/cli/'] + [t + '/' for t in TREES]


def collect():
    out = {}
    for tree in TREES:
        base = os.path.join(ROOT, tree)
        for dirpath, _dirs, files in os.walk(base):
            for name in files:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, ROOT).replace('\\', '/')
                h = hashlib.sha256()
                with open(full, 'rb') as f:
                    for chunk in iter(lambda: f.read(1 << 20), b''):
                        h.update(chunk)
                out[rel] = h.hexdigest()
    return out


def read_manifest(path):
    out = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if line:
                digest, rel = line.split('  ', 1)
                out[rel] = digest
    return out


def compare(expected, actual):
    errors = []
    for rel in sorted(set(expected) | set(actual)):
        if expected.get(rel) != actual.get(rel):
            errors.append('%s: %s' % (rel, 'missing' if rel not in actual else 'new' if rel not in expected else 'changed'))
    return errors


def git(*args):
    return subprocess.run(['git'] + list(args), cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace').stdout


def main():
    if '--write' in sys.argv:
        data = collect()
        with open(MANIFEST, 'w', encoding='utf-8', newline='\n') as f:
            for rel in sorted(data):
                f.write('%s  %s\n' % (data[rel], rel))
        print('wrote %d entries' % len(data))
        return 0
    if '--selftest-negative' in sys.argv:
        expected = read_manifest(MANIFEST)
        key = sorted(expected)[0]
        expected[key] = '0' * 64
        errors = compare(expected, collect())
        print('negative control: %d difference(s) found' % len(errors))
        return 1 if errors else 0
    errors = compare(read_manifest(MANIFEST), collect())
    for name in git('diff', '--name-only', 'HEAD').split('\n'):
        name = name.strip()
        if not name:
            continue
        if name in ALLOWED_TRACKED or any(name.startswith(p) for p in ALLOWED_TRACKED_PREFIXES):
            continue
        errors.append('tracked file differs from HEAD: ' + name)
    for line in git('status', '--porcelain').split('\n'):
        if not line.strip():
            continue
        path = line[3:].strip().strip('"').replace('\\', '/')
        if line.startswith('??') and not any((path + '/').startswith(p) or path.startswith(p) for p in ALLOWED_UNTRACKED_PREFIXES):
            errors.append('untracked path outside the allowed areas: ' + path)
    for e in errors:
        print('FAIL ' + e)
    print('manifest check: %s (%d problem(s))' % ('FAILED' if errors else 'ok', len(errors)))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
