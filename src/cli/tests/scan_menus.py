#!/usr/bin/env python3
"""Rule M scan: lists the (class, label) pairs of the context menus / toolbars of the Qt GUI (src/gui/Src, without ThirdPartyLibs).

A label is the first tr("...") inside a statement that creates a QAction / QMenu or calls one of the make*Action / addAction helpers.
Usage: python src/cli/tests/scan_menus.py          prints the class counts
       python src/cli/tests/scan_menus.py json     prints {class: [labels]}
Standard library only.
"""
import collections
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
GUI = os.path.join(ROOT, 'src', 'gui', 'Src')
PAT_TR = re.compile(r'tr\(\s*"((?:[^"\\]|\\.)*)"')
STMT = re.compile(r'(?:QAction\s*\(|make\w*Action\s*\(|makeMenuAction\s*\(|addAction\s*\(|addMenu\s*\(|setupAction\s*\(|makeActionColor\s*\(|makeShortcutDescAction\s*\(|new\s+QMenu\s*\(|QMenu\s*\(|makeMenu\s*\()[^;]*?;', re.S)


def scan(root=GUI):
    res = collections.OrderedDict()
    for d in sorted(os.listdir(root)):
        p = os.path.join(root, d)
        if not os.path.isdir(p) or d == 'ThirdPartyLibs':
            continue
        for dp, _dn, fns in os.walk(p):
            if 'ThirdPartyLibs' in dp:
                continue
            for fn in sorted(fns):
                if not (fn.endswith('.cpp') or fn.endswith('.h')):
                    continue
                cls = os.path.splitext(fn)[0]
                txt = open(os.path.join(dp, fn), encoding='utf-8', errors='replace').read().replace('\r\n', '\n')
                labels = []
                for m in STMT.finditer(txt):
                    t = PAT_TR.search(m.group(0))
                    if t:
                        lab = t.group(1).replace('&', '')
                        if lab not in labels:
                            labels.append(lab)
                if labels:
                    res[cls] = labels
    return res


if __name__ == '__main__':
    r = scan()
    if len(sys.argv) > 1 and sys.argv[1] == 'json':
        print(json.dumps(r, indent=1))
    else:
        print('total %d classes %d' % (sum(len(v) for v in r.values()), len(r)))
        for c, v in r.items():
            print(c, len(v))
