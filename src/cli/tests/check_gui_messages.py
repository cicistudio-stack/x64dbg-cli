#!/usr/bin/env python3
"""Static completeness check: every enumerator of GUIMSG_LIST (src/bridge/bridgemain.h) has a `case` in
src/cli/host_exports.cpp (design 10). Runtime behaviour is verified by the integration runs.

python src/cli/tests/check_gui_messages.py          exit 0 when every message is handled
python src/cli/tests/check_gui_messages.py --list   print every message with its status
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
HEADER = os.path.join(ROOT, 'src', 'bridge', 'bridgemain.h')
HOST = os.path.join(ROOT, 'src', 'cli', 'host_exports.cpp')


def main():
    with open(HEADER, encoding='utf-8', errors='replace') as f:
        text = f.read()
    start = text.index('#define GUIMSG_LIST(msg)')
    end = text.index('// clang-format on', start)
    block = text[start:end]
    msgs = re.findall(r'msg\((GUI_\w+)\s*,', block)
    with open(HOST, encoding='utf-8', errors='replace') as f:
        src = f.read()
    handled = set(re.findall(r'case\s+(GUI_\w+)\s*:', src))
    missing = [m for m in msgs if m not in handled]
    # other Gui enums whose values appear as nested `case` labels (selection and menu types)
    other = set()
    for name in ('GUISELECTIONTYPE', 'GUIMENUTYPE'):
        m = re.search(r'typedef enum\s*\{(.*?)\}\s*' + name, text, re.S)
        if m:
            other.update(re.findall(r'\b(GUI_\w+)\b', m.group(1)))
    unknown = sorted(h for h in handled if h not in msgs and h not in other)
    dup = sorted({m for m in msgs if msgs.count(m) > 1})
    if '--list' in sys.argv:
        for m in msgs:
            print('%-4s %s' % ('ok' if m in handled else 'MISS', m))
    print('%d messages in GUIMSG_LIST, %d handled in host_exports.cpp' % (len(msgs), len(msgs) - len(missing)))
    for m in missing:
        print('missing case: ' + m)
    for m in unknown:
        print('case for a message that is not in GUIMSG_LIST: ' + m)
    for m in dup:
        print('duplicate enumerator: ' + m)
    ok = bool(msgs) and not missing and not unknown and not dup
    print('gui message check: ' + ('ok' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
