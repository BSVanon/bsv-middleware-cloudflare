#!/usr/bin/env bash
# Estate shapes from epoch's pre-push hook and bsv-stack-lean/tools/mirror_sync.sh.
# Report paths and line numbers only, never matched values.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - "${1:-origin/main}" <<'PY'
import re
import subprocess
import sys

patterns = [
    r'''(?:Bearer |[A-Za-z_]*TOKEN[A-Za-z_]*\s*[:=]\s*["']?)[A-Za-z0-9_-]{40}(?![A-Za-z0-9_-])''',
    r'\bgh[pousr]_[A-Za-z0-9]{36}\b',
    r'\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b',
    r'\bcio[A-Za-z0-9]{32}\b',
    r'\bnpm_[A-Za-z0-9]{36}\b',
    r'\bcfut_[A-Za-z0-9_-]{20,}\b',
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
    r'AKIA[0-9A-Z]{16}',
    r'xox[bp]-[0-9A-Za-z-]+',
    r'[0-9a-f]{64}:[0-9a-f]{64}',
    r'''api[_-]?key\s*[:=]\s*"[A-Za-z0-9_-]{20,}"''',
    r'Bearer [A-Za-z0-9_.-]{30,}',
]
shape = re.compile('|'.join(patterns))
failed = False

def scan(label, data):
    global failed
    for number, line in enumerate(data.decode('utf-8', errors='replace').splitlines(), 1):
        if shape.search(line):
            print(f'secret shape: {label}:{number}')
            failed = True

paths = subprocess.check_output(['git', 'ls-files', '-z']).split(b'\0')
for path in filter(None, paths):
    try:
        with open(path, 'rb') as source:
            scan(path.decode(), source.read())
    except FileNotFoundError:
        pass  # Deleted paths are still scanned in the diff below.
base = sys.argv[1]
subprocess.run(['git', 'rev-parse', '--verify', base], check=True, stdout=subprocess.DEVNULL)
# Include removed lines and every branch commit, plus staged and unstaged edits.
scan('branch diff', subprocess.check_output(['git', 'diff', '--no-ext-diff', '--no-textconv', '--unified=0', f'{base}...HEAD']))
scan('working diff', subprocess.check_output(['git', 'diff', '--no-ext-diff', '--no-textconv', '--unified=0', 'HEAD']))
if failed:
    sys.exit(1)
print('secrets scan: tracked tree and diff clean')
PY
