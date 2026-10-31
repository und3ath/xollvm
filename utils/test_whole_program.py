#!/usr/bin/env python3
"""Check global selection, annotation precedence, and unchanged default behaviour."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--compiler', default='clang++')
p.add_argument('--plugin', required=True, type=Path)
a = p.parse_args()
plugin = str(a.plugin.resolve())
with tempfile.TemporaryDirectory(prefix='obf-all-') as d:
    root = Path(d)
    source = root/'input.cpp'
    source.write_text('''extern "C" {
__attribute__((noinline)) unsigned plain(unsigned x) { return (x + 13U) ^ (x * 17U); }
__attribute__((noinline, annotate("obf: substitution(loop=1)")))
unsigned annotated(unsigned x) { return (x + 19U) ^ (x * 23U); }
}''')
    for mode, flags in [('annotations', []), ('empty', ['-mllvm', '-obf-all=']),
                        ('global', ['-mllvm', '-obf-all=mba(prob=100,maxDepth=1,maxSites=12)'])]:
        report = root/(mode + '.json')
        subprocess.run([a.compiler, '-O1', '-c', str(source), '-o', str(root/(mode+'.o')),
            '-Xclang', '-load', '-Xclang', plugin, '-fpass-plugin='+plugin,
            '-mllvm', '-enable-obfuscation', '-mllvm', '-obf-deterministic',
            '-mllvm', '-obf-seed=1', '-mllvm', '-obf-verify',
            '-mllvm', '-obf-report-json='+str(report), *flags], check=True)
        functions = json.loads(report.read_text())['functions']
        ran = {f['name']: [p for p in f.get('passes', []) if p.get('status') == 'ran'] for f in functions}
        assert ran.get('annotated'), (mode, functions)
        assert bool(ran.get('plain')) == (mode == 'global'), (mode, functions)
        if mode == 'global':
            assert 'substitution' not in json.dumps(functions), functions
        print('PASS', mode)
