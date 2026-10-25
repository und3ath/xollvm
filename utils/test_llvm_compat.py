#!/usr/bin/env python3
"""Exercise conditional/unconditional branch handling with a matching native plugin."""
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
with tempfile.TemporaryDirectory(prefix='llvm-compat-') as d:
    root = Path(d)
    source = root/'input.cpp'
    expected = None
    for name, passes in [('baseline', ''), ('substitution', 'substitution(loop=1)'),
                         ('flattening', 'flattening(minBlocks=2)'),
                         ('vm', 'vm(minBlocks=1,antiDebug=0)')]:
        annotation = '' if not passes else '__attribute__((annotate("obf: '+passes+'")))'
        source.write_text('''#include <cstdio>
ANNOTATION __attribute__((noinline)) unsigned compute(unsigned x) {
  unsigned sum = 0;
  for (unsigned i = 0; i < (x & 15U); ++i) {
    if ((x ^ i) & 1U) sum += x * (i + 3U);
    else sum ^= (x >> (i % 7U)) + 19U;
    switch (i % 3U) {
      case 0: sum ^= 0xA5A5U; break;
      case 1: sum += 17U; break;
      default: sum = (sum << 3U) ^ (sum >> 2U);
    }
  }
  return sum;
}
int main() {
  unsigned sum = 0;
  for (unsigned i = 0; i != 200; ++i) sum = sum * 31U + compute(i);
  std::printf("%u\\n", sum);
}
'''.replace('ANNOTATION', annotation))
        exe = root/name
        report = root/(name+'.json')
        command = [a.compiler, '-O1', str(source), '-o', str(exe)]
        if passes:
            command += ['-Xclang', '-load', '-Xclang', plugin, '-fpass-plugin='+plugin,
                        '-mllvm', '-enable-obfuscation', '-mllvm', '-obf-verify',
                        '-mllvm', '-obf-deterministic', '-mllvm', '-obf-seed=1',
                        '-mllvm', '-obf-report-json='+str(report)]
        subprocess.run(command, check=True, timeout=120)
        result = subprocess.check_output([str(exe)], text=True, timeout=30)
        if expected is None:
            expected = result
        assert result == expected, (name, result, expected)
        if passes:
            functions = json.loads(report.read_text())['functions']
            assert any(p.get('id') == name and p.get('changed') for f in functions for p in f.get('passes', [])), functions
        print('PASS', name, result.strip())
