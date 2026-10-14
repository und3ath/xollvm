#!/usr/bin/env python3
"""Preserve Itanium-mangled Embind signature globals, not matching user text."""
import argparse
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--compiler', default='clang++')
p.add_argument('--plugin', required=True, type=Path)
a = p.parse_args()
plugin = str(a.plugin.resolve())
with tempfile.TemporaryDirectory(prefix='strenc-signatures-') as d:
    root = Path(d)
    for cipher in ('xor', 'chacha', 'aes'):
        source = root/'input.cpp'
        source.write_text('''namespace emscripten { namespace internal {
template<class... Args> struct Signature { static constexpr char types[] = "ppjpp"; };
}}
extern void consume(const char*);
__attribute__((annotate("obf: strenc(minlen=4,cipher=CIPHER)"), noinline))
void check() {
  consume(emscripten::internal::Signature<int, double>::types);
  consume(emscripten::internal::Signature<int, int, int, int, int, int, int>::types);
  consume("ppjpp");
}
'''.replace('CIPHER', cipher))
        output = root/(cipher+'.ll')
        subprocess.run([a.compiler, '-std=c++17', '-O1', '-S', '-emit-llvm', str(source), '-o', str(output),
            '-Xclang', '-load', '-Xclang', plugin, '-fpass-plugin='+plugin,
            '-mllvm', '-enable-obfuscation', '-mllvm', '-obf-verify'], check=True)
        lines = output.read_text().splitlines()
        plaintext = [line for line in lines if 'c"ppjpp' in line]
        assert len(plaintext) == 2, plaintext
        assert all(line.startswith('@_ZN10emscripten8internal9SignatureI') for line in plaintext), plaintext
        print('PASS', cipher)
