#!/usr/bin/env python3
"""Section metadata must remain plaintext while ordinary strings are encrypted."""
import argparse
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--compiler', default='clang++')
p.add_argument('--plugin', required=True, type=Path)
a = p.parse_args()
plugin = str(a.plugin.resolve())
with tempfile.TemporaryDirectory(prefix='strenc-sections-') as d:
    root = Path(d)
    for cipher in ('xor', 'chacha', 'aes'):
        source = root/'input.cpp'
        source.write_text('''static const char assembly[] __attribute__((section("em_asm"), used)) = "metadata assembly payload";
static const char javascript[] __attribute__((section("em_js"), used)) = "metadata javascript payload";
static const char custom[] __attribute__((section("custom_metadata"), used)) = "metadata custom payload";
__attribute__((annotate("obf: strenc(minlen=4,cipher=CIPHER)"), noinline))
unsigned check(unsigned i) {
  return assembly[i % 24] + javascript[i % 26] + custom[i % 23] + "ordinary secret payload"[i % 23];
}
'''.replace('CIPHER', cipher))
        output = root/(cipher+'.ll')
        subprocess.run([a.compiler, '-O1', '-S', '-emit-llvm', str(source), '-o', str(output),
            '-Xclang', '-load', '-Xclang', plugin, '-fpass-plugin='+plugin,
            '-mllvm', '-enable-obfuscation', '-mllvm', '-obf-verify'], check=True)
        ir = output.read_text()
        for text in ('metadata assembly payload', 'metadata javascript payload', 'metadata custom payload'):
            assert text in ir, (cipher, text)
        assert 'ordinary secret payload' not in ir, cipher
        print('PASS', cipher)
