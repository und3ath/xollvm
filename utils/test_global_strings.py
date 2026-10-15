#!/usr/bin/env python3
"""Native multi-TU startup, stable addresses, repeated reads, and all ciphers."""
import argparse
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--compiler', default='clang++')
p.add_argument('--plugin', required=True, type=Path)
a = p.parse_args()
plugin = str(a.plugin.resolve())
with tempfile.TemporaryDirectory(prefix='strenc-globals-') as d:
    root = Path(d)
    source = root/'table.cpp'
    other = root/'other.cpp'
    main = root/'main.cpp'
    header = root/'shared.h'
    header.write_text('''inline constexpr char shared[] = "shared ODR string";
inline const char* shared_ptr = shared;
''')
    template = '''#include "shared.h"
#ifndef ANN
#define ANN
#endif
namespace {
struct Row { const char* text; unsigned length; };
constexpr Row rows[] = {{"persistent global alpha", 23}, {"persistent global beta", 22}};
volatile unsigned index = 0;
}
extern "C" ANN __attribute__((noinline)) const char* NAME() { return rows[index % 2].text; }
extern "C" const char* SHARED() { return shared_ptr; }
'''
    main.write_text('''#include <cstdio>
extern "C" const char *first(), *second(), *shared_first(), *shared_second();
const char* saved = first();
unsigned early = 0;
__attribute__((constructor(101))) static void initialise() {
  early = static_cast<unsigned char>(first()[0]) + static_cast<unsigned char>(second()[0]);
}
int main() {
  unsigned sum = early;
  for (unsigned i = 0; i != 100; ++i) {
    if (first() != saved || shared_first() != shared_second()) return 1;
    for (const char* p : {first(), second(), shared_first()})
      for (; *p; ++p) sum = sum * 31U + static_cast<unsigned char>(*p);
  }
  std::printf("%u\\n", sum);
}
'''.replace('#include <cstdio>', '#include <cstdio>\n#include <initializer_list>'))
    expected = None
    for cipher in ('baseline', 'xor', 'chacha', 'aes'):
        ann = '' if cipher == 'baseline' else '__attribute__((annotate("obf: strenc(minlen=4,cipher='+cipher+')")))'
        source.write_text(template.replace('NAME', 'first').replace('SHARED', 'shared_first').replace('#define ANN', '#define ANN '+ann))
        other.write_text(template.replace('NAME', 'second').replace('SHARED', 'shared_second').replace('#define ANN', '#define ANN '+ann))
        exe = root/cipher
        command = [a.compiler, '-std=c++17', '-O2', str(source), str(other), str(main), '-o', str(exe)]
        if cipher != 'baseline':
            command += ['-Xclang', '-load', '-Xclang', plugin, '-fpass-plugin='+plugin,
                        '-mllvm', '-enable-obfuscation', '-mllvm', '-obf-verify']
        subprocess.run(command, check=True)
        result = subprocess.check_output([str(exe)], text=True, timeout=30)
        if expected is None:
            expected = result
        assert result == expected, (cipher, result, expected)
        if cipher != 'baseline':
            assert b'persistent global' not in exe.read_bytes(), cipher
        print('PASS', cipher, result.strip())
