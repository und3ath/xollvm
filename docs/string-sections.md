# Preserve explicitly sectioned strings

String encryption leaves globals with an explicit section unchanged. Linkers
and tooling can consume those bytes before runtime decryption is possible;
Emscripten's `em_asm` and `em_js` are examples. Explicit placement may also impose
storage constraints incompatible with replacing or modifying the global.

This deliberately conservative rule also excludes ordinary strings deliberately
placed in custom sections. Unsectioned application strings remain eligible.

Run `python3 utils/test_string_sections.py --compiler clang++ --plugin /path/to/Obfuscator.so`
to check metadata preservation and continued encryption for all three ciphers.
