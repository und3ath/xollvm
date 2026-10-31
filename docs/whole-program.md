# Whole-program pass selection

Pass `-mllvm -obf-all='mba(prob=20,maxDepth=1,maxSites=12),substitution(loop=1,maxSites=12)'`
alongside `-mllvm -enable-obfuscation`. Load a plugin before LLVM option parsing
with `-Xclang -load -Xclang /path/to/Obfuscator.so` as well as
`-fpass-plugin=/path/to/Obfuscator.so`.

A non-empty specification replaces function annotations; it does not merge with
them. Omitting the option, or supplying an empty value, preserves annotation-only
behaviour. Function declarations are excluded. Existing eligibility, target,
and growth-budget checks still apply. This affects the current module: compile
all desired translation units with the same flags. Precompiled libraries are
not rewritten.

Regression: `python3 utils/test_whole_program.py --compiler clang++ --plugin /path/to/Obfuscator.so`.
