# LLVM API compatibility

`LLVMCompat.h` isolates the LLVM 23/24 branch-instruction split and explicit pass
policy from the LLVM 21--22 API. Existing `isRequired()` overrides are retained.
Instruction insertion uses iterators, supported by both APIs.

Build the plugin against each LLVM installation separately; plugin binaries are
not ABI-compatible across LLVM versions. Exercise both conditional and
unconditional branches through arithmetic, flattening and VM regression cases.
Run `python3 utils/test_llvm_compat.py --compiler clang++ --plugin /path/to/Obfuscator.so`
with each matching compiler/plugin pair. The focused regression checks runtime
results, IR verification, and actual transformations for substitution, flattening,
and virtualisation on a loop with conditional branches and a switch. The full
runtime runner remains available for broader coverage.
