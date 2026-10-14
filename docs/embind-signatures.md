# Embind signature metadata

Emscripten's `internal::Signature<...>` static members describe the calling ABI
used while bindings are registered. String-like storage does not make them
application text: changing their contents/lifetime breaks function registration,
particularly WASM64 pointer conversions.

The exclusion uses the Itanium-mangled template-name prefix emitted by the
Emscripten Clang toolchain. It is independent of the particular signature text,
so matching application strings remain encryptable. It covers all template
instantiations, rather than listing known signature contents. This is an
Emscripten-specific compatibility rule, not a generic mangling parser.

Run `python3 utils/test_embind_signatures.py --compiler clang++ --plugin /path/to/Obfuscator.so`
for an isolated IR regression using the same template symbol names. Actual
WASM64 Embind callbacks are also exercised by the integration probe.
