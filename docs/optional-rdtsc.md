# Optional rdtscStretch component

`-DOBF_ENABLE_RDTSC_STRETCH=OFF` excludes the x86 timing technique's source and
registry entry, removing its `IntrinsicsX86.h` dependency. Other techniques and
runtime eligibility checks are unchanged.

The default remains ON when LLVM includes the X86 target (or all targets).
It defaults OFF for target-limited LLVM installations without X86, including
Pillbox's WebAssembly-only LLVM header build. Explicit ON/OFF overrides that
default. ON requires the X86 intrinsics headers to be available.

Check both configurations with `CMAKE_EXPORT_COMPILE_COMMANDS=ON`: the OFF
configuration must not compile `Tech_RdtscStretch.cpp`, while ON must compile it.
The fork integration checks build both configurations against native LLVM and
exercise the target-limited configuration with Emscripten.
