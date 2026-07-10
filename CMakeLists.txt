# ============================================================================
# xollvm — Obfuscator pass, built two ways from one source, with NO edits to
# any LLVM file:
#
#   * Loadable plugin (standalone, configured against an installed/exported
#     LLVM): builds Obfuscator.so, loaded via clang -fpass-plugin= /
#     opt -load-pass-plugin=. Linux/macOS only.
#
#   * Static in-tree extension (configured as part of an LLVM build via
#     -DLLVM_EXTERNAL_PROJECTS=Obfuscator
#     -DLLVM_EXTERNAL_OBFUSCATOR_SOURCE_DIR=<this dir>
#     -DLLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON): compiled straight into clang/opt.
#     Works on Windows too. Registration flows through
#     getObfuscatorPluginInfo() via LLVM's generated HANDLE_EXTENSION.
#
# Both modes use add_llvm_pass_plugin(); LLVM decides module-vs-object from
# LLVM_OBFUSCATOR_LINK_INTO_TOOLS. There is no in-tree component library and no
# PassRegistry.def / PassBuilder.cpp glue anymore.
# ============================================================================

cmake_minimum_required(VERSION 3.20)


# ---------------------------------------------------------------------------
# Build-mode detection
#   In-LLVM-tree  : LLVM_MAIN_SRC_DIR is set (we were add_subdirectory'd by the
#                   LLVM build, e.g. via LLVM_EXTERNAL_PROJECTS). LLVM's CMake
#                   modules are already loaded.
#   Standalone    : configure on our own against an installed/exported LLVM.
# ---------------------------------------------------------------------------
if(NOT DEFINED LLVM_MAIN_SRC_DIR)
  project(xollvm C CXX)
  find_package(LLVM REQUIRED CONFIG)
  list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
  include(AddLLVM)
  include(HandleLLVMOptions)
  include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
  add_definitions(${LLVM_DEFINITIONS})
endif()


# ---------------------------------------------------------------------------
# AES stub prerequisites (both modes)
# ---------------------------------------------------------------------------
if(NOT DEFINED AES_STUB_TARGET)
  set(AES_STUB_TARGET "${LLVM_HOST_TRIPLE}"
      CACHE STRING "Target triple used when compiling the AES stub")
endif()

# Pick the clang used to compile the AES stub to bitcode.
#   * Component/loadable builds may use the in-tree clang target directly.
#   * A static extension (LINK_INTO_TOOLS) must NOT depend on the in-tree clang:
#     clang links LLVMExtensions -> Obfuscator -> (aes) -> clang would be a
#     dependency cycle. Use an external clang in that case.
if(TARGET clang AND NOT LLVM_OBFUSCATOR_LINK_INTO_TOOLS)
  set(_AES_CLANG_EXE "$<TARGET_FILE:clang>")
  set(_AES_CLANG_DEP clang)
else()
  find_program(_AES_CLANG_EXE NAMES clang clang-22 clang-21 clang-20 clang-19)
  if(NOT _AES_CLANG_EXE)
    message(FATAL_ERROR "aes stub: external clang not found (needed to break the "
                        "LINK_INTO_TOOLS dependency cycle).")
  endif()
  set(_AES_CLANG_DEP "")
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_subdirectory(aes_stub)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
set(OBF_SOURCES
  Utils.cpp
  OpaqueUtils.cpp
  ObfDebug.cpp
  ObfMetrics.cpp
  ObfReport.cpp
  ObfuscationPipeline.cpp
  Substitution.cpp
  BogusControlFlow.cpp
  SplitBasicBlock.cpp
  Flattening.cpp
  MBAUtils.cpp
  MBAObfuscation.cpp
  SemanticDiffusion.cpp
  StringEncryption.cpp
  VirtualCall.cpp
  AntiDecompiler.cpp
  ADec/ArchBackend.cpp
  ADec/Arch_X86_64.cpp
  ADec/Arch_AArch64.cpp
  ADec/GadgetPool.cpp
  ADec/Technique.cpp
  ADec/Tech_AsmGadgets.cpp
  ADec/Tech_IndirectBr.cpp
  ADec/Tech_DeadDecoy.cpp
  ADec/Tech_StackPollution.cpp
  ADec/Tech_CallTrampoline.cpp
  ADec/Tech_AliasConfusion.cpp
  ADec/Tech_FakeLoop.cpp
  ADec/Tech_RdtscStretch.cpp
  ADec/Tech_ConstLaunder.cpp
  AntiOptimizationShield.cpp
  VMPass.cpp
  VMPass_Emitter.cpp
  VMPass_Verifier.cpp
  VMPass_Impl.cpp
  EHUtils.cpp
  DebugInfoPreserver.cpp
  TargetCompat.cpp
  FunctionObfContextAnalysis.cpp
  ObfuscationAnnotationAnalysis.cpp
  ObfuscationOptions.cpp
  ObfuscationConfig.cpp

  # Registration entry point (getObfuscatorPluginInfo / llvmGetPassPluginInfo).
  registration/PluginEntry.cpp
)


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
# ObfuscationConfig.cpp uses C++ exceptions (try/throw/catch, contained within
# that TU). LLVM builds -fno-exceptions by default (MSVC tolerates, clang/gcc
# reject); opt this module into EH. AddLLVM applies the right per-compiler flag.
set(LLVM_REQUIRES_EH ON)

# Directory-scope includes: the module's own headers (include/llvm/Transforms/
# Obfuscator/** — prefix preserved) and the generated AES bitcode header. Set
# before the target so they apply whether add_llvm_pass_plugin builds a module
# (.so) or an object library (static extension).
include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_BINARY_DIR}/aes_stub"
)

# intrinsics_gen only exists inside an LLVM build tree.
if(TARGET intrinsics_gen)
  set(_OBF_DEPENDS DEPENDS intrinsics_gen)
else()
  set(_OBF_DEPENDS "")
endif()

# One call, both modes. NO LINK_COMPONENTS on purpose: a loadable plugin must
# resolve LLVM symbols from the host at load, and a static extension resolves
# them from the tool it is linked into -- static-linking LLVM here would give a
# second copy of LLVM global state (e.g. the CommandLine registry) and abort at
# load ("Option '...' registered more than once").
add_llvm_pass_plugin(Obfuscator
  ${OBF_SOURCES}
  ${AES_GENERATED_INC}
  ${_OBF_DEPENDS}
)

# The AES stub .inc must be generated before any obfuscator source that
# includes it is compiled. Under LINK_INTO_TOOLS add_llvm_pass_plugin compiles
# into obj.Obfuscator (not Obfuscator), so depend on both targets.
add_dependencies(Obfuscator aes_stub_inc)
if(TARGET obj.Obfuscator)
  add_dependencies(obj.Obfuscator aes_stub_inc)
endif()
