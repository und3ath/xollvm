# ============================================================================
# LLVMObfuscator  /  Obfuscator pass plugin
#
# Dual-mode build:
#   * In-tree     (LLVM_MAIN_SRC_DIR defined): builds the LLVMObfuscator static
#                 component that links into clang/opt. Registration flows
#                 through llvm/lib/Passes/PassRegistry.def. Behavior unchanged.
#   * Standalone  (configured on its own against an installed/exported LLVM):
#                 builds the loadable `Obfuscator` pass plugin. Registration
#                 flows through registration/PluginEntry.cpp (llvmGetPassPluginInfo,
#                 gated by OBF_BUILD_PLUGIN). Loadable-plugin support is
#                 Linux/macOS only -- Windows needs the host LLVM built with
#                 -DLLVM_EXPORT_SYMBOLS_FOR_PLUGINS=ON, so Windows stays in-tree.
# ============================================================================

cmake_minimum_required(VERSION 3.20)


# ---------------------------------------------------------------------------
# Build-mode detection
# ---------------------------------------------------------------------------
if(DEFINED LLVM_MAIN_SRC_DIR)
  set(OBF_IN_TREE ON)
else()
  set(OBF_IN_TREE OFF)
  project(ObfuscatorPlugin C CXX)
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


if(TARGET clang)
  set(_AES_CLANG_EXE "$<TARGET_FILE:clang>")
  set(_AES_CLANG_DEP clang)
else()
  find_program(_AES_CLANG_EXE NAMES clang clang-22 clang-21 clang-20 clang-19)
  if(NOT _AES_CLANG_EXE)
    message(FATAL_ERROR "aes stub: clang not found.")
  endif()
  set(_AES_CLANG_DEP "")
endif()


find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_subdirectory(aes_stub)


# ---------------------------------------------------------------------------
# Shared source list
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

  # Out-of-tree plugin entry point. In-tree it is compiled for validation only;
  # llvmGetPassPluginInfo() is gated behind OBF_BUILD_PLUGIN, so the in-tree
  # static component is unchanged. Standalone it is the live registration path.
  registration/PluginEntry.cpp
)


# ---------------------------------------------------------------------------
# Library / plugin target
# ---------------------------------------------------------------------------
set(OBF_LINK_COMPONENTS
  Analysis
  BitReader
  Core
  Linker
  Support
  TransformUtils
)

# ObfuscationConfig.cpp parses config using C++ exceptions (try/throw/catch,
# all contained within that TU). LLVM compiles -fno-exceptions by default,
# which MSVC tolerates but clang/gcc reject ("cannot use 'try' with exceptions
# disabled"). Opt this module into EH so it builds identically in-tree
# (Linux + Windows) and as the standalone plugin. AddLLVM applies the correct
# per-compiler flag (-fexceptions / MSVC default) for both add_llvm_* calls.
set(LLVM_REQUIRES_EH ON)

if(OBF_IN_TREE)
  add_llvm_component_library(LLVMObfuscator
    ${OBF_SOURCES}
    ${AES_GENERATED_INC}

    ADDITIONAL_HEADER_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/llvm/Transforms
    ${CMAKE_CURRENT_SOURCE_DIR}/include/llvm/Transforms/Obfuscator
    DEPENDS
    intrinsics_gen

    LINK_COMPONENTS
    ${OBF_LINK_COMPONENTS}
  )
  set(OBF_TARGET LLVMObfuscator)

  # As a submodule the obfuscator headers live in the module's own include/
  # tree (include/llvm/Transforms/Obfuscator/**), not in the LLVM include root.
  # Export that root PUBLICly so LLVMPasses -- which links LLVMObfuscator and
  # compiles PassBuilder.cpp / PassRegistry.def -- resolves
  # "llvm/Transforms/Obfuscator*.h" transitively without any edit to the LLVM
  # integration files.
  target_include_directories(${OBF_TARGET} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
  target_include_directories(${OBF_TARGET}
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/aes_stub")
else()
  # add_llvm_pass_plugin may create a non-plain target (object/interface
  # wrapper) depending on platform and LLVM_<name>_LINK_INTO_TOOLS, so inject
  # the plugin macro and include paths at directory scope BEFORE the target is
  # created rather than via target_* (which rejects non-compilable targets).
  add_compile_definitions(OBF_BUILD_PLUGIN)
  include_directories(
    # Repo-local headers: include/llvm/Transforms/Obfuscator/** (prefix kept).
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_BINARY_DIR}/aes_stub"
  )

  # NOTE: deliberately NO LINK_COMPONENTS here. A loadable plugin must resolve
  # LLVM symbols from the host (opt/clang) at dlopen time. Static-linking the
  # LLVM components into the .so gives it a second copy of LLVM's global state
  # (e.g. the CommandLine registry), which aborts at load with
  # "Option '...' registered more than once". The in-tree static component
  # above still needs LINK_COMPONENTS; the plugin does not.
  add_llvm_pass_plugin(Obfuscator
    ${OBF_SOURCES}
    ${AES_GENERATED_INC}
  )
  set(OBF_TARGET Obfuscator)
endif()


add_dependencies(${OBF_TARGET} aes_stub_inc)
