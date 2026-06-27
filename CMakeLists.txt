# ============================================================================
# LLVMObfuscator
# ============================================================================

cmake_minimum_required(VERSION 3.20)


if(NOT DEFINED AES_STUB_TARGET)
  set(AES_STUB_TARGET "${LLVM_HOST_TRIPLE}"
      CACHE STRING "Target triple used when compiling the AES stub")
endif()


if(TARGET clang)
  set(_AES_CLANG_EXE "$<TARGET_FILE:clang>")
  set(_AES_CLANG_DEP clang)
else()
  find_program(_AES_CLANG_EXE NAMES clang clang-21 clang-20 clang-19)
  if(NOT _AES_CLANG_EXE)
    message(FATAL_ERROR "aes stub: clang not found.")
  endif()
  set(_AES_CLANG_DEP "")
endif()


find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_subdirectory(aes_stub)


add_llvm_component_library(LLVMObfuscator
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


  ${AES_GENERATED_INC}

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms/Obfuscator
  DEPENDS
  intrinsics_gen

  LINK_COMPONENTS
  Analysis
  BitReader
  Core
  Linker
  Support
  TransformUtils
)


add_dependencies(LLVMObfuscator aes_stub_inc)


target_include_directories(LLVMObfuscator
  PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}/aes_stub"
)
