//===-- PluginEntry.cpp - out-of-tree obfuscator plugin entry ---*- C++ -*-===//
//
// Provides llvmGetPassPluginInfo() so the obfuscator can be loaded as an
// out-of-tree LLVM pass plugin (`clang -fpass-plugin=` / `opt
// -load-pass-plugin=`).
//
// Registration flows through the canonical name table in ObfPasses.inc, the
// same table hand-mirrored by the in-tree PassRegistry.def entries. Authoring
// the names once here keeps the plugin and in-tree builds from drifting.
//
// Build modes:
//   * In-tree (LLVMObfuscator static component): OBF_BUILD_PLUGIN is NOT
//     defined. The plugin entry point is compiled out so the static library
//     exports no stray llvmGetPassPluginInfo; only registerObfuscatorPasses()
//     is compiled, purely to keep it validated against the real LLVM headers.
//     In-tree pass registration continues to run through PassRegistry.def, so
//     in-tree behavior is unchanged.
//   * Standalone plugin (Phase 2): the build defines OBF_BUILD_PLUGIN and the
//     entry point below is emitted and used.
//
//===----------------------------------------------------------------------===//

#include "llvm/Config/llvm-config.h" // LLVM_VERSION_MAJOR
#include "llvm/Passes/PassBuilder.h"
// LLVM 22 relocated the plugin API header from llvm/Passes/ to llvm/Plugins/.
// Select the correct path per LLVM version so the plugin builds on 21 and 22.
#if LLVM_VERSION_MAJOR >= 22
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Support/Compiler.h"

#include "llvm/Transforms/Obfuscator.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfDebug.h" // ObfDumpConfigPass (not in umbrella)

using namespace llvm;

// Canonical registration entry. Wires every name in ObfPasses.inc into the
// PassBuilder via the new-PM callback surface. Reused (later) by the in-tree
// PassBuilder hook so both builds share one registration path.
LLVM_ATTRIBUTE_UNUSED
static void registerObfuscatorPasses(PassBuilder &PB) {
  // Named module passes: -passes=obfuscation
  PB.registerPipelineParsingCallback(
      [](StringRef Name, ModulePassManager &MPM,
         ArrayRef<PassBuilder::PipelineElement>) {
#define OBF_MODULE_PASS(NAME, CREATE)                                          \
  if (Name == NAME) {                                                          \
    MPM.addPass(CREATE);                                                       \
    return true;                                                               \
  }
#include "ObfPasses.inc"
        return false;
      });

  // Named function passes: -passes=obfuscation-fn
  PB.registerPipelineParsingCallback(
      [](StringRef Name, FunctionPassManager &FPM,
         ArrayRef<PassBuilder::PipelineElement>) {
#define OBF_FUNCTION_PASS(NAME, CREATE)                                        \
  if (Name == NAME) {                                                          \
    FPM.addPass(CREATE);                                                       \
    return true;                                                               \
  }
#include "ObfPasses.inc"
        return false;
      });

  // Module analyses (queried by the module pass, e.g. ObfReportAnalysis).
  PB.registerAnalysisRegistrationCallback([](ModuleAnalysisManager &MAM) {
#define OBF_MODULE_ANALYSIS(NAME, CREATE) MAM.registerPass([] { return CREATE; });
#include "ObfPasses.inc"
  });

  // Function analyses (queried by the function driver, e.g.
  // FunctionObfContextAnalysis). Without these the driver asserts at run time.
  PB.registerAnalysisRegistrationCallback([](FunctionAnalysisManager &FAM) {
#define OBF_FUNCTION_ANALYSIS(NAME, CREATE) FAM.registerPass([] { return CREATE; });
#include "ObfPasses.inc"
  });
}

#ifdef OBF_BUILD_PLUGIN
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "Obfuscator", LLVM_VERSION_STRING,
          registerObfuscatorPasses};
}
#endif // OBF_BUILD_PLUGIN
