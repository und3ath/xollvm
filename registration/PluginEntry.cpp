//===-- PluginEntry.cpp - out-of-tree obfuscator plugin entry ---*- C++ -*-===//
//
// Single registration entry point for the obfuscator, driving both build
// modes from one source (no edits to any LLVM file):
//
//   * Loadable plugin (add_llvm_pass_plugin MODULE): built as Obfuscator.so and
//     loaded via `clang -fpass-plugin=` / `opt -load-pass-plugin=`. Here
//     LLVM_OBFUSCATOR_LINK_INTO_TOOLS is NOT defined, so llvmGetPassPluginInfo()
//     is emitted as the loadable entry. Linux/macOS only.
//
//   * Static in-tree extension (add_llvm_pass_plugin with
//     LLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON, wired via LLVM_EXTERNAL_PROJECTS):
//     compiled into clang/opt. LLVM calls getObfuscatorPluginInfo() at startup
//     through the generated HANDLE_EXTENSION(Obfuscator). Works on Windows too.
//     LLVM defines LLVM_OBFUSCATOR_LINK_INTO_TOOLS, so llvmGetPassPluginInfo()
//     is compiled out (the tool must not export a second copy).
//
// Registration itself flows through the canonical name table in ObfPasses.inc.
// This mirrors the LLVM `Bye` example pattern.
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

// Canonical registration. Wires every name in ObfPasses.inc into the
// PassBuilder via the new-PM callback surface. Shared by both build modes.
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

// Extension entry point. LLVM's static-extension machinery declares and calls
// `getObfuscatorPluginInfo()` (via HANDLE_EXTENSION(Obfuscator)). Always
// emitted; also reused by the loadable entry below. Not extern "C" -- the
// generated declaration is a plain C++ symbol, matching the Bye example.
llvm::PassPluginLibraryInfo getObfuscatorPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "Obfuscator", LLVM_VERSION_STRING,
          registerObfuscatorPasses};
}

// Loadable-plugin entry, emitted only when NOT statically linked into tools
// (so clang/opt don't end up with two definitions).
#ifndef LLVM_OBFUSCATOR_LINK_INTO_TOOLS
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getObfuscatorPluginInfo();
}
#endif // LLVM_OBFUSCATOR_LINK_INTO_TOOLS
