#pragma once 
#include "llvm/Support/CommandLine.h"
#include <cstdint>
#include <string>

namespace llvm {

	extern llvm::cl::opt<uint64_t> ObfSeed;
	extern llvm::cl::opt<bool> ObfDeterministic;
	extern llvm::cl::opt<bool> ObfVerbose;


	extern llvm::cl::opt<bool> ObfSeedManifest;
	extern llvm::cl::opt<bool> ObfSeedManifestMD;
	extern llvm::cl::opt<bool> ObfVerify;


	// Global safety/cost caps (0=disabled)
	extern llvm::cl::opt<unsigned> ObfMaxFunctionInsts;
	extern llvm::cl::opt<unsigned> ObfMaxFunctionBlocks;
	extern llvm::cl::opt<unsigned> ObfMaxLoopDepth;

	// IR instruction budget (0=disabled)
	extern llvm::cl::opt<unsigned> ObfIRBudgetMultiplier;
	extern llvm::cl::opt<unsigned> ObfIRBudgetMax;


	// Debug info control
	extern llvm::cl::opt<bool> ObfStripDebug;
	extern llvm::cl::opt<bool> ObfPreserveDebugSynthetic;

	// Reporting / artifacts
	extern llvm::cl::opt<std::string> ObfReportDir;
	extern llvm::cl::opt<std::string> ObfReportJson;

} // namespace llvm