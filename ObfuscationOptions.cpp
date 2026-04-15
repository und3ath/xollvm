#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

using namespace llvm;

cl::opt<uint64_t> llvm::ObfSeed("obf-seed",
	cl::desc("Base seed for obfuscation (enables reproducible builds)."),
	cl::init(0));

cl::opt<bool> llvm::ObfDeterministic("obf-deterministic",
	cl::desc("If true and -obf-seed is not provided"),
	cl::init(false));

cl::opt<bool> llvm::ObfVerbose("obf-verbose",
	cl::desc("Verbose obfuscator logging."),
	cl::init(false));

cl::opt<bool> llvm::ObfSeedManifest(
	"obf-seed-manifest",
	llvm::cl::desc("Print per-function/per-pass seed manifest (debug)"),
	llvm::cl::init(false));

cl::opt<bool> llvm::ObfSeedManifestMD(
	"obf-seed-manifest-md",
	llvm::cl::desc("Also emit seed manifest into IR metadata"),
	llvm::cl::init(false));

cl::opt<bool> llvm::ObfVerify(
	"obf-verify",
	llvm::cl::desc("Verify IR after each obfuscation pass (fatal on failure)."),
	llvm::cl::init(false));

cl::opt<unsigned> llvm::ObfMaxFunctionInsts(
	"obf-max-function-insts",
	cl::desc("Skip obfuscation for functions with more than N instructions (0=off)"),
	cl::init(0));

cl::opt<unsigned> llvm::ObfMaxFunctionBlocks(
	"obf-max-function-blocks",
	cl::desc("Skip obfuscation for functions with more than N basic blocks (0=off)"),
	cl::init(0));

cl::opt<unsigned> llvm::ObfMaxLoopDepth(
	"obf-max-loop-depth",
	cl::desc("Skip obfuscation for functions with loop nesting deeper than N (0=off)"),
	cl::init(0));

cl::opt<unsigned> llvm::ObfIRBudgetMultiplier(
	"obf-ir-budget-multiplier",
	cl::desc("IR instruction budget: final_insts <= initial_insts * N (0=unlimited)"),
	cl::init(50));

cl::opt<unsigned> llvm::ObfIRBudgetMax(
	"obf-ir-budget-max",
	cl::desc("Absolute IR instruction ceiling per function (0=no hard cap)"),
	cl::init(0));

cl::opt<bool> llvm::ObfStripDebug(
	"obf-strip-debug",
	cl::desc("Strip debug info from obfuscated functions only."),
	cl::init(false));

cl::opt<bool> llvm::ObfPreserveDebugSynthetic(
	"obf-debug-synthetic",
	cl::desc("Assign synthetic line-0 debug locs to obfuscated instructions."),
	cl::init(true));

cl::opt<std::string> llvm::ObfReportDir(
	"obf-report-dir",
	cl::desc("Directory to emit obfuscation report artifacts (CFG DOT + default JSON). Empty=off"),
	cl::init(""));

cl::opt<std::string> llvm::ObfReportJson(
	"obf-report-json",
	cl::desc("Write JSON obfuscation map to this path ('-' for stdout). Empty=off"),
	cl::init(""));
