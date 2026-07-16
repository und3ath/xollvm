#pragma once
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/CommandLine.h"
#include <cstdint>
#include <string>
#include <vector>

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


	// When true, the AntiOptimizationShield pass auto-enables itself with
	// default knobs for any function that has any obfuscation pass annotated
	// but no explicit `shield(...)` token. Default off — silent auto-enable
	// surprised users + consumed IR budget invisibly. Opt-in restores the
	// legacy behavior.
	extern llvm::cl::opt<bool> ObfShieldAuto;

	// When true, any pass skip recorded by the driver (eligibility bail-out,
	// budget exhaustion, function cap) is escalated to report_fatal_error.
	// Tests enable this to assert "nothing got silently skipped". Off by
	// default in production builds.
	extern llvm::cl::opt<bool> ObfNoSkips;

	// When true, the VM anti-debug gate emits a getenv("__OBF_DISABLE_ANTIDEBUG")
	// escape hatch. For CI/testing only. Default off — no kill-switch string in
	// shipped binaries.
	extern llvm::cl::opt<bool> ObfVMAllowAntiDebugBypass;

	// Reporting / artifacts
	extern llvm::cl::opt<std::string> ObfReportDir;
	extern llvm::cl::opt<std::string> ObfReportJson;

	// Pipeline ordering control
	// Comma-separated list of canonical pass short names that imposes an
	// explicit pre-order on those passes. Passes that are enabled but not
	// listed here are appended in topological order after the explicit list.
	// Empty = no explicit override.
	extern llvm::cl::opt<std::string> ObfPipelineOrdering;

	// When true, use the per-function annotation order verbatim instead of
	// running the topological sort. Ignored if -obf-pipeline-ordering is set.
	extern llvm::cl::opt<bool> ObfPipelineOrderingAnn;

	// Parse a raw comma-separated ordering string into a normalized list:
	// trim whitespace, lowercase, drop empty entries. Does not validate names.
	std::vector<std::string> ParsePipelineOrdering(llvm::StringRef raw);

	// =====================================================================
	// AntiDecompiler pass — user-extensible gadget pool + per-tech tuning
	// =====================================================================

	// Comma-separated list of JSON gadget files merged into the global pool.
	// Empty = no external gadgets (built-ins only).
	extern llvm::cl::opt<std::string> ADecGadgetsFile;

	// When true, suppress the compile-time built-in gadget tables and rely
	// entirely on user-supplied files / annotations.
	extern llvm::cl::opt<bool> ADecDisableBuiltinGadgets;

	// Override default inline-asm clobber list per architecture. When set,
	// these strings replace the backend's defaultClobbers() return value.
	// Comma-separated short register names; the parser formats to LLVM
	// "~{a},~{b}" form. Empty = use backend default.
	extern llvm::cl::opt<std::string> ADecClobbersX86;
	extern llvm::cl::opt<std::string> ADecClobbersAArch64;

	// Whitelist of technique short names ("asmGadgets,indirectBr,..."). When
	// non-empty, only the listed techniques run.
	extern llvm::cl::opt<std::string> ADecTechniques;

	// Gadget category filter ("anti-disasm,anti-trace,..."). When non-empty,
	// only gadgets whose category appears in this list are eligible.
	extern llvm::cl::opt<std::string> ADecCategories;

	// Per-technique budget percent split, e.g.
	//   -adec-budget-split="asm:30,ibr:20,decoy:20,call:15,alias:15,
	//                       loop:5,rdtsc:5,clndr:10"
	// Empty = use compiled-in defaults (matches Phase A behavior).
	extern llvm::cl::opt<std::string> ADecBudgetSplit;

	// IR-name prefix for anti-decompiler artifacts. Default "adec".
	// Setting a per-build random/secret value defeats simple signature
	// scans against the canonical "adec.*" pattern.
	extern llvm::cl::opt<std::string> ADecPrefix;

	// When true, replace hard-coded literal constants in the dead-decoy
	// payload (golden ratio multiplier, FP literals, etc.) with RNG-driven
	// values. Eliminates the static signature surface in decoy blocks.
	extern llvm::cl::opt<bool> ADecRandomizeConsts;

	// Helpers — pure string parsers, no validation against known names.
	std::vector<std::string> ParseAdecCsv(llvm::StringRef raw);
	std::string FormatClobberList(llvm::StringRef rawCsv);

} // namespace llvm