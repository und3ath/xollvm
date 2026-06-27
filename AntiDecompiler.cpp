// ============================================================================
// AntiDecompiler.cpp — driver
//
// Walks the technique registry, computes per-technique budget shares,
// and invokes each technique against the current function. The actual
// IR mutations live in lib/Transforms/Obfuscator/ADec/*.
// ============================================================================

#include "llvm/Transforms/Obfuscator/AntiDecompiler.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include "llvm/Transforms/Obfuscator/ADec/ArchBackend.h"
#include "llvm/Transforms/Obfuscator/ADec/GadgetPool.h"
#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

#define DEBUG_TYPE "adec"

STATISTIC(ADecFunctions, "Functions processed by anti-decompiler");

using namespace llvm;

namespace llvm {
namespace obf {
namespace adec {

ADecCtx::ADecCtx(Function& F, FunctionAnalysisManager& AM,
                 const AntiDecompilerConfig& C, FunctionObfContext& Foc,
                 const GadgetPool* P, llvm::StringRef NamePrefix,
                 bool RandConsts)
	: FuncPassCtx(F, AM, "adec"),
	  Cfg(C),
	  FOC(Foc),
	  Opaque(M, R,
	         (NamePrefix.empty() ? llvm::StringRef("adec") : NamePrefix).str()
	             + ".opaque.salt.i32",
	         [&]() {
	             llvm::obf::OpaqueUtils::Options O;
	             O.EnableOpaqueConsts = true;
	             O.EnableOpaqueBools = true;
	             O.EnableHardPreds = true;
	             O.VolatileLoads = true;
	             O.PredStrength = std::min<unsigned>(C.strength, 3u);
	             return O;
	         }()),
	  SelectRng(R.fork("select")),
	  GadgetRng(R.fork("gadget")),
	  StackRng(R.fork("stack")),
	  DecoyRng(R.fork("decoy")),
	  CallRng(R.fork("call")),
	  AliasRng(R.fork("alias")),
	  ShuffleRng(R.fork("shuffle")) {
	llvm::Triple T(M.getTargetTriple());
	IsX86_64 = T.isX86() && T.isArch64Bit();
	IsAArch64 = T.isAArch64();
	Pool = P;
	Prefix = NamePrefix.empty() ? std::string("adec") : NamePrefix.str();
	RandomizeConsts = RandConsts;
}

} // namespace adec
} // namespace obf
} // namespace llvm

namespace {

using ADecCtx = llvm::obf::adec::ADecCtx;

// ============================================================================
// Eligibility
// ============================================================================
static bool isEligible(const FunctionObfContext& Ctx, raw_ostream* R) {
	if (Ctx.HasNaked) {
		if (R) *R << "naked function";
		return false;
	}
	if (Ctx.HasCallBr) {
		if (R) *R << "callbr present";
		return false;
	}
	if (Ctx.HasConvergentCalls) {
		if (R) *R << "convergent calls present";
		return false;
	}
	if (Ctx.NumBlocks < 2) {
		if (R) *R << "too few blocks (" << Ctx.NumBlocks << ")";
		return false;
	}
	return true;
}

// ============================================================================
// Config
// ============================================================================
static AntiDecompilerConfig getConfig(Function& F,
                                      FunctionAnalysisManager& AM) {
	const ObfuscationConfig& OC = llvm::getObfConfig(F, AM);
	auto PC = OC.getPassConfig("adec");
	if (!PC.has_value()) {
		AntiDecompilerConfig cfg;
		cfg.enable = false;
		return cfg;
	}
	AntiDecompilerConfig cfg = AntiDecompilerConfig::fromPassConfig(*PC);
	if (!cfg.validate()) {
		if (ObfVerbose)
			errs() << "[adec] Invalid config for " << F.getName()
			       << ", disabling\n";
		cfg.enable = false;
	}
	return cfg;
}

// ============================================================================
// Budget allocation
//
// Defaults mirror the original ADecImpl::run percentages so Phase A behavior
// is preserved when -adec-budget-split is unset:
//   asmGadgets      30%
//   indirectBr      20%
//   deadDecoy       20%
//   callTrampoline  15%
//   aliasConfusion  15%
//   stackPollution  ignores budget (always-on, fixed cost)
//
// Users can override via -adec-budget-split="asm:30,ibr:20,..." (short keys).
// ============================================================================
struct BudgetTable {
	unsigned asmPct      = 30;
	unsigned ibrPct      = 20;
	unsigned decoyPct    = 20;
	unsigned callPct     = 15;
	unsigned aliasPct    = 15;
	unsigned loopPct     = 5;   // Phase C — opt-in techs share leftover
	unsigned rdtscPct    = 5;
	unsigned clndrPct    = 10;
};

static BudgetTable parseBudgetSplit(llvm::StringRef Raw) {
	BudgetTable T;
	if (Raw.empty())
		return T;
	llvm::SmallVector<llvm::StringRef, 16> Parts;
	Raw.split(Parts, ',', /*MaxSplit=*/-1, /*KeepEmpty=*/false);
	for (auto& P : Parts) {
		auto KV = P.trim().split(':');
		llvm::StringRef K = KV.first.trim();
		llvm::StringRef V = KV.second.trim();
		unsigned N = 0;
		if (V.getAsInteger(10, N))
			llvm::report_fatal_error(
			    llvm::Twine("-adec-budget-split: '") + V +
			    "' is not an integer", /*gen_crash_diag=*/false);
		if (K == "asm")        T.asmPct   = N;
		else if (K == "ibr")   T.ibrPct   = N;
		else if (K == "decoy") T.decoyPct = N;
		else if (K == "call")  T.callPct  = N;
		else if (K == "alias") T.aliasPct = N;
		else if (K == "loop")  T.loopPct  = N;
		else if (K == "rdtsc") T.rdtscPct = N;
		else if (K == "clndr") T.clndrPct = N;
		else
			llvm::report_fatal_error(
			    llvm::Twine("-adec-budget-split: unknown key '") + K + "'",
			    /*gen_crash_diag=*/false);
	}
	return T;
}

static unsigned budgetFor(llvm::StringRef Name, unsigned Total,
                          const BudgetTable& T) {
	if (Name == "asmGadgets")     return std::max<unsigned>(1u, Total * T.asmPct   / 100);
	if (Name == "indirectBr")     return std::max<unsigned>(1u, Total * T.ibrPct   / 100);
	if (Name == "deadDecoy")      return std::max<unsigned>(1u, Total * T.decoyPct / 100);
	if (Name == "callTrampoline") return std::max<unsigned>(1u, Total * T.callPct  / 100);
	if (Name == "aliasConfusion") return std::max<unsigned>(1u, Total * T.aliasPct / 100);
	if (Name == "fakeLoop")       return std::max<unsigned>(1u, Total * T.loopPct  / 100);
	if (Name == "rdtscStretch")   return std::max<unsigned>(1u, Total * T.rdtscPct / 100);
	if (Name == "constLaunder")   return std::max<unsigned>(1u, Total * T.clndrPct / 100);
	if (Name == "stackPollution") return 0;
	return 0;
}

// ============================================================================
// Filter helpers
// ============================================================================
static bool techniqueAllowed(llvm::StringRef TechName,
                             llvm::ArrayRef<std::string> AnnotationList,
                             llvm::ArrayRef<std::string> CliList) {
	// Annotation wins when present; otherwise CLI; otherwise allow all.
	const auto& Eff = !AnnotationList.empty() ? AnnotationList : CliList;
	if (Eff.empty())
		return true;
	for (const auto& Name : Eff)
		if (TechName == Name)
			return true;
	return false;
}

} // namespace

// ============================================================================
// Pass entry point
// ============================================================================
PreservedAnalyses AntiDecompilerPass::run(Function& F,
                                          FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	AntiDecompilerConfig Cfg = getConfig(F, AM);
	if (!Cfg.enable)
		return PreservedAnalyses::all();

	FunctionObfContext& Foc = *AM.getResult<FunctionObfContextAnalysis>(F);

	{
		std::string R;
		raw_string_ostream OS(R);
		if (!isEligible(Foc, &OS)) {
			if (ObfVerbose)
				errs() << "[adec] Skipping " << F.getName()
				       << " (" << OS.str() << ")\n";
			return PreservedAnalyses::all();
		}
	}

	if (ObfVerbose)
		errs() << "[adec] Processing: " << F.getName()
		       << " prob=" << Cfg.prob
		       << " strength=" << Cfg.strength
		       << " maxSites=" << Cfg.maxSites << "\n";

	llvm::Triple T(F.getParent()->getTargetTriple());
	auto ArchRegistry = llvm::obf::adec::buildArchBackendRegistry();
	const auto* Backend = llvm::obf::adec::selectBackend(T, ArchRegistry);

	// Resolve category filter: annotation overrides CLI.
	auto CliCategories = llvm::ParseAdecCsv(std::string(ADecCategories));
	const auto& EffCategories =
	    !Cfg.categoriesAllowed.empty() ? Cfg.categoriesAllowed : CliCategories;

	auto CliGadgetFiles = llvm::ParseAdecCsv(std::string(ADecGadgetsFile));
	std::string ClobberOverride;
	if (Backend) {
		if (Backend->archName() == "x86_64")
			ClobberOverride = std::string(ADecClobbersX86);
		else if (Backend->archName() == "aarch64")
			ClobberOverride = std::string(ADecClobbersAArch64);
	}

	llvm::obf::adec::GadgetPool Pool(Backend, CliGadgetFiles,
	                                 ADecDisableBuiltinGadgets,
	                                 ClobberOverride,
	                                 Cfg.gadgetsFile,
	                                 Cfg.inlineAsm,
	                                 EffCategories);

	std::string PrefixStr = std::string(ADecPrefix);
	if (PrefixStr.empty())
		PrefixStr = "adec";

	ADecCtx Ctx(F, AM, Cfg, Foc, &Pool, PrefixStr, ADecRandomizeConsts);

	auto Registry = llvm::obf::adec::buildTechniqueRegistry();
	BudgetTable Split = parseBudgetSplit(std::string(ADecBudgetSplit));

	auto CliTechniques = llvm::ParseAdecCsv(std::string(ADecTechniques));

	bool Changed = false;
	unsigned TotalApplied = 0;
	const unsigned Total = Cfg.maxSites;

	for (auto& Tech : Registry) {
		if (!Tech->isEnabled(Cfg))
			continue;
		if (!Tech->supportsTarget(T))
			continue;
		if (!techniqueAllowed(Tech->name(), Cfg.techniquesAllowed,
		                      CliTechniques))
			continue;
		unsigned B = budgetFor(Tech->name(), Total, Split);
		unsigned N = Tech->run(Ctx, B);
		if (N > 0)
			Changed = true;
		TotalApplied += N;
	}

	// stackPollution is in the registry but reports 0 work; the original
	// driver always counted it as "Changed". Mirror that.
	Changed = true;

	if (ObfVerbose)
		errs() << "[adec] " << F.getName()
		       << ": applied " << TotalApplied << " transforms\n";

	++ADecFunctions;

	if (!Changed)
		return PreservedAnalyses::all();

	return PreservedAnalyses::none();
}
