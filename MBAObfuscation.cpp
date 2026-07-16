#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/ValueTracking.h"

#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/IRBudget.h"
#include "llvm/Transforms/Obfuscator/MBAObfuscation.h"
#include "llvm/Transforms/Obfuscator/MBAUtils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/Utils.h"


#include <algorithm>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "mba"



namespace {

	struct MbaCtx;


	// ---- Per-pass-only helpers (remain in MBAObfuscation.cpp) ----
	[[nodiscard]] constexpr bool isTargetOpcode(unsigned opcode) {
		return opcode == Instruction::Add || opcode == Instruction::Sub ||
			opcode == Instruction::And || opcode == Instruction::Or ||
			opcode == Instruction::Xor;
	}

	static bool hasPoisonSensitiveFlags(const BinaryOperator& BO) {
		switch (BO.getOpcode()) {
		case Instruction::Add:
		case Instruction::Sub:
			return BO.hasNoSignedWrap() || BO.hasNoUnsignedWrap();
		default:return false;
		}
	}

	static bool shouldTransform(Instruction& I, int probability, llvm::obf::Rng& R) {
		auto* BO = dyn_cast<BinaryOperator>(&I);
		if (!BO)
			return false;

		if (!isTargetOpcode(BO->getOpcode()))
			return false;

		if (!BO->getType()->isIntegerTy())
			return false;
		unsigned BW = cast<IntegerType>(BO->getType())->getBitWidth();
		if (BW < 2)
			return false;

		if (hasPoisonSensitiveFlags(*BO))
			return false;

		return R.range(100) < (uint32_t)probability;
	}

	static void collectFromBlock(BasicBlock& BB, int probability, SmallVectorImpl<BinaryOperator*>& output, llvm::obf::Rng& R)
	{
		for (Instruction& I : BB) {
			if (shouldTransform(I, probability, R)) {
				output.push_back(cast<BinaryOperator>(&I));
			}
		}
	}

	static MBAConfig getMBAConfig(Function& F, FunctionAnalysisManager& AM) {
		const ObfuscationConfig obfConfig = getObfConfig(F, AM);
		auto passConfig = obfConfig.getPassConfig("mba");
		if (!passConfig.has_value()) {
			MBAConfig cfg; cfg.enable = false; return cfg;
		}
		MBAConfig cfg = MBAConfig::fromPassConfig(*passConfig);
		if (!cfg.validate()) {
			if (ObfVerbose)
				errs() << "MBA: Invalid configuration for function "
				<< F.getName() << ", disabling pass\n";
			cfg.enable = false;
		}
		return cfg;
	}

	// ---- Site analysis helpers (pass-specific, use FunctionObfContext) ----

	struct SiteInfo { unsigned BW = 0; bool SmallRange = false; };

	static SiteInfo analyzeSite(MbaCtx& PCtx, BinaryOperator& BO);
	static unsigned computeLocalDepth(const FunctionObfContext& Ctx,
		const BinaryOperator& BO, unsigned BaseDepth);
	static unsigned computeLocalProbability(const FunctionObfContext& Ctx,
		const BinaryOperator& BO, unsigned BaseProb);
	static bool runMBA(MbaCtx& PCtx, int probability, unsigned depth, unsigned maxSites);

	// ---- Helper: build MbaUtils::Options from MBAConfig ----

	static llvm::obf::MbaUtils::Options makeMbaOptions(const MBAConfig& Cfg) {
		llvm::obf::MbaUtils::Options Opts;
		Opts.LinearTermsMin = Cfg.linearTermsMin;
		Opts.LinearTermsMax = Cfg.linearTermsMax;
		Opts.EnableNonLinear = Cfg.enableNonLinear;
		Opts.NonLinearWeight = Cfg.nonLinearWeight;
		Opts.EnableLayered = Cfg.enableLayered;
		Opts.LayeredWindow = Cfg.layeredWindow;
		Opts.LayeredBudget = Cfg.layeredBudget;
		return Opts;
	}

	// ============================================================================
	// MbaCtx � per-invocation pass context
	// ============================================================================

	struct MbaCtx : llvm::obf::FuncPassCtx {
		MBAConfig Cfg;
		FunctionObfContext& FOC;

		llvm::obf::Rng SelectRng; // decisions: shouldTransform, local prob gating
		llvm::obf::Rng RecRng;    // recursion alt choice + recurse chance
		llvm::obf::Rng NoiseRng;
		// Factory: owns per-function noise slot + all transform implementations.
		// Constructed AFTER NoiseRng so the reference is stable.
		llvm::obf::MbaUtils MBA;

		MbaCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "mba"),
			Cfg(getMBAConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),
			SelectRng(R.fork("select")),
			RecRng(R.fork("recurse")),
			NoiseRng(R.fork("noise")),
			MBA(*F.getParent(), NoiseRng, "obf.mba.noise.i32", makeMbaOptions(Cfg)) {
			// Entropy anchor is pinned inside MbaUtils::ensureNoiseSlot on first use.

		}
	};




	// ============================================================================
	// Helper Functions
	// ============================================================================

	static SiteInfo analyzeSite(MbaCtx& PCtx, BinaryOperator& BO) {
		SiteInfo SI = {};
		if (!BO.getType()->isIntegerTy())
			return SI;
		SI.BW = cast<IntegerType>(BO.getType())->getBitWidth();

		// Quick small-range heuristic (context-aware):
		// If both operands are constants, treat as small only if both < 2^16.
		auto isSmallConst = [&](Value* V) -> bool {
			if (auto* CI = dyn_cast<ConstantInt>(V)) {
				APInt A = CI->getValue();
				if (A.getBitWidth() > 16)
					return A.ult(APInt(A.getBitWidth(), 1ull << 16));
				return true;

			}
			return false;
			};

		Value* X = BO.getOperand(0);
		Value* Y = BO.getOperand(1);
		if (isSmallConst(X) && isSmallConst(Y)) {
			SI.SmallRange = true;
			return SI;

		}

		// computeKnownBits-based heuristic (safe and cheap enough)
		const DataLayout& DL = PCtx.M.getDataLayout();


		auto isSmallByKnownBits = [&](Value* V) -> bool {
			if (!V || !V->getType()->isIntegerTy())
				return false;
			unsigned BW = cast<IntegerType>(V->getType())->getBitWidth();
			// Use the overload available on your LLVM: computeKnownBits(V, DL, ...)
			KnownBits KB = computeKnownBits(V, DL);
			APInt Max = KB.getMaxValue();
			if (BW <= 16) return true;
			return Max.ult(APInt(BW, 1ull << 16));
			};

		SI.SmallRange = isSmallByKnownBits(X) && isSmallByKnownBits(Y);
		return SI;

	}


	static unsigned computeLocalDepth(const FunctionObfContext& Ctx,
		const BinaryOperator& BO, unsigned BaseDepth) {

		unsigned D = BaseDepth;

		auto* BB = BO.getParent();
		auto It = Ctx.BlockIDs.find(BB);
		if (It != Ctx.BlockIDs.end() && It->second % 2 == 0)
			D++;

		if (!Ctx.EntropySources.empty())
			D++;

		return std::min(D, 5u);

	}


	static unsigned computeLocalProbability(const FunctionObfContext& Ctx,
		const BinaryOperator& BO, unsigned BaseProb) {
		unsigned P = BaseProb;

		auto* BB = BO.getParent();
		auto It = Ctx.BlockIDs.find(BB);

		// Structural diversity
		if (It != Ctx.BlockIDs.end() && It->second % 2 == 0)
			P += 5;

		// Entropy availability encourages MBA
		if (!Ctx.EntropySources.empty())
			P += 10;

		// Penalize very large functions
		if (Ctx.NumInsts > 500)
			P -= 10;

		return std::clamp(P, 0u, 100u);
	}




	// ============================================================================
	// Main Transformation Logic
	// ============================================================================

	static bool runMBA(MbaCtx& PCtx, int probability, unsigned depth, unsigned maxSites) {
		Function& F = PCtx.F;
		FunctionObfContext& Ctx = PCtx.FOC;

		// Budget-aware site cap: estimate ~15-40 insts per site depending on
		// depth.  This is the *initial* estimate; the live cap below tightens
		// it dynamically once we observe actual per-site growth.
		unsigned InstsPerSiteEst = 10 * (1 + depth);
		if (Ctx.BudgetRemaining != UINT_MAX) {
			unsigned budgetSites = Ctx.BudgetRemaining / std::max(1u, InstsPerSiteEst);
			budgetSites = std::max(1u, budgetSites);
			if (budgetSites < maxSites) {
				maxSites = budgetSites;
				if (ObfVerbose)
					errs() << "[mba] budget-throttled maxSites to " << maxSites << "\n";
			}
		}

		// Live mid-pass cap with observed-cost tracking.  The static
		// per-site estimate routinely undershoots (deep MBA + non-linear
		// addends + layered window can stack to 300+ insts/site).  Poll
		// before each site using the maximum *observed* delta so far —
		// guarantees we never start a site whose worst-case cost would
		// push us past the cap.
		unsigned BudgetCap = UINT_MAX;
		unsigned LastInsts = 0;
		unsigned MaxObservedDelta = InstsPerSiteEst;
		if (Ctx.BudgetRemaining != UINT_MAX) {
			LastInsts = llvm::obf::countInstructions(F);
			BudgetCap = (Ctx.BudgetRemaining > UINT_MAX - LastInsts)
				? UINT_MAX
				: LastInsts + Ctx.BudgetRemaining;
		}

		SmallVector<BinaryOperator*, 32> toTransform;

		// Collect candidates from all basic blocks
		for (BasicBlock& BB : F) {
			collectFromBlock(BB, probability, toTransform, PCtx.SelectRng);
		}

		bool Changed = false;
		unsigned SitesDone = 0;

		// Apply transformations (with budget)
		for (BinaryOperator* BO : toTransform) {
			if (SitesDone >= maxSites)
				break;
			if (BudgetCap != UINT_MAX) {
				unsigned cur = llvm::obf::countInstructions(F);
				if (cur + MaxObservedDelta >= BudgetCap) {
					if (ObfVerbose)
						errs() << "[mba] live budget reached at " << SitesDone
						<< " sites (cur=" << cur << " +next~" << MaxObservedDelta
						<< " >= " << BudgetCap << ")\n";
					break;
				}
				LastInsts = cur;
			}
			// Safety guards
			if (!BO->getType()->isIntegerTy())
				continue;

			if (isa<Constant>(BO->getOperand(0)) && isa<Constant>(BO->getOperand(1)))
				continue;

			IRBuilder<> B(BO);


			unsigned LocalDepth = computeLocalDepth(Ctx, *BO, depth);
			unsigned LocalProb = computeLocalProbability(Ctx, *BO, probability);

			if (PCtx.SelectRng.range(100) >= (uint32_t)LocalProb)
				continue;

			Value* NewV = PCtx.MBA.applyMBARecursive(B, BO, LocalDepth, PCtx.RecRng);


			if (!NewV || NewV == BO)
				continue;


			// --- Advanced MBA: context-aware selection ---
			SiteInfo SI = analyzeSite(PCtx, *BO);

			// Inflate to 10-20 terms by default.
			// If operands appear small-range, we bias toward deeper linear inflation and layered ops.
			unsigned InflateDepthHint = LocalDepth;
			if (SI.SmallRange)
				InflateDepthHint = std::min(5u, LocalDepth + 1);

			NewV = PCtx.MBA.inflateLinear(B, NewV, InflateDepthHint);

			// Nonlinear addends (mul/urem): increase SMT hardness.
			// Bias: more likely for wide-range values, less for small-range.
			if (PCtx.Cfg.enableNonLinear) {
				unsigned W = PCtx.Cfg.nonLinearWeight;
				if (SI.SmallRange && W > 10) W -= 10;
				if (!SI.SmallRange && W < 90) W += 10;
				if (PCtx.NoiseRng.range(100) < W)
					NewV = PCtx.MBA.addNonLinearZero(B, *BO, NewV);
				// High-degree and mixed-mode addends (degree 4/5 + bitwise/rotate mixing).
				if (PCtx.NoiseRng.range(100) < (W / 2 + 10))
					NewV = PCtx.MBA.addHighDegreeZero(B, *BO, NewV, InflateDepthHint);
				if (PCtx.NoiseRng.range(100) < (W / 2 + 10))
					NewV = PCtx.MBA.addMixedModeZero(B, *BO, NewV, InflateDepthHint);


			}

			// Layered MBA: rewrite some internal ops close to the anchor site
			// Expression chaining: re-inflate after nonlinear injection to break linear patterns.
			if (PCtx.Cfg.enableLayered) {
				if (auto* NI = dyn_cast<Instruction>(NewV))
					PCtx.MBA.applyLayeredWindow(NI, /*Skip=*/BO, /*DepthHint=*/LocalDepth, PCtx.RecRng);

			}


			AllocaInst* NSlot = PCtx.MBA.getOrCreateNoiseSlot(B);
			NewV = llvm::obf::xorWithRuntimeZero(B, NewV, NSlot, PCtx.NoiseRng,
				"mba.noise", /*Prob=*/15);

			BO->replaceAllUsesWith(NewV);
			BO->eraseFromParent();
			++SitesDone;
			Changed = true;

			// Track observed per-site cost so the predictive cap above
			// can tighten on subsequent iterations.
			if (BudgetCap != UINT_MAX) {
				unsigned after = llvm::obf::countInstructions(F);
				unsigned delta = after > LastInsts ? after - LastInsts : 0;
				if (delta > MaxObservedDelta)
					MaxObservedDelta = delta;
				LastInsts = after;
			}
		}

		return Changed;
	}


} // anonymous namespace

// ============================================================================
// Pass Implementation
// ============================================================================
PreservedAnalyses MBAPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	MbaCtx Ctx(F, AM);

	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();

	int prob = Ctx.Cfg.prob;
	unsigned depth = Ctx.Cfg.maxDepth;

	if (Ctx.FOC.NumBlocks > 20)
		depth++;

	if (Ctx.FOC.HasIndirectCalls)
		prob += 10;

	bool Changed = runMBA(Ctx, prob, depth, Ctx.Cfg.maxSites);

	if (!Changed)
		return PreservedAnalyses::all();

	PreservedAnalyses PA = PreservedAnalyses::none();
	PA.preserveSet<CFGAnalyses>();
	return PA;

}
