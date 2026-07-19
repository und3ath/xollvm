#include "llvm/ADT/APInt.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/IRBudget.h"
#include "llvm/Transforms/Obfuscator/ConstantEncryption.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"


#include <algorithm>
#include <climits>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "constenc"



namespace {

	static ConstEncConfig getConstEncConfig(Function& F, FunctionAnalysisManager& AM) {
		const ObfuscationConfig obfConfig = getObfConfig(F, AM);
		auto passConfig = obfConfig.getPassConfig("constenc");
		if (!passConfig.has_value()) {
			ConstEncConfig cfg; cfg.enable = false; return cfg;
		}
		ConstEncConfig cfg = ConstEncConfig::fromPassConfig(*passConfig);
		if (!cfg.validate()) {
			if (ObfVerbose)
				errs() << "ConstEnc: Invalid configuration for function "
				<< F.getName() << ", disabling pass\n";
			cfg.enable = false;
		}
		return cfg;
	}

	// ============================================================================
	// ConstEncCtx — per-invocation pass context
	// ============================================================================

	struct ConstEncCtx : llvm::obf::FuncPassCtx {
		ConstEncConfig Cfg;
		FunctionObfContext& FOC;

		llvm::obf::Rng SelectRng; // per-site apply-probability gate
		llvm::obf::Rng SaltRng;   // feeds OpaqueUtils' volatile anchor / mixing
		// Factory: owns per-function opaque-const anchor. Constructed AFTER
		// SaltRng so the reference stays stable (mirrors MbaCtx ordering).
		llvm::obf::OpaqueUtils OU;

		ConstEncCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "constenc"),
			Cfg(getConstEncConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),
			SelectRng(R.fork("select")),
			SaltRng(R.fork("salt")),
			OU(*F.getParent(), SaltRng, "obf.constenc.salt.i32", llvm::obf::OpaqueUtils::Options{}) {
		}
	};

	// ============================================================================
	// Site description — collected before any mutation, applied afterwards.
	// ============================================================================

	struct ConstEncSite {
		Instruction* I;
		unsigned OpIdx;
		Constant* C;
	};

	// ============================================================================
	// Materialization engine
	// ============================================================================

	// Builds a value equal to the low W bits of `Bits` (an APInt of bit-width W)
	// but opaque to the optimizer. Supports W in {1..32} and W==64 only; caller
	// must have already validated the width.
	static Value* materializeIntBits(IRBuilder<>& B, llvm::obf::OpaqueUtils& OU,
		const APInt& Bits, unsigned W) {
		if (W <= 32) {
			uint32_t Masked = (uint32_t)Bits.zextOrTrunc(32).getZExtValue();
			Value* V32 = OU.opaqueI32Const(B, Masked);
			if (W == 32)
				return V32;
			return B.CreateTrunc(V32, B.getIntNTy(W));
		}
		if (W == 64) {
			uint64_t U = Bits.getZExtValue();
			uint32_t Lo = (uint32_t)(U & 0xFFFFFFFFull);
			uint32_t Hi = (uint32_t)((U >> 32) & 0xFFFFFFFFull);
			Value* Lo32 = OU.opaqueI32Const(B, Lo);
			Value* Hi32 = OU.opaqueI32Const(B, Hi);
			Value* ZLo = B.CreateZExt(Lo32, B.getInt64Ty());
			Value* ZHi = B.CreateZExt(Hi32, B.getInt64Ty());
			return B.CreateOr(ZLo, B.CreateShl(ZHi, 32));
		}
		return nullptr;
	}

	// Returns a Value equal to C but opaque to the optimizer, or nullptr if C's
	// type/width isn't supported (caller must skip the site in that case).
	static Value* materializeConst(IRBuilder<>& B, llvm::obf::OpaqueUtils& OU, Constant* C) {
		if (auto* CI = dyn_cast<ConstantInt>(C)) {
			unsigned W = CI->getBitWidth();
			if (!(W >= 1 && W <= 32) && W != 64)
				return nullptr;
			return materializeIntBits(B, OU, CI->getValue(), W);
		}
		if (auto* CF = dyn_cast<ConstantFP>(C)) {
			Type* Ty = CF->getType();
			unsigned W;
			if (Ty->isFloatTy())
				W = 32;
			else if (Ty->isDoubleTy())
				W = 64;
			else
				return nullptr; // x86_fp80/half/etc. unsupported in v1

			APInt Bits = CF->getValueAPF().bitcastToAPInt();
			Value* IntV = materializeIntBits(B, OU, Bits, W);
			if (!IntV)
				return nullptr;
			return B.CreateBitCast(IntV, Ty);
		}
		return nullptr;
	}

	// ============================================================================
	// Site selection — skip-list enforcement
	// ============================================================================

	// Decides whether operand value `Op` is an eligible constant under Cfg.
	// Returns the Constant* to encode, or nullptr if ineligible.
	static Constant* considerOperand(Value* Op, const ConstEncConfig& Cfg) {
		if (auto* CI = dyn_cast<ConstantInt>(Op)) {
			if (!Cfg.encInt)
				return nullptr;
			unsigned W = CI->getBitWidth();
			// Only widths we can materialize: 1..32 and 64.
			if (!((W >= 1 && W <= 32) || W == 64))
				return nullptr;

			// Triviality: skip small-magnitude constants (0/1/booleans included).
			// abs() treats the APInt as signed; magnitude fits in 64 bits since
			// W<=64 here, so zext-to-64 + getZExtValue is safe.
			APInt AbsV = CI->getValue().abs();
			uint64_t AbsVal = AbsV.zextOrTrunc(64).getZExtValue();
			if (AbsVal < (uint64_t)Cfg.minAbs)
				return nullptr;

			return CI;
		}
		if (auto* CF = dyn_cast<ConstantFP>(Op)) {
			if (!Cfg.encFP)
				return nullptr;
			Type* Ty = CF->getType();
			if (!Ty->isFloatTy() && !Ty->isDoubleTy())
				return nullptr;
			return CF;
		}
		return nullptr;
	}

	// Collects eligible (Instruction*, opIdx, Constant*) sites from a single
	// instruction, enforcing the full skip-list. Appends to Sites; never
	// mutates I.
	static void collectSitesFromInstruction(Instruction& I, const ConstEncConfig& Cfg,
		SmallVectorImpl<ConstEncSite>& Sites) {
		// --- Whole-instruction skips ---
		// Switch: case values must remain constant (and the sole non-case
		// operand is the condition, not a constant we'd touch anyway).
		if (isa<SwitchInst>(I))
			return;
		// GEP: struct/array indices must stay constant.
		if (isa<GetElementPtrInst>(I))
			return;
		// PHI: materialization would need to go in the predecessor block;
		// not supported in v1.
		if (isa<PHINode>(I))
			return;
		// EH funclet instructions: operands are EH-structural, not safe to touch.
		if (isa<LandingPadInst>(I) || isa<CatchPadInst>(I) ||
			isa<CleanupPadInst>(I) || isa<CatchSwitchInst>(I))
			return;
		// Alloca: rewriting a constant array-size would turn a static alloca
		// into a dynamic (VLA) alloca — legal but off-intent and hostile to
		// stack layout / promotion. Structural, not a computation constant.
		if (isa<AllocaInst>(I))
			return;

		// --- Call/Invoke/CallBr: only touch argument operands, and only
		//     those without immarg; skip entirely for intrinsics (conservative). ---
		if (auto* CB = dyn_cast<CallBase>(&I)) {
			if (isa<IntrinsicInst>(&I))
				return;
			// Inline asm: operands under "i"/"n"/"I".. constraints must be
			// compile-time constants (constraints aren't ImmArg attrs, so the
			// per-arg check below won't catch them). Skip the whole call.
			if (CB->isInlineAsm())
				return;

			for (unsigned a = 0, e = CB->arg_size(); a != e; ++a) {
				if (CB->paramHasAttr(a, Attribute::ImmArg))
					continue;
				Value* ArgOp = CB->getArgOperand(a);
				Constant* C = considerOperand(ArgOp, Cfg);
				if (!C)
					continue;
				// Arg operands occupy operand indices [0, arg_size) on
				// CallBase, so `a` doubles as the operand index for setOperand.
				Sites.push_back(ConstEncSite{ &I, a, C });
			}
			return; // never touch the callee / bundle operands
		}

		// --- General instructions: scan all operands. ---
		for (unsigned opIdx = 0, e = I.getNumOperands(); opIdx != e; ++opIdx) {
			Value* Op = I.getOperand(opIdx);
			Constant* C = considerOperand(Op, Cfg);
			if (!C)
				continue;
			Sites.push_back(ConstEncSite{ &I, opIdx, C });
		}
	}

	// Deterministic traversal: collect every eligible site up front, before
	// any mutation, so applying one site can never invalidate or re-process
	// another (avoids iterator invalidation + reprocessing newly-inserted insts).
	static void collectSites(Function& F, const ConstEncConfig& Cfg,
		SmallVectorImpl<ConstEncSite>& Sites) {
		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				collectSitesFromInstruction(I, Cfg, Sites);
			}
		}
	}

	// ============================================================================
	// Main Transformation Logic
	// ============================================================================

	static bool runConstEnc(ConstEncCtx& PCtx) {
		Function& F = PCtx.F;
		FunctionObfContext& Ctx = PCtx.FOC;
		const ConstEncConfig& Cfg = PCtx.Cfg;

		SmallVector<ConstEncSite, 32> Sites;
		collectSites(F, Cfg, Sites);

		if (Sites.empty())
			return false;

		unsigned maxSites = Cfg.maxSites;

		// Budget-aware site cap. Each site is a small, bounded materialization
		// (a handful of insts for W<=32, roughly double for W==64) — simpler
		// and cheaper than MBA's recursive expansion, so a flat estimate is fine.
		unsigned InstsPerSiteEst = 6;
		if (Ctx.BudgetRemaining != UINT_MAX) {
			unsigned budgetSites = Ctx.BudgetRemaining / std::max(1u, InstsPerSiteEst);
			budgetSites = std::max(1u, budgetSites);
			if (budgetSites < maxSites) {
				maxSites = budgetSites;
				if (ObfVerbose)
					errs() << "[constenc] budget-throttled maxSites to " << maxSites << "\n";
			}
		}

		unsigned BudgetCap = UINT_MAX;
		if (Ctx.BudgetRemaining != UINT_MAX) {
			unsigned LastInsts = llvm::obf::countInstructions(F);
			BudgetCap = (Ctx.BudgetRemaining > UINT_MAX - LastInsts)
				? UINT_MAX
				: LastInsts + Ctx.BudgetRemaining;
		}

		bool Changed = false;
		unsigned SitesDone = 0;

		for (ConstEncSite& Site : Sites) {
			if (SitesDone >= maxSites)
				break;

			if (BudgetCap != UINT_MAX) {
				unsigned cur = llvm::obf::countInstructions(F);
				if (cur + InstsPerSiteEst >= BudgetCap) {
					if (ObfVerbose)
						errs() << "[constenc] live budget reached at " << SitesDone
						<< " sites\n";
					break;
				}
			}

			// Per-site probability gate (deterministic fork, consumed in
			// program order regardless of whether the site is later applied).
			if (PCtx.SelectRng.range(100) >= (uint32_t)Cfg.prob)
				continue;

			// Defensive re-check: the operand must still be the constant we
			// collected (sites on the same instruction are independent, but
			// this guards against any future change to the apply order).
			if (Site.I->getOperand(Site.OpIdx) != Site.C)
				continue;

			IRBuilder<> B(Site.I);
			Value* NV = materializeConst(B, PCtx.OU, Site.C);
			if (!NV)
				continue;

			// TODO(wrapMBA): optionally route NV through MbaUtils-style linear
			// wrapping for extra hardness (cfg.wrapMBA). Left unimplemented —
			// needs its own opaque-const-safe MBA entry point to stay correct;
			// not worth the correctness risk for v1.

			Site.I->setOperand(Site.OpIdx, NV);
			++SitesDone;
			Changed = true;
		}

		return Changed;
	}

} // anonymous namespace

// ============================================================================
// Pass Implementation
// ============================================================================
PreservedAnalyses ConstEncPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	ConstEncCtx Ctx(F, AM);

	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();

	bool Changed = runConstEnc(Ctx);

	if (!Changed)
		return PreservedAnalyses::all();

	PreservedAnalyses PA = PreservedAnalyses::none();
	PA.preserveSet<CFGAnalyses>();
	return PA;
}
