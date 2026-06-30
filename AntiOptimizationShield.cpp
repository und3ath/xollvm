// ============================================================================
// AntiOptimizationShield.cpp — Post-obfuscation hardening pass
//
// Runs as the last function pass in the obfuscation pipeline (before adec)
// to protect obfuscation patterns from being undone by later optimization.
//
// Techniques:
//   1. Volatile barrier injection on fragile intermediaries
//   2. Opaque identity replacement for trivial patterns
//   3. Anti-SCCP barriers for constant-looking runtime values
//   4. Dead-store protection (volatilize state stores)
//   5. CFG anti-simplification (opaque-predicate edge guards)
//   6. !obf.shield metadata annotation
//
// ============================================================================

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/AntiOptimizationShield.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/Utils.h"

using namespace llvm;

#define DEBUG_TYPE "anti-opt-shield"

STATISTIC(ShieldVolatileBarriers, "Volatile barriers injected");
STATISTIC(ShieldOpaqueIdentities, "Opaque identity replacements");
STATISTIC(ShieldDeadStoreProtect, "Stores volatilized for DSE protection");
STATISTIC(ShieldCFGGuards, "CFG anti-simplification guards inserted");
STATISTIC(ShieldFunctionsProcessed, "Functions processed by shield");

namespace {

	// ============================================================================
	// Shield configuration resolver.
	//
	// Parsing of `shield(...)` params is owned by llvm::ShieldConfig::fromPassConfig
	// (ObfuscationConfig.cpp). This helper layers the auto-enable heuristic on top:
	// when the function has obfuscation passes annotated but no explicit `shield`
	// token, default-construct a ShieldConfig and enable it.
	// ============================================================================
	static llvm::ShieldConfig buildShieldConfig(Function& F, FunctionAnalysisManager& AM) {
		const auto& Cache = getObfCache(F, AM);
		const auto& Cfg = Cache.getConfig(F);

		auto shieldPC = Cfg.getPassConfig("shield");
		if (shieldPC.has_value())
			return llvm::ShieldConfig::fromPassConfig(*shieldPC);

		// Auto-enable: opt-in via -obf-shield-auto. Default off — silently
		// adding shield + budget on every annotated function was surprising.
		llvm::ShieldConfig SC;
		if (llvm::ObfShieldAuto)
			SC.enable = !Cfg.passes.empty();
		return SC;
	}

	// ============================================================================
	// Context
	// ============================================================================
	struct ShieldCtx : llvm::obf::FuncPassCtx {
		llvm::ShieldConfig Cfg;
		FunctionObfContext& FOC;
		llvm::obf::Rng SelectRng;
		llvm::obf::Rng NoiseRng;
		llvm::obf::OpaqueUtils Opaque;
		unsigned SitesDone = 0;

		ShieldCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "shield"),
			Cfg(buildShieldConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),
			SelectRng(R.fork("select")), NoiseRng(R.fork("noise")),
			Opaque(M, NoiseRng, "shield.opaque.salt.i32",
				[&]() {
					llvm::obf::OpaqueUtils::Options O;
					O.EnableOpaqueConsts = true;
					O.EnableOpaqueBools = true;
					O.EnableHardPreds = true;
					O.VolatileLoads = true;
					O.PredStrength = 1;
					return O;
				}()) {
		}

		bool budgetOk() const { return SitesDone < Cfg.maxSites; }
	};

	// ============================================================================
	// Helper: check if an instruction name matches obfuscation artifacts
	// ============================================================================
	static bool isObfArtifactName(StringRef Name) {
		// Match prefixes used by our passes
		static constexpr const char* Prefixes[] = {
			"fla.",   "bcf.",  "mba.",   "sub.",    "sdiff.",
			"vcall.", "adec.", "strenc", "shield.", "obf." };
		for (const char* P : Prefixes)
			if (Name.starts_with(P))
				return true;
		return false;
	}

	// ============================================================================
	// Helper: check if a store targets an obfuscation state variable
	// ============================================================================
	static bool isObfStateStore(StoreInst* SI) {
		Value* Ptr = SI->getPointerOperand();
		if (auto* AI = dyn_cast<AllocaInst>(Ptr))
			return isObfArtifactName(AI->getName());
		if (auto* GV = dyn_cast<GlobalVariable>(Ptr))
			return isObfArtifactName(GV->getName());
		return false;
	}

	// ============================================================================
	// Helper: attach !obf.shield metadata
	// ============================================================================
	static void tagShielded(Instruction* I) {
		LLVMContext& C = I->getContext();
		MDNode* Tag = MDNode::get(C, MDString::get(C, "shielded"));
		I->setMetadata("obf.shield", Tag);
	}

	// ============================================================================
	// Technique 1: Volatile barrier injection
	//
	// Find "fragile" values: results of icmp, select, and/or/xor that feed
	// into branch conditions or state stores. Replace them with
	// store→volatile_load round-trips.
	// ============================================================================
	static unsigned injectVolatileBarriers(ShieldCtx& Ctx) {
		if (!Ctx.Cfg.volatileBarriers)
			return 0;

		Function& F = Ctx.F;
		unsigned Count = 0;

		// Collect fragile instructions: icmp/select feeding terminators
		SmallVector<Instruction*, 32> Fragile;
		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				if (!Ctx.budgetOk())
					break;

				// Skip already-volatile loads
				if (auto* LI = dyn_cast<LoadInst>(&I))
					if (LI->isVolatile())
						continue;

				// Target: icmp results that feed branch conditions
				if (auto* Cmp = dyn_cast<ICmpInst>(&I)) {
					bool FeedsBranch = false;
					for (User* U : Cmp->users()) {
						if (isa<BranchInst>(U) || isa<SwitchInst>(U) || isa<SelectInst>(U))
							FeedsBranch = true;
					}
					// Only barrier icmps with obfuscation-related operands
					if (FeedsBranch && isObfArtifactName(Cmp->getName()))
						Fragile.push_back(Cmp);
				}
			}
		}

		// For each fragile value, insert a volatile barrier
		for (Instruction* I : Fragile) {
			if (!Ctx.budgetOk())
				break;

			// Create a volatile round-trip: alloca → store → volatile load
			IRBuilder<> B(I->getNextNode());
			Type* Ty = I->getType();

			// For i1 values, widen to i8 for the volatile store/load
			Type* StoreTy = Ty->isIntegerTy(1) ? Type::getInt8Ty(F.getContext()) : Ty;

			AllocaInst* Slot = new AllocaInst(
				StoreTy, F.getAddressSpace(),
				nullptr, Align(4), "shield.barrier",
				F.getEntryBlock().getFirstNonPHIOrDbg());

			Value* ToStore = I;
			if (Ty->isIntegerTy(1))
				ToStore = B.CreateZExt(I, StoreTy, "shield.widen");

			B.CreateStore(ToStore, Slot);

			LoadInst* Reload = B.CreateLoad(StoreTy, Slot, "shield.reload");
			Reload->setVolatile(true);

			Value* Result = Reload;
			if (Ty->isIntegerTy(1))
				Result = B.CreateTrunc(Reload, Ty, "shield.narrow");

			// Replace all uses of the original (except the store we just created)
			I->replaceUsesWithIf(Result, [&](Use& U) {
				Instruction* User = dyn_cast<Instruction>(U.getUser());
				if (!User)
					return false;
				// Don't replace the use in the store we just created
				if (User == cast<Instruction>(ToStore) && ToStore != I)
					return false;
				if (auto* SI = dyn_cast<StoreInst>(User))
					if (SI->getPointerOperand() == Slot)
						return false;
				return true;
				});

			tagShielded(Reload);
			++Count;
			++Ctx.SitesDone;
			++ShieldVolatileBarriers;
		}

		return Count;
	}

	// ============================================================================
	// Technique 2: Opaque identity replacement
	//
	// Scan for trivial patterns that InstCombine would eliminate:
	//   add x, 0   →   add x, opaqueZero()
	//   xor x, 0   →   xor x, opaqueZero()
	//   mul x, 1   →   mul x, opaqueOne()
	//   or  x, 0   →   or  x, opaqueZero()
	//   and x, -1  →   and x, opaqueAllOnes()
	// ============================================================================
	static unsigned replaceOpaqueIdentities(ShieldCtx& Ctx) {
		if (!Ctx.Cfg.opaqueIdentities)
			return 0;

		Function& F = Ctx.F;
		unsigned Count = 0;

		SmallVector<BinaryOperator*, 64> Candidates;
		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				auto* BO = dyn_cast<BinaryOperator>(&I);
				if (!BO)
					continue;

				// Only target 32-bit integer operations (most common in obf output)
				if (!BO->getType()->isIntegerTy(32))
					continue;

				// Check for identity patterns
				Value* LHS = BO->getOperand(0);
				Value* RHS = BO->getOperand(1);
				auto* CRHS = dyn_cast<ConstantInt>(RHS);
				if (!CRHS)
					continue;

				unsigned Op = BO->getOpcode();
				bool IsIdentity = false;

				if ((Op == Instruction::Add || Op == Instruction::Sub ||
					Op == Instruction::Xor || Op == Instruction::Or) &&
					CRHS->isZero())
					IsIdentity = true;
				else if (Op == Instruction::Mul && CRHS->isOne())
					IsIdentity = true;
				else if (Op == Instruction::And && CRHS->isAllOnesValue())
					IsIdentity = true;

				if (IsIdentity)
					Candidates.push_back(BO);
			}
		}

		for (BinaryOperator* BO : Candidates) {
			if (!Ctx.budgetOk())
				break;

			// 50% chance to transform (avoid over-hardening)
			if (Ctx.SelectRng.range(100) >= 50)
				continue;

			IRBuilder<> B(BO);
			unsigned Op = BO->getOpcode();
			auto* CRHS = cast<ConstantInt>(BO->getOperand(1));

			Value* OpaqueRHS = nullptr;

			if (CRHS->isZero()) {
				// Replace 0 with opaqueZero
				OpaqueRHS = Ctx.Opaque.opaqueZero32(B);
			}
			else if (CRHS->isOne()) {
				// Replace 1 with opaqueConst(1)
				OpaqueRHS = Ctx.Opaque.opaqueI32Const(B, 1);
			}
			else if (CRHS->isAllOnesValue()) {
				// Replace -1 with opaqueConst(-1)
				OpaqueRHS = Ctx.Opaque.opaqueI32Const(B, 0xFFFFFFFF);
			}

			if (!OpaqueRHS)
				continue;

			BO->setOperand(1, OpaqueRHS);

			// Drop nsw/nuw flags — the opaque replacement may violate them.
			// Only Add/Sub/Mul/Shl carry these (OverflowingBinaryOperator);
			// And/Or/Xor are in our candidate set but the setters crash via
			// cast<OverflowingBinaryOperator> in LLVM 22 builds.
			if (isa<OverflowingBinaryOperator>(BO)) {
				BO->setHasNoSignedWrap(false);
				BO->setHasNoUnsignedWrap(false);
			}

			tagShielded(BO);
			++Count;
			++Ctx.SitesDone;
			++ShieldOpaqueIdentities;
		}

		return Count;
	}

	// ============================================================================
	// Technique 3: Dead-store protection
	//
	// Find stores to obfuscation state variables (fla.state, bcf.*, etc.)
	// and mark them volatile to prevent DSE from eliminating them.
	// ============================================================================
	static unsigned protectDeadStores(ShieldCtx& Ctx) {
		if (!Ctx.Cfg.deadStoreProtect)
			return 0;

		Function& F = Ctx.F;
		unsigned Count = 0;

		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				auto* SI = dyn_cast<StoreInst>(&I);
				if (!SI || SI->isVolatile())
					continue;

				if (!Ctx.budgetOk())
					break;

				if (isObfStateStore(SI)) {
					SI->setVolatile(true);
					tagShielded(SI);
					++Count;
					++Ctx.SitesDone;
					++ShieldDeadStoreProtect;
				}
			}
		}

		return Count;
	}

	// ============================================================================
	// Technique 4: CFG anti-simplification
	//
	// Find unconditional branches between blocks with obfuscation names
	// and replace them with opaque-predicate conditional branches.
	// This prevents SimplifyCFG from merging blocks.
	// ============================================================================
	static unsigned insertCFGGuards(ShieldCtx& Ctx) {
		if (!Ctx.Cfg.cfgGuards)
			return 0;

		Function& F = Ctx.F;
		unsigned Count = 0;

		SmallVector<BranchInst*, 32> UncondBranches;
		for (BasicBlock& BB : F) {
			auto* BI = dyn_cast<BranchInst>(BB.getTerminator());
			if (!BI || BI->isConditional())
				continue;

			// Only guard branches between obfuscation-named blocks
			if (!isObfArtifactName(BB.getName()))
				continue;

			BasicBlock* Succ = BI->getSuccessor(0);
			if (!isObfArtifactName(Succ->getName()))
				continue;

			// Skip if successor has PHI nodes from multiple predecessors
			// (we'd need to update them, which is complex and risky here)
			if (Succ->hasNPredecessorsOrMore(3))
				continue;

			UncondBranches.push_back(BI);
		}

		for (BranchInst* BI : UncondBranches) {
			if (!Ctx.budgetOk())
				break;

			// Only 30% chance to guard (avoid excessive bloat)
			if (Ctx.SelectRng.range(100) >= 30)
				continue;

			BasicBlock* BB = BI->getParent();
			BasicBlock* RealSucc = BI->getSuccessor(0);

			// Create a decoy block that just branches to the real successor
			BasicBlock* Decoy = BasicBlock::Create(
				F.getContext(), "shield.decoy", &F, RealSucc);
			IRBuilder<> DB(Decoy);
			DB.CreateBr(RealSucc);

			// Replace the unconditional branch with: if (hardTrue) goto Real else goto Decoy
			IRBuilder<> B(BI);
			Value* Cond = Ctx.Opaque.hardTrue(B);
			B.CreateCondBr(Cond, RealSucc, Decoy);
			BI->eraseFromParent();

			// Update PHI nodes in RealSucc to account for the new predecessor
			for (PHINode& Phi : RealSucc->phis()) {
				Value* V = Phi.getIncomingValueForBlock(BB);
				if (V)
					Phi.addIncoming(V, Decoy);
			}

			tagShielded(Decoy->getTerminator());
			++Count;
			++Ctx.SitesDone;
			++ShieldCFGGuards;
		}

		return Count;
	}

} // anonymous namespace

// ============================================================================
// Pass entry point
// ============================================================================
PreservedAnalyses AntiOptimizationShieldPass::run(Function& F,
	FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	ShieldCtx Ctx(F, AM);
	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();

	if (ObfVerbose)
		errs() << "[shield] Processing: " << F.getName()
		<< " maxSites=" << Ctx.Cfg.maxSites << "\n";

	++ShieldFunctionsProcessed;

	unsigned Total = 0;

	// Order matters: protect stores first (cheap), then identities, then
	// barriers (moderate), then CFG guards (most expensive).
	Total += protectDeadStores(Ctx);
	Total += replaceOpaqueIdentities(Ctx);
	Total += injectVolatileBarriers(Ctx);
	Total += insertCFGGuards(Ctx);

	if (ObfVerbose)
		errs() << "[shield] " << F.getName() << ": " << Total
		<< " transformations (volatile=" << (unsigned)ShieldVolatileBarriers
		<< " identity=" << (unsigned)ShieldOpaqueIdentities
		<< " dse=" << (unsigned)ShieldDeadStoreProtect
		<< " cfg=" << (unsigned)ShieldCFGGuards << ")\n";

	if (Total == 0)
		return PreservedAnalyses::all();

	return PreservedAnalyses::none();
}