
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "llvm/Transforms/Obfuscator/IRBudget.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/BogusControlFlow.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/EHUtils.h"




using namespace llvm;

#define DEBUG_TYPE "bcf"

STATISTIC(NumFunction, "Number of functions processed");
STATISTIC(NumModifiedBasicBlocks, "Number of modified basic blocks");
STATISTIC(NumAddedBasicBlocks, "Number of added basic blocks");

namespace {


	struct BcfCtx;

	struct BcfImpl final {
		// --------------------------------------------------------------------------
		// Config
		// --------------------------------------------------------------------------
		static BCFConfig getBCFConfig(Function& F, FunctionAnalysisManager& AM);

		// ============================================================================
		// Helper Functions
		// ============================================================================
		static bool isBcfEligible(const FunctionObfContext& Ctx, raw_ostream* Reason = nullptr);
		static unsigned computeBcfMaxBlocks(const FunctionObfContext& Ctx, const BCFConfig& Cfg, unsigned Iterations);
		static bool canObfuscateBlock(BasicBlock* BB);
		static void collectBlocks(Function& F, SmallVectorImpl<BasicBlock*>& blocks);

		// ============================================================================
		// Junk Code Generation (no UB / no poison / no side effects)
		// ============================================================================
		static Value* maskShiftAmount(IRBuilder<>& B, Value* Amt, unsigned BW);
		static void emitSafeJunk(IRBuilder<>& B, BcfCtx& Ctx, unsigned Count);


		// ============================================================================
		// Bogus Control Flow
		// ============================================================================
		static void buildBogusLoop(Function& F, BasicBlock* InsertBefore,
			BasicBlock* RealBB, BasicBlock*& BogusEntryOut, BcfCtx& Ctx);
		static void addBogusFlow(BasicBlock* BB, Function& F, BcfCtx& ctx);


		// ============================================================================
		// Main Transformation
		// ============================================================================
		static bool applyBogusControlFlow(Function& F, BcfCtx& Ctx);
	};


	

	struct BcfCtx : llvm::obf::FuncPassCtx {
		llvm::BCFConfig Cfg;
		llvm::FunctionObfContext& FOC;

		llvm::obf::Rng SelectRng; // probability gating
		llvm::obf::Rng JunkRng;   // junk intensity
		llvm::obf::Rng OpGenRng;  // opaque predicate randomness (stable)
		llvm::obf::Rng ShuffleRng; // stable block selection order

		//llvm::OpaquePredicateGenerator OpGen; // requires (Module&, Rng&)
		llvm::obf::OpaqueUtils Opaque;

		BcfCtx(llvm::Function& F, llvm::FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "bcf"),
			Cfg(BcfImpl::getBCFConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),

			SelectRng(R.fork("select")),
			JunkRng(R.fork("junk")),
			OpGenRng(R.fork("opgen")),
			ShuffleRng(R.fork("shuffle")),
			Opaque(M, OpGenRng, "bcf.opaque.salt.i32",
				[&]() {
					llvm::obf::OpaqueUtils::Options O;
					O.EnableOpaqueConsts = true;
					O.EnableOpaqueBools = true;
					O.EnableHardPreds = true;
					O.VolatileLoads = true;
								         // BCF: keep it moderate by default (still diversified).
					O.PredStrength = 1u;
					return O;
					}()) { }
	};


	// ============================================================================
	// Helper Functions
	// ============================================================================


	bool BcfImpl::isBcfEligible(const FunctionObfContext & Ctx, raw_ostream * Reason)
	{
		// NOTE: HasInvoke is NOT rejected at the function level.
		// Block-level safety (canObfuscateBlock) skips EH pads and EH regions.
		// BCF's addBogusFlow splits before the terminator, so invoke blocks
		// are handled correctly — the invoke stays in the split-off realBB
		// and the opaque-predicate branch is inserted before it.
		if (Ctx.HasIndirectBr) {
			if (Reason) *Reason << "indirectbr present";
			return false;
			
		}
		if (Ctx.HasCallBr) {
			if (Reason) *Reason << "callbr present";
			return false;
			
		}
		if (Ctx.HasMustTail) {
			if (Reason) *Reason << "musttail present";
			return false;
			
		}
		if (Ctx.HasConvergentCalls) {
			if (Reason) *Reason << "convergent call present";
			return false;
			
		}
		return true;
		
	}
	
	unsigned BcfImpl::computeBcfMaxBlocks(const FunctionObfContext & Ctx, const BCFConfig & Cfg, unsigned Iterations)
	{
		if (Cfg.maxBlocks > 0)
			return (unsigned)Cfg.maxBlocks;
		// Auto: keep bounded and scale down when looping.
		unsigned Base = std::min<unsigned>(Ctx.NumBlocks, 32u);
		Base = std::max<unsigned>(1u, Base / std::max<unsigned>(1u, Iterations));
		return Base;
		
	}


	bool BcfImpl::canObfuscateBlock(BasicBlock* BB) {
		if (!BB || BB->empty())
			return false;

		Instruction* firstNonPHI = BB->getFirstNonPHI();
		if (firstNonPHI && firstNonPHI->isEHPad())
			return false;

		// Skip blocks in EH regions (between landingpad and resume)
		if (llvm::obf::isInEHRegion(BB))
			return false;
		

		return true;
	}

	void BcfImpl::collectBlocks(Function& F, SmallVectorImpl<BasicBlock*>& blocks) {
		for (BasicBlock& BB : F) {
			if (canObfuscateBlock(&BB)) {
				blocks.push_back(&BB);
			}
		}
	}

	// ============================================================================
	// Junk Code Generation (Phase 2: no UB / no poison / no side effects)
	// ============================================================================

	Value* BcfImpl::maskShiftAmount(IRBuilder<>& B, Value* Amt, unsigned BW) {
		// shift amount is masked with (BW-1) to avoid UB.
		if (!Amt->getType()->isIntegerTy())
			return Amt;

		auto* Ty = cast<IntegerType>(Amt->getType());
		Value* Mask = ConstantInt::get(Ty, (BW - 1));
		return B.CreateAnd(Amt, Mask, "bcf.shamt");
	}

	void BcfImpl::emitSafeJunk(IRBuilder<>& B, BcfCtx &Ctx, unsigned Count)
	{
		LLVMContext& C = B.getContext();
		Type* i32Ty = Type::getInt32Ty(C);
		(void)i32Ty;
		for (unsigned i = 0; i < Count; ++i) {
			Value* x = Ctx.Opaque.opaqueBool(B); // i1, but we can zext it and mix
			Value* a = Ctx.Opaque.hardTrue(B);
			Value* z1 = B.CreateZExt(x, Type::getInt32Ty(C), "bcf.z1");
			Value* z2 = B.CreateZExt(a, Type::getInt32Ty(C), "bcf.z2");
			// Some safe arithmetic that never traps:
			// t = (z1 + 7) ^ (z2 * 3)
			Value* t1 =
				B.CreateAdd(z1, ConstantInt::get(Type::getInt32Ty(C), 7), "bcf.j1");
			Value* t2 =
				B.CreateMul(z2, ConstantInt::get(Type::getInt32Ty(C), 3), "bcf.j2");
			Value* t = B.CreateXor(t1, t2, "bcf.j3");
			// Safe shift with masked amount.
			Value* shamt = maskShiftAmount(B, t, 32);
			(void)B.CreateShl(t, shamt, "bcf.jshl");
		}
	}

	// ============================================================================
	// Bogus Control Flow
	// ============================================================================


	void BcfImpl::buildBogusLoop(Function& F, BasicBlock* InsertBefore,
		BasicBlock* RealBB, BasicBlock*& BogusEntryOut, BcfCtx &Ctx) {
		LLVMContext& C = F.getContext();
		Type* I32 = Type::getInt32Ty(C);

		BasicBlock* Hdr = BasicBlock::Create(C, "bcf.bogus.hdr", &F, InsertBefore);
		BasicBlock* Body = BasicBlock::Create(C, "bcf.bogus.body", &F, InsertBefore);
		BasicBlock* Exit = BasicBlock::Create(C, "bcf.bogus.exit", &F, InsertBefore);

		// Hdr: limit = (entropy & 3) + 1; br Body
		{
			IRBuilder<> B(Hdr);
			Value* E = llvm::obf::getObfEntropyI32(B);
			Value* Lim = B.CreateAnd(E, ConstantInt::get(I32, 3), "bcf.lim.and");
			Lim = B.CreateAdd(Lim, ConstantInt::get(I32, 1), "bcf.lim");
			B.CreateBr(Body);

			// Attach Lim in Body via block argument-like pattern using a PHI
			IRBuilder<> BB(Body);
			auto* Iphi = BB.CreatePHI(I32, 2, "bcf.i");
			auto* Lphi = BB.CreatePHI(I32, 2, "bcf.lim.phi");
			Iphi->addIncoming(ConstantInt::get(I32, 0), Hdr);
			Lphi->addIncoming(Lim, Hdr);

			emitSafeJunk(BB, Ctx, 1 + (unsigned)Ctx.JunkRng.range(3));

			
			Value* Inext = BB.CreateAdd(Iphi, ConstantInt::get(I32, 1), "bcf.inext");
			Value* Cond = BB.CreateICmpULT(Inext, Lphi, "bcf.loopc");
			Iphi->addIncoming(Inext, Body);
			Lphi->addIncoming(Lphi, Body);
			BB.CreateCondBr(Cond, Body, Exit);
		}

		// Exit: tiny junk + br Real
		{
			IRBuilder<> B(Exit);
			emitSafeJunk(B, Ctx, 1 + (unsigned)Ctx.JunkRng.range(2));
			B.CreateBr(RealBB);
		}

		BogusEntryOut = Hdr;
	}




	void BcfImpl::addBogusFlow(BasicBlock* BB, Function& F, BcfCtx &ctx) {

		if (BB == &F.getEntryBlock())
			return;


		if (!canObfuscateBlock(BB))
			return;

		// Choose a split point that avoids moving entry allocas into a non-entry
		// block.
		auto splitIt = BB->getFirstNonPHIOrDbgOrLifetime();
		while (splitIt != BB->end() && isa<AllocaInst>(&*splitIt))
			++splitIt;

		if (splitIt == BB->end())
			return; // nothing meaningful to split

		BasicBlock* realBB = BB->splitBasicBlock(splitIt, "bcf.real");
		DEBUG_WITH_TYPE("bcf", errs() << "bcf: Block split (phase2)\n");
		// Create a bogus block that is semantics-preserving even if executed.
		BasicBlock* bogusBB =
			BasicBlock::Create(F.getContext(), "bcf.bogus", &F, realBB);
		// Remove the unconditional branch auto-inserted by splitBasicBlock().
		if (BB->getTerminator())
			BB->getTerminator()->eraseFromParent();



		// Entry branch: unpredictable; bogus path is semantics-preserving and now loop-shaped.
		IRBuilder<> entryB(BB);

		Value* cond = ctx.Opaque.opaqueBool(entryB);
		BasicBlock* BogusEntry = nullptr;

		// Replace single bogus block with a bounded bogus loop (harder to pattern-match).
		bogusBB->eraseFromParent(); // remove unused placeholder
		buildBogusLoop(F, realBB, realBB, BogusEntry, ctx);

		entryB.CreateCondBr(cond, realBB, BogusEntry);



		++NumAddedBasicBlocks;
	}

	// ============================================================================
	// Configuration
	// ============================================================================

	BCFConfig BcfImpl::getBCFConfig(Function& F, FunctionAnalysisManager& AM) {

		const ObfuscationConfig& obfConfig = getObfConfig(F, AM);
		auto passConfig = obfConfig.getPassConfig("bcf");

		BCFConfig cfg = BCFConfig::fromPassConfig(*passConfig);

		if (!cfg.validate()) {
			if (ObfVerbose) {
				errs() << "BCF: Invalid configuration for function " << F.getName()
					<< ", disabling pass\n";
			}
			cfg.enable = false;
		}

		return cfg;
	}

	// ============================================================================
	// Main Transformation
	// ============================================================================

	bool BcfImpl::applyBogusControlFlow(Function& F, BcfCtx &Ctx) {


		int probability = Ctx.Cfg.prob;
		int iterations = Ctx.Cfg.loop;

		// Budget-aware: clamp iterations based on remaining budget.
		// Each BCF application adds ~20-30 instructions (bogus loop + opaque pred).
		unsigned budgetLeft = Ctx.FOC.BudgetRemaining;
		if (budgetLeft != UINT_MAX) {
			unsigned instsPerBlock = 25;
			unsigned maxTransforms = std::max(1u, budgetLeft / instsPerBlock);
			unsigned totalBlocks = std::max(1u, Ctx.FOC.NumBlocks);
			unsigned totalWork = (unsigned)iterations * totalBlocks;
			if (totalWork > maxTransforms) {
				iterations = std::max(1, (int)(maxTransforms / totalBlocks));
			}
			if (ObfVerbose)
				errs() << "[bcf] budget-throttled iterations to " << iterations
				<< " (budgetLeft=" << budgetLeft << ")\n";
		}

		if (probability <= 0 || probability > 100) {
			DEBUG_WITH_TYPE("bcf", errs() << "bcf: Invalid probability\n");
			return false;
		}

		if (iterations <= 0) {
			DEBUG_WITH_TYPE("bcf", errs() << "bcf: Invalid iteration count\n");
			return false;
		}

		// Important: only consider the original block set (avoid exponential growth
		// by re-obfuscating blocks created by this pass).
		SmallVector<BasicBlock*, 64> BaseBlocks;
		collectBlocks(F, BaseBlocks);
		if (BaseBlocks.empty())
			return false;
		
		const unsigned MaxBlocks = computeBcfMaxBlocks(Ctx.FOC, Ctx.Cfg, (unsigned)iterations);
		


		bool modified = false;
		unsigned bcfStartInsts = llvm::obf::countInstructions(F);
		unsigned bcfBudgetCap = (budgetLeft != UINT_MAX)
			? (bcfStartInsts > UINT_MAX - budgetLeft
				? UINT_MAX
				: bcfStartInsts + budgetLeft)
			: UINT_MAX;
		// Observed worst-case per-site delta (each addBogusFlow can add
		// 20-200 insts depending on opaque predicate complexity and post-MBA
		// block size). Tracked dynamically so the predictive check below
		// tightens after the first few applications.
		unsigned bcfMaxObservedDelta = 50;
		unsigned bcfLastInsts = bcfStartInsts;

		for (int iter = 0; iter < iterations; ++iter) {
			// Live budget check: stop if we've blown past our allocation
			if (bcfBudgetCap != UINT_MAX) {
				unsigned now = llvm::obf::countInstructions(F);
				if (now >= bcfBudgetCap) {
					if (ObfVerbose)
						errs() << "[bcf] budget exhausted mid-loop at iter "
						<< iter << "\n";
					break;
				}
			}

			SmallVector<BasicBlock*, 64> blocks = BaseBlocks;

			// Stable-but-randomized per-iteration order (does not affect SelectRng)
			std::string L = ("iter" + std::to_string(iter));
			auto IterShuffle = Ctx.ShuffleRng.fork(L);
			IterShuffle.shuffle(llvm::MutableArrayRef<BasicBlock*>(blocks.data(), blocks.size()));

			if (MaxBlocks && blocks.size() > MaxBlocks)
				blocks.resize(MaxBlocks);

			for (BasicBlock* BB : blocks) {
				// Predictive cap: never start a site whose worst-case cost
				// would push us past the budget.
				if (bcfBudgetCap != UINT_MAX) {
					unsigned cur = llvm::obf::countInstructions(F);
					if (cur + bcfMaxObservedDelta >= bcfBudgetCap) {
						if (ObfVerbose)
							errs() << "[bcf] live budget reached (cur=" << cur
							<< " +next~" << bcfMaxObservedDelta
							<< " >= " << bcfBudgetCap << ")\n";
						return modified;
					}
					bcfLastInsts = cur;
				}

				if (Ctx.SelectRng.range(100) < (uint32_t)probability) {
					addBogusFlow(BB, F, Ctx);
					++NumModifiedBasicBlocks;
					modified = true;

					if (bcfBudgetCap != UINT_MAX) {
						unsigned after = llvm::obf::countInstructions(F);
						unsigned delta = after > bcfLastInsts ? after - bcfLastInsts : 0;
						if (delta > bcfMaxObservedDelta)
							bcfMaxObservedDelta = delta;
						bcfLastInsts = after;
					}
				}
			}
		}

		return modified;
	}

} // anonymous namespace

// ============================================================================
// Pass Implementation
// ============================================================================

PreservedAnalyses BogusControlFlowPass::run(Function& F, FunctionAnalysisManager& AM) 
{
	if (F.isDeclaration())
		return PreservedAnalyses::all();


	BcfCtx Ctx(F, AM);
	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();

	
	{
		std::string R;
		raw_string_ostream OS(R);
		if (!BcfImpl::isBcfEligible(Ctx.FOC, &OS)) {
			if (ObfVerbose)
				errs() << "[BCF] Skipping: " << F.getName() << " (" << OS.str() << ")\n";
			llvm::obf::recordObfPassSkip(Ctx.FOC, "bcf",
				R.empty() ? "ineligible" : R);
			return PreservedAnalyses::all();

		}
	}
	



	if (ObfVerbose) {
		errs() << "[BCF] Processing: " << F.getName() << "\n";
		errs() << "      probability=" << Ctx.Cfg.prob << ", iterations=" << Ctx.Cfg.loop << "\n";
	}

	++NumFunction;


	bool success = BcfImpl::applyBogusControlFlow(F, Ctx);

	if (success) {
		if (ObfVerbose) {
			errs() << "       Modified " << NumModifiedBasicBlocks << " blocks, added "
				<< NumAddedBasicBlocks << " blocks\n";
		}
		return PreservedAnalyses::none();
	}

	if (ObfVerbose) {
		errs() << "No modifications\n";
	}
	return PreservedAnalyses::all();
}