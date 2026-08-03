#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/MBAUtils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"



// ============================================================================
// Handler-Level MBA + Opaque Predicates
//
// hardenVMEngine() is called once after populateVMEngine() builds all
// 51 handler blocks in __vm_engine.  It applies two transformations:
//
//   Part B — MBA substitutions on arithmetic in handler blocks:
//     ADD → (a|b)+(a&b) or (a^b)+2*(a&b) or 2*(a|b)-(a^b)
//     SUB → a + ~b + 1
//     XOR → (a|b) - (a&b)
//     AND → ~(~a | ~b)
//     OR  → (a^b) | (a&b)
//
//   Part C — Opaque predicates on dispatch back-edge + handler guards:
//     - hard-false before vm.dispatch → dead code block
//     - hard-true at ~30% of handler entries → bogus handler
//     - 3–5 dead code blocks with junk arithmetic
// ============================================================================

// Note: MBA helpers previously defined above as mbaAdd/mbaSub/mbaXor/mbaAnd/mbaOr
// are now provided by MbaUtils.  See hardenVMEngine below.

static bool isHandlerBlock(const BasicBlock& BB) {
	StringRef N = BB.getName();
	return N.starts_with("vm.opc.") || N.starts_with("vm.bo.") ||
		N.starts_with("vm.bo64.") || N.starts_with("vm.bof.") ||
		N.starts_with("vm.sl.") || N.starts_with("vm.cl.") ||
		N.starts_with("vm.fcp.") || N.starts_with("vm.c64.") ||
		N.starts_with("vm.sw.");
}


void VMImpl::hardenVMEngine(Function* EF, VMEngine::SharedState* SS) {
	if (!EF || !SS) return;

	auto HardenRng = R.fork("vm.harden");
	llvm::obf::OpaqueUtils Opaque(M, HardenRng, "vm.opaque.salt.i32");
	llvm::obf::MbaUtils MBA(M, HardenRng, "obf.vm.mba.noise.i32");

	unsigned MBASites = 0;
	unsigned GuardedHandlers = 0;
	unsigned DeadBlocks = 0;

	// ════════════════════════════════════════════════════════════════════
	// MBA substitutions on handler arithmetic
	// ════════════════════════════════════════════════════════════════════

	// Collect candidates first (can't modify while iterating).
	SmallVector<BinaryOperator*, 64> Candidates;
	for (BasicBlock& BB : *EF) {
		if (!isHandlerBlock(BB)) continue;
		for (Instruction& I : BB) {
			if (auto* BO = dyn_cast<BinaryOperator>(&I))
			{
				// Only transform i32 and i64 integer arithmetic.
				if (!BO->getType()->isIntegerTy()) continue;
				if (!llvm::obf::MbaUtils::isTargetOpcode(BO->getOpcode())) continue;
				Candidates.push_back(BO);
			}
		}
	}

	for (BinaryOperator* BO : Candidates) {
		if (!BO->getParent()) continue; // already erased

		IRBuilder<> B(BO);
		Value* A = BO->getOperand(0);
		Value* V = BO->getOperand(1);
		Value* Replacement = nullptr;

		HardenRng.u32(); // preserve RNG stream (variant selector, result unused)
		switch (BO->getOpcode()) {
		case Instruction::Add: {
			switch (HardenRng.range(3))
			{
			case 0:  Replacement = MBA.addAlt(B, A, V);  break; // (a|b)+(a&b)
			case 1:  Replacement = MBA.add(B, A, V);     break; // (a^b)+2*(a&b)
			default: Replacement = MBA.addAlt2(B, A, V); break; // 2*(a|b)-(a^b)
			}
			break;
		}
		case Instruction::Sub: Replacement = MBA.subAlt2(B, A, V); break;
		case Instruction::Xor: Replacement = MBA.bitwiseXor(B, A, V); break;
		case Instruction::And: Replacement = MBA.bitwiseAndAlt(B, A, V); break;
		case Instruction::Or:  Replacement = MBA.bitwiseOrAlt2(B, A, V); break;
		default: break;
		}

		if (!Replacement) continue;

		// ~30% chance: XOR result with opaque zero for noise.
		if (HardenRng.range(100) < 30) {
			Value* Zero = Opaque.opaqueZero32(B);            // i32
			Type* RepTy = Replacement->getType();
			if (RepTy != Zero->getType()) {
				unsigned BW = RepTy->getIntegerBitWidth();
				if (BW > 32)
					Zero = B.CreateZExt(Zero, RepTy, "mba.z.ext");
				else
					Zero = B.CreateTrunc(Zero, RepTy, "mba.z.trunc");
			}
			Replacement = B.CreateXor(Replacement, Zero, "mba.noise");
		}

		BO->replaceAllUsesWith(Replacement);
		BO->eraseFromParent();
		++MBASites;
	}

	// ════════════════════════════════════════════════════════════════════
	// Opaque predicates on dispatch + dead code
	// ════════════════════════════════════════════════════════════════════

	// Dead code blocks + opaque predicate on the dispatch back-edge both
	// require a single shared SS->Dispatch block to branch to / split.
	// threadedDispatch has no such block (every handler inlines its own
	// tail) -- both sections are no-ops there. The handler-level MBA above
	// and the hard-true handler guards below are unaffected and stay active.
	if (!ThreadedDispatch && SS->Dispatch) {
		// Dead code blocks
		// Create 3–5 dead code blocks with junk instructions that branch
		// back to vm.dispatch (makes CFG look connected).
		unsigned NDeadBlocks = 3 + HardenRng.range(3); // 3..5
		SmallVector<BasicBlock*, 8> DeadBBs;
		for (unsigned i = 0; i < NDeadBlocks; ++i) {
			auto* DBB = BasicBlock::Create(Ctx, "vm.dead." + Twine(i), EF);
			IRBuilder<> DB(DBB);

			// Junk arithmetic using opaque constants.
			Value* J1 = Opaque.opaqueI32Const(DB, HardenRng.u32());
			Value* J2 = Opaque.opaqueI32Const(DB, HardenRng.u32());
			Value* R1 = DB.CreateXor(J1, J2, "vm.dead.xor");
			Value* R2 = DB.CreateMul(R1, J1, "vm.dead.mul");
			Value* R3 = DB.CreateAdd(R2, J2, "vm.dead.add");
			(void)R3; // result unused — this is dead code

			// Branch back to dispatch (makes block look connected in CFG).
			DB.CreateBr(SS->Dispatch);
			DeadBBs.push_back(DBB);
			++DeadBlocks;
		}

		// Opaque predicate on vm.dispatch back-edge
		// Split vm.dispatch: insert a pre-dispatch block with hard-false
		// branch to dead code.
		if (!DeadBBs.empty()) {
			BasicBlock* DispBB = SS->Dispatch;
			// Create a new pre-dispatch block.
			BasicBlock* PreDisp = BasicBlock::Create(Ctx, "vm.predisp", EF, DispBB);

			// Redirect all predecessors of vm.dispatch to vm.predisp.
			SmallVector<BasicBlock*, 32> Preds(predecessors(DispBB));
			for (BasicBlock* Pred : Preds) {
				if (Pred == PreDisp) continue; // skip self
				Instruction* Term = Pred->getTerminator();
				if (!Term) continue;
				for (unsigned i = 0, e = Term->getNumSuccessors(); i < e; ++i) {
					if (Term->getSuccessor(i) == DispBB)
						Term->setSuccessor(i, PreDisp);
				}
			}

			// PreDisp: hard-false → dead code, else → real dispatch.
			IRBuilder<> PB(PreDisp);
			Value* Fake = Opaque.hardFalse(PB);
			unsigned DeadIdx = HardenRng.range((uint32_t)DeadBBs.size());
			PB.CreateCondBr(Fake, DeadBBs[DeadIdx], DispBB);
		}
	}

	// Hard-true guards on ~30% of handler entries
	// For a random subset of handler blocks, split at entry and add
	// a hard-true guard branching to a bogus block.
	SmallVector<BasicBlock*, 64> HandlerBBs;
	for (BasicBlock& BB : *EF) {
		if (BB.getName().starts_with("vm.opc."))
			HandlerBBs.push_back(&BB);
	}

	for (BasicBlock* HBB : HandlerBBs) {
		if (HardenRng.range(100) >= 30) continue; // ~30% probability

		// Create guard block before the handler.
		BasicBlock* GuardBB = BasicBlock::Create(Ctx,
			HBB->getName().str() + ".guard", EF, HBB);

		// Create bogus block (junk + back to dispatch / next-instruction
		// tail -- nextInsn() picks whichever this build uses).
		BasicBlock* BogusBB = BasicBlock::Create(Ctx,
			HBB->getName().str() + ".bogus", EF);
		{
			IRBuilder<> BB(BogusBB);
			Value* J = Opaque.opaqueI32Const(BB, HardenRng.u32());
			(void)BB.CreateXor(J, J, "vm.bogus.j");
			nextInsn(BB);
		}

		// Redirect predecessors of handler to guard block.
		SmallVector<BasicBlock*, 8> HPreds(predecessors(HBB));
		for (BasicBlock* Pred : HPreds) {
			if (Pred == GuardBB) continue;
			Instruction* Term = Pred->getTerminator();
			if (!Term) continue;
			for (unsigned i = 0, e = Term->getNumSuccessors(); i < e; ++i) {
				if (Term->getSuccessor(i) == HBB)
					Term->setSuccessor(i, GuardBB);
			}
		}

		// Guard: hard-true → real handler, else → bogus.
		IRBuilder<> GB(GuardBB);
		Value* Guard = Opaque.randomHardTrue(GB);
		GB.CreateCondBr(Guard, HBB, BogusBB);
		++GuardedHandlers;
	}

	// handler spot-check timing traps 
	// Inject a micro-timing gate into ~10% of handler entry blocks.
	// Two readcyclecounter reads straddle the handler's first few
	// instructions.  Delta > 500 cycles catches breakpoints set inside
	// the handler (debug exception takes 5000+ cycles).
	//
	// Platform: only on targets with readcyclecounter (x86_64, AArch64).
	// The check is self-contained within the handler block — no cross-BB
	// alloca needed.
	unsigned HandlerTraps = 0;
	// Skipped entirely under bindAntiDebug: the ctor-time key-mask fold
	// replaces these RDTSC spot-checks, removing their false-positive flake
	// exposure (see buildAntiDebugKeyBindCtor in VMPass_AntiDebug.cpp).
	if (!BindAntiDebug && Cfg.antiDebug && (TI.IsX86_64 || TI.IsAArch64)) {
		Function* RCC = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);


		// Collect candidates FIRST to avoid iterator invalidation.
		SmallVector<BasicBlock*, 16> TrapCandidates;
		for (BasicBlock& BB : *EF) {
			if (!isHandlerBlock(BB)) continue;
			if (BB.getName().contains(".ad.") || BB.getName().contains(".guard")
				|| BB.getName().contains(".bogus")) continue;
			// Only variant-0 handler blocks: injecting a spot-check into all K
			// duplicated variant copies (handlerVariants>1) multiplies the traps
			// and their cumulative false-positive exposure. Keep trap count
			// independent of K. (At K=1 every handler block is variant 0.)
			if (VariantOf.lookup(&BB) != 0) continue;
			if (HardenRng.range(100) >= (int)Cfg.adHandlerProb) continue;

			TrapCandidates.push_back(&BB);
		}

		// Consecutive-slow debounce. A real debugger makes EVERY execution of a
		// trapped handler slow (a debug exception / single-step costs many
		// thousands of cycles), so the count of consecutive slow observations
		// climbs to kDebounce almost immediately. A transient scheduling or
		// cache-miss spike is isolated: the next (fast) execution resets the
		// counter to 0, so it never reaches the threshold. This distinguishes
		// persistent slowness (a debugger) from one-off noise, killing the
		// first-execution false-poison flake the old one-shot-on-first design
		// had (the first execution is the coldest, noisiest sample). A separate
		// latch makes the salt poison apply exactly once: XOR is self-inverse,
		// so re-applying it on every subsequent execution would cancel it.
		const unsigned kDebounce = 3;   // consecutive slow hits before poisoning
		for (BasicBlock* HBB : TrapCandidates) {
			AllocaInst* Cnt, * Latched;
			{
				IRBuilder<> EntB(SS->Entry->getTerminator());
				Cnt = EntB.CreateAlloca(I32Ty, nullptr, "vm.ad.h.cnt");
				EntB.CreateStore(EntB.getInt32(0), Cnt)->setVolatile(true);
				Latched = EntB.CreateAlloca(I32Ty, nullptr, "vm.ad.h.lat");
				EntB.CreateStore(EntB.getInt32(0), Latched)->setVolatile(true);
			}

			// Insert at handler entry — before all existing instructions.
			IRBuilder<> B(&*HBB->getFirstInsertionPt());

			Value* T1 = B.CreateCall(RCC, {}, "vm.ad.h.t1");
			// Volatile barrier between reads
			auto* Bar = B.CreateLoad(I32Ty, SS->EngineSalt, "vm.ad.h.bar");
			cast<LoadInst>(Bar)->setVolatile(true);
			(void)B.CreateAdd(Bar, B.getInt32(0), "vm.ad.h.sink");
			Value* T2 = B.CreateCall(RCC, {}, "vm.ad.h.t2");

			Value* Delta = B.CreateSub(T2, T1, "vm.ad.h.delta");
			Value* Slow = B.CreateICmpUGT(Delta,
				B.getInt64((uint64_t)Cfg.adHandlerThreshold),
				"vm.ad.h.slow");

			// Consecutive-slow counter: slow ? cnt+1 : 0 (branchless).
			auto* OldCnt = B.CreateLoad(I32Ty, Cnt, "vm.ad.h.cnt.o");
			cast<LoadInst>(OldCnt)->setVolatile(true);
			Value* Inc = B.CreateAdd(OldCnt, B.getInt32(1), "vm.ad.h.cnt.i");
			Value* NewCnt = B.CreateSelect(Slow, Inc, B.getInt32(0), "vm.ad.h.cnt.n");
			B.CreateStore(NewCnt, Cnt)->setVolatile(true);

			// Poison only when kDebounce consecutive slow hits AND not yet latched.
			Value* Reached = B.CreateICmpUGE(NewCnt, B.getInt32(kDebounce), "vm.ad.h.rch");
			auto* OldLat = B.CreateLoad(I32Ty, Latched, "vm.ad.h.lat.o");
			cast<LoadInst>(OldLat)->setVolatile(true);
			Value* NotLatched = B.CreateICmpEQ(OldLat, B.getInt32(0), "vm.ad.h.nl");
			Value* DoPoison = B.CreateAnd(Reached, NotLatched, "vm.ad.h.dop");

			// Branchless salt corruption: select poison or zero
			Value* Poison = B.CreateSelect(DoPoison,
				B.getInt32(ADPoisonKey), B.getInt32(0), "vm.ad.h.pois");
			auto* OldSalt = B.CreateLoad(I32Ty, SS->EngineSalt, "vm.ad.h.salt");
			cast<LoadInst>(OldSalt)->setVolatile(true);
			Value* NewSalt = B.CreateXor(OldSalt, Poison, "vm.ad.h.xsal");
			B.CreateStore(NewSalt, SS->EngineSalt)->setVolatile(true);

			// Latch once poisoned so the self-inverse XOR is never applied twice.
			Value* NewLat = B.CreateSelect(DoPoison, B.getInt32(1), OldLat, "vm.ad.h.lat.n");
			B.CreateStore(NewLat, Latched)->setVolatile(true);

			++HandlerTraps;
		}


	}




	LLVM_DEBUG(dbgs() << "[vm] hardened vm_engine: " << MBASites << " MBA sites, "
		<< GuardedHandlers << " guarded handlers, "
		<< DeadBlocks << " dead blocks, "
		<< HandlerTraps << " handler traps\n");
	if (ObfVerbose)
		errs() << "[vm] hardened=1: " << MBASites << " MBA substitutions, "
		<< GuardedHandlers << " handler guards, "
		<< DeadBlocks << " dead code blocks, "
		<< HandlerTraps << " handler timing traps\n";

}



// ============================================================================
// diversifyHandlerVariants
//
// Makes the K structurally-identical handler-variant copies (built by
// buildOpcodeHandlers() when VMPassConfig.handlerVariants > 1) structurally
// DISTINCT. Each block tagged in VariantOf (populated by buildOpcodeHandlers)
// gets its target integer BinaryOperators rewritten with an MBA identity
// chosen deterministically from the block's variant index, then XORed with a
// per-site opaque zero so even repeated identities diverge and the rewrite
// resists -O2 folding. Semantics-preserving: mirrors hardenVMEngine's proven
// construction/replacement pattern.
// ============================================================================

void VMImpl::diversifyHandlerVariants(Function* EF) {
	if (!EF || NumVariants < 2) return;

	auto DivRng = R.fork("vm.variant.diversify");
	llvm::obf::MbaUtils   MBA(M, DivRng, "obf.vm.variant.mba.i32");
	llvm::obf::OpaqueUtils Opaque(M, DivRng, "vm.variant.opaque.i32");

	// Collect first (cannot rewrite while iterating).
	SmallVector<std::pair<BinaryOperator*, unsigned>, 256> Cands;
	for (BasicBlock& BB : *EF) {
		auto It = VariantOf.find(&BB);
		if (It == VariantOf.end()) continue;      // not a handler-variant block
		unsigned vi = It->second;
		for (Instruction& I : BB) {
			if (auto* BO = dyn_cast<BinaryOperator>(&I)) {
				if (!BO->getType()->isIntegerTy()) continue;
				if (!llvm::obf::MbaUtils::isTargetOpcode(BO->getOpcode())) continue;
				Cands.push_back({ BO, vi });
			}
		}
	}

	unsigned Rewrites = 0;
	for (auto& [BO, vi] : Cands) {
		if (!BO->getParent()) continue; // already erased
		IRBuilder<> B(BO);
		Value* A = BO->getOperand(0);
		Value* V = BO->getOperand(1);
		Value* R = nullptr;
		switch (BO->getOpcode()) {
		case Instruction::Add:
			switch (vi % 3) { case 0: R = MBA.add(B, A, V); break;
							  case 1: R = MBA.addAlt(B, A, V); break;
							  default: R = MBA.addAlt2(B, A, V); } break;
		case Instruction::Sub:
			switch (vi % 3) { case 0: R = MBA.sub(B, A, V); break;
							  case 1: R = MBA.subAlt(B, A, V); break;
							  default: R = MBA.subAlt2(B, A, V); } break;
		case Instruction::Or:
			switch (vi % 3) { case 0: R = MBA.bitwiseOr(B, A, V); break;
							  case 1: R = MBA.bitwiseOrAlt(B, A, V); break;
							  default: R = MBA.bitwiseOrAlt2(B, A, V); } break;
		case Instruction::And:
			R = (vi % 2) ? MBA.bitwiseAndAlt(B, A, V) : MBA.bitwiseAnd(B, A, V); break;
		case Instruction::Xor:
			R = (vi % 2) ? MBA.bitwiseXorAlt(B, A, V) : MBA.bitwiseXor(B, A, V); break;
		default: break;
		}
		if (!R) continue;

		// Variant-unique opaque-zero XOR (matches hardenVMEngine's noise pattern,
		// incl. i64 width handling).
		Value* Z = Opaque.opaqueZero32(B);
		Type* RT = R->getType();
		if (RT != Z->getType()) {
			if (RT->getIntegerBitWidth() > 32) Z = B.CreateZExt(Z, RT, "vd.z.ext");
			else                                Z = B.CreateTrunc(Z, RT, "vd.z.tr");
		}
		R = B.CreateXor(R, Z, "vd.noise");

		BO->replaceAllUsesWith(R);
		BO->eraseFromParent();
		++Rewrites;
	}

	LLVM_DEBUG(dbgs() << "[vm] diversifyHandlerVariants: " << Rewrites
		<< " per-variant MBA rewrites across "
		<< NumVariants << " variants\n");
	if (ObfVerbose)
		errs() << "[vm] variant-diversify: " << Rewrites
		<< " MBA rewrites (" << NumVariants << " variants)\n";
}
