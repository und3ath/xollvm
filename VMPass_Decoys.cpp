#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

using namespace llvm;

#define DEBUG_TYPE "vm"

// ============================================================================
// M3: static decoy handlers
//
// Registers NumDecoys extra handler-shaped basic blocks inside the shared
// vm_engine. Each decoy is built with the exact instruction shapes real
// handlers use (advIP / rdVR / rdByte / ldVR) so a static lifter sees them
// as ordinary opcodes, but every result is sunk into a private vm.junk
// alloca that nothing ever reads back -- the store is dead by construction.
//
// Decoys are NEVER reachable from the real dispatch path: buildHandlerTable()
// appends their blockaddresses past the real handler-table slots, and
// vm.fetch/emitThreadedTail clamp the fetched opcode index with
// `P = OIdx % OP_COUNT` before indexing the table, so no decoded opcode byte
// can ever select a decoy slot. Only the blockaddress-taken keeps them alive
// through DCE.
//
// Gated per engine LAYER, not per function request: computeNumDecoys() looks
// at VMEngine::engineLayer(EngineId), the layer this VMImpl instance is
// currently populating. The plain engine (layer 0) hosts decoys under
// preset=max (nestedVM=1) same as always; only the inner nested engine layer
// (layer 1, its own dispatch loop) skips them.
// ============================================================================

namespace {
	// Private per-engine junk sink. Kept small and power-of-two sized so the
	// index mask below never needs a bounds check.
	constexpr unsigned kNJunk = 8;
} // namespace


unsigned VMImpl::computeNumDecoys() const {
	// populateVMEngine() runs separately per engine layer (plain, then nest
	// when nestedVM is requested). Decoys are a property of a specific
	// engine build, not of the function's nestedVM request, so gate on which
	// layer THIS VMImpl instance is currently populating: the plain engine
	// (layer 0) always gets decoys per handlerDecoys; only the inner nested
	// engine layer (layer 1) skips them, since it has its own dispatch loop
	// that decoys would interact awkwardly with.
	if (VMEngine::engineLayer(EngineId) != 0) {
		if (Cfg.handlerDecoys != 0 && ObfVerbose)
			errs() << "[vm] handlerDecoys=" << Cfg.handlerDecoys
				   << " skipped: nested engine layer does not host decoys\n";
		return 0;
	}

	switch (Cfg.handlerDecoys) {
		case 1:  return 14;          // ~25% of OP_COUNT (0x38 == 56)
		case 2:  return 28;          // ~50%
		case 3:  return kMaxDecoys;  // 32, hard cap
		default: return 0;           // off (byte-identical)
	}
}


void VMImpl::buildDecoyHandlers() {
	DecoyBB.clear();
	if (NumDecoys == 0)
		return;

	// vm.junk: allocated once, in the same block (vm.entry) as vm.ip/vm.salt.
	// Entry has no terminator yet at this point in populateVMEngine() (that
	// happens later, in buildDispatch()), so appending here lands it right
	// after the existing allocas/stores.
	IRBuilder<> EB(Entry);
	AllocaInst* Junk = EB.CreateAlloca(ArrayType::get(I32Ty, kNJunk),
		nullptr, "vm.junk");
	Junk->setAlignment(Align(4));
	EngineJunk = Junk;

	auto storeJunk = [&](IRBuilder<>& B, unsigned DecoyIdx, Value* V) {
		Value* Ptr = B.CreateGEP(I32Ty, EngineJunk,
			B.getInt32(DecoyIdx & (kNJunk - 1)), "vm.dc.jp");
		B.CreateStore(V, Ptr);
	};

	for (unsigned DI = 0; DI < NumDecoys; ++DI) {
		unsigned Template = DI % 3;

		switch (Template) {
			case 0: {
				// Template A: ADD-shape.
				// dst = a + b + pred  (dst/a/b are register-index operands,
				// pred a plain byte -- same operand mix as OP_BINOP).
				BasicBlock* BB = BasicBlock::Create(Ctx,
					"vm.decoy.add." + Twine(DI), HFn);
				DecoyBB.push_back(BB);
				IRBuilder<> B(BB);
				Value* IP = advIP(B, 4);
				Value* DstIdx = rdVR(B, IP, 0, "vm.dc.d");
				Value* AIdx = rdVR(B, IP, 1, "vm.dc.a");
				Value* BIdx = rdVR(B, IP, 2, "vm.dc.b");
				Value* Pred = rdByte(B, IP, 3, "vm.dc.p");  // already zext'd to i32
				Value* Sum = B.CreateAdd(ldVR(B, AIdx), ldVR(B, BIdx), "vm.dc.s");
				Value* R = B.CreateAdd(Sum, Pred, "vm.dc.r");
				(void)DstIdx;  // decoded like a real dst operand, never stored to
				storeJunk(B, DI, R);
				nextInsn(B);
				break;
			}
			case 1: {
				// Template B: LOAD-shape.
				// dst/ptr operand mix mirrors OP_LOAD32 (dst:u8 ptrreg:u8), but
				// the "load" is really a register read, mixed with salt + dst.
				BasicBlock* BB = BasicBlock::Create(Ctx,
					"vm.decoy.load." + Twine(DI), HFn);
				DecoyBB.push_back(BB);
				IRBuilder<> B(BB);
				Value* IP = advIP(B, 2);
				Value* DstIdx = rdVR(B, IP, 0, "vm.dc.d");
				Value* PtrIdx = rdVR(B, IP, 1, "vm.dc.p");
				auto* SaltL = B.CreateLoad(I32Ty, EffSalt, "vm.dc.salt");
				SaltL->setVolatile(true);
				Value* X = B.CreateXor(ldVR(B, PtrIdx), SaltL, "vm.dc.x1");
				Value* R = B.CreateXor(X, DstIdx, "vm.dc.r");
				storeJunk(B, DI, R);
				nextInsn(B);
				break;
			}
			default: {
				// Template C: MOV-shape.
				// dst/src operand mix mirrors OP_MOVR; result is a ROL-7 of the
				// source register value instead of a plain copy.
				BasicBlock* BB = BasicBlock::Create(Ctx,
					"vm.decoy.mov." + Twine(DI), HFn);
				DecoyBB.push_back(BB);
				IRBuilder<> B(BB);
				Value* IP = advIP(B, 2);
				Value* DstIdx = rdVR(B, IP, 0, "vm.dc.d");
				Value* SrcIdx = rdVR(B, IP, 1, "vm.dc.s");
				Value* V = ldVR(B, SrcIdx);
				Value* Hi = B.CreateShl(V, 7, "vm.dc.hi");
				Value* Lo = B.CreateLShr(V, 25, "vm.dc.lo");
				Value* R = B.CreateOr(Hi, Lo, "vm.dc.rol");
				(void)DstIdx;
				storeJunk(B, DI, R);
				nextInsn(B);
				break;
			}
		}
	}

	LLVM_DEBUG(dbgs() << "[vm] built " << NumDecoys << " decoy handlers\n");
	if (ObfVerbose)
		errs() << "[vm] vm_engine decoys: " << NumDecoys << "\n";
}


// ============================================================================
// M4: live decoys
//
// At handlerDecoys>=2, ~50% of variant-tagged handler blocks get an
// opaque-false-guarded conditional branch into a randomly chosen decoy
// (DecoyBB). The opaque predicate is always false at runtime, so control
// always falls through to the original successor -- semantics are exactly
// preserved -- but the STATIC CFG now shows a real edge into the decoy,
// so a lifter/DSE attacker must solve the opaque predicate to prove the
// decoy edge unreachable.
//
// Dormant unless handlerDecoys>=2 AND NumDecoys>0 (the nested engine layer
// has NumDecoys==0, see computeNumDecoys()), so handlerDecoys<=1 stays
// byte-identical to M3.
// ============================================================================

void VMImpl::wireLiveDecoys(Function* EF) {
	if (!EF || Cfg.handlerDecoys < 2 || NumDecoys == 0)
		return;

	auto LiveRng = R.fork("vm.decoy.live");
	llvm::obf::OpaqueUtils Opaque(M, LiveRng, "vm.decoy.live.opq");

	// ---- Skip sets, built once ----------------------------------------
	SmallPtrSet<const BasicBlock*, 32> DecoySet;
	for (BasicBlock* BB : DecoyBB)
		DecoySet.insert(BB);

	// CALL opcode head blocks: not contiguous in the VMOp enum
	// (0x0F,0x10,0x11,0x2A,0x2B), so list them explicitly rather than
	// range-scanning. CALL sub-blocks (switch/case/merge/unreachable) are
	// all caught below by the "vm.cl." name-prefix filter instead.
	static const VMOp kCallOps[] = {
		OP_CALL_VOID, OP_CALL_INT, OP_CALL_PTR, OP_CALL_INT64, OP_CALL_F
	};
	SmallPtrSet<const BasicBlock*, 16> CallHeadSet;
	for (VMOp Op : kCallOps)
		for (unsigned v = 0; v < NumVariants; ++v)
			if (OpcBB[Op][v])
				CallHeadSet.insert(OpcBB[Op][v]);

	// ---- Collection pass (do not mutate the CFG while walking it) -----
	SmallVector<std::pair<BasicBlock*, unsigned>, 128> Sites;
	for (BasicBlock& BB : *EF) {
		if (VariantOf.count(&BB) == 0) continue;             // dispatch/fetch/exit/etc
		if (DecoySet.count(&BB)) continue;                   // never nest into a decoy
		if (CallHeadSet.count(&BB)) continue;                // CALL head (belt-and-braces)
		if (BB.getName().starts_with("vm.cl.")) continue;    // CALL sub-blocks

		Instruction* Term = BB.getTerminator();
		auto* Br = dyn_cast_or_null<BranchInst>(Term);
		if (!Br) continue;                                   // only br / condbr terminators

		if (LiveRng.range(2) != 0) continue;                 // ~50% density
		unsigned DecoyIdx = LiveRng.range(NumDecoys);
		Sites.emplace_back(&BB, DecoyIdx);
	}

	// ---- Rewrite pass --------------------------------------------------
	for (auto& Site : Sites) {
		BasicBlock* BB = Site.first;
		unsigned DecoyIdx = Site.second;

		Instruction* Term = BB->getTerminator();
		BasicBlock* Post = BB->splitBasicBlock(Term, "m4post");

		// BB now ends in an unconditional `br Post` (added by splitBasicBlock).
		// Replace it with an opaque-false-guarded condbr into the decoy;
		// the opaque predicate is always false at runtime so Post is always
		// taken -- semantics unchanged, static CFG grows a decoy edge.
		Instruction* SplitBr = BB->getTerminator();
		SplitBr->eraseFromParent();

		IRBuilder<> B(BB);
		Value* Pred = Opaque.randomHardFalse(B);
		B.CreateCondBr(Pred, DecoyBB[DecoyIdx], Post);
	}

	LLVM_DEBUG(dbgs() << "[vm] wireLiveDecoys: " << Sites.size()
		<< " handler blocks wired to live decoys\n");
	if (ObfVerbose)
		errs() << "[vm] vm_engine live decoys wired: " << Sites.size() << "\n";
}
