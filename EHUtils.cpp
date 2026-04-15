// ============================================================================
// EHUtils.cpp — Exception Handling utilities for the obfuscator
// ============================================================================

#include "llvm/Transforms/Obfuscator/EHUtils.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace llvm::obf {

	// ============================================================================
	// isInEHRegion — walk predecessors to determine if BB is in an EH region
	// ============================================================================
	bool isInEHRegion(const BasicBlock* BB) {
		if (!BB)
			return false;

		// Direct EH pad
		if (BB->isEHPad())
			return true;

		// Walk predecessors up to a depth limit to check if all paths
		// from entry go through an EH pad.
		// Conservative: if we find any non-EH predecessor path to entry,
		// the block is not exclusively in an EH region.
		SmallVector<const BasicBlock*, 16> Worklist;
		DenseSet<const BasicBlock*> Visited;

		Worklist.push_back(BB);
		Visited.insert(BB);

		while (!Worklist.empty()) {
			const BasicBlock* Cur = Worklist.pop_back_val();

			// If we reached the entry block through non-EH pads, not in EH region
			if (Cur == &Cur->getParent()->getEntryBlock())
				return false;

			for (const BasicBlock* Pred : predecessors(Cur)) {
				if (Visited.insert(Pred).second) {
					// If predecessor is an invoke and we came from its unwind edge,
					// we're in the EH region
					if (auto* II = dyn_cast<InvokeInst>(Pred->getTerminator())) {
						if (II->getUnwindDest() == Cur) {
							// This path enters through EH — continue checking other paths
							continue;
						}
					}
					// If predecessor is an EH pad, we're in the EH region on this path
					if (Pred->isEHPad())
						continue;

					Worklist.push_back(Pred);
				}
			}
		}

		// All paths from entry go through EH pads
		return true;
	}

	// ============================================================================
	// collectFlattenableBlocks
	// ============================================================================
	void collectFlattenableBlocks(Function& F,
		SmallVectorImpl<BasicBlock*>& Out,
		bool AllowInvoke) {
		Out.clear();

		for (BasicBlock& BB : F) {
			// Never flatten the entry block (it's handled separately by flattening)
			if (&BB == &F.getEntryBlock())
				continue;

			// Skip EH pads — they must remain as-is
			if (BB.isEHPad())
				continue;

			// Skip blocks in EH regions (between landingpad and resume)
			if (isInEHRegion(&BB))
				continue;

			// If we don't allow invoke blocks, skip them
			if (!AllowInvoke && isInvokeBlock(&BB))
				continue;

			Out.push_back(&BB);
		}
	}

	// ============================================================================
	// collectBCFSafeBlocks
	// ============================================================================
	void collectBCFSafeBlocks(Function& F,
		SmallVectorImpl<BasicBlock*>& Out) {
		Out.clear();

		for (BasicBlock& BB : F) {
			// Skip entry block
			if (&BB == &F.getEntryBlock())
				continue;

			// Skip EH pads
			if (BB.isEHPad())
				continue;

			// Skip blocks in EH regions
			if (isInEHRegion(&BB))
				continue;

			// Skip invoke blocks — we can't split invoke edges for BCF
			if (isInvokeBlock(&BB))
				continue;

			// Skip blocks that are unwind destinations
			bool IsUnwindTarget = false;
			for (const BasicBlock* Pred : predecessors(&BB)) {
				if (isUnwindEdge(Pred, &BB)) {
					IsUnwindTarget = true;
					break;
				}
			}
			if (IsUnwindTarget)
				continue;

			Out.push_back(&BB);
		}
	}

	// ============================================================================
	// canSplitEdge
	// ============================================================================
	bool canSplitEdge(const BasicBlock* From, const BasicBlock* To) {
		if (!From || !To)
			return false;

		// Never split invoke unwind edges
		if (isUnwindEdge(From, To))
			return false;

		// Don't split edges to EH pads
		if (To->isEHPad())
			return false;

		// Don't split edges from EH terminators (catchret, cleanupret)
		const Instruction* Term = From->getTerminator();
		if (isa<CatchReturnInst>(Term) || isa<CleanupReturnInst>(Term))
			return false;

		return true;
	}

	// ============================================================================
	// lowerInvokeToCall
	// ============================================================================
	CallInst* lowerInvokeToCall(InvokeInst* II) {
		if (!II)
			return nullptr;

		BasicBlock* BB = II->getParent();
		BasicBlock* NormalDest = II->getNormalDest();
		BasicBlock* UnwindDest = II->getUnwindDest();

		// We can only lower if the unwind destination's landingpad has one
		// predecessor (this invoke). Otherwise, lowering would leave a
		// dangling landingpad.
		// Actually, for flattening purposes, we keep the landingpad as a
		// separate state-machine block, so this check is relaxed.

		// Build the replacement call
		SmallVector<Value*, 8> Args(II->args());
		SmallVector<OperandBundleDef, 2> Bundles;
		II->getOperandBundlesAsDefs(Bundles);

		CallInst* CI = CallInst::Create(II->getFunctionType(),
			II->getCalledOperand(), Args, Bundles,
			II->getName(), II->getIterator());

		// Copy attributes
		CI->setCallingConv(II->getCallingConv());
		CI->setAttributes(II->getAttributes());
		CI->setDebugLoc(II->getDebugLoc());

		// Replace uses of the invoke with the call
		II->replaceAllUsesWith(CI);

		// Create an unconditional branch to the normal destination
		BranchInst::Create(NormalDest, BB);

		// Remove the invoke
		II->eraseFromParent();

		// If the unwind destination's landingpad now has no predecessors,
		// it will be cleaned up by later passes. We don't remove it here
		// to avoid invalidating iterators.

		return CI;
	}

	// ============================================================================
	// collectEHPads
	// ============================================================================
	void collectEHPads(Function& F, SmallVectorImpl<BasicBlock*>& Out) {
		Out.clear();
		for (BasicBlock& BB : F)
			if (BB.isEHPad())
				Out.push_back(&BB);
	}

	// ============================================================================
	// partitionNormalAndEH
	// ============================================================================
	void partitionNormalAndEH(Function& F,
		SmallVectorImpl<BasicBlock*>& NormalBlocks,
		SmallVectorImpl<BasicBlock*>& EHBlocks) {
		NormalBlocks.clear();
		EHBlocks.clear();

		for (BasicBlock& BB : F) {
			if (BB.isEHPad() || isInEHRegion(&BB))
				EHBlocks.push_back(&BB);
			else
				NormalBlocks.push_back(&BB);
		}
	}

} // namespace llvm::obf