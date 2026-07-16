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

} // namespace llvm::obf