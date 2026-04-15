#pragma once

// ============================================================================
// EHUtils.h — Exception Handling utilities for the obfuscator
//
// Provides helper functions for safely manipulating IR that contains
// invoke/landingpad/catchswitch/catchpad/cleanuppad constructs.
//
// Key design principles:
//   - Never split invoke edges (the edge from invoke to landingpad is sacred)
//   - Treat EH pads as opaque (don't insert code into them)
//   - When flattening, invoke unwind targets become state-machine transitions
//   - BCF should never insert bogus blocks on unwind paths
// ============================================================================

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"

namespace llvm::obf {

	// ============================================================================
	// EH classification
	// ============================================================================

	/// Returns true if the block is an EH pad (landingpad, catchswitch,
	/// catchpad, cleanuppad, catchret, cleanupret).
	inline bool isEHPadBlock(const BasicBlock* BB) {
		return BB && BB->isEHPad();
	}

	/// Returns true if the block contains an invoke instruction as its
	/// terminator. Invoke edges require special handling.
	inline bool isInvokeBlock(const BasicBlock* BB) {
		return BB && isa<InvokeInst>(BB->getTerminator());
	}

	/// Returns true if the block is part of an EH "region" — either an EH pad
	/// itself or a block that is reachable only through EH pads (between
	/// landingpad and resume/catchret/cleanupret).
	bool isInEHRegion(const BasicBlock* BB);

	/// Returns true if the terminator of BB is an invoke whose unwind
	/// destination is the given block.
	inline bool isUnwindEdge(const BasicBlock* From, const BasicBlock* To) {
		if (auto* II = dyn_cast<InvokeInst>(From->getTerminator()))
			return II->getUnwindDest() == To;
		return false;
	}

	// ============================================================================
	// Safe block collection
	// ============================================================================

	/// Collect all basic blocks in F that are safe to flatten (i.e., not EH pads,
	/// not unwind targets, and not invoke blocks unless allowInvoke is true).
	///
	/// When allowInvoke=true, invoke blocks are included but the caller must
	/// handle the invoke→landingpad edge correctly.
	void collectFlattenableBlocks(Function& F,
		SmallVectorImpl<BasicBlock*>& Out,
		bool AllowInvoke = false);

	/// Collect all basic blocks safe for BCF transformation (not EH pads,
	/// not critical EH edges).
	void collectBCFSafeBlocks(Function& F,
		SmallVectorImpl<BasicBlock*>& Out);

	// ============================================================================
	// EH-safe edge manipulation
	// ============================================================================

	/// Returns true if it's safe to split the edge From→To.
	/// False if it's an invoke unwind edge or if To is an EH pad with
	/// multiple predecessors (which would require adjusting the landingpad).
	bool canSplitEdge(const BasicBlock* From, const BasicBlock* To);

	/// Returns true if it's safe to insert code at the beginning of BB.
	/// False for EH pads (landingpad must be the first instruction).
	inline bool canInsertAtBegin(const BasicBlock* BB) {
		return BB && !BB->isEHPad();
	}

	// ============================================================================
	// Invoke → Call lowering (for controlled regions)
	// ============================================================================

	/// For invoke instructions whose unwind path we can handle via the state
	/// machine, lower them to call + br. This is only safe when the entire
	/// function is being flattened and EH is handled through state transitions.
	///
	/// Returns the new CallInst (the invoke is erased).
	/// Returns nullptr if the invoke cannot be safely lowered.
	CallInst* lowerInvokeToCall(InvokeInst* II);

	/// Collect all EH pad blocks in the function.
	void collectEHPads(Function& F, SmallVectorImpl<BasicBlock*>& Out);

	/// Given a function, partition blocks into "normal" and "EH" regions.
	/// Normal blocks can be flattened; EH blocks are left as-is with
	/// state transitions patched to route through the dispatcher.
	void partitionNormalAndEH(Function& F,
		SmallVectorImpl<BasicBlock*>& NormalBlocks,
		SmallVectorImpl<BasicBlock*>& EHBlocks);

} // namespace llvm::obf