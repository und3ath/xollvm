#pragma once

// ============================================================================
// DebugInfoPreserver.h — Debug info preservation utilities
//
// Ensures that obfuscation passes propagate !dbg metadata correctly.
// Also provides a utility to selectively strip debug info only from
// obfuscated functions while preserving it on unobfuscated code.
// ============================================================================

#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"

namespace llvm::obf {

	// ============================================================================
	// Debug location propagation
	// ============================================================================

	/// Copy the debug location from Src to Dst.
	/// If Src has no debug location, this is a no-op.
	inline void propagateDebugLoc(Instruction* Dst, const Instruction* Src) {
		if (Src && Dst && Src->getDebugLoc())
			Dst->setDebugLoc(Src->getDebugLoc());
	}

	/// Copy the debug location from Src to all instructions in the range [Begin, End).
	void propagateDebugLocToRange(const Instruction* Src,
		BasicBlock::iterator Begin,
		BasicBlock::iterator End);

	/// For a newly created block, propagate the debug location from the
	/// original block's terminator (or first non-phi instruction) to all
	/// instructions in the new block that lack debug locations.
	void propagateDebugLocToBlock(BasicBlock* NewBB, const BasicBlock* OrigBB);

	/// Find the "best" debug location for a given block: the debug location
	/// of the first non-phi, non-debug instruction with a valid location.
	DebugLoc findBestDebugLoc(const BasicBlock* BB);

	/// For an IRBuilder about to emit instructions, set the debug location
	/// to the best available from the given block.
	void setBuilderDebugLoc(IRBuilder<>& B, const BasicBlock* RefBB);

	// ============================================================================
	// Selective debug info stripping
	// ============================================================================

	/// Strip debug info only from the given function while preserving it
	/// on all other functions in the module.
	/// This is useful when obfuscating selected functions: the obfuscated
	/// functions lose debug info (which would be misleading), but non-obfuscated
	/// functions retain full debuggability.
	void stripDebugInfoFromFunction(Function& F);

	/// Attach a "synthetic" debug location to instructions that lack one.
	/// Some obfuscation passes create new instructions without debug locations,
	/// which can cause assertion failures in some backends or debug info
	/// consumers. This function assigns a minimal debug location (line 0,
	/// column 0, same scope as the function) to such instructions.
	void assignSyntheticDebugLocs(Function& F);

	// ============================================================================
	// Pass: ObfStripDebugPass
	//
	// A function pass that strips debug info from obfuscated functions.
	// Controlled by -obf-strip-debug CLI flag.
	// ============================================================================

	class ObfStripDebugPass : public PassInfoMixin<ObfStripDebugPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return false; }
	};

} // namespace llvm::obf