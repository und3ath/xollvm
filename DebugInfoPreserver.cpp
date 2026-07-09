// ============================================================================
// DebugInfoPreserver.cpp — Debug info preservation and stripping
// ============================================================================

#include "llvm/Transforms/Obfuscator/DebugInfoPreserver.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

using namespace llvm;

// The -obf-strip-debug option is defined once in ObfuscationOptions.cpp and
// declared `extern llvm::cl::opt<bool> ObfStripDebug;` in ObfuscationOptions.h
// (included above). Defining a second cl::opt with the same name here caused a
// duplicate "Option 'obf-strip-debug' registered more than once" abort whenever
// all TUs are linked wholesale (e.g. the loadable plugin build); in the in-tree
// static library it was masked only because this object was dropped when
// unreferenced. Use the shared option below via `llvm::ObfStripDebug`.

namespace llvm::obf {

	// ============================================================================
	// propagateDebugLocToRange
	// ============================================================================
	void propagateDebugLocToRange(const Instruction* Src,
		BasicBlock::iterator Begin,
		BasicBlock::iterator End) {
		if (!Src)
			return;
		DebugLoc DL = Src->getDebugLoc();
		if (!DL)
			return;

		for (auto It = Begin; It != End; ++It) {
			if (!It->getDebugLoc())
				It->setDebugLoc(DL);
		}
	}

	// ============================================================================
	// propagateDebugLocToBlock
	// ============================================================================
	void propagateDebugLocToBlock(BasicBlock* NewBB, const BasicBlock* OrigBB) {
		if (!NewBB || !OrigBB)
			return;

		DebugLoc DL = findBestDebugLoc(OrigBB);
		if (!DL)
			return;

		for (Instruction& I : *NewBB) {
			if (!I.getDebugLoc())
				I.setDebugLoc(DL);
		}
	}

	// ============================================================================
	// findBestDebugLoc
	// ============================================================================
	DebugLoc findBestDebugLoc(const BasicBlock* BB) {
		if (!BB)
			return DebugLoc();

		for (const Instruction& I : *BB) {
			if (isa<PHINode>(&I))
				continue;
			if (I.isDebugOrPseudoInst())
				continue;
			if (I.getDebugLoc())
				return I.getDebugLoc();
		}

		// Fallback: try the terminator
		if (BB->getTerminator() && BB->getTerminator()->getDebugLoc())
			return BB->getTerminator()->getDebugLoc();

		return DebugLoc();
	}

	// ============================================================================
	// setBuilderDebugLoc
	// ============================================================================
	void setBuilderDebugLoc(IRBuilder<>& B, const BasicBlock* RefBB) {
		DebugLoc DL = findBestDebugLoc(RefBB);
		if (DL)
			B.SetCurrentDebugLocation(DL);
	}

	// ============================================================================
	// stripDebugInfoFromFunction
	// ============================================================================
	void stripDebugInfoFromFunction(Function& F) {
		// Remove debug locations from all instructions
		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				if (I.getDebugLoc())
					I.setDebugLoc(DebugLoc());
			}
		}

		// Remove debug-info-related intrinsic calls (llvm.dbg.*)
		SmallVector<Instruction*, 16> ToErase;
		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				if (I.isDebugOrPseudoInst())
					ToErase.push_back(&I);
			}
		}
		for (Instruction* I : ToErase)
			I->eraseFromParent();

		// Remove the function's subprogram reference to avoid stale metadata
		// (but keep the subprogram in the module CU for stack traces).
		// Actually, removing the SP would break stack unwinding. Instead, we
		// just clear the instruction-level locations.
	}

	// ============================================================================
	// assignSyntheticDebugLocs
	// ============================================================================
	void assignSyntheticDebugLocs(Function& F) {
		// Find the function's debug subprogram
		DISubprogram* SP = F.getSubprogram();
		if (!SP)
			return;

		// Create a synthetic location at line 0 (compiler-generated)
		DebugLoc SyntheticLoc =
			DILocation::get(F.getContext(), 0, 0, SP);

		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				if (!I.getDebugLoc() && !I.isDebugOrPseudoInst()) {
					I.setDebugLoc(SyntheticLoc);
				}
			}
		}
	}

	// ============================================================================
	// ObfStripDebugPass
	// ============================================================================
	PreservedAnalyses ObfStripDebugPass::run(Function& F,
		FunctionAnalysisManager& AM) {
		if (!ObfStripDebug)
			return PreservedAnalyses::all();

		if (F.isDeclaration())
			return PreservedAnalyses::all();

		// Only strip debug info from functions that were actually obfuscated
		const auto& Cache = getObfCache(F, AM);
		const auto& Cfg = Cache.getConfig(F);
		if (Cfg.passes.empty())
			return PreservedAnalyses::all();

		if (ObfVerbose)
			errs() << "[debug] Stripping debug info from obfuscated function: "
			<< F.getName() << "\n";

		stripDebugInfoFromFunction(F);

		PreservedAnalyses PA = PreservedAnalyses::all();
		// Debug info stripping doesn't change CFG or analyses
		return PA;
	}

} // namespace llvm::obf