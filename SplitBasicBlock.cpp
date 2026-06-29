#include "llvm/Transforms/Obfuscator/SplitBasicBlock.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/EHUtils.h"


#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Local.h" 


#include <algorithm>
#include <regex>
#include <unordered_map>

using namespace llvm;
using namespace std;

#define DEBUG_TYPE "split"

STATISTIC(Split, "Basicblock splitted");

namespace {

	struct SplitCtx;
	struct SplitImpl final
	{
		static SplitConfig getSplitConfig(Function& F, FunctionAnalysisManager& AM);
		static bool isSplitEligible(const FunctionObfContext& Ctx, raw_ostream* Reason = nullptr);
		static bool containsPHI(BasicBlock* b);
		static bool hasMustTailCall(BasicBlock* BB);
		static bool canSplitAt(Instruction* I);
		static void shuffle(std::vector<int>& vec, llvm::obf::Rng& R);
		static void doSplit(Function& F, int split_num, llvm::obf::Rng& ShuffleRng);
	};


	struct SplitCtx : llvm::obf::FuncPassCtx {
		SplitConfig Cfg;
		FunctionObfContext& FOC;
		llvm::obf::Rng ShuffleRng;

		SplitCtx(Function& F, FunctionAnalysisManager& AM)
			: FuncPassCtx(F, AM, "split"),
			Cfg(SplitImpl::getSplitConfig(F, AM)),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)),
			ShuffleRng(R.fork("shuffle")) {
		}
	};

	SplitConfig SplitImpl::getSplitConfig(Function& F, FunctionAnalysisManager& AM) {
		const ObfuscationConfig obfConfig = getObfConfig(F, AM);

		auto bcfPassConfig = obfConfig.getPassConfig("split");
		if (!bcfPassConfig.has_value()) {
			// Not enabled
			SplitConfig cfg;
			cfg.enable = false;
			return cfg;
		}

		SplitConfig cfg = SplitConfig::fromPassConfig(*bcfPassConfig);

		if (!cfg.validate()) {
			if (ObfVerbose) {
				errs() << "BCF: Invalid configuration for function " << F.getName()
					<< ", disabling pass\n";
			}
			cfg.enable = false;
		}

		return cfg;
	}

	bool SplitImpl::isSplitEligible(const FunctionObfContext& Ctx, raw_ostream* Reason) {
		// NOTE: HasInvoke is NOT rejected at the function level.
		// Block-level checks (line ~190) skip invoke-terminated blocks because
		// splitBasicBlock doesn't update PHIs in invoke successors.
		// Non-invoke blocks in functions with invoke can still be split safely.
		if (Ctx.HasIndirectBr) { if (Reason) *Reason << "indirectbr present"; return false; }
		if (Ctx.HasCallBr) { if (Reason) *Reason << "callbr present"; return false; }
		if (Ctx.HasMustTail) { if (Reason) *Reason << "musttail present"; return false; }
		return true;
	}

	bool SplitImpl::containsPHI(BasicBlock* b) {
		for (BasicBlock::iterator I = b->begin(), IE = b->end(); I != IE; ++I) {
			if (isa<PHINode>(I)) {
				return true;
			}
		}
		return false;
	}

	bool SplitImpl::hasMustTailCall(BasicBlock* BB) {
		for (Instruction& I : *BB) {
			if (auto* CI = dyn_cast<CallInst>(&I)) {
				if (CI->isMustTailCall())
					return true;
			}
		}
		return false;
	}

	bool SplitImpl::canSplitAt(Instruction* I) {
		if (!I)
			return false;
		// Never split at terminators or PHIs.

		if (I->isTerminator() || isa<PHINode>(I))
			return false;

		// Avoid EH pads / EH constructs.
		if (I->isEHPad())
			return false;

		// Avoid splitting around musttail: musttail call must be immediately
		// before ret.
		if (auto* Prev = I->getPrevNode()) {
			if (auto* CI = dyn_cast<CallInst>(Prev)) {
				if (CI->isMustTailCall())
					return false;
			}
		}

		// Avoid splitting in the middle of certain intrinsics if desired.
		if (isa<DbgInfoIntrinsic>(I))
			return false;

		return true;
	}

	void SplitImpl::shuffle(std::vector<int>& vec, llvm::obf::Rng& R) {
		// Fisher�Yates
		for (size_t i = vec.size(); i > 1; --i) {
			size_t j = (size_t)R.range((uint32_t)i); // 0..i-1
			std::swap(vec[i - 1], vec[j]);
		}
	}

	void SplitImpl::doSplit(Function& F, int split_num, llvm::obf::Rng& ShuffleRng)
	{

		// Phase2: budgets and safety gates
		const unsigned MinBlockSize = 4;
		const unsigned MaxSplitsPerFunction = 200;
		unsigned TotalSplits = 0;

		std::vector<BasicBlock*> origBB;
		const int RequestedSplits = split_num;
		BasicBlock* EntryBB = &F.getEntryBlock();

		// Save all basic blocks
		for (Function::iterator I = F.begin(), IE = F.end(); I != IE; ++I) {
			origBB.push_back(&*I);
		}

		for (std::vector<BasicBlock*>::iterator I = origBB.begin(),
			IE = origBB.end();
			I != IE; ++I) {
			BasicBlock* curr = *I;

			if (TotalSplits >= MaxSplitsPerFunction)
				break;

			// Never split the entry block. User-declared allocas live in
			// entry and must dominate their uses across the function. If
			// a later pass (flattening, bcf) pulls the split fragment of
			// entry into a dispatcher case, those allocas lose dominance
			// because they no longer execute unconditionally.
			if (curr == EntryBB)
				continue;

			int splitN = RequestedSplits;

			if (curr->size() < MinBlockSize || containsPHI(curr)) {
				continue;
			}

			// Skip EH pads
			Instruction* FirstNonPHI = curr->getFirstNonPHI();
			if (FirstNonPHI && FirstNonPHI->isEHPad())
				continue;

			// Phase 1.2: Also skip blocks inside EH regions
			if (llvm::obf::isInEHRegion(curr))
				continue;
			

			// Skip invoke/callbr terminators
			if (isa<InvokeInst>(curr->getTerminator()) ||
				isa<CallBrInst>(curr->getTerminator()))
				continue;

			// Skip musttail hazards
			if (hasMustTailCall(curr))
				continue;

			// Check splitN and current BB size
			// Fix overflow
			if ((size_t)splitN >= curr->size()) {
				splitN = curr->size() - 1;
			}

			// Generate candidate split points (phase2: only safe points, never
			// terminator)
			std::vector<int> test;

			unsigned Idx = 0;
			for (Instruction& Inst : *curr) {
				if (Idx > 0 && Idx < curr->size() - 1) {
					if (canSplitAt(&Inst))
						test.push_back((int)Idx);
				}
				++Idx;
			}

			if (test.empty())
				continue;

			if (splitN > (int)test.size()) splitN = (int)test.size();
			if (splitN <= 0) continue;

			// Shuffle
			if (test.size() != 1) {
				shuffle(test, ShuffleRng);
				std::sort(test.begin(), test.begin() + splitN);

			}



			// Split

			BasicBlock* toSplit = curr;
			int last = 0;
			for (int i = 0; i < splitN; ++i) {
				int delta = test[i] - last;
				last = test[i];
				if (delta <= 0)
					continue;


				if (toSplit->size() < 2)
					continue;

				BasicBlock::iterator it = toSplit->begin();
				std::advance(it, delta);
				if (it == toSplit->end())
					continue;

				if (it->isTerminator() || isa<PHINode>(&*it))
					continue;

				toSplit = toSplit->splitBasicBlock(it, toSplit->getName() + ".split");

				++TotalSplits;
				if (TotalSplits >= MaxSplitsPerFunction)
					break;
			}

			++Split;
		}
	}
} // namespace

PreservedAnalyses SplitBasicBlockPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration())
		return PreservedAnalyses::all();

	SplitCtx Ctx(F, AM);
	if (!Ctx.Cfg.enable)
		return PreservedAnalyses::all();


	{
		std::string R;
		raw_string_ostream OS(R);
		if (!SplitImpl::isSplitEligible(Ctx.FOC, &OS)) {
			if (ObfVerbose)
				errs() << "[split] Skipping: " << F.getName() << " (" << OS.str() << ")\n";
			llvm::obf::recordObfPassSkip(Ctx.FOC, "split",
				R.empty() ? "ineligible" : R);
			return PreservedAnalyses::all();

		}
	}


	if (ObfVerbose) {
		errs() << "[+] Running split pass on: " << F.getName() << "\n";
		errs() << "    cfg->num=" << Ctx.Cfg.num << "\n";
	}

	if (!((Ctx.Cfg.num > 1) && (Ctx.Cfg.num <= 10))) {
		if (ObfVerbose)
			errs() << "Split application basic block percentage -split_num=x must be 1 < x <= 10";
		llvm::obf::recordObfPassSkip(Ctx.FOC, "split", "invalid_num_param");
		return PreservedAnalyses::all();
	}

	SplitImpl::doSplit(F, Ctx.Cfg.num, Ctx.ShuffleRng);
	return PreservedAnalyses::none();
}
