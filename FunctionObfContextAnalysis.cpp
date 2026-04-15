#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Attributes.h"
#include "llvm/Support/CommandLine.h"

#include "llvm/Transforms/Obfuscator/EHUtils.h"
#include <algorithm>
#include <functional>

using namespace llvm;

AnalysisKey FunctionObfContextAnalysis::Key;

static cl::opt<bool> ObfDebug("obf-debug", cl::desc("Enable obfuscator debug"),
	cl::init(false));

FunctionObfContextAnalysis::Result
FunctionObfContextAnalysis::run(Function& F, FunctionAnalysisManager& AM) {

	auto Ctx = std::make_unique<FunctionObfContext>(F, ObfDebug);

	if (F.isDeclaration())
		return Ctx;

	Ctx->HasNaked = F.hasFnAttribute(Attribute::Naked);

	// Cache arguments
	for (Argument& Arg : F.args())
		Ctx->Arguments.push_back(&Arg);

	// Assign stable Block IDs
	uint32_t BlockID = 1;
	for (BasicBlock& BB : F)
		Ctx->BlockIDs[&BB] = BlockID++;

	// Collect structural info
	for (BasicBlock& BB : F) {
		++Ctx->NumBlocks;

		for (Instruction& I : BB) {
			++Ctx->NumInsts;

			if (I.isEHPad())
				Ctx->HasEHPad = true;

			if (auto* CB = dyn_cast<CallBase>(&I)) {
				++Ctx->NumCalls;
				if (!CB->getCalledFunction())
					Ctx->HasIndirectCalls = true;

				if (CB->isMustTailCall())
					Ctx->HasMustTail = true;

				if (CB->isInlineAsm())
					Ctx->HasInlineAsm = true;

				if (isa<CallBrInst>(&I))
					Ctx->HasCallBr = true;

				if (CB->isConvergent())
					Ctx->HasConvergentCalls = true;
			}

			if (auto* AI = dyn_cast<AllocaInst>(&I))
				Ctx->StackAllocas.push_back(AI);


			if (isa<InvokeInst>(I))
				Ctx->HasInvoke = true;

			if (isa<IndirectBrInst>(I))
				Ctx->HasIndirectBr = true;


			if (isa<SwitchInst>(I))
				Ctx->HasSwitch = true;

			if (isa<CatchSwitchInst>(&I))
				Ctx->HasCatchSwitch = true;
			if (isa<CleanupPadInst>(&I))
				Ctx->HasCleanupPad = true;
			if (isa<CatchPadInst>(&I))
				Ctx->HasCatchPad = true;


			if (isa<ReturnInst>(I) || isa<UnreachableInst>(I))
				++Ctx->NumExits;
		}
	}




	{
		auto& LI = AM.getResult<LoopAnalysis>(F);
		unsigned MaxDepth = 0;
		unsigned NumLoops = 0;

		std::function<void(Loop*, unsigned)> Visit = [&](Loop* L, unsigned Depth)
			{
				if (!L) return;

				++NumLoops;
				MaxDepth = std::max(MaxDepth, Depth);
				for (Loop* SL : L->getSubLoops())
					Visit(SL, Depth + 1);
			};

		for (Loop* L : LI)
			Visit(L, 1);

		Ctx->NumLoops = NumLoops;
		Ctx->MaxLoopDepth = MaxDepth;
	}




	for (BasicBlock& BB : F) {
		if (BB.isEHPad())
			++Ctx->NumEHPads;
		else if (!llvm::obf::isInEHRegion(&BB))
			++Ctx->NumNormalBlocks;

	}





	// Entropy placeholders
	if (!Ctx->StackAllocas.empty())
		Ctx->EntropySources.push_back(Ctx->StackAllocas.front());

	if (!Ctx->Arguments.empty())
		Ctx->EntropySources.push_back(Ctx->Arguments.front());




	return Ctx;
}
