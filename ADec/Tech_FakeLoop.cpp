// Tech_FakeLoop.cpp — insert opaque-bounded fake loops with junk math.
//
// Before each selected non-EH, non-entry block we split, insert a header
// + body block, and route the original control flow through a loop that
// is opaque-bounded to exactly one iteration. The body performs volatile
// junk math that decompilers will track as live code, while the loop
// shape forces them to materialize an iteration variable that doesn't
// exist in the source.

#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Obfuscator/EHUtils.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecFakeLoops, "Opaque-bounded fake loops inserted");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

class FakeLoopTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "fakeLoop"; }

	bool supportsTarget(const llvm::Triple&) const override { return true; }

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableFakeLoop;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		llvm::SmallVector<llvm::BasicBlock*, 32> Blocks;
		for (llvm::BasicBlock& BB : Ctx.F) {
			if (&BB == &Ctx.F.getEntryBlock())
				continue;
			if (BB.isEHPad())
				continue;
			if (llvm::obf::isInEHRegion(&BB))
				continue;
			if (llvm::isa<llvm::InvokeInst>(BB.getTerminator()))
				continue;
			if (BB.size() < 2)
				continue;
			Blocks.push_back(&BB);
		}

		if (Blocks.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<llvm::BasicBlock*>(
		    Blocks.data(), Blocks.size()));

		llvm::LLVMContext& C = Ctx.F.getContext();
		llvm::Type* I32 = llvm::Type::getInt32Ty(C);

		int EffProb = Ctx.Cfg.effectiveProb(name());

		unsigned Inserted = 0;
		for (llvm::BasicBlock* BB : Blocks) {
			if (Inserted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			auto SplitIt = BB->getFirstNonPHIOrDbgOrLifetime();
			while (SplitIt != BB->end() && llvm::isa<llvm::AllocaInst>(&*SplitIt))
				++SplitIt;
			if (SplitIt == BB->end() || SplitIt->isTerminator())
				continue;

			llvm::BasicBlock* AfterBB =
			    BB->splitBasicBlock(SplitIt, Ctx.prefixed("fl.after"));

			llvm::BasicBlock* HeaderBB = llvm::BasicBlock::Create(
			    C, Ctx.prefixed("fl.h"), &Ctx.F, AfterBB);
			llvm::BasicBlock* BodyBB = llvm::BasicBlock::Create(
			    C, Ctx.prefixed("fl.b"), &Ctx.F, AfterBB);

			// Rewrite BB's auto-inserted branch to jump to HeaderBB instead.
			BB->getTerminator()->eraseFromParent();
			llvm::IRBuilder<> Bsrc(BB);
			Bsrc.CreateBr(HeaderBB);

			// HeaderBB: phi-driven counter.
			llvm::IRBuilder<> Bh(HeaderBB);
			llvm::PHINode* IV = Bh.CreatePHI(I32, 2, Ctx.prefixed("fl.iv"));
			IV->addIncoming(llvm::ConstantInt::get(I32, 0), BB);

			// Body: junk math + volatile sink + increment.
			llvm::Value* Mixer = Ctx.Opaque.opaqueI32Const(
			    Bh, Ctx.DecoyRng.u32() | 1u);
			llvm::Value* OpaqueBound = Ctx.Opaque.opaqueI32Const(Bh, 1u);
			llvm::Value* Cmp = Bh.CreateICmpULT(IV, OpaqueBound,
			                                   Ctx.prefixed("fl.cmp"));
			Bh.CreateCondBr(Cmp, BodyBB, AfterBB);

			llvm::IRBuilder<> Bb(BodyBB);
			llvm::Value* M1 = Bb.CreateXor(IV, Mixer, Ctx.prefixed("fl.x"));
			llvm::Value* M2 = Bb.CreateMul(
			    M1, llvm::ConstantInt::get(I32, Ctx.DecoyRng.u32() | 1u),
			    Ctx.prefixed("fl.m"));
			llvm::AllocaInst* SinkSlot = nullptr;
			{
				llvm::IRBuilder<> EntryB(
				    &*Ctx.F.getEntryBlock().getFirstInsertionPt());
				SinkSlot = EntryB.CreateAlloca(I32, nullptr,
				                               Ctx.prefixed("fl.sink"));
			}
			auto* St = Bb.CreateStore(M2, SinkSlot);
			St->setVolatile(true);

			llvm::Value* Next = Bb.CreateAdd(
			    IV, llvm::ConstantInt::get(I32, 1), Ctx.prefixed("fl.next"));
			Bb.CreateBr(HeaderBB);
			IV->addIncoming(Next, BodyBB);

			++Inserted;
			++ADecFakeLoops;
		}

		return Inserted;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeFakeLoopTechnique() {
	return std::make_unique<FakeLoopTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
