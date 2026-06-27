#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecIndirectBrs, "Branches converted to indirectbr trampolines");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

static bool canConvertBranch(llvm::BranchInst* BI) {
	if (!BI || !BI->isUnconditional())
		return false;

	llvm::BasicBlock* BB = BI->getParent();
	if (BB == &BB->getParent()->getEntryBlock())
		return false;
	if (BB->isEHPad())
		return false;

	llvm::BasicBlock* Succ = BI->getSuccessor(0);
	if (Succ == BB)
		return false;

	return true;
}

static bool blockHasPhis(llvm::BasicBlock* BB) {
	return BB && !BB->empty() && llvm::isa<llvm::PHINode>(&BB->front());
}

class IndirectBrTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "indirectBr"; }

	bool supportsTarget(const llvm::Triple&) const override { return true; }

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableIndirectBr;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		llvm::SmallVector<llvm::BranchInst*, 32> Cands;
		for (llvm::BasicBlock& BB : Ctx.F) {
			auto* BI = llvm::dyn_cast<llvm::BranchInst>(BB.getTerminator());
			if (canConvertBranch(BI))
				Cands.push_back(BI);
		}

		if (Cands.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<llvm::BranchInst*>(
		    Cands.data(), Cands.size()));

		llvm::SmallVector<llvm::BasicBlock*, 16> DecoyPool;
		for (llvm::BasicBlock& BB : Ctx.F) {
			if (&BB == &Ctx.F.getEntryBlock())
				continue;
			if (!BB.isEHPad() && !blockHasPhis(&BB))
				DecoyPool.push_back(&BB);
		}

		llvm::LLVMContext& C = Ctx.F.getContext();
		llvm::BasicBlock& Entry = Ctx.F.getEntryBlock();
		llvm::Type* PtrTy = llvm::PointerType::getUnqual(C);

		int EffProb = Ctx.Cfg.effectiveProb(name());

		unsigned Converted = 0;
		for (llvm::BranchInst* BI : Cands) {
			if (Converted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			llvm::BasicBlock* Target = BI->getSuccessor(0);
			llvm::BasicBlock* SrcBB = BI->getParent();

			llvm::IRBuilder<> EntryB(&*Entry.getFirstInsertionPt());
			llvm::AllocaInst* Slot =
			    EntryB.CreateAlloca(PtrTy, nullptr, Ctx.prefixed("ibr.slot"));

			llvm::IRBuilder<> B(BI);
			llvm::Value* BA = llvm::BlockAddress::get(&Ctx.F, Target);
			auto* St = B.CreateStore(BA, Slot);
			St->setVolatile(true);

			auto* Ld = B.CreateLoad(PtrTy, Slot, Ctx.prefixed("ibr.addr"));
			Ld->setVolatile(true);

			unsigned NumDecoys =
			    std::min<unsigned>(3u, (unsigned)DecoyPool.size());
			auto* IBr =
			    llvm::IndirectBrInst::Create(Ld, 1 + NumDecoys, BI);
			IBr->addDestination(Target);

			unsigned Added = 0;
			for (unsigned i = 0;
			     i < DecoyPool.size() && Added < NumDecoys; ++i) {
				unsigned Pick =
				    Ctx.GadgetRng.range((uint32_t)DecoyPool.size());
				llvm::BasicBlock* Decoy = DecoyPool[Pick];
				if (Decoy == Target || Decoy == SrcBB)
					continue;
				if (blockHasPhis(Decoy))
					continue;
				IBr->addDestination(Decoy);
				++Added;
			}

			BI->eraseFromParent();

			++Converted;
			++ADecIndirectBrs;
		}

		return Converted;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeIndirectBrTechnique() {
	return std::make_unique<IndirectBrTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
