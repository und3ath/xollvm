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

		// Decoy destinations cannot be picked from existing BBs: adding a
		// new edge SrcBB→ExistingBB can violate SSA dominance for any
		// value used downstream of ExistingBB whose definition is not on
		// every path through SrcBB. The runtime branch always lands on
		// the real Target (the slot is loaded with that BlockAddress), so
		// decoys exist only to keep `indirectbr` honest for the verifier
		// and to confuse static analysis. Use synthetic dead BBs
		// containing only `unreachable` — they have zero SSA operands
		// and zero successors, so they are always safe to list.

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

			llvm::IRBuilder<> EntryB(&*Entry.getFirstInsertionPt());
			llvm::AllocaInst* Slot =
			    EntryB.CreateAlloca(PtrTy, nullptr, Ctx.prefixed("ibr.slot"));

			llvm::IRBuilder<> B(BI);
			llvm::Value* BA = llvm::BlockAddress::get(&Ctx.F, Target);
			auto* St = B.CreateStore(BA, Slot);
			St->setVolatile(true);

			auto* Ld = B.CreateLoad(PtrTy, Slot, Ctx.prefixed("ibr.addr"));
			Ld->setVolatile(true);

			// Build N synthetic dead decoys (each = empty BB with
			// `unreachable`). These never execute (the loaded slot
			// holds Target's BlockAddress) but make the indirectbr
			// destination list non-trivial. Synthetic BBs have zero
			// SSA operands and zero successors, so they cannot
			// violate dominance regardless of where SrcBB sits in
			// the CFG.
			constexpr unsigned kNumDecoys = 3;
			auto* IBr =
			    llvm::IndirectBrInst::Create(Ld, 1 + kNumDecoys, BI);
			IBr->addDestination(Target);

			for (unsigned i = 0; i < kNumDecoys; ++i) {
				llvm::BasicBlock* Decoy = llvm::BasicBlock::Create(
				    C, Ctx.prefixed("ibr.decoy"), &Ctx.F);
				new llvm::UnreachableInst(C, Decoy);
				IBr->addDestination(Decoy);
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
