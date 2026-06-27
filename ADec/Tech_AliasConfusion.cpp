#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/Utils.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecAliasPairs, "Pointer-alias confusion pairs");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

class AliasConfusionTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "aliasConfusion"; }

	bool supportsTarget(const llvm::Triple&) const override { return true; }

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableAliasConfusion;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		llvm::SmallVector<llvm::StoreInst*, 32> Cands;
		for (llvm::BasicBlock& BB : Ctx.F) {
			if (BB.isEHPad() || &BB == &Ctx.F.getEntryBlock())
				continue;
			for (llvm::Instruction& I : BB) {
				auto* SI = llvm::dyn_cast<llvm::StoreInst>(&I);
				if (!SI || SI->isVolatile() || SI->isAtomic())
					continue;
				if (!llvm::isa<llvm::AllocaInst>(SI->getPointerOperand()))
					continue;
				llvm::Type* ValTy = SI->getValueOperand()->getType();
				if (!ValTy->isIntegerTy() && !ValTy->isFloatingPointTy())
					continue;
				Cands.push_back(SI);
			}
		}

		if (Cands.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<llvm::StoreInst*>(
		    Cands.data(), Cands.size()));

		llvm::LLVMContext& C = Ctx.F.getContext();
		llvm::Type* I64 = llvm::Type::getInt64Ty(C);

		llvm::AllocaInst* ZeroSlot = llvm::obf::getOrCreateVolatileI32Slot(
		    Ctx.F, Ctx.prefixed("alias.slot"), Ctx.AliasRng);

		int EffProb = Ctx.Cfg.effectiveProb(name());

		unsigned Confused = 0;
		for (llvm::StoreInst* SI : Cands) {
			if (Confused >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			llvm::Value* OrigPtr = SI->getPointerOperand();
			llvm::IRBuilder<> B(SI);

			llvm::Value* PtrInt =
			    B.CreatePtrToInt(OrigPtr, I64, Ctx.prefixed("al.p2i"));

			llvm::Value* RuntimeZero = llvm::obf::makeRuntimeZero(
			    B, ZeroSlot, 64, Ctx.AliasRng, "adec.al");

			llvm::Value* Shifted =
			    B.CreateAdd(PtrInt, RuntimeZero, Ctx.prefixed("al.add"));
			llvm::Value* NewPtr = B.CreateIntToPtr(
			    Shifted, OrigPtr->getType(), Ctx.prefixed("al.p"));

			SI->setOperand(1, NewPtr);

			++Confused;
			++ADecAliasPairs;
		}

		return Confused;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeAliasConfusionTechnique() {
	return std::make_unique<AliasConfusionTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
