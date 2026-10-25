#include "llvm/Transforms/Obfuscator/LLVMCompat.h"
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

static bool canConvertBranch(llvm::Instruction* BI) {
	if (!BI || !llvm::obfIsUnconditionalBranch(BI))
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

class IndirectBrTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "indirectBr"; }

	bool supportsTarget(const llvm::Triple&) const override { return true; }

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableIndirectBr;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		llvm::SmallVector<llvm::Instruction*, 32> Cands;
		for (llvm::BasicBlock& BB : Ctx.F) {
			auto* BI = llvm::obfBranch(BB.getTerminator());
			if (canConvertBranch(BI))
				Cands.push_back(BI);
		}

		if (Cands.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<llvm::Instruction*>(
		    Cands.data(), Cands.size()));

		// A single statically-known BlockAddress trampoline is transparent
		// to stock -O2: the volatile load's value is still constant (it's
		// the only value ever stored to the slot), so instcombine/simplifycfg
		// const-propagate it straight through and fold the indirectbr back
		// into a direct branch, pruning the unreachable decoys. To survive
		// -O2 the branch must be a *runtime* choice between two live,
		// semantically-equivalent destinations: each just records which
		// side was taken (a distinct volatile store, so CSE/simplifycfg
		// cannot merge the two blocks) and then joins back to Target. The
		// join block takes over Target's incoming PHI edge from Source, so
		// correctness is unaffected regardless of which destination is
		// actually taken at runtime.

		llvm::LLVMContext& C = Ctx.F.getContext();
		llvm::BasicBlock& Entry = Ctx.F.getEntryBlock();
		llvm::Type* PtrTy = llvm::PointerType::getUnqual(C);
		llvm::Type* I64Ty = llvm::Type::getInt64Ty(C);
		llvm::Type* I8Ty = llvm::Type::getInt8Ty(C);
		llvm::Type* I1Ty = llvm::Type::getInt1Ty(C);

		int EffProb = Ctx.Cfg.effectiveProb(name());

		unsigned Converted = 0;
		for (llvm::Instruction* BI : Cands) {
			if (Converted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			llvm::BasicBlock* Source = BI->getParent();
			llvm::BasicBlock* Target = BI->getSuccessor(0);

			llvm::IRBuilder<> EntryB(&*Entry.getFirstInsertionPt());
			llvm::AllocaInst* Slot =
			    EntryB.CreateAlloca(PtrTy, nullptr, Ctx.prefixed("ibr.slot"));
			llvm::AllocaInst* Trace =
			    EntryB.CreateAlloca(I8Ty, nullptr, Ctx.prefixed("ibr.trace"));

			llvm::BasicBlock* Dest0 = llvm::BasicBlock::Create(
			    C, Ctx.prefixed("ibr.dest0"), &Ctx.F);
			llvm::BasicBlock* Dest1 = llvm::BasicBlock::Create(
			    C, Ctx.prefixed("ibr.dest1"), &Ctx.F);
			llvm::BasicBlock* Join = llvm::BasicBlock::Create(
			    C, Ctx.prefixed("ibr.join"), &Ctx.F);

			{
				llvm::IRBuilder<> DB(Dest0);
				auto* TraceSt = DB.CreateStore(
				    llvm::ConstantInt::get(I8Ty, 0), Trace);
				TraceSt->setVolatile(true);
				DB.CreateBr(Join);
			}
			{
				llvm::IRBuilder<> DB(Dest1);
				auto* TraceSt = DB.CreateStore(
				    llvm::ConstantInt::get(I8Ty, 1), Trace);
				TraceSt->setVolatile(true);
				DB.CreateBr(Join);
			}
			{
				llvm::IRBuilder<> JB(Join);
				JB.CreateBr(Target);
			}

			// PHI fixup: every incoming edge on Target that used to come
			// from Source now comes from Join (the value is unchanged --
			// it still dominates Join, since every path Source→Dest{0,1}
			// →Join passes through Source).
			for (llvm::PHINode& Phi : Target->phis())
				Phi.replaceIncomingBlockWith(Source, Join);

			llvm::IRBuilder<> B(BI);

			// Opaque runtime selector: derived from the (volatile-load
			// forced) slot's own address, not from a constant, so the
			// optimizer cannot fold the select or the indirectbr.
			llvm::Value* SlotInt =
			    B.CreatePtrToInt(Slot, I64Ty, Ctx.prefixed("ibr.entropy"));
			llvm::Value* Shifted =
			    B.CreateLShr(SlotInt, llvm::ConstantInt::get(I64Ty, 4));
			llvm::Value* Pick =
			    B.CreateTrunc(Shifted, I1Ty, Ctx.prefixed("ibr.pick"));
			llvm::Value* BA = B.CreateSelect(
			    Pick, llvm::BlockAddress::get(&Ctx.F, Dest1),
			    llvm::BlockAddress::get(&Ctx.F, Dest0), Ctx.prefixed("ibr.target"));

			auto* St = B.CreateStore(BA, Slot);
			St->setVolatile(true);

			auto* Ld = B.CreateLoad(PtrTy, Slot, Ctx.prefixed("ibr.addr"));
			Ld->setVolatile(true);

			auto* IBr = llvm::IndirectBrInst::Create(Ld, 2, BI->getIterator());
			IBr->addDestination(Dest0);
			IBr->addDestination(Dest1);

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
