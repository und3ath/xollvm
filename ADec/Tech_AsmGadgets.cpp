#include "llvm/Transforms/Obfuscator/ADec/ArchBackend.h"
#include "llvm/Transforms/Obfuscator/ADec/GadgetPool.h"
#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecAsmGadgets, "Inline ASM anti-disasm gadgets inserted");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

// Pick a gadget by weight. Returns index into Gadgets.
static unsigned weightedPick(llvm::ArrayRef<GadgetSpec> Gadgets,
                             llvm::obf::Rng& R) {
	uint64_t Total = 0;
	for (const auto& G : Gadgets)
		Total += G.Weight;
	if (Total == 0)
		return R.range((uint32_t)Gadgets.size());
	uint64_t Pick = ((uint64_t)R.u32() << 32 | R.u32()) % Total;
	uint64_t Acc = 0;
	for (unsigned i = 0; i < Gadgets.size(); ++i) {
		Acc += Gadgets[i].Weight;
		if (Pick < Acc)
			return i;
	}
	return (unsigned)Gadgets.size() - 1;
}

class AsmGadgetsTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "asmGadgets"; }

	bool supportsTarget(const llvm::Triple& T) const override {
		return (T.isX86() && T.isArch64Bit()) || T.isAArch64();
	}

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableAsmAntiDisasm;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		if (!Ctx.Pool || Ctx.Pool->empty())
			return 0;

		llvm::ArrayRef<GadgetSpec> Gadgets = Ctx.Pool->gadgets();
		llvm::StringRef DefaultClob = Ctx.Pool->defaultClobbers();

		llvm::LLVMContext& C = Ctx.F.getContext();
		llvm::FunctionType* VoidFnTy =
		    llvm::FunctionType::get(llvm::Type::getVoidTy(C), false);

		llvm::SmallVector<llvm::Instruction*, 64> InsertPts;
		for (llvm::BasicBlock& BB : Ctx.F) {
			if (&BB == &Ctx.F.getEntryBlock())
				continue;
			if (BB.isEHPad())
				continue;

			for (auto It = BB.getFirstNonPHI()->getIterator(),
			          E = BB.end(); It != E; ++It) {
				llvm::Instruction* I = &*It;
				if (I->isTerminator())
					break;
				if (llvm::isa<llvm::PHINode>(I) ||
				    llvm::isa<llvm::LandingPadInst>(I))
					continue;
				InsertPts.push_back(I);
			}
		}

		if (InsertPts.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<llvm::Instruction*>(
		    InsertPts.data(), InsertPts.size()));

		int EffProb = Ctx.Cfg.effectiveProb(name());

		unsigned Inserted = 0;
		for (llvm::Instruction* IP : InsertPts) {
			if (Inserted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			unsigned Variant = weightedPick(Gadgets, Ctx.GadgetRng);
			const GadgetSpec& G = Gadgets[Variant];

			llvm::StringRef Clob = G.Clobbers.empty() ? DefaultClob : G.Clobbers;

			llvm::InlineAsm* IA = llvm::InlineAsm::get(
			    VoidFnTy, G.Body, Clob,
			    /*hasSideEffects=*/true, /*isAlignStack=*/false);

			llvm::CallInst::Create(IA, {}, "", IP);

			++Inserted;
			++ADecAsmGadgets;
		}

		return Inserted;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeAsmGadgetsTechnique() {
	return std::make_unique<AsmGadgetsTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
