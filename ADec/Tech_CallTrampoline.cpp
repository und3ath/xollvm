#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecIndirectCalls, "Direct calls converted to indirect trampolines");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

static bool canConvertCall(llvm::CallInst* CI) {
	if (!CI)
		return false;

	llvm::Function* Callee = CI->getCalledFunction();
	if (!Callee)
		return false;

	if (Callee->isIntrinsic() || CI->isInlineAsm())
		return false;

	if (CI->isMustTailCall() || CI->isNoTailCall())
		return false;

	if (CI->getParent()->isEHPad())
		return false;

	if (Callee->isVarArg())
		return false;

	if (Callee->hasPersonalityFn())
		return false;

	return true;
}

class CallTrampolineTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "callTrampoline"; }

	bool supportsTarget(const llvm::Triple&) const override { return true; }

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableCallObfuscation;
	}

	unsigned run(ADecCtx& Ctx, unsigned Budget) override {
		llvm::SmallVector<llvm::CallInst*, 32> Cands;
		for (llvm::BasicBlock& BB : Ctx.F) {
			if (BB.isEHPad())
				continue;
			for (llvm::Instruction& I : BB) {
				if (auto* CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
					if (canConvertCall(CI))
						Cands.push_back(CI);
				}
			}
		}

		if (Cands.empty())
			return 0;

		Ctx.ShuffleRng.shuffle(llvm::MutableArrayRef<llvm::CallInst*>(
		    Cands.data(), Cands.size()));

		llvm::LLVMContext& C = Ctx.F.getContext();
		llvm::BasicBlock& Entry = Ctx.F.getEntryBlock();
		llvm::Type* PtrTy = llvm::PointerType::getUnqual(C);

		int EffProb = Ctx.Cfg.effectiveProb(name());

		unsigned Converted = 0;
		for (llvm::CallInst* CI : Cands) {
			if (Converted >= Budget)
				break;
			if (Ctx.SelectRng.range(100) >= (uint32_t)EffProb)
				continue;

			llvm::Function* Callee = CI->getCalledFunction();
			if (!Callee)
				continue;

			llvm::IRBuilder<> EntryB(&*Entry.getFirstInsertionPt());
			llvm::AllocaInst* FpSlot =
			    EntryB.CreateAlloca(PtrTy, nullptr, Ctx.prefixed("fp.slot"));

			llvm::IRBuilder<> B(CI);
			auto* St = B.CreateStore(Callee, FpSlot);
			St->setVolatile(true);

			auto* Fp = B.CreateLoad(PtrTy, FpSlot, Ctx.prefixed("fp.addr"));
			Fp->setVolatile(true);

			llvm::SmallVector<llvm::Value*, 8> Args;
			for (unsigned i = 0; i < CI->arg_size(); ++i)
				Args.push_back(CI->getArgOperand(i));

			llvm::CallInst* NewCI =
			    B.CreateCall(CI->getFunctionType(), Fp, Args);
			NewCI->setCallingConv(CI->getCallingConv());
			NewCI->setAttributes(CI->getAttributes());

			if (!CI->getType()->isVoidTy()) {
				CI->replaceAllUsesWith(NewCI);
				NewCI->takeName(CI);
			}

			CI->eraseFromParent();

			++Converted;
			++ADecIndirectCalls;
		}

		return Converted;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeCallTrampolineTechnique() {
	return std::make_unique<CallTrampolineTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
