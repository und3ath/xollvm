#include "llvm/Transforms/Obfuscator/ADec/Technique.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#define DEBUG_TYPE "adec"
STATISTIC(ADecStackSlots, "Fake stack-frame pollution slots");

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

class StackPollutionTechnique final : public ADecTechnique {
public:
	llvm::StringRef name() const override { return "stackPollution"; }

	bool supportsTarget(const llvm::Triple&) const override { return true; }

	bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const override {
		return Cfg.enableStackPollution;
	}

	// Stack pollution ignores the budget — it emits a fixed number of slots
	// driven by strength. Returns 0 so it doesn't compete for the per-tech
	// budget pool (matches pre-refactor behavior where it ran unconditionally).
	unsigned run(ADecCtx& Ctx, unsigned /*Budget*/) override {
		llvm::LLVMContext& C = Ctx.F.getContext();
		llvm::BasicBlock& Entry = Ctx.F.getEntryBlock();
		llvm::IRBuilder<> B(&*Entry.getFirstInsertionPt());

		llvm::Type* I32 = llvm::Type::getInt32Ty(C);
		llvm::Type* I64 = llvm::Type::getInt64Ty(C);
		llvm::Type* DblTy = llvm::Type::getDoubleTy(C);
		llvm::Type* I8Ty = llvm::Type::getInt8Ty(C);
		llvm::Type* I8Arr = llvm::ArrayType::get(I8Ty, 16);

		unsigned EffStrength = Ctx.Cfg.effectiveStrength(name());
		unsigned NumSlots = 2 + EffStrength;

		struct SlotSpec { llvm::Type* Ty; std::string Name; };
		llvm::SmallVector<SlotSpec, 8> Specs;
		Specs.push_back({ I32,   Ctx.prefixed("stk.i32") });
		Specs.push_back({ I64,   Ctx.prefixed("stk.i64") });
		Specs.push_back({ DblTy, Ctx.prefixed("stk.dbl") });
		Specs.push_back({ I8Arr, Ctx.prefixed("stk.buf") });
		Specs.push_back({ I32,   Ctx.prefixed("stk.cnt") });
		Specs.push_back({ I64,   Ctx.prefixed("stk.ptr") });

		for (unsigned i = 0; i < NumSlots && i < Specs.size(); ++i) {
			llvm::AllocaInst* AI =
			    B.CreateAlloca(Specs[i].Ty, nullptr, Specs[i].Name);
			AI->setAlignment(llvm::Align(8));

			uint64_t Val = Ctx.StackRng.u64();
			llvm::Value* InitVal;
			if (Specs[i].Ty == DblTy)
				InitVal = llvm::ConstantFP::get(DblTy, (double)(Val & 0xFFFF));
			else if (Specs[i].Ty == I8Arr) {
				llvm::AllocaInst* StoreSlot =
				    B.CreateAlloca(I64, nullptr, Ctx.prefixed("stk.i64"));
				auto* St =
				    B.CreateStore(llvm::ConstantInt::get(I64, Val), StoreSlot);
				St->setVolatile(true);
				++ADecStackSlots;
				continue;
			}
			else {
				unsigned BW = Specs[i].Ty->getIntegerBitWidth();
				uint64_t Masked = (BW < 64) ? (Val & ((uint64_t(1) << BW) - 1)) : Val;
				InitVal = llvm::ConstantInt::get(Specs[i].Ty, Masked);
			}

			auto* St = B.CreateStore(InitVal, AI);
			St->setVolatile(true);

			if (EffStrength >= 2) {
				auto* Rd = B.CreateLoad(Specs[i].Ty, AI, Ctx.prefixed("stk.rd"));
				Rd->setVolatile(true);
			}

			++ADecStackSlots;
		}

		return 0;
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecTechnique> makeStackPollutionTechnique() {
	return std::make_unique<StackPollutionTechnique>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
