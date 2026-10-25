#pragma once
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassManager.h"

namespace llvm {
// LLVM 23 split BranchInst and made the required/optional pass policy explicit.
// Keep those API changes here so LLVM 21--23 retain their original behaviour.
template<class DerivedT>
using ObfPassInfoMixin =
#if LLVM_VERSION_MAJOR >= 23
    OptionalPassInfoMixin<DerivedT>;
#else
    PassInfoMixin<DerivedT>;
#endif

inline bool obfIsBranch(const Value* V) {
#if LLVM_VERSION_MAJOR >= 23
    return V && isa<CondBrInst, UncondBrInst>(V);
#else
    return V && isa<BranchInst>(V);
#endif
}
inline bool obfIsConditionalBranch(const Instruction* I) {
#if LLVM_VERSION_MAJOR >= 23
    return I && isa<CondBrInst>(I);
#else
    auto* B = dyn_cast_or_null<BranchInst>(I);
    return B && B->isConditional();
#endif
}
inline bool obfIsUnconditionalBranch(const Instruction* I) {
#if LLVM_VERSION_MAJOR >= 23
    return I && isa<UncondBrInst>(I);
#else
    auto* B = dyn_cast_or_null<BranchInst>(I);
    return B && B->isUnconditional();
#endif
}
inline Instruction* obfBranch(Instruction* I) {
    return obfIsBranch(I) ? I : nullptr;
}
inline const Instruction* obfBranch(const Instruction* I) {
    return obfIsBranch(I) ? I : nullptr;
}
inline Value* obfBranchCondition(Instruction* I) {
#if LLVM_VERSION_MAJOR >= 23
    return cast<CondBrInst>(I)->getCondition();
#else
    return cast<BranchInst>(I)->getCondition();
#endif
}
} // namespace llvm
