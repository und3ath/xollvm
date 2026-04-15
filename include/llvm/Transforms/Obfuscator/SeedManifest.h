#pragma once
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"

namespace llvm::obf {

	inline void emitFnHeaderIfNeeded(Function& F, const ObfuscationAnnotationCache& Ann) {
		if (!llvm::ObfSeedManifest) return;

		if (F.getMetadata("obf.seed.header"))
			return;

		LLVMContext& C = F.getContext();
		F.setMetadata("obf.seed.header", MDNode::get(C, {}));

		// “master seed” = module seed (== -obf-seed when provided)
		errs() << "[obf] fn=" << F.getName()
			<< " master=" << Ann.ModuleSeed
			<< " fn_seed=" << Ann.getFunctionSeed(F)
			<< "\n";
	}

	inline void emitPassLine(Function& F,
		const ObfuscationAnnotationCache& Ann,
		StringRef PassId,
		uint64_t PassSeed,
		ArrayRef<std::pair<StringRef, uint64_t>> Subs) {
		if (!llvm::ObfSeedManifest && !llvm::ObfSeedManifestMD) return;

		emitFnHeaderIfNeeded(F, Ann);

		if (llvm::ObfSeedManifest) {
			errs() << "  " << PassId << ": seed=" << PassSeed;
			for (auto& KV : Subs)
				errs() << " " << KV.first << "=" << KV.second;
			errs() << "\n";
		}

		if (llvm::ObfSeedManifestMD) {
			LLVMContext& C = F.getContext();
			SmallVector<Metadata*, 16> Ops;

			Ops.push_back(MDString::get(C, PassId));
			Ops.push_back(ConstantAsMetadata::get(
				ConstantInt::get(Type::getInt64Ty(C), PassSeed)));

			for (auto& KV : Subs) {
				Ops.push_back(MDString::get(C, KV.first));
				Ops.push_back(ConstantAsMetadata::get(
					ConstantInt::get(Type::getInt64Ty(C), KV.second)));
			}

			std::string Key = ("obf.seed.manifest." + PassId).str();
			F.setMetadata(Key, MDNode::get(C, Ops));
		}
	}

} // namespace llvm::obf
