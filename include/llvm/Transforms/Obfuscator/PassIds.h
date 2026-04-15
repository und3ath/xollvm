#pragma once 

#include <string>
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"


namespace llvm::obf {


	inline llvm::ArrayRef<llvm::StringRef> allCanonicalPassIds() {
		static constexpr llvm::StringRef Ids[] = {
			"flattening", "bcf", "split", "substitution", "mba", "vcall",
			"strenc", "aes_stub", "sdiff", "adec", "shield", "vm"
		};
		return Ids;
	}

	inline std::string normalizePassId(llvm::StringRef In) {
		std::string S = In.lower();
		if (S == "sdiff")
			return "sdiff";
		if (S == "flattening" || S == "fla")
			return "flattening";
		if (S == "substitution" || S == "sub")
			return "substitution";
		if (S == "mba")
			return "mba";
		if (S == "bcf")
			return "bcf";
		if (S == "split")
			return "split";
		if (S == "vcall")
			return "vcall";
		if (S == "strenc")
			return "strenc";
		if (S == "aes_stub")
			return "aes_stub";
		if (S == "adec" || S == "antidecompiler" || S == "anti-decompiler")
			return "adec";
		if (S == "shield" || S == "antiopt" || S == "anti-opt")
			return "shield";
		if (S == "vm" || S == "virtualize" || S == "virt")
			return "vm";
		// Unknown stays unknown (validator will reject)
		return S;
	}

	inline bool isKnownCanonicalPassId(llvm::StringRef Canon) {
		for (auto P : allCanonicalPassIds())
			if (Canon == P) return true;

		return false;
	}

	inline bool isModuleOnlyPassId(llvm::StringRef Canon) {
		return Canon == "strenc" || Canon == "aes_stub";
	}
} // namespace llvm::obf