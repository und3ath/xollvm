#pragma once
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContext.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

namespace llvm {
namespace obf {
namespace adec {

class GadgetPool;  // forward decl — full def in ADec/GadgetPool.h

// Single inline-asm gadget. Populated by built-in per-arch tables today
// (Phase A) and by JSON-loaded user pools in Phase B.
struct GadgetSpec {
	llvm::StringRef Name;       // identifier (built-in: short, user: from JSON "name")
	llvm::StringRef Arch;       // "x86_64", "aarch64", ...
	llvm::StringRef Category;   // "anti-disasm", "anti-trace", "desync"
	unsigned Weight = 1;        // selection bias (higher = picked more often)
	llvm::StringRef Clobbers;   // raw clobber list (already-formatted "~{...},~{...}")
	llvm::StringRef Body;       // raw asm body (passed verbatim to InlineAsm::get)
};

// Shared runtime context for every ADec technique.
// Lives on the stack for the duration of a single function's pass run.
struct ADecCtx : llvm::obf::FuncPassCtx {
	llvm::AntiDecompilerConfig Cfg;
	llvm::FunctionObfContext& FOC;

	llvm::obf::OpaqueUtils Opaque;

	// Sub-RNGs, forked per concern so reseeding stays stable.
	llvm::obf::Rng SelectRng;
	llvm::obf::Rng GadgetRng;
	llvm::obf::Rng StackRng;
	llvm::obf::Rng DecoyRng;
	llvm::obf::Rng CallRng;
	llvm::obf::Rng AliasRng;
	llvm::obf::Rng ShuffleRng;

	// Cached target info
	bool IsX86_64 = false;
	bool IsAArch64 = false;

	// Externally-owned gadget pool (driver constructs, Ctx borrows).
	// Null on arches without a built-in backend (e.g. unknown triple).
	const GadgetPool* Pool = nullptr;

	// IR-name prefix used by all techniques. Default "adec".
	// User-tunable via -adec-prefix CLI.
	std::string Prefix;

	// When true, payload constants (decoy mixers, etc.) come from RNG
	// instead of hard-coded literals.
	bool RandomizeConsts = false;

	ADecCtx(llvm::Function& F, llvm::FunctionAnalysisManager& AM,
	        const llvm::AntiDecompilerConfig& C,
	        llvm::FunctionObfContext& Foc,
	        const GadgetPool* P,
	        llvm::StringRef NamePrefix,
	        bool RandConsts);

	// Build a prefixed IR name: "<Prefix>.<suffix>", e.g. "adec.ibr.slot".
	std::string prefixed(llvm::StringRef Suffix) const {
		std::string Out;
		Out.reserve(Prefix.size() + 1 + Suffix.size());
		Out.append(Prefix);
		Out.push_back('.');
		Out.append(Suffix.data(), Suffix.size());
		return Out;
	}
};

} // namespace adec
} // namespace obf
} // namespace llvm
