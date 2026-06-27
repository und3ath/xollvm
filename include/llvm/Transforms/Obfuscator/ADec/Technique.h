#pragma once
#include "llvm/ADT/StringRef.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Obfuscator/ADec/Types.h"
#include <memory>
#include <vector>

namespace llvm {
namespace obf {
namespace adec {

// Abstract interface implemented by each anti-decompiler technique.
// Driver walks the registry, asks each tech whether it is enabled +
// supports the target, then invokes run() with a budget.
class ADecTechnique {
public:
	virtual ~ADecTechnique() = default;

	// Stable short identifier. Used for budget keys, telemetry, and the
	// future -adec-techniques CLI whitelist (Phase B).
	virtual llvm::StringRef name() const = 0;

	// Targets this technique can emit valid code for.
	virtual bool supportsTarget(const llvm::Triple& T) const = 0;

	// Per-technique enable flag from AntiDecompilerConfig.
	virtual bool isEnabled(const llvm::AntiDecompilerConfig& Cfg) const = 0;

	// Apply transformation. Return number of sites mutated.
	// Budget == 0 is legal (e.g. always-on techniques that ignore the
	// budget pool, like stack pollution).
	virtual unsigned run(ADecCtx& Ctx, unsigned Budget) = 0;
};

// Concrete-tech factories. Each lives in its own .cpp under ADec/.
std::unique_ptr<ADecTechnique> makeAsmGadgetsTechnique();
std::unique_ptr<ADecTechnique> makeIndirectBrTechnique();
std::unique_ptr<ADecTechnique> makeDeadDecoyTechnique();
std::unique_ptr<ADecTechnique> makeStackPollutionTechnique();
std::unique_ptr<ADecTechnique> makeCallTrampolineTechnique();
std::unique_ptr<ADecTechnique> makeAliasConfusionTechnique();
std::unique_ptr<ADecTechnique> makeFakeLoopTechnique();
std::unique_ptr<ADecTechnique> makeRdtscStretchTechnique();
std::unique_ptr<ADecTechnique> makeConstLaunderTechnique();

// Registry of all built-in techniques in canonical execution order.
// Phase B will optionally filter via -adec-techniques=... whitelist.
std::vector<std::unique_ptr<ADecTechnique>> buildTechniqueRegistry();

} // namespace adec
} // namespace obf
} // namespace llvm
