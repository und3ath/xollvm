#include "llvm/Transforms/Obfuscator/ADec/Technique.h"

namespace llvm {
namespace obf {
namespace adec {

// Registration order:
//   Phase A (original):
//     1. stackPollution        (always-on, ignores budget)
//     2. asmGadgets
//     3. indirectBr
//     4. callTrampoline
//     5. aliasConfusion
//     6. deadDecoy             (last — splits blocks)
//   Phase C additions (off by default, opt-in via config/CLI):
//     7. constLaunder          (operand rewrite — must run before block
//                               splitters and before rdtsc/fakeLoop so
//                               the laundered loads are already in place
//                               when those techs scan instructions)
//     8. fakeLoop              (block-splitter — runs near the end)
//     9. rdtscStretch          (insertion-point scan — after constLaunder)
std::vector<std::unique_ptr<ADecTechnique>> buildTechniqueRegistry() {
	std::vector<std::unique_ptr<ADecTechnique>> R;
	R.push_back(makeStackPollutionTechnique());
	R.push_back(makeAsmGadgetsTechnique());
	R.push_back(makeConstLaunderTechnique());
	R.push_back(makeRdtscStretchTechnique());
	R.push_back(makeIndirectBrTechnique());
	R.push_back(makeCallTrampolineTechnique());
	R.push_back(makeAliasConfusionTechnique());
	R.push_back(makeDeadDecoyTechnique());
	R.push_back(makeFakeLoopTechnique());
	return R;
}

} // namespace adec
} // namespace obf
} // namespace llvm
