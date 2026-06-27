#include "llvm/Transforms/Obfuscator/ADec/ArchBackend.h"

namespace llvm {
namespace obf {
namespace adec {

std::vector<std::unique_ptr<ADecArchBackend>> buildArchBackendRegistry() {
	std::vector<std::unique_ptr<ADecArchBackend>> R;
	R.push_back(makeX86_64Backend());
	R.push_back(makeAArch64Backend());
	return R;
}

const ADecArchBackend*
selectBackend(const llvm::Triple& T,
              const std::vector<std::unique_ptr<ADecArchBackend>>& Registry) {
	for (const auto& B : Registry)
		if (B->matches(T))
			return B.get();
	return nullptr;
}

} // namespace adec
} // namespace obf
} // namespace llvm
