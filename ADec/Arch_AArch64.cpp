#include "llvm/Transforms/Obfuscator/ADec/ArchBackend.h"

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

// AArch64 anti-disassembly gadgets.
//
// AArch64 uses fixed 4-byte instructions, so overlapping isn't possible.
// Instead we branch over data words that decode as valid but misleading
// instructions, confusing CFG recovery and data-flow analysis.
static const GadgetSpec kAArch64Builtin[] = {
	// branch over fake stack adjustment
	{"a64.fake.sub.sp",  "aarch64", "anti-disasm", 1, "", "b 1f\n.4byte 0xd10043ff\n1:"},
	// branch over fake register save
	{"a64.fake.stp",     "aarch64", "anti-disasm", 1, "", "b 1f\n.4byte 0xa9bf7bfd\n1:"},
	// branch over fake load
	{"a64.fake.ldr",     "aarch64", "anti-disasm", 1, "", "b 1f\n.4byte 0xf9400000\n1:"},
	// branch over fake str (store register pair)
	{"a64.fake.stp2",    "aarch64", "anti-disasm", 1, "", "b 1f\n.4byte 0xa9007bfd\n1:"},
	// branch over two fake instructions (double-width data)
	{"a64.fake.dual",    "aarch64", "anti-disasm", 1, "", "b 1f\n.4byte 0xd10083ff\n.4byte 0xa9007bfd\n1:"},
	// branch over fake branch-link (confuses call-graph recovery)
	{"a64.fake.bl",      "aarch64", "anti-disasm", 1, "", "b 1f\n.4byte 0x94000001\n1:"},
};

class AArch64Backend final : public ADecArchBackend {
public:
	llvm::StringRef archName() const override { return "aarch64"; }

	bool matches(const llvm::Triple& T) const override {
		return T.isAArch64();
	}

	llvm::ArrayRef<GadgetSpec> builtinGadgets() const override {
		return kAArch64Builtin;
	}

	llvm::StringRef defaultClobbers() const override { return ""; }
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecArchBackend> makeAArch64Backend() {
	return std::make_unique<AArch64Backend>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
