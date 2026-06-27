#include "llvm/Transforms/Obfuscator/ADec/ArchBackend.h"

using namespace llvm;
using namespace llvm::obf::adec;

namespace {

// x86_64 anti-disassembly gadgets.
//
// Each gadget is a short unconditional jmp that skips over bytes which,
// when decoded linearly, look like the start of a multi-byte instruction.
// This causes linear-sweep disassemblers (and recursive-descent ones that
// fall through) to desync their instruction stream.
static const GadgetSpec kX86_64Builtin[] = {
	// jmp +1, fake CALL prefix (linear scan eats 4 bytes as rel32 operand)
	{"x86.fakecall.rel32",   "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x01,0xe8"},
	// jmp +2, fake JZ near prefix (eats 4 bytes as rel32)
	{"x86.fakejz",           "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x02,0x0f,0x84"},
	// jmp +1, LOCK prefix (next insn gets illegal LOCK → decode confusion)
	{"x86.lockprefix",       "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x01,0xf0"},
	// jmp +3, fake REX.W + MOV imm64 prefix (eats 8 more bytes)
	{"x86.rex.movabs",       "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x03,0x48,0xb8,0xff"},
	// jmp +2, fake REP RET sequence (confuses AMD64 return prediction)
	{"x86.repret",           "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x02,0xf3,0xc3"},
	// jmp +1, VEX 3-byte prefix (eats 2 more bytes as VEX fields)
	{"x86.vex3",             "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x01,0xc4"},
	// jmp +2, fake JNZ near prefix
	{"x86.fakejnz",          "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x02,0x0f,0x85"},
	// jmp +4, fake CALL with partial modrm — linear scan misreads 4 bytes
	{"x86.fakecall.modrm",   "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x04,0xe8,0x00,0x00,0x00"},
	// jmp +3, fake LEA r64,[rip+disp32] prefix — common IDA pattern
	{"x86.fakelea",          "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x03,0x48,0x8d,0x05"},
	// jmp +2, fake 2-byte NOP prefix (0f 1f) — benign but desync
	{"x86.fakenop",          "x86_64", "anti-disasm", 1, "", ".byte 0xeb,0x02,0x0f,0x1f"},
};

class X86_64Backend final : public ADecArchBackend {
public:
	llvm::StringRef archName() const override { return "x86_64"; }

	bool matches(const llvm::Triple& T) const override {
		return T.isX86() && T.isArch64Bit();
	}

	llvm::ArrayRef<GadgetSpec> builtinGadgets() const override {
		return kX86_64Builtin;
	}

	llvm::StringRef defaultClobbers() const override {
		return "~{dirflag},~{fpsr},~{flags}";
	}
};

} // namespace

namespace llvm {
namespace obf {
namespace adec {

std::unique_ptr<ADecArchBackend> makeX86_64Backend() {
	return std::make_unique<X86_64Backend>();
}

} // namespace adec
} // namespace obf
} // namespace llvm
