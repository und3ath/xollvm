// ============================================================================
// TargetCompat.cpp — Cross-platform compatibility utilities
// ============================================================================

#include "llvm/Transforms/Obfuscator/TargetCompat.h"

using namespace llvm;

namespace llvm::obf {

	// ============================================================================
	// TargetInfo construction
	// ============================================================================

	TargetInfo TargetInfo::fromModule(const Module& M) {
		Triple T(M.getTargetTriple());
		return fromTriple(T);
	}

	TargetInfo TargetInfo::fromTriple(const Triple& T) {
		TargetInfo TI;

		// Architecture
		switch (T.getArch()) {
		case Triple::x86_64:
			TI.IsX86_64 = true;
			TI.PointerSizeBits = 64;
			TI.PointerAlignBytes = 8;
			break;
		case Triple::x86:
			TI.IsX86_32 = true;
			TI.PointerSizeBits = 32;
			TI.PointerAlignBytes = 4;
			break;
		case Triple::aarch64:
		case Triple::aarch64_be:
			TI.IsAArch64 = true;
			TI.PointerSizeBits = 64;
			TI.PointerAlignBytes = 8;
			break;
		case Triple::arm:
		case Triple::armeb:
		case Triple::thumb:
		case Triple::thumbeb:
			TI.IsARM32 = true;
			TI.PointerSizeBits = 32;
			TI.PointerAlignBytes = 4;
			break;
		case Triple::riscv32:
			TI.IsRISCV = true;
			TI.PointerSizeBits = 32;
			TI.PointerAlignBytes = 4;
			break;
		case Triple::riscv64:
			TI.IsRISCV = true;
			TI.PointerSizeBits = 64;
			TI.PointerAlignBytes = 8;
			break;
		case Triple::mips:
		case Triple::mipsel:
			TI.IsMIPS = true;
			TI.PointerSizeBits = 32;
			TI.PointerAlignBytes = 4;
			break;
		case Triple::mips64:
		case Triple::mips64el:
			TI.IsMIPS = true;
			TI.PointerSizeBits = 64;
			TI.PointerAlignBytes = 8;
			break;
		case Triple::wasm32:
			TI.IsWasm = true;
			TI.PointerSizeBits = 32;
			TI.PointerAlignBytes = 4;
			TI.SupportsInlineAsm = false;
			TI.SupportsIndirectBr = false;
			TI.SupportsBlockAddress = false;
			break;
		case Triple::wasm64:
			TI.IsWasm = true;
			TI.PointerSizeBits = 64;
			TI.PointerAlignBytes = 8;
			TI.SupportsInlineAsm = false;
			TI.SupportsIndirectBr = false;
			TI.SupportsBlockAddress = false;
			break;
		case Triple::ppc:
		case Triple::ppcle:
			TI.IsPPC = true;
			TI.PointerSizeBits = 32;
			TI.PointerAlignBytes = 4;
			break;
		case Triple::ppc64:
		case Triple::ppc64le:
			TI.IsPPC = true;
			TI.PointerSizeBits = 64;
			TI.PointerAlignBytes = 8;
			break;
		default:
			// Conservative defaults for unknown architectures
			TI.PointerSizeBits = 64;
			TI.PointerAlignBytes = 8;
			break;
		}

		// Object format
		switch (T.getObjectFormat()) {
		case Triple::ELF:
			TI.IsELF = true;
			break;
		case Triple::COFF:
			TI.IsCOFF = true;
			break;
		case Triple::MachO:
			TI.IsMachO = true;
			break;
		case Triple::Wasm:
			TI.IsWasm_ObjFormat = true;
			break;
		default:
			break;
		}

		// Platform / OS
		TI.IsLinux = T.isOSLinux();
		TI.IsWindows = T.isOSWindows();
		TI.IsDarwin = T.isOSDarwin();

		// TLS support
		TI.SupportsTLS = !TI.IsWasm;

		return TI;
	}

	// ============================================================================
	// Inline ASM helpers
	// ============================================================================

	StringRef getNopAsmString(const TargetInfo& TI) {
		if (TI.IsX86_64 || TI.IsX86_32)
			return "nop";
		if (TI.IsAArch64)
			return "nop";
		if (TI.IsARM32)
			return "nop";
		if (TI.IsRISCV)
			return "nop";
		// Unknown target — return empty (caller should check)
		return "";
	}

	StringRef getAsmClobbers(const TargetInfo& TI) {
		if (TI.IsX86_64 || TI.IsX86_32)
			return "~{dirflag},~{fpsr},~{flags}";
		if (TI.IsAArch64)
			return "~{nzcv}";
		if (TI.IsARM32)
			return "~{cpsr}";
		if (TI.IsRISCV)
			return "";
		return "";
	}

	// ============================================================================
	// Alignment helpers
	// ============================================================================

	unsigned getMinGlobalAlign(const TargetInfo& TI) {
		// COFF requires at least 4-byte alignment for data sections
		if (TI.IsCOFF)
			return 4;
		// Most targets default to pointer-sized alignment
		return TI.PointerAlignBytes;
	}

	unsigned getStackAlign(const TargetInfo& TI) {
		if (TI.IsX86_64)
			return 16; // x86-64 ABI requires 16-byte stack alignment
		if (TI.IsAArch64)
			return 16; // AArch64 requires 16-byte stack alignment
		if (TI.IsARM32)
			return 8;
		if (TI.IsRISCV)
			return 16;
		// Conservative default
		return TI.PointerAlignBytes;
	}

} // namespace llvm::obf