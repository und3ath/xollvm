#pragma once

// ============================================================================
// TargetCompat.h — Cross-platform compatibility utilities
//
// Provides target-aware helpers so obfuscation passes work correctly
// across x86-64, AArch64, ARM32, RISC-V, and other architectures.
//
// Key concerns:
//   - Pointer sizes (32 vs 64 bit)
//   - Inline ASM dialects and constraints
//   - Calling conventions affecting musttail/invoke lowering
//   - Section naming conventions (ELF vs COFF vs Mach-O)
//   - Alignment requirements for different targets
// ============================================================================

#include "llvm/IR/Module.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/ADT/StringRef.h"

namespace llvm::obf {

	// ============================================================================
	// Target classification
	// ============================================================================

	struct TargetInfo {
		bool IsX86_64 = false;
		bool IsX86_32 = false;
		bool IsAArch64 = false;
		bool IsARM32 = false;
		bool IsRISCV = false;
		bool IsMIPS = false;
		bool IsWasm = false;
		bool IsPPC = false;

		// Pointer properties
		unsigned PointerSizeBits = 64;
		unsigned PointerAlignBytes = 8;

		// Object format
		bool IsELF = false;
		bool IsCOFF = false;
		bool IsMachO = false;
		bool IsWasm_ObjFormat = false;

		// Platform
		bool IsLinux = false;
		bool IsWindows = false;
		bool IsDarwin = false;

		// Feature support
		bool SupportsInlineAsm = true;
		bool SupportsIndirectBr = true;
		bool SupportsTLS = true;
		bool SupportsBlockAddress = true;

		/// Construct from a Module's target triple.
		static TargetInfo fromModule(const Module& M);

		/// Construct from a Triple.
		static TargetInfo fromTriple(const Triple& T);

		/// Returns the natural integer type for pointers (i32 or i64).
		unsigned getPointerIntWidth() const { return PointerSizeBits; }

		/// Returns true if this target supports the inline ASM anti-disassembly
		/// gadgets used by the adec pass.
		bool supportsAsmGadgets() const {
			return SupportsInlineAsm && (IsX86_64 || IsX86_32 || IsAArch64);
		}

		/// Returns true if the target uses a Windows COFF object format,
		/// which affects section naming and string encryption layout.
		bool usesCOFFSections() const { return IsCOFF; }

		/// Returns the appropriate data section name for encrypted strings.
		StringRef getEncryptedStringSectionName() const {
			if (IsCOFF)
				return ".rdata$obf";
			if (IsMachO)
				return "__DATA,__obf_str";
			return ".obf.str"; // ELF default
		}

		/// Returns the appropriate constructor section for runtime initializers.
		StringRef getCtorSectionName() const {
			if (IsCOFF)
				return ".CRT$XCU";
			if (IsMachO)
				return "__DATA,__mod_init_func";
			return ".init_array"; // ELF
		}
	};

	// ============================================================================
	// Inline ASM helpers
	// ============================================================================

	/// Returns an appropriate "nop-like" inline ASM string for the target.
	/// Used by anti-disassembly gadgets. Returns empty string if unsupported.
	StringRef getNopAsmString(const TargetInfo& TI);

	/// Returns ASM constraint string for the target (e.g., clobber list).
	StringRef getAsmClobbers(const TargetInfo& TI);

	// ============================================================================
	// Alignment helpers
	// ============================================================================

	/// Returns the minimum alignment for global variables on this target.
	/// Important for string encryption globals.
	unsigned getMinGlobalAlign(const TargetInfo& TI);

	/// Returns the stack alignment for alloca instructions.
	unsigned getStackAlign(const TargetInfo& TI);

} // namespace llvm::obf