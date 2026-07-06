#pragma once
// ============================================================================
// VMPass_Verifier.h — Code Virtualisation pass: Bytecode Verifier
//
// Provides verifyBytecode(), a linear-scan post-emission sanity checker.
// It validates:
//
//   - Every physical opcode byte is in range [0, OP_COUNT).
//   - Every register-index operand (after XOR de-obfuscation with CTSalt) is
//     within the bounds declared by the emitter (E.NVR / E.NVR64 / E.NPR).
//   - Every branch/jump/switch target is a known block-start offset.
//   - Variable-length instructions (SWITCH, CALL*) are not truncated.
//   - The bytecode stream is non-empty and IP=0 is a block start.
//
// This is a standalone free function so it can be exercised in unit tests
// without constructing a full VMImpl.
// ============================================================================

#include <cstdint>
#include <string>

namespace llvm {

	struct BytecodeEmitter;
	struct VMOpcodeMap;

	/// Verify the bytecode in \p E after a successful BytecodeEmitter::run().
	///
	/// \param CTSalt    The per-function XOR salt byte used by the emitter for
	///                  register-index obfuscation (0 when obfRegIdx is disabled).
	/// \param OpMap     The per-function opcode permutation map.
	/// \param OutErr    Populated with a human-readable error on failure.
	/// \param OutBadIP  Populated with the bytecode offset of the failing opcode.
	///
	/// Returns true if the bytecode is structurally valid, false otherwise.
	bool verifyBytecode(const BytecodeEmitter& E,
		uint8_t               CTSalt,
		const VMOpcodeMap& OpMap,
		std::string& OutErr,
		uint32_t& OutBadIP,
		uint32_t              SaltFull = 0,       // P3-B: full 32-bit salt for target un-blind
		bool                  BlindTargets = false); // P3-B: branch targets are XOR-blinded

} // namespace llvm