// ============================================================================
// VMPass_Verifier.cpp — Code Virtualisation pass : Bytecode Verifier impl
// ============================================================================

#include "llvm/Transforms/Obfuscator/VMPass_Verifier.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"

#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/Twine.h"

using namespace llvm;

namespace llvm {

	bool verifyBytecode(const BytecodeEmitter& E, uint8_t CTSalt, const VMOpcodeMap& OpMap,
		std::string& OutErr, uint32_t& OutBadIP,
		uint32_t SaltFull, bool BlindTargets) {
		const auto& BC = E.BC;

		// P3-B: branch targets are stored XOR-blinded with tgtKey(SaltFull).
		// Mirror BytecodeEmitter::tgtKeyCT / VMImpl::tgtKeyIR so chkTarget can
		// recover the real offset before range-checking. TgtKey==0 (identity)
		// when blinding is off, so existing behavior is preserved.
		auto tgtKeyCT = [](uint32_t salt) -> uint32_t {
			uint32_t k = salt ^ 0x2545F491u;
			k *= 0x9E3779B1u;
			k ^= k >> 16;
			return k;
			};
		const uint32_t TgtKey = BlindTargets ? tgtKeyCT(SaltFull) : 0u;
		if (BC.empty()) {
			OutErr = "bytecode empty";
			OutBadIP = 0;
			return false;
		}

		DenseSet<uint32_t> BlockStarts;
		for (const auto& KV : E.BlockIP)
			BlockStarts.insert(KV.second);

		auto fail = [&](uint32_t IP, const Twine& Msg) -> bool {
			OutBadIP = IP;
			OutErr = Msg.str();
			for (char& C : OutErr) if (C == '\n' || C == '\r') C = ' ';
			return false;
			};

		auto decIdx = [&](uint8_t Raw) -> unsigned {
			return (unsigned)(Raw ^ CTSalt);
			};

		auto chk = [&](uint32_t IP, const char* Kind, unsigned Idx, unsigned Lim) -> bool {
			if (Idx >= Lim)
				return fail(IP, Twine(Kind) + " index " + Twine(Idx) + " out of range (limit=" + Twine(Lim) + ")");
			return true;
			};

		auto rdU16 = [&](uint32_t Off) -> uint16_t {
			return (uint16_t)((uint16_t)BC[Off] | ((uint16_t)BC[Off + 1] << 8));
			};
		auto rdU32 = [&](uint32_t Off) -> uint32_t {
			return (uint32_t)BC[Off] |
				((uint32_t)BC[Off + 1] << 8) |
				((uint32_t)BC[Off + 2] << 16) |
				((uint32_t)BC[Off + 3] << 24);
			};

		auto chkTarget = [&](uint32_t IP, uint32_t RawTgt, const char* Which) -> bool {
			uint32_t Tgt = RawTgt ^ TgtKey;   // P3-B un-blind (TgtKey=0 when off)
			if (Tgt >= BC.size())
				return fail(IP, Twine(Which) + " target " + Twine(Tgt) + " out of bounds (bc=" + Twine(BC.size()) + ")");
			if (!BlockStarts.count(Tgt))
				return fail(IP, Twine(Which) + " target " + Twine(Tgt) + " is not a block start");
			return true;
			};


		// shared CALL verifier body -- used by all 5 CALL opcodes.
		// Encoding: [dst?] fn:u8 nargs:u8 [arg:u8 * nargs]
		// (flags/argtypes bytes removed -- FunctionType now comes from GVFTyIndices)
		auto verifyCall = [&](uint32_t IP, unsigned DstKind) -> bool {
			// DstKind: 0=void, 1=vreg, 2=preg, 3=vreg64, 4=freg
			const bool HasDst = (DstKind != 0);
			uint32_t Hdr = (uint32_t)(HasDst ? 4 : 3);  // opc+dst?+fn+nargs  [6.2: was 7/6]
			if (IP + Hdr > BC.size()) return fail(IP, "OP_CALL header truncated");
			uint32_t Off = IP + 1;
			if (HasDst) {
				unsigned DstIdx = decIdx(BC[Off++]);
				switch (DstKind) {
				case 1: if (!chk(IP, "vreg", DstIdx, E.NVR))    return false; break;
				case 2: if (!chk(IP, "preg", DstIdx, E.NPR))    return false; break;
				case 3: if (!chk(IP, "vreg64", DstIdx, E.NVR64))  return false; break;
				case 4: if (!chk(IP, "freg", DstIdx, E.NFR))    return false; break;
				}
			}
			uint8_t  FnIdx = BC[Off + 0];
			uint8_t  NArgs = BC[Off + 1];
			// no flags/ArgTypes bytes.
			if (FnIdx >= E.CalleeTab.size())
				return fail(IP, Twine("OP_CALL fn index out of range: ") + Twine((unsigned)FnIdx));
			if (NArgs > 16)
				return fail(IP, Twine("OP_CALL nargs too large: ") + Twine((unsigned)NArgs));
			
			uint32_t Total = Hdr + (uint32_t)NArgs;
			if (IP + Total > BC.size())
				return fail(IP, "OP_CALL args truncated");
			uint32_t ArgBase = IP + Hdr;
			for (unsigned i = 0; i < NArgs; ++i) {
				unsigned Idx = decIdx(BC[ArgBase + i]);
				// arg register file is determined by FTy at runtime;
				// verify conservatively that Idx is in range of at least one file.
				unsigned MaxSlots = std::max({ (unsigned)E.NVR, (unsigned)E.NVR64,
				(unsigned)E.NPR, (unsigned)E.NFR });
				if (!chk(IP, "arg", Idx, MaxSlots)) return false;
			}
			return true;
			// caller advances IP by Total
			(void)Total;  // suppress unused-warning
			};
		// Compute Total for IP advancement (same formula as inside verifyCall)
		auto callTotal = [&](uint32_t IP, bool HasDst) -> uint32_t {
			uint32_t Hdr = HasDst ? 4u : 3u;  // 6.2: was 7/6
			uint32_t Off = IP + 1 + (HasDst ? 1u : 0u);
			uint8_t  NArgs = BC[Off + 1];
			return Hdr + (uint32_t)NArgs;
			};



		uint32_t IP = 0;
		while (IP < BC.size()) {
			uint8_t Phys = BC[IP];
			if (Phys >= OP_COUNT)
				return fail(IP, Twine("invalid opcode byte ") + Twine((unsigned)Phys));

			VMOp Opc = OpMap.decode(Phys);
			switch (Opc) {
			case OP_LOADI: {
				if (IP + 6 > BC.size()) return fail(IP, "OP_LOADI truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				IP += 6; break;
			}
			case OP_MOVR: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_MOVR truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;
				IP += 3; break;
			}
			case OP_BINOP: {
				if (IP + 5 > BC.size()) return fail(IP, "OP_BINOP truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 3]), E.NVR)) return false;
				IP += 5; break;
			}
			case OP_ICMP: {
				if (IP + 5 > BC.size()) return fail(IP, "OP_ICMP truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 3]), E.NVR)) return false;
				IP += 5; break;
			}
			case OP_ICMP64: {
				if (IP + 5 > BC.size()) return fail(IP, "OP_ICMP64 truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "vreg64", decIdx(BC[IP + 2]), E.NVR64)) return false;
				if (!chk(IP, "vreg64", decIdx(BC[IP + 3]), E.NVR64)) return false;
				IP += 5; break;
			}
			case OP_CAST: {
				if (IP + 4 > BC.size()) return fail(IP, "OP_CAST truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;
				IP += 4; break;
			}
			case OP_CAST64: {
				if (IP + 4 > BC.size()) return fail(IP, "OP_CAST64 truncated");
				unsigned Kind = (unsigned)BC[IP + 3];
				if (Kind <= (unsigned)C64_SEXT32) {
					if (!chk(IP, "vreg64", decIdx(BC[IP + 1]), E.NVR64)) return false;
					if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;
				}
				else if (Kind >= (unsigned)C64_TRUNC1 && Kind <= (unsigned)C64_TRUNC32) {
					if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
					if (!chk(IP, "vreg64", decIdx(BC[IP + 2]), E.NVR64)) return false;
				}
				else {
					return fail(IP, Twine("OP_CAST64 invalid kind ") + Twine(Kind));
				}
				IP += 4; break;
			}
			case OP_PTRTOINT: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_PTRTOINT truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_PTRTOINT64: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_PTRTOINT64 truncated");
				if (!chk(IP, "vreg64", decIdx(BC[IP + 1]), E.NVR64)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_INTTOPTR: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_INTTOPTR truncated");
				if (!chk(IP, "preg", decIdx(BC[IP + 1]), E.NPR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;
				IP += 3; break;
			}
			case OP_LOAD32: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_LOAD32 truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_LOAD64: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_LOAD64 truncated");
				if (!chk(IP, "vreg64", decIdx(BC[IP + 1]), E.NVR64)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_LOAD8:
			case OP_LOAD16: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_LOAD{8,16} truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}

			case OP_STORE32: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_STORE32 truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_STORE64: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_STORE64 truncated");
				if (!chk(IP, "vreg64", decIdx(BC[IP + 1]), E.NVR64)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_STORE8:
			case OP_STORE16: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_STORE{8,16} truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_LOADPTR: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_LOADPTR truncated");
				if (!chk(IP, "preg", decIdx(BC[IP + 1]), E.NPR)) return false; // dstp
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false; // ptrreg
				IP += 3; break;
			}
			case OP_STOREPTR: {
				if (IP + 3 > BC.size()) return fail(IP, "OP_STOREPTR truncated");
				if (!chk(IP, "preg", decIdx(BC[IP + 1]), E.NPR)) return false; // valp
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false; // ptrreg
				IP += 3; break;
			}

			case OP_GEP: {
				if (IP + 6 > BC.size()) return fail(IP, "OP_GEP truncated");
				if (!chk(IP, "preg", decIdx(BC[IP + 1]), E.NPR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 3]), E.NVR)) return false;
				IP += 6; break;
			}
			case OP_GEP64: {
				if (IP + 6 > BC.size()) return fail(IP, "OP_GEP64 truncated");
				if (!chk(IP, "preg", decIdx(BC[IP + 1]), E.NPR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				if (!chk(IP, "vreg64", decIdx(BC[IP + 3]), E.NVR64)) return false;
				IP += 6; break;
			}
			case OP_JMP: {
				if (IP + 5 > BC.size()) return fail(IP, "OP_JMP truncated");
				uint32_t Tgt = rdU32(IP + 1);
				if (!chkTarget(IP, Tgt, "OP_JMP")) return false;
				IP += 5; break;
			}
			case OP_JMPC: {
				if (IP + 10 > BC.size()) return fail(IP, "OP_JMPC truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				uint32_t T = rdU32(IP + 2);
				uint32_t F = rdU32(IP + 6);
				if (!chkTarget(IP, T, "OP_JMPC.true")) return false;
				if (!chkTarget(IP, F, "OP_JMPC.false")) return false;
				IP += 10; break;
			}
			case OP_RET_VOID: {
				IP += 1; break;
			}
			case OP_RET_INT: {
				if (IP + 2 > BC.size()) return fail(IP, "OP_RET_INT truncated");
				// OP_RET_INT is emitted for BOTH i32 (vreg slot) and i64
				// (vreg64 slot) returns — the opcode does not encode which.
				// Accept a slot valid in EITHER integer register file, else an
				// i64 return whose vreg64 slot index exceeds NVR false-fails.
				unsigned RetLim = E.NVR > E.NVR64 ? E.NVR : E.NVR64;
				if (!chk(IP, "vreg/vreg64", decIdx(BC[IP + 1]), RetLim)) return false;
				IP += 2; break;
			}
			case OP_RET_PTR: {
				if (IP + 2 > BC.size()) return fail(IP, "OP_RET_PTR truncated");
				if (!chk(IP, "preg", decIdx(BC[IP + 1]), E.NPR)) return false;
				IP += 2; break;
			}
			case OP_CALL_VOID: {
				if (!verifyCall(IP, 0)) return false;
				IP += callTotal(IP, false); break;
			}
			case OP_CALL_INT: {
				if (!verifyCall(IP, 1)) return false;
				IP += callTotal(IP, true); break;
			}
			case OP_CALL_PTR: {
				if (!verifyCall(IP, 2)) return false;
				IP += callTotal(IP, true); break;
			}
			case OP_CALL_INT64: {  
				if (!verifyCall(IP, 3)) return false;
				IP += callTotal(IP, true); break;
			}
			case OP_CALL_F: {      
				if (!verifyCall(IP, 4)) return false;
				IP += callTotal(IP, true); break;
			}
			case OP_SELECT: {
				if (IP + 6 > BC.size()) return fail(IP, "OP_SELECT truncated");
				uint8_t Kind = BC[IP + 1];
				if (!chk(IP, "vreg", decIdx(BC[IP + 3]), E.NVR)) return false; 
				if (Kind == 0) {
					if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;
					if (!chk(IP, "vreg", decIdx(BC[IP + 4]), E.NVR)) return false;
					if (!chk(IP, "vreg", decIdx(BC[IP + 5]), E.NVR)) return false;
				}
				else if (Kind == 1) {
					if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
					if (!chk(IP, "preg", decIdx(BC[IP + 4]), E.NPR)) return false;
					if (!chk(IP, "preg", decIdx(BC[IP + 5]), E.NPR)) return false;
				}
				else if (Kind == 2) {
					if (!chk(IP, "vreg64", decIdx(BC[IP + 2]), E.NVR64)) return false;
					if (!chk(IP, "vreg64", decIdx(BC[IP + 4]), E.NVR64)) return false;
					if (!chk(IP, "vreg64", decIdx(BC[IP + 5]), E.NVR64)) return false;
				}
				else {
					return fail(IP, Twine("OP_SELECT invalid kind ") + Twine((unsigned)Kind));
				}
				IP += 6; break;
			}
			case OP_BINOP64: {
				if (IP + 5 > BC.size()) return fail(IP, "OP_BINOP64 truncated");
				if (!chk(IP, "vreg64", decIdx(BC[IP + 1]), E.NVR64)) return false;
				if (!chk(IP, "vreg64", decIdx(BC[IP + 2]), E.NVR64)) return false;
				if (!chk(IP, "vreg64", decIdx(BC[IP + 3]), E.NVR64)) return false;
				IP += 5; break;
			}
			case OP_SWITCH: {
				if (IP + 8 > BC.size()) return fail(IP, "OP_SWITCH header truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR)) return false;
				uint16_t NC = rdU16(IP + 2);
				uint32_t Def = rdU32(IP + 4);
				uint32_t Sz = 8u + (uint32_t)NC * 8u;
				if (IP + Sz > BC.size()) return fail(IP, "OP_SWITCH cases truncated");
				if (!chkTarget(IP, Def, "OP_SWITCH.default")) return false;
				uint32_t COff = IP + 8;
				for (unsigned i = 0; i < NC; ++i) {
					(void)rdU32(COff + 0);
					uint32_t Tgt = rdU32(COff + 4);
					if (!chkTarget(IP, Tgt, "OP_SWITCH.case")) return false;
					COff += 8;
				}
				IP += Sz; break;
			}


		

			// ── float register file opcodes ────────────────────────────
			case OP_LOADI_F: {  // dst:u8 imm:f64le (10 bytes)
				if (IP + 10 > BC.size()) return fail(IP, "OP_LOADI_F truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				IP += 10; break;
			}
			case OP_MOVR_F: {   // dst:u8 src:u8 (3 bytes)
				if (IP + 3 > BC.size()) return fail(IP, "OP_MOVR_F truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				if (!chk(IP, "freg", decIdx(BC[IP + 2]), E.NFR)) return false;
				IP += 3; break;
			}
			case OP_BINOP_F: {  // dst:u8 a:u8 b:u8 subop:u8 (5 bytes)
				// subop byte layout: bits[6:0] = FBinSubop, bit[7] = FBS_F32_FLAG.
				// Mask bit 7 before range-checking the operation.
				if (IP + 5 > BC.size()) return fail(IP, "OP_BINOP_F truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				if (!chk(IP, "freg", decIdx(BC[IP + 2]), E.NFR)) return false;
				if (!chk(IP, "freg", decIdx(BC[IP + 3]), E.NFR)) return false;
				{
					uint8_t Sub = BC[IP + 4] & ~(uint8_t)FBS_F32_FLAG;
					if (Sub > (uint8_t)FBS_FREM)
						return fail(IP, Twine("OP_BINOP_F invalid subop: ") + Twine((unsigned)Sub));
				}
				IP += 5; break;
			}
			case OP_FCMP: {     // dst_vr:u8 a_fr:u8 b_fr:u8 pred:u8 (5 bytes) → result in vreg
				if (IP + 5 > BC.size()) return fail(IP, "OP_FCMP truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR))  return false;  // dst in vreg
				if (!chk(IP, "freg", decIdx(BC[IP + 2]), E.NFR))  return false;
				if (!chk(IP, "freg", decIdx(BC[IP + 3]), E.NFR))  return false;
				IP += 5; break;
			}
			
			case OP_FCAST_FF: {   // dst_fr:u8 src_fr:u8 kind:u8 (4 bytes) — freg→freg
				if (IP + 4 > BC.size()) return fail(IP, "OP_FCAST_FF truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				if (!chk(IP, "freg", decIdx(BC[IP + 2]), E.NFR)) return false;
				{
					unsigned K = BC[IP + 3];
					if (K != FK_FPEXT && K != FK_FPTRUNC)
						return fail(IP, Twine("OP_FCAST_FF invalid kind ") + Twine(K));
				}
				IP += 4; break;
			}
			case OP_FCAST_FV: {   // dst_vr:u8 src_fr:u8 kind:u8 (4 bytes) — freg→vreg i32
				if (IP + 4 > BC.size()) return fail(IP, "OP_FCAST_FV truncated");
				if (!chk(IP, "vreg", decIdx(BC[IP + 1]), E.NVR))  return false;
				if (!chk(IP, "freg", decIdx(BC[IP + 2]), E.NFR))  return false;
				{
					unsigned K = BC[IP + 3];
					if (K != FK_FPTOSI && K != FK_FPTOUI)
						return fail(IP, Twine("OP_FCAST_FV invalid kind ") + Twine(K));
				}
				IP += 4; break;
			}
			case OP_FCAST_FV64: { // dst_vr64:u8 src_fr:u8 kind:u8 (4 bytes) — freg→vreg64 i64
				if (IP + 4 > BC.size()) return fail(IP, "OP_FCAST_FV64 truncated");
				if (!chk(IP, "vreg64", decIdx(BC[IP + 1]), E.NVR64)) return false;
				if (!chk(IP, "freg", decIdx(BC[IP + 2]), E.NFR))   return false;
				{
					unsigned K = BC[IP + 3];
					if (K != FK_FPTOSI64 && K != FK_FPTOUI64)
						return fail(IP, Twine("OP_FCAST_FV64 invalid kind ") + Twine(K));
				}
				IP += 4; break;
			}
			case OP_FCAST_VF: {   // dst_fr:u8 src_vr:u8 kind:u8 (4 bytes) — vreg i32→freg
				if (IP + 4 > BC.size()) return fail(IP, "OP_FCAST_VF truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;
				{
					unsigned K = BC[IP + 3] & 0x7Fu;  // mask FCAST_F32_FLAG
					if (K != FK_SITOFP && K != FK_UITOFP)
						return fail(IP, Twine("OP_FCAST_VF invalid kind ") + Twine(K));
				}
				IP += 4; break;
			}
			case OP_FCAST_V64F: { // dst_fr:u8 src_vr64:u8 kind:u8 (4 bytes) — vreg64 i64→freg
				if (IP + 4 > BC.size()) return fail(IP, "OP_FCAST_V64F truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR))   return false;
				if (!chk(IP, "vreg64", decIdx(BC[IP + 2]), E.NVR64)) return false;
				{
					unsigned K = BC[IP + 3] & 0x7Fu;  // mask FCAST_F32_FLAG
					if (K != FK_SI64TOFP && K != FK_UI64TOFP)
						return fail(IP, Twine("OP_FCAST_V64F invalid kind ") + Twine(K));
				}
				IP += 4; break;
			}




			case OP_LOAD_F: {   // dst_fr:u8 ptrreg:u8 (3 bytes)
				if (IP + 3 > BC.size()) return fail(IP, "OP_LOAD_F truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_STORE_F: {  // val_fr:u8 ptrreg:u8 (3 bytes)
				if (IP + 3 > BC.size()) return fail(IP, "OP_STORE_F truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_LOAD_F32: {  // dst_fr:u8 ptrreg:u8 (3 bytes) — 4-byte float load
				if (IP + 3 > BC.size()) return fail(IP, "OP_LOAD_F32 truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_STORE_F32: {  // val_fr:u8 ptrreg:u8 (3 bytes) — 4-byte float store
				if (IP + 3 > BC.size()) return fail(IP, "OP_STORE_F32 truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				if (!chk(IP, "preg", decIdx(BC[IP + 2]), E.NPR)) return false;
				IP += 3; break;
			}
			case OP_RET_F: {    // src_fr:u8 (2 bytes)
				if (IP + 2 > BC.size()) return fail(IP, "OP_RET_F truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;
				IP += 2; break;
			}
			case OP_SELECT_F: { // dst_fr:u8 cond_vr:u8 t_fr:u8 f_fr:u8 (5 bytes)
				if (IP + 5 > BC.size()) return fail(IP, "OP_SELECT_F truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;  // dst
				if (!chk(IP, "vreg", decIdx(BC[IP + 2]), E.NVR)) return false;  // cond
				if (!chk(IP, "freg", decIdx(BC[IP + 3]), E.NFR)) return false;  // t
				if (!chk(IP, "freg", decIdx(BC[IP + 4]), E.NFR)) return false;  // f
				IP += 5; break;
			}
			case OP_FNEG: {  // dst_fr:u8 src_fr:u8 (3 bytes)
				if (IP + 3 > BC.size()) return fail(IP, "OP_FNEG truncated");
				if (!chk(IP, "freg", decIdx(BC[IP + 1]), E.NFR)) return false;  // dst
				if (!chk(IP, "freg", decIdx(BC[IP + 2]), E.NFR)) return false;  // src
				IP += 3; break;
			}

			default: {
				return fail(IP, Twine("unhandled opcode in verifier: phys=") + Twine((unsigned)Phys) + " logical=" + Twine((unsigned)Opc));
			}
			}
		}

		if (!BlockStarts.count(0))
			return fail(0, "missing block start at IP=0");

		return true;
	}

} // namespace llvm