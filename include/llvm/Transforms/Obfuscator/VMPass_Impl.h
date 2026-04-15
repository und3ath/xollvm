#pragma once

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/MemoryBuffer.h"

#include "llvm/Transforms/Obfuscator/VMPass.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/TargetCompat.h"
#include "llvm/Transforms/Obfuscator/PassCtx.h"


#include <cstring>

namespace llvm {

	// ============================================================================
	// Compile-time AES-128 engine for VMPass
	//
	// These functions run ONLY inside the compiler to encrypt bytecode at compile
	// time.  None of this code is emitted into the target binary.  The runtime
	// decryption is handled by __obf_aes_ctr_decrypt() from strenc_stub.c.
	//
	// The engine is identical to the one in StringEncryption.cpp — it is
	// duplicated here (as static functions in the anonymous namespace) to keep
	// VMPass self-contained and avoid cross-pass header dependencies.
	// ============================================================================
	namespace vm_aes {

		// AES forward S-box (FIPS-197)
		extern const uint8_t SBOX[256];
		// AES round constants
		extern const uint8_t RCON[11];

		// Expand 16-byte key → 176-byte round-key schedule.
		void keyExpand(const uint8_t key[16], uint8_t rk[176]);

		// Encrypt one 16-byte block in-place.
		void encryptBlock(const uint8_t rk[176], uint8_t blk[16]);

		// AES-128-CTR: encrypt/decrypt buf in-place (symmetric).
		void ctr(const uint8_t rk[176], const uint8_t nonce8[8],
			uint8_t* buf, size_t len);

	} // namespace vm_aes
} // namespace llvm


namespace llvm {
	struct VMCtx : public obf::FuncPassCtx {
		VMPassConfig              Cfg;
		const FunctionObfContext& FOC;
		explicit VMCtx(Function& F, FunctionAnalysisManager& AM)
			: obf::FuncPassCtx(F, AM, "vm"),
			Cfg([&] { const ObfuscationConfig& OC = getObfConfig(F, AM);
		auto PC = OC.getPassConfig("vm");
		if (!PC.has_value()) { VMPassConfig C; C.enable = false; return C; }
		VMPassConfig C = VMPassConfig::fromPassConfig(*PC);
		if (!C.validate()) C.enable = false; return C; }()),
			FOC(*AM.getResult<FunctionObfContextAnalysis>(F)) {
		}
	};

	static bool isVMEligible(Function& F, const FunctionObfContext& FOC,
		const VMPassConfig& Cfg, raw_ostream* R = nullptr) {
		if (FOC.HasEHPad || FOC.HasInvoke) { if (R)*R << "EH/invoke"; return false; }
		if (FOC.HasCallBr) { if (R)*R << "callbr";  return false; }
		if (FOC.HasIndirectBr) { if (R)*R << "indirectbr already"; return false; }
		if (FOC.HasNaked) { if (R)*R << "naked";   return false; }
		if (FOC.NumNormalBlocks < Cfg.minBlocks) {
			if (R)*R << "too few blocks(" << FOC.NumNormalBlocks << "<" << Cfg.minBlocks << ")";
			return false;
		}
		if (Cfg.maxBlocks > 0 && FOC.NumNormalBlocks > Cfg.maxBlocks) {
			if (R)*R << "too many blocks(" << FOC.NumNormalBlocks << ">" << Cfg.maxBlocks << ")";
			return false;
		}
		return true;
	}



	// ========================================================================
	// Shared vm_engine infrastructure
	//
	// The VMEngine namespace defines the parameter layout and construction
	// helpers for the module-level __vm_engine() function.  This function is
	// created once per Module and hosts all 51 opcode handler BasicBlocks.
	// Each virtualised function becomes a thin wrapper that tail-calls
	// vm_engine with per-function context (bytecode, register files, handler
	// table).
	// ========================================================================
	namespace VMEngine {

		// ── Parameter indices for vm_engine() ──────────────────────────────────
		//  void @__vm_engine(
		//      ptr  %bc,           // 0   GVBytecodeRT pointer
		//      i32  %bc_len,       // 1   bytecode length
		//      ptr  %regs,         // 2   caller-allocated [N x i32]
		//      ptr  %regs64,       // 3   caller-allocated [N x i64]
		//      ptr  %fregs,        // 4   caller-allocated [N x double]
		//      ptr  %pregs,        // 5   caller-allocated [N x ptr]
		//      ptr  %callees,      // 6   GVCallees pointer (may be null)
		//      i32  %salt,         // 7   full 32-bit compile-time salt
		//      i32  %regMask,      // 8   (nextPow2(NVR) - 1)
		//      i32  %reg64Mask,    // 9   (nextPow2(NVR64) - 1)
		//      i32  %fregMask,     // 10  (nextPow2(NFR) - 1)
		//      i32  %pregMask,     // 11  (nextPow2(NPR) - 1)
		//      ptr  %handlers,     // 12  GVHandlers per-function permuted table
		//      ptr  %fty_indices   // 13  GVFTyIndices per-function type table
		//      ptr  %regkeys,      // 14  Step 05: per-slot i32 XOR keys (null = off)
		//      ptr  %reg64keys,    // 15  Step 05: per-slot i64 XOR keys (null = off)
		//      ptr  %fregkeys,     // 16  Step 05: per-slot i64 XOR keys for f64 (null = off)
		//  )

		static constexpr unsigned kParamBC = 0;
		static constexpr unsigned kParamBCLen = 1;
		static constexpr unsigned kParamRegs = 2;
		static constexpr unsigned kParamRegs64 = 3;
		static constexpr unsigned kParamFregs = 4;
		static constexpr unsigned kParamPregs = 5;
		static constexpr unsigned kParamCallees = 6;
		static constexpr unsigned kParamSalt = 7;
		static constexpr unsigned kParamRegMask = 8;
		static constexpr unsigned kParamReg64Mask = 9;
		static constexpr unsigned kParamFregMask = 10;
		static constexpr unsigned kParamPregMask = 11;
		static constexpr unsigned kParamHandlers = 12;
		static constexpr unsigned kParamFTyIndices = 13;
		static constexpr unsigned kParamRegKeys = 14;
		static constexpr unsigned kParamReg64Keys = 15;
		static constexpr unsigned kParamFRegKeys = 16;
		static constexpr unsigned kParamCalleeMask = 17;
		static constexpr unsigned kNumParams = 18;

		/// The well-known symbol name for the shared engine function.
		static constexpr const char* kVMEngineName = "__vm_engine";

		/// Return the canonical FunctionType for vm_engine.
		inline FunctionType* getVMEngineFunctionType(LLVMContext& Ctx) {
			Type* PtrTy = PointerType::getUnqual(Ctx);
			Type* I32Ty = Type::getInt32Ty(Ctx);
			Type* VoidTy = Type::getVoidTy(Ctx);
			Type* I64Ty = Type::getInt64Ty(Ctx);
			Type* Params[kNumParams] = {
				PtrTy, I32Ty, PtrTy, PtrTy, PtrTy, PtrTy,
				PtrTy, I32Ty, I32Ty, I32Ty, I32Ty, I32Ty,
				PtrTy, PtrTy,
				PtrTy, PtrTy, PtrTy,   // regkeys, reg64keys, fregkeys
				I64Ty,                 // callee_mask
			};
			return FunctionType::get(VoidTy, Params, /*isVarArg=*/false);
		}

		/// Get or create the module-level @__vm_engine function.
		Function* getOrBuildVMEngine(Module& M);

		/// Check whether the vm_engine body has been populated with handlers.
		bool isEnginePopulated(Function* VMEngineFunc);

		/// Mark the vm_engine body as populated.
		void markEnginePopulated(Function* VMEngineFunc);

		// CALL handler types (hoisted from VMImpl for SharedState visibility)
		enum RetKind2 { RK2_VOID = 0, RK2_I32 = 1, RK2_PTR = 2, RK2_I64 = 3, RK2_F64 = 4 };
		static constexpr unsigned MaxArgs = 16;

		// Module-level shared state for the vm_engine
		struct SharedState {
			Function* EngineFn = nullptr;
			BasicBlock* OpcBB[OP_COUNT] = {};
			BasicBlock* Dispatch = nullptr;
			BasicBlock* ExitBB = nullptr;
			BasicBlock* Entry = nullptr;
			AllocaInst* EngineVMIP = nullptr;
			AllocaInst* EngineSalt = nullptr;

			SmallVector<FunctionType*, 16> SharedFTys;
			DenseMap<FunctionType*, uint8_t> FTyToIdx;

			struct CallSwitchInfo {
				SwitchInst* SW = nullptr;
				BasicBlock* MergeBB = nullptr;
				PHINode* RetPHI = nullptr;
				Value* Callee = nullptr;
				SmallVector<Value*, 8> PVals, IVals, I64Vs, FregVals;
				RetKind2    RK = RK2_VOID;
			};
			CallSwitchInfo CallSW[5];

			bool Populated = false;
			unsigned FTyCountAtLastBuild = 0;
		};

		SharedState* getSharedState(Module& M);
		void releaseSharedState(Module& M);

	} // namespace VMEngine


	struct VMImpl {
		Function& F;
		Module& M;
		LLVMContext& Ctx;
		Type* I8Ty, * I16Ty, * I32Ty, * I64Ty, * PtrTy;
		Type* DoubleTy;  // f64 type — used by float handler builders 
		VMCtx& VCtx;

		const bool     ObfRegIdx;
		const bool     EncBytecode;
		const bool     UseAES;       // AES-CTR replaces LCG
		const bool     RegEncrypt;   // XOR-encrypt register values at rest
		const uint32_t SaltConst;    // full 32-bit salt stored in vm.salt
		const uint8_t  CTSalt;       // low byte of SaltConst must match deobf() key
		const uint64_t EncSeed;      // seed for bytecode LCG encryption

		VMOpcodeMap OpMap;

		BytecodeEmitter E;
		std::string FailReason;

		AllocaInst* VMIP = nullptr, * VMSalt = nullptr, * VMRegs = nullptr, * VMRegs64 = nullptr, * VMPRegs = nullptr;
		AllocaInst* VMFregs = nullptr;  // vm.fregs — f64 register file 
		BasicBlock* Entry = nullptr, * Dispatch = nullptr, * ExitBB = nullptr;

		GlobalVariable* GVBytecode = nullptr, * GVBytecodeRT = nullptr, * GVHandlers = nullptr, * GVCallees = nullptr;
		// parallel [C x i8] table -- callee slot -> index into UniqueFTys.
		GlobalVariable* GVFTyIndices = nullptr;
		// unique FunctionType* list built by buildCalleeGlobal(), consumed by buildCall2().
		SmallVector<FunctionType*, 8> UniqueFTys;
		// AES-128-CTR key material 
		// Generated once per virtualised function from the RNG hierarchy.
		uint8_t AESKey[16] = {};          // raw 16-byte key
		uint8_t AESExpandedKey[176] = {}; // full round-key schedule
		uint8_t AESKeyMask[16] = {};      // compile-time XOR mask for the key
		uint8_t AESRKMask[176] = {};      // compile-time XOR mask for expanded key
		uint64_t AESNonce = 0;            // 8-byte per-function nonce


		// per-slot XOR keys for register value encryption 
		// Generated from a forked RNG after register file sizes are known.
		// Consumed by ldVR/stVR/ldVR64/stVR64/ldFR/stFR in the engine handlers
		// and by buildWrapper() for pre-load encryption + return decryption.
		SmallVector<uint32_t, 64> RegKeys;     // [NVRAlloc]   i32 XOR keys
		SmallVector<uint64_t, 64> Reg64Keys;   // [NVR64Alloc] i64 XOR keys
		SmallVector<uint64_t, 64> FRegKeys;    // [NFRAlloc]   i64 XOR keys (bitcast on f64)

		// per-function engine-pointer XOR mask
		// GVHandlers is extended to [OP_COUNT+1 x ptr].  Slot [OP_COUNT]
		// stores @__vm_engine as a plain ptr (LLVM 21 does not support
		// xor(ptrtoint) in constant-expression initialisers).  The wrapper
		// loads it and makes an indirect call, breaking call-site xrefs.
		// EngineMask is generated here for use by Step 06b.2 (constant
		// blinding) which will obfuscate the runtime load path.
		uint64_t EngineMask = 0;


		// anti-debug salt corruption key
		// Non-zero per-function constant.  When a debug trap fires,
		// salt ^= ADPoisonKey corrupts all subsequent bytecode fetches.
		uint32_t ADPoisonKey = 0;

		// per-function callee XOR mask 
		uint64_t CalleeMask = 0;

		// platform detection 
		obf::TargetInfo TI;



		// Globals for AES runtime decryption
		GlobalVariable* GVAESExpandedKey = nullptr;  // @fn.vm.aes.rk (masked)
		GlobalVariable* GVAESNonce = nullptr;  // @fn.vm.aes.nonce

		// Handler indirection layer
		Function* HFn = nullptr;       // target for BasicBlock creation
		Value* EffBC = nullptr;        // bytecode base pointer
		Value* EffBCLen = nullptr;     // bytecode length (i32)
		Value* EffSalt = nullptr;      // salt alloca (volatile loads)
		Value* EffRegs = nullptr;      // i32 register file base
		Value* EffRegs64 = nullptr;    // i64 register file base
		Value* EffFregs = nullptr;     // f64 register file base
		Value* EffPregs = nullptr;     // ptr register file base
		Value* EffCallees = nullptr;   // callee table base
		Value* EffFTyIndices = nullptr;// FTy index table base
		Value* EffHandlers = nullptr;  // handler table base
		Value* EffCalleeMask = nullptr;// callee XOR mask (i64, null when off)
		Value* MaskVR = nullptr;       // i32 mask values
		Value* MaskVR64 = nullptr;
		Value* MaskFR = nullptr;
		Value* MaskPR = nullptr;
		Value* EffRegKeys = nullptr;   // ptr to [N x i32] XOR key array (null = off)
		Value* EffReg64Keys = nullptr; // ptr to [N x i64] XOR key array
		Value* EffFRegKeys = nullptr;  // ptr to [N x i64] XOR key array (f64 bitcast)
		bool      SharedEngineMode = false;

		// return value info for thin wrapper
		int       WrapRetSlot = -1;       // register file slot of return value (-1 = void)
		VMEngine::RetKind2 WrapRetKind = VMEngine::RK2_VOID;


		BasicBlock* OpcBB[OP_COUNT] = {};

		// vm.regs/vm.regs64/vm.pregs are allocated with sizes rounded up to the next power of two.
		// This ensures the bitmask in deobf() never produces an out-of-bounds index.
		unsigned NVRAlloc = 0, NVR64Alloc = 0, NPRAlloc = 0, NFRAlloc = 0;

		static unsigned nextPow2(unsigned N) {
			if (N == 0) return 1;
			unsigned P = 1; while (P < N) P <<= 1; return P;
		}

		explicit VMImpl(VMCtx& VCtx)
			: F(VCtx.F), M(*VCtx.F.getParent()), Ctx(VCtx.F.getContext()),
			I8Ty(Type::getInt8Ty(Ctx)),
			I16Ty(Type::getInt16Ty(Ctx)),
			I32Ty(Type::getInt32Ty(Ctx)),
			I64Ty(Type::getInt64Ty(Ctx)),
			PtrTy(PointerType::getUnqual(Ctx)),
			DoubleTy(Type::getDoubleTy(Ctx)),
			VCtx(VCtx),
			ObfRegIdx(VCtx.Cfg.obfRegIdx),
			EncBytecode(VCtx.Cfg.encBytecode),
			UseAES(VCtx.Cfg.useAES),
			RegEncrypt(VCtx.Cfg.regEncrypt),
			SaltConst(VCtx.R.u32()),
			// IMPORTANT: indices are only XOR-salted when obfRegIdx=1.
			// When obfRegIdx=0, emitter must write raw indices (CTSalt=0).
			CTSalt(ObfRegIdx ? (uint8_t)(SaltConst & 0xFF) : 0),
			EncSeed(((uint64_t)VCtx.R.u32() << 32) | VCtx.R.u32()) {
			// per-function opcode permutation for handler-table/bytecode diversity.
			OpMap.initPermuted(VCtx.R);

			//  generate per-function AES key material from RNG
			if (UseAES) {
				for (int i = 0; i < 4; i++) {
					uint32_t W = VCtx.R.u32();
					AESKey[i * 4 + 0] = (W >> 0) & 0xFF;
					AESKey[i * 4 + 1] = (W >> 8) & 0xFF;
					AESKey[i * 4 + 2] = (W >> 16) & 0xFF;
					AESKey[i * 4 + 3] = (W >> 24) & 0xFF;
				}
				vm_aes::keyExpand(AESKey, AESExpandedKey);
				for (auto& b : AESRKMask) b = (uint8_t)(VCtx.R.u32() & 0xFF);
				AESNonce = ((uint64_t)VCtx.R.u32() << 32) | VCtx.R.u32();
			}
		}

		bool run();

	private:
		//  IR helpers 
		// Key: byte ^= (vm.salt ^ absolute_byte_index) & 0xFF
		Value* loadBC(IRBuilder<>& B, Value* IP, uint32_t Off, const Twine& N = "vm.bc") {
			Value* Idx32 = Off ? B.CreateAdd(IP, B.getInt32(Off), N + ".i32") : IP;
			Value* Idx64 = B.CreateSExt(Idx32, I64Ty, N + ".ip64");
			Value* Ptr = B.CreateGEP(I8Ty, EffBC, Idx64, N + ".p");
			Value* Raw = B.CreateLoad(I8Ty, Ptr, N);
			if (!EncBytecode) return Raw;

			auto* SL = B.CreateLoad(I32Ty, EffSalt, N + ".s");
			SL->setVolatile(true);
			Value* Key32 = B.CreateAnd(B.CreateXor(SL, Idx32, N + ".kx"), B.getInt32(0xFF), N + ".km");
			Value* Key8 = B.CreateTrunc(Key32, I8Ty, N + ".k8");
			return B.CreateXor(Raw, Key8, N + ".dec");
		}

		Value* loadBCDyn(IRBuilder<>& B, Value* IP, Value* Off, const Twine& N = "vm.bcd") {
			Value* Idx32 = B.CreateAdd(IP, Off, N + ".i32");
			Value* Idx64 = B.CreateSExt(Idx32, I64Ty, N + ".ip64");
			Value* Ptr = B.CreateGEP(I8Ty, EffBC, Idx64, N + ".p");
			Value* Raw = B.CreateLoad(I8Ty, Ptr, N);
			if (!EncBytecode) return Raw;

			auto* SL = B.CreateLoad(I32Ty, EffSalt, N + ".s");
			SL->setVolatile(true);
			Value* Key32 = B.CreateAnd(B.CreateXor(SL, Idx32, N + ".kx"), B.getInt32(0xFF), N + ".km");
			Value* Key8 = B.CreateTrunc(Key32, I8Ty, N + ".k8");
			return B.CreateXor(Raw, Key8, N + ".dec");
		}

		Value* rdByteDyn(IRBuilder<>& B, Value* IP, Value* Off, const Twine& N) {
			return B.CreateZExt(loadBCDyn(B, IP, Off, N), I32Ty, N + ".b");
		}
		Value* rdU32Dyn(IRBuilder<>& B, Value* IP, Value* Off, const Twine& N) {
			Value* o1 = B.CreateAdd(Off, B.getInt32(1), N + "o1");
			Value* o2 = B.CreateAdd(Off, B.getInt32(2), N + "o2");
			Value* o3 = B.CreateAdd(Off, B.getInt32(3), N + "o3");
			Value* b0 = rdByteDyn(B, IP, Off, N + "0"), * b1 = rdByteDyn(B, IP, o1, N + "1");
			Value* b2 = rdByteDyn(B, IP, o2, N + "2"), * b3 = rdByteDyn(B, IP, o3, N + "3");
			Value* W = B.CreateOr(b0, B.CreateShl(b1, 8, N + "s1"), N + "w01");
			W = B.CreateOr(W, B.CreateShl(b2, 16, N + "s2"), N + "w02");
			return B.CreateOr(W, B.CreateShl(b3, 24, N + "s3"), N + "w03");
		}



		// Deobfuscate a register index: (byte XOR salt_lo_byte) & mask
		Value* deobf(IRBuilder<>& B, Value* Raw8, Value* MaskVal, const Twine& N = "vm.do") {
			Value* Ext = B.CreateZExt(Raw8, I32Ty, N + ".e");
			if (ObfRegIdx) {
				auto* SL = B.CreateLoad(I32Ty, EffSalt, N + ".s"); SL->setVolatile(true);
				Ext = B.CreateXor(Ext, B.CreateAnd(SL, B.getInt32(0xFF), N + ".sb"), N + ".x");
			}
			return B.CreateAnd(Ext, MaskVal, N + ".m");
		}

		// Helpers that read one obfuscated register-index byte at IP+Off
		Value* rdVR(IRBuilder<>& B, Value* IP, uint32_t Off, const Twine& N) {
			return deobf(B, loadBC(B, IP, Off, N + ".rb"), MaskVR, N);
		}
		Value* rdVR64(IRBuilder<>& B, Value* IP, uint32_t Off, const Twine& N) {
			return deobf(B, loadBC(B, IP, Off, N + ".rb"), MaskVR64, N);
		}
		Value* rdPR(IRBuilder<>& B, Value* IP, uint32_t Off, const Twine& N) {
			return deobf(B, loadBC(B, IP, Off, N + ".rb"), MaskPR, N);
		}
		// Read a freg slot index (same deobf as integer regs)
		Value* rdFR(IRBuilder<>& B, Value* IP, uint32_t Off, const Twine& N) {
			return deobf(B, loadBC(B, IP, Off, N + ".rb"), MaskFR, N);
		}
		// Read a plain byte (no deobf)
		Value* rdByte(IRBuilder<>& B, Value* IP, uint32_t Off, const Twine& N) {
			return B.CreateZExt(loadBC(B, IP, Off, N), I32Ty, N + ".b");
		}
		// Read a u32le at IP+Off
		Value* rdU32(IRBuilder<>& B, Value* IP, uint32_t Off, const Twine& N) {
			Value* b0 = rdByte(B, IP, Off, N + "0"), * b1 = rdByte(B, IP, Off + 1, N + "1");
			Value* b2 = rdByte(B, IP, Off + 2, N + "2"), * b3 = rdByte(B, IP, Off + 3, N + "3");
			Value* W = B.CreateOr(b0, B.CreateShl(b1, 8, N + "s1"), N + "w01");
			W = B.CreateOr(W, B.CreateShl(b2, 16, N + "s2"), N + "w02");
			return B.CreateOr(W, B.CreateShl(b3, 24, N + "s3"), N + "w03");
		}

		// Load/store virtual registers
		Value* ldVR(IRBuilder<>& B, Value* Idx) {
			Value* Raw = B.CreateLoad(I32Ty, B.CreateGEP(I32Ty, EffRegs, Idx, "vm.rg.p"), "vm.rg.v");
			if (!RegEncrypt || !EffRegKeys) return Raw;
			Value* Key = B.CreateLoad(I32Ty,
				B.CreateGEP(I32Ty, EffRegKeys, Idx, "vm.rk.p"), "vm.rk.v");
			return B.CreateXor(Raw, Key, "vm.rg.dec");
		}
		void stVR(IRBuilder<>& B, Value* Idx, Value* V) {
			if (V->getType() != I32Ty && V->getType()->isIntegerTy())
				V = B.CreateZExt(V, I32Ty, "vm.rg.w");
			if (RegEncrypt && EffRegKeys) {
				Value* Key = B.CreateLoad(I32Ty,
					B.CreateGEP(I32Ty, EffRegKeys, Idx, "vm.rk.p"), "vm.rk.v");
				V = B.CreateXor(V, Key, "vm.rg.enc");
			}
			B.CreateStore(V, B.CreateGEP(I32Ty, EffRegs, Idx, "vm.rg.p"));
		}
		Value* ldVR64(IRBuilder<>& B, Value* Idx) {
			Value* Raw = B.CreateLoad(I64Ty, B.CreateGEP(I64Ty, EffRegs64, Idx, "vm.rg64.p"), "vm.rg64.v");
			if (!RegEncrypt || !EffReg64Keys) return Raw;
			Value* Key = B.CreateLoad(I64Ty,
				B.CreateGEP(I64Ty, EffReg64Keys, Idx, "vm.rk64.p"), "vm.rk64.v");
			return B.CreateXor(Raw, Key, "vm.rg64.dec");
		}
		void stVR64(IRBuilder<>& B, Value* Idx, Value* V) {
			if (V->getType() != I64Ty && V->getType()->isIntegerTy())
				V = B.CreateZExtOrTrunc(V, I64Ty, "vm.rg64.w");
			if (RegEncrypt && EffReg64Keys) {
				Value* Key = B.CreateLoad(I64Ty,
					B.CreateGEP(I64Ty, EffReg64Keys, Idx, "vm.rk64.p"), "vm.rk64.v");
				V = B.CreateXor(V, Key, "vm.rg64.enc");
			}
			B.CreateStore(V, B.CreateGEP(I64Ty, EffRegs64, Idx, "vm.rg64.p"));
		}
		Value* ldPR(IRBuilder<>& B, Value* Idx) {
			return B.CreateLoad(PtrTy, B.CreateGEP(PtrTy, EffPregs, Idx, "vm.pg.p"), "vm.pg.v");
		}
		void stPR(IRBuilder<>& B, Value* Idx, Value* V) {
			B.CreateStore(V, B.CreateGEP(PtrTy, EffPregs, Idx, "vm.pg.p"));
		}

		// Load/store f64 virtual registers (freg file) 
		Value* ldFR(IRBuilder<>& B, Value* Idx) {
			Value* Raw = B.CreateLoad(DoubleTy, B.CreateGEP(DoubleTy, EffFregs, Idx, "vm.fg.p"), "vm.fg.v");
			if (!RegEncrypt || !EffFRegKeys) return Raw;
			// XOR on the i64 bit-pattern, then bitcast back to f64
			Value* RawBits = B.CreateBitCast(Raw, I64Ty, "vm.fg.bits");
			Value* Key = B.CreateLoad(I64Ty,
				B.CreateGEP(I64Ty, EffFRegKeys, Idx, "vm.fk.p"), "vm.fk.v");
			Value* Dec = B.CreateXor(RawBits, Key, "vm.fg.dec");
			return B.CreateBitCast(Dec, DoubleTy, "vm.fg.val");
		}
		void stFR(IRBuilder<>& B, Value* Idx, Value* V) {
			// Widen f32 to f64 if needed so freg always holds DoubleTy
			if (V->getType()->isFloatTy()) V = B.CreateFPExt(V, DoubleTy, "vm.fg.w");
			if (RegEncrypt && EffFRegKeys) {
				// XOR on the i64 bit-pattern, then bitcast back to f64
				Value* Bits = B.CreateBitCast(V, I64Ty, "vm.fg.bits");
				Value* Key = B.CreateLoad(I64Ty,
					B.CreateGEP(I64Ty, EffFRegKeys, Idx, "vm.fk.p"), "vm.fk.v");
				V = B.CreateBitCast(B.CreateXor(Bits, Key, "vm.fg.enc"),
					DoubleTy, "vm.fg.eval");
			}
			B.CreateStore(V, B.CreateGEP(DoubleTy, EffFregs, Idx, "vm.fg.p"));
		}

		// Advance IP by N and return the pre-advance value for operand reads
		Value* advIP(IRBuilder<>& B, uint32_t N) {
			auto* Cur = B.CreateLoad(I32Ty, VMIP, "vm.ip.c"); Cur->setVolatile(true);
			auto* St = B.CreateStore(B.CreateAdd(Cur, B.getInt32(N), "vm.ip.n"), VMIP);
			St->setVolatile(true); return Cur;
		}

		// Build one opcode handler block and return an IRBuilder positioned in it
		IRBuilder<> mkOpc(VMOp Opc, const Twine& Name) {
			BasicBlock* BB = BasicBlock::Create(Ctx, "vm.opc." + Name, HFn);
			OpcBB[Opc] = BB; return IRBuilder<>(BB);
		}

		// ── CALL handler support ─────────────────────────────────────────────
		// RetKind2 and MaxArgs were local to buildOpcodeHandlers; promoted to
		// class scope so buildCall2 can be a proper method.
		// RetKind2 and MaxArgs hoisted to VMEngine namespace for SharedState.
		//using llvm::VMEngine::RetKind2;
		static constexpr auto RK2_VOID = VMEngine::RK2_VOID;
		static constexpr auto RK2_I32 = VMEngine::RK2_I32;
		static constexpr auto RK2_PTR = VMEngine::RK2_PTR;
		static constexpr auto RK2_I64 = VMEngine::RK2_I64;
		static constexpr auto RK2_F64 = VMEngine::RK2_F64;
		static constexpr unsigned MaxArgs = VMEngine::MaxArgs;

		void stripBody();
		void buildBytecodeGlobal();
		void buildCalleeGlobal();
		void buildVMEntry();

		// buildOpcodeHandlers sequences the six groups below.
		// Each group is independently testable and recompilable.
		void buildOpcodeHandlers();
		void buildHandlersIntArith();  // LOADI MOVR BINOP BINOP64 ICMP ICMP64 CAST
		void buildHandlersConv();      // SELECT PTRTOINT CAST64 PTRTOINT64 INTTOPTR
		void buildHandlersMem();       // LOAD*/STORE* (all widths)  GEP*  LOADPTR  STOREPTR
		void buildHandlersControl();   // JMP JMPC SWITCH  RET_VOID RET_INT RET_PTR
		void buildHandlersFloat();     // all float/freg opcodes (LOADI_F .. FNEG)
		void buildHandlersCall();      // CALL_VOID CALL_INT CALL_PTR CALL_INT64 CALL_F
		void buildCall2(VMOp Opc, const Twine& Name, llvm::VMEngine::RetKind2 RK);

		void buildHandlerTable();   // must come AFTER buildOpcodeHandlers
		void buildDispatch();       // must come AFTER buildHandlerTable
		void buildEncryptCtor();    // optional encryption constructor
		void buildEncryptCtorAES(); // Step 03: AES-CTR constructor
		void buildEncryptCtorLCG(); // Legacy LCG constructor (useAES=0)

		// Step 06: shared engine setup
		void setupEffLocal();         // point Eff* at per-function state
		void populateVMEngine();      // build handlers in shared vm_engine
		void ensureCallFTyCases();    // extend CALL switches for new FTys
		void computeReturnInfo();     // scan F for return slot before stripBody
		void buildWrapper();          // thin wrapper that tail-calls vm_engine
		void hardenWrapper();         // split + junk + opaque preds
		void mbaHardenWrapper();      // MBA on wrapper arithmetic
		void flattenWrapper();        // switch-dispatch flattening
		void hardenVMEngine(Function* EF, VMEngine::SharedState* SS);

		// anti-debug infrastructure
		/// Emit IR to silently corrupt the salt value (salt ^= PoisonKey).
		/// Used by all anti-debug trap layers.
		void emitSaltCorruption(IRBuilder<>& B, Value* SaltPtr, uint32_t PoisonKey);
		void buildIntegrityHashCtor();   // .init_array FNV-1a check
		void buildCalleeXorCtor();       // .init_array callee XOR masking
		void buildAntiDebugGate(VMEngine::SharedState* SS); // dispatch timing gate
	};

} // namespace llvm
