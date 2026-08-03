#pragma once

#include "llvm/ADT/ArrayRef.h"
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
		// Present only when the engine was built with lazyDecrypt=1 (one extra
		// trailing ptr param). kNumParams above is unchanged so the non-lazy
		// signature — and therefore all output when the feature is off — is
		// byte-identical to before this param was added.
		static constexpr unsigned kParamLazyCtx = kNumParams;

		// Layout of the per-call lazy-decrypt context block (a flat byte buffer
		// allocated by buildWrapper() and threaded through as kParamLazyCtx):
		//   [0..175]   rk      — unmasked 176-byte AES round-key schedule
		//   [176..183] nonce   — 8-byte AES-CTR nonce
		//   [184..199] window  — last-fetched 16-byte AES keystream block
		//   [200..203] cachedBlk (i32) — block index currently held in `window`
		static constexpr unsigned kLazyCtxRKOff = 0;
		static constexpr unsigned kLazyCtxNonceOff = 176;
		static constexpr unsigned kLazyCtxWindowOff = 184;
		static constexpr unsigned kLazyCtxCachedBlkOff = 200;
		static constexpr unsigned kLazyCtxSize = 204;

		/// The well-known symbol name for the shared engine function.
		static constexpr const char* kVMEngineName = "__vm_engine";

		/// Nested-VM: a second, distinct engine function for builds whose
		/// OP_BINOP calls into the inner-virtualized helper. Keeping it a
		/// SEPARATE function (not a runtime flag on the same engine) is what
		/// breaks the recursion: the helper is itself virtualized against
		/// EngineId 0 (the plain engine, computes OP_BINOP inline), so its
		/// bytecode's own binops never call back into the helper.
		static constexpr const char* kVMEngineNestName = "__vm_engine.nest";

		/// P10 engine pool: EngineId packs (poolIdx, layer) as
		/// `EngineId = poolIdx*2 + layer`, where layer 0 = plain, 1 = nest.
		/// poolIdx 0 reproduces the pre-pool ids 0/1 exactly, so a single-engine
		/// build (enginePoolSize==1) is byte-identical.
		inline unsigned engineLayer(unsigned EngineId)  { return EngineId & 1u; }
		inline unsigned enginePoolOf(unsigned EngineId) { return EngineId >> 1; }
		inline unsigned makeEngineId(unsigned Pool, unsigned Layer) {
			return Pool * 2u + (Layer & 1u);
		}

		/// EngineId 0 -> plain engine ("__vm_engine"), 1 -> nesting engine
		/// ("__vm_engine.nest"); pool members >0 append ".p<N>" to the base name
		/// ("__vm_engine.p1", "__vm_engine.nest.p1", ...). Selects both the
		/// SharedState instance and the emitted Function's symbol name. poolIdx 0
		/// returns the exact pre-pool names -> byte-identical single-engine build.
		inline std::string vmEngineName(unsigned EngineId) {
			std::string Base = engineLayer(EngineId) ? kVMEngineNestName : kVMEngineName;
			unsigned Pool = enginePoolOf(EngineId);
			if (Pool == 0) return Base;
			return Base + ".p" + std::to_string(Pool);
		}

		/// Return the canonical FunctionType for vm_engine. `lazy` appends the
		/// trailing lazyctx ptr param; false (default) reproduces the exact
		/// pre-existing signature.
		inline FunctionType* getVMEngineFunctionType(LLVMContext& Ctx, bool lazy = false) {
			Type* PtrTy = PointerType::getUnqual(Ctx);
			Type* I32Ty = Type::getInt32Ty(Ctx);
			Type* VoidTy = Type::getVoidTy(Ctx);
			Type* I64Ty = Type::getInt64Ty(Ctx);
			Type* Params[kNumParams + 1] = {
				PtrTy, I32Ty, PtrTy, PtrTy, PtrTy, PtrTy,
				PtrTy, I32Ty, I32Ty, I32Ty, I32Ty, I32Ty,
				PtrTy, PtrTy,
				PtrTy, PtrTy, PtrTy,   // regkeys, reg64keys, fregkeys
				I64Ty,                 // callee_mask
				PtrTy,                 // lazyctx (only present when lazy)
			};
			unsigned N = lazy ? (kNumParams + 1) : kNumParams;
			return FunctionType::get(VoidTy, ArrayRef<Type*>(Params, N), /*isVarArg=*/false);
		}

		/// Get or create the module-level @__vm_engine (EngineId 0) or
		/// @__vm_engine.nest (EngineId 1) function.
		Function* getOrBuildVMEngine(Module& M, unsigned EngineId = 0);

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
			BasicBlock* OpcBB[OP_COUNT][kMaxHandlerVariants] = {};
			unsigned    NumVariants = 1;   // active variant count for this engine
			bool        EncDispatch = false;   // engine-wide: dispatch uses encrypted index map
			bool        LazyMode = false;      // engine-wide: fetch removes AES per-block instead of ctor whole-buffer
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

			// nested-VM: set once the module-level pure opcode helper(s) have been
			// inner-virtualized, so later functions' VMImpl::run() don't repeat it.
			bool NestedHelpersBuilt = false;
		};

		// EngineId selects which of the (at most two) shared engines' state to
		// return: 0 = plain engine, 1 = nesting engine. Each is built/populated
		// independently (independent "first function" guard), so a nesting-
		// engine build never observes or perturbs the plain engine's state
		// and vice versa. Default (0) reproduces pre-nestedVM behavior exactly.
		SharedState* getSharedState(Module& M, unsigned EngineId = 0);
		void releaseSharedState(Module& M);  // clears state for every EngineId of M

	} // namespace VMEngine


	// Nested-VM helper symbol names + fixed nesting order. Single definition
	// via inline constexpr so every translation unit sees the same objects.
	inline constexpr const char* kNestedBinopHelperName   = "__vm_h_binop";
	inline constexpr const char* kNestedBinop64HelperName = "__vm_h_binop64";
	inline constexpr const char* kNestedIcmpHelperName    = "__vm_h_icmp";
	inline constexpr const char* kNestedIcmp64HelperName  = "__vm_h_icmp64";
	inline constexpr const char* kNestedFcmpHelperName    = "__vm_h_fcmp";
	inline constexpr const char* kNestedCastHelperName    = "__vm_h_cast";
	inline constexpr const char* kNestedBinopFHelperName  = "__vm_h_binop_f";

	// Fixed deterministic nesting order, consumed by VMImpl::run()
	// (helper creation), opcodeNests() (the nestedVMOpcodes cap) and
	// virtualizeNestedHelpersOnce() (inner virtualization). When
	// NestedVMOpcodes==N>0, only the first N entries of this list nest;
	// the rest stay inline.
	struct NestedHelperDesc { VMOp Op; const char* Name; };
	inline constexpr NestedHelperDesc kNestedHelperOrder[] = {
		{ OP_BINOP,   kNestedBinopHelperName   },
		{ OP_BINOP64, kNestedBinop64HelperName },
		{ OP_ICMP,    kNestedIcmpHelperName    },
		{ OP_ICMP64,  kNestedIcmp64HelperName  },
		{ OP_FCMP,    kNestedFcmpHelperName    },
		{ OP_CAST,    kNestedCastHelperName    },
		{ OP_BINOP_F, kNestedBinopFHelperName  },
	};
	inline constexpr unsigned kNumNestedHelpers =
		sizeof(kNestedHelperOrder) / sizeof(kNestedHelperOrder[0]);


	struct VMImpl {
		Function& F;
		Module& M;
		LLVMContext& Ctx;
		Type* I8Ty, * I16Ty, * I32Ty, * I64Ty, * PtrTy;
		Type* DoubleTy;  // f64 type — used by float handler builders

		// Config + RNG are owned/referenced directly (not via VMCtx) so VMImpl
		// can be constructed either from the annotation-driven VMCtx (normal
		// per-function path) or from an explicit config+RNG (synthetic helper
		// functions authored by the pass itself, e.g. nested-VM helpers, which
		// have no FunctionObfContext / annotation of their own).
		VMPassConfig Cfg;
		obf::Rng&    R;

		const bool     ObfRegIdx;
		const bool     EncBytecode;
		const bool     StrongBC;     // P3: per-position PRF Layer-1 keystream
		const bool     BlindTargets; // P3-B: XOR-blind bytecode branch targets
		const bool     LazyDecrypt;  // AES layer removed per-instruction at fetch instead of whole-buffer in ctor
		const bool     RegEncrypt;   // XOR-encrypt register values at rest
		const bool     RollingRegKey; // P4-C: evolve per-slot reg XOR key on each store
		const bool     ConstInStream; // move int/i64/fp constants into the encrypted bytecode stream instead of plaintext wrapper stores
		const bool     NestedVM;         // eligible opcode handlers call a second VM-interpreted layer instead of computing inline
		const unsigned NestedVMOpcodes;  // 0 = all eligible opcodes nest; N>0 = first N in the fixed order (see opcodeNests)
		const bool     NestedVMHardened; // reserved: harden the inner VM layer
		const bool     ThreadedDispatch; // inline fetch/decode/indirectbr into every handler's back-edge; no central vm.dispatch/vm.fetch
		const bool     KeyedDispatch;    // XOR each opcode byte with a per-IP compile-time key at emit/fetch time
		const bool     SuperOps;         // fuse eligible i32 mul+add chains into one OP_MULADD opcode at emission
		const bool     BindAntiDebug;    // fold anti-debug detection into the AES round-key mask instead of salt-poisoning traps
		const bool     RandISA;          // per-build permutation of semantic operand-field byte encodings (currently BinSubop)
		// Which shared engine this build targets. Packs (poolIdx, layer) as
		// poolIdx*2 + layer (layer 0 = plain "__vm_engine", 1 = nesting
		// "__vm_engine.nest"). The layer is derived from NestedVM (a nestedVM=true
		// build wants the engine whose OP_BINOP calls the helper; nestedVM=false,
		// including the helper's own inner-virtualization, wants the plain one).
		// The poolIdx (P10) selects which of EnginePoolSize structurally-distinct
		// engines this function runs; poolIdx 0 reproduces the pre-pool ids 0/1.
		const unsigned EngineId;
		// Number of distinct engines in the module pool (P10, Cfg.enginePoolSize
		// clamped to >=1). 1 = single shared engine (byte-identical to pre-pool).
		const unsigned EnginePoolSize;
		const uint32_t SaltConst;    // full 32-bit salt stored in vm.salt
		const uint8_t  CTSalt;       // low byte of SaltConst must match deobf() key
		// Module-uniform obfuscation seed (Ann.ModuleSeed). Same value for every
		// function of the module — the derivation source for RandISA's module-wide
		// operand-encoding permutation (must agree between the shared handler and
		// every per-function/nested emitter). Passed explicitly through the
		// synthetic ctor so nested-helper virtualization inherits the same map.
		const uint64_t MasterSeed;

		VMOpcodeMap OpMap;
		ISAEnc      IsaEnc;   // identity unless RandISA; module-uniform subop-byte permutation

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
		GlobalVariable* GVAESRKMask = nullptr;  // @fn.vm.aes.rkmask (unmask key for GVAESExpandedKey)

		// lazyDecrypt: forward-declared/looked-up once per module (during the
		// founding function's populateVMEngine call) so the shared engine's
		// fetch path can call it before buildEncryptCtor() links the stub.
		Function* KeystreamFn = nullptr;

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
		Value* EffLazyCtx = nullptr;   // lazy-decrypt context block ptr (null unless LazyDecrypt)
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


		BasicBlock* OpcBB[OP_COUNT][kMaxHandlerVariants] = {};
		unsigned CurVariant = 0;    // variant index currently being emitted
		unsigned NumVariants = 1;   // active variant count (from Cfg, clamped)
		bool EncDispatch = false;   // == SharedState::EncDispatch for this build

		// Maps every block created during buildOpcodeHandlers() to its variant
		// index (0..NumVariants-1). Populated by the emission loop; consumed by
		// diversifyHandlerVariants(). Covers head AND sub-blocks.
		DenseMap<const BasicBlock*, uint8_t> VariantOf;

		// vm.regs/vm.regs64/vm.pregs are allocated with sizes rounded up to the next power of two.
		// This ensures the bitmask in deobf() never produces an out-of-bounds index.
		unsigned NVRAlloc = 0, NVR64Alloc = 0, NPRAlloc = 0, NFRAlloc = 0;

		static unsigned nextPow2(unsigned N) {
			if (N == 0) return 1;
			unsigned P = 1; while (P < N) P <<= 1; return P;
		}

		// Normal per-function path: config + RNG come from the annotation-driven
		// VMCtx (FunctionObfContextAnalysis-backed).
		explicit VMImpl(VMCtx& VCtx) : VMImpl(VCtx.F, VCtx.Cfg, VCtx.R, VCtx.MasterSeed) {}

		// Synthetic-function path: explicit config + RNG, no VMCtx/annotation.
		// Used to virtualize compiler-authored helper functions (e.g. nested-VM
		// opcode helpers) that have no FunctionObfContext of their own. The caller
		// must forward the outer module's MasterSeed so RandISA's operand-encoding
		// map is identical to the shared handler and the outer emitters.
		VMImpl(Function& Fn, const VMPassConfig& CfgIn, obf::Rng& RIn, uint64_t MasterSeedIn = 0)
			: F(Fn), M(*Fn.getParent()), Ctx(Fn.getContext()),
			I8Ty(Type::getInt8Ty(Ctx)),
			I16Ty(Type::getInt16Ty(Ctx)),
			I32Ty(Type::getInt32Ty(Ctx)),
			I64Ty(Type::getInt64Ty(Ctx)),
			PtrTy(PointerType::getUnqual(Ctx)),
			DoubleTy(Type::getDoubleTy(Ctx)),
			Cfg(CfgIn), R(RIn),
			ObfRegIdx(Cfg.obfRegIdx),
			EncBytecode(Cfg.encBytecode),
			StrongBC(Cfg.strongBytecode),
			BlindTargets(Cfg.blindTargets),
			LazyDecrypt(Cfg.lazyDecrypt),
			RegEncrypt(Cfg.regEncrypt),
			RollingRegKey(Cfg.rollingRegKey),
			ConstInStream(Cfg.constInStream),
			NestedVM(Cfg.nestedVM),
			NestedVMOpcodes(Cfg.nestedVMOpcodes),
			NestedVMHardened(Cfg.nestedVMHardened),
			ThreadedDispatch(Cfg.threadedDispatch),
			KeyedDispatch(Cfg.keyedDispatch),
			SuperOps(Cfg.superOps),
			BindAntiDebug(Cfg.bindAntiDebug),
			RandISA(Cfg.randISA),
			EngineId(NestedVM ? 1u : 0u),
			EnginePoolSize(Cfg.enginePoolSize ? Cfg.enginePoolSize : 1u),
			SaltConst(R.u32()),
			// IMPORTANT: indices are only XOR-salted when obfRegIdx=1.
			// When obfRegIdx=0, emitter must write raw indices (CTSalt=0).
			CTSalt(ObfRegIdx ? (uint8_t)(SaltConst & 0xFF) : 0),
			MasterSeed(MasterSeedIn) {
			// per-function opcode permutation for handler-table/bytecode diversity.
			OpMap.initPermuted(R);

			// RandISA (P9-A): module-uniform permutation of semantic operand-field
			// byte encodings. Derived from MasterSeed (NOT the per-function RNG R)
			// so the shared handler switch-cases, every per-function emitter, and
			// nested-helper emitters all agree module-wide. Drawn from a private
			// RNG so R's stream is untouched -> knob-off is byte-identical
			// (IsaEnc stays the identity map from its default ctor).
			if (RandISA) {
				// Each family draws from its own MasterSeed-derived RNG (distinct
				// fork label) so adding a family leaves the others bit-identical.
				obf::Rng BinRng(obf::mix64(MasterSeed ^ obf::fnv1a64("vm.isa.binsubop")));
				IsaEnc.initPermuted(BinRng);
				obf::Rng IcmpRng(obf::mix64(MasterSeed ^ obf::fnv1a64("vm.isa.icmppred")));
				IsaEnc.initIcmpPermuted(IcmpRng);
				obf::Rng CastRng(obf::mix64(MasterSeed ^ obf::fnv1a64("vm.isa.castkind")));
				IsaEnc.initCastPermuted(CastRng);
				obf::Rng FBinRng(obf::mix64(MasterSeed ^ obf::fnv1a64("vm.isa.fbinsubop")));
				IsaEnc.initFBinPermuted(FBinRng);
				obf::Rng FcmpRng(obf::mix64(MasterSeed ^ obf::fnv1a64("vm.isa.fcmppred")));
				IsaEnc.initFcmpPermuted(FcmpRng);
			}

			//  generate per-function AES key material from RNG
			for (int i = 0; i < 4; i++) {
				uint32_t W = R.u32();
				AESKey[i * 4 + 0] = (W >> 0) & 0xFF;
				AESKey[i * 4 + 1] = (W >> 8) & 0xFF;
				AESKey[i * 4 + 2] = (W >> 16) & 0xFF;
				AESKey[i * 4 + 3] = (W >> 24) & 0xFF;
			}
			vm_aes::keyExpand(AESKey, AESExpandedKey);
			for (auto& b : AESRKMask) b = (uint8_t)(R.u32() & 0xFF);
			AESNonce = ((uint64_t)R.u32() << 32) | R.u32();
		}

		bool run();

	private:
		//  IR helpers
		// Key: byte ^= (vm.salt ^ absolute_byte_index) & 0xFF  (or PRF mix when StrongBC)

		// Compile-time mix — mirrors ksByteIR() op-for-op. Used by buildBytecodeGlobal()
		// to compute the Layer-1 keystream byte at compile time.
		static uint8_t ksByteCT(uint32_t salt, uint32_t idx) {
			uint32_t k = salt ^ (idx * 0x9E3779B1u);
			k ^= k >> 15;
			k *= 0x85EBCA77u;
			k ^= k >> 13;
			return (uint8_t)(k & 0xFFu);
		}

		// Runtime (IR) mix — mirrors ksByteCT() op-for-op. Emits the instructions that
		// compute the Layer-1 keystream byte from the volatile runtime salt and index.
		Value* ksByteIR(IRBuilder<>& B, Value* Salt, Value* Idx32, const Twine& N) {
			Value* k = B.CreateXor(Salt,
				B.CreateMul(Idx32, B.getInt32(0x9E3779B1u), N + ".k0m"),
				N + ".k0");
			k = B.CreateXor(k, B.CreateLShr(k, B.getInt32(15), N + ".k1s"), N + ".k1");
			k = B.CreateMul(k, B.getInt32(0x85EBCA77u), N + ".k2");
			k = B.CreateXor(k, B.CreateLShr(k, B.getInt32(13), N + ".k3s"), N + ".k3");
			Value* Key32 = B.CreateAnd(k, B.getInt32(0xFF), N + ".km");
			return B.CreateTrunc(Key32, I8Ty, N + ".k8");
		}

		// P3-B: runtime (IR) branch-target-blind key mix — mirrors
		// BytecodeEmitter::tgtKeyCT() op-for-op. Loads the volatile runtime salt
		// itself and returns the full 32-bit key. Distinct constants from
		// ksByteIR() (Layer-1 keystream) so the two blinding layers don't share
		// a constant.
		Value* tgtKeyIR(IRBuilder<>& B, const Twine& N) {
			auto* SL = B.CreateLoad(I32Ty, EffSalt, N + ".tks"); SL->setVolatile(true);
			Value* k = B.CreateXor(SL, B.getInt32(0x2545F491u), N + ".tk0");
			k = B.CreateMul(k, B.getInt32(0x9E3779B1u), N + ".tk1");
			k = B.CreateXor(k, B.CreateLShr(k, B.getInt32(16), N + ".tk2s"), N + ".tk2");
			return k;
		}

		// keyedDispatch: runtime (IR) mix — mirrors BytecodeEmitter::opKeyByteCT
		// op-for-op. Computes the per-IP opcode-byte XOR key from the runtime
		// salt (caller loads it, volatile, before calling this) and the
		// fetch-time IP. Applied to the raw fetched opcode byte before the
		// OP_COUNT urem in emitThreadedTail/buildDispatch.
		Value* opKeyByteIR(IRBuilder<>& B, Value* Salt, Value* Idx32, const Twine& N) {
			Value* IPp1 = B.CreateAdd(Idx32, B.getInt32(1), N + ".ok0");
			Value* Mul = B.CreateMul(Salt, IPp1, N + ".ok1");
			Value* Shr = B.CreateLShr(Salt, B.getInt32(8), N + ".ok2");
			Value* K = B.CreateXor(Mul, Shr, N + ".ok3");
			Value* Key32 = B.CreateAnd(K, B.getInt32(0xFF), N + ".okm");
			return B.CreateTrunc(Key32, I8Ty, N + ".ok8");
		}

		// Lazy AES fetch: remove the AES-CTR layer for the byte at Idx32.
		// Recomputes the 16-byte keystream block covering Idx32 via KeystreamFn
		// into the per-call scratch window (EffLazyCtx), then reads the covering
		// byte. Emitted straight-line (no control flow) so callers that assume
		// linear emission across loadBC/loadBCDyn stay valid.
		// Only called when LazyDecrypt (implies EncBytecode).
		Value* lazyAESByte(IRBuilder<>& B, Value* Idx32, const Twine& N) {
			Value* RKPtr = B.CreateGEP(I8Ty, EffLazyCtx,
				B.getInt64(VMEngine::kLazyCtxRKOff), N + ".lz.rk");
			Value* NoncePtr = B.CreateGEP(I8Ty, EffLazyCtx,
				B.getInt64(VMEngine::kLazyCtxNonceOff), N + ".lz.nc");
			Value* WindowPtr = B.CreateGEP(I8Ty, EffLazyCtx,
				B.getInt64(VMEngine::kLazyCtxWindowOff), N + ".lz.win");

			Value* Blk = B.CreateLShr(Idx32, B.getInt32(4), N + ".lz.blk");
			B.CreateCall(KeystreamFn, { RKPtr, NoncePtr, Blk, WindowPtr });
			Value* ByteOff = B.CreateAnd(Idx32, B.getInt32(0xF), N + ".lz.boff");
			Value* BytePtr = B.CreateGEP(I8Ty, WindowPtr,
				B.CreateZExt(ByteOff, I64Ty, N + ".lz.boff64"), N + ".lz.bytep");
			return B.CreateLoad(I8Ty, BytePtr, N + ".lz.byte");
		}

		Value* loadBC(IRBuilder<>& B, Value* IP, uint32_t Off, const Twine& N = "vm.bc") {
			Value* Idx32 = Off ? B.CreateAdd(IP, B.getInt32(Off), N + ".i32") : IP;
			Value* Idx64 = B.CreateSExt(Idx32, I64Ty, N + ".ip64");
			Value* Ptr = B.CreateGEP(I8Ty, EffBC, Idx64, N + ".p");
			Value* Raw = B.CreateLoad(I8Ty, Ptr, N);
			if (!EncBytecode) return Raw;

			if (LazyDecrypt && EffLazyCtx)
				Raw = B.CreateXor(Raw, lazyAESByte(B, Idx32, N), N + ".aesx");

			auto* SL = B.CreateLoad(I32Ty, EffSalt, N + ".s");
			SL->setVolatile(true);
			Value* Key8;
			if (StrongBC) {
				Key8 = ksByteIR(B, SL, Idx32, N);
			} else {
				Value* Key32 = B.CreateAnd(B.CreateXor(SL, Idx32, N + ".kx"), B.getInt32(0xFF), N + ".km");
				Key8 = B.CreateTrunc(Key32, I8Ty, N + ".k8");
			}
			return B.CreateXor(Raw, Key8, N + ".dec");
		}

		Value* loadBCDyn(IRBuilder<>& B, Value* IP, Value* Off, const Twine& N = "vm.bcd") {
			Value* Idx32 = B.CreateAdd(IP, Off, N + ".i32");
			Value* Idx64 = B.CreateSExt(Idx32, I64Ty, N + ".ip64");
			Value* Ptr = B.CreateGEP(I8Ty, EffBC, Idx64, N + ".p");
			Value* Raw = B.CreateLoad(I8Ty, Ptr, N);
			if (!EncBytecode) return Raw;

			if (LazyDecrypt && EffLazyCtx)
				Raw = B.CreateXor(Raw, lazyAESByte(B, Idx32, N), N + ".aesx");

			auto* SL = B.CreateLoad(I32Ty, EffSalt, N + ".s");
			SL->setVolatile(true);
			Value* Key8;
			if (StrongBC) {
				Key8 = ksByteIR(B, SL, Idx32, N);
			} else {
				Value* Key32 = B.CreateAnd(B.CreateXor(SL, Idx32, N + ".kx"), B.getInt32(0xFF), N + ".km");
				Key8 = B.CreateTrunc(Key32, I8Ty, N + ".k8");
			}
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

		// P4-C: rolling register-key evolution (LCG step). Only invoked when
		// RollingRegKey is set; keeps rollingRegKey=false byte-identical.
		Value* evolveKey32(IRBuilder<>& B, Value* K) {
			return B.CreateAdd(B.CreateMul(K, B.getInt32(0x9E3779B1u), "vm.rk.em"),
				B.getInt32(0x85EBCA77u), "vm.rk.ev");
		}
		Value* evolveKey64(IRBuilder<>& B, Value* K) {
			return B.CreateAdd(
				B.CreateMul(K, B.getInt64(0x9E3779B97F4A7C15ull), "vm.rk64.em"),
				B.getInt64(0x2545F4914F6CDD1Dull), "vm.rk64.ev");
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
				Value* KPtr = B.CreateGEP(I32Ty, EffRegKeys, Idx, "vm.rk.p");
				Value* Key = B.CreateLoad(I32Ty, KPtr, "vm.rk.v");
				if (RollingRegKey) {
					Key = evolveKey32(B, Key);
					B.CreateStore(Key, KPtr);
				}
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
				Value* KPtr64 = B.CreateGEP(I64Ty, EffReg64Keys, Idx, "vm.rk64.p");
				Value* Key = B.CreateLoad(I64Ty, KPtr64, "vm.rk64.v");
				if (RollingRegKey) {
					Key = evolveKey64(B, Key);
					B.CreateStore(Key, KPtr64);
				}
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
				Value* KPtr = B.CreateGEP(I64Ty, EffFRegKeys, Idx, "vm.fk.p");
				Value* Key = B.CreateLoad(I64Ty, KPtr, "vm.fk.v");
				if (RollingRegKey) {
					Key = evolveKey64(B, Key);
					B.CreateStore(Key, KPtr);
				}
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

		// Build one opcode handler block and return an IRBuilder positioned in it.
		// threadedDispatch pre-creates every OpcBB[Opc][variant] placeholder
		// before any handler body is built (each handler's inlined dispatch
		// tail needs the full successor set up front) -- reuse and rename that
		// block instead of allocating a fresh one. Off path unchanged.
		IRBuilder<> mkOpc(VMOp Opc, const Twine& Name) {
			if (ThreadedDispatch && OpcBB[Opc][CurVariant]) {
				BasicBlock* BB = OpcBB[Opc][CurVariant];
				BB->setName("vm.opc." + Name + ".v" + Twine(CurVariant));
				return IRBuilder<>(BB);
			}
			BasicBlock* BB = BasicBlock::Create(Ctx,
				"vm.opc." + Name + ".v" + Twine(CurVariant), HFn);
			OpcBB[Opc][CurVariant] = BB; return IRBuilder<>(BB);
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

		// Nested-VM: pure per-opcode helpers authored fresh + virtualized via a
		// second VMImpl over the shared engine. See VMPass_Impl.cpp for the
		// sequencing rationale.
		Function* getOrCreateNestedBinopHelper();   // idempotent per module
		Function* getOrCreateNestedBinop64Helper(); // idempotent per module
		Function* getOrCreateNestedIcmpHelper();    // idempotent per module
		Function* getOrCreateNestedIcmp64Helper();  // idempotent per module
		Function* getOrCreateNestedFcmpHelper();    // idempotent per module
		Function* getOrCreateNestedCastHelper();    // idempotent per module
		Function* getOrCreateNestedBinopFHelper();  // idempotent per module
		Function* getOrCreateNestedHelper(VMOp Op); // dispatches to the per-opcode authors above
		void virtualizeNestedHelpersOnce();         // idempotent per module

		// Whether Op is nested for this build: NestedVM is on, and (Op is
		// within the first NestedVMOpcodes entries of the fixed nesting order,
		// or NestedVMOpcodes==0, meaning "all eligible opcodes nest").
		bool opcodeNests(VMOp Op) const;

		void buildHandlerTable();   // must come AFTER buildOpcodeHandlers
		void buildDispatch();       // must come AFTER buildHandlerTable

		// threadedDispatch: emits the fetch/decode/indirectbr sequence inline
		// at B's current insertion point (bounds check -> ExitBB; otherwise
		// load+advance IP, decode opcode, indirectbr to the target handler).
		// Terminates B's current block; callers must not emit after calling
		// this. Mirrors buildDispatch()'s vm.fetch logic exactly.
		void emitThreadedTail(IRBuilder<>& B);

		// Handler back-edge dispatch: central Dispatch branch when
		// !ThreadedDispatch, inlined threaded tail otherwise.
		void nextInsn(IRBuilder<>& B);
		void buildEncryptCtor();    // optional encryption constructor (AES-CTR)

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
		void diversifyHandlerVariants(Function* EF); // per-variant MBA metamorphism

		// anti-debug infrastructure
		/// Emit IR to silently corrupt the salt value (salt ^= PoisonKey).
		/// Used by all anti-debug trap layers.
		void emitSaltCorruption(IRBuilder<>& B, Value* SaltPtr, uint32_t PoisonKey);
		void buildIntegrityHashCtor();   // .init_array FNV-1a check
		void buildCalleeXorCtor();       // .init_array callee XOR masking
		void buildAntiDebugGate(VMEngine::SharedState* SS); // dispatch timing gate
		void buildAntiDebugKeyBindCtor(); // .init_array: fold detection into AES round-key mask
	};

} // namespace llvm
