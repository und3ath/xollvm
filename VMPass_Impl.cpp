#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/VMPass_Verifier.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/AESStubBitcode.h"
#include "llvm/Transforms/Obfuscator/OpaqueUtils.h"
#include "llvm/Transforms/Obfuscator/MbaUtils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"

STATISTIC(VMFunctions, "Functions virtualised by VMPass");
STATISTIC(VMCallSites, "Call sites virtualised");



// ============================================================================
// Compile-time AES-128 engine 
//
// Runs ONLY inside the compiler.  Identical to the engine in
// StringEncryption.cpp — duplicated here to avoid cross-pass coupling.
// None of this code is emitted into the target binary.
// ============================================================================

namespace llvm
{
	namespace vm_aes
	{

		const uint8_t SBOX[256] = {
			0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
			0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
			0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
			0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
			0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
			0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
			0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
			0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
			0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
			0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
			0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
			0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
			0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
			0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
			0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
			0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
		};

		const uint8_t RCON[11] = {
			0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
		};

		void keyExpand(const uint8_t key[16], uint8_t rk[176]) {
			for (int i = 0; i < 16; i++) rk[i] = key[i];
			for (int i = 4; i < 44; i++) {
				uint8_t temp[4];
				for (int j = 0; j < 4; j++) temp[j] = rk[(i - 1) * 4 + j];
				if (i % 4 == 0) {
					uint8_t t = temp[0];
					temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
					for (int j = 0; j < 4; j++) temp[j] = SBOX[temp[j]];
					temp[0] ^= RCON[i / 4];
				}
				for (int j = 0; j < 4; j++)
					rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ temp[j];
			}
		}

		static inline uint8_t xtime(uint8_t x) {
			return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1bu));
		}

		static void shiftRows(uint8_t s[16]) {
			uint8_t t;
			t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
			t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
			t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
		}

		static void mixColumns(uint8_t s[16]) {
			for (int c = 0; c < 4; c++) {
				uint8_t a = s[c * 4], b = s[c * 4 + 1], cc = s[c * 4 + 2], d = s[c * 4 + 3];
				uint8_t tmp = a ^ b ^ cc ^ d;
				s[c * 4 + 0] ^= tmp ^ xtime((uint8_t)(a ^ b));
				s[c * 4 + 1] ^= tmp ^ xtime((uint8_t)(b ^ cc));
				s[c * 4 + 2] ^= tmp ^ xtime((uint8_t)(cc ^ d));
				s[c * 4 + 3] ^= tmp ^ xtime((uint8_t)(d ^ a));
			}
		}

		void encryptBlock(const uint8_t rk[176], uint8_t blk[16]) {
			uint8_t s[16];
			for (int i = 0; i < 16; i++) s[i] = blk[i] ^ rk[i];
			for (int r = 1; r <= 9; r++) {
				for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
				shiftRows(s);
				mixColumns(s);
				for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
			}
			for (int i = 0; i < 16; i++) s[i] = SBOX[s[i]];
			shiftRows(s);
			for (int i = 0; i < 16; i++) blk[i] = s[i] ^ rk[160 + i];
		}

		void ctr(const uint8_t rk[176], const uint8_t nonce8[8],
			uint8_t* buf, size_t len) {
			uint8_t ctrblk[16] = {};
			for (int i = 0; i < 8; i++) ctrblk[i] = nonce8[i];
			// ctrblk[8..15] = 0

			size_t off = 0;
			while (off < len) {
				uint8_t ks[16];
				for (int i = 0; i < 16; i++) ks[i] = ctrblk[i];
				encryptBlock(rk, ks);

				size_t n = std::min<size_t>(16, len - off);
				for (size_t i = 0; i < n; i++) buf[off + i] ^= ks[i];
				off += 16;

				// Increment big-endian 64-bit counter in bytes [8..15]
				for (int i = 15; i >= 8; i--)
					if (++ctrblk[i]) break;
			}
		}

	} // namespace vm_aes
} // namespace llvm




static void provideStubKeyProviderBodies(Module& M) {
	LLVMContext& C = M.getContext();
	Type* VoidTy = Type::getVoidTy(C);
	Type* PtrTy = PointerType::getUnqual(C);
	Type* I8Ty = Type::getInt8Ty(C);
	Type* I64Ty = Type::getInt64Ty(C);

	for (const char* Name : { "__aes_key_a", "__aes_key_b" }) {
		Function* F = M.getFunction(Name);
		if (!F) continue;                    // not in module — fine
		if (!F->isDeclaration()) continue;   // strenc gave it a body — skip

		// Trivial body: memset(out, 0, 88); ret void;
		BasicBlock* BB = BasicBlock::Create(C, "entry", F);
		IRBuilder<> B(BB);
		B.CreateMemSet(F->getArg(0), ConstantInt::get(I8Ty, 0),
			ConstantInt::get(I64Ty, 88), MaybeAlign(1));
		B.CreateRetVoid();

		F->setLinkage(GlobalValue::PrivateLinkage);
		F->addFnAttr(Attribute::NoUnwind);
		F->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
	}
}




//  VMImpl method bodies ─

void VMImpl::stripBody() {
	SmallVector<BasicBlock*, 32> BBs;
	for (BasicBlock& BB : F) BBs.push_back(&BB);
	for (BasicBlock* BB : BBs) BB->dropAllReferences();
	for (BasicBlock* BB : BBs) BB->eraseFromParent();
}

// ─ linkStubForVM 
// Link the strenc AES stub into the module (if not already present) and
// return the __obf_aes_ctr_decrypt function.  Uses the same dedup logic
// as strenc: if __strenc_decrypt already exists, skip re-linking.
// This is a thin wrapper that calls StrEncImpl::linkStubAndGetCTRDecrypt
// (defined in StringEncryption.cpp) via the same embedded bitcode.

//  buildBytecodeGlobal 

void VMImpl::buildBytecodeGlobal() {
	SmallVector<Constant*, 1024> Bytes;
	Bytes.reserve(E.BC.size());

	//  Layer 1: XOR-at-rest (salt ^ ip) — removed by loadBC() at each fetch
	//  Layer 2: keystream layer removed by the global ctor before main()
	//    useAES=1: AES-128-CTR keystream 
	//    useAES=0: LCG keystream (legacy)

	// Pre-compute AES keystream for compile-time encryption
	SmallVector<uint8_t, 1024> AESKeystream;
	if (EncBytecode && UseAES) {
		// Generate the full keystream at compile time
		uint8_t nonce8[8];
		for (int i = 0; i < 8; i++)
			nonce8[i] = (uint8_t)((AESNonce >> (8 * i)) & 0xFF);

		AESKeystream.resize(E.BC.size(), 0);
		// XOR a zero buffer with the keystream = the keystream itself
		vm_aes::ctr(AESExpandedKey, nonce8, AESKeystream.data(), AESKeystream.size());
	}

	uint64_t LCGKey = EncSeed;
	for (size_t I = 0; I < E.BC.size(); ++I) {
		uint8_t V = E.BC[I];
		if (EncBytecode) {
			// Layer 1: XOR-at-rest (removed by loadBC() at each fetch)
			uint8_t K = (uint8_t)((SaltConst ^ (uint32_t)I) & 0xFFu);
			V ^= K;

			// Layer 2: keystream (removed by ctor before main())
			if (UseAES) {
				V ^= AESKeystream[I];
			}
			else {
				LCGKey = LCGKey * LCG_A + LCG_C;
				V ^= (uint8_t)((LCGKey >> 24) & 0xFFu);
			}
		}
		Bytes.push_back(ConstantInt::get(I8Ty, V));
	}

	auto* ATy = ArrayType::get(I8Ty, Bytes.size());
	GVBytecode = new GlobalVariable(
		M, ATy,
		/*isConst=*/true,
		GlobalValue::PrivateLinkage,
		ConstantArray::get(ATy, Bytes),
		(F.getName() + ".vm.bytecode").str());
	GVBytecode->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);


	// Writable runtime buffer filled by the constructor when encBytecode=1.
	// The interpreter reads from this buffer (still XOR-at-rest) to avoid writing into .rdata.
	if (EncBytecode) {
		GVBytecodeRT = new GlobalVariable(
			M, ATy,
			/*isConst=*/false,
			GlobalValue::PrivateLinkage,
			Constant::getNullValue(ATy),
			(F.getName() + ".vm.bytecode.rt").str());
		GVBytecodeRT->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
	}
}

//  buildCalleeGlobal 

void VMImpl::buildCalleeGlobal() {
	if (E.CalleeTab.empty()) return;

	// Existing: emit GVCallees [C x ptr]
	SmallVector<Constant*, 8> Cs;
	for (Value* V : E.CalleeTab) Cs.push_back(cast<Constant>(V));
	auto* ATy = ArrayType::get(PtrTy, Cs.size());
	// writable when hardened (callee XOR ctor modifies in-place)
	GVCallees = new GlobalVariable(M, ATy,
		/*isConstant=*/!VCtx.Cfg.hardened,
		GlobalValue::PrivateLinkage,
		ConstantArray::get(ATy, Cs), (F.getName() + ".vm.callees").str());
	GVCallees->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
	VMCallSites += (unsigned)Cs.size();

	// emit GVFTyIndices [C x i8] and populate shared FTy registry.
	UniqueFTys.clear();
	auto* SS = VMEngine::getSharedState(M);
	SmallVector<uint8_t, 8> IdxBytes;
	IdxBytes.reserve(E.CalleeFTyTab.size());
	for (FunctionType* FTy : E.CalleeFTyTab) {
		auto [It, Inserted] = SS->FTyToIdx.try_emplace(
			FTy, (uint8_t)SS->SharedFTys.size());
		if (Inserted) SS->SharedFTys.push_back(FTy);
		IdxBytes.push_back(It->second);
	}
	UniqueFTys.assign(SS->SharedFTys.begin(), SS->SharedFTys.end());
	SmallVector<Constant*, 8> IdxConsts;
	IdxConsts.reserve(IdxBytes.size());
	for (uint8_t Idx : IdxBytes)
		IdxConsts.push_back(ConstantInt::get(I8Ty, Idx));
	auto* IATy = ArrayType::get(I8Ty, IdxConsts.size());
	GVFTyIndices = new GlobalVariable(M, IATy, /*isConstant=*/true,
		GlobalValue::PrivateLinkage,
		ConstantArray::get(IATy, IdxConsts),
		(F.getName() + ".vm.ftyidx").str());
	GVFTyIndices->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
}

//  buildVMEntry 

void VMImpl::buildVMEntry()
{
	Entry = BasicBlock::Create(Ctx, "vm.entry", &F);
	IRBuilder<> B(Entry);



	// IMPORTANT: Re-create the original entry-block allocas *first*.
	//
	// The i64-ops runtime test observes a stack address via ptrtoint64.
	// If we allocate VM state before the original locals, we shift those
	// locals in the frame and change the ptrtoint value (breaking
	// correctness vs the base binary).
	SmallVector<AllocaInst*, 8> Reallocas;
	Reallocas.reserve(E.PHIAllocas.size());
	for (const auto& PA : E.PHIAllocas) {
		auto* NA = B.CreateAlloca(PA.AllocTy, nullptr, Twine(PA.Name) + ".v7");
		if (PA.A) NA->setAlignment(*PA.A);
		Reallocas.push_back(NA);
	}


	VMIP = B.CreateAlloca(I32Ty, nullptr, "vm.ip");
	VMSalt = B.CreateAlloca(I32Ty, nullptr, "vm.salt");
	VMRegs = B.CreateAlloca(I32Ty, B.getInt64(NVRAlloc), "vm.regs");
	VMRegs64 = B.CreateAlloca(I64Ty, B.getInt64(NVR64Alloc), "vm.regs64");
	VMPRegs = B.CreateAlloca(PtrTy, B.getInt64(NPRAlloc), "vm.pregs");
	VMFregs = B.CreateAlloca(DoubleTy, B.getInt64(NFRAlloc), "vm.fregs");

	// Write compile-time salt (volatile so optimizer cannot track its value)
	B.CreateStore(B.getInt32(SaltConst), VMSalt)->setVolatile(true);

	// Integer args -> vregs / vregs64
	for (Argument& A : F.args()) {
		Type* AT = A.getType();
		if (!AT->isIntegerTy()) continue;

		if (AT->isIntegerTy(64)) {
			stVR64(B, B.getInt32(E.VR64.lookup(&A)), &A);
			continue;
		}
		Value* V = (AT == I32Ty) ? (Value*)&A : B.CreateZExt(&A, I32Ty, "vm.ax");
		stVR(B, B.getInt32(E.VR.lookup(&A)), V);
	}
	// Pointer args -> pregs
	for (Argument& A : F.args()) {
		if (A.getType()->isPointerTy()) stPR(B, B.getInt32(E.PR.lookup(&A)), &A);
	}

	// Entry-block allocas -> pregs
	for (unsigned I = 0, N = (unsigned)E.PHIAllocas.size(); I != N; ++I)
		stPR(B, B.getInt32(E.PHIAllocas[I].Slot), Reallocas[I]);

	// Integer constants -> vregs
	for (auto& [S, CI] : E.ImmLoads) {
		Value* V = (CI->getType() == I32Ty)
			? (Value*)CI
			: B.CreateZExt(CI, I32Ty, "vm.cx");
		stVR(B, B.getInt32(S), V);
	}
	// i64 constants -> vregs64
	for (auto& [S, CI] : E.ImmLoads64) {
		Value* V = (CI->getType() == I64Ty) ? (Value*)CI : B.CreateZExtOrTrunc(CI, I64Ty, "vm.c64x");
		stVR64(B, B.getInt32(S), V);
	}
	// Pointer constants / globals -> pregs
	for (auto& [S, PV] : E.PtrLoads)
		stPR(B, B.getInt32(S), cast<Constant>(PV));


	// Float args -> fregs  
	for (Argument& A : F.args()) {
		Type* AT = A.getType();
		if (!AT->isFloatTy() && !AT->isDoubleTy()) continue;
		Value* V = AT->isDoubleTy() ? (Value*)&A
			: B.CreateFPExt(&A, DoubleTy, "vm.fa.ext");
		stFR(B, B.getInt32(E.FR.lookup(&A)), V);
	}
	// Float constants -> fregs  
	for (auto& [Slot, CF] : E.ImmLoadsF) {
		double DV = CF->getType()->isDoubleTy()
			? CF->getValueAPF().convertToDouble()
			: (double)CF->getValueAPF().convertToFloat();
		stFR(B, B.getInt32(Slot), ConstantFP::get(DoubleTy, DV));
	}


	// IP = 0  (entry block is always first, starts at offset 0)
	B.CreateStore(B.getInt32(0), VMIP)->setVolatile(true);
	// Point Eff* at per-function state for handler building
	setupEffLocal();
}





void VMImpl::buildOpcodeHandlers() {
	buildHandlersIntArith();
	buildHandlersConv();
	buildHandlersMem();
	buildHandlersControl();
	buildHandlersFloat();
	buildHandlersCall();
}

void VMImpl::buildHandlersIntArith() {
	//  OP_LOADI  [dst:u8 imm:u32le] -- vreg[dst] = imm 
	{
		auto B = mkOpc(OP_LOADI, "loadi");
		Value* IP = advIP(B, 5);
		stVR(B, rdVR(B, IP, 0, "vm.li.d"), rdU32(B, IP, 1, "vm.li.i"));
		B.CreateBr(Dispatch);
	}

	//  OP_MOVR  [dst:u8 src:u8] -- vreg[dst] = vreg[src] 
	{
		auto B = mkOpc(OP_MOVR, "movr");
		Value* IP = advIP(B, 2);
		stVR(B, rdVR(B, IP, 0, "vm.mr.d"), ldVR(B, rdVR(B, IP, 1, "vm.mr.s")));
		B.CreateBr(Dispatch);
	}

	//  OP_BINOP  -- [dst:u8 a:u8 b:u8 subop:u8] 
	// NOTE: must not speculatively execute div/rem for other subops (would trap on BV==0).
	{
		auto B = mkOpc(OP_BINOP, "binop");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.bo.d");
		Value* AIdx = rdVR(B, IP, 1, "vm.bo.a");
		Value* BIdx = rdVR(B, IP, 2, "vm.bo.b");
		Value* Sub = rdByte(B, IP, 3, "vm.bo.op");
		Value* AV = ldVR(B, AIdx);
		Value* BV = ldVR(B, BIdx);

		BasicBlock* MergeBB = BasicBlock::Create(Ctx, "vm.bo.merge", HFn);
		BasicBlock* DefBB = BasicBlock::Create(Ctx, "vm.bo.def", HFn);


		// Default implements BS_ADD (matches previous select-chain fallback)
		SwitchInst* SW = B.CreateSwitch(Sub, DefBB, 12);

		IRBuilder<> BM(MergeBB);
		auto* Phi = BM.CreatePHI(I32Ty, 13, "vm.bo.r");
		stVR(BM, Dst, Phi);
		BM.CreateBr(Dispatch);

		{
			IRBuilder<> BD(DefBB);
			Value* R = BD.CreateAdd(AV, BV, "vm.add");
			Phi->addIncoming(R, DefBB);
			BD.CreateBr(MergeBB);
		}

		auto addCase = [&](uint32_t Case, const Twine& BBName, auto Emit) {
			BasicBlock* CBB = BasicBlock::Create(Ctx, BBName, HFn);
			IRBuilder<> BC(CBB);
			Value* R = Emit(BC);
			Phi->addIncoming(R, CBB);
			BC.CreateBr(MergeBB);
			SW->addCase(B.getInt32(Case), CBB);
			};

		addCase(BS_SUB, "vm.bo.sub", [&](IRBuilder<>& BC) { return BC.CreateSub(AV, BV, "vm.sub"); });
		addCase(BS_MUL, "vm.bo.mul", [&](IRBuilder<>& BC) { return BC.CreateMul(AV, BV, "vm.mul"); });
		addCase(BS_AND, "vm.bo.and", [&](IRBuilder<>& BC) { return BC.CreateAnd(AV, BV, "vm.and"); });
		addCase(BS_OR, "vm.bo.or", [&](IRBuilder<>& BC) { return BC.CreateOr(AV, BV, "vm.or"); });
		addCase(BS_XOR, "vm.bo.xor", [&](IRBuilder<>& BC) { return BC.CreateXor(AV, BV, "vm.xor"); });
		addCase(BS_SHL, "vm.bo.shl", [&](IRBuilder<>& BC) { return BC.CreateShl(AV, BV, "vm.shl"); });
		addCase(BS_LSHR, "vm.bo.lshr", [&](IRBuilder<>& BC) { return BC.CreateLShr(AV, BV, "vm.lshr"); });
		addCase(BS_ASHR, "vm.bo.ashr", [&](IRBuilder<>& BC) { return BC.CreateAShr(AV, BV, "vm.ashr"); });
		addCase(BS_SDIV, "vm.bo.sdiv", [&](IRBuilder<>& BC) { return BC.CreateSDiv(AV, BV, "vm.sdiv"); });
		addCase(BS_UDIV, "vm.bo.udiv", [&](IRBuilder<>& BC) { return BC.CreateUDiv(AV, BV, "vm.udiv"); });
		addCase(BS_SREM, "vm.bo.srem", [&](IRBuilder<>& BC) { return BC.CreateSRem(AV, BV, "vm.srem"); });
		addCase(BS_UREM, "vm.bo.urem", [&](IRBuilder<>& BC) { return BC.CreateURem(AV, BV, "vm.urem"); });
	}


	//  OP_BINOP64 -- [dst64:u8 a64:u8 b64:u8 subop:u8] 
	// NOTE: must not speculatively execute div/rem for other subops (would trap on BV==0).
	{
		auto B = mkOpc(OP_BINOP64, "binop64");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR64(B, IP, 0, "vm.bo64.d");
		Value* AIdx = rdVR64(B, IP, 1, "vm.bo64.a");
		Value* BIdx = rdVR64(B, IP, 2, "vm.bo64.b");
		Value* Sub = rdByte(B, IP, 3, "vm.bo64.op");
		Value* AV = ldVR64(B, AIdx);
		Value* BV = ldVR64(B, BIdx);

		BasicBlock* MergeBB = BasicBlock::Create(Ctx, "vm.bo64.merge", HFn);
		BasicBlock* DefBB = BasicBlock::Create(Ctx, "vm.bo64.def", HFn);

		// Default implements BS_ADD (matches previous select-chain fallback)
		SwitchInst* SW = B.CreateSwitch(Sub, DefBB, 12);

		IRBuilder<> BM(MergeBB);
		auto* Phi = BM.CreatePHI(I64Ty, 13, "vm.bo64.r");
		stVR64(BM, Dst, Phi);
		BM.CreateBr(Dispatch);

		{
			IRBuilder<> BD(DefBB);
			Value* R = BD.CreateAdd(AV, BV, "vm64.add");
			Phi->addIncoming(R, DefBB);
			BD.CreateBr(MergeBB);
		}

		auto addCase = [&](uint32_t Case, const Twine& BBName, auto Emit) {
			BasicBlock* CBB = BasicBlock::Create(Ctx, BBName, HFn);
			IRBuilder<> BC(CBB);
			Value* R = Emit(BC);
			Phi->addIncoming(R, CBB);
			BC.CreateBr(MergeBB);
			SW->addCase(B.getInt32(Case), CBB);
			};

		addCase(BS_SUB, "vm.bo64.sub", [&](IRBuilder<>& BC) { return BC.CreateSub(AV, BV, "vm64.sub"); });
		addCase(BS_MUL, "vm.bo64.mul", [&](IRBuilder<>& BC) { return BC.CreateMul(AV, BV, "vm64.mul"); });
		addCase(BS_AND, "vm.bo64.and", [&](IRBuilder<>& BC) { return BC.CreateAnd(AV, BV, "vm64.and"); });
		addCase(BS_OR, "vm.bo64.or", [&](IRBuilder<>& BC) { return BC.CreateOr(AV, BV, "vm64.or"); });
		addCase(BS_XOR, "vm.bo64.xor", [&](IRBuilder<>& BC) { return BC.CreateXor(AV, BV, "vm64.xor"); });
		addCase(BS_SHL, "vm.bo64.shl", [&](IRBuilder<>& BC) { return BC.CreateShl(AV, BV, "vm64.shl"); });
		addCase(BS_LSHR, "vm.bo64.lshr", [&](IRBuilder<>& BC) { return BC.CreateLShr(AV, BV, "vm64.lshr"); });
		addCase(BS_ASHR, "vm.bo64.ashr", [&](IRBuilder<>& BC) { return BC.CreateAShr(AV, BV, "vm64.ashr"); });
		addCase(BS_SDIV, "vm.bo64.sdiv", [&](IRBuilder<>& BC) { return BC.CreateSDiv(AV, BV, "vm64.sdiv"); });
		addCase(BS_UDIV, "vm.bo64.udiv", [&](IRBuilder<>& BC) { return BC.CreateUDiv(AV, BV, "vm64.udiv"); });
		addCase(BS_SREM, "vm.bo64.srem", [&](IRBuilder<>& BC) { return BC.CreateSRem(AV, BV, "vm64.srem"); });
		addCase(BS_UREM, "vm.bo64.urem", [&](IRBuilder<>& BC) { return BC.CreateURem(AV, BV, "vm64.urem"); });
	}
	//  OP_ICMP -- [dst:u8 a:u8 b:u8 pred:u8] 
	{
		auto B = mkOpc(OP_ICMP, "icmp");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.ic.d"), * AIdx = rdVR(B, IP, 1, "vm.ic.a");
		Value* BIdx = rdVR(B, IP, 2, "vm.ic.b"), * Pred = rdByte(B, IP, 3, "vm.ic.p");
		Value* AV = ldVR(B, AIdx), * BV = ldVR(B, BIdx);
		using P = CmpInst::Predicate;
		Value* Cs[] = {
		  B.CreateICmpEQ(AV,BV), B.CreateICmpNE(AV,BV),
		  B.CreateICmpUGT(AV,BV), B.CreateICmpUGE(AV,BV),
		  B.CreateICmpULT(AV,BV), B.CreateICmpULE(AV,BV),
		  B.CreateICmpSGT(AV,BV), B.CreateICmpSGE(AV,BV),
		  B.CreateICmpSLT(AV,BV), B.CreateICmpSLE(AV,BV),
		};
		P Ps[] = { P::ICMP_EQ,P::ICMP_NE,P::ICMP_UGT,P::ICMP_UGE,P::ICMP_ULT,
				P::ICMP_ULE,P::ICMP_SGT,P::ICMP_SGE,P::ICMP_SLT,P::ICMP_SLE };
		Value* R = B.getInt1(false);
		for (unsigned i = 0; i < 10; i++)
			R = B.CreateSelect(B.CreateICmpEQ(Pred, B.getInt32((uint32_t)Ps[i])), Cs[i], R);
		stVR(B, Dst, B.CreateZExt(R, I32Ty, "vm.ic.r")); B.CreateBr(Dispatch);
	}






	//  OP_ICMP64 -- [dst:u8 a:u8 b:u8 pred:u8] 
	{
		auto B = mkOpc(OP_ICMP64, "icmp64");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.ic64.d");
		Value* AIdx = rdVR64(B, IP, 1, "vm.ic64.a");
		Value* BIdx = rdVR64(B, IP, 2, "vm.ic64.b");
		Value* Pred = rdByte(B, IP, 3, "vm.ic64.p");
		Value* AV = ldVR64(B, AIdx), * BV = ldVR64(B, BIdx);

		using P = CmpInst::Predicate;
		Value* Cs[] = {
		  B.CreateICmpEQ(AV,BV), B.CreateICmpNE(AV,BV),
		  B.CreateICmpUGT(AV,BV), B.CreateICmpUGE(AV,BV),
		  B.CreateICmpULT(AV,BV), B.CreateICmpULE(AV,BV),
		  B.CreateICmpSGT(AV,BV), B.CreateICmpSGE(AV,BV),
		  B.CreateICmpSLT(AV,BV), B.CreateICmpSLE(AV,BV),
		};
		P Ps[] = { P::ICMP_EQ,P::ICMP_NE,P::ICMP_UGT,P::ICMP_UGE,P::ICMP_ULT,
				   P::ICMP_ULE,P::ICMP_SGT,P::ICMP_SGE,P::ICMP_SLT,P::ICMP_SLE };

		Value* R = B.getInt1(false);
		for (unsigned i = 0; i < 10; i++)
			R = B.CreateSelect(B.CreateICmpEQ(Pred, B.getInt32((uint32_t)Ps[i])), Cs[i], R);

		stVR(B, Dst, B.CreateZExt(R, I32Ty, "vm.ic64.r"));
		B.CreateBr(Dispatch);
	}


	//  OP_CAST -- [dst:u8 src:u8 kind:u8] 
	{
		auto B = mkOpc(OP_CAST, "cast");
		Value* IP = advIP(B, 3);
		Value* Dst = rdVR(B, IP, 0, "vm.ca.d"), * Src = rdVR(B, IP, 1, "vm.ca.s"), * Kind = rdByte(B, IP, 2, "vm.ca.k");
		Value* SV = ldVR(B, Src);
		auto ze = [&](uint32_t M) {return B.CreateAnd(SV, B.getInt32(M), "vm.ze"); };
		auto se = [&](uint32_t W)->Value* {
			return B.CreateAShr(B.CreateShl(SV, B.getInt32(32 - W), "vm.ssl"), B.getInt32(32 - W), "vm.ssr"); };
		Value* Cvs[] = { ze(1),ze(0xFF),ze(0xFFFF),se(8),se(16),ze(1),ze(0xFF),ze(0xFFFF) };
		Value* R = SV;
		for (unsigned i = 0; i < 8; i++)
			R = B.CreateSelect(B.CreateICmpEQ(Kind, B.getInt32(i)), Cvs[i], R, "vm.ca.r");
		stVR(B, Dst, R); B.CreateBr(Dispatch);
	}
}

void VMImpl::buildHandlersConv() {
	//  OP_SELECT -- [kind:u8 dst:u8 cond:u8 t:u8 f:u8] 
	// kind 0: integer vregs (dst/t/f are VR) ; kind 1: pointer pregs (dst/t/f are PR) ; kind 2: i64 vregs (dst/t/f are VR64)
	{
		auto B = mkOpc(OP_SELECT, "select");
		Value* IP = advIP(B, 5);
		Value* Kind = rdByte(B, IP, 0, "vm.sl.k");
		Value* IsPtr = B.CreateICmpEQ(Kind, B.getInt32(1), "vm.sl.isp");
		Value* IsI64 = B.CreateICmpEQ(Kind, B.getInt32(2), "vm.sl.is64");

		BasicBlock* IntBB = BasicBlock::Create(Ctx, "vm.sl.int", HFn);
		BasicBlock* PtrBB = BasicBlock::Create(Ctx, "vm.sl.ptr", HFn);
		BasicBlock* I64BB = BasicBlock::Create(Ctx, "vm.sl.i64", HFn);
		BasicBlock* K0BB = BasicBlock::Create(Ctx, "vm.sl.k0", HFn);
		B.CreateCondBr(IsPtr, PtrBB, K0BB);

		// decode kind 0 vs kind 2
		{
			IRBuilder<> BK(K0BB);
			BK.CreateCondBr(IsI64, I64BB, IntBB);
		}

		//  ptr path 
		{
			IRBuilder<> BP(PtrBB);
			Value* DstP = rdPR(BP, IP, 1, "vm.sl.pd");
			Value* Cond = rdVR(BP, IP, 2, "vm.sl.pc");
			Value* TP = ldPR(BP, rdPR(BP, IP, 3, "vm.sl.pt"));
			Value* FP = ldPR(BP, rdPR(BP, IP, 4, "vm.sl.pf"));
			Value* Bool = BP.CreateICmpNE(ldVR(BP, Cond), BP.getInt32(0), "vm.sl.pb");
			stPR(BP, DstP, BP.CreateSelect(Bool, TP, FP, "vm.sl.pr"));
			BP.CreateBr(Dispatch);
		}

		//  int path 
		{
			IRBuilder<> BI(IntBB);
			Value* Dst = rdVR(BI, IP, 1, "vm.sl.id");
			Value* Cond = rdVR(BI, IP, 2, "vm.sl.ic");
			Value* TV = ldVR(BI, rdVR(BI, IP, 3, "vm.sl.it"));
			Value* FV = ldVR(BI, rdVR(BI, IP, 4, "vm.sl.if"));
			Value* Bool = BI.CreateICmpNE(ldVR(BI, Cond), BI.getInt32(0), "vm.sl.ib");
			stVR(BI, Dst, BI.CreateSelect(Bool, TV, FV, "vm.sl.ir"));
			BI.CreateBr(Dispatch);
		}

		//  i64 path 
		{
			IRBuilder<> B64(I64BB);
			Value* Dst = rdVR64(B64, IP, 1, "vm.sl.64d");
			Value* Cond = rdVR(B64, IP, 2, "vm.sl.64c");
			Value* TV = ldVR64(B64, rdVR64(B64, IP, 3, "vm.sl.64t"));
			Value* FV = ldVR64(B64, rdVR64(B64, IP, 4, "vm.sl.64f"));
			Value* Bool = B64.CreateICmpNE(ldVR(B64, Cond), B64.getInt32(0), "vm.sl.64b");
			stVR64(B64, Dst, B64.CreateSelect(Bool, TV, FV, "vm.sl.64r"));
			B64.CreateBr(Dispatch);
		}
	}
	//  OP_PTRTOINT -- [dst:u8 srcp:u8] 
	{
		auto B = mkOpc(OP_PTRTOINT, "ptrtoint");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR(B, IP, 0, "vm.pi.d"), * SP = rdPR(B, IP, 1, "vm.pi.s");
		stVR(B, Dst, B.CreatePtrToInt(ldPR(B, SP), I32Ty, "vm.pi.v")); B.CreateBr(Dispatch);
	}


	//  OP_CAST64 -- [dst:u8 src:u8 kind:u8] 
	{
		auto B = mkOpc(OP_CAST64, "cast64");
		Value* IP = advIP(B, 3);
		Value* Kind = rdByte(B, IP, 2, "vm.c64.k");

		Value* IsTrunc = B.CreateICmpUGE(Kind, B.getInt32((uint32_t)C64_TRUNC1), "vm.c64.tr");
		BasicBlock* ExtBB = BasicBlock::Create(Ctx, "vm.c64.ext", HFn);
		BasicBlock* TrBB = BasicBlock::Create(Ctx, "vm.c64.trn", HFn);
		B.CreateCondBr(IsTrunc, TrBB, ExtBB);

		//  extend path: VR(i32) -> VR64(i64) 
		{
			IRBuilder<> BE(ExtBB);
			Value* Dst = rdVR64(BE, IP, 0, "vm.c64.d");
			Value* Src = rdVR(BE, IP, 1, "vm.c64.s");
			Value* SV = ldVR(BE, Src);

			auto ze = [&](uint32_t M) -> Value* {
				return BE.CreateZExt(BE.CreateAnd(SV, BE.getInt32(M), "vm.c64.zm"), I64Ty, "vm.c64.ze");
				};
			auto se32 = [&](uint32_t W) -> Value* {
				return BE.CreateAShr(BE.CreateShl(SV, BE.getInt32(32 - W), "vm.c64.ssl"),
					BE.getInt32(32 - W), "vm.c64.ssr");
				};

			Value* Z1 = ze(1);
			Value* Z8 = ze(0xFF);
			Value* Z16 = ze(0xFFFF);
			Value* Z32 = BE.CreateZExt(SV, I64Ty, "vm.c64.z32");

			Value* S8 = BE.CreateSExt(se32(8), I64Ty, "vm.c64.s8");
			Value* S16 = BE.CreateSExt(se32(16), I64Ty, "vm.c64.s16");
			Value* S32 = BE.CreateSExt(SV, I64Ty, "vm.c64.s32");

			Value* R = Z32; // default
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_ZEXT1)), Z1, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_ZEXT8)), Z8, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_ZEXT16)), Z16, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_ZEXT32)), Z32, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_SEXT8)), S8, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_SEXT16)), S16, R, "vm.c64.r");
			R = BE.CreateSelect(BE.CreateICmpEQ(Kind, BE.getInt32((uint32_t)C64_SEXT32)), S32, R, "vm.c64.r");

			stVR64(BE, Dst, R);
			BE.CreateBr(Dispatch);
		}

		//  trunc path: VR64(i64) -> VR(i32) 
		{
			IRBuilder<> BT(TrBB);
			Value* Dst = rdVR(BT, IP, 0, "vm.c64.td");
			Value* Src = rdVR64(BT, IP, 1, "vm.c64.ts");
			Value* SV = ldVR64(BT, Src);
			Value* Lo32 = BT.CreateTrunc(SV, I32Ty, "vm.c64.lo");

			Value* T1 = BT.CreateAnd(Lo32, BT.getInt32(1), "vm.c64.t1");
			Value* T8 = BT.CreateAnd(Lo32, BT.getInt32(0xFF), "vm.c64.t8");
			Value* T16 = BT.CreateAnd(Lo32, BT.getInt32(0xFFFF), "vm.c64.t16");
			Value* T32 = Lo32;

			Value* R = T32; // default
			R = BT.CreateSelect(BT.CreateICmpEQ(Kind, BT.getInt32((uint32_t)C64_TRUNC1)), T1, R, "vm.c64.tr");
			R = BT.CreateSelect(BT.CreateICmpEQ(Kind, BT.getInt32((uint32_t)C64_TRUNC8)), T8, R, "vm.c64.tr");
			R = BT.CreateSelect(BT.CreateICmpEQ(Kind, BT.getInt32((uint32_t)C64_TRUNC16)), T16, R, "vm.c64.tr");
			R = BT.CreateSelect(BT.CreateICmpEQ(Kind, BT.getInt32((uint32_t)C64_TRUNC32)), T32, R, "vm.c64.tr");

			stVR(BT, Dst, R);
			BT.CreateBr(Dispatch);
		}
	}


	//  OP_PTRTOINT64 -- [dst64:u8 srcp:u8] 
	{
		auto B = mkOpc(OP_PTRTOINT64, "ptrtoint64");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR64(B, IP, 0, "vm.pi64.d"), * SP = rdPR(B, IP, 1, "vm.pi64.s");
		stVR64(B, Dst, B.CreatePtrToInt(ldPR(B, SP), I64Ty, "vm.pi64.v")); B.CreateBr(Dispatch);
	}


	//  OP_INTTOPTR -- [dstp:u8 src:u8] 
	{
		auto B = mkOpc(OP_INTTOPTR, "inttoptr");
		Value* IP = advIP(B, 2);
		Value* DP = rdPR(B, IP, 0, "vm.pp.d"), * Src = rdVR(B, IP, 1, "vm.pp.s");
		stPR(B, DP, B.CreateIntToPtr(ldVR(B, Src), PtrTy, "vm.pp.v")); B.CreateBr(Dispatch);
	}

}

void VMImpl::buildHandlersMem() {
	//  OP_LOAD32 -- [dst:u8 ptrreg:u8] 
	{
		auto B = mkOpc(OP_LOAD32, "load32");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR(B, IP, 0, "vm.ld.d"), * PP = rdPR(B, IP, 1, "vm.ld.p");
		stVR(B, Dst, B.CreateLoad(I32Ty, ldPR(B, PP), "vm.ld.v")); B.CreateBr(Dispatch);
	}

	//  OP_LOAD64 -- [dst64:u8 ptrreg:u8] 
	{
		auto B = mkOpc(OP_LOAD64, "load64");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR64(B, IP, 0, "vm.ld64.d"), * PP = rdPR(B, IP, 1, "vm.ld64.p");
		stVR64(B, Dst, B.CreateLoad(I64Ty, ldPR(B, PP), "vm.ld64.v")); B.CreateBr(Dispatch);
	}

	//  OP_STORE32 -- [val:u8 ptrreg:u8] 
	{
		auto B = mkOpc(OP_STORE32, "store32");
		Value* IP = advIP(B, 2);
		Value* VR = rdVR(B, IP, 0, "vm.st.v"), * PP = rdPR(B, IP, 1, "vm.st.p");
		B.CreateStore(ldVR(B, VR), ldPR(B, PP)); B.CreateBr(Dispatch);
	}

	//  OP_STORE64 -- [val64:u8 ptrreg:u8] 
	{
		auto B = mkOpc(OP_STORE64, "store64");
		Value* IP = advIP(B, 2);
		Value* VIdx = rdVR64(B, IP, 0, "vm.st64.v"), * PP = rdPR(B, IP, 1, "vm.st64.p");
		B.CreateStore(ldVR64(B, VIdx), ldPR(B, PP)); B.CreateBr(Dispatch);
	}

	//  OP_GEP -- [dstp:u8 basep:u8 idx:u8 elemsz:u16le] 
	// Byte offset = vreg[idx] * elemsz.  Interpreter always operates in bytes.
	{
		auto B = mkOpc(OP_GEP, "gep");
		Value* IP = advIP(B, 5);   // 3 reg bytes + 2 elemsz bytes
		Value* DP = rdPR(B, IP, 0, "vm.gp.d"), * BP = rdPR(B, IP, 1, "vm.gp.b"), * Idx = rdVR(B, IP, 2, "vm.gp.i");
		// Reconstruct elemsz (plain u16le, not obfuscated ├ö├ç├Â it's a stride constant)
		Value* ELo = B.CreateZExt(loadBC(B, IP, 3, "vm.gp.el"), I64Ty, "vm.gp.elo");
		Value* EHi = B.CreateZExt(loadBC(B, IP, 4, "vm.gp.eh"), I64Ty, "vm.gp.ehi");
		Value* ESz = B.CreateOr(ELo, B.CreateShl(EHi, B.getInt64(8), "vm.gp.es"), "vm.gp.esz");
		// Byte offset = (i64)idx_value * elemsz
		Value* IdxVal = B.CreateSExt(ldVR(B, Idx), I64Ty, "vm.gp.iv");
		Value* ByteOff = B.CreateMul(IdxVal, ESz, "vm.gp.bo");
		stPR(B, DP, B.CreateGEP(I8Ty, ldPR(B, BP), ByteOff, "vm.gp.v")); B.CreateBr(Dispatch);
	}

	//  OP_GEP64 -- [dstp:u8 basep:u8 idx64:u8 elemsz:u16le] 
	{
		auto B = mkOpc(OP_GEP64, "gep64");
		Value* IP = advIP(B, 5);
		Value* DP = rdPR(B, IP, 0, "vm.gp64.d"), * BP = rdPR(B, IP, 1, "vm.gp64.b");
		Value* Idx = rdVR64(B, IP, 2, "vm.gp64.i");
		Value* ELo = B.CreateZExt(loadBC(B, IP, 3, "vm.gp64.el"), I64Ty, "vm.gp64.elo");
		Value* EHi = B.CreateZExt(loadBC(B, IP, 4, "vm.gp64.eh"), I64Ty, "vm.gp64.ehi");
		Value* ESz = B.CreateOr(ELo, B.CreateShl(EHi, B.getInt64(8), "vm.gp64.es"), "vm.gp64.esz");
		Value* IdxVal = ldVR64(B, Idx);
		Value* ByteOff = B.CreateMul(IdxVal, ESz, "vm.gp64.bo");
		stPR(B, DP, B.CreateGEP(I8Ty, ldPR(B, BP), ByteOff, "vm.gp64.v")); B.CreateBr(Dispatch);
	}



	// LOAD/STORE -- 8/16:
	{
		auto B = mkOpc(OP_LOAD8, "load8");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR(B, IP, 0, "vm.ld8.d");
		Value* PP = rdPR(B, IP, 1, "vm.ld8.p");
		Value* V8 = B.CreateLoad(I8Ty, ldPR(B, PP), "vm.ld8.v");
		stVR(B, Dst, B.CreateZExt(V8, I32Ty, "vm.ld8.z"));
		B.CreateBr(Dispatch);
	}
	{
		auto B = mkOpc(OP_STORE8, "store8");
		Value* IP = advIP(B, 2);
		Value* VIdx = rdVR(B, IP, 0, "vm.st8.v");
		Value* PP = rdPR(B, IP, 1, "vm.st8.p");
		Value* V8 = B.CreateTrunc(ldVR(B, VIdx), I8Ty, "vm.st8.t");
		B.CreateStore(V8, ldPR(B, PP));
		B.CreateBr(Dispatch);
	}
	{
		auto B = mkOpc(OP_LOAD16, "load16");
		Value* IP = advIP(B, 2);
		Value* Dst = rdVR(B, IP, 0, "vm.ld16.d");
		Value* PP = rdPR(B, IP, 1, "vm.ld16.p");
		Value* V16 = B.CreateLoad(I16Ty, ldPR(B, PP), "vm.ld16.v");
		stVR(B, Dst, B.CreateZExt(V16, I32Ty, "vm.ld16.z"));
		B.CreateBr(Dispatch);
	}
	{
		auto B = mkOpc(OP_STORE16, "store16");
		Value* IP = advIP(B, 2);
		Value* VIdx = rdVR(B, IP, 0, "vm.st16.v");
		Value* PP = rdPR(B, IP, 1, "vm.st16.p");
		Value* V16 = B.CreateTrunc(ldVR(B, VIdx), I16Ty, "vm.st16.t");
		B.CreateStore(V16, ldPR(B, PP));
		B.CreateBr(Dispatch);
	}


	// LOAD/STORE -- PTR:
	{
		auto B = mkOpc(OP_LOADPTR, "loadptr");
		Value* IP = advIP(B, 2);
		Value* Dst = rdPR(B, IP, 0, "vm.lp.d");
		Value* PP = rdPR(B, IP, 1, "vm.lp.p");
		Value* V = B.CreateLoad(PtrTy, ldPR(B, PP), "vm.lp.v");
		stPR(B, Dst, V);
		B.CreateBr(Dispatch);
	}
	{
		auto B = mkOpc(OP_STOREPTR, "storeptr");
		Value* IP = advIP(B, 2);
		Value* VIdx = rdPR(B, IP, 0, "vm.sp.v");
		Value* PP = rdPR(B, IP, 1, "vm.sp.p");
		B.CreateStore(ldPR(B, VIdx), ldPR(B, PP));
		B.CreateBr(Dispatch);
	}


}

void VMImpl::buildHandlersControl() {
	//  OP_JMP -- [target:u32le] 
	{
		auto B = mkOpc(OP_JMP, "jmp");
		Value* IP = advIP(B, 4);
		B.CreateStore(rdU32(B, IP, 0, "vm.jm.t"), VMIP)->setVolatile(true);
		B.CreateBr(Dispatch);
	}

	//  OP_JMPC -- [cond:u8 tgt_t:u32 tgt_f:u32] 
	{
		auto B = mkOpc(OP_JMPC, "jmpc");
		Value* IP = advIP(B, 9);
		Value* Cond = rdVR(B, IP, 0, "vm.jc.c"), * Tt = rdU32(B, IP, 1, "vm.jc.t"), * Tf = rdU32(B, IP, 5, "vm.jc.f");
		Value* Bool = B.CreateICmpNE(ldVR(B, Cond), B.getInt32(0), "vm.jc.b");
		B.CreateStore(B.CreateSelect(Bool, Tt, Tf, "vm.jc.s"), VMIP)->setVolatile(true);
		B.CreateBr(Dispatch);
	}


	//  OP_SWITCH -- [cond:u8 ncases:u16le def:u32le [case:u32le tgt:u32le]*ncases] 
	// Linear scan at runtime using a compact table; no per-case IR bloat.
	{
		auto B = mkOpc(OP_SWITCH, "switch");
		// CurIP points at first operand byte (fetch already consumed opcode)
		auto* CurIP = B.CreateLoad(I32Ty, VMIP, "vm.sw.ip");
		CurIP->setVolatile(true);

		Value* CondIdx = rdVR(B, CurIP, 0, "vm.sw.ci");
		Value* CondVal = ldVR(B, CondIdx);

		// ncases = u16le at offsets 1..2 (plain)
		Value* NLo = B.CreateZExt(loadBC(B, CurIP, 1, "vm.sw.nl"), I32Ty, "vm.sw.nlo");
		Value* NHi = B.CreateZExt(loadBC(B, CurIP, 2, "vm.sw.nh"), I32Ty, "vm.sw.nhi");
		Value* NCases = B.CreateOr(NLo, B.CreateShl(NHi, B.getInt32(8), "vm.sw.ns"), "vm.sw.nc");

		Value* DefT = rdU32(B, CurIP, 3, "vm.sw.df");

		// Advance IP past the whole switch payload: 7 + 8*ncases bytes
		Value* Adv = B.CreateAdd(B.getInt32(7),
			B.CreateMul(NCases, B.getInt32(8), "vm.sw.mul"),
			"vm.sw.adv");
		B.CreateStore(B.CreateAdd(CurIP, Adv, "vm.sw.nip"), VMIP)->setVolatile(true);

		BasicBlock* EntryBB = B.GetInsertBlock();
		BasicBlock* LoopBB = BasicBlock::Create(Ctx, "vm.sw.loop", HFn);
		BasicBlock* BodyBB = BasicBlock::Create(Ctx, "vm.sw.body", HFn);
		BasicBlock* DoneBB = BasicBlock::Create(Ctx, "vm.sw.done", HFn);
		B.CreateBr(LoopBB);

		// loop: i from 0..NCases-1, R accumulates selected target (default by default)
		IRBuilder<> LB(LoopBB);
		PHINode* I = LB.CreatePHI(I32Ty, 2, "vm.sw.i");
		PHINode* R = LB.CreatePHI(I32Ty, 2, "vm.sw.r");
		I->addIncoming(LB.getInt32(0), EntryBB);
		R->addIncoming(DefT, EntryBB);

		Value* More = LB.CreateICmpULT(I, NCases, "vm.sw.more");
		LB.CreateCondBr(More, BodyBB, DoneBB);

		IRBuilder<> BB(BodyBB);
		// Off = 7 + i*8
		Value* Off = BB.CreateAdd(BB.getInt32(7),
			BB.CreateMul(I, BB.getInt32(8), "vm.sw.os"),
			"vm.sw.off");
		Value* CaseV = rdU32Dyn(BB, CurIP, Off, "vm.sw.cv");
		Value* Off4 = BB.CreateAdd(Off, BB.getInt32(4), "vm.sw.of4");
		Value* Tgt = rdU32Dyn(BB, CurIP, Off4, "vm.sw.tg");

		Value* Eq = BB.CreateICmpEQ(CondVal, CaseV, "vm.sw.eq");
		Value* NewR = BB.CreateSelect(Eq, Tgt, R, "vm.sw.nr");
		Value* NextI = BB.CreateAdd(I, BB.getInt32(1), "vm.sw.ni");
		BB.CreateBr(LoopBB);

		I->addIncoming(NextI, BodyBB);
		R->addIncoming(NewR, BodyBB);

		IRBuilder<> DB(DoneBB);
		DB.CreateStore(R, VMIP)->setVolatile(true);
		DB.CreateBr(Dispatch);
	}


	// OP_RET_VOID 
	{
		auto B = mkOpc(OP_RET_VOID, "ret_void");
		advIP(B, 0);
		if (SharedEngineMode) {
			B.CreateRetVoid();
		}
		else if (F.getReturnType()->isVoidTy()) {
			B.CreateRetVoid();
		}
		else {
			B.CreateUnreachable();
		}
	}


	{
		auto B = mkOpc(OP_RET_INT, "ret_int");
		Value* IP = advIP(B, 1);
		if (SharedEngineMode) {
			rdVR(B, IP, 0, "vm.ri.s");  // consume operand
			B.CreateRetVoid();

		}
		else {
			Type* RT = F.getReturnType();
			if (RT->isIntegerTy() && RT->getIntegerBitWidth() <= 32) {
				Value* Src = rdVR(B, IP, 0, "vm.ri.s");
				Value* V = ldVR(B, Src);
				if (RT != I32Ty) V = B.CreateTrunc(V, RT, "vm.ri.tr");
				B.CreateRet(V);
			}
			else if (RT->isIntegerTy(64)) {  // i64 return via vreg64
				Value* Src = rdVR64(B, IP, 0, "vm.ri64.s");
				B.CreateRet(ldVR64(B, Src));
			}
			else {
				B.CreateUnreachable();
			}
		}
	}


	{
		auto B = mkOpc(OP_RET_PTR, "ret_ptr");
		Value* IP = advIP(B, 1);
		if (SharedEngineMode) {
			rdPR(B, IP, 0, "vm.rp.s");
			B.CreateRetVoid();

		}
		else {
			Type* RT = F.getReturnType();
			if (RT->isPointerTy()) {
				Value* SP = rdPR(B, IP, 0, "vm.rp.s");
				Value* P = ldPR(B, SP);
				if (P->getType() != RT && P->getType()->isPointerTy())
					P = B.CreateBitCast(P, RT, "vm.rp.bc");
				B.CreateRet(P);
			}
			else {
				B.CreateUnreachable();
			}
		}
	}





}

void VMImpl::buildHandlersFloat() {
	// OP_LOADI_F -- [dst_fr:u8 imm:f64le]    freg[dst] = imm 
	{
		auto B = mkOpc(OP_LOADI_F, "loadi_f");
		Value* IP = advIP(B, 9);  // 1 dst + 8 bytes of f64
		Value* Dst = rdFR(B, IP, 0, "vm.lif.d");
		// Reconstruct f64 from 8 LE bytes
		Value* Bits = B.getInt64(0);
		for (unsigned i = 0; i < 8; ++i) {
			Value* ByteV = B.CreateZExt(loadBC(B, IP, 1 + i, "vm.lif.b"), I64Ty, "vm.lif.bz");
			if (i) ByteV = B.CreateShl(ByteV, B.getInt64(i * 8), "vm.lif.bs");
			Bits = B.CreateOr(Bits, ByteV, "vm.lif.or");
		}
		Value* FV = B.CreateBitCast(Bits, DoubleTy, "vm.lif.v");
		stFR(B, Dst, FV);
		B.CreateBr(Dispatch);
	}

	// OP_MOVR_F -- [dst_fr:u8 src_fr:u8]  freg[dst] = freg[src] 
	{
		auto B = mkOpc(OP_MOVR_F, "movr_f");
		Value* IP = advIP(B, 2);
		stFR(B, rdFR(B, IP, 0, "vm.mrf.d"), ldFR(B, rdFR(B, IP, 1, "vm.mrf.s")));
		B.CreateBr(Dispatch);
	}

	// OP_BINOP_F -- [dst_fr:u8 a_fr:u8 b_fr:u8 subop:u8] 
	// subop layout: bits[6:0] = FBinSubop,  bit[7] = f32-mode flag.
	// When bit 7 is set the f64 result is rounded back to f32 precision
	// (fptruncf32 then fpextf64) so float arithmetic matches native
	// semantics exactly.
	{
		auto B = mkOpc(OP_BINOP_F, "binop_f");
		Value* IP = advIP(B, 4);
		Value* Dst = rdFR(B, IP, 0, "vm.bof.d");
		Value* AIdx = rdFR(B, IP, 1, "vm.bof.a");
		Value* BIdx = rdFR(B, IP, 2, "vm.bof.b");
		Value* Sub8 = rdByte(B, IP, 3, "vm.bof.op");   // raw byte incl. bit7
		Value* Sub = B.CreateAnd(Sub8, B.getInt32(0x7F), "vm.bof.sub"); // op only
		Value* IsF32 = B.CreateICmpNE(
			B.CreateAnd(Sub8, B.getInt32(0x80)), B.getInt32(0), "vm.bof.f32");
		Value* AV = ldFR(B, AIdx), * BV = ldFR(B, BIdx);

		// Carry IsF32 (i1) into the merge block via alloca so every incoming
		// edge can read it without duplicating the comparison.
		auto* IsF32Slot = new AllocaInst(Type::getInt1Ty(Ctx), 0, "vm.bof.f32.sl",
			&*HFn->getEntryBlock().getFirstInsertionPt());
		B.CreateStore(IsF32, IsF32Slot);

		BasicBlock* FMergeBB = BasicBlock::Create(Ctx, "vm.bof.merge", HFn);
		BasicBlock* FDefBB = BasicBlock::Create(Ctx, "vm.bof.def", HFn);
		SwitchInst* FSW = B.CreateSwitch(Sub, FDefBB, 5);

		IRBuilder<> FBM(FMergeBB);
		auto* FPhi = FBM.CreatePHI(DoubleTy, 6, "vm.bof.r");
		// Round to f32 precision when bit 7 was set in subop.
		Value* IsF32M = FBM.CreateLoad(Type::getInt1Ty(Ctx), IsF32Slot, "vm.bof.f32.m");
		Value* Narrow = FBM.CreateFPExt(
			FBM.CreateFPTrunc(FPhi, Type::getFloatTy(Ctx), "vm.bof.nt"),
			DoubleTy, "vm.bof.ne");
		Value* Final = FBM.CreateSelect(IsF32M, Narrow, FPhi, "vm.bof.fin");
		stFR(FBM, Dst, Final);
		FBM.CreateBr(Dispatch);

		{
			IRBuilder<> BD(FDefBB); Value* R = BD.CreateFAdd(AV, BV, "vm.fadd");
			FPhi->addIncoming(R, FDefBB); BD.CreateBr(FMergeBB);
		}

		auto addFCase = [&](uint32_t C, const Twine& N, auto Emit) {
			BasicBlock* CB = BasicBlock::Create(Ctx, N, HFn);
			IRBuilder<> BC(CB); Value* R = Emit(BC);
			FPhi->addIncoming(R, CB); BC.CreateBr(FMergeBB);
			FSW->addCase(B.getInt32(C), CB); };

		addFCase(FBS_FSUB, "vm.bof.sub", [&](IRBuilder<>& BC) { return BC.CreateFSub(AV, BV, "vm.fsub"); });
		addFCase(FBS_FMUL, "vm.bof.mul", [&](IRBuilder<>& BC) { return BC.CreateFMul(AV, BV, "vm.fmul"); });
		addFCase(FBS_FDIV, "vm.bof.div", [&](IRBuilder<>& BC) { return BC.CreateFDiv(AV, BV, "vm.fdiv"); });
		addFCase(FBS_FREM, "vm.bof.rem", [&](IRBuilder<>& BC) { return BC.CreateFRem(AV, BV, "vm.frem"); });
	}

	// OP_FCMP -- [dst_vr:u8 a_fr:u8 b_fr:u8 pred:u8] 
	// pred = raw CmpInst::Predicate value (FCMP_OEQ=1 .. FCMP_UNO=14).
	// Result is i1 zero-extended to i32 and stored in vreg.
	// Switch+PHI pattern identical to OP_BINOP: only the matching predicate's
	// fcmp executes per dispatch.  No speculative evaluation of all 14 branches.
	{
		auto B = mkOpc(OP_FCMP, "fcmp");
		Value* IP = advIP(B, 4);
		Value* Dst = rdVR(B, IP, 0, "vm.fcp.d");
		Value* AIdx = rdFR(B, IP, 1, "vm.fcp.a");
		Value* BIdx = rdFR(B, IP, 2, "vm.fcp.b");
		Value* Pred = rdByte(B, IP, 3, "vm.fcp.p");
		Value* AV = ldFR(B, AIdx);
		Value* BV = ldFR(B, BIdx);

		using FP = CmpInst::Predicate;

		BasicBlock* MergeBB = BasicBlock::Create(Ctx, "vm.fcp.merge", HFn);
		BasicBlock* DefBB = BasicBlock::Create(Ctx, "vm.fcp.def", HFn);

		// Default: FCMP_FALSE (pred=0) — result always 0.
		SwitchInst* SW = B.CreateSwitch(Pred, DefBB, 14);

		// MergeBB: PHI first, then stVR, then br — same order as OP_BINOP.
		IRBuilder<> BM(MergeBB);
		auto* Phi = BM.CreatePHI(I32Ty, 15, "vm.fcp.r");
		stVR(BM, Dst, Phi);
		BM.CreateBr(Dispatch);

		// Default block handles FCMP_FALSE (pred==0): result is always 0.
		{
			IRBuilder<> BD(DefBB);
			Phi->addIncoming(BD.getInt32(0), DefBB);
			BD.CreateBr(MergeBB);
		}

		auto addCase = [&](FP pred, const Twine& BBName, auto Emit) {
			BasicBlock* CBB = BasicBlock::Create(Ctx, BBName, HFn);
			IRBuilder<> BC(CBB);
			Value* R = BC.CreateZExt(Emit(BC), I32Ty, "vm.fcp.z");
			Phi->addIncoming(R, CBB);
			BC.CreateBr(MergeBB);
			SW->addCase(B.getInt32((uint32_t)pred), CBB);
			};

		addCase(FP::FCMP_OEQ, "vm.fcp.oeq", [&](IRBuilder<>& BC) { return BC.CreateFCmpOEQ(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_OGT, "vm.fcp.ogt", [&](IRBuilder<>& BC) { return BC.CreateFCmpOGT(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_OGE, "vm.fcp.oge", [&](IRBuilder<>& BC) { return BC.CreateFCmpOGE(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_OLT, "vm.fcp.olt", [&](IRBuilder<>& BC) { return BC.CreateFCmpOLT(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_OLE, "vm.fcp.ole", [&](IRBuilder<>& BC) { return BC.CreateFCmpOLE(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_ONE, "vm.fcp.one", [&](IRBuilder<>& BC) { return BC.CreateFCmpONE(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_ORD, "vm.fcp.ord", [&](IRBuilder<>& BC) { return BC.CreateFCmpORD(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_UEQ, "vm.fcp.ueq", [&](IRBuilder<>& BC) { return BC.CreateFCmpUEQ(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_UGT, "vm.fcp.ugt", [&](IRBuilder<>& BC) { return BC.CreateFCmpUGT(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_UGE, "vm.fcp.uge", [&](IRBuilder<>& BC) { return BC.CreateFCmpUGE(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_ULT, "vm.fcp.ult", [&](IRBuilder<>& BC) { return BC.CreateFCmpULT(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_ULE, "vm.fcp.ule", [&](IRBuilder<>& BC) { return BC.CreateFCmpULE(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_UNE, "vm.fcp.une", [&](IRBuilder<>& BC) { return BC.CreateFCmpUNE(AV, BV, "vm.fcp.v"); });
		addCase(FP::FCMP_UNO, "vm.fcp.uno", [&](IRBuilder<>& BC) { return BC.CreateFCmpUNO(AV, BV, "vm.fcp.v"); });
	}



	// OP_FCAST_FF --  [dst_fr:u8 src_fr:u8 kind:u8]  freg→freg  (fpext / fptrunc) 
	// FK_FPEXT:  -- freg already stores f64; value is already widened — select returns SV unchanged.
	// FK_FPTRUNC: -- round to f32 precision via fptrunc+fpext.
	{
		auto B = mkOpc(OP_FCAST_FF, "fcast_ff");
		Value* IP = advIP(B, 3);
		Value* Dst = rdFR(B, IP, 0, "vm.cff.d");
		Value* SV = ldFR(B, rdFR(B, IP, 1, "vm.cff.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cff.k");
		Value* Narrow = B.CreateFPExt(
			B.CreateFPTrunc(SV, Type::getFloatTy(Ctx), "vm.cff.nt"), DoubleTy, "vm.cff.ne");
		Value* IsExt = B.CreateICmpEQ(Kind, B.getInt32(FK_FPEXT), "vm.cff.ie");
		stFR(B, Dst, B.CreateSelect(IsExt, SV, Narrow, "vm.cff.r"));
		B.CreateBr(Dispatch);
	}

	//  OP_FCAST_FV --  [dst_vr:u8 src_fr:u8 kind:u8]  freg→vreg i32  (fptosi / fptoui) 
	{
		auto B = mkOpc(OP_FCAST_FV, "fcast_fv");
		Value* IP = advIP(B, 3);
		Value* Dst = rdVR(B, IP, 0, "vm.cfv.d");
		Value* SV = ldFR(B, rdFR(B, IP, 1, "vm.cfv.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cfv.k");
		Value* SI = B.CreateFPToSI(SV, I32Ty, "vm.cfv.si");
		Value* UI = B.CreateFPToUI(SV, I32Ty, "vm.cfv.ui");
		Value* IsS = B.CreateICmpEQ(Kind, B.getInt32(FK_FPTOSI), "vm.cfv.is");
		stVR(B, Dst, B.CreateSelect(IsS, SI, UI, "vm.cfv.r"));
		B.CreateBr(Dispatch);
	}

	// OP_FCAST_FV64 -- [dst_vr64:u8 src_fr:u8 kind:u8]  freg→vreg64 i64 
	{
		auto B = mkOpc(OP_FCAST_FV64, "fcast_fv64");
		Value* IP = advIP(B, 3);
		Value* Dst = rdVR64(B, IP, 0, "vm.cfv64.d");
		Value* SV = ldFR(B, rdFR(B, IP, 1, "vm.cfv64.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cfv64.k");
		Value* SI = B.CreateFPToSI(SV, I64Ty, "vm.cfv64.si");
		Value* UI = B.CreateFPToUI(SV, I64Ty, "vm.cfv64.ui");
		Value* IsS = B.CreateICmpEQ(Kind, B.getInt32(FK_FPTOSI64), "vm.cfv64.is");
		stVR64(B, Dst, B.CreateSelect(IsS, SI, UI, "vm.cfv64.r"));
		B.CreateBr(Dispatch);
	}

	//  OP_FCAST_VF -- [dst_fr:u8 src_vr:u8 kind:u8]  vreg i32→freg  (sitofp / uitofp)
	//  kind bit 7 = FCAST_F32_FLAG: round f64 result to f32 precision.
	{
		auto B = mkOpc(OP_FCAST_VF, "fcast_vf");
		Value* IP = advIP(B, 3);
		Value* Dst = rdFR(B, IP, 0, "vm.cvf.d");
		Value* SV = ldVR(B, rdVR(B, IP, 1, "vm.cvf.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cvf.k");
		Value * KindOp = B.CreateAnd(Kind, B.getInt32(0x7F), "vm.cvf.kop");
		Value * IsF32 = B.CreateICmpNE(
			B.CreateAnd(Kind, B.getInt32(0x80)), B.getInt32(0), "vm.cvf.f32");
		Value* SI = B.CreateSIToFP(SV, DoubleTy, "vm.cvf.si");
		Value* UI = B.CreateUIToFP(SV, DoubleTy, "vm.cvf.ui");
		Value * IsS = B.CreateICmpEQ(KindOp, B.getInt32(FK_SITOFP), "vm.cvf.is");
		Value * Result = B.CreateSelect(IsS, SI, UI, "vm.cvf.r");
		Value * Narrow = B.CreateFPExt(
			B.CreateFPTrunc(Result, Type::getFloatTy(Ctx), "vm.cvf.nt"),
			DoubleTy, "vm.cvf.ne");
		stFR(B, Dst, B.CreateSelect(IsF32, Narrow, Result, "vm.cvf.fin"));
		B.CreateBr(Dispatch);
	}

	//  OP_FCAST_V64F -- [dst_fr:u8 src_vr64:u8 kind:u8]  vreg64 i64→freg
	//  kind bit 7 = FCAST_F32_FLAG: round f64 result to f32 precision.
	{
		auto B = mkOpc(OP_FCAST_V64F, "fcast_v64f");
		Value* IP = advIP(B, 3);
		Value* Dst = rdFR(B, IP, 0, "vm.cv64f.d");
		Value* SV = ldVR64(B, rdVR64(B, IP, 1, "vm.cv64f.s"));
		Value* Kind = rdByte(B, IP, 2, "vm.cv64f.k");
		Value * KindOp = B.CreateAnd(Kind, B.getInt32(0x7F), "vm.cv64f.kop");
		Value * IsF32 = B.CreateICmpNE(
			B.CreateAnd(Kind, B.getInt32(0x80)), B.getInt32(0), "vm.cv64f.f32");
		Value* SI = B.CreateSIToFP(SV, DoubleTy, "vm.cv64f.si");
		Value* UI = B.CreateUIToFP(SV, DoubleTy, "vm.cv64f.ui");
		Value * IsS = B.CreateICmpEQ(KindOp, B.getInt32(FK_SI64TOFP), "vm.cv64f.is");
		Value * Result = B.CreateSelect(IsS, SI, UI, "vm.cv64f.r");
		Value * Narrow = B.CreateFPExt(
			B.CreateFPTrunc(Result, Type::getFloatTy(Ctx), "vm.cv64f.nt"),
			DoubleTy, "vm.cv64f.ne");
		stFR(B, Dst, B.CreateSelect(IsF32, Narrow, Result, "vm.cv64f.fin"));
		B.CreateBr(Dispatch);
	}



	// OP_LOAD_F  [dst_fr:u8 ptrreg:u8]    freg[dst] = *ptr (f64) 
	// NOTE: always loads 8 bytes as f64. f32 memory pointers will produce incorrect
	// results (reads 8 bytes from a 4-byte slot). Use double in IR for correct behaviour.
	{
		auto B = mkOpc(OP_LOAD_F, "load_f");
		Value* IP = advIP(B, 2);
		Value* Dst = rdFR(B, IP, 0, "vm.ldf.d");
		Value* PP = rdPR(B, IP, 1, "vm.ldf.p");
		stFR(B, Dst, B.CreateLoad(DoubleTy, ldPR(B, PP), "vm.ldf.v"));
		B.CreateBr(Dispatch);
	}

	//  OP_STORE_F  [src_fr:u8 ptrreg:u8]    *ptr = freg[src] (f64) 
	{
		auto B = mkOpc(OP_STORE_F, "store_f");
		Value* IP = advIP(B, 2);
		Value* Src = rdFR(B, IP, 0, "vm.stf.s");
		Value* PP = rdPR(B, IP, 1, "vm.stf.p");
		B.CreateStore(ldFR(B, Src), ldPR(B, PP));
		B.CreateBr(Dispatch);
	}


	// OP_LOAD_F32  [dst_fr:u8 ptrreg:u8]  →  freg[dst] = fpext(*ptr as float) 
	// Loads 4 bytes from a float* slot, fpext to f64, stores in freg.
	// Used when the source IR has type float (not double) — e.g. float* function parameter.
	{
		auto B = mkOpc(OP_LOAD_F32, "load_f32");
		Value* IP = advIP(B, 2);
		Value* Dst = rdFR(B, IP, 0, "vm.ldf32.d");
		Value* PP = rdPR(B, IP, 1, "vm.ldf32.p");
		Value* F32V = B.CreateLoad(Type::getFloatTy(Ctx), ldPR(B, PP), "vm.ldf32.v");
		stFR(B, Dst, B.CreateFPExt(F32V, DoubleTy, "vm.ldf32.ext"));
		B.CreateBr(Dispatch);
	}

	// OP_STORE_F32  [val_fr:u8 ptrreg:u8]  →  *ptr (float*) = fptrunc(freg[val]) 
	// fptrunc f64 freg value to float, stores 4 bytes.
	// Used when the destination IR type is float — e.g. float* function parameter.
	{
		auto B = mkOpc(OP_STORE_F32, "store_f32");
		Value* IP = advIP(B, 2);
		Value* Src = rdFR(B, IP, 0, "vm.stf32.s");
		Value* PP = rdPR(B, IP, 1, "vm.stf32.p");
		Value* F32V = B.CreateFPTrunc(ldFR(B, Src), Type::getFloatTy(Ctx), "vm.stf32.tr");
		B.CreateStore(F32V, ldPR(B, PP));
		B.CreateBr(Dispatch);
	}

	//  OP_RET_F  [src_fr:u8]    return freg[src] 
	{
		auto B = mkOpc(OP_RET_F, "ret_f");
		Value* IP = advIP(B, 1);
		if (SharedEngineMode) {
			rdFR(B, IP, 0, "vm.rf.s");
			B.CreateRetVoid();

		}
		else {
			Type* RT = F.getReturnType();
			Value* Src = rdFR(B, IP, 0, "vm.rf.s");
			Value* FV = ldFR(B, Src);
			if (RT->isDoubleTy()) {
				B.CreateRet(FV);
			}
			else if (RT->isFloatTy()) {
				B.CreateRet(B.CreateFPTrunc(FV, RT, "vm.rf.tr"));
			}
			else {
				B.CreateUnreachable();
			}
		}
	}

	// OP_SELECT_F  [dst_fr:u8 cond_vr:u8 t_fr:u8 f_fr:u8] 
	{
		auto B = mkOpc(OP_SELECT_F, "select_f");
		Value* IP = advIP(B, 4);
		Value* Dst = rdFR(B, IP, 0, "vm.slf.d");
		Value* Cond = rdVR(B, IP, 1, "vm.slf.c");
		Value* TV = ldFR(B, rdFR(B, IP, 2, "vm.slf.t"));
		Value* FV = ldFR(B, rdFR(B, IP, 3, "vm.slf.f"));
		Value* Bool = B.CreateICmpNE(ldVR(B, Cond), B.getInt32(0), "vm.slf.b");
		stFR(B, Dst, B.CreateSelect(Bool, TV, FV, "vm.slf.r"));
		B.CreateBr(Dispatch);
	}



	//  OP_FNEG  [dst_fr:u8 src_fr:u8]  
	{
		auto B = mkOpc(OP_FNEG, "fneg");
		Value* IP = advIP(B, 2);
		Value* Dst = rdFR(B, IP, 0, "vm.neg.d");
		Value* SV = ldFR(B, rdFR(B, IP, 1, "vm.neg.s"));
		stFR(B, Dst, B.CreateFNeg(SV, "vm.neg.r"));
		B.CreateBr(Dispatch);
	}



}

void VMImpl::buildHandlersCall() {
	buildCall2(OP_CALL_VOID, "call_void", RK2_VOID);
	buildCall2(OP_CALL_INT, "call_int", RK2_I32);
	buildCall2(OP_CALL_PTR, "call_ptr", RK2_PTR);
	buildCall2(OP_CALL_INT64, "call_int64", RK2_I64);
	buildCall2(OP_CALL_F, "call_f", RK2_F64);
}

void VMImpl::buildCall2(VMOp Opc, const Twine& Name, llvm::VMEngine::RetKind2 RK) {
	auto B = mkOpc(Opc, Name);

	auto* CurIP = B.CreateLoad(I32Ty, VMIP, "vm.cl.ip"); CurIP->setVolatile(true);

	const bool IsVoid = (RK == RK2_VOID);
	const unsigned Base = IsVoid ? 0u : 1u;

	Value* DstSlot = nullptr;
	if (!IsVoid) {
		Value* DR = loadBC(B, CurIP, 0, "vm.cl.dr");
		Value* DMask = (RK == RK2_PTR) ? MaskPR
			: (RK == RK2_I64) ? MaskVR64
			: (RK == RK2_F64) ? MaskFR : MaskVR;
		DstSlot = deobf(B, DR, DMask, "vm.cl.ds");
	}

	// fn(Base+0), nargs(Base+1), flags(Base+2), types_lo(Base+3), types_hi(Base+4)
	Value* FnIdx = B.CreateZExt(loadBC(B, CurIP, Base + 0, "vm.cl.fi"), I32Ty, "vm.cl.fx");
	Value* NArgs = B.CreateZExt(loadBC(B, CurIP, Base + 1, "vm.cl.na"), I32Ty, "vm.cl.nx");
	// fn(Base+0), nargs(Base+1) -- flags/types removed, now in GVFTyIndices.


	Value* Callee = ConstantPointerNull::get(cast<PointerType>(PtrTy));
	if (EffCallees) {
		Value* FnIdx64 = B.CreateZExt(FnIdx, I64Ty, "vm.cl.fi64");
		Callee = B.CreateLoad(PtrTy,
			B.CreateGEP(PtrTy, EffCallees, FnIdx64, "vm.cl.cg"),
			"vm.cl.fn");

		// XOR-decode callee pointer when mask is active
		if (EffCalleeMask) {
			Value* CalInt = B.CreatePtrToInt(Callee, I64Ty, "vm.cl.ci");
			Value* Decoded = B.CreateXor(CalInt, EffCalleeMask, "vm.cl.dec");
			Callee = B.CreateIntToPtr(Decoded, PtrTy, "vm.cl.dp");
		}

	}


	// Load FTyIdx from GVFTyIndices[FnIdx].
	Value* FTyIdx = B.getInt32(0);
	if (EffFTyIndices && !UniqueFTys.empty()) {
		Value* FnIdx64b = B.CreateZExt(FnIdx, I64Ty, "vm.cl.fi64b");
		Value* FTyIdxByte = B.CreateLoad(I8Ty,
			B.CreateGEP(I8Ty, EffFTyIndices, FnIdx64b, "vm.cl.fig"),
			"vm.cl.ftyi");
		FTyIdx = B.CreateZExt(FTyIdxByte, I32Ty, "vm.cl.ftyx");
	}

	// Pre-load all MaxArgs arg slots.  The per-FTy case BBs select the right
	// register file for each argument statically (no runtime Cat switch needed).
	SmallVector<Value*, MaxArgs> PVals, IVals, I64Vs, FregVals;
	for (unsigned i = 0; i < MaxArgs; ++i) {
		// arg bytes now start at Base+2 (was Base+5).
		Value* AB = loadBC(B, CurIP, Base + 2 + i, "vm.cl.ab");
		Value* PIdx = deobf(B, AB, MaskPR, "vm.cl.pi");
		Value* VIdx = deobf(B, AB, MaskVR, "vm.cl.vi");
		Value* V64I = deobf(B, AB, MaskVR64, "vm.cl.v64i");

		Value* FIdx = deobf(B, AB, MaskFR, "vm.cl.fxi");
		PVals.push_back(ldPR(B, PIdx));
		IVals.push_back(B.CreateIntToPtr(ldVR(B, VIdx), PtrTy, "vm.cl.ivp"));
		I64Vs.push_back(B.CreateIntToPtr(ldVR64(B, V64I), PtrTy, "vm.cl.i64p"));

		FregVals.push_back(ldFR(B, FIdx));
	}





	// Advance IP: Base + 2 header bytes + nargs arg bytes  (was Base + 5).
	Value* Adv = B.CreateAdd(B.getInt32(Base + 2), NArgs, "vm.cl.adv");
	B.CreateStore(B.CreateAdd(CurIP, Adv, "vm.cl.nb"), VMIP)->setVolatile(true);


	Type* RetTy = (RK == RK2_PTR) ? (Type*)PtrTy
		: (RK == RK2_I64) ? (Type*)I64Ty
		: (RK == RK2_F64) ? (Type*)DoubleTy
		: (RK == RK2_I32) ? (Type*)I32Ty
		: (Type*)Type::getVoidTy(Ctx);

	BasicBlock* MergeBB = BasicBlock::Create(Ctx, "vm.cl.merge", HFn);

	// switch on FTyIdx -- one case per unique FunctionType.
	unsigned NFTy = (unsigned)UniqueFTys.size();
	PHINode* RetPHI = nullptr;


	// In shared engine mode, always create the PHI and switch even if
	// NFTy==0 — ensureCallFTyCases() will add cases later when subsequent
	// functions register new FunctionTypes.
	if (!IsVoid)
		RetPHI = PHINode::Create(RetTy, std::max(NFTy, 1u), "vm.cl.phi", MergeBB);

	// Default (unreachable): FTyIdx out of range.
	auto* UnreachBB = BasicBlock::Create(Ctx, "vm.cl.ur", HFn);
	IRBuilder<>(UnreachBB).CreateUnreachable();

	// Always create the switch (even with 0 cases in shared mode).
	auto* FTySW = B.CreateSwitch(FTyIdx, UnreachBB, std::max(NFTy, 1u));
	for (unsigned TIdx = 0; TIdx < NFTy; ++TIdx) {
		FunctionType* SrcFTy = UniqueFTys[TIdx];
		unsigned N = SrcFTy->getNumParams();
		bool     isVA = SrcFTy->isVarArg();

		auto* CaseBB = BasicBlock::Create(Ctx, "vm.cl.fty" + Twine(TIdx), HFn);
		FTySW->addCase(B.getInt32(TIdx), CaseBB);
		IRBuilder<> CB(CaseBB);

		SmallVector<Type*, MaxArgs> ATys;
		SmallVector<Value*, MaxArgs> CA;
		for (unsigned i = 0; i < N && i < MaxArgs; ++i) {
			Type* PT = SrcFTy->getParamType(i);
			if (PT->isFloatTy() || PT->isDoubleTy()) {
				ATys.push_back(DoubleTy);
				CA.push_back(FregVals[i]);
			}
			else {
				ATys.push_back(PtrTy);
				if (PT->isPointerTy())
					CA.push_back(PVals[i]);
				else if (PT->isIntegerTy(64))
					CA.push_back(I64Vs[i]);
				else
					CA.push_back(IVals[i]);

			}

		}


		auto* CallFTy = FunctionType::get(RetTy, ATys, isVA);
		auto* CI = CB.CreateCall(CallFTy, Callee, CA, IsVoid ? "" : "vm.cl.rv");
		if (!IsVoid && RetPHI) RetPHI->addIncoming(CI, CB.GetInsertBlock());
		CB.CreateBr(MergeBB);
	}

	// Store switch info for ensureCallFTyCases() to extend later.
	if (SharedEngineMode) {
		auto* SS = VMEngine::getSharedState(M);
		auto& CSW = SS->CallSW[(unsigned)RK];
		CSW.SW = FTySW;
		CSW.MergeBB = MergeBB;
		CSW.RetPHI = RetPHI;
		CSW.Callee = Callee;
		CSW.RK = RK;
		CSW.PVals.assign(PVals.begin(), PVals.end());
		CSW.IVals.assign(IVals.begin(), IVals.end());
		CSW.I64Vs.assign(I64Vs.begin(), I64Vs.end());
		CSW.FregVals.assign(FregVals.begin(), FregVals.end());
	}

	IRBuilder<> MB(MergeBB);
	if (!IsVoid && DstSlot && RetPHI) {
		switch (RK) {
		case RK2_PTR: stPR(MB, DstSlot, RetPHI);  break;
		case RK2_I64: stVR64(MB, DstSlot, RetPHI); break;
		case RK2_F64: stFR(MB, DstSlot, RetPHI);  break;
		default:      stVR(MB, DstSlot, RetPHI);  break;
		}
	}
	MB.CreateBr(Dispatch);
}


void VMImpl::buildHandlerTable() {
	// table is [OP_COUNT+1 x ptr].  Slots 0..OP_COUNT-1 hold
	// permuted BlockAddress entries (existing).  Slot [OP_COUNT] holds the
	// engine function pointer — the wrapper loads it and makes an indirect
	// call, breaking static call-site xref analysis.
	//
	// NOTE: The pointer is stored unmasked here because LLVM 21 does not
	// support xor(ptrtoint) in constant-expression global initialisers.
	// The handler table already contains 51 blockaddress(@__vm_engine,...)
	// entries so one more raw ptr adds no new information for the analyst.
	// (constant blinding) will obfuscate the wrapper's runtime
	// load path so the connection is not trivially visible in the wrapper.
	static constexpr unsigned TableSize = OP_COUNT + 1;
	SmallVector<Constant*, OP_COUNT + 1> Es;
	Es.resize(TableSize, nullptr);

	// In shared engine mode, OpcBB[] lives in vm_engine.
	Function* BAFn = SharedEngineMode
		? VMEngine::getSharedState(M)->EngineFn : &F;
	BasicBlock** SrcBB = SharedEngineMode
		? VMEngine::getSharedState(M)->OpcBB : OpcBB;

	for (unsigned L = 0; L < OP_COUNT; ++L) {
		assert(SrcBB[L] && "missing opcode handler");
		unsigned P = (unsigned)OpMap.encode((VMOp)L);
		assert(P < OP_COUNT && "opcode map out of range");
		Es[P] = BlockAddress::get(BAFn, SrcBB[L]);
	}
	for (unsigned P = 0; P < OP_COUNT; ++P)
		assert(Es[P] && "unfilled handler table slot");

	// engine pointer in slot [OP_COUNT]
	{
		Function* EngFn = M.getFunction(VMEngine::kVMEngineName);
		assert(EngFn && "vm_engine must exist before building handler table");
		Es[OP_COUNT] = EngFn;
	}

	auto* ATy = ArrayType::get(PtrTy, TableSize);
	GVHandlers = new GlobalVariable(M, ATy, true, GlobalValue::PrivateLinkage,
		ConstantArray::get(ATy, Es), (F.getName() + ".vm.ophandlers").str());
	GVHandlers->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
}

// buildDispatch 
// vm.dispatch: bounds-check IP  vm.fetch: fetch opcode  decrypt  indirectbr

void VMImpl::buildDispatch() {
	// ExitBB is new; Dispatch is the shell already created in run()
	ExitBB = BasicBlock::Create(Ctx, "vm.exit", HFn);
	auto* FetchBB = BasicBlock::Create(Ctx, "vm.fetch", HFn);

	new UnreachableInst(Ctx, ExitBB);

	//  vm.dispatch: bounds check 
	{
		IRBuilder<> B(Dispatch);
		auto* IP = B.CreateLoad(I32Ty, VMIP, "vm.ip.d"); IP->setVolatile(true);
		Value* BCLen = EffBCLen ? EffBCLen
			: (Value*)B.getInt32((uint32_t)E.BC.size());
		Value* OOB = B.CreateICmpUGE(IP, BCLen, "vm.oob");
		B.CreateCondBr(OOB, ExitBB, FetchBB);
	}

	//  vm.fetch: load opcode, decrypt, dispatch 
	{
		IRBuilder<> B(FetchBB);
		auto* IP = B.CreateLoad(I32Ty, VMIP, "vm.ip.f"); IP->setVolatile(true);
		Value* Raw = loadBC(B, IP, 0, "vm.raw");

		// loadBC() already decrypts when EncBytecode=1
		Value* OpB = Raw;

		// Advance IP past opcode byte
		B.CreateStore(B.CreateAdd(IP, B.getInt32(1), "vm.ip1"), VMIP)->setVolatile(true);

		// Clamp opcode index (prevents out-of-bounds GEP on corrupted bytecode)
		Value* OIdx = B.CreateZExt(OpB, I32Ty, "vm.oidx");
		Value* Safe = B.CreateURem(OIdx, B.getInt32(OP_COUNT), "vm.safe");

		// GEP into handler table[safe_opcode]
		Value* Slot = B.CreateGEP(PtrTy, EffHandlers, Safe, "vm.ohsl");
		Value* Hndl = B.CreateLoad(PtrTy, Slot, "vm.hndl");

		// indirectbr with all opcode blocks declared as successors
		IndirectBrInst* IBR = B.CreateIndirectBr(Hndl, OP_COUNT + 1);
		for (unsigned i = 0; i < OP_COUNT; ++i) IBR->addDestination(OpcBB[i]);
		IBR->addDestination(ExitBB);
	}

	// Terminate vm.entry with branch to vm.dispatch
	if (Entry && !Entry->getTerminator())
		IRBuilder<>(Entry).CreateBr(Dispatch);
}


// buildEncryptCtor
// Dispatches to AES or LCG based on the useAES config flag.

void VMImpl::buildEncryptCtor() {
	if (!EncBytecode) return;
	if (!GVBytecodeRT) return;
	if (E.BC.empty()) return;

	if (UseAES)
		buildEncryptCtorAES();
	else
		buildEncryptCtorLCG();
}

// buildEncryptCtorLCG 
// Legacy LCG constructor (useAES=0 fallback).  Kept for regression safety.

void VMImpl::buildEncryptCtorLCG() {
	unsigned BCLen = (unsigned)E.BC.size();
	if (!BCLen) return;

	std::string FnName = (F.getName() + ".vm.ctor").str();
	auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	auto* Fn = Function::Create(FTy, GlobalValue::InternalLinkage, FnName, M);
	Fn->addFnAttr(Attribute::NoUnwind);

	// Blocks
	BasicBlock* EntBB = BasicBlock::Create(Ctx, "vm.ctor.entry", Fn);
	BasicBlock* LoopBB = BasicBlock::Create(Ctx, "vm.ctor.loop", Fn);
	BasicBlock* BodyBB = BasicBlock::Create(Ctx, "vm.ctor.body", Fn);
	BasicBlock* ExBB = BasicBlock::Create(Ctx, "vm.ctor.exit", Fn);

	// Entry: initialise idx = 0, key = EncSeed
	AllocaInst* IdxA = nullptr;
	AllocaInst* KeyA = nullptr;
	{
		IRBuilder<> B(EntBB);
		IdxA = B.CreateAlloca(I32Ty, nullptr, "ctor.idx");
		KeyA = B.CreateAlloca(I64Ty, nullptr, "ctor.key");
		B.CreateStore(B.getInt32(0), IdxA);
		B.CreateStore(ConstantInt::get(I64Ty, EncSeed), KeyA);
		B.CreateBr(LoopBB);
	}

	// Loop header: if idx < BCLen  body, else exit
	{
		IRBuilder<> LB(LoopBB);
		Value* Idx = LB.CreateLoad(I32Ty, IdxA, "ctor.i");
		LB.CreateCondBr(LB.CreateICmpULT(Idx, LB.getInt32(BCLen), "ctor.ib"), BodyBB, ExBB);
	}

	// Body: advance LCG, remove LCG layer into the writable runtime buffer
	{
		IRBuilder<> BB(BodyBB);
		Value* Idx = BB.CreateLoad(I32Ty, IdxA, "ctor.i2");
		Value* Key = BB.CreateLoad(I64Ty, KeyA, "ctor.k");
		// key = key * LCG_A + LCG_C
		Value* NK = BB.CreateAdd(BB.CreateMul(Key, BB.getInt64(LCG_A), "ctor.km"),
			BB.getInt64(LCG_C), "ctor.kn");
		BB.CreateStore(NK, KeyA);

		// keystream byte = (key >> 24) & 0xFF
		Value* KB = BB.CreateTrunc(BB.CreateLShr(NK, 24, "ctor.ks"), I8Ty, "ctor.kb");

		// Read const bytecode, XOR keystream to remove LCG layer, store into runtime buffer.
		Value* Src = BB.CreateGEP(I8Ty, GVBytecode, Idx, "ctor.src");
		Value* Dst = BB.CreateGEP(I8Ty, GVBytecodeRT, Idx, "ctor.dst");
		Value* EncB = BB.CreateLoad(I8Ty, Src, "ctor.eb");
		Value* DecB = BB.CreateXor(EncB, KB, "ctor.dec");
		BB.CreateStore(DecB, Dst);



		BB.CreateStore(BB.CreateAdd(Idx, BB.getInt32(1), "ctor.ni"), IdxA);
		BB.CreateBr(LoopBB);
	}
	IRBuilder<>(ExBB).CreateRetVoid();
	appendToGlobalCtors(M, Fn, 65535, nullptr);
}

//  buildEncryptCtorAES ─
// AES-128-CTR constructor.
//
// Architecture:
//   1. Store the 176-byte expanded key schedule as a XOR-masked global.
//   2. Store the 8-byte nonce as a global.
//   3. The .init_array constructor:
//      a) Copies the masked key to a stack buffer and XOR-unmasks it.
//      b) Copies the const bytecode into the writable runtime buffer.
//      c) Calls __obf_aes_ctr_decrypt(rt_buf, len, unmasked_key, nonce).
//   4. The runtime buffer now has Layer 2 stripped; Layer 1 (per-fetch XOR)
//      remains and is removed by loadBC() in the dispatch loop.
//
// When strenc is also active, the __obf_aes_ctr_decrypt function is already
// linked from the strenc pass — the dedup check prevents double-linking.

void VMImpl::buildEncryptCtorAES() {
	unsigned BCLen = (unsigned)E.BC.size();
	if (!BCLen) return;

	// Link the AES stub (shared with strenc)
	Function* CTRDecryptFn = M.getFunction("__obf_aes_ctr_decrypt");
	if (!CTRDecryptFn) {
		// If strenc already linked the stub, both functions are present.
		// If not, link from the shared embedded bitcode.
		if (!M.getFunction("__aes_decrypt")) {
			if (llvm::obf::StubBitcodeSize > 0) {
				MemoryBufferRef MBR(
					StringRef(reinterpret_cast<const char*>(llvm::obf::StubBitcode),
						llvm::obf::StubBitcodeSize),
					"aes_stub.bc");
				auto StubOrErr = parseBitcodeFile(MBR, Ctx);
				if (StubOrErr) {
					auto StubM = std::move(*StubOrErr);
					StubM->setDataLayout(M.getDataLayout());
					StubM->setTargetTriple(M.getTargetTriple());
					if (Linker::linkModules(M, std::move(StubM), 0)) {
						errs() << "[vm] linkModules failed for AES stub\n";
					}
				}
				else {
					handleAllErrors(StubOrErr.takeError(),
						[](const ErrorInfoBase& EI) {
							errs() << "[vm] AES stub parse failed: "
								<< EI.message() << "\n";
						});
				}
			}
			else {
				errs() << "[vm] embedded AES stub bitcode is empty — "
					<< "did the CMake strenc_stub build rule run?\n";
			}
		}
		CTRDecryptFn = M.getFunction("__obf_aes_ctr_decrypt");
	}

	if (!CTRDecryptFn) {
		errs() << "[vm] WARNING: __obf_aes_ctr_decrypt not available, "
			<< "falling back to LCG\n";
		buildEncryptCtorLCG();
		return;
	}


	// Resolve dangling __strenc_key_a / __strenc_key_b declarations
	provideStubKeyProviderBodies(M);

	// Create masked expanded-key global 
	SmallVector<Constant*, 176> MaskedRK;
	for (int i = 0; i < 176; i++)
		MaskedRK.push_back(ConstantInt::get(I8Ty, AESExpandedKey[i] ^ AESRKMask[i]));

	auto* RKTy = ArrayType::get(I8Ty, 176);
	GVAESExpandedKey = new GlobalVariable(
		M, RKTy, /*isConst=*/true, GlobalValue::PrivateLinkage,
		ConstantArray::get(RKTy, MaskedRK),
		(F.getName() + ".vm.aes.rk").str());
	GVAESExpandedKey->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
	GVAESExpandedKey->setAlignment(Align(16));

	// Nonce global (8 bytes, little-endian)
	SmallVector<Constant*, 8> NonceBytes;
	for (int i = 0; i < 8; i++)
		NonceBytes.push_back(ConstantInt::get(I8Ty, (AESNonce >> (8 * i)) & 0xFF));
	auto* NonceTy = ArrayType::get(I8Ty, 8);
	GVAESNonce = new GlobalVariable(
		M, NonceTy, /*isConst=*/true, GlobalValue::PrivateLinkage,
		ConstantArray::get(NonceTy, NonceBytes),
		(F.getName() + ".vm.aes.nonce").str());
	GVAESNonce->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

	// Mask global (used to unmask the expanded key on the stack)
	SmallVector<Constant*, 176> MaskConsts;
	for (int i = 0; i < 176; i++)
		MaskConsts.push_back(ConstantInt::get(I8Ty, AESRKMask[i]));
	auto* MaskGV = new GlobalVariable(
		M, RKTy, /*isConst=*/true, GlobalValue::PrivateLinkage,
		ConstantArray::get(RKTy, MaskConsts),
		(F.getName() + ".vm.aes.rkmask").str());
	MaskGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

	// Build the .init_array constructor 
	std::string FnName = (F.getName() + ".vm.ctor").str();
	auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	auto* CtorFn = Function::Create(FTy, GlobalValue::InternalLinkage, FnName, M);
	CtorFn->addFnAttr(Attribute::NoUnwind);

	BasicBlock* BB = BasicBlock::Create(Ctx, "vm.ctor.aes", CtorFn);
	IRBuilder<> B(BB);

	// a) Unmask the expanded key on the stack
	auto* RKAlloca = B.CreateAlloca(RKTy, nullptr, "vm.ctor.rk");
	RKAlloca->setAlignment(Align(16));
	// memcpy masked key to stack
	B.CreateMemCpy(RKAlloca, Align(16), GVAESExpandedKey, Align(16),
		ConstantInt::get(I64Ty, 176));
	// XOR with mask: rk[i] ^= mask[i] for i in 0..175
	// Emit as a simple loop
	BasicBlock* LoopHdr = BasicBlock::Create(Ctx, "vm.ctor.unmask.hdr", CtorFn);
	BasicBlock* LoopBody = BasicBlock::Create(Ctx, "vm.ctor.unmask.body", CtorFn);
	BasicBlock* AfterLoop = BasicBlock::Create(Ctx, "vm.ctor.unmask.done", CtorFn);

	B.CreateBr(LoopHdr);
	// Loop header
	IRBuilder<> LH(LoopHdr);
	PHINode* Idx = LH.CreatePHI(I32Ty, 2, "vm.ctor.idx");
	Idx->addIncoming(LH.getInt32(0), BB);
	LH.CreateCondBr(LH.CreateICmpULT(Idx, LH.getInt32(176)), LoopBody, AfterLoop);

	// Loop body: rk[i] ^= mask[i]
	IRBuilder<> LB(LoopBody);
	Value* Idx64 = LB.CreateZExt(Idx, I64Ty);
	Value* RKPtr = LB.CreateGEP(I8Ty, RKAlloca, Idx64, "vm.ctor.rkp");
	Value* MkPtr = LB.CreateGEP(I8Ty, MaskGV, Idx64, "vm.ctor.mkp");
	Value* RKByte = LB.CreateLoad(I8Ty, RKPtr);
	Value* MkByte = LB.CreateLoad(I8Ty, MkPtr);
	LB.CreateStore(LB.CreateXor(RKByte, MkByte), RKPtr);
	Value* NextIdx = LB.CreateAdd(Idx, LB.getInt32(1));
	Idx->addIncoming(NextIdx, LoopBody);
	LB.CreateBr(LoopHdr);

	// b) memcpy const bytecode → writable runtime buffer
	IRBuilder<> AB(AfterLoop);
	AB.CreateMemCpy(GVBytecodeRT, Align(16), GVBytecode, Align(1),
		ConstantInt::get(I64Ty, BCLen));

	// c) Call __obf_aes_ctr_decrypt(rt_buf, len, rk_stack, nonce_ptr)
	Value* RTBufPtr = AB.CreateBitCast(GVBytecodeRT, PointerType::getUnqual(Ctx));
	Value* RKPtr2 = AB.CreateBitCast(RKAlloca, PointerType::getUnqual(Ctx));
	Value* NoncePtr = AB.CreateBitCast(GVAESNonce, PointerType::getUnqual(Ctx));
	AB.CreateCall(CTRDecryptFn, {
		RTBufPtr,
		ConstantInt::get(I32Ty, BCLen),
		RKPtr2,
		NoncePtr
		});
	AB.CreateRetVoid();

	appendToGlobalCtors(M, CtorFn, 65535, nullptr);

	if (ObfVerbose)
		errs() << "[vm] AES-CTR ctor built for '" << F.getName()
		<< "' [" << BCLen << "B, nonce=0x"
		<< Twine::utohexstr(AESNonce) << "]\n";
}



// ============================================================================
// SharedState management + vm_engine shell + engine population
// ============================================================================

#include <mutex>

namespace {
	static std::mutex SharedStateMu;
	static DenseMap<Module*, std::unique_ptr<VMEngine::SharedState>> SharedStateMap;
}

namespace llvm {
	namespace VMEngine {

		static const char* const kParamNames[kNumParams] = {
			"bc", "bc_len", "regs", "regs64", "fregs", "pregs",
			"callees", "salt", "regMask", "reg64Mask", "fregMask", "pregMask",
			"handlers", "fty_indices",
			"regkeys", "reg64keys", "fregkeys",
			"callee_mask",

		};
		static constexpr const char* kPopulatedMDKey = "obf.vm.engine.populated";

		Function* getOrBuildVMEngine(Module& M) {
			// Lookup only — returns null if not yet created.
			// populateVMEngine() handles atomic creation + population.
			if (Function* Existing = M.getFunction(kVMEngineName)) {
				assert(Existing->arg_size() == kNumParams &&
					"vm_engine parameter count mismatch");
				return Existing;
			}
			return nullptr;
		}

		bool isEnginePopulated(Function* VMEngineFunc) {
			if (!VMEngineFunc) return false;
			MDNode* MD = VMEngineFunc->getMetadata(kPopulatedMDKey);
			if (!MD || MD->getNumOperands() == 0) return false;
			auto* CAM = dyn_cast<ConstantAsMetadata>(MD->getOperand(0));
			if (!CAM) return false;
			auto* CI = dyn_cast<ConstantInt>(CAM->getValue());
			return CI && CI->isOne();
		}

		void markEnginePopulated(Function* VMEngineFunc) {
			if (!VMEngineFunc) return;
			LLVMContext& C = VMEngineFunc->getContext();
			MDNode* TrueMD = MDNode::get(C, {
				ConstantAsMetadata::get(ConstantInt::getTrue(C))
				});
			VMEngineFunc->setMetadata(kPopulatedMDKey, TrueMD);
		}

		SharedState* getSharedState(Module& M) {
			std::lock_guard<std::mutex> LK(SharedStateMu);
			auto& Ptr = SharedStateMap[&M];
			if (!Ptr) Ptr = std::make_unique<SharedState>();
			return Ptr.get();
		}

		void releaseSharedState(Module& M) {
			std::lock_guard<std::mutex> LK(SharedStateMu);
			SharedStateMap.erase(&M);
		}

	} // namespace VMEngine
} // namespace llvm

// setupEffLocal: point Eff* at per-function allocas/globals

void VMImpl::setupEffLocal() {
	HFn = &F;
	EffBC = (EncBytecode && GVBytecodeRT) ? (Value*)GVBytecodeRT : (Value*)GVBytecode;
	EffBCLen = nullptr;
	EffSalt = VMSalt;
	EffRegs = VMRegs;
	EffRegs64 = VMRegs64;
	EffFregs = VMFregs;
	EffPregs = VMPRegs;
	EffCallees = GVCallees;
	EffFTyIndices = GVFTyIndices;
	EffHandlers = GVHandlers;
	MaskVR = ConstantInt::get(I32Ty, NVRAlloc > 0 ? NVRAlloc - 1 : 0);
	MaskVR64 = ConstantInt::get(I32Ty, NVR64Alloc > 0 ? NVR64Alloc - 1 : 0);
	MaskFR = ConstantInt::get(I32Ty, NFRAlloc > 0 ? NFRAlloc - 1 : 0);
	MaskPR = ConstantInt::get(I32Ty, NPRAlloc > 0 ? NPRAlloc - 1 : 0);
	// local mode never encrypts registers (no engine params)
	EffRegKeys = nullptr;
	EffReg64Keys = nullptr;
	EffFRegKeys = nullptr;
	EffCalleeMask = nullptr;  // no callee masking in local mode
	SharedEngineMode = false;
}

// populateVMEngine: build all handlers inside shared vm_engine 

void VMImpl::populateVMEngine() {
	auto* SS = VMEngine::getSharedState(M);
	if (SS->Populated) return;

	// Create __vm_engine AND populate it atomically 
	// The function must never be visible to LLVM infrastructure as an
	// empty declaration — MSVC debug ilist sentinel assertions fire when
	// anything iterates an empty basic block list.  We create the function
	// and immediately start adding blocks in the same C++ scope.

	FunctionType* FTy = VMEngine::getVMEngineFunctionType(Ctx);
	Function* EF = Function::Create(FTy, GlobalValue::InternalLinkage,
		VMEngine::kVMEngineName, &M);

	// CRITICAL: Create the entry block IMMEDIATELY after Function::Create.
	// The function must never be observable with an empty block list —
	// MSVC debug builds assert on ilist sentinel dereference if anything
	// (pass manager, analysis invalidation) iterates an empty function.
	BasicBlock* EngEntry = BasicBlock::Create(Ctx, "vm.entry", EF);

	{
		unsigned PIdx = 0;
		static const char* const PNames[] = {
			"bc", "bc_len", "regs", "regs64", "fregs", "pregs",
			"callees", "salt", "regMask", "reg64Mask", "fregMask", "pregMask",
			"handlers", "fty_indices",
			"regkeys", "reg64keys", "fregkeys",
			"callee_mask",
		};
		for (Argument& A : EF->args()) A.setName(PNames[PIdx++]);
	}
	EF->addFnAttr(Attribute::NoUnwind);
	EF->addFnAttr(Attribute::NoInline);
	EF->addFnAttr(Attribute::OptimizeNone);
	EF->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
	SS->EngineFn = EF;



	// Set up Eff* to point at vm_engine parameters
	HFn = EF;
	SharedEngineMode = true;

	EffBC = EF->getArg(VMEngine::kParamBC);
	EffBCLen = EF->getArg(VMEngine::kParamBCLen);
	EffRegs = EF->getArg(VMEngine::kParamRegs);
	EffRegs64 = EF->getArg(VMEngine::kParamRegs64);
	EffFregs = EF->getArg(VMEngine::kParamFregs);
	EffPregs = EF->getArg(VMEngine::kParamPregs);
	EffCallees = EF->getArg(VMEngine::kParamCallees);
	EffHandlers = EF->getArg(VMEngine::kParamHandlers);
	EffFTyIndices = EF->getArg(VMEngine::kParamFTyIndices);
	MaskVR = EF->getArg(VMEngine::kParamRegMask);
	MaskVR64 = EF->getArg(VMEngine::kParamReg64Mask);
	MaskFR = EF->getArg(VMEngine::kParamFregMask);
	MaskPR = EF->getArg(VMEngine::kParamPregMask);
	// key array pointers (null when regEncrypt is off)
	EffRegKeys = EF->getArg(VMEngine::kParamRegKeys);
	EffReg64Keys = EF->getArg(VMEngine::kParamReg64Keys);
	EffFRegKeys = EF->getArg(VMEngine::kParamFRegKeys);
	EffCalleeMask = EF->getArg(VMEngine::kParamCalleeMask);

	// Build vm.entry with VMIP + salt alloca
	Entry = EngEntry;  // already created above
	IRBuilder<> EB(Entry);
	VMIP = EB.CreateAlloca(I32Ty, nullptr, "vm.ip");
	AllocaInst* SaltAlloca = EB.CreateAlloca(I32Ty, nullptr, "vm.salt");
	EB.CreateStore(EF->getArg(VMEngine::kParamSalt), SaltAlloca)->setVolatile(true);
	EffSalt = SaltAlloca;
	EB.CreateStore(EB.getInt32(0), VMIP)->setVolatile(true);

	SS->EngineVMIP = VMIP;
	SS->EngineSalt = SaltAlloca;
	SS->Entry = Entry;

	// Create Dispatch shell
	Dispatch = BasicBlock::Create(Ctx, "vm.dispatch", EF);
	SS->Dispatch = Dispatch;

	// Build all 51 opcode handlers
	buildOpcodeHandlers();

	for (unsigned i = 0; i < OP_COUNT; ++i)
		SS->OpcBB[i] = OpcBB[i];

	// Build dispatch loop
	buildDispatch();
	SS->ExitBB = ExitBB;

	// insert anti-debug timing gate between dispatch and fetch
	buildAntiDebugGate(SS);

	SS->Populated = true;
	SS->FTyCountAtLastBuild = (unsigned)SS->SharedFTys.size();
	VMEngine::markEnginePopulated(EF);

	if (VCtx.Cfg.hardened)
		hardenVMEngine(EF, SS);

	LLVM_DEBUG(dbgs() << "[vm] populated vm_engine with "
		<< OP_COUNT << " handler blocks\n");
	if (ObfVerbose)
		errs() << "[vm] vm_engine populated: " << OP_COUNT << " handlers\n";

	// Restore per-function state
	SharedEngineMode = false;
	HFn = &F;
}


// ============================================================================
// Handler-Level MBA + Opaque Predicates
//
// hardenVMEngine() is called once after populateVMEngine() builds all
// 51 handler blocks in __vm_engine.  It applies two transformations:
//
//   Part B — MBA substitutions on arithmetic in handler blocks:
//     ADD → (a|b)+(a&b) or (a^b)+2*(a&b) or 2*(a|b)-(a^b)
//     SUB → a + ~b + 1
//     XOR → (a|b) - (a&b)
//     AND → ~(~a | ~b)
//     OR  → (a^b) | (a&b)
//
//   Part C — Opaque predicates on dispatch back-edge + handler guards:
//     - hard-false before vm.dispatch → dead code block
//     - hard-true at ~30% of handler entries → bogus handler
//     - 3–5 dead code blocks with junk arithmetic
// ============================================================================

// Note: MBA helpers previously defined above as mbaAdd/mbaSub/mbaXor/mbaAnd/mbaOr
// are now provided by MbaUtils.  See hardenVMEngine below.

static bool isHandlerBlock(const BasicBlock& BB) {
	StringRef N = BB.getName();
	return N.starts_with("vm.opc.") || N.starts_with("vm.bo.") ||
		N.starts_with("vm.bo64.") || N.starts_with("vm.bof.") ||
		N.starts_with("vm.sl.") || N.starts_with("vm.cl.") ||
		N.starts_with("vm.fcp.") || N.starts_with("vm.c64.") ||
		N.starts_with("vm.sw.");
}

void VMImpl::hardenVMEngine(Function* EF, VMEngine::SharedState* SS) {
	if (!EF || !SS) return;

	auto HardenRng = VCtx.R.fork("vm.harden");
	llvm::obf::OpaqueUtils Opaque(M, HardenRng, "vm.opaque.salt.i32");
	llvm::obf::MbaUtils MBA(M, HardenRng, "obf.vm.mba.noise.i32");

	unsigned MBASites = 0;
	unsigned GuardedHandlers = 0;
	unsigned DeadBlocks = 0;

	// ════════════════════════════════════════════════════════════════════
	// MBA substitutions on handler arithmetic
	// ════════════════════════════════════════════════════════════════════

	// Collect candidates first (can't modify while iterating).
	SmallVector<BinaryOperator*, 64> Candidates;
	for (BasicBlock& BB : *EF) {
		if (!isHandlerBlock(BB)) continue;
		for (Instruction& I : BB) {
			if (auto* BO = dyn_cast<BinaryOperator>(&I))
			{
				// Only transform i32 and i64 integer arithmetic.
				if (!BO->getType()->isIntegerTy()) continue;
				unsigned Opc = BO->getOpcode();
				if (!llvm::obf::MbaUtils::isTargetOpcode(BO->getOpcode())) continue;
				Candidates.push_back(BO);
			}
		}
	}

	for (BinaryOperator* BO : Candidates) {
		if (!BO->getParent()) continue; // already erased

		IRBuilder<> B(BO);
		Value* A = BO->getOperand(0);
		Value* V = BO->getOperand(1);
		Value* Replacement = nullptr;

		unsigned Variant = HardenRng.u32();
		switch (BO->getOpcode()) {
		case Instruction::Add: {
			switch (HardenRng.range(3))
			{
			case 0:  Replacement = MBA.addAlt(B, A, V);  break; // (a|b)+(a&b)
			case 1:  Replacement = MBA.add(B, A, V);     break; // (a^b)+2*(a&b)
			default: Replacement = MBA.addAlt2(B, A, V); break; // 2*(a|b)-(a^b)
			}
			break;
		}
		case Instruction::Sub: Replacement = MBA.subAlt2(B, A, V); break;
		case Instruction::Xor: Replacement = MBA.bitwiseXor(B, A, V); break;
		case Instruction::And: Replacement = MBA.bitwiseAndAlt(B, A, V); break;
		case Instruction::Or:  Replacement = MBA.bitwiseOrAlt2(B, A, V); break;
		default: break;
		}

		if (!Replacement) continue;

		// ~30% chance: XOR result with opaque zero for noise.
		if (HardenRng.range(100) < 30) {
			Value* Zero = Opaque.opaqueZero32(B);            // i32
			Type* RepTy = Replacement->getType();
			if (RepTy != Zero->getType()) {
				unsigned BW = RepTy->getIntegerBitWidth();
				if (BW > 32)
					Zero = B.CreateZExt(Zero, RepTy, "mba.z.ext");
				else
					Zero = B.CreateTrunc(Zero, RepTy, "mba.z.trunc");
			}
			Replacement = B.CreateXor(Replacement, Zero, "mba.noise");
		}

		BO->replaceAllUsesWith(Replacement);
		BO->eraseFromParent();
		++MBASites;
	}

	// ════════════════════════════════════════════════════════════════════
	// Opaque predicates on dispatch + dead code
	// ════════════════════════════════════════════════════════════════════

	// Dead code blocks
	// Create 3–5 dead code blocks with junk instructions that branch
	// back to vm.dispatch (makes CFG look connected).
	unsigned NDeadBlocks = 3 + HardenRng.range(3); // 3..5
	SmallVector<BasicBlock*, 8> DeadBBs;
	for (unsigned i = 0; i < NDeadBlocks; ++i) {
		auto* DBB = BasicBlock::Create(Ctx, "vm.dead." + Twine(i), EF);
		IRBuilder<> DB(DBB);

		// Junk arithmetic using opaque constants.
		Value* J1 = Opaque.opaqueI32Const(DB, HardenRng.u32());
		Value* J2 = Opaque.opaqueI32Const(DB, HardenRng.u32());
		Value* R1 = DB.CreateXor(J1, J2, "vm.dead.xor");
		Value* R2 = DB.CreateMul(R1, J1, "vm.dead.mul");
		Value* R3 = DB.CreateAdd(R2, J2, "vm.dead.add");
		(void)R3; // result unused — this is dead code

		// Branch back to dispatch (makes block look connected in CFG).
		DB.CreateBr(SS->Dispatch);
		DeadBBs.push_back(DBB);
		++DeadBlocks;
	}

	// Opaque predicate on vm.dispatch back-edge 
	// Split vm.dispatch: insert a pre-dispatch block with hard-false
	// branch to dead code.
	if (SS->Dispatch && !DeadBBs.empty()) {
		BasicBlock* DispBB = SS->Dispatch;
		// Create a new pre-dispatch block.
		BasicBlock* PreDisp = BasicBlock::Create(Ctx, "vm.predisp", EF, DispBB);

		// Redirect all predecessors of vm.dispatch to vm.predisp.
		SmallVector<BasicBlock*, 32> Preds(predecessors(DispBB));
		for (BasicBlock* Pred : Preds) {
			if (Pred == PreDisp) continue; // skip self
			Instruction* Term = Pred->getTerminator();
			if (!Term) continue;
			for (unsigned i = 0, e = Term->getNumSuccessors(); i < e; ++i) {
				if (Term->getSuccessor(i) == DispBB)
					Term->setSuccessor(i, PreDisp);
			}
		}

		// PreDisp: hard-false → dead code, else → real dispatch.
		IRBuilder<> PB(PreDisp);
		Value* Fake = Opaque.hardFalse(PB);
		unsigned DeadIdx = HardenRng.range((uint32_t)DeadBBs.size());
		PB.CreateCondBr(Fake, DeadBBs[DeadIdx], DispBB);
	}

	// Hard-true guards on ~30% of handler entries
	// For a random subset of handler blocks, split at entry and add
	// a hard-true guard branching to a bogus block.
	SmallVector<BasicBlock*, 64> HandlerBBs;
	for (BasicBlock& BB : *EF) {
		if (BB.getName().starts_with("vm.opc."))
			HandlerBBs.push_back(&BB);
	}

	for (BasicBlock* HBB : HandlerBBs) {
		if (HardenRng.range(100) >= 30) continue; // ~30% probability

		// Create guard block before the handler.
		BasicBlock* GuardBB = BasicBlock::Create(Ctx,
			HBB->getName().str() + ".guard", EF, HBB);

		// Create bogus block (junk + branch to dispatch).
		BasicBlock* BogusBB = BasicBlock::Create(Ctx,
			HBB->getName().str() + ".bogus", EF);
		{
			IRBuilder<> BB(BogusBB);
			Value* J = Opaque.opaqueI32Const(BB, HardenRng.u32());
			(void)BB.CreateXor(J, J, "vm.bogus.j");
			BB.CreateBr(SS->Dispatch);
		}

		// Redirect predecessors of handler to guard block.
		SmallVector<BasicBlock*, 8> HPreds(predecessors(HBB));
		for (BasicBlock* Pred : HPreds) {
			if (Pred == GuardBB) continue;
			Instruction* Term = Pred->getTerminator();
			if (!Term) continue;
			for (unsigned i = 0, e = Term->getNumSuccessors(); i < e; ++i) {
				if (Term->getSuccessor(i) == HBB)
					Term->setSuccessor(i, GuardBB);
			}
		}

		// Guard: hard-true → real handler, else → bogus.
		IRBuilder<> GB(GuardBB);
		Value* Guard = Opaque.randomHardTrue(GB);
		GB.CreateCondBr(Guard, HBB, BogusBB);
		++GuardedHandlers;
	}

	// handler spot-check timing traps 
	// Inject a micro-timing gate into ~10% of handler entry blocks.
	// Two readcyclecounter reads straddle the handler's first few
	// instructions.  Delta > 500 cycles catches breakpoints set inside
	// the handler (debug exception takes 5000+ cycles).
	//
	// Platform: only on targets with readcyclecounter (x86_64, AArch64).
	// The check is self-contained within the handler block — no cross-BB
	// alloca needed.
	unsigned HandlerTraps = 0;
	if (VCtx.Cfg.antiDebug && (TI.IsX86_64 || TI.IsAArch64)) {
		Function* RCC = Intrinsic::getDeclaration(&M, Intrinsic::readcyclecounter);


		// Collect candidates FIRST to avoid iterator invalidation.
		SmallVector<BasicBlock*, 16> TrapCandidates;
		for (BasicBlock& BB : *EF) {
			if (!isHandlerBlock(BB)) continue;
			if (BB.getName().contains(".ad.") || BB.getName().contains(".guard")
				|| BB.getName().contains(".bogus")) continue;
			if (HardenRng.range(100) >= (int)VCtx.Cfg.adHandlerProb) continue;


		}

		for (BasicBlock* HBB : TrapCandidates) {
			// Insert at handler entry — before all existing instructions.
			IRBuilder<> B(&*HBB->getFirstInsertionPt());

			Value* T1 = B.CreateCall(RCC, {}, "vm.ad.h.t1");
			// Volatile barrier between reads
			auto* Bar = B.CreateLoad(I32Ty, SS->EngineSalt, "vm.ad.h.bar");
			cast<LoadInst>(Bar)->setVolatile(true);
			(void)B.CreateAdd(Bar, B.getInt32(0), "vm.ad.h.sink");
			Value* T2 = B.CreateCall(RCC, {}, "vm.ad.h.t2");

			Value* Delta = B.CreateSub(T2, T1, "vm.ad.h.delta");
			Value* Slow = B.CreateICmpUGT(Delta,
				B.getInt64((uint64_t)VCtx.Cfg.adHandlerThreshold),
				"vm.ad.h.slow");

			// Branchless salt corruption: select poison or zero
			Value* Poison = B.CreateSelect(Slow,
				B.getInt32(ADPoisonKey), B.getInt32(0), "vm.ad.h.pois");
			auto* OldSalt = B.CreateLoad(I32Ty, SS->EngineSalt, "vm.ad.h.salt");
			cast<LoadInst>(OldSalt)->setVolatile(true);
			Value* NewSalt = B.CreateXor(OldSalt, Poison, "vm.ad.h.xsal");
			B.CreateStore(NewSalt, SS->EngineSalt)->setVolatile(true);

			++HandlerTraps;
		}


	}




	LLVM_DEBUG(dbgs() << "[vm] hardened vm_engine: " << MBASites << " MBA sites, "
		<< GuardedHandlers << " guarded handlers, "
		<< DeadBlocks << " dead blocks, "
		<< HandlerTraps << " handler traps\n");
	if (ObfVerbose)
		errs() << "[vm] hardened=1: " << MBASites << " MBA substitutions, "
		<< GuardedHandlers << " handler guards, "
		<< DeadBlocks << " dead code blocks, "
		<< HandlerTraps << " handler timing traps\n";

}





// ensureCallFTyCases: extend CALL switches for new FunctionTypes
//
// Called after buildCalleeGlobal() in each function's run().  If this
// function introduced FunctionTypes not seen when the engine was first
// populated, adds new case blocks to the existing CALL handler switches
// inside __vm_engine.

void VMImpl::ensureCallFTyCases() {
	auto* SS = VMEngine::getSharedState(M);
	if (!SS->Populated) return;
	unsigned OldCount = SS->FTyCountAtLastBuild;
	unsigned NewCount = (unsigned)SS->SharedFTys.size();
	if (NewCount <= OldCount) return;

	Function* EF = SS->EngineFn;
	if (!EF) return;

	LLVM_DEBUG(dbgs() << "[vm] extending CALL switches: " << OldCount
		<< " -> " << NewCount << " FunctionTypes\n");

	// For each CALL opcode (indexed by RetKind2 0..4):
	for (unsigned RKIdx = 0; RKIdx < 5; ++RKIdx) {
		auto& CSW = SS->CallSW[RKIdx];
		if (!CSW.SW) continue;  // this CALL opcode wasn't built

		VMEngine::RetKind2 RK = CSW.RK;
		bool IsVoid = (RK == VMEngine::RK2_VOID);
		Type* RetTy = (RK == VMEngine::RK2_PTR) ? (Type*)PtrTy
			: (RK == VMEngine::RK2_I64) ? (Type*)I64Ty
			: (RK == VMEngine::RK2_F64) ? (Type*)DoubleTy
			: (RK == VMEngine::RK2_I32) ? (Type*)I32Ty
			: (Type*)Type::getVoidTy(Ctx);

		for (unsigned TIdx = OldCount; TIdx < NewCount; ++TIdx) {
			FunctionType* SrcFTy = SS->SharedFTys[TIdx];
			unsigned N = SrcFTy->getNumParams();
			bool isVA = SrcFTy->isVarArg();

			auto* CaseBB = BasicBlock::Create(Ctx,
				"vm.cl.fty" + Twine(TIdx), EF);
			CSW.SW->addCase(
				cast<ConstantInt>(ConstantInt::get(I32Ty, TIdx)), CaseBB);
			IRBuilder<> CB(CaseBB);

			SmallVector<Type*, VMEngine::MaxArgs> ATys;
			SmallVector<Value*, VMEngine::MaxArgs> CA;
			for (unsigned i = 0; i < N && i < VMEngine::MaxArgs; ++i) {
				Type* PT = SrcFTy->getParamType(i);
				if (PT->isFloatTy() || PT->isDoubleTy()) {
					ATys.push_back(DoubleTy);
					CA.push_back(CSW.FregVals[i]);
				}
				else {
					ATys.push_back(PtrTy);
					if (PT->isPointerTy())
						CA.push_back(CSW.PVals[i]);
					else if (PT->isIntegerTy(64))
						CA.push_back(CSW.I64Vs[i]);
					else
						CA.push_back(CSW.IVals[i]);
				}
			}

			auto* CallFTy = FunctionType::get(RetTy, ATys, isVA);
			auto* CI = CB.CreateCall(CallFTy, CSW.Callee, CA,
				IsVoid ? "" : "vm.cl.rv");
			if (!IsVoid && CSW.RetPHI)
				CSW.RetPHI->addIncoming(CI, CB.GetInsertBlock());
			CB.CreateBr(CSW.MergeBB);
		}
	}

	SS->FTyCountAtLastBuild = NewCount;
	if (ObfVerbose && NewCount > OldCount)
		errs() << "[vm] extended CALL handlers: +"
		<< (NewCount - OldCount) << " FunctionTypes\n";
}




// computeReturnInfo: scan F for ReturnInst before stripBody 
// Records which register file slot the return value occupies so
// buildWrapper() can extract it after vm_engine returns.

void VMImpl::computeReturnInfo() {
	WrapRetSlot = -1;
	WrapRetKind = VMEngine::RK2_VOID;

	for (BasicBlock& BB : F) {
		auto* RI = dyn_cast<ReturnInst>(BB.getTerminator());
		if (!RI) continue;
		Value* RV = RI->getReturnValue();
		if (!RV) {
			WrapRetKind = VMEngine::RK2_VOID;
			WrapRetSlot = -1;
			return;  // void
		}
		Type* RT = RV->getType();
		if (RT->isPointerTy()) {
			auto It = E.PR.find(RV);
			if (It != E.PR.end()) {
				WrapRetKind = VMEngine::RK2_PTR;
				WrapRetSlot = (int)It->second;
			}
		}
		else if (RT->isIntegerTy(64)) {
			auto It = E.VR64.find(RV);
			if (It != E.VR64.end()) {
				WrapRetKind = VMEngine::RK2_I64;
				WrapRetSlot = (int)It->second;
			}
		}
		else if (RT->isFloatTy() || RT->isDoubleTy()) {
			auto It = E.FR.find(RV);
			if (It != E.FR.end()) {
				WrapRetKind = VMEngine::RK2_F64;
				WrapRetSlot = (int)It->second;
			}
		}
		else if (RT->isIntegerTy()) {
			auto It = E.VR.find(RV);
			if (It != E.VR.end()) {
				WrapRetKind = VMEngine::RK2_I32;
				WrapRetSlot = (int)It->second;
			}
		}
		return;  // first ReturnInst is enough
	}
}

//  buildWrapper: thin wrapper that tail-calls vm_engine
// Replaces the per-function interpreter with:
//   1. Stack-allocate register files
//   2. Pre-load arguments + constants into register files
//   3. Call @__vm_engine(bc, bc_len, regs, ..., handlers, fty_indices)
//   4. Extract return value from register file
//   5. Return

void VMImpl::buildWrapper() {
	Entry = BasicBlock::Create(Ctx, "vm.entry", &F);
	IRBuilder<> B(Entry);

	// constant blinding helpers 
	// When hardened=1, security-sensitive constants (salt, masks, register
	// keys, encrypted values, engine-table index) are materialised through
	// opaque expression trees instead of bare immediates.  Structural
	// constants (GEP indices, alloca sizes) are left as-is.
	auto WrapBlindRng = VCtx.R.fork("vm.wrap.blind");
	llvm::obf::OpaqueUtils WrapOpaque(M, WrapBlindRng, "vm.wrap.opaque.i32");
	const bool Blind = VCtx.Cfg.hardened;

	auto blindI32 = [&](uint32_t C) -> Value* {
		if (!Blind) return B.getInt32(C);
		return WrapOpaque.opaqueI32Const(B, C);
		};
	auto blindI64 = [&](uint64_t C) -> Value* {
		if (!Blind) return B.getInt64(C);
		Value* Lo = B.CreateZExt(
			WrapOpaque.opaqueI32Const(B, (uint32_t)(C & 0xFFFFFFFF)),
			I64Ty, "vm.w.b64.lo");
		Value* Hi = B.CreateShl(B.CreateZExt(
			WrapOpaque.opaqueI32Const(B, (uint32_t)(C >> 32)),
			I64Ty, "vm.w.b64.hi"),
			B.getInt64(32), "vm.w.b64.sh");
		return B.CreateOr(Lo, Hi, "vm.w.b64");
		};


	// per-function polymorphism RNG
	auto PolyRng = VCtx.R.fork("vm.wrap.poly");
	const bool Poly = VCtx.Cfg.hardened;

	// Fisher-Yates shuffle helper
	auto fyShuffle = [&](unsigned* Arr, unsigned N) {
		if (!Poly || N < 2) return;
		for (unsigned i = N - 1; i > 0; --i)
			std::swap(Arr[i], Arr[PolyRng.range(i + 1)]);
		};


	// Re-create original entry-block allocas (PHI demotions) 
	// Same ordering as buildVMEntry to preserve ptrtoint64 stability.
	SmallVector<AllocaInst*, 8> Reallocas;
	Reallocas.reserve(E.PHIAllocas.size());
	for (const auto& PA : E.PHIAllocas) {
		auto* NA = B.CreateAlloca(PA.AllocTy, nullptr, Twine(PA.Name) + ".v7");
		if (PA.A) NA->setAlignment(*PA.A);
		Reallocas.push_back(NA);
	}

	// allocate register files in shuffled order (hardened)
	AllocaInst* WRegs = nullptr;
	AllocaInst* WRegs64 = nullptr;
	AllocaInst* WFregs = nullptr;
	AllocaInst* WPregs = nullptr;
	{
		unsigned AllocOrd[] = { 0, 1, 2, 3 };
		fyShuffle(AllocOrd, 4);
		for (unsigned idx : AllocOrd) {
			switch (idx) {
			case 0: WRegs = B.CreateAlloca(I32Ty, B.getInt64(NVRAlloc), "vm.regs");   break;
			case 1: WRegs64 = B.CreateAlloca(I64Ty, B.getInt64(NVR64Alloc), "vm.regs64"); break;
			case 2: WFregs = B.CreateAlloca(DoubleTy, B.getInt64(NFRAlloc), "vm.fregs");  break;
			case 3: WPregs = B.CreateAlloca(PtrTy, B.getInt64(NPRAlloc), "vm.pregs");  break;
			}
		}
	}

	// Zero-initialize register files (shuffled order when hardened)
	auto zeroFill = [&](AllocaInst* A, Type* ElemTy, unsigned Count) {
		if (Count == 0) return;
		for (unsigned i = 0; i < Count; ++i)
			B.CreateStore(Constant::getNullValue(ElemTy),
				B.CreateGEP(ElemTy, A, B.getInt64(i)));
		};


	{
		unsigned FillOrd[] = { 0, 1, 2, 3 };
		fyShuffle(FillOrd, 4);
		for (unsigned idx : FillOrd) {
			switch (idx) {
			case 0: zeroFill(WRegs, I32Ty, NVRAlloc);   break;
			case 1: zeroFill(WRegs64, I64Ty, NVR64Alloc); break;
			case 2: zeroFill(WFregs, DoubleTy, NFRAlloc);   break;
			case 3: zeroFill(WPregs, PtrTy, NPRAlloc);   break;
			}
		}
	}


	// allocate + fill per-slot XOR key arrays ————————————————
	// Keys are compile-time constants from RegKeys[]/Reg64Keys[]/FRegKeys[].
	// Engine handlers will XOR with these keys on every register read/write.
	AllocaInst* WRegKeys = nullptr;
	AllocaInst* WReg64Keys = nullptr;
	AllocaInst* WFRegKeys = nullptr;
	const bool DoRegEncrypt = RegEncrypt && !RegKeys.empty();

	if (DoRegEncrypt) {
		WRegKeys = B.CreateAlloca(I32Ty, B.getInt64(NVRAlloc), "vm.regkeys");
		WReg64Keys = B.CreateAlloca(I64Ty, B.getInt64(NVR64Alloc), "vm.reg64keys");
		WFRegKeys = B.CreateAlloca(I64Ty, B.getInt64(NFRAlloc), "vm.fregkeys");
		for (unsigned i = 0; i < NVRAlloc; ++i)
			B.CreateStore(blindI32(RegKeys[i]),
				B.CreateGEP(I32Ty, WRegKeys, B.getInt64(i)));
		for (unsigned i = 0; i < NVR64Alloc; ++i)
			B.CreateStore(blindI64(Reg64Keys[i]),
				B.CreateGEP(I64Ty, WReg64Keys, B.getInt64(i)));
		for (unsigned i = 0; i < NFRAlloc; ++i)
			B.CreateStore(blindI64(FRegKeys[i]),
				B.CreateGEP(I64Ty, WFRegKeys, B.getInt64(i)));
	}


	// pre-load in shuffled category order (hardened) 
	// 8 independent load categories: each writes to distinct register
	// file slots, so execution order is arbitrary.  Shuffling breaks
	// structural pattern matching between different wrapper functions.

	auto emitIntArgs = [&]() {
		for (Argument& A : F.args()) {
			Type* AT = A.getType();
			if (!AT->isIntegerTy()) continue;
			if (AT->isIntegerTy(64)) {
				Value* Idx = B.getInt32(E.VR64.lookup(&A));
				Value* V = &A;
				if (V->getType() != I64Ty) V = B.CreateZExtOrTrunc(V, I64Ty, "vm.w64");
				if (DoRegEncrypt) {
					uint8_t Slot = E.VR64.lookup(&A);
					V = B.CreateXor(V, blindI64(Reg64Keys[Slot]), "vm.w64.enc");
				}
				B.CreateStore(V, B.CreateGEP(I64Ty, WRegs64, Idx));
				continue;
			}
			Value* Idx = B.getInt32(E.VR.lookup(&A));
			Value* V = (AT == I32Ty) ? (Value*)&A : B.CreateZExt(&A, I32Ty, "vm.wax");






			if (DoRegEncrypt) {
				uint8_t Slot = E.VR.lookup(&A);
				V = B.CreateXor(V, blindI32(RegKeys[Slot]), "vm.wax.enc");
			}
			B.CreateStore(V, B.CreateGEP(I32Ty, WRegs, Idx));
			continue;
		}


		};
	auto emitPtrArgs = [&]() {
		for (Argument& A : F.args()) {
			if (!A.getType()->isPointerTy()) continue;
			Value* Idx = B.getInt32(E.PR.lookup(&A));
			B.CreateStore(&A, B.CreateGEP(PtrTy, WPregs, Idx));
		}







		};
	auto emitAllocaArgs = [&]() {
		for (unsigned I = 0, N = (unsigned)E.PHIAllocas.size(); I != N; ++I) {
			Value* Idx = B.getInt32(E.PHIAllocas[I].Slot);
			B.CreateStore(Reallocas[I], B.CreateGEP(PtrTy, WPregs, Idx));




		}


		};
	auto emitIntConsts = [&]() {
		for (auto& [S, CI] : E.ImmLoads) {
			Value* V = (CI->getType() == I32Ty)
				? (Value*)CI
				: B.CreateZExt(CI, I32Ty, "vm.wcx");
			if (DoRegEncrypt) {
				if (auto* CIV = dyn_cast<ConstantInt>(V))
					V = blindI32((uint32_t)(CIV->getZExtValue() ^ RegKeys[S]));
				else
					V = B.CreateXor(V, blindI32(RegKeys[S]), "vm.wcx.enc");
			}
			B.CreateStore(V, B.CreateGEP(I32Ty, WRegs, B.getInt32(S)));


		}



		};
	auto emitI64Consts = [&]() {
		for (auto& [S, CI] : E.ImmLoads64) {
			Value* V = (CI->getType() == I64Ty)
				? (Value*)CI
				: B.CreateZExtOrTrunc(CI, I64Ty, "vm.wc64x");
			if (DoRegEncrypt) {
				if (auto* CIV = dyn_cast<ConstantInt>(V))
					V = blindI64(CIV->getZExtValue() ^ Reg64Keys[S]);
				else
					V = B.CreateXor(V, blindI64(Reg64Keys[S]), "vm.wc64x.enc");
			}
			B.CreateStore(V, B.CreateGEP(I64Ty, WRegs64, B.getInt32(S)));

		}



		};
	auto emitPtrConsts = [&]() {
		for (auto& [S, PV] : E.PtrLoads)
			B.CreateStore(cast<Constant>(PV), B.CreateGEP(PtrTy, WPregs, B.getInt32(S)));
		};
	auto emitFloatArgs = [&]() {
		for (Argument& A : F.args()) {
			Type* AT = A.getType();
			if (!AT->isFloatTy() && !AT->isDoubleTy()) continue;
			uint8_t Slot = E.FR.lookup(&A);
			Value* V = AT->isDoubleTy() ? (Value*)&A
				: B.CreateFPExt(&A, DoubleTy, "vm.wfa");
			if (DoRegEncrypt) {
				Value* Bits = B.CreateBitCast(V, I64Ty, "vm.wfa.bits");
				Bits = B.CreateXor(Bits, blindI64(FRegKeys[Slot]), "vm.wfa.enc");
				V = B.CreateBitCast(Bits, DoubleTy, "vm.wfa.eval");
			}
			B.CreateStore(V, B.CreateGEP(DoubleTy, WFregs, B.getInt32(Slot)));
		}
		};
	auto emitFloatConsts = [&]() {
		for (auto& [Slot, CF] : E.ImmLoadsF)
		{
			double DV = CF->getType()->isDoubleTy()
				? CF->getValueAPF().convertToDouble()
				: (double)CF->getValueAPF().convertToFloat();
			if (DoRegEncrypt)
			{
				uint64_t RawBits;
				std::memcpy(&RawBits, &DV, sizeof(uint64_t));
				RawBits ^= FRegKeys[Slot];
				if (Blind) {
					Value* BlindBits = blindI64(RawBits);
					Value* FVal = B.CreateBitCast(BlindBits, DoubleTy, "vm.wcf.blind");
					B.CreateStore(FVal, B.CreateGEP(DoubleTy, WFregs, B.getInt32(Slot)));
				}
				else {
					double EncDV;
					std::memcpy(&EncDV, &RawBits, sizeof(double));
					B.CreateStore(ConstantFP::get(DoubleTy, APFloat(EncDV)),
						B.CreateGEP(DoubleTy, WFregs, B.getInt32(Slot)));
				}







			}
			else
			{
				B.CreateStore(ConstantFP::get(DoubleTy, DV),
					B.CreateGEP(DoubleTy, WFregs, B.getInt32(Slot)));
			}
		}
		};

	// Dispatch in shuffled order (8 categories, Fisher-Yates)
	{
		using LoadFn = std::function<void()>;
		LoadFn Cats[] = {
			emitIntArgs, emitPtrArgs, emitAllocaArgs, emitIntConsts,
			emitI64Consts, emitPtrConsts, emitFloatArgs, emitFloatConsts,
		};
		unsigned CatOrd[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
		fyShuffle(CatOrd, 8);
		for (unsigned idx : CatOrd) Cats[idx]();
	}


	// Call vm_engine (indirect via handler table)
	// the engine pointer is stored in GVHandlers[OP_COUNT].
	// We load it and make an indirect call.  This eliminates every direct
	// call-site xref from wrappers to @__vm_engine, breaking static
	// cross-reference analysis in IDA/Ghidra.

	// Bytecode base: use runtime copy if encryption is enabled
	Value* BCBase = (EncBytecode && GVBytecodeRT) ? (Value*)GVBytecodeRT : (Value*)GVBytecode;

	Value* Args[VMEngine::kNumParams] = {
		BCBase,                                                          // bc
		blindI32((uint32_t)E.BC.size()),                                 // bc_len
		WRegs,                                                           // regs
		WRegs64,                                                         // regs64
		WFregs,                                                          // fregs
		WPregs,                                                          // pregs
		GVCallees ? (Value*)GVCallees                                    // callees
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		blindI32(SaltConst),                                             // salt
		blindI32(NVRAlloc > 0 ? NVRAlloc - 1 : 0),                       // regMask
		blindI32(NVR64Alloc > 0 ? NVR64Alloc - 1 : 0),                   // reg64Mask
		blindI32(NFRAlloc > 0 ? NFRAlloc - 1 : 0),                       // fregMask
		blindI32(NPRAlloc > 0 ? NPRAlloc - 1 : 0),                       // pregMask
		GVHandlers,                                                      // handlers
		GVFTyIndices ? (Value*)GVFTyIndices                              // fty_indices
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		// per-slot XOR key arrays for register encryption
		DoRegEncrypt ? (Value*)WRegKeys                                  // regkeys
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		DoRegEncrypt ? (Value*)WReg64Keys                                // reg64keys
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		DoRegEncrypt ? (Value*)WFRegKeys                                 // fregkeys
			: ConstantPointerNull::get(cast<PointerType>(PtrTy)),
		// per-function callee XOR mask (0 when unhardened)
		VCtx.Cfg.hardened ? blindI64(CalleeMask) : B.getInt64(0),       // callee_mask
	};

	// Load engine function pointer from handler table slot [OP_COUNT]
	Value* EngSlot = B.CreateGEP(PtrTy, GVHandlers,
		blindI32(OP_COUNT), "vm.eng.slot");
	Value* EngPtr = B.CreateLoad(PtrTy, EngSlot, "vm.eng.ptr");

	FunctionType* EngFTy = VMEngine::getVMEngineFunctionType(Ctx);
	B.CreateCall(EngFTy, EngPtr, Args);

	// Extract return value and return
	Type* RT = F.getReturnType();
	if (RT->isVoidTy()) {
		B.CreateRetVoid();
	}
	else if (WrapRetSlot >= 0) {
		Value* SlotIdx = B.getInt32(WrapRetSlot);
		switch (WrapRetKind) {
		case VMEngine::RK2_I32: {
			Value* V = B.CreateLoad(I32Ty, B.CreateGEP(I32Ty, WRegs, SlotIdx), "vm.ret.v");
			if (DoRegEncrypt)
				V = B.CreateXor(V, blindI32(RegKeys[WrapRetSlot]), "vm.ret.dec");
			if (RT != I32Ty && RT->isIntegerTy())
				V = B.CreateTrunc(V, RT, "vm.ret.tr");
			B.CreateRet(V);
			break;
		}
		case VMEngine::RK2_I64: {
			Value* V = B.CreateLoad(I64Ty, B.CreateGEP(I64Ty, WRegs64, SlotIdx), "vm.ret.v64");
			if (DoRegEncrypt)
				V = B.CreateXor(V, blindI64(Reg64Keys[WrapRetSlot]), "vm.ret.dec64");
			B.CreateRet(V);
			break;
		}
		case VMEngine::RK2_PTR: {
			Value* V = B.CreateLoad(PtrTy, B.CreateGEP(PtrTy, WPregs, SlotIdx), "vm.ret.vp");
			B.CreateRet(V);
			break;
		}
		case VMEngine::RK2_F64: {
			Value* V = B.CreateLoad(DoubleTy, B.CreateGEP(DoubleTy, WFregs, SlotIdx), "vm.ret.vf");
			if (DoRegEncrypt) {
				Value* Bits = B.CreateBitCast(V, I64Ty, "vm.ret.fbits");
				Bits = B.CreateXor(Bits, blindI64(FRegKeys[WrapRetSlot]), "vm.ret.fdec");
				V = B.CreateBitCast(Bits, DoubleTy, "vm.ret.fval");
			}
			if (RT->isFloatTy())
				V = B.CreateFPTrunc(V, RT, "vm.ret.ftr");
			B.CreateRet(V);
			break;
		}
		default:
			B.CreateUnreachable();
			break;
		}
	}
	else {
		// RetSlot unknown — should not happen for non-void functions
		B.CreateUnreachable();
	}

	LLVM_DEBUG(dbgs() << "[vm] built thin wrapper for '" << F.getName()
		<< "' [retKind=" << (int)WrapRetKind
		<< " retSlot=" << WrapRetSlot
		<< " engMask=0x" << Twine::utohexstr(EngineMask) << "]\n");
}

// wrapper phase-splitting + junk interleaving ─
// After buildWrapper() finishes, the wrapper function has a single basic
// block.  hardenWrapper() splits it into multiple phases connected by
// opaque-predicate-guarded branches and inserts dead blocks with junk
// arithmetic.  The decompiler sees a conditional CFG instead of a flat stub.
//
// Split strategy:
//   - allocas MUST stay in the entry block (mem2reg requirement)
//   - everything after the last alloca is split into 4-6 chunks
//   - each edge gets: if (hardTrue) goto RealPhase else goto JunkBlock
//   - 3-5 fully dead blocks with junk stores and opaque constants
//
// Gated by VCtx.Cfg.hardened — no-op when hardened=0.


//salt corruption primitive
// Emits IR to silently poison the salt value.  After this executes,
// every subsequent loadBC() returns garbage because the per-byte XOR
// key (salt ^ idx) is now wrong.  The program continues running but
// produces incorrect output — no crash, no signal.

void VMImpl::emitSaltCorruption(IRBuilder<>& B, Value* SaltPtr, uint32_t PoisonKey) {
	auto* Old = B.CreateLoad(I32Ty, SaltPtr, "vm.ad.salt");
	cast<LoadInst>(Old)->setVolatile(true);
	auto* Poisoned = B.CreateXor(Old, B.getInt32(PoisonKey), "vm.ad.poison");
	B.CreateStore(Poisoned, SaltPtr)->setVolatile(true);
}


// .init_array bytecode integrity hash 
// Builds a constructor that computes FNV-1a over the on-disk encrypted
// GVBytecode global and compares against an embedded compile-time hash.
// On mismatch (binary patching detected): GVBytecodeRT[0] ^= 0xFF,
// silently corrupting the first opcode dispatch.
//
// Runs with priority 65535 (same as the AES/LCG decrypt ctor) but is
// appended after it in run(), so LLVM emits it second — the decrypted
// GVBytecodeRT is already populated when the hash check corrupts [0].
//
// Gated by hardened=1 && antiDebug=1.

void VMImpl::buildIntegrityHashCtor() {
	if (!VCtx.Cfg.hardened || !VCtx.Cfg.antiDebug) return;
	if (!GVBytecode || E.BC.empty()) return;

	unsigned BCLen = (unsigned)E.BC.size();

	//  Compile-time: compute FNV-1a over GVBytecode's initializer 
	uint32_t ExpectedHash = 2166136261u;
	if (auto* Init = GVBytecode->getInitializer()) {
		if (auto* CDA = dyn_cast<ConstantDataArray>(Init)) {
			for (unsigned i = 0; i < CDA->getNumElements(); ++i)
				ExpectedHash = (ExpectedHash ^ (uint8_t)CDA->getElementAsInteger(i))
				* 16777619u;
		}
		else if (auto* CA = dyn_cast<ConstantArray>(Init)) {
			for (unsigned i = 0; i < CA->getNumOperands(); ++i) {
				if (auto* CI = dyn_cast<ConstantInt>(CA->getOperand(i)))
					ExpectedHash = (ExpectedHash ^ (uint8_t)CI->getZExtValue())
					* 16777619u;
			}
		}
	}

	//  Build the constructor function 
	std::string FnName = (F.getName() + ".vm.hash.ctor").str();
	auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	auto* Fn = Function::Create(FTy, GlobalValue::InternalLinkage, FnName, M);
	Fn->addFnAttr(Attribute::NoUnwind);

	BasicBlock* EntBB = BasicBlock::Create(Ctx, "vm.hash.entry", Fn);
	BasicBlock* LoopBB = BasicBlock::Create(Ctx, "vm.hash.loop", Fn);
	BasicBlock* BodyBB = BasicBlock::Create(Ctx, "vm.hash.body", Fn);
	BasicBlock* CheckBB = BasicBlock::Create(Ctx, "vm.hash.check", Fn);
	BasicBlock* FailBB = BasicBlock::Create(Ctx, "vm.hash.fail", Fn);
	BasicBlock* ExitBB = BasicBlock::Create(Ctx, "vm.hash.exit", Fn);

	// Entry: alloca hash accumulator + index, initialise
	AllocaInst* HashA;
	AllocaInst* IdxA;
	{
		IRBuilder<> B(EntBB);
		HashA = B.CreateAlloca(I32Ty, nullptr, "vm.hash.h");
		IdxA = B.CreateAlloca(I32Ty, nullptr, "vm.hash.i");
		B.CreateStore(B.getInt32(2166136261u), HashA);  // FNV offset basis
		B.CreateStore(B.getInt32(0), IdxA);
		B.CreateBr(LoopBB);
	}

	// Loop header: idx < BCLen ? body : check
	{
		IRBuilder<> B(LoopBB);
		Value* Idx = B.CreateLoad(I32Ty, IdxA, "vm.hash.idx");
		B.CreateCondBr(
			B.CreateICmpULT(Idx, B.getInt32(BCLen), "vm.hash.cmp"),
			BodyBB, CheckBB);
	}

	// Body: h = (h ^ byte) * 16777619
	{
		IRBuilder<> B(BodyBB);
		Value* Idx = B.CreateLoad(I32Ty, IdxA, "vm.hash.idx2");
		Value* H = B.CreateLoad(I32Ty, HashA, "vm.hash.hv");

		// Load byte from GVBytecode (const global, not the runtime copy)
		Value* Ptr = B.CreateGEP(I8Ty, GVBytecode,
			B.CreateSExt(Idx, I64Ty, "vm.hash.idx64"), "vm.hash.ptr");
		Value* Byte = B.CreateLoad(I8Ty, Ptr, "vm.hash.byte");
		Value* ByteW = B.CreateZExt(Byte, I32Ty, "vm.hash.bw");

		// FNV-1a h = (h ^ byte) * prime
		Value* HX = B.CreateXor(H, ByteW, "vm.hash.xor");
		Value* HM = B.CreateMul(HX, B.getInt32(16777619u), "vm.hash.mul");
		B.CreateStore(HM, HashA);

		// idx++
		B.CreateStore(B.CreateAdd(Idx, B.getInt32(1), "vm.hash.inc"), IdxA);
		B.CreateBr(LoopBB);
	}

	// Check: compare computed hash against expected
	{
		IRBuilder<> B(CheckBB);
		Value* H = B.CreateLoad(I32Ty, HashA, "vm.hash.final");
		Value* Match = B.CreateICmpEQ(H, B.getInt32(ExpectedHash), "vm.hash.ok");
		B.CreateCondBr(Match, ExitBB, FailBB);
	}

	// Fail: silently corrupt GVBytecodeRT[0] (or GVBytecode[0] if no RT)
	{
		IRBuilder<> B(FailBB);
		GlobalVariable* Target = GVBytecodeRT ? GVBytecodeRT : GVBytecode;
		Value* Ptr = B.CreateGEP(I8Ty, Target, B.getInt64(0), "vm.hash.tgt");
		Value* Old = B.CreateLoad(I8Ty, Ptr, "vm.hash.old");
		Value* Corrupted = B.CreateXor(Old, B.getInt8((uint8_t)0xFF), "vm.hash.bad");
		B.CreateStore(Corrupted, Ptr);
		B.CreateBr(ExitBB);
	}

	// Exit
	IRBuilder<>(ExitBB).CreateRetVoid();

	// Register as .init_array constructor (same priority as decrypt ctor)
	appendToGlobalCtors(M, Fn, 65535, nullptr);

	LLVM_DEBUG(dbgs() << "[vm] integrity hash ctor for '"
		<< F.getName() << "' [hash=0x"
		<< Twine::utohexstr(ExpectedHash) << " len=" << BCLen << "]\n");
}


// .init_array callee XOR masking constructor ─
// Builds a constructor that XOR-masks each entry in GVCallees with
// CalleeMask.  Runs at startup AFTER the linker resolves relocations
// (raw function addresses are in memory) but BEFORE main().
//
// After this ctor: GVCallees[i] = inttoptr(ptrtoint(original) ^ mask)
// The CALL handler  reverses this with the same XOR.
//
// For small callee counts (typical: 1-10), the loop is fully unrolled.
// Gated by hardened=1 and non-empty callee table.

void VMImpl::buildCalleeXorCtor() {
	if (!VCtx.Cfg.hardened || !GVCallees || E.CalleeTab.empty()) return;
	if (CalleeMask == 0) return;

	unsigned NCallees = (unsigned)E.CalleeTab.size();

	std::string FnName = (F.getName() + ".vm.callee.ctor").str();
	auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	auto* Fn = Function::Create(FTy, GlobalValue::InternalLinkage, FnName, M);
	Fn->addFnAttr(Attribute::NoUnwind);

	auto* BB = BasicBlock::Create(Ctx, "vm.cm.entry", Fn);
	IRBuilder<> B(BB);

	// Unrolled: for each slot, load → ptrtoint → xor → inttoptr → store
	for (unsigned i = 0; i < NCallees; ++i) {
		Value* SlotPtr = B.CreateGEP(PtrTy, GVCallees,
			B.getInt64(i), "vm.cm.slot" + Twine(i));
		Value* Raw = B.CreateLoad(PtrTy, SlotPtr, "vm.cm.raw" + Twine(i));
		Value* RawInt = B.CreatePtrToInt(Raw, I64Ty, "vm.cm.ri" + Twine(i));
		Value* Masked = B.CreateXor(RawInt,
			B.getInt64(CalleeMask), "vm.cm.xor" + Twine(i));
		Value* MaskedPtr = B.CreateIntToPtr(Masked, PtrTy, "vm.cm.mp" + Twine(i));
		B.CreateStore(MaskedPtr, SlotPtr);
	}

	B.CreateRetVoid();
	appendToGlobalCtors(M, Fn, 65535, nullptr);

	LLVM_DEBUG(dbgs() << "[vm] callee XOR ctor for '"
		<< F.getName() << "' [" << NCallees << " entries, mask=0x"
		<< Twine::utohexstr(CalleeMask) << "]\n");
}


// vm.dispatch anti-debug timing + debugger-API gate 
// Inserts a counter-gated check between vm.dispatch and vm.fetch inside
// the shared __vm_engine.  Every 64 fetch iterations the gate fires and:
//   (a) reads the cycle counter twice with a small computation between,
//       if delta > threshold → salt corruption (catches single-stepping)
//   (b) on Windows, calls IsDebuggerPresent() → salt corruption
//
// On detection: emitSaltCorruption() XORs the salt, making all subsequent
// bytecode decryptions produce garbage.  Execution continues — no crash.
//
// When no debugger is attached, the counter check is a single AND+CMP
// that the branch predictor learns is almost-always-false (~1 cycle).

void VMImpl::buildAntiDebugGate(VMEngine::SharedState* SS) {
	if (!VCtx.Cfg.hardened || !VCtx.Cfg.antiDebug) return;
	if (!SS || !SS->EngineFn || !SS->Dispatch || !SS->EngineSalt) return;

	Function* EF = SS->EngineFn;

	//  Find FetchBB: it's the false-successor of vm.dispatch ─
	auto* DispTerm = dyn_cast<BranchInst>(SS->Dispatch->getTerminator());
	if (!DispTerm || !DispTerm->isConditional()) return;
	BasicBlock* FetchBB = DispTerm->getSuccessor(1); // false = !OOB = fetch

	//  Create counter alloca in vm.entry (before its terminator) ─
	IRBuilder<> EntB(SS->Entry->getTerminator());
	AllocaInst* CtrA = EntB.CreateAlloca(I32Ty, nullptr, "vm.ad.ctr");
	EntB.CreateStore(EntB.getInt32(0), CtrA)->setVolatile(true);

	//  Create new basic blocks 
	BasicBlock* CountBB = BasicBlock::Create(Ctx, "vm.ad.count", EF);
	BasicBlock* GateBB = BasicBlock::Create(Ctx, "vm.ad.gate", EF);
	BasicBlock* CorruptBB = BasicBlock::Create(Ctx, "vm.ad.corrupt", EF);

	//  Redirect Dispatch → FetchBB  to  Dispatch → CountBB 
	DispTerm->setSuccessor(1, CountBB);

	//  vm.ad.count: increment counter, check every N iterations ─
	{
		IRBuilder<> B(CountBB);
		auto* Ctr = B.CreateLoad(I32Ty, CtrA, "vm.ad.c");
		cast<LoadInst>(Ctr)->setVolatile(true);
		auto* NCtr = B.CreateAdd(Ctr, B.getInt32(1), "vm.ad.cn");
		B.CreateStore(NCtr, CtrA)->setVolatile(true);
		// interval from config (rounded to power-of-2 for AND mask)
		unsigned Interval = VCtx.Cfg.adDispatchInterval;
		if (Interval == 0) Interval = 64;
		unsigned Mask = 1;
		while (Mask < Interval) Mask <<= 1;
		Mask -= 1; // e.g. 64 → 63
		auto* Masked = B.CreateAnd(NCtr, B.getInt32(Mask), "vm.ad.mask");
		auto* DoCheck = B.CreateICmpEQ(Masked, B.getInt32(0), "vm.ad.fire");
		B.CreateCondBr(DoCheck, GateBB, FetchBB);
	}

	//  vm.ad.gate: platform-specific detection ─
	{
		IRBuilder<> B(GateBB);
		Value* Detected = ConstantInt::getFalse(Ctx);


		// CI safety — skip detection if __OBF_DISABLE_ANTIDEBUG is set
		{
			FunctionCallee GetEnv = M.getOrInsertFunction("getenv",
				FunctionType::get(PtrTy, { PtrTy }, false));
			Value* EnvName = B.CreateGlobalStringPtr(
				"__OBF_DISABLE_ANTIDEBUG", "vm.ad.envname");
			Value* EnvVal = B.CreateCall(GetEnv, { EnvName }, "vm.ad.env");
			Value* EnvSet = B.CreateICmpNE(EnvVal,
				ConstantPointerNull::get(cast<PointerType>(PtrTy)), "vm.ad.envset");
			// If env var is set, jump straight to FetchBB (skip all checks)
			BasicBlock* RealGateBB = BasicBlock::Create(Ctx, "vm.ad.gate.real", EF);
			B.CreateCondBr(EnvSet, FetchBB, RealGateBB);
			B.SetInsertPoint(RealGateBB);
			Detected = ConstantInt::getFalse(Ctx);
		}

		//  Timing gate: readcyclecounter (x86_64 + AArch64) 
		bool HasCycleCounter = TI.IsX86_64 || TI.IsAArch64;
		if (HasCycleCounter) {
			Function* RCC = Intrinsic::getDeclaration(&M, Intrinsic::readcyclecounter);
			auto* T1 = B.CreateCall(RCC, {}, "vm.ad.t1");

			// Small computation between reads (prevents the two reads from
			// being coalesced and gives a realistic baseline delta)
			auto* Dummy = B.CreateLoad(I32Ty, CtrA, "vm.ad.dummy");
			cast<LoadInst>(Dummy)->setVolatile(true);
			auto* Sink = B.CreateAdd(Dummy, B.getInt32(1), "vm.ad.sink");
			B.CreateStore(Sink, CtrA)->setVolatile(true);

			auto* T2 = B.CreateCall(RCC, {}, "vm.ad.t2");
			auto* Delta = B.CreateSub(T2, T1, "vm.ad.delta");
			// threshold from config
			auto* Slow = B.CreateICmpUGT(Delta,
				B.getInt64((uint64_t)VCtx.Cfg.adDispatchThreshold), "vm.ad.slow");
			Detected = B.CreateOr(Detected, Slow, "vm.ad.det.time");
		}

		//  Windows: IsDebuggerPresent() 
		if (TI.IsWindows) {
			auto* IDPTy = FunctionType::get(I32Ty, false);
			FunctionCallee IDP = M.getOrInsertFunction("IsDebuggerPresent", IDPTy);
			if (auto* IDPFn = dyn_cast<Function>(IDP.getCallee()))
				IDPFn->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
			auto* Dbg = B.CreateCall(IDP, {}, "vm.ad.idb");
			auto* IsDbg = B.CreateICmpNE(Dbg, B.getInt32(0), "vm.ad.win");
			Detected = B.CreateOr(Detected, IsDbg, "vm.ad.det.win");
		}

		B.CreateCondBr(Detected, CorruptBB, FetchBB);
	}

	//  vm.ad.corrupt: silently poison salt, then continue 
	{
		IRBuilder<> B(CorruptBB);
		emitSaltCorruption(B, SS->EngineSalt, ADPoisonKey);
		B.CreateBr(FetchBB);
	}

	LLVM_DEBUG(dbgs() << "[vm] anti-debug gate in vm_engine"
		<< " [timing=" << (TI.IsX86_64 || TI.IsAArch64)
		<< " winAPI=" << TI.IsWindows << "]\n");
}




void VMImpl::hardenWrapper() {
	if (!VCtx.Cfg.hardened) return;

	auto HRng = VCtx.R.fork("vm.wrap.split");
	llvm::obf::OpaqueUtils HOpaque(M, HRng, "vm.wrap.split.i32");
	BasicBlock* EntryBB = &F.getEntryBlock();
	if (!EntryBB || EntryBB->empty()) return;

	// Find the last alloca — everything before it stays in entry
	Instruction* LastAlloca = nullptr;
	for (auto& I : *EntryBB)
		if (isa<AllocaInst>(&I)) LastAlloca = &I;
	if (!LastAlloca) return;

	// Collect split-candidate instructions (after last alloca, pre-terminator)
	SmallVector<Instruction*, 128> Candidates;
	bool Past = false;
	for (auto& I : *EntryBB) {
		if (&I == LastAlloca) { Past = true; continue; }
		if (Past && !I.isTerminator())
			Candidates.push_back(&I);
	}
	if (Candidates.size() < 8) return; // too few instructions to split

	// Choose 3-5 evenly-spaced split points 
	unsigned NSplits = 3 + HRng.range(3); // 3..5
	if (NSplits >= Candidates.size()) NSplits = 2;
	unsigned ChunkSize = (unsigned)Candidates.size() / (NSplits + 1);
	if (ChunkSize < 2) ChunkSize = 2;

	SmallVector<Instruction*, 8> SplitPoints;
	for (unsigned i = 1; i <= NSplits; ++i) {
		unsigned Idx = i * ChunkSize;
		if (Idx < Candidates.size())
			SplitPoints.push_back(Candidates[Idx]);
	}
	if (SplitPoints.empty()) return;

	// Always split right after the last alloca (Phase 0 = allocas) 
	Instruction* FirstPostAlloca = LastAlloca->getNextNode();
	if (FirstPostAlloca && !FirstPostAlloca->isTerminator()) {
		// Insert at front only if not already present
		if (SplitPoints.empty() || SplitPoints.front() != FirstPostAlloca)
			SplitPoints.insert(SplitPoints.begin(), FirstPostAlloca);
	}

	// Split in reverse order to preserve instruction pointers 
	SmallVector<BasicBlock*, 8> PhaseBBs;
	for (int i = (int)SplitPoints.size() - 1; i >= 0; --i) {
		BasicBlock* NewBB = EntryBB->splitBasicBlock(
			SplitPoints[i], "vm.w.p" + Twine(i));
		PhaseBBs.push_back(NewBB);
	}
	std::reverse(PhaseBBs.begin(), PhaseBBs.end());
	// Now: EntryBB(allocas) → PhaseBBs[0] → PhaseBBs[1] → ... → PhaseBBs[N-1](ret)
	// Each edge is an unconditional branch inserted by splitBasicBlock.

	// Create dead blocks with junk arithmetic 
	unsigned NDeadBlocks = 3 + HRng.range(3); // 3..5
	SmallVector<BasicBlock*, 8> DeadBBs;
	for (unsigned i = 0; i < NDeadBlocks; ++i) {
		auto* DBB = BasicBlock::Create(Ctx, "vm.w.dead." + Twine(i), &F);
		IRBuilder<> DB(DBB);

		// Junk: opaque constants + arithmetic (2-4 operations)
		Value* J1 = HOpaque.opaqueI32Const(DB, HRng.u32());
		Value* J2 = HOpaque.opaqueI32Const(DB, HRng.u32());
		Value* R1 = DB.CreateXor(J1, J2, "vm.w.d.xor");
		Value* R2 = DB.CreateMul(R1, J1, "vm.w.d.mul");
		Value* R3 = DB.CreateAdd(R2, J2, "vm.w.d.add");
		(void)R3;

		// Branch to a random phase block (makes CFG look connected)
		unsigned Tgt = HRng.range((unsigned)PhaseBBs.size());
		DB.CreateBr(PhaseBBs[Tgt]);
		DeadBBs.push_back(DBB);
	}

	//  Replace unconditional branches with opaque-predicate branches 
	auto replaceEdge = [&](BasicBlock* From) {
		auto* Term = From->getTerminator();
		if (!Term || !isa<BranchInst>(Term)) return;
		auto* BI = cast<BranchInst>(Term);
		if (!BI->isUnconditional()) return;

		BasicBlock* RealSucc = BI->getSuccessor(0);
		BasicBlock* FakeDst = DeadBBs[HRng.range((unsigned)DeadBBs.size())];

		IRBuilder<> OB(Term);
		Value* Cond = HOpaque.hardTrue(OB);
		OB.CreateCondBr(Cond, RealSucc, FakeDst);
		Term->eraseFromParent();
		};

	// Entry → PhaseBBs[0]
	replaceEdge(EntryBB);
	// PhaseBBs[i] → PhaseBBs[i+1]  (last phase has the ret, no branch to replace)
	for (unsigned i = 0; i + 1 < PhaseBBs.size(); ++i)
		replaceEdge(PhaseBBs[i]);

	LLVM_DEBUG(dbgs() << "[vm] hardened wrapper for '"
		<< F.getName() << "' [phases=" << (PhaseBBs.size() + 1)
		<< " dead=" << NDeadBlocks << "]\n");
}


// switch-dispatch flattening of the wrapper ─
// Converts the multi-block wrapper CFG (produced by hardenWrapper) into
// a while-true / switch(state) dispatcher.  Each original basic block
// becomes a switch case.  Inter-block branches are replaced with
// state-variable assignments that jump back to the dispatcher.
//
// State encoding: each block gets a random i32 tag.  Transitions store
// the XOR delta between the current and next tag, so the decompiler
// sees: state ^= <opaque_delta>;  This prevents trivial state recovery.
//
// Blocks that terminate with ret/unreachable are left as function exits.
// Gated by VCtx.Cfg.hardened — no-op when hardened=0.

void VMImpl::flattenWrapper() {
	if (!VCtx.Cfg.hardened) return;

	auto FRng = VCtx.R.fork("vm.wrap.flat");
	llvm::obf::OpaqueUtils FOpaque(M, FRng, "vm.wrap.flat.i32");

	BasicBlock* EntryBB = &F.getEntryBlock();

	// Collect all non-entry blocks that should become switch cases.
	SmallVector<BasicBlock*, 16> Blocks;
	for (BasicBlock& BB : F) {
		if (&BB == EntryBB) continue;
		Blocks.push_back(&BB);
	}
	if (Blocks.size() < 3) return; // too few blocks to flatten

	// Assign random state tags to each block.
	DenseMap<BasicBlock*, uint32_t> StateMap;
	for (auto* BB : Blocks) {
		uint32_t Tag;
		do { Tag = FRng.u32(); } while (Tag == 0); // avoid 0 (used as init)
		StateMap[BB] = Tag;
	}

	//  Create state variable in entry block 
	// Insert alloca before the entry block's terminator.
	IRBuilder<> EntryB(EntryBB->getTerminator());
	AllocaInst* StateVar = EntryB.CreateAlloca(I32Ty, nullptr, "vm.w.flat.st");

	// Initial state = tag of the first successor of entry.
	BasicBlock* FirstSucc = nullptr;
	if (auto* BI = dyn_cast<BranchInst>(EntryBB->getTerminator())) {
		FirstSucc = BI->getSuccessor(0);
	}
	if (!FirstSucc || !StateMap.count(FirstSucc)) return;
	uint32_t InitState = StateMap[FirstSucc];
	EntryB.CreateStore(FOpaque.opaqueI32Const(EntryB, InitState), StateVar);

	//  Create dispatcher block 
	BasicBlock* DispBB = BasicBlock::Create(Ctx, "vm.w.flat.disp", &F);
	IRBuilder<> DB(DispBB);
	LoadInst* StateLoad = DB.CreateLoad(I32Ty, StateVar, "vm.w.flat.ld");
	StateLoad->setVolatile(true);

	// Default case goes to the first block (fallback).
	SwitchInst* SW = DB.CreateSwitch(StateLoad, Blocks[0], (unsigned)Blocks.size());
	for (auto* BB : Blocks) {
		SW->addCase(ConstantInt::get(cast<IntegerType>(I32Ty), StateMap[BB]), BB);
	}

	//  Redirect entry block terminator to dispatcher ─
	EntryBB->getTerminator()->eraseFromParent();
	IRBuilder<> EB(EntryBB);
	EB.CreateBr(DispBB);

	//  Rewrite terminators of flattened blocks ─
	// Replace branches with: state ^= delta; br dispatcher
	for (auto* BB : Blocks) {
		auto* Term = BB->getTerminator();
		if (!Term) continue;

		// ret / unreachable — leave as function exit
		if (isa<ReturnInst>(Term) || isa<UnreachableInst>(Term))
			continue;

		if (auto* BI = dyn_cast<BranchInst>(Term)) {
			IRBuilder<> TB(Term);
			uint32_t CurTag = StateMap[BB];

			if (BI->isUnconditional()) {
				BasicBlock* Succ = BI->getSuccessor(0);
				if (StateMap.count(Succ)) {
					uint32_t NextTag = StateMap[Succ];
					uint32_t Delta = CurTag ^ NextTag;
					Value* Old = TB.CreateLoad(I32Ty, StateVar, "vm.w.flat.old");
					cast<LoadInst>(Old)->setVolatile(true);
					Value* New = TB.CreateXor(Old,
						FOpaque.opaqueI32Const(TB, Delta), "vm.w.flat.xor");
					TB.CreateStore(New, StateVar)->setVolatile(true);
					TB.CreateBr(DispBB);
					Term->eraseFromParent();
				}
			}
			else {
				// Conditional branch (opaque predicates from 06b.3)
				BasicBlock* TSucc = BI->getSuccessor(0);
				BasicBlock* FSucc = BI->getSuccessor(1);
				Value* Cond = BI->getCondition();

				if (StateMap.count(TSucc) && StateMap.count(FSucc)) {
					uint32_t TDelta = CurTag ^ StateMap[TSucc];
					uint32_t FDelta = CurTag ^ StateMap[FSucc];
					Value* SelDelta = TB.CreateSelect(Cond,
						FOpaque.opaqueI32Const(TB, TDelta),
						FOpaque.opaqueI32Const(TB, FDelta), "vm.w.flat.sel");
					Value* Old = TB.CreateLoad(I32Ty, StateVar, "vm.w.flat.old");
					cast<LoadInst>(Old)->setVolatile(true);
					Value* New = TB.CreateXor(Old, SelDelta, "vm.w.flat.xor");
					TB.CreateStore(New, StateVar)->setVolatile(true);
					TB.CreateBr(DispBB);
					Term->eraseFromParent();
				}
			}
		}
	}

	LLVM_DEBUG(dbgs() << "[vm] flattened wrapper for '"
		<< F.getName() << "' [blocks=" << Blocks.size()
		<< " states=" << StateMap.size() << "]\n");
}


// MBA substitutions on wrapper arithmetic ─
// After buildWrapper + hardenWrapper, the wrapper contains XOR, ADD, OR
// etc. for argument encryption, return decryption, opaque predicates,
// and junk arithmetic.  This pass replaces every eligible integer
// BinaryOperator with an MBA equivalent, making the decompiler output
// a multi-node expression tree for each operation.
//
// Operates on all basic blocks of the wrapper function (including the
// phase blocks and dead blocks created by hardenWrapper).
// Gated by VCtx.Cfg.hardened — no-op when hardened=0.

void VMImpl::mbaHardenWrapper() {
	if (!VCtx.Cfg.hardened) return;

	auto MRng = VCtx.R.fork("vm.wrap.mba");
	llvm::obf::MbaUtils    WMBA(M, MRng, "vm.wrap.mba.noise.i32");
	llvm::obf::OpaqueUtils WOpq(M, MRng, "vm.wrap.mba.salt.i32");

	// Collect candidates (can't modify while iterating).
	SmallVector<BinaryOperator*, 64> Candidates;
	for (BasicBlock& BB : F) {
		for (Instruction& I : BB) {
			auto* BO = dyn_cast<BinaryOperator>(&I);
			if (!BO || !BO->getType()->isIntegerTy()) continue;
			if (!llvm::obf::MbaUtils::isTargetOpcode(BO->getOpcode())) continue;
			Candidates.push_back(BO);
		}
	}

	unsigned Sites = 0;
	for (BinaryOperator* BO : Candidates) {
		if (!BO->getParent()) continue; // erased by prior iteration

		IRBuilder<> B(BO);
		Value* A = BO->getOperand(0);
		Value* V = BO->getOperand(1);
		Value* Rep = nullptr;

		switch (BO->getOpcode()) {
		case Instruction::Add: {
			switch (MRng.range(3)) {
			case 0:  Rep = WMBA.addAlt(B, A, V);  break;
			case 1:  Rep = WMBA.add(B, A, V);     break;
			default: Rep = WMBA.addAlt2(B, A, V); break;
			}
			break;
		}
		case Instruction::Sub: Rep = WMBA.subAlt2(B, A, V); break;
		case Instruction::Xor: {
			Rep = (MRng.range(2) == 0)
				? WMBA.bitwiseXor(B, A, V)
				: WMBA.bitwiseXorAlt(B, A, V);
			break;
		}
		case Instruction::And: Rep = WMBA.bitwiseAndAlt(B, A, V); break;
		case Instruction::Or:  Rep = WMBA.bitwiseOrAlt2(B, A, V); break;
		default: break;
		}

		if (!Rep) continue;

		// ~25% chance: XOR result with opaque zero for extra noise.
		if (MRng.range(100) < 25) {
			Value* Zero = WOpq.opaqueZero32(B);
			Type* RT = Rep->getType();
			if (RT != Zero->getType()) {
				if (RT->getIntegerBitWidth() > 32)
					Zero = B.CreateZExt(Zero, RT, "vm.w.mba.z.ext");
				else
					Zero = B.CreateTrunc(Zero, RT, "vm.w.mba.z.tr");
			}
			Rep = B.CreateXor(Rep, Zero, "vm.w.mba.noise");
		}

		BO->replaceAllUsesWith(Rep);
		BO->eraseFromParent();
		++Sites;
	}

	LLVM_DEBUG(dbgs() << "[vm] MBA-hardened wrapper for '"
		<< F.getName() << "' [sites=" << Sites << "]\n");
}



bool VMImpl::run() {
	// Demote PHI nodes to memory
	SmallVector<PHINode*, 32> Phis;
	for (BasicBlock& BB : F)
		for (Instruction& I : BB)
			if (auto* PN = dyn_cast<PHINode>(&I)) Phis.push_back(PN);
	for (PHINode* PN : Phis) DemotePHIToStack(PN);






	//     Lower/strip intrinsics that clang emits at -O0 but the VM cannot
	//      encode.  Three tiers:
	//        A) Strip  — debug, lifetime, assume: zero runtime semantics.
	//        B) Memory — memcpy/memmove/memset with constant size ≤ 8:
	//                    replace with a single typed load+store or store.
	//        C) Float  — fabs, fmuladd, fma, minnum, maxnum, copysign:
	//                    expand to FNeg/FMul/FAdd/FCmp/Select the VM handles.
	//        D) Int    — abs: expand to ICmp/Sub/Select.
	//      Anything else stays and isize() will markUnsupported gracefully.
	{
		SmallVector<CallInst*, 32> Intrinsics;
		for (BasicBlock& BB : F)
			for (Instruction& I : BB)
				if (auto* CI = dyn_cast<CallInst>(&I))
					if (auto* CF = CI->getCalledFunction(); CF && CF->isIntrinsic())
						Intrinsics.push_back(CI);

		for (CallInst* CI : Intrinsics) {
			Intrinsic::ID IID = CI->getCalledFunction()->getIntrinsicID();
			IRBuilder<> B(CI);

			//  Tier A: strip ─
			switch (IID) {
			case Intrinsic::lifetime_start:
			case Intrinsic::lifetime_end:
			case Intrinsic::dbg_declare:
			case Intrinsic::dbg_value:
			case Intrinsic::dbg_assign:
			case Intrinsic::assume:
				CI->eraseFromParent();
				continue;
			default: break;
			}

			//  Tier B: memcpy / memmove 
			if (IID == Intrinsic::memcpy || IID == Intrinsic::memmove) {
				if (auto* SzC = dyn_cast<ConstantInt>(CI->getArgOperand(2))) {
					Type* ElemTy = nullptr;
					switch (SzC->getZExtValue()) {
					case 1: ElemTy = I8Ty;  break;
					case 2: ElemTy = I16Ty; break;
					case 4: ElemTy = I32Ty; break;
					case 8: ElemTy = I64Ty; break;
					default: break;
					}
					if (ElemTy) {
						B.CreateStore(B.CreateLoad(ElemTy, CI->getArgOperand(1), "mc.ld"),
							CI->getArgOperand(0));
						CI->eraseFromParent();
						continue;
					}
				}
				continue; // non-constant / odd size → markUnsupported later
			}

			//  Tier B: memset ─
			if (IID == Intrinsic::memset) {
				auto* SzC = dyn_cast<ConstantInt>(CI->getArgOperand(2));
				auto* ValC = dyn_cast<ConstantInt>(CI->getArgOperand(1));
				if (SzC && ValC && SzC->getZExtValue() <= 8) {
					uint64_t Sz = SzC->getZExtValue();
					uint8_t  Val = (uint8_t)ValC->getZExtValue();
					uint64_t Fill = 0;
					for (uint64_t i = 0; i < Sz; ++i) Fill |= ((uint64_t)Val << (i * 8));
					Type* ElemTy = IntegerType::get(Ctx, (unsigned)(Sz * 8));
					B.CreateStore(ConstantInt::get(ElemTy, Fill), CI->getArgOperand(0));
					CI->eraseFromParent();
					continue;
				}
				continue;
			}

			//  Tier C: fabs(x) → x >= 0.0 ? x : -x 
			if (IID == Intrinsic::fabs) {
				Value* X = CI->getArgOperand(0);
				Type* FT = X->getType();
				Value* Neg = B.CreateFNeg(X, "fabs.neg");
				Value* Cmp = B.CreateFCmpOGE(X, ConstantFP::get(FT, 0.0), "fabs.cmp");
				Value* R = B.CreateSelect(Cmp, X, Neg, "fabs.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			//  Tier C: fmuladd / fma → a*b + c ─
			if (IID == Intrinsic::fmuladd || IID == Intrinsic::fma) {
				Value* A = CI->getArgOperand(0);
				Value* Bv = CI->getArgOperand(1);
				Value* C = CI->getArgOperand(2);
				Value* R = B.CreateFAdd(B.CreateFMul(A, Bv, "fma.mul"), C, "fma.add");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			//  Tier C: minnum / maxnum 
			if (IID == Intrinsic::minnum) {
				Value* A = CI->getArgOperand(0), * Bv = CI->getArgOperand(1);
				Value* R = B.CreateSelect(B.CreateFCmpOLT(A, Bv, "min.cmp"), A, Bv, "min.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}
			if (IID == Intrinsic::maxnum) {
				Value* A = CI->getArgOperand(0), * Bv = CI->getArgOperand(1);
				Value* R = B.CreateSelect(B.CreateFCmpOGT(A, Bv, "max.cmp"), A, Bv, "max.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			//  Tier C: copysign(mag, sgn)
			if (IID == Intrinsic::copysign) {
				Value* Mag = CI->getArgOperand(0);
				Value* Sgn = CI->getArgOperand(1);
				Type* FT = Mag->getType();
				Value* Zero = ConstantFP::get(FT, 0.0);
				Value* NegM = B.CreateFNeg(Mag, "cs.nm");
				Value* AbsM = B.CreateSelect(B.CreateFCmpOGE(Mag, Zero, "cs.ac"), Mag, NegM, "cs.am");
				Value* R = B.CreateSelect(B.CreateFCmpOGE(Sgn, Zero, "cs.sc"),
					AbsM, B.CreateFNeg(AbsM, "cs.na"), "cs.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			//  Tier D: abs(x, _) → x < 0 ? -x : x ─
			if (IID == Intrinsic::abs) {
				Value* X = CI->getArgOperand(0);
				Type* IT = X->getType();
				Value* Zero = ConstantInt::get(IT, 0);
				Value* Neg = B.CreateSub(Zero, X, "abs.neg");
				Value* R = B.CreateSelect(B.CreateICmpSLT(X, Zero, "abs.cmp"), Neg, X, "abs.r");
				CI->replaceAllUsesWith(R);
				CI->eraseFromParent();
				continue;
			}

			// Anything else: leave in place, isize() will markUnsupported.
		}
	}



	// Widen f32 allocas to f64 so OP_LOAD_F / OP_STORE_F (which always
	// operate on 8 bytes) never read/write past the end of a 4-byte slot.
	// At -O0 each float local is an alloca used only by load/store float;
	// widening is semantics-preserving: fpext on stores, fptrunc on loads.
	{
		SmallVector<AllocaInst*, 16> FloatAllocas;
		for (BasicBlock& BB : F)
			for (Instruction& I : BB)
				if (auto* AI = dyn_cast<AllocaInst>(&I))
					if (AI->getAllocatedType()->isFloatTy())
						FloatAllocas.push_back(AI);

		for (AllocaInst* AI : FloatAllocas) {
			IRBuilder<> AB(AI);
			auto* NewAI = AB.CreateAlloca(DoubleTy, nullptr, AI->getName() + ".f2d");
			NewAI->setAlignment(Align(8));

			SmallVector<Instruction*, 16> ToErase;
			SmallVector<std::pair<Use*, Value*>, 16> ToReplace;

			for (Use& U : AI->uses()) {
				auto* User = cast<Instruction>(U.getUser());
				if (auto* SI = dyn_cast<StoreInst>(User)) {
					IRBuilder<> B(SI);
					B.CreateStore(B.CreateFPExt(SI->getValueOperand(), DoubleTy, "f2d.ext"), NewAI);
					ToErase.push_back(SI);
				}
				else if (auto* LI = dyn_cast<LoadInst>(User)) {
					IRBuilder<> B(LI);
					Value* Dbl = B.CreateLoad(DoubleTy, NewAI, "f2d.ld");
					Value* Trn = B.CreateFPTrunc(Dbl, Type::getFloatTy(Ctx), "f2d.trn");
					LI->replaceAllUsesWith(Trn);
					ToErase.push_back(LI);
				}
				else {
					ToReplace.push_back({ &U, NewAI });
				}
			}
			for (Instruction* I : ToErase)  I->eraseFromParent();
			for (auto& [U, V] : ToReplace)  U->set(V);
			AI->eraseFromParent();
		}
	}



	// Compile function body to bytecode
	E.setOpcodeMap(&OpMap);
	if (!E.run(F, CTSalt, M.getDataLayout())) {
		FailReason = E.getFailReason().str();
		if (FailReason.empty()) FailReason = "bytecode emission failed";
		return false;
	}

	if (ObfVerify) {
		std::string VErr;
		uint32_t BadIP = 0;
		if (!verifyBytecode(E, CTSalt, OpMap, VErr, BadIP)) {
			FailReason = ("bytecode verify failed at ip " + std::to_string(BadIP) + ": " + VErr);
			return false;
		}
	}

	// Compute power-of-2 padded register file sizes 
	NVRAlloc = nextPow2(E.NVR);
	NVR64Alloc = nextPow2(E.NVR64);
	NPRAlloc = nextPow2(E.NPR);
	NFRAlloc = nextPow2(E.NFR);


	// generate per-slot XOR keys for register encryption ————
	// Keys are compile-time constants derived from a forked RNG with a
	// distinct label ("vm.regkeys") so they do not perturb any existing
	// RNG sequence.  One key per allocated slot (power-of-2 padded).
	if (RegEncrypt) {
		auto KeyRng = VCtx.R.fork("vm.regkeys");
		RegKeys.resize(NVRAlloc);
		for (auto& K : RegKeys)   K = (uint32_t)KeyRng.u32();
		Reg64Keys.resize(NVR64Alloc);
		for (auto& K : Reg64Keys) K = KeyRng.u64();
		FRegKeys.resize(NFRAlloc);
		for (auto& K : FRegKeys)  K = KeyRng.u64();

		LLVM_DEBUG(dbgs() << "[vm] generated register keys for '"
			<< F.getName() << "' [vreg=" << NVRAlloc
			<< " vreg64=" << NVR64Alloc
			<< " freg=" << NFRAlloc << "]\n");
	}


	// Generate per-function engine-pointer XOR mask 
	// Uses a forked RNG so it does not perturb any existing sequence.
	{
		auto EngRng = VCtx.R.fork("vm.engine.mask");
		EngineMask = ((uint64_t)EngRng.u32() << 32) | EngRng.u32();
		// Ensure mask is non-zero to avoid storing the raw pointer.
		if (EngineMask == 0) EngineMask = 0xDEADBEEFCAFEBABEULL;
	}

	// generate anti-debug poison key + init TargetInfo 
	{
		auto ADRng = VCtx.R.fork("vm.antidebug");
		ADPoisonKey = ADRng.u32();
		if (ADPoisonKey == 0) ADPoisonKey = 0xDEAD07u;
	}
	TI = obf::TargetInfo::fromModule(M);

	// generate per-function callee XOR mask 
	{
		auto CMRng = VCtx.R.fork("vm.callee.mask");
		CalleeMask = ((uint64_t)CMRng.u32() << 32) | CMRng.u32();
		if (CalleeMask == 0) CalleeMask = 0xCAFEBABE08080808ULL;
	}


	// Record return slot before stripping body
	computeReturnInfo();


	// Erase original body
	stripBody();

	// Emit globals
	buildBytecodeGlobal();
	buildCalleeGlobal();

	// Populate shared vm_engine (first function only)
	populateVMEngine();

	// Extend CALL handler switches if this function introduced new FTys
	ensureCallFTyCases();

	// Build per-function handler table (uses shared OpcBB with per-function permutation)
	auto* SS = VMEngine::getSharedState(M);
	SharedEngineMode = true;
	buildHandlerTable();
	SharedEngineMode = false;


	// Build thin wrapper that tail-calls vm_engine
	buildWrapper();

	// Split wrapper into phases + insert junk (hardened only)
	hardenWrapper();

	// switch-dispatch flattening of wrapper (hardened only)
	flattenWrapper();

	// MBA substitutions on wrapper arithmetic (hardened only)
	mbaHardenWrapper();

	// Encryption constructor (per-function, targets GVBytecodeRT)
	buildEncryptCtor();

	// .init_array bytecode integrity hash (hardened + antiDebug)
	buildIntegrityHashCtor();

	// .init_array callee XOR masking (hardened only)
	buildCalleeXorCtor();

	++VMFunctions;
	return true;
}