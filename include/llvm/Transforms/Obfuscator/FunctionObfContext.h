#pragma once

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include <random>
#include <string>
#include <unordered_map>

namespace llvm {

	struct FunctionObfContext
	{
		Function* F = nullptr;

		// Structural identity
		DenseMap<BasicBlock*, uint32_t> BlockIDs;

		// Entropy shared accross passes
		SmallVector<Value*, 8> EntropySources;
		SmallVector<AllocaInst*, 8> StackAllocas;
		SmallVector<Argument*, 8> Arguments;

		unsigned NumBlocks = 0;
		unsigned NumInsts = 0;
		unsigned NumCalls = 0;
		unsigned NumLoops = 0;
		unsigned MaxLoopDepth = 0;
		bool HasIndirectCalls = false;
		bool HasInvoke = false;
		bool HasIndirectBr = false;
		bool HasMustTail = false;
		bool HasSwitch = false;
		bool HasEHPad = false;
		bool HasInlineAsm = false;
		bool HasCallBr = false;
		bool HasConvergentCalls = false;
		bool HasNaked = false;
		unsigned NumExits = 0;
		unsigned NumEHPads = 0;
		unsigned NumNormalBlocks = 0;  // blocks outside EH regions
		bool HasCatchSwitch = false;
		bool HasCleanupPad = false;
		bool HasCatchPad = false;

		uint32_t StateXorKey;
		uint32_t StateAddKey;

		bool Debug = false;

		AllocaInst* StatVar = nullptr;
		BasicBlock* Dispatcher = nullptr;
		SmallVector<BasicBlock*, 8> FlattenedBlocks;
		SmallVector<BasicBlock*, 4> Dispatchers; // all dispatcher blocks

		unsigned NumDispatchers = 1;

		// Direct mapping from block to its owning dispatcher
		DenseMap<BasicBlock*, BasicBlock*> BlockToDispatcher;
		// Keep existing for compatibility:
		DenseMap<BasicBlock*, uint32_t> DispatcherGroups;
		//  State value -> Dispatcher that handles it
		DenseMap<uint32_t, BasicBlock*> StateToDispatcher;

		// Router-based 
		BasicBlock* Router = nullptr;
		// Router hash keys (per function)
		uint32_t RouterXorKey = 0;
		uint32_t RouterMulKey = 0;
		uint32_t RouterAddKey = 0;

		// --- Per-dispatcher decoding domain keys (router domain unchanged)
		std::vector<uint32_t> DomXor1, DomMul, DomAdd, DomXor2;
		std::vector<uint8_t>  DomRot;

		// --- State pointer obfuscation / aliasing
		AllocaInst* AliasStateSlot = nullptr;   // i32
		AllocaInst* StatePtrSlot = nullptr;     // alloca i8*  (type is i8**)
		AllocaInst* StatePtrSlotFake = nullptr; // alloca i8*  (type is i8**)

		unsigned BudgetRemaining = UINT_MAX;  // UINT_MAX = unlimited

		/// Per-pass skip records published by individual passes via
		/// `llvm::obf::recordObfPassSkip(FOC, "<passId>", "<reason>")` (Utils.h).
		/// Keyed by canonical pass id. Empty value or missing entry = no skip.
		/// The driver reads these after each pass run and feeds them into the
		/// IRBudget record + JSON report, and fatals when `-obf-no-skips` is on.
		std::unordered_map<std::string, std::string> PassSkipReasons;

		FunctionObfContext() = default;
		FunctionObfContext(Function& F, bool Debug)
			: F(&F), Debug(Debug) {
		}
	};

} // namespace llvm