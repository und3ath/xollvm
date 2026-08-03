// ============================================================================
// VMPass.cpp — Code Virtualisation pass : pass driver
//
// This file contains only:
//   - VMPassConfig::fromPassConfig() and validate()
//   - VMPass::run()
//
// The heavy lifting is split across:
//   VMPass_ISA.h            ISA enums, VMOpcodeMap, LCG constants
//   VMPass_Emitter.h/.cpp   BytecodeEmitter (two-pass IR -> bytecode compiler)
//   VMPass_Verifier.h/.cpp  verifyBytecode (post-emission sanity checker)
//   VMPass_Impl.h/.cpp      VMCtx, isVMEligible, VMImpl (IR transformation engine)
// ============================================================================

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/VMPass.h"
#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/Utils.h"

using namespace llvm;

#define DEBUG_TYPE "vm"

// ============================================================================
// VMPassConfig
// ============================================================================

VMPassConfig VMPassConfig::fromPassConfig(const PassConfig& PC) {
	VMPassConfig Cfg;
	Cfg.enable = PC.enabled;

	// preset=<light|medium|high|max>: shortcut bundle applied before explicit
	// knobs below, so any explicit knob in the annotation overrides the preset.
	auto It = PC.params.find("preset");
	if (It != PC.params.end()) {
		const std::string& P = It->second;
		if (P == "light") {
			// always-on baseline + K=1, no other hardening
			Cfg.obfRegIdx = true;
			Cfg.encBytecode = true;
			Cfg.handlerVariants = 1;
			Cfg.encDispatch = false;
			Cfg.strongBytecode = false;
			Cfg.blindTargets = false;
		} else if (P == "medium") {
			// current defaults; explicit for readability + stability
			Cfg.obfRegIdx = true;
			Cfg.encBytecode = true;
			Cfg.handlerVariants = 3;
			Cfg.encDispatch = true;
			Cfg.strongBytecode = true;
			Cfg.blindTargets = true;
		} else if (P == "high") {
			// medium + hardened + threaded + keyed
			Cfg.obfRegIdx = true;
			Cfg.encBytecode = true;
			Cfg.handlerVariants = 3;
			Cfg.encDispatch = true;
			Cfg.strongBytecode = true;
			Cfg.blindTargets = true;
			Cfg.hardened = true;
			Cfg.threadedDispatch = true;
			Cfg.keyedDispatch = true;
		} else if (P == "max") {
			// high + all remaining knobs on
			Cfg.obfRegIdx = true;
			Cfg.encBytecode = true;
			Cfg.handlerVariants = 3;
			Cfg.encDispatch = true;
			Cfg.strongBytecode = true;
			Cfg.blindTargets = true;
			Cfg.hardened = true;
			Cfg.threadedDispatch = true;
			Cfg.keyedDispatch = true;
			Cfg.lazyDecrypt = true;
			Cfg.constInStream = true;
			Cfg.nestedVM = true;
			Cfg.superOps = true;
			Cfg.rollingRegKey = true;
			Cfg.bindAntiDebug = true;
			Cfg.randISA = true;
		}
		// Unknown preset name: silently ignore, falls through to defaults +
		// explicit knobs.
	}

	auto getUInt = [&](StringRef K, unsigned& O) {
		auto It = PC.params.find(K.str());
		if (It != PC.params.end()) O = (unsigned)std::stoul(It->second);
		};
	auto getBool = [&](StringRef K, bool& O) {
		auto It = PC.params.find(K.str());
		if (It != PC.params.end()) O = (It->second != "0" && It->second != "false");
		};
	getUInt("minBlocks", Cfg.minBlocks);
	getUInt("maxBlocks", Cfg.maxBlocks);
	getBool("obfRegIdx", Cfg.obfRegIdx);
	getBool("encDispatch", Cfg.encDispatch);
	getBool("encBytecode", Cfg.encBytecode);
	getBool("constInStream", Cfg.constInStream);
	getBool("strongBytecode", Cfg.strongBytecode);
	getBool("blindTargets", Cfg.blindTargets);
	getBool("lazyDecrypt", Cfg.lazyDecrypt);
	getBool("hardened", Cfg.hardened);
	getBool("regEncrypt", Cfg.regEncrypt);
	getBool("rollingRegKey", Cfg.rollingRegKey);
	getBool("antiDebug", Cfg.antiDebug);
	getUInt("adDispatchThreshold", Cfg.adDispatchThreshold);
	getUInt("adHandlerThreshold", Cfg.adHandlerThreshold);
	getUInt("adDispatchInterval", Cfg.adDispatchInterval);
	getUInt("adHandlerProb", Cfg.adHandlerProb);
	getBool("bindAntiDebug", Cfg.bindAntiDebug);
	getUInt("handlerVariants", Cfg.handlerVariants);
	getBool("nestedVM", Cfg.nestedVM);
	getUInt("nestedVMOpcodes", Cfg.nestedVMOpcodes);
	getBool("nestedVMHardened", Cfg.nestedVMHardened);
	getBool("threadedDispatch", Cfg.threadedDispatch);
	getBool("keyedDispatch", Cfg.keyedDispatch);
	getBool("superOps", Cfg.superOps);
	getBool("randISA", Cfg.randISA);

	// lazyDecrypt requires encBytecode — nothing to defer if bytecode isn't encrypted.
	if (!Cfg.encBytecode) Cfg.lazyDecrypt = false;
	// hardened requires encBytecode (meaningful only with encrypted bytecode)
	if (!Cfg.encBytecode) Cfg.hardened = false;
	// constInStream requires encBytecode — the whole point is to hide constants
	// in the encrypted stream instead of plaintext wrapper stores.
	if (!Cfg.encBytecode) Cfg.constInStream = false;
	// hardened implies regEncrypt — encrypted registers complement MBA-obscured handlers
	if (Cfg.hardened) Cfg.regEncrypt = true;
	// bindAntiDebug requires hardened + antiDebug (its detection substrate)
	if (!Cfg.hardened || !Cfg.antiDebug) Cfg.bindAntiDebug = false;
	if (Cfg.handlerVariants < 1) Cfg.handlerVariants = 1;
	if (Cfg.handlerVariants > kMaxHandlerVariants) Cfg.handlerVariants = kMaxHandlerVariants;
	return Cfg;
}

bool VMPassConfig::validate() const {
	if (minBlocks < 1) return false;
	if (maxBlocks > 0 && maxBlocks < minBlocks) return false;
	return true;
}

// ============================================================================
// VMPass::run
// ============================================================================

PreservedAnalyses VMPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration()) return PreservedAnalyses::all();

	VMCtx VCtx(F, AM);
	if (!VCtx.Cfg.enable) return PreservedAnalyses::all();

	{
		std::string Reason; raw_string_ostream RS(Reason);
		if (!isVMEligible(F, VCtx.FOC, VCtx.Cfg, &RS)) {
			LLVM_DEBUG(dbgs() << "[vm] skip '" << F.getName() << "': " << RS.str() << "\n");
			if (ObfVerbose) errs() << "[vm] skip '" << F.getName() << "': " << Reason << "\n";
			auto& MutFOC = *AM.getResult<FunctionObfContextAnalysis>(F);
			llvm::obf::recordObfPassSkip(MutFOC, "vm",
				Reason.empty() ? "ineligible" : Reason);
			return PreservedAnalyses::all();
		}
	}

	VMImpl Impl(VCtx);
	if (!Impl.run()) {
		LLVM_DEBUG(dbgs() << "[vm] fail '" << F.getName() << "': " << Impl.FailReason << "\n");
		if (ObfVerbose) {
			if (!Impl.FailReason.empty())
				errs() << "[vm] fail '" << F.getName() << "': " << Impl.FailReason << "\n";
			else
				errs() << "[vm] fail '" << F.getName() << "'" << "\n";
		}
		auto& MutFOC = *AM.getResult<FunctionObfContextAnalysis>(F);
		llvm::obf::recordObfPassSkip(MutFOC, "vm",
			Impl.FailReason.empty() ? "impl_failed" : Impl.FailReason);
		return PreservedAnalyses::all();
	}

	if (ObfVerbose)
		errs() << "[vm] virtualised '" << F.getName() << "' ["
		<< Impl.E.BC.size() << "B bytecode | "
		<< (unsigned)Impl.E.NVR << "vregs+"
		<< (unsigned)Impl.E.NVR64 << "vregs64+"
		<< (unsigned)Impl.E.NPR << "pregs"
		<< (VCtx.Cfg.obfRegIdx ? " |obf-idx" : "")
		<< (VCtx.Cfg.encBytecode ? " |enc-bc" : "")
		<< (VCtx.Cfg.hardened ? " |hardened" : "")
		<< "]\n";

	return PreservedAnalyses::none();
}