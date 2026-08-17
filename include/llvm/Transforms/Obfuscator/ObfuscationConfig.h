#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <cstdint>
#include <vector>
#include <optional>

namespace llvm {
	class Function;

	// Individual pass configuration
	struct PassConfig {
		std::string passName;
		std::unordered_map<std::string, std::string> params;
		std::string rawInner;   // raw content between outermost parens, for nested specs
		bool enabled = false;
	};

	// Complete obfuscation configuration for a function
	struct ObfuscationConfig {
		std::vector<PassConfig> passes;

		// IR budget: 0 means "use CLI default".
		unsigned budgetMultiplier = 0;  // per-annotation override of --obf-ir-budget-multiplier
		unsigned budgetHardCap = 0;  // per-annotation override of --obf-ir-budget-max

		// Find configuration for a specific pass
		//std::optional<PassConfig> getPassConfig(const std::string& passName) const;
		std::optional<PassConfig> getPassConfig(std::string_view passName) const;

		// Check if a specific pass is enabled
		bool isPassEnabled(const std::string& passName) const;

		// Get ordered list of enabled passes
		std::vector<std::string> getEnabledPasses() const;
	};

	// Main parser class
	class AnnotationParser {
	public:
		// Parse function annotations
		static ObfuscationConfig parseAnnotations(Function* F);

		// Parse a single annotation string
		static ObfuscationConfig parseAnnotationString(const std::string& annotation);

	private:
		// Parse individual pass configuration
		static PassConfig parsePassConfig(const std::string& passSpec);

		// Parse key=value pairs
		static std::unordered_map<std::string, std::string>
			parseParams(const std::string& paramStr);

		// Validate pass configuration
		static bool validatePassConfig(const PassConfig& config);

		// Helper to extract obf: prefix
		static std::string extractObfuscationSpec(const std::string& annotation);
	};

	// Configuration helpers for specific passes
	struct BCFConfig {
		bool enable = false;
		int prob = 30;
		int loop = 1;
		int maxBlocks = 0; // 0 = auto

		static BCFConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct FlatteningConfig {
		bool enable = false;
		unsigned MinBlocks = 3;
		unsigned MaxBlocks = 200;
		bool AllowIndirect = false;
		bool Hybrid = true;
		// If true: state updates are stored as opaque expressions (volatile anchored),
		// instead of plain constants.
		bool OpaqueState = true;
		// If true: inject hard-false selects on state updates + optional fake switch cases.
		bool FakeTransitions = false;
		// Extra fake cases per dispatcher (only used when FakeTransitions=true).
		// 0 = none. If FakeTransitions=true and this stays 0, default will be applied.
		unsigned FakeCases = 0;
		// Per-dispatcher switch domain (router domain unchanged)
		bool PerDispatcherDomain = true;
		// Hide state accesses behind pointer games (trolololo)
		bool ObfuscateStatePtr = true;
		// Add hard-false pointer alias to poison  AA/MemorySSA
		bool OpaqueAliasStatePtr = true;

		static FlatteningConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct SplitConfig {
		bool enable = false;
		int num = 5;

		static SplitConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct SubstitutionConfig {
		bool enable = false;
		int loop = 1;
		unsigned maxSites = 0; // 0 = auto

		static SubstitutionConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct ConstEncConfig {
		bool     enable   = false;
		int      prob     = 60;   // per-site %
		unsigned maxSites = 200;  // per-function
		unsigned minAbs   = 2;    // skip |C| < minAbs
		bool     encInt   = true;
		bool     encFP    = true;
		bool     wrapMBA  = false;

		static ConstEncConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct MBAConfig {
		bool enable = false;
		int prob = 40;
		unsigned maxDepth = 3; // recursive MBA depth (1..10)
		unsigned maxSites = 120; // per-function replacement budget
		// --- Advanced MBA knobs (safe defaults) ---
		// Linear MBA inflation: number of additive "terms" we add (each term is runtime-zero shaped).
		unsigned linearTermsMin = 6;
		unsigned linearTermsMax = 10;
		// Nonlinear MBA (mul + urem) used as runtime-zero addends (semantics preserved).
		bool enableNonLinear = true;
		unsigned nonLinearWeight = 20; // % chance per transformed site (context-aware may raise/lower)
		// Layered MBA: apply MBA to some newly created internal ops in a bounded window.
		bool enableLayered = true;
		unsigned layeredWindow = 48;   // scan up to N insts backward from anchor
		unsigned layeredBudget = 1;    // rewrite up to N internal ops per site
		// Input-derived zeros (V1): memory-free runtime-zero addends built from the
		// site's operands via nonlinear-lifted MBA identities. Unlike the memory-slot
		// zeros, these have no alloca a value-set analysis can fold to 0; the solver
		// must bit-blast the nonlinear lift (SMT-timeout-strong). Default OFF so
		// existing output is byte-identical.
		bool enableInputZero = false;
		unsigned inputZeroWeight = 40; // % chance per transformed site (0-100)
		// inputZeroReplace: when enableInputZero, suppress the slot-based inflation
		// (inflateLinear + nonlinear/high-degree/mixed-mode addends) and rely solely
		// on the input-derived zeros. Off = augment (both); on = replace (Input mode).
		bool inputZeroReplace = false;
		unsigned inputZeroCount = 1;   // distinct input-derived forms per fired site (1-8)

		static MBAConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct SemanticDiffusionConfig {
		bool enable = false;
		int prob = 45;          // probability per site
		int slots = 3;          // number of volatile slots
		int maxSites = 80;      // per function budget

		static SemanticDiffusionConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct StringEncryptionConfig {
		bool enable = false;
		int  minLength = 4;          // minimum string length to encrypt (1–100)
		// ── AES-CTR options ──────────────────────────────────────────────────────
		bool useAES = true;        // true  → AES-128-CTR (default)
		// false → legacy single-byte XOR fallback
		bool keySplit = true;        // true  → split 176-byte key schedule across
		//         data segment + code segment (stores)
		// false → store all 176 bytes in data only
		//         (simpler, weaker)
		bool useChaCha = false;      // true → ChaCha20 (tableless). Takes precedence
		                             // over useAES in dispatch. Opt-in via cipher=chacha.
		// Passes to apply to the linked stub functions.
		// Populated from a sibling strenc_stub(...) annotation token.
		ObfuscationConfig stubPasses;

		static StringEncryptionConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct FunctionMergingConfig {
		bool enable = false;
		std::string group;            // bucket label ("" -> "_auto")
		unsigned chunk = 4;           // _auto pool chunk size (2..16)
		bool opaqueSel = true;        // obfuscate the selector
		std::string dispatch = "switch";
		unsigned minInsts = 4;
		unsigned maxInsts = 2000;
		bool stripDbg = true;
		bool thunkAddrTaken = false;  // merge address-taken/external funcs via a thunk
		bool dissimilar = true;       // _auto pool groups maximally-different shapes
		bool launderSel = false;      // load call-site selectors from a global (defeats devirt)

		static FunctionMergingConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct AntiDecompilerConfig {
		bool enable = false;
		int  prob = 50;              // probability per eligible site (0-100)
		unsigned maxSites = 40;      // per-function transform budget
		unsigned strength = 2;       // 0=light, 1=medium, 2=heavy, 3=extreme
		bool enableIndirectBr = true;  // indirectbr trampolines
		bool enableAsmAntiDisasm = true;  // inline asm junk bytes
		bool enableStackPollution = true;  // fake stack frame entries
		bool enableDeadCodeDecoys = true;  // opaque pred + type-confusing dead blocks
		bool enableCallObfuscation = true;  // indirect call through volatile slots
		bool enableAliasConfusion = true;  // pointer aliasing via ptrtoint chains
		bool enableFakeLoop = false;   // opaque-bounded fake loop with junk math
		bool enableRdtscStretch = false;  // passive rdtsc anti-trace reads (x86 only)
		bool enableConstLaunder = false;  // route literal constants through volatile globals

		// Per-technique probability overrides. -1 = fall back to `prob`.
		int asmProb = -1;
		int ibrProb = -1;
		int decoyProb = -1;
		int callProb = -1;
		int aliasProb = -1;
		int fakeLoopProb = -1;
		int rdtscProb = -1;
		int constLaunderProb = -1;

		// Per-technique strength overrides. -1 = fall back to `strength`.
		int decoyStrength = -1;
		int stackStrength = -1;

		// Per-function annotation path to a JSON gadget pool.
		std::string gadgetsFile;
		// Per-function inline asm bodies (raw, separated by ';').
		// Appended to the function-scope gadget pool.
		std::string inlineAsm;
		// Per-function technique whitelist (empty = no filter).
		std::vector<std::string> techniquesAllowed;
		// Per-function gadget category filter (empty = no filter).
		std::vector<std::string> categoriesAllowed;

		// Resolve effective per-technique prob/strength with fallback.
		int effectiveProb(std::string_view techName) const;
		unsigned effectiveStrength(std::string_view techName) const;

		static AntiDecompilerConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct ShieldConfig {
		bool enable = false;
		unsigned maxSites = 200;
		bool volatileBarriers = true;
		bool opaqueIdentities = true;
		bool deadStoreProtect = true;
		bool cfgGuards = true;

		static ShieldConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;

	};

	struct VirtualCallConfig {
		bool enable = false;
		int prob = 30;
		unsigned maxSites = 0; // 0 = auto
		// --- Enhanced Virtual Calls ---
		bool opaqueVTableNames = true;      // hash-based global naming
		bool addDecoyEntries = true;        // decoy slots contain safe stubs
		unsigned decoyMin = 2;              // per-table (bounded by kTableSize-1)
		unsigned decoyMax = 4;
		bool varyIndexPerCallsite = true;   // per callsite index expression
		unsigned indexStrength = 2;         // 0..3 (see implementation)
		// Optional (opt-in) vtable merging across callees sharing a FunctionType.
		// Default off for safety until you validate it in your tests.
		bool mergeVTables = false;
		// Encrypted, runtime-initialized vtable (non-merged path only): entries
		// are stored as ptrtoint(entry) XOR K in a mutable [kTableSize x i64]
		// global, filled by a global constructor. Default off (byte-identical
		// plaintext vtable when false). Falls back to plaintext when
		// mergeVTables is also on (not supported together yet).
		bool encryptTable = false;

		static VirtualCallConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct VMPassConfig {
		bool     enable = false;
		unsigned minBlocks = 1;
		unsigned maxBlocks = 400;     // 0 = no limit
		bool     lazyDecrypt = false; // AES layer removed per-instruction at fetch instead of whole-buffer in ctor (requires encBytecode)
		bool     obfRegIdx = true;    // XOR register indices with compile-time salt
		bool     encDispatch = true;   // P2: encrypted per-opcode->handler index indirection (on)
		unsigned handlerVariants = 3;  // K handler-body variants per opcode (P1 polymorphism on; 1 = off)
		unsigned handlerDecoys   = 0;  // {0,1,2,3} decoy-handler density (0 = off; 1 static, 2 mixed live, 3 aggressive) — see docs/VM.md
		bool     encBytecode = true;  // LCG-encrypt bytecode stream at load time
		bool     constInStream = false;  // move int/i64/fp constants into the encrypted bytecode stream instead of plaintext wrapper stores (requires encBytecode)
		bool     strongBytecode = true;   // P3: per-position PRF Layer-1 keystream (on; 0 = weak salt^index)
		bool     blindTargets = true;   // P3: XOR-blind bytecode branch targets (on)
		bool     hardened = false;    // MBA + opaque predicates on handler blocks
		bool     regEncrypt = false;  // XOR-encrypt register values at rest
		bool     rollingRegKey = false;  // P4-C: evolve per-slot reg XOR key on each store
		bool     antiDebug = true;    // anti-debug traps (active when hardened=1)
		// configurable anti-debug thresholds
		unsigned adDispatchThreshold = 5000;  // rdtsc delta for dispatch-level gate (cycles)
		unsigned adHandlerThreshold = 5000;  // rdtsc delta for handler spot-checks (cycles) — at the debug-exception floor; debounced over kDebounce consecutive hits
		unsigned adDispatchInterval = 64;    // check every N fetch iterations (power of 2)
		unsigned adHandlerProb = 10;    // % of handlers to trap (0-100)
		bool     bindAntiDebug = false; // W7: fold anti-debug detection into AES key mask (bytecode decodes wrong under debugger). Requires hardened.

		bool     nestedVM = false;         // virtualize eligible opcode handlers with a second VM layer
		// 0 = all eligible opcodes nest; N>0 = only the first N, in the fixed
		// order BINOP, BINOP64, ICMP, ICMP64, FCMP, CAST (see kNestedHelperOrder).
		unsigned nestedVMOpcodes = 0;
		bool     nestedVMHardened = false; // reserved: harden the inner VM layer (unused)

		// threadedDispatch: inline the fetch/decode/indirectbr sequence into
		// every handler's back-edge instead of routing through one shared
		// vm.dispatch/vm.fetch pair. Removes the single central dispatch loop
		// a lifter would otherwise fingerprint (one urem, one GEP, one
		// indirectbr). Off = byte-identical to the central-dispatch build.
		bool     threadedDispatch = false;

		// keyedDispatch: XOR each written opcode byte with a per-IP compile-time
		// key at emit time; un-XOR at fetch time. The same physical byte read
		// from two different IPs decodes to different logical opcodes, so a
		// static byte->handler map no longer holds. Off = byte-identical.
		bool     keyedDispatch = false;

		// superOps: fuse eligible i32 `mul`+`add` chains (mul result single-use,
		// consumed directly by the add) into one OP_MULADD opcode instead of two
		// OP_BINOP opcodes. Off = correctness-identical (OP_COUNT grows by one).
		bool     superOps = false;

		// randISA: per-build randomization of semantic operand-field encodings.
		// W6: permutes the sub-opcode byte values (BinSubop for OP_BINOP/BINOP64)
		// module-uniformly from the module seed, so the shared handler's switch-
		// case constants — and the bytecode subop bytes — differ across builds.
		// Two builds of the same source at different seeds share no static handler
		// signature for the permuted families. Off = byte-identical (identity map).
		bool     randISA = false;

		// enginePoolSize: number of distinct shared VM engines built per module
		// (W1 "the real kill"). N>1 builds N structurally-independent engines;
		// each virtualized function deterministically picks one by its own seed,
		// so lifting one function's engine gives no shortcut for a function that
		// runs a different engine. 1 = single shared engine (byte-identical to
		// the pre-pool build). Clamped to >=1.
		unsigned enginePoolSize = 1;

		// metamorphicEngines: give each engine in the pool a structurally
		// distinct handler body, not just a distinct name. Every engine's integer
		// handler arithmetic is rewritten with semantics-preserving MBA identities
		// chosen from a per-engine (pool-index-derived) seed, so lifting one
		// clone's handlers yields no pattern match for another clone -- even when
		// handlerVariants=1 and hardened=0 leave the bodies otherwise identical.
		// Requires enginePoolSize>1 (no clones to diversify otherwise). Off =
		// byte-identical.
		bool     metamorphicEngines = false;

		// perFnEngine: give THIS function its own dedicated shared engine instead
		// of hashing it into the enginePoolSize pool. Because annotations are
		// per-function, setting it on selected (critical) functions gives them
		// private engines while the rest share the pool (annotation-selective);
		// setting it everywhere gives a full per-function engine build. Highest
		// structural resilience, highest .text cost. Off = use enginePoolSize.
		bool     perFnEngine = false;

		static VMPassConfig fromPassConfig(const PassConfig& PC);
		bool validate() const;
	};


} // namespace llvm

