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

		static VirtualCallConfig fromPassConfig(const PassConfig& pc);
		bool validate() const;
	};

	struct VMPassConfig {
		bool     enable = false;
		unsigned minBlocks = 1;
		unsigned maxBlocks = 400;     // 0 = no limit
		bool     useAES = true;       // AES-CTR replaces LCG (Layer 2)
		bool     obfRegIdx = true;    // XOR register indices with compile-time salt
		bool     encDispatch = true;   // P2: encrypted per-opcode->handler index indirection (on)
		unsigned handlerVariants = 3;  // K handler-body variants per opcode (P1 polymorphism on; 1 = off)
		bool     encBytecode = true;  // LCG-encrypt bytecode stream at load time
		bool     strongBytecode = true;   // P3: per-position PRF Layer-1 keystream (on; 0 = weak salt^index)
		bool     blindTargets = true;   // P3: XOR-blind bytecode branch targets (on)
		bool     hardened = false;    // MBA + opaque predicates on handler blocks
		bool     regEncrypt = false;  // XOR-encrypt register values at rest
		bool     rollingRegKey = false;  // P4-C: evolve per-slot reg XOR key on each store
		bool     antiDebug = true;    // anti-debug traps (active when hardened=1)
		// configurable anti-debug thresholds
		unsigned adDispatchThreshold = 5000;  // rdtsc delta for dispatch-level gate (cycles)
		unsigned adHandlerThreshold = 500;   // rdtsc delta for handler spot-checks (cycles)
		unsigned adDispatchInterval = 64;    // check every N fetch iterations (power of 2)
		unsigned adHandlerProb = 10;    // % of handlers to trap (0-100)

		static VMPassConfig fromPassConfig(const PassConfig& PC);
		bool validate() const;
	};


} // namespace llvm

