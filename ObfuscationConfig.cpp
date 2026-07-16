#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/Utils.h"


#include "llvm/Transforms/Obfuscator/PassIds.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"

#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <regex>
#include <stdexcept>
#include <cctype>

using namespace llvm;

// ============================================================================
// ObfuscationConfig 
// ============================================================================

std::optional<PassConfig> ObfuscationConfig::getPassConfig(std::string_view passName) const {
	auto it =
		std::find_if(passes.begin(), passes.end(), [&](const PassConfig& pc) {
		return pc.enabled && pc.passName == passName;
			});

	return (it != passes.end()) ? std::optional<PassConfig>(*it) : std::nullopt;
}

bool ObfuscationConfig::isPassEnabled(const std::string& passName) const {
	return getPassConfig(passName).has_value();
}

std::vector<std::string> ObfuscationConfig::getEnabledPasses() const {
	std::vector<std::string> result;
	for (const auto& pc : passes) {
		if (pc.enabled) {
			result.push_back(pc.passName);
		}
	}
	return result;
}

// ============================================================================
// AnnotationParser 
// ============================================================================

std::string AnnotationParser::extractObfuscationSpec(const std::string& annotation) {
	// Handle "obf:" prefix
	std::regex obfPrefixRe(R"(obf\s*:\s*(.+))");
	std::smatch m;

	if (std::regex_search(annotation, m, obfPrefixRe)) {
		return m[1].str();
	}

	// No prefix, return as-is
	return annotation;
}

std::unordered_map<std::string, std::string>
AnnotationParser::parseParams(const std::string& paramStr)
{

	std::unordered_map<std::string, std::string> params;

	if (paramStr.empty()) {
		return params;
	}

	std::regex paramRe(R"((\w+)\s*=\s*(?:\"([^\"]*)\"|([^\s,]+)))");

	auto begin = std::sregex_iterator(paramStr.begin(), paramStr.end(), paramRe);
	auto end = std::sregex_iterator();

	for (std::sregex_iterator i = begin; i != end; ++i) {
		std::smatch match = *i;
		std::string key = match[1].str();
		std::string value = match[2].matched ? match[2].str() : match[3].str();

		params[key] = value;
	}

	return params;
}

PassConfig AnnotationParser::parsePassConfig(const std::string& passSpec) {
	PassConfig config;
	std::string spec = passSpec;
	// trim...

	// Find the first '(' � everything before is the pass name
	auto parenPos = spec.find('(');
	if (parenPos == std::string::npos) {
		// No params: just a name
		config.passName = llvm::obf::normalizePassId(
			StringRef(spec).trim().lower());
		config.enabled = true;
		return config;
	}

	config.passName = llvm::obf::normalizePassId(
		StringRef(spec.substr(0, parenPos)).trim().lower());

	// Extract content between outermost parens (handles nesting)
	int depth = 0;
	size_t start = std::string::npos, end = std::string::npos;
	for (size_t i = parenPos; i < spec.size(); i++) {
		if (spec[i] == '(') {
			if (depth++ == 0) start = i + 1;
		}
		else if (spec[i] == ')') {
			if (--depth == 0) { end = i; break; }
		}
	}

	if (start != std::string::npos && end != std::string::npos) {
		config.params = parseParams(spec.substr(start, end - start));
		// For strenc_stub: the inner content is sub-pass specs, not key=val pairs.
		// Store the raw inner string for later re-parsing.
		config.rawInner = spec.substr(start, end - start);
	}

	config.enabled = true;
	return config;
}

bool AnnotationParser::validatePassConfig(const PassConfig& config) {
	// Known passes
	if (!llvm::obf::isKnownCanonicalPassId(config.passName)) {
		errs() << "Warning: Unknown obfuscation pass: " << config.passName << "\n";
		return false;
	}
	return true;
}

ObfuscationConfig AnnotationParser::parseAnnotationString(
	const std::string& annotation) {

	ObfuscationConfig config;

	// Extract the obfuscation specification
	std::string spec = extractObfuscationSpec(annotation);

	if (spec.empty()) {
		return config;
	}

	// Split by comma (but not commas inside parentheses)
	std::vector<std::string> passSpecs;
	std::string current;
	int parenDepth = 0;

	for (char c : spec) {
		if (c == '(') {
			parenDepth++;
			current += c;
		}
		else if (c == ')') {
			parenDepth--;
			current += c;
		}
		else if (c == ',' && parenDepth == 0) {
			if (!current.empty()) {
				passSpecs.push_back(current);
				current.clear();
			}
		}
		else {
			current += c;
		}
	}

	if (!current.empty()) {
		passSpecs.push_back(current);
	}

	// Parse each pass specification
	for (const auto& passSpec : passSpecs) {
		PassConfig pc = parsePassConfig(passSpec);
		if (pc.enabled && validatePassConfig(pc)) {
			config.passes.push_back(pc);
		}
	}




	// Parse top-level budget params (not per-pass).
	// Annotation syntax: obf: budget=40, budgetMax=50000, mba(...), bcf(...)
	// Budget params can appear as standalone tokens in the annotation.
	for (const auto& pc : config.passes) {
		if (pc.params.count("budget"))
			config.budgetMultiplier = (unsigned)std::stoul(pc.params.at("budget"));
		if (pc.params.count("budgetMax"))
			config.budgetHardCap = (unsigned)std::stoul(pc.params.at("budgetMax"));
		if (pc.params.count("budgetMultiplier"))
			config.budgetMultiplier = (unsigned)std::stoul(pc.params.at("budgetMultiplier"));
	}

	return config;
}


ObfuscationConfig AnnotationParser::parseAnnotations(Function* F) {
	ObfuscationConfig finalConfig;

	// Get all annotations
	std::vector<std::string> annotations = llvm::obf::readAnnotations(F);

	if (annotations.empty()) {
		return finalConfig;
	}

	if (ObfVerbose) {
		errs() << "Found " << annotations.size() << " annotation(s) for function "
			<< F->getName() << "\n";
	}

	// Parse each annotation and merge
	for (const auto& ann : annotations) {
		if (ObfVerbose) errs() << "  Parsing: '" << ann << "'\n";

		ObfuscationConfig parsedConfig = parseAnnotationString(ann);

		// Merge into final config
		for (auto& pc : parsedConfig.passes) {
			// Check if this pass already exists
			bool found = false;
			for (auto& existingPc : finalConfig.passes) {
				if (existingPc.passName == pc.passName) {
					// Merge parameters (new ones override)
					for (const auto& kv : pc.params) {
						existingPc.params[kv.first] = kv.second;
					}
					found = true;
					break;
				}
			}

			// If not found, add it
			if (!found) {
				finalConfig.passes.push_back(pc);
			}
		}
	}

	if (ObfVerbose)
		errs() << "  Total passes enabled: " << finalConfig.passes.size() << "\n";

	for (const auto& pc : finalConfig.passes) {

		if (ObfVerbose) errs() << "    - " << pc.passName;

		if (!pc.params.empty()) {


			if (ObfVerbose) errs() << "(";

			bool first = true;
			for (const auto& kv : pc.params) {
				if (!first && ObfVerbose) errs() << ",";

				if (ObfVerbose)
					errs() << kv.first << "=" << kv.second;

				first = false;
			}
			if (ObfVerbose)
				errs() << ")";
		}
		if (ObfVerbose)
			errs() << "\n";
	}

	return finalConfig;
}

// ============================================================================
// Pass-Specific Config Helpers 
// ============================================================================

static std::string toLowerCopy(std::string S) {
	std::transform(S.begin(), S.end(), S.begin(),
		[](unsigned char c) { return (char)std::tolower(c); });
	return S;
}

static bool parseBoolLoose(const std::string& In, bool& Out) {
	std::string s = toLowerCopy(In);
	if (s == "1" || s == "true" || s == "yes" || s == "on") { Out = true; return true; }
	if (s == "0" || s == "false" || s == "no" || s == "off") { Out = false; return true; }
	return false;
}

// ============================================================================
// Bogus control flow
// ============================================================================

BCFConfig BCFConfig::fromPassConfig(const PassConfig& pc) {
	BCFConfig cfg;
	cfg.enable = pc.enabled;

	try {
		if (pc.params.count("prob")) {
			cfg.prob = std::stoi(pc.params.at("prob"));
		}
		if (pc.params.count("loop")) {
			cfg.loop = std::stoi(pc.params.at("loop"));
		}
		if (pc.params.count("maxBlocks")) {
			cfg.maxBlocks = std::stoi(pc.params.at("maxBlocks"));
		}
	}
	catch (const std::exception& e) {
		errs() << "Error parsing BCF parameters: " << e.what() << "\n";
		cfg.enable = false;
	}

	return cfg;
}

bool BCFConfig::validate() const {
	if (!enable) return true;

	if (prob < 0 || prob > 100) {
		errs() << "BCF: Invalid probability " << prob
			<< " (must be 0-100)\n";
		return false;
	}

	if (loop < 1 || loop > 10) {
		errs() << "BCF: Invalid loop count " << loop
			<< " (must be 1-10)\n";
		return false;
	}

	if (maxBlocks < 0 || maxBlocks > 100000) {
		errs() << "BCF: Invalid maxBlocks " << maxBlocks
			<< " (must be 0..100000)\n";
		return false;

	}
	return true;
}


// ============================================================================
// Flattening 
// ============================================================================

FlatteningConfig FlatteningConfig::fromPassConfig(const PassConfig& pc) {
	FlatteningConfig cfg;
	cfg.enable = pc.enabled;

	// Case-insensitive key handling.
	std::unordered_map<std::string, std::string> P;
	P.reserve(pc.params.size());
	for (const auto& kv : pc.params) {
		P[toLowerCopy(kv.first)] = kv.second;
	}

	auto getU = [&](const char* Key, unsigned& Dst) {
		auto it = P.find(Key);
		if (it == P.end()) return;
		Dst = (unsigned)std::stoul(it->second);
		};

	auto getB = [&](const char* Key, bool& Dst) {
		auto it = P.find(Key);
		if (it == P.end()) return;
		bool V;
		if (!parseBoolLoose(it->second, V))
			throw std::runtime_error(std::string("invalid bool for ") + Key);
		Dst = V;
		};

	try {
		if (P.count("minblocks")) getU("minblocks", cfg.MinBlocks);
		if (P.count("maxblocks")) getU("maxblocks", cfg.MaxBlocks);

		// Aliases
		if (P.count("min")) getU("min", cfg.MinBlocks);
		if (P.count("max")) getU("max", cfg.MaxBlocks);

		if (P.count("allowindirect")) getB("allowindirect", cfg.AllowIndirect);
		if (P.count("indirect")) getB("indirect", cfg.AllowIndirect);

		if (P.count("hybrid")) getB("hybrid", cfg.Hybrid);

		if (P.count("opaquestate")) getB("opaquestate", cfg.OpaqueState);
		if (P.count("opaque")) getB("opaque", cfg.OpaqueState);

		if (P.count("faketransitions")) getB("faketransitions", cfg.FakeTransitions);
		if (P.count("fake")) getB("fake", cfg.FakeTransitions);

		if (P.count("fakecases")) getU("fakecases", cfg.FakeCases);
		if (P.count("fakecase")) getU("fakecase", cfg.FakeCases);


		if (P.count("perdispatcherdomain")) getB("perdispatcherdomain", cfg.PerDispatcherDomain);
		if (P.count("domain")) getB("domain", cfg.PerDispatcherDomain);

		if (P.count("obfuscatestateptr")) getB("obfuscatestateptr", cfg.ObfuscateStatePtr);
		if (P.count("stateptr")) getB("stateptr", cfg.ObfuscateStatePtr);
		if (P.count("ptr")) getB("ptr", cfg.ObfuscateStatePtr);

		if (P.count("opaquealiasstateptr")) getB("opaquealiasstateptr", cfg.OpaqueAliasStatePtr);
		if (P.count("aliasptr")) getB("aliasptr", cfg.OpaqueAliasStatePtr);
		if (P.count("alias")) getB("alias", cfg.OpaqueAliasStatePtr);

	}
	catch (const std::exception& e) {
		errs() << "Error parsing Flattening parameters: " << e.what() << "\n";
		cfg.enable = false;
	}

	// Default behavior: if fake transitions are enabled but no fakeCases provided,
	// pick a small practical default.
	if (cfg.enable && cfg.FakeTransitions && cfg.FakeCases == 0)
		cfg.FakeCases = 2;

	return cfg;
}

bool FlatteningConfig::validate() const {
	if (!enable) return true;

	if (MinBlocks < 2 || MinBlocks > 100000) {
		errs() << "Flattening: Invalid MinBlocks " << MinBlocks
			<< " (must be 2..100000)\n";
		return false;
	}

	if (MaxBlocks < MinBlocks || MaxBlocks > 200000) {
		errs() << "Flattening: Invalid MaxBlocks " << MaxBlocks
			<< " (must be >= MinBlocks and <= 200000)\n";
		return false;
	}

	if (FakeCases > 64) {
		errs() << "Flattening: FakeCases too large (" << FakeCases
			<< ", must be <= 64)\n";
		return false;
	}

	return true;
}


// ============================================================================
// Split basic block
// ============================================================================

SplitConfig SplitConfig::fromPassConfig(const PassConfig& pc) {
	SplitConfig cfg;
	cfg.enable = pc.enabled;

	try {
		if (pc.params.count("num")) {
			cfg.num = std::stoi(pc.params.at("num"));
		}
	}
	catch (const std::exception& e) {
		errs() << "Error parsing Split parameters: " << e.what() << "\n";
		cfg.enable = false;
	}

	return cfg;
}

bool SplitConfig::validate() const {
	if (!enable) return true;

	if (num < 2 || num > 10) {
		errs() << "Split: Invalid num " << num
			<< " (must be 2-10)\n";
		return false;
	}

	return true;
}


// ============================================================================
// Substitution
// ============================================================================

SubstitutionConfig SubstitutionConfig::fromPassConfig(const PassConfig& pc) {
	SubstitutionConfig cfg;
	cfg.enable = pc.enabled;

	try {
		if (pc.params.count("loop")) {
			cfg.loop = std::stoi(pc.params.at("loop"));
		}
		if (pc.params.count("maxSites")) {
			cfg.maxSites = (unsigned)std::stoul(pc.params.at("maxSites"));

		}
	}
	catch (const std::exception& e) {
		errs() << "Error parsing Substitution parameters: " << e.what() << "\n";
		cfg.enable = false;
	}

	return cfg;
}

bool SubstitutionConfig::validate() const {
	if (!enable) return true;

	if (loop < 1 || loop > 10) {
		errs() << "Substitution: Invalid loop count " << loop
			<< " (must be 1-10)\n";
		return false;
	}
	if (maxSites > 100000) {
		errs() << "Substitution: Invalid maxSites " << maxSites
			<< " (must be 0..100000)\n";
		return false;

	}
	return true;
}


// ============================================================================
// MBA
// ============================================================================

MBAConfig MBAConfig::fromPassConfig(const PassConfig& pc) {
	MBAConfig cfg;
	cfg.enable = pc.enabled;
	try {
		if (pc.params.count("prob")) {
			cfg.prob = std::stoi(pc.params.at("prob"));
		}
		if (pc.params.count("depth")) {
			cfg.maxDepth = (unsigned)std::stoul(pc.params.at("depth"));
		}
		if (pc.params.count("maxDepth")) {
			cfg.maxDepth = (unsigned)std::stoul(pc.params.at("maxDepth"));

		}
		if (pc.params.count("maxSites")) {
			cfg.maxSites = (unsigned)std::stoul(pc.params.at("maxSites"));

		}

		// Advanced MBA
		if (pc.params.count("linearTermsMin"))
			cfg.linearTermsMin = (unsigned)std::stoul(pc.params.at("linearTermsMin"));
		if (pc.params.count("linearTermsMax"))
			cfg.linearTermsMax = (unsigned)std::stoul(pc.params.at("linearTermsMax"));
		// short aliases
		if (pc.params.count("termsMin"))
			cfg.linearTermsMin = (unsigned)std::stoul(pc.params.at("termsMin"));
		if (pc.params.count("termsMax"))
			cfg.linearTermsMax = (unsigned)std::stoul(pc.params.at("termsMax"));

		if (pc.params.count("enableNonLinear"))
			cfg.enableNonLinear = (pc.params.at("enableNonLinear") != "0");
		if (pc.params.count("nonLinearWeight"))
			cfg.nonLinearWeight = (unsigned)std::stoul(pc.params.at("nonLinearWeight"));
		if (pc.params.count("nonLinearProb"))
			cfg.nonLinearWeight = (unsigned)std::stoul(pc.params.at("nonLinearProb"));

		if (pc.params.count("enableLayered"))
			cfg.enableLayered = (pc.params.at("enableLayered") != "0");
		if (pc.params.count("layeredWindow"))
			cfg.layeredWindow = (unsigned)std::stoul(pc.params.at("layeredWindow"));
		if (pc.params.count("layeredBudget"))
			cfg.layeredBudget = (unsigned)std::stoul(pc.params.at("layeredBudget"));
	}
	catch (const std::exception& e) {
		errs() << "Error parsing MBA parameters: " << e.what() << "\n";
		cfg.enable = false;
	}
	return cfg;
}

bool MBAConfig::validate() const {
	if (!enable)
		return true;

	if (prob < 0 || prob > 100) {
		errs() << "MBA: Invalid probability " << prob << " (must be 0-100)\n";
		return false;
	}
	if (maxDepth < 1 || maxDepth > 10) {
		errs() << "MBA: Invalid maxDepth " << maxDepth << " (must be 1-10)\n";
		return false;

	}
	if (maxSites < 1 || maxSites > 5000) {
		errs() << "MBA: Invalid maxSites " << maxSites << " (must be 1-5000)\n";
		return false;
	}

	// Advanced MBA validation
	if (linearTermsMin < 1 || linearTermsMin > 64) {
		errs() << "MBA: Invalid linearTermsMin " << linearTermsMin << " (must be 1-64)\n";
		return false;

	}
	if (linearTermsMax < linearTermsMin || linearTermsMax > 96) {
		errs() << "MBA: Invalid linearTermsMax " << linearTermsMax
			<< " (must be >= linearTermsMin and <= 96)\n";
		return false;

	}
	if (nonLinearWeight > 100) {
		errs() << "MBA: Invalid nonLinearWeight " << nonLinearWeight << " (must be 0-100)\n";
		return false;

	}
	if (layeredWindow > 256) {
		errs() << "MBA: Invalid layeredWindow " << layeredWindow << " (must be 0-256)\n";
		return false;

	}
	if (layeredBudget > 32) {
		errs() << "MBA: Invalid layeredBudget " << layeredBudget << " (must be 0-32)\n";
		return false;

	}
	return true;
}

// ============================================================================
// Semantic diffusion
// ============================================================================

SemanticDiffusionConfig SemanticDiffusionConfig::fromPassConfig(const PassConfig& pc) {
	SemanticDiffusionConfig cfg;
	cfg.enable = pc.enabled;
	auto it = pc.params.find("prob");
	if (it != pc.params.end()) cfg.prob = std::stoi(it->second);
	it = pc.params.find("slots");
	if (it != pc.params.end()) cfg.slots = std::stoi(it->second);
	it = pc.params.find("maxSites");
	if (it != pc.params.end()) cfg.maxSites = std::stoi(it->second);
	return cfg;

}

bool SemanticDiffusionConfig::validate() const {
	if (!enable) return true;
	if (prob < 1 || prob > 100) return false;
	if (slots < 1 || slots > 8) return false;
	if (maxSites < 1 || maxSites > 2000) return false;
	return true;

}


// ============================================================================
// String encryption
// ============================================================================

StringEncryptionConfig
StringEncryptionConfig::fromPassConfig(const PassConfig& pc) {
	StringEncryptionConfig cfg;
	cfg.enable = pc.enabled;

	try {
		// minlen / minLength / min  � minimum string length
		for (StringRef key : {"minlen", "minlength", "min"}) {
			if (pc.params.count(key.str())) {
				cfg.minLength = std::stoi(pc.params.at(key.str()));
				break;
			}
		}

		// aes=0|1  � enable/disable AES-CTR (default: 1)
		if (pc.params.count("aes"))
			cfg.useAES = (pc.params.at("aes") != "0");

		// keysplit=0|1  � split key across segments (default: 1)
		if (pc.params.count("keysplit"))
			cfg.keySplit = (pc.params.at("keysplit") != "0");

		// cipher=chacha|aes|xor  (default: aes/legacy). chacha -> tableless path.
		if (pc.params.count("cipher")) {
			const std::string& v = pc.params.at("cipher");
			if (v == "chacha")   { cfg.useChaCha = true;  cfg.useAES = true;  }
			else if (v == "aes") { cfg.useChaCha = false; cfg.useAES = true;  }
			else if (v == "xor") { cfg.useChaCha = false; cfg.useAES = false; }
		}
	}
	catch (const std::exception& e) {
		errs() << "[strenc] error parsing params: " << e.what() << "\n";
		cfg.enable = false;
	}

	return cfg;
}

bool StringEncryptionConfig::validate() const {
	if (!enable) return true;

	if (minLength < 1 || minLength > 100) {
		errs() << "[strenc] invalid minLength=" << minLength
			<< " (must be 1�100)\n";
		return false;
	}
	return true;
}

// ============================================================================
// Anti-decompilation
// ============================================================================

int AntiDecompilerConfig::effectiveProb(std::string_view techName) const {
	if (techName == "asmGadgets"     && asmProb         >= 0) return asmProb;
	if (techName == "indirectBr"     && ibrProb         >= 0) return ibrProb;
	if (techName == "deadDecoy"      && decoyProb       >= 0) return decoyProb;
	if (techName == "callTrampoline" && callProb        >= 0) return callProb;
	if (techName == "aliasConfusion" && aliasProb       >= 0) return aliasProb;
	if (techName == "fakeLoop"       && fakeLoopProb    >= 0) return fakeLoopProb;
	if (techName == "rdtscStretch"   && rdtscProb       >= 0) return rdtscProb;
	if (techName == "constLaunder"   && constLaunderProb >= 0) return constLaunderProb;
	return prob;
}

unsigned AntiDecompilerConfig::effectiveStrength(std::string_view techName) const {
	if (techName == "deadDecoy"      && decoyStrength >= 0)
		return (unsigned)decoyStrength;
	if (techName == "stackPollution" && stackStrength >= 0)
		return (unsigned)stackStrength;
	return strength;
}

AntiDecompilerConfig AntiDecompilerConfig::fromPassConfig(const PassConfig& pc) {
	AntiDecompilerConfig cfg;
	cfg.enable = pc.enabled;

	try {
		if (pc.params.count("prob"))
			cfg.prob = std::stoi(pc.params.at("prob"));
		if (pc.params.count("maxSites"))
			cfg.maxSites = (unsigned)std::stoul(pc.params.at("maxSites"));
		if (pc.params.count("strength"))
			cfg.strength = (unsigned)std::stoul(pc.params.at("strength"));

		// Individual toggles (0/1 or true/false)
		auto boolParam = [&](const char* key) -> std::optional<bool> {
			auto it = pc.params.find(key);
			if (it == pc.params.end()) return std::nullopt;
			return it->second != "0" && it->second != "false";
			};

		if (auto v = boolParam("indirectBr"))      cfg.enableIndirectBr = *v;
		if (auto v = boolParam("asmAntiDisasm"))    cfg.enableAsmAntiDisasm = *v;
		if (auto v = boolParam("stackPollution"))   cfg.enableStackPollution = *v;
		if (auto v = boolParam("deadCodeDecoys"))   cfg.enableDeadCodeDecoys = *v;
		if (auto v = boolParam("callObfuscation"))  cfg.enableCallObfuscation = *v;
		if (auto v = boolParam("aliasConfusion"))   cfg.enableAliasConfusion = *v;
		if (auto v = boolParam("fakeLoop"))         cfg.enableFakeLoop = *v;
		if (auto v = boolParam("rdtscStretch"))     cfg.enableRdtscStretch = *v;
		if (auto v = boolParam("constLaunder"))     cfg.enableConstLaunder = *v;

		// Shorthand aliases
		if (auto v = boolParam("asm"))    cfg.enableAsmAntiDisasm = *v;
		if (auto v = boolParam("ibr"))    cfg.enableIndirectBr = *v;
		if (auto v = boolParam("decoy"))  cfg.enableDeadCodeDecoys = *v;
		if (auto v = boolParam("alias"))  cfg.enableAliasConfusion = *v;
		if (auto v = boolParam("loop"))   cfg.enableFakeLoop = *v;
		if (auto v = boolParam("rdtsc"))  cfg.enableRdtscStretch = *v;
		if (auto v = boolParam("clndr"))  cfg.enableConstLaunder = *v;

		// Per-technique probability overrides.
		if (pc.params.count("asmProb"))      cfg.asmProb      = std::stoi(pc.params.at("asmProb"));
		if (pc.params.count("ibrProb"))      cfg.ibrProb      = std::stoi(pc.params.at("ibrProb"));
		if (pc.params.count("decoyProb"))    cfg.decoyProb    = std::stoi(pc.params.at("decoyProb"));
		if (pc.params.count("callProb"))     cfg.callProb     = std::stoi(pc.params.at("callProb"));
		if (pc.params.count("aliasProb"))    cfg.aliasProb    = std::stoi(pc.params.at("aliasProb"));
		if (pc.params.count("fakeLoopProb")) cfg.fakeLoopProb = std::stoi(pc.params.at("fakeLoopProb"));
		if (pc.params.count("rdtscProb"))    cfg.rdtscProb    = std::stoi(pc.params.at("rdtscProb"));
		if (pc.params.count("constLaunderProb"))
			cfg.constLaunderProb = std::stoi(pc.params.at("constLaunderProb"));

		// Per-technique strength overrides.
		if (pc.params.count("decoyStrength"))
			cfg.decoyStrength = std::stoi(pc.params.at("decoyStrength"));
		if (pc.params.count("stackStrength"))
			cfg.stackStrength = std::stoi(pc.params.at("stackStrength"));

		// External gadget JSON path.
		if (pc.params.count("gadgets"))
			cfg.gadgetsFile = pc.params.at("gadgets");
		// Inline ad-hoc asm gadgets (';' separated raw bodies).
		if (pc.params.count("asmInline"))
			cfg.inlineAsm = pc.params.at("asmInline");

		// Technique / category filters (comma separated).
		auto splitCsv = [](const std::string& s) {
			std::vector<std::string> out;
			std::string cur;
			for (char c : s) {
				if (c == ',') {
					if (!cur.empty()) { out.push_back(cur); cur.clear(); }
				} else if (c != ' ' && c != '\t') {
					cur.push_back(c);
				}
			}
			if (!cur.empty()) out.push_back(cur);
			return out;
		};
		if (pc.params.count("techniques"))
			cfg.techniquesAllowed = splitCsv(pc.params.at("techniques"));
		if (pc.params.count("categories"))
			cfg.categoriesAllowed = splitCsv(pc.params.at("categories"));
	}
	catch (const std::exception& e) {
		errs() << "Error parsing AntiDecompiler parameters: " << e.what() << "\n";
		cfg.enable = false;
	}

	return cfg;
}

bool AntiDecompilerConfig::validate() const {
	if (!enable) return true;
	if (prob < 1 || prob > 100) {
		errs() << "AntiDecompiler: Invalid prob " << prob << " (must be 1-100)\n";
		return false;
	}
	if (maxSites < 1 || maxSites > 500) {
		errs() << "AntiDecompiler: Invalid maxSites " << maxSites << " (must be 1-500)\n";
		return false;
	}
	if (strength > 3) {
		errs() << "AntiDecompiler: Invalid strength " << strength << " (must be 0-3)\n";
		return false;
	}
	auto checkProb = [&](const char* name, int v) {
		if (v == -1) return true;
		if (v < 1 || v > 100) {
			errs() << "AntiDecompiler: Invalid " << name << " " << v
			       << " (must be 1-100 or -1)\n";
			return false;
		}
		return true;
	};
	if (!checkProb("asmProb",          asmProb))          return false;
	if (!checkProb("ibrProb",          ibrProb))          return false;
	if (!checkProb("decoyProb",        decoyProb))        return false;
	if (!checkProb("callProb",         callProb))         return false;
	if (!checkProb("aliasProb",        aliasProb))        return false;
	if (!checkProb("fakeLoopProb",     fakeLoopProb))     return false;
	if (!checkProb("rdtscProb",        rdtscProb))        return false;
	if (!checkProb("constLaunderProb", constLaunderProb)) return false;
	if (decoyStrength != -1 && (decoyStrength < 0 || decoyStrength > 3)) {
		errs() << "AntiDecompiler: Invalid decoyStrength " << decoyStrength
		       << " (must be 0-3 or -1)\n";
		return false;
	}
	if (stackStrength != -1 && (stackStrength < 0 || stackStrength > 3)) {
		errs() << "AntiDecompiler: Invalid stackStrength " << stackStrength
		       << " (must be 0-3 or -1)\n";
		return false;
	}
	return true;
}

// ============================================================================
// Virtual calls
// ============================================================================

VirtualCallConfig VirtualCallConfig::fromPassConfig(const PassConfig& pc) {
	VirtualCallConfig cfg;
	cfg.enable = pc.enabled;

	try {
		if (pc.params.count("prob")) {
			cfg.prob = std::stoi(pc.params.at("prob"));
		}
		if (pc.params.count("maxSites")) {
			cfg.maxSites = (unsigned)std::stoul(pc.params.at("maxSites"));
		}


		if (pc.params.count("opaqueVTableNames")) cfg.opaqueVTableNames = (pc.params.at("opaqueVTableNames") != "0");
		if (pc.params.count("opaqueNames")) cfg.opaqueVTableNames = (pc.params.at("opaqueNames") != "0");

		if (pc.params.count("addDecoyEntries")) cfg.addDecoyEntries = (pc.params.at("addDecoyEntries") != "0");
		if (pc.params.count("decoys")) cfg.addDecoyEntries = (pc.params.at("decoys") != "0");
		if (pc.params.count("decoyMin")) cfg.decoyMin = (unsigned)std::stoul(pc.params.at("decoyMin"));
		if (pc.params.count("decoyMax")) cfg.decoyMax = (unsigned)std::stoul(pc.params.at("decoyMax"));

		if (pc.params.count("varyIndexPerCallsite")) cfg.varyIndexPerCallsite = (pc.params.at("varyIndexPerCallsite") != "0");
		if (pc.params.count("varyIndex")) cfg.varyIndexPerCallsite = (pc.params.at("varyIndex") != "0");
		if (pc.params.count("indexStrength")) cfg.indexStrength = (unsigned)std::stoul(pc.params.at("indexStrength"));

		if (pc.params.count("mergeVTables")) cfg.mergeVTables = (pc.params.at("mergeVTables") != "0");
		if (pc.params.count("merge")) cfg.mergeVTables = (pc.params.at("merge") != "0");
	}
	catch (const std::exception& e) {
		errs() << "Error parsing VirtualCall parameters: " << e.what() << "\n";
		cfg.enable = false;
	}

	return cfg;
}

bool VirtualCallConfig::validate() const {
	if (!enable)
		return true;

	if (prob < 0 || prob > 100) {
		errs() << "VirtualCall: Invalid probability " << prob
			<< " (must be 0-100)\n";
		return false;
	}
	if (maxSites > 100000) {
		errs() << "VirtualCall: Invalid maxSites " << maxSites
			<< " (must be 0..100000)\n";
		return false;

	}
	if (indexStrength > 3) return false;
	if (decoyMax < decoyMin) return false;
	if (decoyMax > 64) return false;

	return true;
}


// ============================================================================
// Optimization shield
// ============================================================================

ShieldConfig ShieldConfig::fromPassConfig(const PassConfig& pc) {
	ShieldConfig cfg;
	cfg.enable = pc.enabled;
	auto& P = pc.params;
	if (P.count("maxSites"))
		cfg.maxSites = std::stoul(P.at("maxSites"));
	if (P.count("volatile"))
		cfg.volatileBarriers = (P.at("volatile") != "0");
	if (P.count("identity"))
		cfg.opaqueIdentities = (P.at("identity") != "0");
	if (P.count("dse"))
		cfg.deadStoreProtect = (P.at("dse") != "0");
	if (P.count("cfg"))
		cfg.cfgGuards = (P.at("cfg") != "0");
	return cfg;

}

bool ShieldConfig::validate() const {
	if (maxSites > 10000)
		return false;
	return true;

}