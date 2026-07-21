/*===----------------------------------------------------------------------===*\
|*                                                                            *|
|*  obf_annotations.h  --  LLVM Obfuscator annotation cheat-sheet             *|
|*                                                                            *|
|*  Drop this header into your own project and annotate functions with the    *|
|*  OBF() macro (or one of the ready-made presets) to drive the in-tree LLVM  *|
|*  Obfuscator pass. It is a *reference* header: every knob the pass reads is  *|
|*  documented below with its accepted range and default.                     *|
|*                                                                            *|
|*  This file is standalone. It has no dependencies, defines only macros, and *|
|*  compiles to NOTHING under non-clang compilers (the annotations are a      *|
|*  clang extension). Ship it, include it, forget it.                         *|
|*                                                                            *|
|*  Quick start:                                                              *|
|*                                                                            *|
|*      #include "obf_annotations.h"                                          *|
|*                                                                            *|
|*      OBF("vm(hardened=1), mba, bcf")                                       *|
|*      int secret_check(const char *pw) { ... }                             *|
|*                                                                            *|
|*      OBF_MAX                                                               *|
|*      int license_verify(void) { ... }                                     *|
|*                                                                            *|
|*  Then compile with clang using the obfuscator-enabled toolchain. Only      *|
|*  functions carrying an annotation are transformed; everything else is      *|
|*  left untouched.                                                           *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef OBF_ANNOTATIONS_H
#define OBF_ANNOTATIONS_H

/*===----------------------------------------------------------------------===*\
|*  CORE MACROS                                                               *|
\*===----------------------------------------------------------------------===*/

/*
 * OBF(spec)
 *   Attach an obfuscation spec to a function. `spec` is a STRING LITERAL
 *   holding a comma-separated pass list, e.g.  OBF("mba, bcf(prob=80)").
 *   The "obf: " prefix is added for you.
 *
 * OBF_FN(spec)
 *   Same as OBF() but also marks the function `noinline`. Recommended for
 *   small/hot functions: without it the inliner may copy the body into a
 *   caller that has no annotation, defeating per-function obfuscation.
 *
 * On non-clang compilers both macros expand to nothing, so the same source
 * still builds with gcc/msvc (just un-obfuscated).
 */
#if defined(__clang__)
#  define OBF(spec)    __attribute__((annotate("obf: " spec)))
#  define OBF_FN(spec) __attribute__((annotate("obf: " spec), noinline))
#else
#  define OBF(spec)
#  define OBF_FN(spec)
#endif

/*===----------------------------------------------------------------------===*\
|*  READY-MADE PRESETS                                                        *|
|*                                                                            *|
|*  Rough strength / size-cost ladder. Pick the lowest tier that meets your   *|
|*  threat model — each step up multiplies code size and slows the function.  *|
\*===----------------------------------------------------------------------===*/

/* Cheap arithmetic/CFG noise. Negligible size hit. Stops casual reading. */
#define OBF_MINIMAL     OBF("substitution, mba(prob=40)")

/* Everyday hardening: MBA + bogus control flow + block splitting.          */
#define OBF_BALANCED    OBF("mba, bcf, split")

/* Heavy static-analysis resistance: adds control-flow flattening + strings
 * + anti-decompiler gadgets + an anti-optimization shield to keep -O2 from
 * peeling the disguise back off.                                            */
#define OBF_AGGRESSIVE  OBF("flattening, mba, bcf, split, strenc, adec, shield")

/* Maximum: routes the function through the bytecode VM (hardened profile)
 * and stacks the static passes on top. Largest + slowest; reserve for the
 * few functions that truly warrant it (license/root-of-trust checks).      */
#define OBF_MAX         OBF("vm(hardened=1), mba, bcf, flattening, strenc, adec, shield")

/* Convenience one-liners for a single technique at its defaults. */
#define OBF_VM          OBF("vm")
#define OBF_VM_HARDENED OBF("vm(hardened=1)")
#define OBF_STRINGS     OBF("strenc")
#define OBF_FLATTEN     OBF("flattening")
#define OBF_CONSTENC    OBF("constenc")
#define OBF_FMERGE      OBF("fmerge")

/*===----------------------------------------------------------------------===*\
|*  SPEC SYNTAX                                                               *|
|*                                                                            *|
|*    "pass1, pass2(k=v), pass3(k1=v1, k2=v2)"                                *|
|*                                                                            *|
|*  - Comma-separated pass list (commas inside (...) are safe).              *|
|*  - Params are key=value; bare values, "quoted values", 0/1, and           *|
|*    true/false/yes/no/on/off are all accepted for bools.                   *|
|*  - Unknown pass names are rejected with a warning; unknown params are     *|
|*    ignored. Pass names are case-insensitive.                              *|
|*  - Multiple annotations on one function are merged (later params win).    *|
|*  - Top-level budget knobs may appear as params on any pass:               *|
|*        budget=N        IR-growth multiplier for this function             *|
|*        budgetMax=N     absolute instruction ceiling for this function     *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/*===----------------------------------------------------------------------===*\
|*  PASS REFERENCE  (canonical name — aliases — params [range] (default))    *|
\*===----------------------------------------------------------------------===*/

/*----------------------------------------------------------------------------
 * mba                                                    Mixed Boolean-Arith
 *   Rewrites arithmetic/bitwise ops into equivalent MBA identities.
 *
 *   prob            [0-100]  (75)   % of eligible sites rewritten
 *   depth|maxDepth  [1-10]   (?)    recursive rewrite depth
 *   maxSites        [1-5000]        cap on rewritten sites
 *   termsMin|linearTermsMin  [1-64]     linear-combination term floor
 *   termsMax|linearTermsMax  [>=min,<=96] linear-combination term ceiling
 *   enableNonLinear [0/1]           allow non-linear identities
 *   nonLinearWeight|nonLinearProb [0-100]  non-linear mix weight
 *   enableLayered   [0/1]           layered/window rewriting
 *   layeredWindow   [0-256]         window size for layered pass
 *   layeredBudget   [0-32]          layered rewrite budget
 *
 *   e.g.  OBF("mba(prob=90, depth=3, enableNonLinear=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * constenc                                               Constant Encryption
 *   Encrypts numeric (int + FP) constants; each is reconstructed at runtime
 *   by a decrypt sequence. Runs first, before other passes touch the CFG.
 *
 *   prob      [0-100]     (60)   % of eligible constants encrypted
 *   maxSites  [0-100000]  (200)  per-function cap on encrypted sites
 *   minAbs                (2)    skip constants with |C| < minAbs
 *   encInt    [0/1]       (1)    encrypt integer constants
 *   encFP     [0/1]       (1)    encrypt floating-point constants
 *   wrapMBA   [0/1]       (0)    wrap the decrypt expr in MBA for extra hardness
 *
 *   e.g.  OBF("constenc(prob=80, encFP=0)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * bcf                                                    Bogus Control Flow
 *   Wraps blocks in opaque-predicate-guarded fake branches.
 *
 *   prob      [0-100]     (?)   % of blocks that get a bogus guard
 *   loop      [1-10]            times the transform is re-applied
 *   maxBlocks [0-100000]        skip functions above this block count
 *
 *   e.g.  OBF("bcf(prob=80, loop=2)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * split                                                  Basic-Block Splitting
 *   Chops basic blocks into smaller pieces to fragment the CFG.
 *
 *   num  [2-10]  (?)   number of pieces each eligible block is split into
 *
 *   e.g.  OBF("split(num=4)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * substitution                          alias: sub      Instruction Subst.
 *   Replaces simple ops with longer equivalent instruction sequences.
 *
 *   loop     [1-10]        applications of the substitution table
 *   maxSites [0-100000]    cap on substituted sites
 *
 *   e.g.  OBF("substitution(loop=2)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * flattening                            alias: fla      Control-Flow Flatten
 *   Rebuilds the CFG as a dispatcher-driven state machine.
 *
 *   min|minBlocks   [2-100000]  (?)   minimum blocks to bother flattening
 *   max|maxBlocks   [>=min,<=200000]  maximum blocks handled
 *   indirect|allowIndirect  [0/1]     allow indirectbr dispatch
 *   hybrid          [0/1]             hybrid dispatcher mode
 *   opaque|opaqueState      [0/1]     opaque state variable
 *   fake|fakeTransitions    [0/1]     inject fake state transitions
 *   fakecase|fakeCases      [0-64]    number of fake switch cases
 *   domain|perDispatcherDomain [0/1]  per-dispatcher state domain
 *   ptr|stateptr|obfuscateStatePtr  [0/1]  obfuscate the state pointer
 *   alias|aliasptr|opaqueAliasStatePtr [0/1] opaque-alias the state pointer
 *
 *   e.g.  OBF("flattening(opaque=1, fake=1, fakecase=4)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * vcall                                                  Virtual-Call Disguise
 *   Routes direct calls through synthetic vtables.
 *
 *   prob        [0-100]     (?)   % of call sites disguised
 *   maxSites    [0-100000]        cap on disguised sites
 *   opaqueNames|opaqueVTableNames [0/1] opaque vtable symbol names
 *   decoys|addDecoyEntries [0/1]        add decoy vtable entries
 *   decoyMin / decoyMax                 decoy-entry count range
 *   varyIndex|varyIndexPerCallsite [0/1] vary the dispatch index per site
 *   indexStrength                       index-obfuscation strength
 *   merge|mergeVTables  [0/1]           merge vtables across functions
 *
 *   e.g.  OBF("vcall(prob=60, decoys=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * sdiff                                                  Semantic Diffusion
 *   Spreads a value's definition across extra computation slots.
 *
 *   prob     [1-100]   (?)   % of eligible values diffused
 *   slots    [1-8]           diffusion slots per value
 *   maxSites [1-2000]        cap on diffused sites
 *
 *   e.g.  OBF("sdiff(slots=4)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * strenc                                                 String Encryption
 *   Encrypts string literals; a runtime stub decrypts them lazily. This is a
 *   module-level pass — annotate any one function to enable it module-wide.
 *
 *   min|minlen|minLength [1-100]  (?)  only encrypt strings this long or more
 *   cipher   {chacha|aes|xor}     (aes)  cipher family (chacha = tableless)
 *   aes      [0/1]                (1)   enable AES-CTR (ignored if cipher set)
 *   keysplit [0/1]                (1)   split the key across segments
 *
 *   e.g.  OBF("strenc(cipher=chacha, min=4)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * fmerge                  alias: -                       Function Merging
 *   Merges several functions into one body dispatched by a hidden selector,
 *   erasing per-function boundaries. Module-level and runs first; opt in by
 *   tagging functions with a matching group= label to bucket them together.
 *
 *   group=NAME               bucket label (functions sharing it are merged;
 *                            "" -> the "_auto" pool)
 *   chunk|c   [2-16]   (4)   _auto pool chunk size (functions per merge)
 *   opaque|opaqueSel [0/1](1) obfuscate the selector
 *   dispatch  {switch|indirectbr}  (switch)  dispatch mechanism
 *   min|minInsts       (4)   skip functions below this instruction count
 *   max|maxInsts [>=min,<=100000] (2000)  skip functions above this count
 *   stripDbg  [0/1]    (1)   strip debug info from merged bodies
 *   thunk|thunkAddrTaken [0/1] (0)  merge address-taken/external fns via a thunk
 *   dissim|dissimilar    [0/1] (1)  _auto pool groups maximally-different shapes
 *   launder|launderSel   [0/1] (0)  load call-site selectors from a global
 *                                   (defeats devirtualization)
 *
 *   e.g.  OBF("fmerge(group=checks, dispatch=indirectbr, launder=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * aes_stub                                               AES Runtime Stub
 *   Links the shared AES-CTR runtime stub. Module-level; usually pulled in
 *   automatically by strenc/vm when they need AES — rarely annotated alone.
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * adec                    alias: antidecompiler          Anti-Decompiler
 *   Injects gadgets that break disassemblers/decompilers.
 *
 *   prob      [1-100]   (?)   base per-technique probability
 *   maxSites  [1-500]         cap on gadget sites
 *   strength  [0-3]           global gadget strength
 *
 *   Technique toggles (0/1) — long name / shorthand:
 *     indirectBr / ibr          asmAntiDisasm / asm    deadCodeDecoys / decoy
 *     aliasConfusion / alias    fakeLoop / loop        rdtscStretch / rdtsc
 *     constLaunder / clndr      stackPollution         callObfuscation
 *
 *   Per-technique prob overrides ([1-100] or -1=use base):
 *     asmProb ibrProb decoyProb callProb aliasProb
 *     fakeLoopProb rdtscProb constLaunderProb
 *   Per-technique strength ([0-3] or -1): decoyStrength stackStrength
 *
 *   Filters / inputs:
 *     techniques="a,b"   whitelist technique names
 *     categories="a,b"   gadget category filter
 *     gadgets="path.json" external gadget file
 *     asmInline="..."    ';'-separated raw asm gadget bodies
 *
 *   e.g.  OBF("adec(prob=50, ibr=1, decoy=1, strength=2)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * shield                  alias: antiopt                 Anti-Optimization
 *   Plants barriers so later -O2/-O3 passes cannot strip the obfuscation.
 *   Add it LAST. (See also OBF_MAX / OBF_AGGRESSIVE which already include it.)
 *
 *   maxSites [0-10000]  (?)   cap on barrier sites
 *   volatile [0/1]            volatile memory barriers
 *   identity [0/1]            opaque identity guards
 *   dse      [0/1]            dead-store-elimination protection
 *   cfg      [0/1]            CFG guards
 *
 *   e.g.  OBF("shield(volatile=1, cfg=1)")
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * vm                      alias: virtualize, virt        Code Virtualization
 *   Compiles the function to bytecode run by an embedded interpreter. The
 *   strongest (and heaviest) technique.
 *
 *   minBlocks        (1)     don't virtualize below this many blocks
 *   maxBlocks        (400)   don't virtualize above this (0 = no limit)
 *   handlerVariants  [1-K] (3)  polymorphic handler-body variants (1 = off)
 *   useAES           (1)     AES-128-CTR bytecode cipher (needs encBytecode)
 *   obfRegIdx        (1)     XOR register indices with a compile-time salt
 *   encDispatch      (1)     encrypt the opcode->handler dispatch table
 *   encBytecode      (1)     encrypt the bytecode stream at load
 *   strongBytecode   (1)     per-position PRF keystream (0 = weak salt^idx)
 *   blindTargets     (1)     XOR-blind bytecode branch targets
 *   hardened         (0)     MBA + opaque predicates + engine hardening;
 *                            implies regEncrypt, gates the anti-debug traps
 *   regEncrypt       (0)     XOR-encrypt the register file at rest
 *   rollingRegKey    (0)     evolve the per-slot register key on each store
 *   antiDebug        (1)     anti-debug traps (active only when hardened=1)
 *   adDispatchThreshold  (5000)  rdtsc cycle delta for the dispatch gate
 *   adHandlerThreshold   (500)   rdtsc cycle delta for handler spot-checks
 *   adDispatchInterval   (64)    check every N fetches (power of 2)
 *   adHandlerProb        [0-100] (10)  % of handlers that carry a trap
 *
 *   e.g.  OBF("vm(hardened=1, handlerVariants=4, rollingRegKey=1)")
 *--------------------------------------------------------------------------*/

/*===----------------------------------------------------------------------===*\
|*  GLOBAL KNOBS (driver command-line flags, not annotations)                *|
|*                                                                            *|
|*  These are set on the opt/clang command line, not in source. Listed here   *|
|*  so the reference is complete:                                             *|
|*                                                                            *|
|*    -obf-seed=N              reproducible-build base seed                   *|
|*    -obf-deterministic       derive a stable seed from the module id        *|
|*    -obf-verbose             log annotation parsing + pass decisions        *|
|*    -obf-verify              verify IR after every pass (fatal on break)    *|
|*    -obf-max-function-insts  skip functions above N instructions            *|
|*    -obf-ir-budget-multiplier  global IR-growth cap (default 50x)           *|
|*    -obf-pipeline-ordering="mba,split,bcf"  force a partial pass order      *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#endif /* OBF_ANNOTATIONS_H */
