# Function Merging (`fmerge`)

`fmerge` collapses several distinct functions into a single **super-function** whose extra
*selector* parameter picks which original body runs. All direct calls to the originals are
rewritten to call the super-function with the appropriate selector. This destroys function
boundaries in the call graph and forces an analyst to reason about a hidden selector value
to isolate any one behavior.

This is **not** LLVM's `MergeFunctions` (which folds *identical* functions to save size).
`fmerge` deliberately merges *dissimilar* functions for confusion, and it amplifies every
downstream function pass — after merging, `flattening` / `bcf` / `mba` / `vm` operate on one
large body that mixes unrelated logic.

`fmerge` is a **module-only** pass (like `strenc`) and runs **before** the function pipeline
so downstream passes see the merged result.

---

## Opt-in, annotation-driven

Nothing is merged unless annotated. Consistent with every other xollvm pass, `fmerge` is
per-function opt-in via `__attribute__((annotate("obf: fmerge...")))`.

### Group annotation

Functions that share a `group=` label are merged into the same super-function:

```c
__attribute__((annotate("obf: fmerge(group=alpha)"))) int  parse_hdr(const u8*, int);
__attribute__((annotate("obf: fmerge(group=alpha)"))) long crc_step(long, const u8*);
__attribute__((annotate("obf: fmerge(group=alpha)"))) void reset_ctx(ctx_t*);
// parse_hdr + crc_step + reset_ctx  ->  __obf_merged_alpha

__attribute__((annotate("obf: fmerge(group=beta)")))  ...   // separate super-function
__attribute__((annotate("obf: fmerge")))               ...   // bare: auto-pool
```

- **`fmerge(group=NAME)`** — explicit bucket. All same-`NAME` functions become one
  super-function. The user controls exactly which functions merge together.
- **bare `fmerge`** (no `group=`) — dropped into the default `_auto` pool and chunked by the
  `chunk=` knob (default 4).
- **no annotation** — the function is left untouched.

A function belongs to exactly one group (one annotation). A group needs **≥ 2** eligible
members to be merged; smaller groups are skipped (a single-function trampoline adds nothing).

---

## Eligibility (skip-list)

An annotated function is dropped from its group (with a warning) unless **all** hold:

- `hasLocalLinkage()` — internal/private, every use is visible and rewritable.
- Not a declaration, not `available_externally`.
- Not vararg.
- No exception handling: no `invoke` / `landingpad` / personality function.
- No inline asm, no `musttail` call, no `blockaddress` / `indirectbr` targeting it.
- No `byval` / `sret` / `inalloca` / `preallocated` / `swiftself` / `swiftasync` /
  `swifterror` parameters (memory repacking would break the ABI copy semantics).
- Not `naked`.
- Not address-taken (v1). Only functions whose every use is a direct-call operand qualify.
- Instruction count within `[minInsts, maxInsts]` (skip trivial functions, bound blow-up).
- Not in `llvm.used` / `llvm.compiler.used`.

If dropping members takes a group below 2, the whole group is skipped — merges are never
partial.

---

## Transformation

### Unified signature (memory ABI)

Arguments and the return value pass through memory, side-stepping calling-convention
lowering:

```llvm
define internal i64 @__obf_merged_<label>(i64 %selector, ptr %argpack, ptr %retslot)
```

- `%argpack` — pointer to a caller-allocated struct holding that callee's arguments.
- `%retslot` — pointer to a caller-allocated return slot (`null` for `void` callees).
- `%selector` — obfuscated index selecting the body.

The super-function is `internal noinline` (the inliner must not undo the merge) and carries
no parameter attributes.

### Body

```llvm
entry:
  %idx = <deobfuscate %selector>            ; identity when opaqueSel=0
  switch i64 %idx, label %trap [ i64 0, %case0  i64 1, %case1  ... ]

case_i:                                     ; cloned body of member i
  ; %a0 = load T0, ptr gep(%struct_i, %argpack, 0)
  ; %a1 = load T1, ptr gep(%struct_i, %argpack, 1) ...
  ; <cloned instructions of member i, args remapped to the loads above>
  ; each `ret X`  ->  store X, ptr %retslot ; br %exit      (void: just br %exit)

exit:
  ret i64 0
trap:
  unreachable                               ; (optional llvm.trap for anti-tamper)
```

Bodies are cloned with a `ValueToValueMapTy`: each member's `Argument` is pre-mapped to a
load from `%argpack`, blocks are cloned into the super-function, then instructions are
remapped. `ret` terminators are rewritten to `store`-to-`retslot` + branch to `exit`.

### Call-site rewrite

Every direct `call F_i(a0, a1, ...)` in the module (including calls that end up **inside** a
merged body, so self-recursion is handled) becomes:

```llvm
%pack = alloca %struct_i                    ; hoisted to caller entry block
store a0, ptr gep(%struct_i, %pack, 0)
store a1, ptr gep(%struct_i, %pack, 1) ...
%ret  = alloca RetTy_i                      ; omitted for void
call i64 @__obf_merged_<label>(i64 <sel_i>, ptr %pack, ptr %ret)
%v = load RetTy_i, ptr %ret                 ; omitted for void
; RAUW original call result -> %v
```

`alloca`s are placed in the caller's entry block to avoid unbounded stack growth in loops.

### Opaque selector (`opaqueSel=1`, default)

The call-site selector is not the literal index. A group-wide key `K` obfuscates it:
`sel_i = i XOR K`, with `K` materialized through an opaque predicate (`OpaqueUtils`); the
dispatch computes `%idx = %selector XOR K`. Downstream `mba` / `constenc` hide `K` further.
With `opaqueSel=0` the selector is the raw index.

### Cleanup

Original functions whose call sites are all rewritten and that are not address-taken are
erased. Each group is committed **transactionally**: bodies are built into a fresh
super-function, `verifyFunction` / `verifyModule` gate the result, and on failure the whole
group is rolled back (super-function discarded, originals untouched). Debug info on merged
bodies is stripped by default (`stripDbg=1`) to avoid leaking original identities.

---

## Determinism

Seed derives from the module seed (`ObfuscationAnnotationCache::ModuleSeed`) mixed with
`"fmerge"`. All collections are sorted by stable keys (function name; call sites by parent
name + index) before iteration — never rely on `use`/map iteration order. The `_auto` pool
shuffle uses the seeded `Rng`.

---

## Configuration

| key         | scope     | default  | meaning                                             |
|-------------|-----------|----------|-----------------------------------------------------|
| `group`     | per-func  | —        | merge-bucket label (string)                         |
| `chunk`     | group     | 4        | `_auto`-pool chunk size (bare `fmerge` only, 2–16)  |
| `opaqueSel` | group     | 1        | obfuscate the selector                              |
| `dispatch`  | group     | `switch` | dispatch shape (`switch` or `indirectbr`)           |
| `minInsts`  | group     | 4        | skip functions smaller than this                    |
| `maxInsts`  | group     | 2000     | skip functions larger than this (blow-up bound)     |
| `stripDbg`  | group     | 1        | drop debug info on merged bodies                    |
| `thunkAddrTaken` | group | 0        | merge address-taken / external funcs via a thunk (v2) |
| `launderSel` | group    | 0        | load call-site selectors from a mutable global (v3, defeats devirt) |

Only `group=` is inherently per-function. Group-wide knobs are resolved from the
lexicographically-first member's params; a warning is emitted if members disagree. Global CLI
defaults apply when an annotation omits a knob.

---

## Pipeline placement

- Canonical id **`fmerge`**; aliases `funcmerge`, `merge`. Module-only.
- Runs first, before the function pipeline, so `flattening` / `bcf` / `mba` / `vm` amplify the
  merged super-functions. No hard conflicts with other passes.

---

## v2 — thunks + indirectbr dispatch

### Thunks for address-taken / external functions (`thunkAddrTaken=1`)

v1 skips any function that is externally visible or has its address taken (no way to rewrite
every use). v2 merges them anyway: the body is cloned into the super-function as usual, but the
original function is **not erased** — its body is replaced with a thin forwarder (thunk) that
packs its own arguments and tail-calls the super-function:

```llvm
define <orig-linkage> RetTy_i @Fi(origparams...) {
  %pack = alloca %struct_i
  store <params> into %pack
  %ret  = alloca RetTy_i            ; omitted for void
  call i64 @__obf_merged_G(i64 <sel_i>, ptr %pack, ptr %ret)
  ret <load %ret>                   ; or ret void
}
```

The symbol, signature, and address are preserved, so function pointers and cross-TU callers
keep working while the real logic lives in the merged body. Direct call sites are still
rewritten straight to the super-function (bypassing the thunk); only indirect / external uses
go through it. Eligibility with `thunkAddrTaken=1` additionally admits external-linkage
(defined) and address-taken functions and `llvm.used` members; the hard skips (EH, vararg,
byval/sret, naked, inline asm, musttail, blockaddress-in-body) still apply. The thunk clears
function-level memory-effect / `willreturn` / `norecurse` attributes (it now calls into the
merged body) but keeps ABI-relevant param/return attributes intact.

### indirectbr jump-table dispatch (`dispatch=indirectbr`)

Instead of a `switch`, the deobfuscated index selects a target from a private
`[N x ptr]` table of `blockaddress`es and branches via `indirectbr`:

```llvm
@__obf_fmjt_G = internal constant [N x ptr] [ ptr blockaddress(@__obf_merged_G, %case0), ... ]
...
%tgt = load ptr, ptr getelementptr([N x ptr], ptr @__obf_fmjt_G, i64 0, i64 %idx)
indirectbr ptr %tgt, [ label %case0, label %case1, ... ]
```

This erases the switch structure decompilers rely on for CFG recovery. The selector is always
in range by construction, so no bounds check is emitted (a corrupted selector faults — an
acceptable anti-tamper property).

## Roadmap

- **v1** (done): internal, direct-call-only, memory ABI, `switch` dispatch, opaque selector,
  self-recursion, erase originals, transactional verify.
- **v2** (in progress): thunks for address-taken / externally-visible functions; `indirectbr`
  jump-table dispatch.
- **v2.1** (done): dissimilarity-driven `_auto` grouping — members are hashed by shape
  (return type / arity / param types / size), sorted, and round-robined across chunks so each
  super-function mixes maximally unrelated behaviors. Default on (`dissimilar=1`); only affects
  the bare-`fmerge` `_auto` pool (explicit `group=` buckets are honored verbatim).
- **v3** (in progress): selector laundering (`launderSel=1`) — call-site selectors are read
  from a mutable per-group global `@__obf_fmsel_<label>` via a **volatile load** instead of an
  inline constant, so constant-propagation / symbolic devirtualization can't recover which
  behavior a call runs. Cross-group merged→merged calls already work (a call from one group's
  member into another's is rewritten to the other super-function). Remaining: tighter `constenc`
  integration on the selector key.
