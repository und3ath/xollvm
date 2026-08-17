#!/usr/bin/env python3
"""
mba_sle_gen.py — V2 SLE pool generator + vetter.

Mints diverse runtime-zero MBA forms and writes a swappable pool FILE the
obfuscator loads at runtime (regen without rebuilding LLVM/xollvm).

Each pool entry is a nonlinear-lifted SLE form:

    zero(x,y) = lift(f(x,y)) - lift(g(x,y)),   f == g,   lift in {cube, pow4, prodsq}

where
  g = the canonical spelling of a base value V in {add: x+y, sub: x-y}
  f = an SLE-minted spelling of the SAME V: base(V) + a random integer null-space
      vector over the 13-function bitwise basis (so f == V exactly, but structurally
      diverse -> defeats pattern-DB deobfuscators).

The nonlinear lift is what gives strength: SiMBA (linear-MBA simplifier) is out of
scope on a nonlinear expression, and Z3 must bit-blast it. The SLE spelling gives
per-form diversity on top.

Vetting per entry (all must pass to ship it):
  1. exact zero over an exhaustive int32 stress set + random pairs
  2. -O2 fold-resistant (opt does NOT reduce lift(f)-lift(g) to `ret i32 0`)
  3. SiMBA-nonlinear (check_linear_mba says NOT a linear MBA -> SiMBA can't touch)
  4. (optional, sampled) Z3 times out proving it 0 within a budget

Output: a pool file (default utils/sle_pool.txt). Optionally a small compiled-in
fallback header (--fallback include/.../MBASlePool.inc) baked into the binary so
obfuscation always works with no file present.
"""

from __future__ import annotations

import argparse
import os
import random
import subprocess
import sys
import time
from pathlib import Path

import sympy as sp

# --- optional oracles (vetting still runs without them, just skips that gate) ---
_HERE = Path(__file__).resolve().parent
_SIMBA_SRC = _HERE.parent.parent / "SiMBA" / "src"
if _SIMBA_SRC.is_dir() and str(_SIMBA_SRC) not in sys.path:
    sys.path.insert(0, str(_SIMBA_SRC))
try:
    from check_linear_mba import check_linear_mba
    _HAVE_SIMBA = True
except Exception:
    _HAVE_SIMBA = False
try:
    import z3
    _HAVE_Z3 = True
except Exception:
    _HAVE_Z3 = False

W = 32
M = 1 << W
MASK = M - 1

# ── fixed basis order (MUST match the C++ loader) ───────────────────────────
BASIS_ORDER = ["one", "x", "y", "and", "or", "xor",
               "nx", "ny", "nand", "nor", "xnor", "xany", "nxay"]

# truth table over (xb,yb) = 00,01,10,11 ; python word eval ; z3 word eval ; C-string
TT = {
    "one":  [1, 1, 1, 1], "x": [0, 0, 1, 1], "y": [0, 1, 0, 1],
    "and":  [0, 0, 0, 1], "or": [0, 1, 1, 1], "xor": [0, 1, 1, 0],
    "nx":   [1, 1, 0, 0], "ny": [1, 0, 1, 0], "nand": [1, 1, 1, 0],
    "nor":  [1, 0, 0, 0], "xnor": [1, 0, 0, 1], "xany": [0, 0, 1, 0], "nxay": [0, 1, 0, 0],
}
PYF = {
    "one": lambda x, y: MASK, "x": lambda x, y: x, "y": lambda x, y: y,
    "and": lambda x, y: x & y, "or": lambda x, y: x | y, "xor": lambda x, y: x ^ y,
    "nx": lambda x, y: (~x) & MASK, "ny": lambda x, y: (~y) & MASK,
    "nand": lambda x, y: (~(x & y)) & MASK, "nor": lambda x, y: (~(x | y)) & MASK,
    "xnor": lambda x, y: (~(x ^ y)) & MASK, "xany": lambda x, y: x & (~y) & MASK,
    "nxay": lambda x, y: (~x) & y & MASK,
}
# infix C-string for a basis fn over vars "a","b" (SiMBA syntax)
STR = {
    "one": "4294967295", "x": "a", "y": "b", "and": "(a&b)", "or": "(a|b)",
    "xor": "(a^b)", "nx": "(~a)", "ny": "(~b)", "nand": "(~(a&b))", "nor": "(~(a|b))",
    "xnor": "(~(a^b))", "xany": "(a&(~b))", "nxay": "((~a)&b)",
}

# base value V -> canonical coeff vector over BASIS_ORDER (f starts here, plus a null zero)
BASE_COEFFS = {
    "add": {"xor": 1, "and": 2},          # a+b == (a^b)+2(a&b)
    "sub": {"xany": 1, "nxay": -1},       # a-b == (a&~b)-(~a&b)
}
LIFTS = ["cube", "pow4", "prodsq"]

STRESS = [0, 1, 2, 3, MASK, MASK - 1, 1 << 31, (1 << 31) - 1,
          0x55555555, 0xAAAAAAAA, 0xDEADBEEF, 0xCAFEBABE]


def _vec(d):
    return [int(d.get(n, 0)) for n in BASIS_ORDER]


def nullspace_vectors(names):
    F = sp.Matrix([[TT[n][r] for n in names] for r in range(4)])
    out = []
    for v in F.nullspace():
        den = sp.lcm([sp.fraction(c)[1] for c in v])
        out.append([int(c * den) for c in v])
    return out


def mint_spelling(base, rng, max_terms):
    """f = base(V) + a random integer null-space zero. Returns 13-coeff vector."""
    co = dict(BASE_COEFFS[base])
    names = rng.sample(BASIS_ORDER, rng.choice([6, 7, 8]))
    for v in nullspace_vectors(names):
        k = rng.randint(-3, 3)
        if k == 0:
            continue
        for n, vi in zip(names, v):
            co[n] = co.get(n, 0) + k * vi
    vec = _vec(co)
    # cap coefficient magnitude / active-term count for IR sanity
    if sum(1 for c in vec if c != 0) > max_terms:
        return None
    if any(abs(c) > (1 << 20) for c in vec):
        return None
    return vec


# ── evaluation of a spelling coeff-vector ──────────────────────────────────
def spell_int(vec, x, y):
    return sum(c * PYF[n](x, y) for c, n in zip(vec, BASIS_ORDER) if c) & MASK

def canon_int(base, x, y):
    return ((x + y) if base == "add" else (x - y)) & MASK

def _lift_int(v, lift):
    v &= MASK
    if lift == "cube":
        return (v * v * v) & MASK
    if lift == "pow4":
        s = (v * v) & MASK
        return (s * s) & MASK
    # prodsq: (v * w)^2 with w = (x^y) folded in by caller; handled separately
    return (v * v) & MASK

def entry_int(base, lift, vec, x, y, w):
    f = spell_int(vec, x, y)
    g = canon_int(base, x, y)
    if lift == "prodsq":
        fl = ((f * w) * (f * w)) & MASK
        gl = ((g * w) * (g * w)) & MASK
    else:
        fl = _lift_int(f, lift)
        gl = _lift_int(g, lift)
    return (fl - gl) & MASK


def is_exact_zero(base, lift, vec, rng):
    w_of = lambda a, b: (a ^ b) & MASK   # prodsq weight = x^y
    for a in STRESS:
        for b in STRESS:
            if entry_int(base, lift, vec, a, b, w_of(a, b)) != 0:
                return (a, b)
    for _ in range(20000):
        a = rng.randrange(M); b = rng.randrange(M)
        if entry_int(base, lift, vec, a, b, w_of(a, b)) != 0:
            return (a, b)
    return None


# ── string emit (for SiMBA linearity check) ────────────────────────────────
def spell_str(vec):
    terms = []
    for c, n in zip(vec, BASIS_ORDER):
        if not c:
            continue
        terms.append(f"{c}*{STR[n]}" if c != 1 else STR[n])
    return "(" + "+".join(terms) + ")" if terms else "0"

def canon_str(base):
    return "(a+b)" if base == "add" else "(a-b)"

def entry_str(base, lift, vec):
    f, g = spell_str(vec), canon_str(base)
    if lift == "cube":
        return f"({f}*{f}*{f})-({g}*{g}*{g})"
    if lift == "pow4":
        return f"(({f}*{f})*({f}*{f}))-(({g}*{g})*({g}*{g}))"
    w = "(a^b)"
    return f"(({f}*{w})*({f}*{w}))-(({g}*{w})*({g}*{w}))"


# ── IR emit (for -O2 fold vet + Z3) ────────────────────────────────────────
_IRB = {"and": "and i32 %x, %y", "or": "or i32 %x, %y", "xor": "xor i32 %x, %y",
        "nx": "xor i32 %x, -1", "ny": "xor i32 %y, -1"}

def _emit_basis(name, L, fr):
    if name == "x": return "%x"
    if name == "y": return "%y"
    if name == "one": return "-1"
    if name in _IRB:
        r = fr("b"); L.append(f"  {r} = {_IRB[name]}"); return r
    two = {"nand": "and", "nor": "or", "xnor": "xor"}
    if name in two:
        t = fr("b"); L.append(f"  {t} = {two[name]} i32 %x, %y")
        r = fr("b"); L.append(f"  {r} = xor i32 {t}, -1"); return r
    if name == "xany":
        t = fr("b"); L.append(f"  {t} = xor i32 %y, -1")
        r = fr("b"); L.append(f"  {r} = and i32 %x, {t}"); return r
    t = fr("b"); L.append(f"  {t} = xor i32 %x, -1")
    r = fr("b"); L.append(f"  {r} = and i32 {t}, %y"); return r

def _emit_spell(vec, L, fr):
    acc = None
    for c, n in zip(vec, BASIS_ORDER):
        if not c:
            continue
        b = _emit_basis(n, L, fr)
        t = b
        if c != 1:
            t = fr("t"); L.append(f"  {t} = mul i32 {c & MASK}, {b}")
        if acc is None:
            acc = t
        else:
            s = fr("s"); L.append(f"  {s} = add i32 {acc}, {t}"); acc = s
    return acc if acc is not None else "0"

def entry_ir(base, lift, vec):
    L = []; n = [0]
    def fr(p): n[0] += 1; return f"%{p}{n[0]}"
    f = _emit_spell(vec, L, fr)
    g = fr("g"); L.append(f"  {g} = {'add' if base=='add' else 'sub'} i32 %x, %y")
    def do_lift(src, tag):
        if lift == "cube":
            a = fr(tag); L.append(f"  {a} = mul i32 {src}, {src}")
            b = fr(tag); L.append(f"  {b} = mul i32 {a}, {src}"); return b
        if lift == "pow4":
            a = fr(tag); L.append(f"  {a} = mul i32 {src}, {src}")
            b = fr(tag); L.append(f"  {b} = mul i32 {a}, {a}"); return b
        w = fr(tag); L.append(f"  {w} = xor i32 %x, %y")
        p = fr(tag); L.append(f"  {p} = mul i32 {src}, {w}")
        b = fr(tag); L.append(f"  {b} = mul i32 {p}, {p}"); return b
    fl = do_lift(f, "fl"); gl = do_lift(g, "gl")
    r = fr("r"); L.append(f"  {r} = sub i32 {fl}, {gl}")
    L.append(f"  ret i32 {r}")
    return "define i32 @f(i32 %x, i32 %y) {\n" + "\n".join(L) + "\n}\n"


def _find_opt():
    b = Path(r"C:\Users\und3ath\Desktop\llvm-o\xollvm-windows\build")
    for c in [b / "bin" / "opt.exe", b / "Release" / "bin" / "opt.exe"]:
        if c.is_file():
            return str(c)
    return None

_OPT = _find_opt()

def o2_folds(base, lift, vec):
    if not _OPT:
        return None
    p = subprocess.run([_OPT, "-O2", "-S", "-o", "-"], input=entry_ir(base, lift, vec),
                       text=True, capture_output=True)
    return "ret i32 0" in p.stdout


def simba_nonlinear(base, lift, vec):
    if not _HAVE_SIMBA:
        return None
    try:
        return not check_linear_mba(entry_str(base, lift, vec))
    except Exception:
        return None


def z3_timeout(base, lift, vec, ms=3000):
    if not _HAVE_Z3:
        return None
    x = z3.BitVec("x", W); y = z3.BitVec("y", W)
    ZF = {"one": z3.BitVecVal(MASK, W), "x": x, "y": y, "and": x & y, "or": x | y,
          "xor": x ^ y, "nx": ~x, "ny": ~y, "nand": ~(x & y), "nor": ~(x | y),
          "xnor": ~(x ^ y), "xany": x & ~y, "nxay": ~x & y}
    f = z3.BitVecVal(0, W)
    for c, n in zip(vec, BASIS_ORDER):
        if c:
            f = f + z3.BitVecVal(c & MASK, W) * ZF[n]
    g = (x + y) if base == "add" else (x - y)
    if lift == "cube":
        diff = f * f * f - g * g * g
    elif lift == "pow4":
        diff = (f * f) * (f * f) - (g * g) * (g * g)
    else:
        w = x ^ y
        diff = (f * w) * (f * w) - (g * w) * (g * w)
    s = z3.Solver(); s.set("timeout", ms); s.add(diff != 0)
    return s.check() == z3.unknown   # timeout == strong


def generate(n, seed, max_terms, z3_sample):
    rng = random.Random(seed)
    entries = []
    tried = 0
    z3_done = 0
    t0 = time.monotonic()
    while len(entries) < n and tried < n * 40:
        tried += 1
        base = rng.choice(["add", "sub"])
        lift = rng.choice(LIFTS)
        vec = mint_spelling(base, rng, max_terms)
        if vec is None:
            continue
        if is_exact_zero(base, lift, vec, rng) is not None:
            continue                       # not a zero (shouldn't happen; guard)
        folds = o2_folds(base, lift, vec)
        if folds:
            continue                       # collapsed under -O2
        nl = simba_nonlinear(base, lift, vec)
        if nl is False:
            continue                       # SiMBA could linearize it (reject)
        if z3_done < z3_sample:
            z3_done += 1
            if z3_timeout(base, lift, vec) is False:
                continue                   # Z3 proved it fast -> reject
        entries.append((base, lift, vec))
    dt = time.monotonic() - t0
    return entries, tried, dt


POOL_HEADER = (
    "# xollvm SLE pool v1 — nonlinear-lifted SLE runtime-zero forms\n"
    "# basis order: " + " ".join(BASIS_ORDER) + "\n"
    "# line: <base:add|sub> <lift:cube|pow4|prodsq> <13 int coeffs of spelling f>\n"
    "#   zero(x,y) = lift(f) - lift(canonical(base)),  f == canonical(base)\n"
)

def write_pool(path, entries):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(POOL_HEADER)
        for base, lift, vec in entries:
            fh.write(f"{base} {lift} " + " ".join(str(c) for c in vec) + "\n")


def write_fallback(path, entries):
    lines = ["// AUTO-GENERATED by utils/mba_sle_gen.py — compiled-in SLE fallback pool.",
             "// Regenerate the runtime pool file instead of editing this by hand.",
             "// Format mirrors the pool file: {base, lift, {13 coeffs}}.",
             "#pragma once", "namespace llvm::obf {",
             "struct SleFallbackEntry { const char* base; const char* lift; int coeffs[13]; };",
             "static const SleFallbackEntry kSleFallbackPool[] = {"]
    for base, lift, vec in entries:
        lines.append('  {"%s", "%s", {%s}},' % (base, lift, ", ".join(str(c) for c in vec)))
    lines += ["};", "static const unsigned kSleFallbackPoolSize = "
              f"{len(entries)};", "} // namespace llvm::obf", ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Generate + vet the xollvm SLE pool.")
    ap.add_argument("--n", type=int, default=256, help="pool size (vetted entries)")
    ap.add_argument("--seed", type=int, default=1, help="deterministic seed")
    ap.add_argument("--max-terms", type=int, default=8, help="max active basis terms in f")
    ap.add_argument("--z3-sample", type=int, default=8, help="how many entries to Z3-vet")
    ap.add_argument("--out", default=str(_HERE / "sle_pool.txt"), help="pool file path")
    ap.add_argument("--fallback", default="", help="also emit a compiled-in .inc header")
    ap.add_argument("--fallback-n", type=int, default=16, help="entries in fallback header")
    args = ap.parse_args()

    print(f"oracles: opt={'yes' if _OPT else 'NO'} simba={_HAVE_SIMBA} z3={_HAVE_Z3}")
    entries, tried, dt = generate(args.n, args.seed, args.max_terms, args.z3_sample)
    print(f"generated {len(entries)}/{args.n} vetted entries "
          f"(tried {tried}, {dt:.1f}s, {sum(1 for e in entries if e[0]=='add')} add / "
          f"{sum(1 for e in entries if e[0]=='sub')} sub)")
    if len(entries) < args.n:
        print("WARNING: fewer entries than requested — loosen --max-terms or raise trials")
    write_pool(args.out, entries)
    print(f"wrote pool -> {args.out}")
    if args.fallback:
        write_fallback(args.fallback, entries[:args.fallback_n])
        print(f"wrote fallback -> {args.fallback} ({min(args.fallback_n, len(entries))} entries)")


if __name__ == "__main__":
    main()
