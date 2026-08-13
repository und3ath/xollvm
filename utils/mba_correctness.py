#!/usr/bin/env python3
"""
mba_correctness.py — Python-level (numpy-only) correctness check for the
MbaUtils identity pool (MBA_EXT_V2 ME1).

Verifies that every identity implemented in MBAUtils.cpp matches its
primitive op (+, -, &, |, ^) under two's-complement int32 semantics, across
a fixed edge-case set plus 1024 random int32 pairs (seed=42), cross-producted
against each other. All identity functions are evaluated vectorized over
numpy int32 arrays (wraps naturally on overflow) to keep runtime well under
the 30s budget even for ~1e6 pairs.

No LLVM dependency.
"""

import sys
import numpy as np

I32 = np.int32
INT_MIN = -2147483648
INT_MAX = 2147483647


# ---------------------------------------------------------------------------
# Primitives (elementwise over numpy int32 arrays)
# ---------------------------------------------------------------------------

def p_add(x, y): return I32(x + y)
def p_sub(x, y): return I32(x - y)
def p_and(x, y): return I32(x & y)
def p_or(x, y):  return I32(x | y)
def p_xor(x, y): return I32(x ^ y)
def p_mul(x, y): return I32(x * y)


# ---------------------------------------------------------------------------
# Identities under test — bit-for-bit translation of the C++ IR expansions.
# ---------------------------------------------------------------------------

def i_add(x, y):        return I32((x ^ y) + I32(2) * (x & y))
def i_addAlt(x, y):     return I32((x | y) + (x & y))
def i_addAlt2(x, y):    return I32(I32(2) * (x | y) - (x ^ y))
def i_addAlt3(x, y):    return I32((x - I32(~y)) - I32(1))

def i_sub(x, y):        return I32((x ^ y) - I32(2) * (I32(~x) & y))
def i_subAlt(x, y):     return I32((x & I32(~y)) - (I32(~x) & y))
def i_subAlt2(x, y):    return I32(x + I32(~y) + I32(1))
def i_subAlt3(x, y):    return I32(~(I32(~x) + y))

def i_bitwiseAnd(x, y):     return I32((x + y) - (x | y))
def i_bitwiseAndAlt(x, y):  return I32(~(I32(~x) | I32(~y)))
def i_bitwiseAndAlt2(x, y): return I32((x | y) - (x ^ y))

def i_bitwiseOr(x, y):      return I32((x & y) + (x ^ y))
def i_bitwiseOrAlt(x, y):   return I32((x + y) - (x & y))
def i_bitwiseOrAlt2(x, y):  return I32((x ^ y) | (x & y))

def i_bitwiseXor(x, y):     return I32((x | y) - (x & y))
def i_bitwiseXorAlt(x, y):  return I32((I32(~x) & y) | (x & I32(~y)))
def i_bitwiseXorAlt2(x, y): return I32((x | y) & I32(~(x & y)))

def i_mul(x, y):     return I32(x * y)
def i_mulAlt(x, y):  return I32(-((I32(0) - x) * y))
def i_mulAlt2(x, y): return I32(-(x * (I32(0) - y)))

# ---------------------------------------------------------------------------
# Shl identities — const-RHS only. n ranges over a fixed set of shift amounts
# (not the full int32 domain like the other opcodes); x still ranges over the
# full 1035-value set built by build_value_set().
# ---------------------------------------------------------------------------

def p_shl(x, n): return I32(np.int32(x) << n)

def i_shl(x, n): return p_shl(x, n)

def i_shlAlt(x, n):
    pow2 = (np.uint32(1) << n).astype(np.int32)
    return I32(np.int32(x) * pow2)

def i_shlAlt2(x, n):
    notx = I32(~np.int32(x))
    shifted = I32(notx << n)
    notshifted = I32(~shifted)
    mask = ((np.uint32(1) << n) - np.uint32(1)).astype(np.int32)  # n=0 => mask=0
    return I32(notshifted - mask)


IDENTITIES = [
    ("add",             i_add,             p_add),
    ("addAlt",          i_addAlt,          p_add),
    ("addAlt2",         i_addAlt2,         p_add),
    ("addAlt3",         i_addAlt3,         p_add),
    ("sub",             i_sub,             p_sub),
    ("subAlt",          i_subAlt,          p_sub),
    ("subAlt2",         i_subAlt2,         p_sub),
    ("subAlt3",         i_subAlt3,         p_sub),
    ("bitwiseAnd",      i_bitwiseAnd,      p_and),
    ("bitwiseAndAlt",   i_bitwiseAndAlt,   p_and),
    ("bitwiseAndAlt2",  i_bitwiseAndAlt2,  p_and),
    ("bitwiseOr",       i_bitwiseOr,       p_or),
    ("bitwiseOrAlt",    i_bitwiseOrAlt,    p_or),
    ("bitwiseOrAlt2",   i_bitwiseOrAlt2,   p_or),
    ("bitwiseXor",      i_bitwiseXor,      p_xor),
    ("bitwiseXorAlt",   i_bitwiseXorAlt,   p_xor),
    ("bitwiseXorAlt2",  i_bitwiseXorAlt2,  p_xor),
    ("mul",             i_mul,             p_mul),
    ("mulAlt",          i_mulAlt,          p_mul),
    ("mulAlt2",         i_mulAlt2,         p_mul),
]

IDENTITIES_SHL = [
    ("shl",             i_shl,             p_shl),
    ("shlAlt",          i_shlAlt,          p_shl),
    ("shlAlt2",         i_shlAlt2,         p_shl),
]

# Shift amounts exercised for the shl family (const-RHS only in production;
# the correctness suite tests each amount separately rather than the full
# int32 domain used for the other opcodes' second operand).
SHIFT_AMOUNTS = [0, 1, 2, 3, 7, 15, 16, 23, 30, 31]


def build_value_set():
    fixed = np.array(
        [-3, -2, -1, 0, 1, 2, 3, INT_MIN, INT_MAX, 0x55555555, -0x55555555],
        dtype=np.int32,
    )
    rng = np.random.default_rng(seed=42)
    rand_vals = rng.integers(
        low=INT_MIN, high=INT_MAX + 1, size=1024, endpoint=False, dtype=np.int64
    ).astype(np.int32)
    return np.concatenate([fixed, rand_vals])


def main():
    np.seterr(over="ignore")
    values = build_value_set()
    # Full cross-product of the combined value set (both operands).
    X, Y = np.meshgrid(values, values, indexing="ij")
    X = X.astype(np.int32).ravel()
    Y = Y.astype(np.int32).ravel()
    total = X.size

    overall_fail = False
    rows = []

    for name, fn, prim in IDENTITIES:
        expected = prim(X, Y)
        got = fn(X, Y)
        mismatch = expected != got
        n_fail = int(np.count_nonzero(mismatch))
        passed = total - n_fail
        status = "PASS" if n_fail == 0 else "FAIL"
        first_fail = None
        if n_fail:
            overall_fail = True
            idx = int(np.argmax(mismatch))
            first_fail = (int(X[idx]), int(Y[idx]), int(expected[idx]), int(got[idx]))
        rows.append((name, passed, total, status, first_fail))

    # Shl family: x ranges over the full value set, n ranges over a fixed
    # shift-amount set (const-RHS only), cross-producted.
    n_vals = np.array(SHIFT_AMOUNTS, dtype=np.int32)
    Xs, Ns = np.meshgrid(values, n_vals, indexing="ij")
    Xs = Xs.astype(np.int32).ravel()
    Ns = Ns.astype(np.int32).ravel()
    total_shl = Xs.size

    for name, fn, prim in IDENTITIES_SHL:
        expected = prim(Xs, Ns)
        got = fn(Xs, Ns)
        mismatch = expected != got
        n_fail = int(np.count_nonzero(mismatch))
        passed = total_shl - n_fail
        status = "PASS" if n_fail == 0 else "FAIL"
        first_fail = None
        if n_fail:
            overall_fail = True
            idx = int(np.argmax(mismatch))
            first_fail = (int(Xs[idx]), int(Ns[idx]), int(expected[idx]), int(got[idx]))
        rows.append((name, passed, total_shl, status, first_fail))

    name_w = max(len(r[0]) for r in rows)
    header = f"{'identity':<{name_w}}  {'passed':>9}  {'total':>9}  status"
    print(header)
    print("-" * len(header))
    for name, passed, tot, status, first_fail in rows:
        print(f"{name:<{name_w}}  {passed:>9}  {tot:>9}  {status}")
        if status == "FAIL" and first_fail is not None:
            x, y, expected, got = first_fail
            print(f"    first failure: x={x} y={y} expected={expected} got={got}")

    if overall_fail:
        print("\nRESULT: FAIL — one or more identities mismatched the primitive.")
        sys.exit(1)
    else:
        print(
            f"\nRESULT: PASS — {len(rows)} identities all matched "
            f"({len(IDENTITIES)} x {total} pairs + {len(IDENTITIES_SHL)} x {total_shl} pairs)."
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
