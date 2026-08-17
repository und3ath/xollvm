#!/usr/bin/env python3
"""
mba_fold_check.py — best-effort -O2 fold-resistance probe for the 4 new
MbaUtils identities added in MBA_EXT_V2 ME1 (addAlt3/subAlt3/bitwiseAndAlt2/
bitwiseXorAlt2). Not a gate: some identities are expected to fold back to the
primitive under InstCombine; this just reports which ones do.
"""

import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_BUILD = os.path.normpath(os.path.join(_HERE, "..", "..", "xollvm-windows", "build"))
# ninja single-config build lands opt at build/bin/opt.exe;
# multi-config (VS) lands it at build/Release/bin/opt.exe. Try both.
_CANDIDATES = [
    os.path.join(_BUILD, "bin", "opt.exe"),
    os.path.join(_BUILD, "Release", "bin", "opt.exe"),
]
OPT = next((p for p in _CANDIDATES if os.path.isfile(p)), _CANDIDATES[0])

IDENTITIES = {
    "addAlt3": """define i32 @f(i32 %x, i32 %y) {
  %nv = xor i32 %y, -1
  %d = sub i32 %x, %nv
  %r = sub i32 %d, 1
  ret i32 %r
}
""",
    "subAlt3": """define i32 @f(i32 %x, i32 %y) {
  %na = xor i32 %x, -1
  %s = add i32 %na, %y
  %r = xor i32 %s, -1
  ret i32 %r
}
""",
    "bitwiseAndAlt2": """define i32 @f(i32 %x, i32 %y) {
  %o = or i32 %x, %y
  %x2 = xor i32 %x, %y
  %r = sub i32 %o, %x2
  ret i32 %r
}
""",
    "bitwiseXorAlt2": """define i32 @f(i32 %x, i32 %y) {
  %o = or i32 %x, %y
  %a = and i32 %x, %y
  %na = xor i32 %a, -1
  %r = and i32 %o, %na
  ret i32 %r
}
""",
    "mulAlt": """define i32 @f(i32 %x, i32 %y) {
  %nx = sub i32 0, %x
  %m = mul i32 %nx, %y
  %r = sub i32 0, %m
  ret i32 %r
}
""",
    "mulAlt2": """define i32 @f(i32 %x, i32 %y) {
  %ylo = and i32 %y, 65535
  %yhi = lshr i32 %y, 16
  %mlo = mul i32 %x, %ylo
  %mhi = mul i32 %x, %yhi
  %mhis = shl i32 %mhi, 16
  %r = add i32 %mlo, %mhis
  ret i32 %r
}
""",
    "shlAlt": """define i32 @f(i32 %x, i32 %y) {
  %r = mul i32 %x, 8
  ret i32 %r
}
""",
    "shlAlt2": """define i32 @f(i32 %x, i32 %y) {
  %nx = xor i32 %x, -1
  %s = shl i32 %nx, 3
  %ns = xor i32 %s, -1
  %r = sub i32 %ns, 7
  ret i32 %r
}
""",
}

# ---------------------------------------------------------------------------
# Input-derived zero forms (V1). Emitted alone as `ret i32 <zeroexpr>`, each is
# an exact 0. The V1 acceptance bar: opt -O2 must NOT prove it 0 (i.e. must not
# emit `ret i32 0`). If InstCombine folds the inner MBA spelling f -> g, then
# lift(f)-lift(g) collapses to 0 and the term is worthless under an attacker's
# own -O2 cleanup. This is a GATE (unlike the identity fold-report above).
# ---------------------------------------------------------------------------

ZERO_FORMS = {
    "idz.K0.add.cube": """define i32 @f(i32 %x, i32 %y) {
  %xor = xor i32 %x, %y
  %and = and i32 %x, %y
  %t = mul i32 2, %and
  %f = add i32 %xor, %t
  %g = add i32 %x, %y
  %f2 = mul i32 %f, %f
  %f3 = mul i32 %f2, %f
  %g2 = mul i32 %g, %g
  %g3 = mul i32 %g2, %g
  %r = sub i32 %f3, %g3
  ret i32 %r
}
""",
    "idz.K1.sub.w2": """define i32 @f(i32 %x, i32 %y) {
  %ny = xor i32 %y, -1
  %nx = xor i32 %x, -1
  %a1 = and i32 %x, %ny
  %a2 = and i32 %nx, %y
  %f = sub i32 %a1, %a2
  %g = sub i32 %x, %y
  %o = or i32 %x, %y
  %w2 = mul i32 %o, %o
  %fw = mul i32 %f, %w2
  %gw = mul i32 %g, %w2
  %r = sub i32 %fw, %gw
  ret i32 %r
}
""",
    "idz.K2.mul.prod": """define i32 @f(i32 %x, i32 %y) {
  %xor = xor i32 %x, %y
  %and = and i32 %x, %y
  %t = mul i32 2, %and
  %s = add i32 %xor, %t
  %o = or i32 %x, %y
  %d = sub i32 %o, %and
  %f = mul i32 %s, %d
  %sum = add i32 %x, %y
  %g = mul i32 %sum, %xor
  %f2 = mul i32 %f, %f
  %g2 = mul i32 %g, %g
  %r = sub i32 %f2, %g2
  ret i32 %r
}
""",
    "idz.K3.add.pow4": """define i32 @f(i32 %x, i32 %y) {
  %xor = xor i32 %x, %y
  %and = and i32 %x, %y
  %t = mul i32 2, %and
  %f = add i32 %xor, %t
  %g = add i32 %x, %y
  %f2 = mul i32 %f, %f
  %f4 = mul i32 %f2, %f2
  %g2 = mul i32 %g, %g
  %g4 = mul i32 %g2, %g2
  %r = sub i32 %f4, %g4
  ret i32 %r
}
""",
    "idz.K4.sub.cube": """define i32 @f(i32 %x, i32 %y) {
  %ny = xor i32 %y, -1
  %nx = xor i32 %x, -1
  %a1 = and i32 %x, %ny
  %a2 = and i32 %nx, %y
  %f = sub i32 %a1, %a2
  %g = sub i32 %x, %y
  %f2 = mul i32 %f, %f
  %f3 = mul i32 %f2, %f
  %g2 = mul i32 %g, %g
  %g3 = mul i32 %g2, %g
  %r = sub i32 %f3, %g3
  ret i32 %r
}
""",
    "idz.K5.add.w2xor": """define i32 @f(i32 %x, i32 %y) {
  %xor = xor i32 %x, %y
  %and = and i32 %x, %y
  %t = mul i32 2, %and
  %f = add i32 %xor, %t
  %g = add i32 %x, %y
  %w2 = mul i32 %xor, %xor
  %fw = mul i32 %f, %w2
  %gw = mul i32 %g, %w2
  %r = sub i32 %fw, %gw
  ret i32 %r
}
""",
    "idz.K6.sub.pow4": """define i32 @f(i32 %x, i32 %y) {
  %ny = xor i32 %y, -1
  %nx = xor i32 %x, -1
  %a1 = and i32 %x, %ny
  %a2 = and i32 %nx, %y
  %f = sub i32 %a1, %a2
  %g = sub i32 %x, %y
  %f2 = mul i32 %f, %f
  %f4 = mul i32 %f2, %f2
  %g2 = mul i32 %g, %g
  %g4 = mul i32 %g2, %g2
  %r = sub i32 %f4, %g4
  ret i32 %r
}
""",
}

# `ret i32 0` (any whitespace) means opt proved the whole expr is 0 — the term
# folded away and is worthless. Anything else = it survived.
ZERO_RET_RE = re.compile(r"ret\s+i32\s+0\b")


def classify_zero(ll_out):
    return "folded_to_zero" if ZERO_RET_RE.search(ll_out) else "preserved"


# A single primitive binop directly on %x/%y (either operand order).
PRIMITIVE_RE = re.compile(
    r"=\s*(add|sub|and|xor|mul)\s+i32\s+(%x, %y|%y, %x)\b")

# A single shl on %x by a compile-time-constant literal shift amount
# (the shl family's fold target — const-RHS only, so operand 1 is a literal).
SHL_RE = re.compile(r"=\s*shl\s+i32\s+%x,\s*\d+\b")


def classify(ll_out):
    shl_ops = SHL_RE.findall(ll_out)
    binops = PRIMITIVE_RE.findall(ll_out)
    total = len(shl_ops) + len(binops)
    if total == 1:
        return "folded_to_primitive"
    return "preserved"


def main():
    if not os.path.isfile(OPT):
        print("[skip] opt not found. Tried:")
        for c in _CANDIDATES:
            print("  " + c)
        return 0

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"

    print(f"{'identity':<18}  status_after_O2")
    print("-" * 40)
    for name, ll in IDENTITIES.items():
        try:
            proc = subprocess.run(
                [OPT, "-O2", "-S", "-o", "-"],
                input=ll, text=True, capture_output=True, env=env, timeout=30)
        except Exception as e:
            print(f"{name:<18}  [error] {e}")
            continue
        if proc.returncode != 0:
            print(f"{name:<18}  [error] opt exited {proc.returncode}: {proc.stderr.strip()[:120]}")
            continue
        status = classify(proc.stdout)
        print(f"{name:<18}  {status}")

    # --- V1 input-derived zeros: fold-resistance GATE ---
    print()
    print(f"{'input-zero form':<18}  status_after_O2  (must be 'preserved')")
    print("-" * 56)
    gate_fail = False
    for name, ll in ZERO_FORMS.items():
        try:
            proc = subprocess.run(
                [OPT, "-O2", "-S", "-o", "-"],
                input=ll, text=True, capture_output=True, env=env, timeout=30)
        except Exception as e:
            print(f"{name:<18}  [error] {e}")
            gate_fail = True
            continue
        if proc.returncode != 0:
            print(f"{name:<18}  [error] opt exited {proc.returncode}: {proc.stderr.strip()[:120]}")
            gate_fail = True
            continue
        status = classify_zero(proc.stdout)
        flag = "" if status == "preserved" else "   <-- FAIL"
        print(f"{name:<18}  {status}{flag}")
        if status != "preserved":
            gate_fail = True

    if gate_fail:
        print("\nRESULT: FAIL — one or more input-derived zeros folded to 0 under -O2.")
        return 1
    print("\nRESULT: PASS — all input-derived zeros survived -O2.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
