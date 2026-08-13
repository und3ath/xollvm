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
}

# A single primitive binop directly on %x/%y (either operand order).
PRIMITIVE_RE = re.compile(
    r"=\s*(add|sub|and|xor)\s+i32\s+(%x, %y|%y, %x)\b")


def classify(ll_out):
    ops = PRIMITIVE_RE.findall(ll_out)
    if len(ops) == 1:
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
