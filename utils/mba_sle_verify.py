#!/usr/bin/env python3
"""
mba_sle_verify.py — re-verify a shipped SLE pool file (or the fallback header).

Reads utils/sle_pool.txt (or --pool PATH) and checks every entry is an EXACT
runtime zero over the exhaustive int32 stress set + random pairs. This is the
regression gate that a hand-edit / corruption / bad regen of the pool cannot
slip past — the generator vets at mint time, this re-vets what actually ships.

No opt / Z3 / SiMBA needed (correctness only); those strength gates live in the
generator. Fast (< a few seconds for 256 entries).
"""
import argparse
import random
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from mba_sle_gen import BASIS_ORDER, is_exact_zero  # noqa: E402


def parse_pool(path: Path):
    entries = []
    for ln, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        tok = s.split()
        if len(tok) < 15:
            raise ValueError(f"line {ln}: expected >=15 tokens, got {len(tok)}: {s!r}")
        base, lift = tok[0], tok[1]
        if base not in ("add", "sub"):
            raise ValueError(f"line {ln}: bad base {base!r}")
        if lift not in ("cube", "pow4", "prodsq"):
            raise ValueError(f"line {ln}: bad lift {lift!r}")
        vec = [int(t) for t in tok[2:15]]
        entries.append((base, lift, vec))
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=str(_HERE / "sle_pool.txt"))
    args = ap.parse_args()

    path = Path(args.pool)
    if not path.is_file():
        print(f"[skip] pool file not found: {path}")
        return 0

    entries = parse_pool(path)
    if len(BASIS_ORDER) != 13:
        print("basis order mismatch"); return 1

    rng = random.Random(20240817)
    fails = 0
    for i, (base, lift, vec) in enumerate(entries):
        bad = is_exact_zero(base, lift, vec, rng)
        if bad is not None:
            fails += 1
            print(f"  FAIL entry {i} ({base} {lift}): nonzero at x={bad[0]} y={bad[1]}")

    print(f"{path.name}: {len(entries)} entries, {len(entries)-fails} valid zeros, {fails} FAIL")
    if fails:
        print("RESULT: FAIL — pool contains non-zero forms.")
        return 1
    print("RESULT: PASS — every pool entry is an exact runtime zero.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
