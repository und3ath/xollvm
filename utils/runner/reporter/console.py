"""Console summary table for completed test runs."""

from __future__ import annotations

from ..fmt import (
    BCYAN, BGREEN, BLUE, BOLD, BRED, CYAN, DIM, GRAY, GREEN, MAGENTA,
    RED, RST, YELLOW, bold, fmt_growth, fmt_time, head, stripped_len,
)


def _cat_label(cat: str) -> str:
    m = {
        "pass": CYAN,
        "feature": MAGENTA,
        "budget": YELLOW,
        "adec": BLUE,
        "meta": GRAY,
        "cpp": BCYAN,
        "options": MAGENTA,
        "matrix": BLUE,
        "exhaustive": GRAY,
        "strenc": BGREEN,
        "vm": BRED,
    }
    c = m.get(cat, DIM)
    return f"{c()}{cat[:4]}{RST()}"


def print_table(results: list) -> None:
    print()
    print(head("═" * 86))
    print(head("  Test Results"))
    print(head("═" * 86))
    print()

    nw = max((len(r.name) for r in results), default=10)
    nw = max(nw, 10)

    header = (f"  {'Test':<{nw}}  {'Cat':>4}  {'Status':>6}  {'Time':>7}  "
              f"{'Base':>6}  {'Obf':>6}  {'Grow':>6}  {'Seed':>4}  {'Inp':>5}")
    print(bold(header))
    rule = "─" * (nw + 58)
    print(f"  {rule}")

    for r in results:
        cat_s = _cat_label(r.category)
        st = (f"{GREEN()}PASS{RST()}" if r.status == "PASS" else
              f"{RED()}FAIL{RST()}" if r.status == "FAIL" else
              f"{YELLOW()}SKIP{RST()}")
        tm = fmt_time(r.elapsed)
        base_s = str(r.base_insts) if r.base_insts else "—"
        obf_s = str(r.obf_insts) if r.obf_insts else "—"
        ratio = (r.obf_insts / r.base_insts
                 if r.base_insts > 0 and r.obf_insts > 0 else 0)
        gr = fmt_growth(ratio)

        def _pad(s: str, w: int) -> str:
            return " " * max(0, w - stripped_len(s)) + s

        print(f"  {r.name:<{nw}}  {_pad(cat_s,4)}  {_pad(st,6)}  {_pad(tm,7)}  "
              f"{base_s:>6}  {obf_s:>6}  {_pad(gr,6)}  {r.seeds_run:>4}  {r.inputs_run:>5}")

        if r.status == "FAIL" and r.reason:
            reason = r.reason[:110] + "..." if len(r.reason) > 113 else r.reason
            print(f"  {' ' * nw}  {DIM()}{RED()}↳ {reason}{RST()}")

    print(f"  {rule}")

    total   = len(results)
    passed  = sum(1 for r in results if r.status == "PASS")
    failed  = sum(1 for r in results if r.status == "FAIL")
    skipped = sum(1 for r in results if r.status == "SKIP")
    t_total = sum(r.elapsed for r in results)

    parts = []
    if passed:
        parts.append(f"{GREEN()}{passed} passed{RST()}")
    if failed:
        parts.append(f"{RED()}{failed} failed{RST()}")
    if skipped:
        parts.append(f"{YELLOW()}{skipped} skipped{RST()}")

    print()
    print(f"  {bold('Total:')} {total} tests — {', '.join(parts)}"
          f"  ({fmt_time(t_total)})")
    print()
