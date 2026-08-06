"""CLI entrypoint for the obfuscator deobfuscation resilience bench."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from runner.config import detect_tools
from runner.fmt import DIM, RST, badge_fail, badge_pass, badge_skip, disable_color, dim, fmt_time, head, info

from . import cases as cases_mod
from .bench import run_bench
from .report import print_table, write_json_report
from .scorer import group_by_case

_BADGE = {"PASS": badge_pass, "SKIP": badge_skip, "FAIL": badge_fail}


def main() -> int:
    # Stdout is never a real tty here (piped/redirected/captured by the
    # harness) — Python fully block-buffers in that case, so nothing shows
    # up until the whole run ends. Force line buffering so results stream
    # out live instead of arriving in one lump at exit.
    try:
        sys.stdout.reconfigure(line_buffering=True, errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(
        description="Deobfuscation resilience bench for the LLVM obfuscator.",
    )
    ap.add_argument("--build-dir", default="", help="LLVM build directory (required unless --list)")
    ap.add_argument("--config", default="Debug", help="MSVC multi-config (Debug/Release)")
    ap.add_argument("--work", default="", help="Work directory for temp artifacts")
    ap.add_argument("--seeds", default="1", help="Comma-separated seeds (e.g. 1,2,3)")
    ap.add_argument("--attacks", default="",
                     help="Comma-separated attack filter (mba,cfg,strenc). Default: all.")
    ap.add_argument("--filter", default="", help="Run only cases matching substring")
    ap.add_argument("--list", action="store_true", help="List all bench cases and exit")
    ap.add_argument("--keep", action="store_true", help="Preserve work dir on success")
    ap.add_argument("--verbose", "-v", action="store_true", help="Print all commands")
    ap.add_argument("--nerd", action="store_true",
                     help="Live phase-by-phase progress + full diagnostics per case "
                          "(solver stats, raw block/edge counts, hex dumps, ...)")
    ap.add_argument("--case-timeout", default=60, type=float,
                     help="Per-case wall-clock budget in seconds (default: 60). "
                          "A case that exceeds it is reported FAIL instead of hanging the run "
                          "(the worker thread is abandoned, not killed — angr/Z3 can't be "
                          "force-stopped mid-call — so pick a budget you're OK leaving orphaned).")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--json-report", default="", help="Write JSON report to path")
    args = ap.parse_args()

    if args.no_color:
        disable_color()

    all_cases = cases_mod.all_cases()
    if args.attacks:
        wanted = {a.strip() for a in args.attacks.split(",") if a.strip()}
        all_cases = [c for c in all_cases if c.attack in wanted]
    if args.filter:
        all_cases = [c for c in all_cases if args.filter in c.name]

    if args.list:
        cur_attack = ""
        for c in all_cases:
            if c.attack != cur_attack:
                cur_attack = c.attack
                print(f"\n  {head(f'-- {cur_attack.upper()} --')}")
            print(f"    - {c.name}  ({', '.join(c.passes)})")
        print()
        return 0

    if not args.build_dir:
        print("error: --build-dir is required (use --list to see cases without it)")
        return 1
    if not all_cases:
        print("error: no cases match the filter")
        return 1

    build_dir = Path(args.build_dir)
    tools = detect_tools(build_dir, args.config)
    work = Path(args.work) if args.work else (Path.cwd() / "deobf_bench_work")
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    seeds = [int(s.strip()) for s in args.seeds.split(",") if s.strip()]
    total = len(all_cases) * len(seeds)

    print()
    print(head("=== LLVM Obfuscator -- Deobfuscation Resilience Bench ==="))
    print()
    print(info(f"clang: {tools.clang}"))
    print(info(f"opt:   {tools.opt}"))
    print(info(f"work:  {work}"))
    print(info(f"seeds: {seeds}"))
    print(info(f"cases: {len(all_cases)} ({total} runs)"))
    print(info(f"case timeout: {args.case_timeout:.0f}s"))
    print(info(f"nerd mode: {'on' if args.nerd else 'off (pass --nerd for live phase progress + full diagnostics)'}"))
    print()

    def on_progress(case_name: str, attack: str, seed: int, msg: str) -> None:
        if args.nerd:
            print(f"    {dim(f'[{case_name}:{attack}:s{seed}] > {msg}')}")

    results = []
    idx = 0
    for r in run_bench(tools, work, all_cases, seeds, verbose=args.verbose,
                        progress=on_progress, case_timeout=args.case_timeout):
        idx += 1
        results.append(r)
        badge = _BADGE[r.status]()
        res_str = f"{r.resilience * 100:5.1f}%" if r.resilience is not None else f"{DIM()}  —  {RST()}"
        print(f"  [{idx}/{total}] {r.case} ({r.attack}, {r.tool})  {badge}  {res_str}  {fmt_time(r.elapsed)}")
        if args.nerd:
            print(f"    {dim(f'technique: {r.technique}')}")
            print(f"    {dim(f'detail:    {r.detail}')}")
            for k, v in r.extra.items():
                print(f"    {dim(f'{k}: {v}')}")
        elif r.status == "FAIL":
            print(f"    {dim(f'detail: {r.detail}')}")

    print()
    scores = group_by_case(results)
    print_table(scores)

    if args.json_report:
        rp = Path(args.json_report)
        write_json_report(scores, rp)
        print()
        print(info(f"JSON report -> {rp}"))

    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)

    return 1 if any(s.status == "FAIL" for s in scores) else 0
