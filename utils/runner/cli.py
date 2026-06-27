"""CLI entrypoint for the obfuscator runtime test suite."""

from __future__ import annotations

import argparse
import io
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Optional

from .config import detect_tools
from .fmt import (
    BG_GREEN, BG_RED, BOLD, CYAN, DIM, RED, RST, WHITE,
    badge_fail, badge_pass, badge_skip, bold, dim, disable_color,
    fmt_time, head, info, warn,
)
from .reporter.console import print_table
from .reporter.html import find_obf_report_html_tool, write_obf_reports_index
from .reporter.json_report import write_json_report
from .targets import TARGETS, is_available, resolve
from .util import build_inputs, die, is_subpath


# ─────────────────────────────────────────────────────────────────────────────
#  Parallel worker
#
#  Top-level so ProcessPoolExecutor can pickle it. Captures stdout/stderr in
#  an in-memory buffer so the main process can flush each test's output
#  atomically (FIFO by completion) without interleaving across workers.
# ─────────────────────────────────────────────────────────────────────────────

def _worker_init() -> None:
    """Run in each ProcessPool worker before any task. Ignores SIGINT so
    Ctrl+C only fires in the main process — main then orderly-terminates
    workers + their subprocess descendants instead of leaving orphans."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _run_test_capture(payload: dict):
    from cases import run_test  # imported inside worker so child re-imports cleanly

    buf = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = buf
    sys.stderr = buf
    try:
        r = run_test(**payload)
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
    return r, buf.getvalue()


def _kill_subtree(pid: int) -> None:
    """Kill pid + all descendants. Prefer psutil; fall back to platform tools."""
    try:
        import psutil  # type: ignore
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        try:
            parent.kill()
        except psutil.NoSuchProcess:
            pass
        return
    except ImportError:
        pass

    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def _hard_kill_pool(pool) -> None:
    """Force-terminate every live worker (and their subprocess descendants)."""
    # ProcessPoolExecutor internal: live worker PIDs.
    procs = list(getattr(pool, "_processes", {}).values())
    for p in procs:
        pid = getattr(p, "pid", None)
        if pid is None:
            continue
        _kill_subtree(pid)
    pool.shutdown(wait=False, cancel_futures=True)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Runtime correctness + feature-gate test suite for the LLVM obfuscator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            categories:
              pass       Individual & combo pass correctness
              feature    MBA-advanced, opaque-predicate families
              options    Option parsing sweeps + alias tests (requires --extended)
              matrix     Pairwise pass interaction matrix (requires --extended)
              exhaustive Exhaustive pass-set combinations (requires --exhaustive-combos)
              adec       Anti-decompiler patterns
              budget     IR instruction budget system
              meta       Seed determinism & divergence
              cpp        C++ / EH programs
              strenc     AES-128-CTR string encryption (correctness + IR gates)
              vm         Code virtualisation pass v7 (structural + hardening gates)
        """),
    )
    ap.add_argument("--build-dir", default="", help="LLVM build directory (required unless --list)")
    ap.add_argument("--config", default="Debug", help="MSVC multi-config (Debug/Release)")
    ap.add_argument("--work", default="", help="Work directory for temp artifacts")
    ap.add_argument("--seeds", default="1", help="Comma-separated seeds (e.g. 1,2,3)")
    ap.add_argument("--inputs", default=24, type=int, help="Input pairs per test")
    ap.add_argument("--o2-gate", action="store_true", help="Test obf→O2 survival")
    ap.add_argument("--no-metrics", action="store_true", help="Skip obf-metrics collection")
    ap.add_argument("--no-gates", action="store_true", help="Skip IR feature-gate checks")
    ap.add_argument("--no-config-check", action="store_true",
                    help="Skip opt -passes=obf-dump-config validation (enabled list + option KV checks)")
    ap.add_argument("--keep", action="store_true", help="Preserve work dir on success")
    ap.add_argument("--verbose", "-v", action="store_true", help="Print all commands")
    ap.add_argument("--filter", default="", help="Run only tests matching substring")
    ap.add_argument("--category", default="",
                    help="Run only tests in category (pass/feature/options/matrix/exhaustive/adec/budget/meta/cpp)")
    ap.add_argument("--list", action="store_true", help="List all tests and exit")
    ap.add_argument("--quick", action="store_true", help="Fewer inputs (8) for fast iteration")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--json-report", default="", help="Write JSON report to path")

    ap.add_argument("--extended", action="store_true",
                    help="Enable extended option sweeps + pairwise matrix tests (slower)")
    ap.add_argument("--exhaustive-combos", action="store_true",
                    help="Generate exhaustive pass-set combos up to --combo-max-size (implies --extended)")
    ap.add_argument("--combo-max-size", default=3, type=int,
                    help="Max pass-set size for --exhaustive-combos (default: 3)")

    ap.add_argument("--obf-report", action="store_true",
                    help="Enable obfuscation map + CFG artifact report generation for every obfuscation run")
    ap.add_argument("--obf-report-out", default="",
                    help="Output directory for reports (default: ./obf_reports)")
    ap.add_argument("--obf-report-no-html", action="store_true",
                    help="Disable HTML generation (still emits JSON + DOT via -obf-report-dir)")
    ap.add_argument("--obf-report-tool", default="",
                    help="Path to obf_report_html.py (auto-detect if empty)")

    ap.add_argument("--targets", default="host",
                    help=("Comma-separated target list (default: host). "
                          f"Known: {','.join(TARGETS)}. Non-host targets run "
                          "correctness-only via cross-gcc + qemu-user; skipped "
                          "when toolchain/qemu missing."))

    _default_jobs = max(1, (os.cpu_count() or 1))
    ap.add_argument("--jobs", "-j", type=int, default=_default_jobs,
                    help=(f"Parallel worker processes (default: {_default_jobs} "
                          "= cpu count). Use 1 for serial execution with "
                          "streaming category headers and live verbose output."))
    args = ap.parse_args()

    if args.no_color:
        disable_color()

    try:
        all_targets = resolve([t.strip() for t in args.targets.split(",") if t.strip()])
    except KeyError as e:
        die(str(e))
    cross_targets = [t for t in all_targets if t.name != "host"]

    # Imported here so disable_color() takes effect before cases module loads
    # any formatter helpers at import-time.
    from cases import make_tests, run_test

    extended = bool(args.extended or args.exhaustive_combos)
    exhaustive = bool(args.exhaustive_combos)

    all_tests = make_tests(
        extended=extended,
        exhaustive_combos=exhaustive,
        combo_max_size=max(1, int(args.combo_max_size)),
    )

    if args.list:
        cur_cat = ""
        for tc in all_tests:
            if tc.category != cur_cat:
                cur_cat = tc.category
                print(f"\n  {bold(f'── {cur_cat.upper()} ──')}")
            gates = f" {dim(f'gates: {chr(44).join(tc.gates)}')}" if tc.gates else ""
            passes = dim(f"({', '.join(tc.passes)})")
            print(f"    {CYAN()}•{RST()} {tc.name} {passes}{gates}")
        print()
        return 0

    if not args.build_dir:
        die("--build-dir is required (use --list to see tests without it)")
    if args.filter:
        all_tests = [t for t in all_tests if args.filter in t.name]
    if args.category:
        all_tests = [t for t in all_tests if t.category == args.category]
    if not all_tests:
        die("no tests match the filter/category")

    build_dir = Path(args.build_dir)
    tools = detect_tools(build_dir, args.config)
    work = Path(args.work) if args.work else (Path.cwd() / "obf_rt_work")
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)

    report_enabled = bool(args.obf_report)
    report_root = Path(args.obf_report_out) if args.obf_report_out else (Path.cwd() / "obf_reports")
    report_html = bool(report_enabled and not args.obf_report_no_html)
    report_tool: Optional[Path] = None

    if report_enabled:
        if report_root.exists():
            shutil.rmtree(report_root, ignore_errors=True)
        report_root.mkdir(parents=True, exist_ok=True)

        if report_html:
            if args.obf_report_tool:
                report_tool = Path(args.obf_report_tool)
            else:
                report_tool = find_obf_report_html_tool(build_dir)
            if not report_tool or not report_tool.exists():
                report_tool = None
                report_html = False

    work.mkdir(parents=True, exist_ok=True)

    seeds  = [int(s.strip()) for s in args.seeds.split(",") if s.strip()]
    n_inp  = 8 if args.quick else args.inputs
    inputs = build_inputs(n_inp)

    print()
    print(head("╔═══════════════════════════════════════════════════════════╗"))
    print(head("║    LLVM Obfuscator — Runtime Correctness Test Suite       ║"))
    print(head("╚═══════════════════════════════════════════════════════════╝"))
    print()
    print(info(f"clang:    {tools.clang}"))
    print(info(f"opt:      {tools.opt}"))
    print(info(f"work:     {work}"))
    print(info(f"seeds:    {seeds}"))
    print(info(f"inputs:   {n_inp} pairs"))
    print(info(f"O2 gate:  {'enabled' if args.o2_gate else 'disabled'}"))
    print(info(f"gates:    {'disabled' if args.no_gates else 'enabled'}"))
    print(info(f"config:   {'disabled' if args.no_config_check else 'enabled'}"))
    print(info(f"extended: {'enabled' if extended else 'disabled'}"))
    if exhaustive:
        print(info(f"exhaustive: enabled (max size {args.combo_max_size})"))
    if report_enabled:
        print(info("reports:  enabled"))
        print(info(f"report out: {report_root}"))
        if report_html and report_tool:
            print(info(f"report html: enabled ({report_tool})"))
        else:
            print(info("report html: disabled"))
    print(info(f"tests:    {len(all_tests)}"))
    jobs = max(1, int(args.jobs))
    if jobs > len(all_tests):
        jobs = len(all_tests)
    print(info(f"jobs:     {jobs} (serial)" if jobs == 1 else f"jobs:     {jobs} parallel"))
    if cross_targets:
        avail = []
        skipped = []
        for t in cross_targets:
            ok, reason = is_available(t)
            avail.append(t.name) if ok else skipped.append(f"{t.name}({reason})")
        line = f"cross-arch: {', '.join(avail) or 'none'}"
        if skipped:
            line += f" — skipped: {', '.join(skipped)}"
        print(info(line))
    print()

    results: list = []
    t_start = time.monotonic()
    total = len(all_tests)

    def _make_payload(tc):
        return dict(
            tc=tc, tools=tools, work=work, seeds=seeds, inputs=inputs,
            o2_gate=args.o2_gate,
            no_metrics=args.no_metrics,
            no_gates=args.no_gates,
            verbose=args.verbose,
            report_enabled=report_enabled,
            report_root=report_root,
            report_html=report_html,
            report_tool=report_tool,
            config_check=(not args.no_config_check),
            cross_targets=cross_targets,
        )

    def _print_result(idx: int, tc, r, log: str) -> None:
        tag = f"[{idx}/{total}]"
        passes_s = dim(f"({', '.join(tc.passes)})")
        head_line = f"  {bold(tag)} {tc.name} {passes_s} "
        if r.status == "PASS":
            print(head_line + f"{badge_pass()} {fmt_time(r.elapsed)}")
        elif r.status == "FAIL":
            print(head_line + f"{badge_fail()} {fmt_time(r.elapsed)}")
            reason = r.reason[:130] + "..." if len(r.reason) > 133 else r.reason
            print(f"         {DIM()}{RED()}↳ {reason}{RST()}")
        else:
            print(head_line + f"{badge_skip()} {fmt_time(r.elapsed)}")
        # Flush captured worker output: verbose mode or any FAIL keeps logs.
        if log and (args.verbose or r.status == "FAIL"):
            sys.stdout.write(log)
            if not log.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()

    if jobs == 1:
        # Serial path: keep streaming category headers + live output.
        cur_cat = ""
        for i, tc in enumerate(all_tests, 1):
            if tc.category != cur_cat:
                cur_cat = tc.category
                label = cur_cat.upper()
                print(f"  {bold(f'── {label} ')}{dim('─' * (60 - len(label)))}")
            r = run_test(**_make_payload(tc))
            results.append(r)
            _print_result(i, tc, r, "")
    else:
        # Parallel path: ProcessPoolExecutor, FIFO-by-completion output.
        from concurrent.futures import ProcessPoolExecutor, as_completed

        idx_results: list[tuple[int, object]] = []
        pool = ProcessPoolExecutor(max_workers=jobs, initializer=_worker_init)
        try:
            futures = {
                pool.submit(_run_test_capture, _make_payload(tc)): (i, tc)
                for i, tc in enumerate(all_tests, 1)
            }
            try:
                for fut in as_completed(futures):
                    idx, tc = futures[fut]
                    try:
                        r, log = fut.result()
                    except Exception as e:  # crash inside worker
                        from cases import TestResult
                        r = TestResult(
                            name=tc.name, category=tc.category,
                            status="FAIL", reason=f"worker crash: {e}",
                        )
                        log = ""
                    idx_results.append((idx, r))
                    _print_result(idx, tc, r, log)
            except KeyboardInterrupt:
                print()
                print(warn("Ctrl+C — terminating workers and their subprocesses..."))
                _hard_kill_pool(pool)
                print(warn(f"Aborted after {len(idx_results)}/{total} tests"))
                return 130
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        idx_results.sort(key=lambda p: p[0])
        results = [r for _, r in idx_results]

    if report_enabled:
        idx = write_obf_reports_index(report_root, results)
        print(info(f"Obfuscation reports index → {idx}"))

    print_table(results)

    if args.json_report:
        rp = Path(args.json_report)
        write_json_report(results, rp)
        print(info(f"JSON report → {rp}"))

    failed = [r for r in results if r.status == "FAIL"]
    if failed:
        print()
        print(head("  Failed:"))
        for r in failed:
            print(f"    {RED()}✗{RST()} {r.name}: {r.reason}")
        print()
        print(f"  {BG_RED()}{BOLD()}{WHITE()} {len(failed)} FAILURE(S) {RST()}")
        print()
        return 1

    t_total = time.monotonic() - t_start
    print(f"  {BG_GREEN()}{BOLD()}{WHITE()} ALL {len(results)} TESTS PASSED {RST()}"
          f"  {fmt_time(t_total)}")
    print()

    if not args.keep:
        if report_enabled and is_subpath(report_root, work):
            print(warn("report out dir is inside work; preserving work dir to keep reports"))
        else:
            shutil.rmtree(work, ignore_errors=True)
    else:
        print(info(f"work dir preserved: {work}"))

    return 0
