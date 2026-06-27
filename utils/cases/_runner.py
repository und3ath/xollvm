"""TestResult dataclass and the run_test driver.

Lives in cases/ rather than runner/ because it depends on TestCase and the
render_*() helpers in cases._common — keeping it here avoids a back-edge
from runner→cases. runner.cli imports run_test through cases.__init__.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from gates import run_gate
from runner import cross
from runner.config import Tools
from runner.fmt import warn
from runner.pipeline import (
    compile_ll_to_exe, compile_src_to_ll, parse_dump_config_for_fn,
    run_dump_config, run_metrics, run_o2, run_obfuscation,
)
from runner.reporter.html import gen_obf_report_html
from runner.targets import Target, is_available
from runner.util import (
    compare, count_all_instructions, count_fn_instructions, exe_name,
    exec_prog, read_text, write_text,
)

from ._common import (
    TestCase, ann_for, render_aes_stub_obfuscated, render_aes_stub_passes,
    render_complex_logic_program, render_cpp_eh_program, render_program,
    render_strenc_basic, render_strenc_minlen, render_strenc_multi,
    render_strenc_xor_fallback,
)


@dataclass
class TestResult:
    name:       str
    category:   str   = "pass"
    status:     str   = "PASS"
    elapsed:    float = 0.0
    reason:     str   = ""
    base_insts: int   = 0
    obf_insts:  int   = 0
    seeds_run:  int   = 0
    inputs_run: int   = 0
    report_json: Dict[str, str] = field(default_factory=dict)
    report_html: Dict[str, str] = field(default_factory=dict)
    # Per-target cross-arch outcome: "PASS" / "SKIP: <reason>" / "FAIL: <reason>".
    cross: Dict[str, str] = field(default_factory=dict)


def _check_dump_expectations(
    tc: TestCase,
    enabled: list[str],
    ordered: list[str],
    params: Dict[str, Dict[str, str]],
) -> Optional[str]:
    exp_enabled = tc.expect_enabled or tc.passes
    if enabled != exp_enabled:
        return f"enabled mismatch: got={enabled} expected={exp_enabled}"

    if tc.expect_order and ordered != tc.expect_order:
        return f"order mismatch: got={ordered} expected={tc.expect_order}"

    if tc.expect_config:
        for pid, exp_kv in tc.expect_config.items():
            if pid not in params:
                return f"missing pass config: {pid}"
            got_kv = params.get(pid, {})
            for k, v in exp_kv.items():
                if k not in got_kv:
                    return f"pass {pid} missing key {k} (expected {k}={v})"
                if got_kv[k] != v:
                    return f"pass {pid} key {k} mismatch: got={got_kv[k]} expected={v}"
    return None


def _cross_arch_eligible(tc: TestCase) -> tuple[bool, str]:
    """Cross-arch is correctness-only via x/y inputs. Skip categories whose
    program shape or runtime semantics don't fit that model."""
    if not tc.correctness:
        return False, "correctness=False"
    if tc.ir_only:
        return False, "ir_only"
    if tc.category in ("strenc", "cpp", "meta"):
        return False, f"category={tc.category}"
    if "seed_determinism" in tc.gates or "seed_divergence" in tc.gates:
        return False, "seed-only test"
    return True, ""


def _select_program(tc: TestCase, ann: str) -> str:
    """Pick the C/C++ source text for this test case using the legacy
    name/category dispatch heuristics. src_override wins if set."""
    if tc.src_override:
        return tc.src_override
    if "eh" in tc.name:
        return render_cpp_eh_program(ann)
    if "complex" in tc.name:
        return render_complex_logic_program(ann)
    if tc.category == "strenc":
        if "multi" in tc.name:      return render_strenc_multi(ann)
        if "minlen" in tc.name:     return render_strenc_minlen(ann)
        if "xor" in tc.name:        return render_strenc_xor_fallback(ann)
        if "stub_obf" in tc.name:   return render_aes_stub_obfuscated(ann)
        if "stub_passes" in tc.name: return render_aes_stub_passes(ann)
        return render_strenc_basic(ann)
    return render_program(ann, want_strenc=("strenc" in tc.passes))


def _run_cross_arch(
    tc: TestCase, tools: Tools, tdir: Path, targets: list[Target],
    base_ll: Path, seeds: list[int],
    inputs: list[tuple[int, int]], verbose: bool,
) -> tuple[Optional[str], Dict[str, str]]:
    """Build base + first-seed obfuscated IR for each target, run via qemu,
    compare. Returns (overall_fail_reason or None, per-target status map)."""
    out: Dict[str, str] = {}
    if not targets:
        return None, out

    eligible, why = _cross_arch_eligible(tc)
    if not eligible:
        for t in targets:
            out[t.name] = f"SKIP: {why}"
        return None, out

    seed = seeds[0] if seeds else 1
    obf_ll = tdir / f"obf_s{seed}.ll"
    if not obf_ll.exists():
        for t in targets:
            out[t.name] = "SKIP: obfuscated IR missing"
        return None, out

    overall_fail: Optional[str] = None

    for t in targets:
        ok, reason = is_available(t)
        if not ok:
            out[t.name] = f"SKIP: {reason}"
            continue

        cdir = tdir / f"cross_{t.name}"
        cdir.mkdir(parents=True, exist_ok=True)
        base_exe = cdir / "base"
        obf_exe = cdir / "obf"

        try:
            cross.build_for_target(tools, base_ll, base_exe, t, verbose=verbose)
            cross.build_for_target(tools, obf_ll, obf_exe, t, verbose=verbose)
        except Exception as e:
            msg = f"build: {str(e)[:120]}"
            out[t.name] = f"FAIL: {msg}"
            if overall_fail is None:
                overall_fail = f"{t.name}: {msg}"
            continue

        mismatch = None
        for x, y in inputs:
            b = cross.exec_target(t, base_exe, x, y)
            o = cross.exec_target(t, obf_exe, x, y)
            why2 = cross.compare(b, o)
            if why2:
                mismatch = f"{why2} (x={x:#x} y={y:#x})"
                break

        if mismatch:
            out[t.name] = f"FAIL: {mismatch}"
            if overall_fail is None:
                overall_fail = f"{t.name}: {mismatch}"
        else:
            out[t.name] = "PASS"

    return overall_fail, out


def run_test(
    tc: TestCase, tools: Tools, work: Path,
    seeds: list[int], inputs: list[tuple[int, int]],
    o2_gate: bool, no_metrics: bool, no_gates: bool, verbose: bool,
    report_enabled: bool, report_root: Path, report_html: bool, report_tool: Optional[Path],
    config_check: bool, cross_targets: Optional[list[Target]] = None,
) -> TestResult:
    t0 = time.monotonic()
    res = TestResult(name=tc.name, category=tc.category)
    tdir = work / tc.name
    tdir.mkdir(parents=True, exist_ok=True)

    test_report_root: Optional[Path] = None
    if report_enabled:
        test_report_root = report_root / tc.name
        test_report_root.mkdir(parents=True, exist_ok=True)

    def _report_opts(label: str) -> tuple[list[str], Optional[Path]]:
        if not report_enabled or test_report_root is None:
            return (list(tc.extra_opts or []), None)
        rdir = test_report_root / label
        rdir.mkdir(parents=True, exist_ok=True)
        opts = list(tc.extra_opts or [])
        opts.append(f"--obf-report-dir={rdir}")
        return (opts, rdir)

    ann = tc.ann_override or ann_for(tc.passes)

    is_cpp = (tc.category == "cpp") or ("_cpp" in tc.name) or ("_eh" in tc.name)
    ext = ".cpp" if is_cpp else ".c"

    src_text = _select_program(tc, ann)
    src_file = tdir / f"test{ext}"
    write_text(src_file, src_text)

    base_ll = tdir / "base.ll"
    try:
        compile_src_to_ll(tools, src_file, base_ll, is_cpp=is_cpp, v=verbose)
    except Exception as e:
        res.status = "FAIL"
        res.reason = f"clang→ll: {e}"
        res.elapsed = time.monotonic() - t0
        return res

    base_ir = read_text(base_ll)
    res.base_insts = count_fn_instructions(base_ir, "obf_target") or count_all_instructions(base_ir)

    if config_check and not tc.no_config_check:
        try:
            seed_cfg = seeds[0] if seeds else 1
            cp = run_dump_config(tools, base_ll, seed_cfg, tc.extra_opts or None, v=verbose)
            enabled, ordered, params = parse_dump_config_for_fn(cp.stdout, "obf_target")
            if not enabled and "OBF-CONFIG-FN obf_target" not in cp.stdout:
                res.status = "FAIL"
                res.reason = "dump-config: missing OBF-CONFIG-FN obf_target block"
                res.elapsed = time.monotonic() - t0
                return res

            why = _check_dump_expectations(tc, enabled, ordered, params)
            if why:
                res.status = "FAIL"
                res.reason = f"dump-config: {why}"
                res.elapsed = time.monotonic() - t0
                return res
        except Exception as e:
            res.status = "FAIL"
            res.reason = f"dump-config: {e}"
            res.elapsed = time.monotonic() - t0
            return res

    base_exe = tdir / exe_name("base")
    try:
        compile_ll_to_exe(tools, base_ll, base_exe, "O0", is_cpp=is_cpp, v=verbose)
    except Exception as e:
        res.status = "FAIL"
        res.reason = f"base compile: {e}"
        res.elapsed = time.monotonic() - t0
        return res

    is_det = "seed_determinism" in tc.gates
    is_div = "seed_divergence" in tc.gates
    if (is_det or is_div) and not no_gates:
        s1, s2 = (42, 42) if is_det else (42, 99)
        ll_a, ll_b = tdir / "det_a.ll", tdir / "det_b.ll"
        try:
            extra_a, rdir_a = _report_opts(f"det_a_s{s1}")
            extra_b, rdir_b = _report_opts(f"det_b_s{s2}")
            run_obfuscation(tools, base_ll, ll_a, s1, extra_a or None, v=verbose)
            run_obfuscation(tools, base_ll, ll_b, s2, extra_b or None, v=verbose)

            if report_enabled and report_html and report_tool:
                for label, rdir in ((f"det_a_s{s1}", rdir_a), (f"det_b_s{s2}", rdir_b)):
                    if not rdir:
                        continue
                    j = rdir / "obf_report.json"
                    h = rdir / "obf_report.html"
                    if j.exists():
                        why2 = gen_obf_report_html(report_tool, j, h, rdir, verbose=verbose)
                        try:
                            res.report_json[label] = str(j.relative_to(report_root))
                        except Exception:
                            res.report_json[label] = str(j)
                        if h.exists():
                            try:
                                res.report_html[label] = str(h.relative_to(report_root))
                            except Exception:
                                res.report_html[label] = str(h)
                        elif why2 and verbose:
                            print(warn(f"report html failed for {tc.name}:{label}: {why2}"))

        except Exception as e:
            res.status = "FAIL"
            res.reason = f"obf: {e}"
            res.elapsed = time.monotonic() - t0
            return res

        ir_a, ir_b = read_text(ll_a), read_text(ll_b)
        key = "seed_determinism" if is_det else "seed_divergence"
        why = run_gate(key, ir_a=ir_a, ir_b=ir_b)
        if why:
            res.status = "FAIL"
            res.reason = f"gate [{key}]: {why}"
        res.obf_insts = count_fn_instructions(ir_a, "obf_target")
        res.seeds_run = 2
        res.elapsed = time.monotonic() - t0
        return res

    for seed in seeds:
        obf_ll  = tdir / f"obf_s{seed}.ll"
        obf_exe = tdir / exe_name(f"obf_s{seed}")

        try:
            extra_opts, rdir = _report_opts(f"seed_{seed}")
            cp = run_obfuscation(tools, base_ll, obf_ll, seed, extra_opts or None, v=verbose)
        except Exception as e:
            res.status = "FAIL"
            res.reason = f"seed {seed}: opt: {e}"
            break

        obf_ir = read_text(obf_ll)

        if report_enabled and rdir is not None:
            j = rdir / "obf_report.json"
            h = rdir / "obf_report.html"
            if j.exists():
                try:
                    res.report_json[f"seed_{seed}"] = str(j.relative_to(report_root))
                except Exception:
                    res.report_json[f"seed_{seed}"] = str(j)

                if report_html and report_tool:
                    why2 = gen_obf_report_html(report_tool, j, h, rdir, verbose=verbose)
                    if h.exists():
                        try:
                            res.report_html[f"seed_{seed}"] = str(h.relative_to(report_root))
                        except Exception:
                            res.report_html[f"seed_{seed}"] = str(h)
                    elif why2 and verbose:
                        print(warn(f"report html failed for {tc.name}:seed_{seed}: {why2}"))

        n = count_fn_instructions(obf_ir, "obf_target")
        res.obf_insts = max(res.obf_insts, n or count_all_instructions(obf_ir))
        res.seeds_run += 1

        if not no_gates and tc.gates:
            stderr_text = cp.stderr or ""
            for gk in tc.gates:
                why = run_gate(gk, obf_ir=obf_ir, base_ir=base_ir, stderr_text=stderr_text)
                if why:
                    res.status = "FAIL"
                    res.reason = f"seed {seed}: gate [{gk}]: {why}"
                    break
            if res.status == "FAIL":
                break

        if tc.ir_only:
            continue

        try:
            compile_ll_to_exe(tools, obf_ll, obf_exe, "O0", is_cpp=is_cpp, v=verbose)
        except Exception as e:
            res.status = "FAIL"
            res.reason = f"seed {seed}: compile: {e}"
            break

        if tc.correctness:
            fail = False
            if tc.category == "strenc":
                rc, stdout, _stderr = exec_prog(obf_exe, 0, 0)
                if rc != 0:
                    res.status = "FAIL"
                    res.reason = (f"seed {seed}: strenc binary exited {rc} "
                                  f"(stdout={stdout.strip()!r})")
                    fail = True
                else:
                    res.inputs_run += 1
            else:
                for x, y in inputs:
                    b = exec_prog(base_exe, x, y)
                    o = exec_prog(obf_exe, x, y)
                    why = compare(b, o)
                    if why:
                        res.status = "FAIL"
                        res.reason = f"seed {seed}: {why} (x={x:#x} y={y:#x})"
                        fail = True
                        break
                    res.inputs_run += 1
            if fail:
                break

        if o2_gate:
            b_o2_ll  = tdir / "base_O2.ll"
            o_o2_ll  = tdir / f"obf_s{seed}_O2.ll"
            b_o2_exe = tdir / exe_name("base_O2")
            o_o2_exe = tdir / exe_name(f"obf_s{seed}_O2")
            try:
                run_o2(tools, base_ll, b_o2_ll, v=verbose)
                run_o2(tools, obf_ll, o_o2_ll, v=verbose)
                compile_ll_to_exe(tools, b_o2_ll, b_o2_exe, "O0", is_cpp=is_cpp, v=verbose)
                compile_ll_to_exe(tools, o_o2_ll, o_o2_exe, "O0", is_cpp=is_cpp, v=verbose)
            except Exception as e:
                res.status = "FAIL"
                res.reason = f"seed {seed}: O2: {e}"
                break

            fail = False
            for x, y in inputs:
                b = exec_prog(b_o2_exe, x, y)
                o = exec_prog(o_o2_exe, x, y)
                why = compare(b, o)
                if why:
                    res.status = "FAIL"
                    res.reason = f"seed {seed}: O2: {why} (x={x:#x} y={y:#x})"
                    fail = True
                    break
            if fail:
                break

        if not no_metrics:
            try:
                bm = run_metrics(tools, base_ll, "obf_target")
                om = run_metrics(tools, obf_ll, "obf_target")
                mf = tdir / "metrics.jsonl"
                with open(mf, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "test": tc.name,
                        "seed": seed,
                        "passes": tc.passes,
                        "base": bm,
                        "obf": om,
                    }) + "\n")
            except Exception:
                pass

    if res.status == "PASS" and cross_targets:
        fail_reason, per_target = _run_cross_arch(
            tc, tools, tdir, cross_targets, base_ll, seeds, inputs, verbose,
        )
        res.cross = per_target
        if fail_reason:
            res.status = "FAIL"
            res.reason = f"cross-arch [{fail_reason}]"

    res.elapsed = time.monotonic() - t0
    return res
