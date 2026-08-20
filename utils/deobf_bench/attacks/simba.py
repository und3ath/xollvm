"""SiMBA linear-MBA resilience attack.

Where the `mba` attack throws a general SMT solver (Z3) at the recovered
expression, this one throws **SiMBA** — Denuvo's dedicated *linear* MBA
simplifier (Reichenwallner & Meinhardt). SiMBA maps a linear MBA to the 1-bit
domain and solves it algebraically in microseconds, defeating linear MBA that
Z3 times out on. It is the real-world threat that a *nonlinear* obfuscation
layer (the input-derived cube/pow4 zeros) must survive.

Model: lift the `obf_target` return value from LLVM IR to a C-like infix
expression string over the inputs `a`, `b` (memory loads / calls / other opaque
IR become fresh free variables), then:

  * if the expression is NOT a linear MBA (contains var*var, shifts, urem, ...),
    SiMBA is out of scope -> the obfuscation survived this attacker -> resilience 1.
  * else run SiMBA and compare its simplification to SiMBA's simplification of
    the canonical op (`a+b`, `a^b`, ...). Equal => fully recovered => resilience 0.
    Not equal (or too many free vars for SiMBA's 2^n enumeration) => resilience 1.

SiMBA is vendored as a sibling clone: llvm-o/SiMBA (src/simplify.py).
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Dict, Optional

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate
from .mba_smt import _extract_fn_body, _strip_flags, _width, UnsupportedIR

# ---- locate the vendored SiMBA clone (llvm-o/SiMBA/src) ----
_SIMBA_SRC = Path(__file__).resolve().parents[4] / "SiMBA" / "src"
_SIMBA_OK = _SIMBA_SRC.is_dir()
if _SIMBA_OK and str(_SIMBA_SRC) not in sys.path:
    sys.path.insert(0, str(_SIMBA_SRC))

BITS = 32
MASK = (1 << BITS) - 1
MAX_FREE_VARS = 4          # SiMBA enumerates 2^vars; bail past this
_SIMPLIFY_TIMEOUT_S = 20   # wall guard around a single simplify call


class _Nonlinear(Exception):
    """Raised when the lifted expression is not a linear MBA (SiMBA out of scope)."""


class StringLifter:
    """Mirror of mba_smt.Lifter but emits a C-like infix string (SiMBA syntax).

    Any construct that makes the expression non-linear (var*var, shifts by a
    non-constant, div/rem, icmp/select) raises _Nonlinear — the honest signal
    that a linear simplifier cannot touch it."""

    def __init__(self, arg_names: list[str]):
        self.env: Dict[str, str] = {a: a for a in arg_names}
        self.mem: Dict[str, str] = {}
        self.free: Dict[str, str] = {}
        self._n = 0

    def _fresh(self, key: str) -> str:
        if key not in self.free:
            self.free[key] = f"u{len(self.free)}"
        return self.free[key]

    def _const(self, v: int) -> str:
        return str(v & MASK)

    def _is_const(self, s: str) -> bool:
        return bool(re.fullmatch(r"\d+", s))

    def _resolve(self, tok: str) -> str:
        tok = tok.strip()
        if tok.startswith("%"):
            reg = tok[1:]
            return self.env.get(reg) or self._fresh(reg)
        if tok in ("true", "false"):
            return "1" if tok == "true" else "0"
        if re.fullmatch(r"-?\d+", tok):
            return self._const(int(tok))
        raise UnsupportedIR(f"operand: {tok!r}")

    def _ops2(self, rest: str):
        parts = rest.split(",")
        head = parts[0].strip()
        m = re.match(r"^\S+\s+(\S+)$", head)
        if not m:
            raise UnsupportedIR(f"operands: {rest!r}")
        x = m.group(1)
        y = parts[1].strip() if len(parts) > 1 else None
        if y is None:
            raise UnsupportedIR(f"need 2 operands: {rest!r}")
        return self._resolve(x), self._resolve(y)

    def run(self, body: str) -> str:
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith(";"):
                continue
            if line.endswith(":") and "=" not in line:
                continue
            if line.startswith("ret "):
                rest = line[4:].strip()
                if rest == "void":
                    raise UnsupportedIR("ret void")
                m = re.match(r"^\S+\s+(.+)$", rest)
                if not m:
                    raise UnsupportedIR(f"ret: {line!r}")
                return self._resolve(m.group(1))
            if line.startswith(("br ", "switch ", "indirectbr", "unreachable",
                                "resume ", "invoke ", "landingpad", "call void")):
                raise UnsupportedIR(f"control-flow: {line.split()[0]}")
            if line.startswith("store "):
                self._store(_strip_flags(line[6:]))
                continue
            m = re.match(r"^%([\w.]+)\s*=\s*(.+)$", line)
            if not m:
                continue
            self.env[m.group(1)] = self._eval(_strip_flags(m.group(2)))
        raise UnsupportedIR("fell off end without ret")

    def _store(self, rest: str):
        m = re.match(r"^(\S+)\s+(\S+)\s*,\s*ptr\s+%([\w.]+)", rest)
        if m:
            self.mem[m.group(3)] = self._resolve(m.group(2))

    def _eval(self, expr: str) -> str:
        m = re.match(r"^(\w+)\s+(.*)$", expr)
        if not m:
            raise UnsupportedIR(f"instr: {expr!r}")
        op, rest = m.group(1), m.group(2)

        if op == "alloca":
            return "0"
        if op in ("add", "sub", "or", "and", "xor"):
            x, y = self._ops2(rest)
            sym = {"add": "+", "sub": "-", "or": "|", "and": "&", "xor": "^"}[op]
            return f"({x} {sym} {y})"
        if op == "mul":
            x, y = self._ops2(rest)
            if not (self._is_const(x) or self._is_const(y)):
                raise _Nonlinear("var*var")          # nonlinear
            return f"({x} * {y})"
        if op == "shl":
            x, y = self._ops2(rest)
            if not self._is_const(y):
                raise _Nonlinear("shl by non-const")
            return f"({x} * {1 << (int(y) % BITS)})"
        if op in ("lshr", "ashr", "udiv", "sdiv", "urem", "srem"):
            raise _Nonlinear(op)                     # not a linear MBA op
        if op in ("icmp", "select"):
            raise _Nonlinear(op)
        if op in ("zext", "sext", "trunc", "freeze"):
            # width change / freeze: pass the value through (single-width model)
            mm = re.match(r"^\S+\s+(\S+)", rest) if op != "freeze" else re.match(r"^\S+\s+(\S+)$", rest)
            if not mm:
                raise UnsupportedIR(f"{op}: {rest!r}")
            return self._resolve(mm.group(1))
        if op == "load":
            m2 = re.match(r"^\S+\s*,\s*ptr\s+%([\w.]+)", rest)
            if m2 and m2.group(1) in self.mem:
                return self.mem[m2.group(1)]
            return self._fresh(f"load.{m2.group(1) if m2 else 'x'}")
        # calls, gep, phi, ptrtoint, ...: opaque free var
        return self._fresh(f"op.{op}.{len(self.env)}")


_TOOL = "SiMBA"
_TECHNIQUE = "linear-MBA simplification (1-bit domain algebra; IR lifted to infix, simplified vs canonical)"


@register("simba")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status, resil, detail, extra=None):
        return AttackResult(case.name, "simba", seed, status, resil, detail,
                            _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    if not _SIMBA_OK:
        return mk("SKIP", None, f"SiMBA clone not found at {_SIMBA_SRC}")
    try:
        from simplify import simplify_linear_mba
        from check_linear_mba import check_linear_mba
    except Exception as e:
        return mk("SKIP", None, f"SiMBA import failed: {e}")

    try:
        prog("compiling + obfuscating (clang -O0, opt -passes=obfuscation)")
        obf_ll = compile_and_obfuscate(tools, case, work, seed, verbose=verbose)
        body = _extract_fn_body(obf_ll.read_text(encoding="utf-8", errors="replace"),
                                "obf_target")
        if body is None:
            return mk("FAIL", None, "obf_target not found in obfuscated IR")

        prog("lifting IR to infix expression")
        lifter = StringLifter(["a", "b"])
        try:
            expr = lifter.run(body)
        except _Nonlinear as e:
            return mk("PASS", 1.0,
                      f"not a linear MBA ({e}) — SiMBA out of scope, obfuscation survived",
                      {"reason": "nonlinear"})

        nfree = len(lifter.free)
        extra = {"free_vars": str(nfree), "expr_len": str(len(expr))}

        if not check_linear_mba(expr):
            return mk("PASS", 1.0, "SiMBA linearity check: not a linear MBA (survived)",
                      {**extra, "reason": "nonlinear-checker"})
        if nfree > MAX_FREE_VARS:
            return mk("PASS", 1.0,
                      f"{nfree} free vars > {MAX_FREE_VARS}: SiMBA 2^n enumeration infeasible (survived)",
                      {**extra, "reason": "too-many-vars"})

        op = case.ground_truth["op"]
        canon = {"add": "a + b", "sub": "a - b", "xor": "a ^ b",
                 "and": "a & b", "or": "a | b"}.get(op, f"a {op} b")

        prog(f"SiMBA simplifying (bits={BITS})")
        t_s = time.monotonic()
        got = simplify_linear_mba(expr, BITS, False)
        want = simplify_linear_mba(canon, BITS, False)
        simp_ms = (time.monotonic() - t_s) * 1000
        extra.update({"simplified": got[:120], "canonical": want, "simplify_ms": f"{simp_ms:.1f}"})

        if got.strip() == want.strip():
            return mk("PASS", 0.0,
                      f"SiMBA recovered '{want}' (linear MBA fully simplified)", extra)
        return mk("PASS", 1.0,
                  f"SiMBA simplified to '{got[:80]}' != canonical '{want}' (survived)", extra)

    except UnsupportedIR as e:
        return mk("FAIL", None, f"lifter hit unsupported construct: {e}")
    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
