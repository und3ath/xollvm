"""MBA (mixed-boolean-arithmetic) resilience attack via SMT equivalence.

Lifts the textual LLVM IR of a single-block, single-return function to a Z3
bitvector expression (a generic straight-line SSA interpreter — no LLVM
bindings needed, `opt -S` output is regular enough to parse with regexes),
then asks Z3 to prove the recovered expression is semantically equivalent to
the simple canonical op (`a+b`, `a^b`, ...) the MBA pass rewrote away.

`unsat` on `recovered != canonical` means Z3 proved equivalence — the MBA
obfuscation was fully undone algebraically (resilience 0 for that site).
`sat`/`unknown`/timeout means the attack failed to collapse it (resilience 1).

Any IR construct this lifter doesn't model concretely (calls, GEPs, PHIs,
ptrtoint/inttoptr, ...) becomes a fresh free symbolic bitvector instead of
aborting — this matches the real attack model: an analyst without the
compiler's internal state (e.g. a stack address used as a per-call nonce)
sees exactly the same opacity. If the surrounding code is a true identity
regardless of that nonce, Z3 still proves it; if not, that's a genuine
resilience win for the obfuscator, not a lifter limitation.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Dict, Optional

from . import AttackResult, register
from .. import cases as cases_mod
from ..runner_glue import compile_and_obfuscate

_SOLVER_TIMEOUT_MS = 5000

# Type tokens (`i32`, `i64`, ...) are always preceded by whitespace, `(`, or
# `,` in `opt -S` output. A plain `\bi(\d+)\b` also matches inside dotted
# identifier names this codebase uses heavily (e.g. `%obf.entropy.i8`,
# `%obf.mba.noise.i32`) since `.` is a non-word char — that false match
# silently picks up the wrong width. Require a real token boundary instead.
_TYPE_WIDTH = re.compile(r"(?:^|[\s,(])i(\d+)\b")

_BINOPS = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "mul": lambda a, b: a * b,
    "and": lambda a, b: a & b,
    "or":  lambda a, b: a | b,
    "xor": lambda a, b: a ^ b,
    "shl": lambda a, b: a << b,
}

_ICMP_OPS = {
    "eq": lambda z3m, a, b: a == b,
    "ne": lambda z3m, a, b: a != b,
    "ugt": lambda z3m, a, b: z3m.UGT(a, b),
    "uge": lambda z3m, a, b: z3m.UGE(a, b),
    "ult": lambda z3m, a, b: z3m.ULT(a, b),
    "ule": lambda z3m, a, b: z3m.ULE(a, b),
    "sgt": lambda z3m, a, b: a > b,
    "sge": lambda z3m, a, b: a >= b,
    "slt": lambda z3m, a, b: a < b,
    "sle": lambda z3m, a, b: a <= b,
}


class UnsupportedIR(Exception):
    pass


def _extract_fn_body(ir: str, fn_name: str) -> Optional[str]:
    m = re.search(rf"^define\s[^\n]*@{re.escape(fn_name)}\s*\([^\n]*\{{", ir, re.MULTILINE)
    if not m:
        return None
    depth = 1
    start = m.end()
    i = start
    while i < len(ir) and depth > 0:
        if ir[i] == "{":
            depth += 1
        elif ir[i] == "}":
            depth -= 1
        i += 1
    return ir[start:i - 1]


def _width(type_str: str) -> int:
    m = _TYPE_WIDTH.search(type_str)
    if not m:
        raise UnsupportedIR(f"unrecognized type: {type_str!r}")
    return int(m.group(1))


def _strip_flags(rest: str) -> str:
    # Drop nsw/nuw/exact/volatile keywords that can precede the type.
    for kw in ("nsw", "nuw", "exact", "volatile", "inbounds"):
        rest = re.sub(rf"\b{kw}\b\s*", "", rest)
    return rest.strip()


class Lifter:
    def __init__(self, z3mod, arg_names: list[str], arg_width: int = 32):
        self.z3 = z3mod
        self.env: Dict[str, "object"] = {}
        self.mem: Dict[str, "object"] = {}
        self._fresh_cache: Dict[str, "object"] = {}
        for a in arg_names:
            self.env[a] = z3mod.BitVec(a, arg_width)

    def _fresh(self, name: str, width: int):
        key = f"{name}:{width}"
        if key not in self._fresh_cache:
            self._fresh_cache[key] = self.z3.BitVec(f"unk_{name}", width)
        return self._fresh_cache[key]

    def _resolve(self, token: str, width: int):
        token = token.strip()
        if token.startswith("%"):
            reg = token[1:]
            if reg in self.env:
                return self.env[reg]
            return self._fresh(reg, width)
        if token in ("true", "false"):
            return self.z3.BitVecVal(1 if token == "true" else 0, 1)
        m = re.match(r"^-?\d+$", token)
        if m:
            return self.z3.BitVecVal(int(token), width)
        raise UnsupportedIR(f"unrecognized operand: {token!r}")

    def _split_type_operands(self, rest: str, n: int) -> tuple[str, list[str]]:
        """`i32 %a, %b` (n=2) -> ("i32", ["%a", "%b"])."""
        parts = rest.split(",")
        head = parts[0].strip()
        type_m = re.match(r"^(\S+)\s+(\S+)$", head)
        if not type_m:
            raise UnsupportedIR(f"can't split type/operand: {rest!r}")
        ty, first_operand = type_m.group(1), type_m.group(2)
        operands = [first_operand] + [p.strip() for p in parts[1:1 + (n - 1)]]
        if len(operands) != n:
            raise UnsupportedIR(f"expected {n} operands in: {rest!r}")
        return ty, operands

    def run(self, body: str) -> "object":
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith(";"):
                continue
            if line.endswith(":") and "=" not in line:
                continue  # basic block label
            if line.startswith("ret "):
                rest = line[len("ret "):].strip()
                if rest == "void":
                    raise UnsupportedIR("ret void")
                ty_m = re.match(r"^(\S+)\s+(.+)$", rest)
                if not ty_m:
                    raise UnsupportedIR(f"bad ret: {line!r}")
                ty, val = ty_m.group(1), ty_m.group(2)
                return self._resolve(val, _width(ty))
            if line.startswith(("br ", "switch ", "indirectbr", "unreachable",
                                 "resume ", "invoke ", "landingpad", "catch",
                                 "call void")):
                raise UnsupportedIR(f"unsupported control-flow/void: {line.split()[0]}")

            if line.startswith("store "):
                # No `%dst = ` LHS to dispatch on — this only mutates `mem`.
                self._eval_def("<store>", _strip_flags(line))
                continue

            m = re.match(r"^%([\w.]+)\s*=\s*(.+)$", line)
            if not m:
                continue
            dst, expr = m.group(1), _strip_flags(m.group(2))
            self.env[dst] = self._eval_def(dst, expr)
        raise UnsupportedIR("fell off end of function body without `ret`")

    def _eval_def(self, dst: str, expr: str):
        head_m = re.match(r"^(\w+)\s+(.*)$", expr)
        if not head_m:
            raise UnsupportedIR(f"bad instruction: {expr!r}")
        op, rest = head_m.group(1), head_m.group(2)

        if op == "alloca":
            return None  # pointer identity irrelevant; only mem[] tracked via store/load

        if op in _BINOPS:
            ty, (x, y) = self._split_type_operands(rest, 2)
            w = _width(ty)
            return _BINOPS[op](self._resolve(x, w), self._resolve(y, w))

        if op in ("lshr", "ashr"):
            ty, (x, y) = self._split_type_operands(rest, 2)
            w = _width(ty)
            xv, yv = self._resolve(x, w), self._resolve(y, w)
            return self.z3.LShR(xv, yv) if op == "lshr" else xv >> yv

        if op in ("udiv", "sdiv", "urem", "srem"):
            ty, (x, y) = self._split_type_operands(rest, 2)
            w = _width(ty)
            xv, yv = self._resolve(x, w), self._resolve(y, w)
            if op == "udiv":
                return self.z3.UDiv(xv, yv)
            if op == "urem":
                return self.z3.URem(xv, yv)
            if op == "sdiv":
                return xv / yv
            return self.z3.SRem(xv, yv)

        if op == "icmp":
            cond_m = re.match(r"^(\w+)\s+(.+)$", rest)
            if not cond_m:
                raise UnsupportedIR(f"bad icmp: {rest!r}")
            cond, tail = cond_m.group(1), cond_m.group(2)
            if cond not in _ICMP_OPS:
                raise UnsupportedIR(f"unsupported icmp cond: {cond!r}")
            ty, (x, y) = self._split_type_operands(tail, 2)
            w = _width(ty)
            b = _ICMP_OPS[cond](self.z3, self._resolve(x, w), self._resolve(y, w))
            return self.z3.If(b, self.z3.BitVecVal(1, 1), self.z3.BitVecVal(0, 1))

        if op == "select":
            parts = rest.split(",")
            if len(parts) != 3:
                raise UnsupportedIR(f"bad select: {rest!r}")
            cond_m = re.match(r"^i1\s+(\S+)$", parts[0].strip())
            if not cond_m:
                raise UnsupportedIR(f"bad select cond: {parts[0]!r}")
            cond = self._resolve(cond_m.group(1), 1)
            t_m = re.match(r"^(\S+)\s+(\S+)$", parts[1].strip())
            f_m = re.match(r"^(\S+)\s+(\S+)$", parts[2].strip())
            if not t_m or not f_m:
                raise UnsupportedIR(f"bad select arms: {rest!r}")
            wt = _width(t_m.group(1))
            tv = self._resolve(t_m.group(2), wt)
            fv = self._resolve(f_m.group(2), _width(f_m.group(1)))
            return self.z3.If(cond == 1, tv, fv)

        if op in ("zext", "sext", "trunc"):
            m2 = re.match(r"^(\S+)\s+(\S+)\s+to\s+(\S+)$", rest)
            if not m2:
                raise UnsupportedIR(f"bad {op}: {rest!r}")
            ty_from, val, ty_to = m2.group(1), m2.group(2), m2.group(3)
            w_from, w_to = _width(ty_from), _width(ty_to)
            v = self._resolve(val, w_from)
            if op == "trunc":
                return self.z3.Extract(w_to - 1, 0, v)
            pad = w_to - w_from
            if pad <= 0:
                return v
            return self.z3.ZeroExt(pad, v) if op == "zext" else self.z3.SignExt(pad, v)

        if op == "freeze":
            m2 = re.match(r"^(\S+)\s+(\S+)$", rest)
            if not m2:
                raise UnsupportedIR(f"bad freeze: {rest!r}")
            return self._resolve(m2.group(2), _width(m2.group(1)))

        if op in ("ptrtoint", "inttoptr"):
            # Not modeled concretely (real address), but keyed by the
            # *source* operand rather than falling through to the generic
            # dst-keyed fallback below: repeated `ptrtoint` of the same
            # pointer (very common — e.g. an entropy-source alloca read at
            # several call sites) must resolve to the same free variable
            # each time, or an attack modeling "is X always true regardless
            # of this unknown" sees spurious counterexamples from treating
            # one real unknown as several independent ones.
            m2 = re.match(r"^\S+\s+(\S+)\s+to\s+(\S+)$", rest)
            if not m2:
                raise UnsupportedIR(f"bad {op}: {rest!r}")
            src, ty_to = m2.group(1), m2.group(2)
            return self._fresh(f"{op}.{src}", _width(ty_to))

        if op == "store":
            m2 = re.match(r"^(\S+)\s+(\S+)\s*,\s*ptr\s+%([\w.]+)", rest)
            if not m2:
                raise UnsupportedIR(f"bad store: {rest!r}")
            ty, val, ptr = m2.group(1), m2.group(2), m2.group(3)
            self.mem[ptr] = self._resolve(val, _width(ty))
            return None

        if op == "load":
            m2 = re.match(r"^(\S+)\s*,\s*ptr\s+%([\w.]+)", rest)
            if not m2:
                raise UnsupportedIR(f"bad load: {rest!r}")
            ty, ptr = m2.group(1), m2.group(2)
            w = _width(ty)
            if ptr in self.mem and self.mem[ptr] is not None:
                return self.mem[ptr]
            return self._fresh(f"load.{ptr}", w)

        # calls, GEPs, ptrtoint/inttoptr, phis, etc: opaque fresh input.
        w_m = _TYPE_WIDTH.search(rest)
        width = int(w_m.group(1)) if w_m else 32
        return self._fresh(dst, width)


def _canonical(z3mod, op: str, a, b):
    # eq/ne match the C idiom `return a == b;` — an i1 comparison the
    # compiler zext's to the function's i32 return type.
    return {
        "add": lambda: a + b,
        "sub": lambda: a - b,
        "xor": lambda: a ^ b,
        "and": lambda: a & b,
        "or":  lambda: a | b,
        "eq":  lambda: z3mod.If(a == b, z3mod.BitVecVal(1, a.size()), z3mod.BitVecVal(0, a.size())),
        "ne":  lambda: z3mod.If(a != b, z3mod.BitVecVal(1, a.size()), z3mod.BitVecVal(0, a.size())),
    }[op]()


_TOOL = "z3-solver"
_TECHNIQUE = "SMT bitvector equivalence proof (IR lifted to Z3, checked vs. canonical op)"


@register("mba")
def run(case: "cases_mod.BenchCase", tools, work: Path, seed: int, *,
        verbose: bool = False, progress=None) -> AttackResult:
    t0 = time.monotonic()
    prog = progress or (lambda msg: None)

    def mk(status: str, resilience, detail: str, extra: dict | None = None) -> AttackResult:
        return AttackResult(case.name, "mba", seed, status, resilience, detail,
                             _TOOL, _TECHNIQUE, time.monotonic() - t0, extra or {})

    try:
        import z3
    except ImportError as e:
        return mk("SKIP", None, f"z3-solver not importable: {e}")

    try:
        prog("compiling + obfuscating (clang -O0, opt -passes=obfuscation)")
        obf_ll = compile_and_obfuscate(tools, case, work, seed, verbose=verbose)
        obf_ir = obf_ll.read_text(encoding="utf-8", errors="replace")
        body = _extract_fn_body(obf_ir, "obf_target")
        if body is None:
            return mk("FAIL", None, "obf_target not found in obfuscated IR")

        prog(f"lifting {len(body.splitlines())} IR lines to Z3 bitvector expr")
        lifter = Lifter(z3, ["a", "b"])
        t_lift0 = time.monotonic()
        recovered = lifter.run(body)
        lift_ms = (time.monotonic() - t_lift0) * 1000

        a, b = lifter.env["a"], lifter.env["b"]
        op = case.ground_truth["op"]
        canonical = _canonical(z3, op, a, b)

        s = z3.Solver()
        s.set("timeout", _SOLVER_TIMEOUT_MS)
        s.add(recovered != canonical)
        prog(f"Z3 solving (unsat = broken), timeout={_SOLVER_TIMEOUT_MS}ms")
        t_solve0 = time.monotonic()
        verdict = s.check()
        solve_ms = (time.monotonic() - t_solve0) * 1000

        ir_insts = len(body.splitlines())
        extra = {
            "ir_instructions": str(ir_insts),
            "free_vars_beyond_a_b": str(len(lifter._fresh_cache)),
            "lift_ms": f"{lift_ms:.1f}",
            "solve_ms": f"{solve_ms:.1f}",
            "solver_timeout_ms": str(_SOLVER_TIMEOUT_MS),
            "z3_verdict": str(verdict),
        }

        if verdict == z3.unsat:
            return mk("PASS", 0.0,
                       f"proved recovered == a {op} b (equivalence found, unsat, "
                       f"{_SOLVER_TIMEOUT_MS}ms budget)", extra)
        if verdict == z3.sat:
            reason = "sat (counterexample exists — not equivalent to canonical op)"
        elif verdict == z3.unknown:
            reason = f"unknown (solver gave up: {s.reason_unknown()})"
        else:
            reason = str(verdict)
        return mk("PASS", 1.0,
                   f"could not prove equivalence to a {op} b: {reason} "
                   f"({_SOLVER_TIMEOUT_MS}ms budget)", extra)

    except UnsupportedIR as e:
        return mk("FAIL", None, f"IR lifter hit unsupported construct: {e}")
    except Exception as e:
        return mk("FAIL", None, f"attack crashed: {e}")
