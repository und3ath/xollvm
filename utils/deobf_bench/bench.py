"""Orchestrator: run each BenchCase's attack across the requested seeds.

`run_bench` is a generator — it yields each AttackResult as soon as that
(case, seed) finishes, instead of collecting everything silently and
returning a list at the end. A single angr/Z3 call can run for minutes;
without streaming, a caller has no visibility into progress and no way to
tell a slow case apart from a genuinely hung one.

Each case runs under a wall-clock watchdog (`case_timeout`) via a daemon
thread — plain `threading.Thread(daemon=True)`, not `ThreadPoolExecutor`
(whose worker threads are non-daemon by design and would block process
exit forever on an abandoned case; angr's symbolic exploration can runaway
into multi-GB memory well past any timeout, so waiting for it to "finish"
is not an option). A timed-out case's thread is simply abandoned; the OS
reclaims it when the process exits.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from . import attacks as attacks_mod
from .attacks import AttackResult
from .cases import BenchCase

_DEFAULT_CASE_TIMEOUT_S = 60


def run_bench(tools, work: Path, cases: List[BenchCase], seeds: List[int],
              *, verbose: bool = False,
              progress: Optional[Callable[[str, str, int, str], None]] = None,
              case_timeout: float = _DEFAULT_CASE_TIMEOUT_S) -> Iterator[AttackResult]:
    """progress(case_name, attack, seed, phase_msg) is called from inside the
    attack's own worker thread at each phase boundary — safe to print from
    directly since it shares stdout with the main thread."""
    attacks_mod.load_all()
    for case in cases:
        fn = attacks_mod.get(case.attack)
        for seed in seeds:
            last_phase = ["(not started)"]

            def on_phase(msg: str, _case=case, _seed=seed, _last=last_phase) -> None:
                _last[0] = msg
                if progress:
                    progress(_case.name, _case.attack, _seed, msg)

            box: list = []

            def worker(_case=case, _seed=seed, _phase=on_phase, _box=box) -> None:
                _box.append(fn(_case, tools, work, _seed, verbose=verbose, progress=_phase))

            t0 = time.monotonic()
            th = threading.Thread(target=worker, daemon=True,
                                   name=f"deobf-bench-{case.name}-s{seed}")
            th.start()
            th.join(timeout=case_timeout)

            if th.is_alive():
                yield AttackResult(
                    case.name, case.attack, seed, "FAIL", None,
                    f"exceeded {case_timeout:.0f}s wall-clock budget "
                    f"(stuck at: {last_phase[0]}) — thread abandoned, "
                    f"still running in background",
                    tool="?", technique="?", elapsed=time.monotonic() - t0,
                )
            else:
                yield box[0]
