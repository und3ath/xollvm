"""--extended suite: option sweeps, alias normalization, recommended order,
and pairwise pass-interaction matrix.

Gated on the --extended CLI flag (passed through opts["extended"]).
"""

from __future__ import annotations

from typing import Any, Dict

from ._common import PASSES, Registry, ann_specs, pass_spec


OPTION_SWEEPS: Dict[str, list[tuple[str, Dict[str, Any]]]] = {
    "bcf": [
        ("prob0", {"prob": 0}),
        ("prob100", {"prob": 100}),
        ("loop1", {"loop": 1}),
        ("loop10", {"loop": 10}),
        ("maxBlocks0", {"maxBlocks": 0}),
        ("maxBlocks100", {"maxBlocks": 100}),
    ],
    "split": [
        ("num2", {"num": 2}),
        ("num5", {"num": 5}),
        ("num10", {"num": 10}),
    ],
    "substitution": [
        ("loop1", {"loop": 1}),
        ("loop10", {"loop": 10}),
        ("maxSites0", {"maxSites": 0}),
        ("maxSites1", {"maxSites": 1}),
        ("maxSites100000", {"maxSites": 100000}),
    ],
    "mba": [
        ("prob0", {"prob": 0, "depth": 2, "maxSites": 200}),
        ("depth1", {"prob": 100, "depth": 1, "maxSites": 200}),
        ("depth10", {"prob": 100, "depth": 10, "maxSites": 200}),
        ("maxSites1", {"prob": 100, "depth": 2, "maxSites": 1}),
        ("maxSites5000", {"prob": 100, "depth": 2, "maxSites": 5000}),
        ("termsMin1", {"prob": 100, "depth": 2, "maxSites": 200, "termsMin": 1, "termsMax": 1}),
        ("termsMax96", {"prob": 100, "depth": 2, "maxSites": 200, "termsMin": 64, "termsMax": 96}),
        ("nonlinearOff", {"prob": 100, "depth": 2, "maxSites": 200, "enableNonLinear": 0}),
        ("nonlinearW100", {"prob": 100, "depth": 2, "maxSites": 200, "nonLinearWeight": 100}),
        ("layeredOff", {"prob": 100, "depth": 2, "maxSites": 200, "enableLayered": 0}),
        ("layeredWin256", {"prob": 100, "depth": 2, "maxSites": 200, "layeredWindow": 256}),
        ("layeredBudget32", {"prob": 100, "depth": 2, "maxSites": 200, "layeredBudget": 32}),
    ],
    "sdiff": [
        ("prob1", {"prob": 1, "slots": 2, "maxSites": 40}),
        ("prob100", {"prob": 100, "slots": 2, "maxSites": 40}),
        ("slots1", {"prob": 100, "slots": 1, "maxSites": 40}),
        ("slots8", {"prob": 100, "slots": 8, "maxSites": 40}),
        ("maxSites1", {"prob": 100, "slots": 2, "maxSites": 1}),
        ("maxSites2000", {"prob": 100, "slots": 2, "maxSites": 2000}),
    ],
    "vcall": [
        ("prob0", {"prob": 0}),
        ("prob100", {"prob": 100}),
        ("opaque0", {"prob": 100, "opaqueVTableNames": 0}),
        ("opaque1", {"prob": 100, "opaqueVTableNames": 1}),
        ("decoysOn", {"prob": 100, "addDecoyEntries": 1, "decoyMin": 1, "decoyMax": 4}),
        ("decoysOff", {"prob": 100, "addDecoyEntries": 0}),
        ("varyIndex3", {"prob": 100, "varyIndex": 1, "indexStrength": 3}),
        ("mergeOn", {"prob": 100, "merge": 1}),
        ("mergeOff", {"prob": 100, "merge": 0}),
    ],
    "strenc": [
        ("min1",         {"minlen": 1}),
        ("min4",         {"minlen": 4}),
        ("min100",       {"minlen": 100}),
        ("aes_on",       {"minlen": 4, "aes": 1}),
        ("aes_off",      {"minlen": 4, "aes": 0}),
        ("keysplit_on",  {"minlen": 4, "aes": 1, "keysplit": 1}),
        ("keysplit_off", {"minlen": 4, "aes": 1, "keysplit": 0}),
    ],
    "shield": [
        ("max1", {"maxSites": 1}),
        ("max10000", {"maxSites": 10000}),
        ("volatile0", {"volatile": 0}),
        ("identity0", {"identity": 0}),
        ("dse0", {"dse": 0}),
        ("cfg0", {"cfg": 0}),
        ("allOff", {"volatile": 0, "identity": 0, "dse": 0, "cfg": 0}),
    ],
    "flattening": [
        ("min2max200", {"minBlocks": 2, "maxBlocks": 200}),
        ("allowIndirect1", {"minBlocks": 2, "maxBlocks": 500, "allowIndirect": 1}),
        ("hybrid1", {"minBlocks": 2, "maxBlocks": 500, "hybrid": 1}),
        ("opaque0", {"minBlocks": 2, "maxBlocks": 500, "opaqueState": 0}),
        ("fake64", {"minBlocks": 2, "maxBlocks": 500, "fakeTransitions": 1, "fakeCases": 64}),
        ("domain0", {"minBlocks": 2, "maxBlocks": 500, "domain": 0}),
        ("ptr0", {"minBlocks": 2, "maxBlocks": 500, "ptr": 0}),
        ("alias0", {"minBlocks": 2, "maxBlocks": 500, "alias": 0}),
    ],
    "adec": [
        ("prob1", {"prob": 1, "strength": 1, "maxSites": 20}),
        ("prob100", {"prob": 100, "strength": 3, "maxSites": 200}),
        ("asm0", {"prob": 100, "strength": 2, "maxSites": 80, "asm": 0}),
        ("asm1", {"prob": 100, "strength": 2, "maxSites": 80, "asm": 1}),
        ("ibr0", {"prob": 100, "strength": 2, "maxSites": 80, "ibr": 0}),
        ("ibr1", {"prob": 100, "strength": 2, "maxSites": 80, "ibr": 1}),
        ("decoy0", {"prob": 100, "strength": 2, "maxSites": 80, "decoy": 0}),
        ("alias0", {"prob": 100, "strength": 2, "maxSites": 80, "alias": 0}),
    ],
}


STRESS: Dict[str, str] = {
    "mba": "mba(prob=100,depth=4,maxSites=400,termsMin=12,termsMax=20,enableNonLinear=1,nonLinearWeight=70,enableLayered=1,layeredBudget=4,layeredWindow=72)",
    "substitution": "substitution(loop=2,maxSites=2000)",
    "vcall": "vcall(prob=90,maxSites=300,opaqueVTableNames=1,addDecoyEntries=1,decoyMin=1,decoyMax=4,varyIndex=1,indexStrength=2,merge=1)",
    "split": "split(num=5)",
    "sdiff": "sdiff(prob=80,slots=3,maxSites=80)",
    "bcf": "bcf(prob=90,loop=2,maxBlocks=500)",
    "flattening": "flattening(minBlocks=2,maxBlocks=500,allowIndirect=1,hybrid=1,opaqueState=1,fakeTransitions=1,fakeCases=4,domain=1,ptr=1,alias=1)",
    "shield": "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1)",
    "strenc": "strenc(minlen=4,aes=1,keysplit=1)",
    "adec": "adec(prob=90,strength=2,maxSites=80,asm=1,ibr=1,stackPollution=1,decoy=1,callObfuscation=1,alias=1)",
}


def register(reg: Registry, *, extended: bool = False, **_opts) -> None:
    if not extended:
        return

    for pid, cases in OPTION_SWEEPS.items():
        for suffix, params in cases:
            ann = ann_specs([pass_spec(pid, params)])
            exp = {pid: {k: str(v) for k, v in params.items()}}
            reg.add(name=f"opt_{pid}_{suffix}", passes=[pid],
                    ann_override=ann, expect_config=exp,
                    category="options")

    reg.add(name="opt_alias_fla", passes=["flattening"],
            ann_override=ann_specs([pass_spec("fla", {"minBlocks": 2, "maxBlocks": 200})]),
            expect_enabled=["flattening"], category="options")
    reg.add(name="opt_alias_sub", passes=["substitution"],
            ann_override=ann_specs([pass_spec("sub", {"loop": 2})]),
            expect_enabled=["substitution"], category="options")
    reg.add(name="opt_alias_antidecompiler", passes=["adec"],
            ann_override=ann_specs([pass_spec("antidecompiler", {"prob": 100, "strength": 2, "maxSites": 50})]),
            expect_enabled=["adec"], category="options")
    reg.add(name="opt_alias_antiopt", passes=["shield"],
            ann_override=ann_specs([pass_spec("antiopt", {"maxSites": 50})]),
            expect_enabled=["shield"], category="options")

    reg.add(name="meta_order_full_pipeline",
            passes=["flattening", "bcf", "sdiff", "split", "vcall",
                    "substitution", "mba", "shield", "adec", "strenc"],
            ann_override=ann_specs([
                "flattening(minBlocks=2,maxBlocks=500)",
                "bcf(prob=100,loop=2,maxBlocks=200)",
                "sdiff(prob=80,slots=3,maxSites=50)",
                "split(num=5)",
                "vcall(prob=80,merge=1,addDecoyEntries=1)",
                "substitution(loop=2,maxSites=2000)",
                "mba(prob=100,depth=4,maxSites=400,termsMin=12,termsMax=20)",
                "shield(maxSites=200,volatile=1,identity=1,dse=1,cfg=1)",
                "adec(prob=90,strength=2,maxSites=80)",
                "strenc(minlen=4,aes=1,keysplit=1)",
            ]),
            expect_order=["mba", "substitution", "vcall", "split", "sdiff",
                          "bcf", "flattening", "shield", "strenc", "adec"],
            category="meta")

    all_for_matrix = [p for p in PASSES + ["adec"] if p in STRESS]
    for a_i in range(len(all_for_matrix)):
        for b_i in range(a_i + 1, len(all_for_matrix)):
            a = all_for_matrix[a_i]
            b = all_for_matrix[b_i]
            reg.add(name=f"mx_{a}__{b}", passes=[a, b],
                    ann_override=ann_specs([STRESS[a], STRESS[b]]),
                    category="matrix")
