"""Optional extension E1: forged-origin sub-prefix hijack (10.10.0.0/25) vs ROA maximum length."""
from __future__ import annotations

from ..core.engine import ScenarioConfig, run_scenario
from ..core.rpki import ROA
from ..core.topology import load_topology


def run() -> dict:
    topo = load_topology()
    allm = frozenset(topo.measured)
    rows = []
    for label, maxlen in (("strict ROA (max length 24, default)", 24), ("loose ROA (max length 25, experimental)", 25)):
        roa = (ROA(topo.prefix, topo.victim, maxlen),)
        for dlabel, rov, pe in (("no defence", frozenset(), frozenset()), ("ROV at all measured ASes", allm, frozenset()),
                                ("ROV + path-end at all measured ASes", allm, allm)):
            res = run_scenario(ScenarioConfig("subprefix", rov, pe, roa), topo)
            m = res["metrics"]
            rows.append({"roa": label, "roa_max_length": maxlen, "defence": dlabel,
                         "rpki_state": res["malicious_route"]["rpki_state"],
                         "diverted_count": m["diverted_count"], "diverted_asns": m["diverted_asns"],
                         "diversion_fraction": m["diversion_fraction"], "diversion_rate": m["diversion_rate"],
                         "baseline_healthy": res["baseline"]["healthy"]})
    return {"experiment": "subprefix", "simulated": True, "rows": rows,
            "note": "Default ROA is unchanged for all other experiments; the loose ROA exists only inside this experiment."}
