"""Experiment 2: compare no attack / Type-0 / Type-1 with ROV disabled and enabled."""
from __future__ import annotations

from typing import List, Optional

from ..core.engine import ScenarioConfig, run_scenario
from ..core.topology import load_topology
from .common import observe


def run(rov_set: Optional[List[int]] = None, path_end_set: Optional[List[int]] = None,
        require_healthy: bool = True) -> dict:
    topo = load_topology()
    n = len(topo.measured)
    rov_on = frozenset(topo.measured if rov_set is None else rov_set)
    pe = frozenset(path_end_set or [])
    rows, details = [], []
    for attack in ("none", "type0", "type1"):
        for label, rset in (("ROV disabled", frozenset()), ("ROV enabled", rov_on)):
            cfg = ScenarioConfig(attack, rset, pe)
            res = run_scenario(cfg, topo)
            obs = observe(cfg, "attack_comparison", len(rset), require_healthy, topo)
            m = res["metrics"]
            rows.append({
                "attack": attack, "rov_policy": label, "rov_adopters": sorted(rset),
                "rov_adoption": f"{len(rset)}/{n}", "rov_adoption_pct": round(100 * len(rset) / n, 2),
                "path_end_adopters": sorted(pe),
                "rpki_state": res["malicious_route"]["rpki_state"] if res["malicious_route"] else "n/a",
                "advertised_path": res["malicious_route"]["advertised_path_str"] if res["malicious_route"] else "(no attack)",
                "accepting_attack_route": m["accepting_attack_route"],
                "diverted_count": m["diverted_count"], "diverted_asns": m["diverted_asns"],
                "diversion_rate": m["diversion_rate"], "diversion_fraction": m["diversion_fraction"],
                "victim_probe_successes": m["victim_probe_successes"],
                "baseline_healthy": res["baseline"]["healthy"],
            })
            details.append({"attack": attack, "rov_policy": label, "observation": obs})
    by = {(r["attack"], r["rov_policy"]): r for r in rows}
    t0e, t1e = by[("type0", "ROV enabled")], by[("type1", "ROV enabled")]
    t0d, t1d = by[("type0", "ROV disabled")], by[("type1", "ROV disabled")]
    findings = [
        f"Type-0 route is RPKI {t0e['rpki_state']}; Type-1 route is RPKI {t1e['rpki_state']}.",
        f"Without ROV, Type-0 diverts {t0d['diversion_fraction']} and Type-1 diverts {t1d['diversion_fraction']}.",
        f"With ROV at {t0e['rov_adoption']} measured ASes, Type-0 diverts {t0e['diversion_fraction']} "
        f"and Type-1 diverts {t1e['diversion_fraction']}.",
    ]
    h1 = t0e["diversion_rate"] < t0d["diversion_rate"]
    h2 = t1e["diversion_rate"] >= t1d["diversion_rate"] and t1e["diversion_rate"] > 0
    hyp = [
        {"hypothesis": "Type-0 attacks become less successful as ROV adoption increases.",
         "supported": bool(h1) if t0d["diversion_rate"] > 0 else None,
         "evidence": f"D {t0d['diversion_fraction']} -> {t0e['diversion_fraction']}"},
        {"hypothesis": "Type-1 attacks remain effective even when ROV adoption is high.",
         "supported": bool(h2),
         "evidence": f"D {t1d['diversion_fraction']} -> {t1e['diversion_fraction']} (route RPKI {t1e['rpki_state']})"},
    ]
    return {"experiment": "attack_comparison", "simulated": True, "measured": n, "rows": rows,
            "details": details, "findings": findings, "hypotheses": hyp}
