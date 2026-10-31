"""Experiment 5: ASPA-style path-end validation on top of ROV (Type-1 forged-origin attack)."""
from __future__ import annotations

from typing import List, Optional

from ..core.engine import ScenarioConfig, run_scenario
from ..core.topology import load_topology
from .common import SET_POLICY_TEXT, levels_for, observe, select_sets, summarize_curve


def run(policy: Optional[dict] = None, rov_set: Optional[List[int]] = None, require_healthy: bool = True,
        attack: str = "type1") -> dict:
    topo = load_topology()
    n = len(topo.measured)
    rov = frozenset(topo.measured if rov_set is None else rov_set)
    obs, mode_seen = [], set()
    for m in levels_for(policy, n):
        sets, mode = select_sets(topo.measured, m, policy)
        mode_seen.add(mode)
        for s in sets:
            o = observe(ScenarioConfig(attack, rov, frozenset(s)), "type1_pathend", m, require_healthy, topo)
            o["adopters"] = list(s)
            obs.append(o)
    curve = summarize_curve(obs, n)
    rov_only = next((c for c in curve if c["k"] == 0), None)
    full = next((c for c in curve if c["k"] == n), None)
    rejected = []
    for o in obs:
        for r in o["rejected"]:
            rejected.append({"m": o["k"], "pe_set": o["pe_set"], **r})
    # explain residual using the full-adoption observation(s)
    residual_notes = []
    if full is not None:
        full_obs = [o for o in obs if o["k"] == n]
        if full["D_mean"] == 0:
            residual_notes.append(
                "At full path-end adoption no measured AS is diverted in this model: every route carrying the forged path "
                "[65800 65700] fails the check because AS65800 is not in AS65700's authorised upstream record (AS65300).")
        else:
            for o in full_obs:
                for r in o["rows"]:
                    if r["diverted"]:
                        residual_notes.append(f"AS{r['client']} still diverted via path {r['best_path_after']}.")
        residual_notes.append("Limits: the check only inspects the AS directly before the claimed origin, relies on the victim's "
                              "registry being correct and complete, and is a simplified educational model, not standards-compliant ASPA.")
    hyp = None
    if rov_only and full:
        hyp = {"hypothesis": "Path-end validation can reduce forged-origin attack success.",
               "supported": full["D_mean"] < rov_only["D_mean"],
               "evidence": f"D {100*rov_only['D_mean']:.1f}% (ROV only) -> {100*full['D_mean']:.1f}% (ROV + path-end at all measured ASes)"}
    return {"experiment": "path_end", "simulated": True, "measured": n, "rov_set": sorted(rov), "attack": attack,
            "aggregation_text": SET_POLICY_TEXT[sorted(mode_seen)[0] if mode_seen else "all"],
            "curve": curve, "rov_only": rov_only, "full_adoption": full, "observations": obs,
            "rejected_routes": rejected, "residual_notes": residual_notes, "hypothesis": hyp,
            "disclaimer": "Simplified educational path-end model inspired by ASPA; not a full standards-compliant ASPA implementation."}
