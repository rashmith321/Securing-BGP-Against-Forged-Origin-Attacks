"""Experiment 4: adoption placement study. Compares adopter sets of equal size k.

p = number of the attacker's providers (AS65400, AS65600) inside the adopter set (guide 2.1).
D(k,p)  = mean diversion rate over the evaluated sets with k adopters, p of them attacker providers.
E(k)    = 100 x (D(k,p_min) - D(k,p_max))          [guide definition; p_min/p_max = fewest/most providers]
          positive => putting adopters at the attacker's providers REDUCES diversion.
E_set(k)= 100 x (D_worst_set - D_best_set)          [master-prompt reading: best vs worst evaluated placement]
          always >= 0; the protection difference attributable to *where* the k adopters sit.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..core import metrics as M
from ..core.engine import ScenarioConfig, run_scenario
from ..core.topology import load_topology
from .common import SET_POLICY_TEXT, levels_for, observe, select_sets

EXPS = {
    "type0_rov": ("type0", "rov"),
    "type1_rov": ("type1", "rov"),
    "type1_pathend": ("type1", "pathend"),
}


def _names(asns) -> str:
    return " ".join(f"r{a - 65000}" for a in asns) or "(none)"


def vulnerability_report(topo=None) -> List[dict]:
    topo = topo or load_topology()
    rows = []
    r0 = run_scenario(ScenarioConfig("type0"), topo)
    r1 = run_scenario(ScenarioConfig("type1"), topo)
    for a in topo.measured:
        row = {"client": a, "router": topo.name(a), "attacker_provider": a in topo.attacker_providers}
        for key, r in (("type0_rov", r0), ("type1_rov", r1)):
            pa = r["per_as"][str(a)]
            row[key] = 1 if pa["diverted"] else 0
            row[key + "_best_path"] = " ".join(map(str, pa["best_route"]["as_path"])) if pa["best_route"] else ""
            row[key + "_why"] = pa["route_choice"]
        rows.append(row)
    return rows


def run(exps=("type0_rov", "type1_rov", "type1_pathend"), policy: Optional[dict] = None,
        rov_base: Optional[List[int]] = None, require_healthy: bool = True) -> dict:
    topo = load_topology()
    n = len(topo.measured)
    prov = set(topo.attacker_providers)
    policy = policy or {"mode": "all"}
    if policy.get("mode") in ("order", "explicit"):
        raise ValueError("placement study needs set-based modes 'all' or 'sample' (same k, several placements)")
    rov_all = frozenset(topo.measured if rov_base is None else rov_base)
    results, observations = {}, []
    for exp in exps:
        attack, kind = EXPS[exp]
        obs = []
        for k in levels_for(policy, n):
            sets, mode = select_sets(topo.measured, k, policy)
            for s in sets:
                cfg = (ScenarioConfig(attack, frozenset(s), frozenset()) if kind == "rov"
                       else ScenarioConfig(attack, rov_all, frozenset(s)))
                o = observe(cfg, exp, k, require_healthy, topo)
                o["adopters"] = list(s)
                o["p"] = len(set(s) & prov)
                obs.append(o)
        observations += obs
        per_k = []
        for k in sorted({o["k"] for o in obs}):
            ok = [o for o in obs if o["k"] == k]
            groups = []
            for p in sorted({o["p"] for o in ok}):
                ds = [o["D"] for o in ok if o["p"] == p]
                groups.append({"p": p, "runs": len(ds), "D_mean": M.mean(ds), "D_min": min(ds), "D_max": max(ds)})
            e_prov = None
            if len(groups) > 1:
                e_prov = M.placement_effect_pp(groups[0]["D_mean"], groups[-1]["D_mean"])
            best = min(ok, key=lambda o: (o["D"], o["adopters"]))
            worst = max(ok, key=lambda o: (o["D"], [-a for a in o["adopters"]]))
            e_set = 100.0 * (worst["D"] - best["D"]) if len(ok) > 1 else None
            per_k.append({
                "k": k, "n_sets": len(ok), "groups": groups, "E_provider_pp": e_prov, "E_set_pp": e_set,
                "best_set": best["adopters"], "best_D": best["D"], "worst_set": worst["adopters"], "worst_D": worst["D"],
                "best_sets_all": [o["adopters"] for o in ok if o["D"] == best["D"]],
            })
        results[exp] = {"per_k": per_k}

    # data-driven explanation (only states what the data shows; one grouped note per experiment)
    notes = []
    for exp, r in results.items():
        both_ks, other = [], []
        for pk in r["per_k"]:
            if pk["n_sets"] < 2 or not pk["E_set_pp"]:
                continue
            if pk["best_D"] == 0 and all(prov <= set(s) for s in pk["best_sets_all"]):
                both_ks.append(pk["k"])
            else:
                other.append(pk)
        if both_ks:
            ks = ", ".join(map(str, both_ks))
            notes.append(f"{exp}, k = {ks}: every zero-diversion placement contains both attacker providers "
                         f"({_names(sorted(prov))}). In this topology the attacker's only links are those two providers, "
                         f"so filtering at both stops the bad route before it spreads.")
        for pk in other:
            notes.append(f"{exp}, k = {pk['k']}: best placement {_names(pk['best_set'])} (D={100*pk['best_D']:.1f}%) vs worst "
                         f"{_names(pk['worst_set'])} (D={100*pk['worst_D']:.1f}%): E_set={pk['E_set_pp']:.1f} pp.")
    # single-provider asymmetry (k=1), read straight from the observations
    for exp in results:
        singles = {o["adopters"][0]: o for o in observations if o["exp"] == exp and o["k"] == 1 and o["adopters"][0] in prov}
        if len(singles) == len(prov) and len({o["D"] for o in singles.values()}) > 1:
            parts = "; ".join(f"{_names([a])} alone -> D={100*o['D']:.1f}%, still diverted: {_names(o['diverted_asns'])}"
                              for a, o in sorted(singles.items()))
            notes.append(f"{exp}, k = 1: the two attacker providers are not interchangeable ({parts}). Which branch an adopter "
                         f"protects decides which downstream ASes lose the bad route.")
    return {"experiment": "placement", "simulated": True, "measured": n, "attacker_providers": sorted(prov),
            "aggregation_text": SET_POLICY_TEXT[policy.get("mode", "all")], "policy": policy,
            "convention": "E(k) > 0 means better placement (more attacker providers among adopters) reduces diversion.",
            "results": results, "observations": observations, "vulnerability": vulnerability_report(topo), "notes": notes}
