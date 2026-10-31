"""Shared helpers for experiments: adopter-set selection, compact observations, aggregation."""
from __future__ import annotations

import itertools
import math
import random
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from ..core import metrics as M
from ..core.engine import BaselineUnhealthy, ScenarioConfig, run_scenario
from ..core.rpki import ROA
from ..core.topology import Topology, load_topology

SET_POLICY_TEXT = {
    "all": "Every adopter set of size k is evaluated (exhaustive; C(6,k) sets). D_mean/D_sd are exact over all placements.",
    "sample": "Deterministic random sample of adopter sets of size k (seeded); NOT exhaustive.",
    "order": "Adopters are the first k ASes of the user-supplied adoption order (one placement per k).",
    "explicit": "Only the user-specified adopter set is evaluated (k = its size).",
}


def select_sets(measured: Sequence[int], k: int, policy: Optional[dict] = None) -> Tuple[List[Tuple[int, ...]], str]:
    """Return (sets, mode_label) for adoption count k under the aggregation policy."""
    policy = policy or {}
    mode = policy.get("mode", "all")
    if mode == "order":
        order = list(policy.get("order") or [])
        if sorted(order) != sorted(measured):
            raise ValueError("adoption order must list each measured AS exactly once")
        return [tuple(sorted(order[:k]))], "order"
    if mode == "explicit":
        ex = tuple(sorted(policy.get("explicit") or []))
        return ([ex] if len(ex) == k else []), "explicit"
    combos = list(itertools.combinations(sorted(measured), k))
    max_sets = policy.get("max_sets")
    if mode == "sample" or (max_sets and len(combos) > max_sets):
        n = max_sets or 3
        rng = random.Random(f"{policy.get('seed', 1)}|{k}")     # per-k stream => reproducible
        combos = sorted(rng.sample(combos, min(n, len(combos))))
        return combos, "sample"
    return combos, "all"


def levels_for(policy: Optional[dict], n: int) -> List[int]:
    policy = policy or {}
    if policy.get("mode") == "explicit":
        return [len(policy.get("explicit") or [])]
    return list(range(n + 1))


def observe(cfg: ScenarioConfig, exp: str, k: int, require_healthy: bool, topo: Optional[Topology] = None) -> dict:
    """Run one scenario and reduce it to a compact, CSV-friendly observation (raw data kept)."""
    topo = topo or load_topology()
    res = run_scenario(cfg, topo)
    if require_healthy and not res["baseline"]["healthy"]:
        raise BaselineUnhealthy({"config": res["config"], "failing": res["baseline"]["failing"],
                                 "converged": res["baseline"]["converged"]})
    rows = []
    for a in topo.measured:
        pa = res["per_as"][str(a)]
        cands = pa["candidate_routes"]
        rows.append({
            "client": a,
            "baseline": pa["baseline_endpoint"],
            "after": pa["endpoint"],
            "diverted": pa["diverted"],
            "best_path_after": " ".join(map(str, pa["best_route"]["as_path"])) if pa["best_route"] else "",
            "all_paths_after": "|".join(" ".join(map(str, c["as_path"])) for c in cands),
            "forwarding_path": pa["probe"]["forwarding_path"],
            "attack_route_status": pa["attack_route_status"],
            "rov": pa["rov"], "path_end": pa["path_end"],
        })
    m = res["metrics"]
    return {
        "exp": exp,
        "scenario": cfg.attack,
        "k": k,
        "rov_set": sorted(cfg.rov_set),
        "pe_set": sorted(cfg.path_end_set),
        "baseline_healthy": res["baseline"]["healthy"],
        "converged": res["converged"],
        "D": m["diversion_rate"],
        "diverted_count": m["diverted_count"],
        "diverted_asns": m["diverted_asns"],
        "unreachable_count": m["unreachable_count"],
        "victim_probe_successes": m["victim_probe_successes"],
        "accepting_attack_route": m["accepting_attack_route"],
        "rpki_state": res["malicious_route"]["rpki_state"] if res["malicious_route"] else None,
        "rows": rows,
        "rejected": [{k2: v for k2, v in r.items() if k2 in ("receiver", "router", "from", "path", "reject_by", "reject_reason", "rpki_state")}
                     for r in res["rejected_routes"]],
    }


def summarize_curve(observations: List[dict], n: int) -> List[dict]:
    """Aggregate observations of one experiment into per-k statistics (guide section 2.3-2.4)."""
    by_k: Dict[int, List[dict]] = {}
    for o in observations:
        by_k.setdefault(o["k"], []).append(o)
    ks = sorted(by_k)
    d0 = M.mean([o["D"] for o in by_k[ks[0]]]) if ks and ks[0] == 0 else None
    out, prev = [], None
    for k in ks:
        ds = [o["D"] for o in by_k[k]]
        us = [o["unreachable_count"] / n for o in by_k[k]]
        dm = M.mean(ds)
        out.append({
            "k": k, "adoption_pct": round(100 * k / n, 2), "runs": len(ds),
            "D_mean": dm, "D_sd": M.sd(ds), "D_min": min(ds), "D_max": max(ds), "U_mean": M.mean(us),
            "protection_pp": None if d0 is None else M.protection_pp(d0, dm),
            "relative_reduction": None if d0 is None else M.relative_reduction(d0, dm),
            "marginal_gain_pp": None if prev is None else M.marginal_gain_pp(prev, dm),
        })
        prev = dm
    return out
