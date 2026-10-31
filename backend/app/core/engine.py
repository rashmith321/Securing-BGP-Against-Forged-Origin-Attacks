"""Scenario engine: baseline -> attack -> probes -> per-AS outcome (orchestrates concepts 1-7)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

from .metrics import diversion_rate, pct
from .path_end import validate_path_end
from .propagation import Announcement, BGPSim
from .rpki import ROA, roas_from_dicts, rov_decision, validate_origin
from .route_selection import explain_choice
from .topology import Topology, load_topology
from .traffic import ProbeResult, probe

ATTACKS = ("none", "type0", "type1", "subprefix")


class BaselineUnhealthy(Exception):
    def __init__(self, details: dict):
        super().__init__("Baseline is unhealthy: not every measured AS reaches the legitimate victim.")
        self.details = details


@dataclass(frozen=True)
class ScenarioConfig:
    attack: str = "type1"
    rov_set: FrozenSet[int] = frozenset()
    path_end_set: FrozenSet[int] = frozenset()
    roas: Optional[Tuple[ROA, ...]] = None            # None -> topology default ROAs
    rov_reject_notfound: bool = False

    def key(self) -> str:
        return "|".join([
            self.attack,
            "rov=" + ",".join(map(str, sorted(self.rov_set))),
            "pe=" + ",".join(map(str, sorted(self.path_end_set))),
            "roas=" + (";".join(f"{r.prefix}>{r.max_length}@{r.origin}" for r in self.roas) if self.roas else "default"),
            f"nf={int(self.rov_reject_notfound)}",
        ])


def _name(asn: int) -> str:
    return f"AS{asn}"


def _attack_announcement(topo: Topology, attack: str) -> Optional[Announcement]:
    if attack == "type0":
        return Announcement(topo.attacker, topo.prefix, forged_tail=(), malicious=True)
    if attack == "type1":
        return Announcement(topo.attacker, topo.prefix, forged_tail=(topo.victim,), malicious=True)
    if attack == "subprefix":
        # forged-origin more-specific, as in the guide's optional extension (E1)
        return Announcement(topo.attacker, topo.subprefix, forged_tail=(topo.victim,), malicious=True)
    return None


def _probe_all(sim: BGPSim, topo: Topology) -> Dict[int, ProbeResult]:
    out = {}
    for a in topo.measured:
        pr = probe(sim, a, topo.probe_ip, topo.probe_port)
        out[a] = pr
    return out


def _attack_route_status(sim: BGPSim, topo: Topology, prefix: str, asn: int) -> dict:
    """Did `asn` accept / reject / never see a route that carries the attacker's AS?"""
    acc = [r for r in sim.all_candidates(asn, prefix) if topo.attacker in r.as_path]
    rej = [r for r in sim.rejected(asn, prefix) if topo.attacker in r.as_path]
    if acc:
        return {"status": "accepted", "routes": [r.to_dict() for r in acc]}
    if rej:
        return {"status": "rejected", "routes": [r.to_dict() for r in rej]}
    return {"status": "not_received", "routes": []}


def run_scenario(cfg: ScenarioConfig, topo: Optional[Topology] = None) -> dict:
    topo = topo or load_topology()
    if cfg.attack not in ATTACKS:
        raise ValueError(f"unknown attack '{cfg.attack}'")
    bad = (set(cfg.rov_set) | set(cfg.path_end_set)) - set(topo.measured)
    if bad:
        raise ValueError(f"adopters must be measured ASes; got {sorted(bad)}")
    roas = list(cfg.roas) if cfg.roas is not None else roas_from_dicts(topo.roas)

    sim = BGPSim(topo, roas, cfg.rov_set, cfg.path_end_set, cfg.rov_reject_notfound)

    # --- baseline: victim legitimately originates the prefix --------------------------------------
    sim.originate(Announcement(topo.victim, topo.prefix))
    base_converged = sim.converge()
    base_probes = _probe_all(sim, topo)
    base_best = {a: (sim.best_route(a, topo.prefix).to_dict() if sim.best_route(a, topo.prefix) else None)
                 for a in topo.ases}
    def _why(a, p):
        rej = sim.rejected(a, topo.prefix)
        if rej:
            return f"AS{a} rejected the legitimate route ({rej[0].reject_by}): {rej[0].reject_reason}"
        upstream = [(x, r) for x in topo.ases for r in sim.rejected(x, topo.prefix)]
        if upstream and not p.reply_received:
            x, r = upstream[0]
            return (f"{p.failure_reason}; the legitimate route was rejected upstream at AS{x} "
                    f"({r.reject_by}): {r.reject_reason}")
        return p.failure_reason or ("traffic reached " + p.endpoint)

    failing = [
        {"asn": a, "endpoint": p.endpoint, "likely_reason": _why(a, p)}
        for a, p in base_probes.items() if not p.reached_victim
    ]
    baseline = {
        "healthy": base_converged and not failing,
        "converged": base_converged,
        "failing": failing,
        "probes": {str(a): p.to_dict() for a, p in base_probes.items()},
        "best_routes": {str(a): r for a, r in base_best.items()},
        "victims_reached": sum(1 for p in base_probes.values() if p.reached_victim),
    }

    # --- attack ------------------------------------------------------------------------------------
    ann = _attack_announcement(topo, cfg.attack)
    malicious = None
    if ann is not None:
        sim.originate(ann)
    converged = sim.converge()
    probes = _probe_all(sim, topo)

    attack_prefix = ann.prefix if ann else topo.prefix
    if ann is not None:
        adv_path = (topo.attacker,) + ann.forged_tail
        state, why, applicable = validate_origin(ann.prefix, adv_path[-1], roas)
        pe_ok, pe_why = validate_path_end(adv_path, topo.path_end_registry)
        malicious = {
            "attack": cfg.attack,
            "prefix": ann.prefix,
            "advertised_as_path": list(adv_path),
            "advertised_path_str": " ".join(map(str, adv_path)),
            "claimed_origin": adv_path[-1],
            "actual_originator": topo.attacker,
            "rpki_state": state,
            "rpki_explanation": why,
            "applicable_roas": applicable,
            "path_end_ok": pe_ok,
            "path_end_explanation": pe_why,
            "origin_validation_note": (
                "ROV only checks the LAST AS in the path (the claimed origin) against the ROA. "
                "It does not check that AS%d is really connected to the origin, so a forged path can be RPKI Valid."
                % adv_path[-2] if len(adv_path) > 1 else
                "Claimed origin is the attacker itself, which the ROA does not authorise."),
        }

    per_as = {}
    for a in topo.measured:
        p = probes[a]
        best = sim.best_route(a, attack_prefix if ann else topo.prefix)
        cands = sim.all_candidates(a, attack_prefix if ann else topo.prefix)
        status = _attack_route_status(sim, topo, attack_prefix, a) if ann else {"status": "not_received", "routes": []}
        # RPKI decision for the malicious route at this AS
        decision = None
        if malicious:
            ok, why = rov_decision(malicious["rpki_state"], a in cfg.rov_set, cfg.rov_reject_notfound)
            decision = {"rov_enabled": a in cfg.rov_set, "rov_accepts": ok, "rov_explanation": why,
                        "path_end_enabled": a in cfg.path_end_set}
        per_as[str(a)] = {
            "asn": a,
            "router": topo.name(a),
            "rov": a in cfg.rov_set,
            "path_end": a in cfg.path_end_set,
            "attacker_provider": a in topo.attacker_providers,
            "baseline_endpoint": base_probes[a].endpoint,
            "endpoint": p.endpoint,
            "diverted": p.diverted,
            "reached_victim": p.reached_victim,
            "probe": p.to_dict(),
            "best_route": best.to_dict() if best else None,
            "route_choice": explain_choice(cands, best, topo.router_id) if best else None,
            "candidate_routes": [c.to_dict() for c in sorted(cands, key=lambda r: (r.length, r.learned_from))],
            "attack_route_status": status["status"],
            "attack_route_detail": status["routes"],
            "malicious_route_decision": decision,
        }

    n = len(topo.measured)
    diverted = [a for a in topo.measured if probes[a].diverted]
    victim_ok = [a for a in topo.measured if probes[a].reached_victim]
    unreachable = [a for a in topo.measured if not probes[a].reply_received]
    accepted_attack = [a for a in topo.measured if per_as[str(a)]["attack_route_status"] == "accepted"]
    rejections = []
    for a in topo.measured:
        for r in sim.rejected(a, attack_prefix):
            rejections.append({"receiver": a, "router": topo.name(a), "from": r.learned_from, **r.to_dict()})
    # also include rejections at non-measured ASes (victim/attacker) for completeness
    D = diversion_rate(len(diverted), n)
    result = {
        "model_version": topo.model_version,
        "simulated": True,
        "config": {
            "attack": cfg.attack,
            "rov_set": sorted(cfg.rov_set),
            "path_end_set": sorted(cfg.path_end_set),
            "roas": [r.to_dict() for r in roas],
            "rov_reject_notfound": cfg.rov_reject_notfound,
            "key": cfg.key(),
        },
        "converged": converged,
        "ticks": sim.converged_at,
        "baseline": baseline,
        "malicious_route": malicious,
        "per_as": per_as,
        "rejected_routes": rejections,
        "metrics": {
            "measured": n,
            "diverted_count": len(diverted),
            "diverted_asns": diverted,
            "diversion_rate": D,
            "diversion_pct": pct(D),
            "diversion_fraction": f"{len(diverted)}/{n}",
            "victim_probe_successes": len(victim_ok),
            "attacker_received_probes": len(diverted),
            "unreachable_count": len(unreachable),
            "unreachable_rate": diversion_rate(len(unreachable), n),
            "protected_asns": victim_ok,
            "vulnerable_asns": diverted,
            "protected_count": len(victim_ok),
            "vulnerable_count": len(diverted),
            "accepting_attack_route": len(accepted_attack),
            "accepting_attack_asns": accepted_attack,
            "granularity_note": f"With {n} measured ASes D moves in steps of {100/n:.1f} percentage points.",
        },
    }
    return result


def run_id_for(prefix: str, payload) -> str:
    h = hashlib.sha1(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:8]
    return f"{prefix}-{h}"
