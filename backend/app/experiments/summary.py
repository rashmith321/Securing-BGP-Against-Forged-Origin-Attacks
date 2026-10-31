"""Automatic research summary generated from experiment data (never hard-coded conclusions)."""
from __future__ import annotations

from typing import Dict, List, Optional


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _flags(*results: Optional[dict]) -> List[str]:
    flags = []
    for r in results:
        if not r:
            continue
        obs = r.get("observations") or []
        if any(not o["baseline_healthy"] for o in obs):
            flags.append(f"{r['experiment']}: at least one run had an UNHEALTHY baseline - interpret with care.")
        if any(not o["converged"] for o in obs):
            flags.append(f"{r['experiment']}: at least one run did not converge.")
        unreach = [o for o in obs if o["unreachable_count"] > 0]
        if unreach:
            ex = unreach[0]
            who = [row["client"] for row in ex["rows"] if row["after"] == "unreachable"]
            flags.append(
                f"{r['experiment']}: {len(unreach)} of {len(obs)} runs left some measured AS with NO route (unreachable, counted "
                f"separately from diversion). Example: ROV set {ex['rov_set']} / path-end set {ex['pe_set']} -> "
                f"AS{', AS'.join(map(str, who))} unreachable. Cause: a filtering AS whose only upstream re-advertises the "
                f"rejected route; the filtered update replaces the earlier valid one, leaving no route (collateral blackhole).")
    return flags


def build(attack_cmp: Optional[dict], rov: Optional[dict], placement: Optional[dict], path_end: Optional[dict]) -> dict:
    bullets: List[str] = []
    hyps: List[dict] = []
    if attack_cmp:
        rows = {(r["attack"], r["rov_policy"]): r for r in attack_cmp["rows"]}
        t0, t1 = rows[("type0", "ROV enabled")], rows[("type1", "ROV enabled")]
        bullets.append(f"Type-0 vs Type-1: the Type-0 route (origin AS65800) is RPKI {t0['rpki_state']}; the Type-1 route "
                       f"(advertised path {t1['advertised_path']}) is RPKI {t1['rpki_state']}. With ROV at {t1['rov_adoption']} "
                       f"measured ASes, Type-0 diverts {t0['diversion_fraction']} and Type-1 diverts {t1['diversion_fraction']}.")
    if rov:
        c0, c1 = rov["curves"].get("type0_rov"), rov["curves"].get("type1_rov")
        if c0:
            mono = all(c0[i + 1]["D_mean"] <= c0[i]["D_mean"] + 1e-12 for i in range(len(c0) - 1))
            sup = c0[-1]["D_mean"] < c0[0]["D_mean"]
            bullets.append(f"ROV adoption (Type-0): mean diversion {_pct(c0[0]['D_mean'])} at k=0 -> {_pct(c0[-1]['D_mean'])} at k={c0[-1]['k']}"
                           f"; curve is {'monotonically non-increasing' if mono else 'NOT monotonic'}.")
            hyps.append({"hypothesis": "Type-0 diversion falls as ROV adoption rises", "supported": sup,
                         "evidence": f"D_mean {_pct(c0[0]['D_mean'])} -> {_pct(c0[-1]['D_mean'])}"})
        if c1:
            flat = abs(c1[-1]["D_mean"] - c1[0]["D_mean"]) < 1e-12
            bullets.append(f"ROV adoption (Type-1): mean diversion {_pct(c1[0]['D_mean'])} at k=0 -> {_pct(c1[-1]['D_mean'])} at k={c1[-1]['k']} "
                           f"(residual {_pct(c1[-1]['D_mean'])}); ROV {'did not change' if flat else 'changed'} Type-1 diversion.")
            hyps.append({"hypothesis": "Type-1 stays effective at high ROV adoption", "supported": c1[-1]["D_mean"] > 0,
                         "evidence": f"residual D at full ROV = {_pct(c1[-1]['D_mean'])}"})
    if placement:
        for exp, r in placement["results"].items():
            es = [(pk["k"], pk["E_set_pp"]) for pk in r["per_k"] if pk["E_set_pp"]]
            if es:
                k, e = max(es, key=lambda t: t[1])
                bullets.append(f"Placement ({exp}): largest best-vs-worst gap E_set={e:.1f} pp at k={k}.")
            else:
                bullets.append(f"Placement ({exp}): all evaluated placements at equal k give the same D - placement does not matter here.")
        e0 = [pk["E_set_pp"] for pk in placement["results"].get("type0_rov", {"per_k": []})["per_k"] if pk["E_set_pp"]]
        hyps.append({"hypothesis": "Which ASes adopt ROV matters (not only how many)", "supported": bool(e0 and max(e0) > 0),
                     "evidence": f"max E_set for Type-0 = {max(e0):.1f} pp" if e0 else "no placement spread found"})
        vul = [v for v in placement["vulnerability"] if v["type1_rov"] or v["type0_rov"]]
        bullets.append("No-defence vulnerability: " + (", ".join(
            f"{v['router']} (Type-0: {'diverted' if v['type0_rov'] else 'safe'}, Type-1: {'diverted' if v['type1_rov'] else 'safe'})"
            for v in vul) or "no measured AS is diverted") + ".")
    if path_end and path_end.get("full_adoption"):
        f, r0 = path_end["full_adoption"], path_end["rov_only"]
        bullets.append(f"Path-end (Type-1, ROV everywhere): D {_pct(r0['D_mean'])} (ROV only) -> {_pct(f['D_mean'])} "
                       f"with path-end at all measured ASes (residual {_pct(f['D_mean'])}).")
        if path_end.get("hypothesis"):
            hyps.append(path_end["hypothesis"])
    return {"bullets": bullets, "hypotheses": hyps, "flags": _flags(rov, placement, path_end),
            "note": "Generated from the computed experiment data. Simulated results; topology/policy specific."}
