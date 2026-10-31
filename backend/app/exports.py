"""CSV tables and reproducibility text built *from saved result dicts* (never from re-simulation)."""
from __future__ import annotations

import csv
import io
from typing import Dict, List


def _csv(fields: List[str], rows: List[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def _setstr(xs) -> str:
    return " ".join(str(x) for x in xs)


def results_rows(observations: List[dict]) -> List[dict]:
    rows = []
    for o in observations:
        run_id = f"{o['exp']}|{o['k']}|{'-'.join(map(str, o['rov_set']))}|{'-'.join(map(str, o['pe_set']))}"
        for r in o["rows"]:
            rows.append({"run_id": run_id, "exp": o["exp"], "scenario": o["scenario"], "k": o["k"],
                         "rov_set": _setstr(o["rov_set"]), "pe_set": _setstr(o["pe_set"]),
                         "client": r["client"], "converged": int(o["converged"]),
                         "baseline_healthy": int(o["baseline_healthy"]),
                         "baseline": r["baseline"], "after": r["after"], "diverted": int(r["diverted"]),
                         "best_path_after": r["best_path_after"], "all_paths_after": r["all_paths_after"],
                         "attack_route_status": r["attack_route_status"]})
    return rows


RESULT_FIELDS = ["run_id", "exp", "scenario", "k", "rov_set", "pe_set", "client", "converged", "baseline_healthy",
                 "baseline", "after", "diverted", "best_path_after", "all_paths_after", "attack_route_status"]
SUMMARY_FIELDS = ["exp", "k", "adoption_pct", "runs", "D_mean", "D_sd", "D_min", "D_max", "U_mean",
                  "protection_pp", "relative_reduction", "marginal_gain_pp"]


def summary_rows(curves: Dict[str, List[dict]]) -> List[dict]:
    return [{"exp": e, **c} for e, cs in curves.items() for c in cs]


def placement_tables(res: dict) -> Dict[str, str]:
    groups, effects, sets = [], [], []
    for exp, r in res["results"].items():
        for pk in r["per_k"]:
            for g in pk["groups"]:
                groups.append({"exp": exp, "k": pk["k"], "p": g["p"], "D_mean": g["D_mean"], "D_min": g["D_min"],
                               "D_max": g["D_max"], "runs": g["runs"]})
            effects.append({"exp": exp, "k": pk["k"], "n_sets": pk["n_sets"], "E_provider_pp": pk["E_provider_pp"],
                            "E_set_pp": pk["E_set_pp"], "best_set": _setstr(pk["best_set"]), "best_D": pk["best_D"],
                            "worst_set": _setstr(pk["worst_set"]), "worst_D": pk["worst_D"]})
    for o in res["observations"]:
        sets.append({"exp": o["exp"], "k": o["k"], "p": o["p"], "adopters": _setstr(o["adopters"]), "D": o["D"],
                     "diverted_asns": _setstr(o["diverted_asns"])})
    return {
        "placement.csv": _csv(["exp", "k", "p", "D_mean", "D_min", "D_max", "runs"], groups),
        "placement_effect.csv": _csv(["exp", "k", "n_sets", "E_provider_pp", "E_set_pp", "best_set", "best_D",
                                      "worst_set", "worst_D"], effects),
        "placement_sets.csv": _csv(["exp", "k", "p", "adopters", "D", "diverted_asns"], sets),
        "vulnerability.csv": _csv(["client", "router", "attacker_provider", "type0_rov", "type1_rov",
                                   "type0_rov_best_path", "type1_rov_best_path", "type0_rov_why", "type1_rov_why"],
                                  res["vulnerability"]),
    }


def path_end_tables(res: dict) -> Dict[str, str]:
    rows = [{"exp": "type1_pathend", "m": o["k"], "rov_set": _setstr(o["rov_set"]), "pe_set": _setstr(o["pe_set"]),
             "D": o["D"], "diverted_count": o["diverted_count"], "diverted_asns": _setstr(o["diverted_asns"]),
             "victim_probe_successes": o["victim_probe_successes"],
             "accepting_attack_route": o["accepting_attack_route"], "baseline_healthy": int(o["baseline_healthy"])}
            for o in res["observations"]]
    rej = [{"m": r["m"], "pe_set": _setstr(r["pe_set"]), "receiver": r["receiver"], "from": r["from"], "path": r["path"],
            "reject_by": r["reject_by"], "reject_reason": r["reject_reason"]} for r in res["rejected_routes"]]
    return {
        "path_end_results.csv": _csv(["exp", "m", "rov_set", "pe_set", "D", "diverted_count", "diverted_asns",
                                      "victim_probe_successes", "accepting_attack_route", "baseline_healthy"], rows),
        "path_end_rejections.csv": _csv(["m", "pe_set", "receiver", "from", "path", "reject_by", "reject_reason"], rej),
        "path_end_summary.csv": _csv(SUMMARY_FIELDS, [{"exp": "type1_pathend", **c} for c in res["curve"]]),
    }


def rov_tables(res: dict) -> Dict[str, str]:
    return {"results.csv": _csv(RESULT_FIELDS, results_rows(res["observations"])),
            "summary.csv": _csv(SUMMARY_FIELDS, summary_rows(res["curves"]))}


def attack_comparison_tables(res: dict) -> Dict[str, str]:
    f = ["attack", "rov_policy", "rov_adoption", "rpki_state", "advertised_path", "accepting_attack_route",
         "diverted_count", "diversion_fraction", "diversion_rate", "victim_probe_successes", "baseline_healthy"]
    return {"attack_comparison.csv": _csv(f, res["rows"])}


def subprefix_tables(res: dict) -> Dict[str, str]:
    f = ["roa", "roa_max_length", "defence", "rpki_state", "diverted_count", "diversion_fraction", "diversion_rate"]
    return {"subprefix.csv": _csv(f, res["rows"])}


def tables_for(kind: str, result: dict) -> Dict[str, str]:
    return {"rov_adoption": rov_tables, "placement": placement_tables, "path_end": path_end_tables,
            "attack_comparison": attack_comparison_tables, "subprefix": subprefix_tables}.get(kind, lambda r: {})(result)


def simulate_tables(result: dict) -> Dict[str, str]:
    rows = []
    for a, v in result["per_as"].items():
        rows.append({"client": v["asn"], "router": v["router"], "rov": int(v["rov"]), "path_end": int(v["path_end"]),
                     "baseline_endpoint": v["baseline_endpoint"], "endpoint": v["endpoint"], "diverted": int(v["diverted"]),
                     "best_path": " ".join(map(str, v["best_route"]["as_path"])) if v["best_route"] else "",
                     "forwarding_path": " ".join(map(str, v["probe"]["forwarding_path"])),
                     "attack_route_status": v["attack_route_status"]})
    f = ["client", "router", "rov", "path_end", "baseline_endpoint", "endpoint", "diverted", "best_path",
         "forwarding_path", "attack_route_status"]
    return {"results.csv": _csv(f, rows)}


def versions_text(meta: dict, extra: dict = None) -> str:
    lines = ["# Reproducibility metadata (simulation, not a real BGP testbed)"]
    for k, v in {**meta, **(extra or {})}.items():
        lines.append(f"{k}: {v}")
    return "\n".join(lines) + "\n"
