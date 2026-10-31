"""Run all experiments, save each run, and write the deliverable files (results.csv, summary.csv, ...)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .. import exports, plots, store
from . import attack_comparison, path_end_adoption, placement, rov_adoption, subprefix, summary

LIMITATIONS = [
    "This is a simulation, not a real Internet or production BGP testbed; Mininet/FRR/Routinator validation is future work.",
    "The topology has 8 ASes (6 measured), one router each; D therefore moves in steps of 16.7 percentage points.",
    "Routing outcomes depend on the configured topology, Gao-Rexford-style policy, tie-breaking and defence adoption.",
    "The path-end defence is a simplified ASPA-inspired model, not standards-compliant ASPA.",
    "Do not generalise these results to the whole Internet without further experiments.",
]


def run_all(policy: Optional[dict] = None, include_subprefix: bool = True, require_healthy: bool = True) -> dict:
    pol = policy or {}
    seed = pol.get("seed") if (pol.get("mode") == "sample" or pol.get("max_sets")) else None
    cmp_r = attack_comparison.run(require_healthy=require_healthy)
    rov_r = rov_adoption.run(policy, require_healthy=require_healthy)
    pl_r = placement.run(policy=policy if (policy or {}).get("mode") in ("all", "sample") else None, require_healthy=require_healthy)
    pe_r = path_end_adoption.run(policy, require_healthy=require_healthy)
    sub_r = subprefix.run() if include_subprefix else None
    summ = summary.build(cmp_r, rov_r, pl_r, pe_r)
    ids = {}
    for kind, res in (("attack_comparison", cmp_r), ("rov_adoption", rov_r), ("placement", pl_r), ("path_end", pe_r),
                      ("subprefix", sub_r)):
        if res is None:
            continue
        rec = store.save_run(kind, {"policy": policy, "via": "suite"}, res, seed)
        ids[kind] = rec["run_id"]
    suite = store.save_run("suite", {"policy": policy}, {"run_ids": ids, "summary": summ, "limitations": LIMITATIONS},
                           seed, extra={"summary": summ["bullets"][:1]})
    out_dir = store.results_dir() / "outputs" / suite["run_id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {}
    files.update(exports.rov_tables(rov_r))
    files.update(exports.placement_tables(pl_r))
    files.update(exports.path_end_tables(pe_r))
    files.update(exports.attack_comparison_tables(cmp_r))
    if sub_r:
        files.update(exports.subprefix_tables(sub_r))
    # results.csv also carries the path-end sweep (guide layout: one file, exp column distinguishes them)
    both = rov_r["observations"] + pe_r["observations"]
    files["results.csv"] = exports._csv(exports.RESULT_FIELDS, exports.results_rows(both))
    curves = dict(rov_r["curves"])
    curves["type1_pathend"] = pe_r["curve"]
    files["summary.csv"] = exports._csv(exports.SUMMARY_FIELDS, exports.summary_rows(curves))
    files["versions.txt"] = exports.versions_text(suite["metadata"], {"suite_run_id": suite["run_id"], "run_ids": ids,
                                                                          "set_policy": policy or {"mode": "all"}})
    files["README.md"] = _readme(suite["run_id"], summ)
    for name, text in files.items():
        (out_dir / name).write_text(text, encoding="utf-8")
    plots.adoption_curves(rov_r, pe_r, out_dir / "gap1_adoption_curves.png")
    plots.placement(pl_r, out_dir / "gap1_placement.png")
    return {"suite_run_id": suite["run_id"], "run_ids": ids, "files": sorted(list(files) + ["gap1_adoption_curves.png",
            "gap1_placement.png"]), "summary": summ, "limitations": LIMITATIONS}


def _readme(run_id: str, summ: dict) -> str:
    lines = [f"# Output bundle {run_id}", "", "SIMULATED results from the BGP forged-origin web simulator (not real BGP).", "",
             "Files: results.csv, summary.csv, gap1_adoption_curves.png, placement.csv, placement_effect.csv, placement_sets.csv,",
             "gap1_placement.png, vulnerability.csv, path_end_results.csv, path_end_rejections.csv, versions.txt.", "",
             "## Automatically generated summary", ""]
    lines += [f"- {b}" for b in summ["bullets"]]
    lines += ["", "## Hypotheses"] + [f"- {'SUPPORTED' if h['supported'] else 'NOT supported'}: {h['hypothesis']} ({h['evidence']})"
                                      for h in summ["hypotheses"]]
    lines += ["", "## Limitations"] + [f"- {l}" for l in LIMITATIONS]
    return "\n".join(lines) + "\n"
