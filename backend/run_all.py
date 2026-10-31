#!/usr/bin/env python3
"""CLI: run every experiment and write the deliverable files without starting the web server.

    python run_all.py                 # exhaustive adopter sets (recommended)
    python run_all.py --sample 3 --seed 7
Outputs go to results/outputs/<suite-run-id>/ ; every run is also saved under results/runs/.
"""
import argparse
import json

from app.experiments import suite


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", type=int, default=None, help="evaluate only N seeded random adopter sets per level (default: all)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-subprefix", action="store_true")
    ap.add_argument("--allow-unhealthy-baseline", action="store_true")
    a = ap.parse_args()
    policy = {"mode": "sample", "max_sets": a.sample, "seed": a.seed} if a.sample else {"mode": "all", "seed": a.seed}
    out = suite.run_all(policy, include_subprefix=not a.no_subprefix, require_healthy=not a.allow_unhealthy_baseline)
    print("suite run:", out["suite_run_id"])
    print("files    :", ", ".join(out["files"]))
    for b in out["summary"]["bullets"]:
        print(" -", b)
    for f in out["summary"]["flags"]:
        print(" ! FLAG:", f)
    for h in out["summary"]["hypotheses"]:
        print(f" * {'SUPPORTED' if h['supported'] else 'NOT supported'}: {h['hypothesis']} ({h['evidence']})")


if __name__ == "__main__":
    main()
