"""Experiment 3: incremental ROV adoption sweep (k = 0..6) for Type-0 and Type-1."""
from __future__ import annotations

from typing import Dict, List, Optional

from ..core.engine import ScenarioConfig
from ..core.topology import load_topology
from .common import SET_POLICY_TEXT, levels_for, observe, select_sets, summarize_curve


def run(policy: Optional[dict] = None, attacks=("type0", "type1"), require_healthy: bool = True,
        roas=None) -> dict:
    topo = load_topology()
    n = len(topo.measured)
    obs_all: List[dict] = []
    curves: Dict[str, List[dict]] = {}
    modes = set()
    for attack in attacks:
        exp = f"{attack}_rov"
        obs = []
        for k in levels_for(policy, n):
            sets, mode = select_sets(topo.measured, k, policy)
            modes.add(mode)
            for s in sets:
                obs.append(observe(ScenarioConfig(attack, frozenset(s), frozenset(), roas), exp, k, require_healthy, topo))
        obs_all += obs
        curves[exp] = summarize_curve(obs, n)
    mode = "all" if modes == {"all"} else sorted(modes)[0]
    types = {e: c for e, c in curves.items()}
    # curve-shape findings computed from data
    findings = []
    for exp, c in curves.items():
        first, last = c[0], c[-1]
        findings.append(f"{exp}: D_mean {100*first['D_mean']:.1f}% at k={first['k']} -> {100*last['D_mean']:.1f}% at k={last['k']} "
                        f"(residual diversion {100*last['D_mean']:.1f}%).")
    return {"experiment": "rov_adoption", "simulated": True, "measured": n, "aggregation_policy": policy or {"mode": "all"},
            "aggregation_text": SET_POLICY_TEXT[mode], "set_mode": mode, "curves": curves,
            "observations": obs_all, "findings": findings}
