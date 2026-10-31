"""PNG figures generated from saved experiment results (not from re-simulation, never hand-drawn)."""
from __future__ import annotations

from pathlib import Path
from typing import Dict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

LABELS = {"type0_rov": "Type-0 vs ROV adoption", "type1_rov": "Type-1 vs ROV adoption",
          "type1_pathend": "Type-1 vs path-end adoption (ROV everywhere)"}
COLORS = {"type0_rov": "#2B5FAE", "type1_rov": "#B3261E", "type1_pathend": "#7A4FB3"}


def adoption_curves(rov: dict, path_end: dict, out: Path) -> Path:
    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    curves = dict(rov["curves"])
    curves["type1_pathend"] = path_end["curve"]
    for exp, c in curves.items():
        ks = [x["k"] for x in c]
        ax.errorbar(ks, [100 * x["D_mean"] for x in c], yerr=[100 * x["D_sd"] for x in c], marker="o", capsize=3,
                    label=LABELS[exp], color=COLORS[exp])
    ax.set_xlabel("number of adopting ASes, k (out of 6 measured)")
    ax.set_ylabel("diversion rate D (% of measured ASes reaching the attacker)")
    ax.set_ylim(-5, 105)
    ax.grid(alpha=.3)
    ax.legend(fontsize=8)
    ax.set_title("SIMULATED results - mean over all adopter sets, bars = sd", fontsize=9)
    fig.tight_layout()
    fig.savefig(out, dpi=160)
    plt.close(fig)
    return out


def placement(res: dict, out: Path) -> Path:
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.4))
    for ax, k in zip(axes[:2], (1, 2)):
        for i, (exp, r) in enumerate(res["results"].items()):
            pk = next((x for x in r["per_k"] if x["k"] == k), None)
            if not pk:
                continue
            ax.bar([g["p"] + (i - 1) * 0.25 for g in pk["groups"]], [100 * g["D_mean"] for g in pk["groups"]], 0.25,
                   label=LABELS[exp], color=COLORS[exp])
        ax.set_title(f"k = {k} adopter(s)")
        ax.set_xticks(range(0, k + 1))
        ax.set_xlabel("p = attacker providers (r400, r600) among adopters")
        ax.set_ylim(0, 105)
        ax.grid(axis="y", alpha=.3)
    axes[0].set_ylabel("mean diversion rate D (%)")
    axes[0].legend(fontsize=7)
    ax = axes[2]
    for exp, r in res["results"].items():
        pts = [(x["k"], x["E_set_pp"]) for x in r["per_k"] if x["E_set_pp"] is not None]
        if pts:
            ax.plot(*zip(*pts), marker="o", label=LABELS[exp], color=COLORS[exp])
    ax.set_title("Placement effect E_set(k) = worst - best set")
    ax.set_xlabel("k adopters")
    ax.set_ylabel("percentage points")
    ax.grid(alpha=.3)
    fig.suptitle("SIMULATED results - exhaustive adopter sets", fontsize=9)
    fig.tight_layout()
    fig.savefig(out, dpi=160)
    plt.close(fig)
    return out
