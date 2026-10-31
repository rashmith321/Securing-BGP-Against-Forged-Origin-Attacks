"""Run persistence (file-based, no database). Runs are never overwritten: every save gets a new id."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .core.topology import CONFIG_PATH, load_topology

_lock = threading.Lock()


def results_dir() -> Path:
    d = Path(os.environ.get("BGP_RESULTS_DIR") or Path(__file__).resolve().parents[1] / "results")
    (d / "runs").mkdir(parents=True, exist_ok=True)
    return d


def _pkg_version(name: str) -> str:
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:
        return "unknown"


def environment_metadata(seed: Optional[int] = None) -> dict:
    topo = load_topology()
    return {
        "model_version": topo.model_version,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "fastapi": _pkg_version("fastapi"), "pydantic": _pkg_version("pydantic"),
        "uvicorn": _pkg_version("uvicorn"), "matplotlib": _pkg_version("matplotlib"),
        "topology_config_sha256": hashlib.sha256(Path(CONFIG_PATH).read_bytes()).hexdigest(),
        "random_seed": seed,
        "determinism": ("The simulation is deterministic. A seed is only used when adopter sets are sampled "
                        "(policy.mode='sample' or max_sets); exhaustive runs use no randomness."),
        "simulated": True,
    }


def new_run_id(kind: str) -> str:
    return f"{kind}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}"


def save_run(kind: str, request: dict, result: dict, seed: Optional[int] = None, extra: Optional[dict] = None) -> dict:
    with _lock:
        d = results_dir() / "runs"
        run_id = new_run_id(kind)
        path = d / f"{run_id}.json"
        n = 1
        while path.exists():                    # never overwrite
            n += 1
            path = d / f"{run_id}-{n}.json"
        run_id = path.stem
        record = {"run_id": run_id, "kind": kind, "created_at": datetime.now(timezone.utc).isoformat(),
                  "request": request, "metadata": environment_metadata(seed), "result": result}
        if extra:
            record.update(extra)
        path.write_text(json.dumps(record, indent=1, default=str), encoding="utf-8")
        return record


def load_run(run_id: str) -> Optional[dict]:
    if not run_id or "/" in run_id or "\\" in run_id or ".." in run_id:
        return None
    p = results_dir() / "runs" / f"{run_id}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def list_runs(limit: int = 200) -> List[dict]:
    out = []
    for p in sorted((results_dir() / "runs").glob("*.json"), reverse=True)[:limit]:
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append({"run_id": rec["run_id"], "kind": rec["kind"], "created_at": rec["created_at"],
                    "request": rec.get("request"), "summary": rec.get("summary")})
    return out
