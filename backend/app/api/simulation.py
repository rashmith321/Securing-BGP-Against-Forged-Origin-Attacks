from fastapi import APIRouter, HTTPException

from .. import store
from ..core.engine import BaselineUnhealthy, ScenarioConfig, run_scenario
from ..core.rpki import ROA
from ..schemas.models import SimulateRequest

router = APIRouter()


def _cfg(req: SimulateRequest) -> ScenarioConfig:
    roas = tuple(ROA(r.prefix, r.origin, r.max_length) for r in req.roas) if req.roas else None
    return ScenarioConfig(req.attack, frozenset(req.rov_set), frozenset(req.path_end_set), roas, req.rov_reject_notfound)


def _unhealthy(res: dict):
    raise HTTPException(409, detail={
        "error": "baseline_unhealthy",
        "message": "Not every measured AS reaches the legitimate victim before the attack; attack results would be meaningless.",
        "failing": res["baseline"]["failing"], "converged": res["baseline"]["converged"]})


@router.post("/baseline")
def baseline(req: SimulateRequest):
    """Run (and save) the no-attack baseline for the given defence configuration."""
    req = req.model_copy(update={"attack": "none"})
    res = run_scenario(_cfg(req))
    rec = store.save_run("baseline", req.model_dump(), res) if req.save else None
    return {"run_id": rec["run_id"] if rec else None, "result": res}


@router.post("/simulate")
def simulate(req: SimulateRequest):
    res = run_scenario(_cfg(req))
    if req.require_healthy_baseline and not res["baseline"]["healthy"]:
        _unhealthy(res)
    run_id = None
    if req.save:
        m = res["metrics"]
        rec = store.save_run("simulate", req.model_dump(), res,
                             extra={"summary": f"{req.attack} | ROV {len(req.rov_set)}/6 | PE {len(req.path_end_set)}/6 | D={m['diversion_fraction']}"})
        run_id = rec["run_id"]
    return {"run_id": run_id, "result": res}
