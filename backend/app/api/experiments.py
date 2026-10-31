from fastapi import APIRouter

from .. import store
from ..experiments import attack_comparison, path_end_adoption, placement, rov_adoption, subprefix, suite, summary
from ..schemas.models import (AttackComparisonRequest, PathEndRequest, PlacementRequest, RovAdoptionRequest,
                              SuiteRequest)

router = APIRouter(prefix="/experiments")


def _seed(policy):
    return policy.seed if policy.mode == "sample" or policy.max_sets else None


@router.post("/attack-comparison")
def attack_cmp(req: AttackComparisonRequest):
    res = attack_comparison.run(req.rov_set, req.path_end_set, req.require_healthy_baseline)
    rec = store.save_run("attack_comparison", req.model_dump(), res, extra={"summary": "; ".join(res["findings"][:1])})
    return {"run_id": rec["run_id"], "result": res, "metadata": rec["metadata"]}


@router.post("/rov-adoption")
def rov(req: RovAdoptionRequest):
    pol = req.policy.model_dump()
    res = rov_adoption.run(pol, tuple(req.attacks), req.require_healthy_baseline)
    res["summary"] = summary.build(None, res, None, None)
    rec = store.save_run("rov_adoption", req.model_dump(), res, _seed(req.policy),
                         extra={"summary": res["findings"][0] if res["findings"] else ""})
    return {"run_id": rec["run_id"], "result": res, "metadata": rec["metadata"]}


@router.post("/placement")
def place(req: PlacementRequest):
    pol = req.policy.model_dump()
    res = placement.run(tuple(req.experiments), pol, req.rov_base, req.require_healthy_baseline)
    rec = store.save_run("placement", req.model_dump(), res, _seed(req.policy),
                         extra={"summary": (res["notes"][0] if res["notes"] else "")})
    return {"run_id": rec["run_id"], "result": res, "metadata": rec["metadata"]}


@router.post("/path-end")
def path_end(req: PathEndRequest):
    pol = req.policy.model_dump()
    res = path_end_adoption.run(pol, req.rov_set, req.require_healthy_baseline)
    res["summary"] = summary.build(None, None, None, res)
    rec = store.save_run("path_end", req.model_dump(), res, _seed(req.policy),
                         extra={"summary": (res["hypothesis"] or {}).get("evidence", "")})
    return {"run_id": rec["run_id"], "result": res, "metadata": rec["metadata"]}


@router.post("/subprefix")
def sub():
    res = subprefix.run()
    rec = store.save_run("subprefix", {}, res, extra={"summary": "sub-prefix vs ROA max length"})
    return {"run_id": rec["run_id"], "result": res, "metadata": rec["metadata"]}


@router.post("/full-suite")
def full(req: SuiteRequest):
    pol = req.policy.model_dump()
    out = suite.run_all(pol, req.include_subprefix, req.require_healthy_baseline)
    return out
