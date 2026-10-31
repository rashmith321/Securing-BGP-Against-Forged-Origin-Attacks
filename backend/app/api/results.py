import json

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from .. import exports, store

router = APIRouter(prefix="/results")


def _get(run_id: str) -> dict:
    rec = store.load_run(run_id)
    if rec is None:
        raise HTTPException(404, f"run '{run_id}' not found")
    return rec


def _tables(rec: dict) -> dict:
    if rec["kind"] in ("simulate", "baseline"):
        return exports.simulate_tables(rec["result"])
    return exports.tables_for(rec["kind"], rec["result"])


@router.get("")
def list_runs(limit: int = 100):
    return {"runs": store.list_runs(limit)}


@router.get("/{run_id}")
def get_run(run_id: str):
    return _get(run_id)


@router.get("/{run_id}/tables")
def list_tables(run_id: str):
    rec = _get(run_id)
    out = {"tables": sorted(_tables(rec))}
    if rec["kind"] == "suite":
        d = store.results_dir() / "outputs" / run_id
        out["files"] = sorted(p.name for p in d.iterdir()) if d.exists() else []
    return out


@router.get("/{run_id}/csv", response_class=PlainTextResponse)
def run_csv(run_id: str, table: str = Query(default=None, description="CSV table name; default = main table")):
    rec = _get(run_id)
    t = _tables(rec)
    if not t:
        raise HTTPException(404, "this run has no CSV tables (suite runs: use /files/{name})")
    name = table or ("results.csv" if "results.csv" in t else sorted(t)[0])
    if name not in t:
        raise HTTPException(404, f"table '{name}' not found; available: {sorted(t)}")
    return PlainTextResponse(t[name], media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{run_id}_{name}"'})


@router.get("/{run_id}/json")
def run_json(run_id: str):
    rec = _get(run_id)
    return JSONResponse(rec, headers={"Content-Disposition": f'attachment; filename="{run_id}.json"'})


@router.get("/{run_id}/files/{name}")
def suite_file(run_id: str, name: str):
    d = store.results_dir() / "outputs" / run_id
    allowed = {p.name: p for p in d.iterdir()} if d.exists() else {}
    if name not in allowed:
        raise HTTPException(404, f"file '{name}' not found for {run_id}")
    return FileResponse(allowed[name], filename=name)
