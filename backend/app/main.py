"""FastAPI entry point.  Run:  uvicorn app.main:app --reload --port 8000   (from backend/)"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api import experiments, results, simulation, topology
from .core.engine import BaselineUnhealthy

app = FastAPI(title="BGP Forged-Origin Hijacking Simulator",
              description="Simulation (NOT a real BGP testbed). All numbers are computed by the backend engine.",
              version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                                                  "http://localhost:4173", "http://127.0.0.1:4173"],
                   allow_methods=["*"], allow_headers=["*"])
for r in (topology.router, simulation.router, experiments.router, results.router):
    app.include_router(r, prefix="/api")


@app.exception_handler(BaselineUnhealthy)
async def _baseline(_: Request, exc: BaselineUnhealthy):
    return JSONResponse(status_code=409, content={"detail": {"error": "baseline_unhealthy", "message": str(exc), **exc.details}})


@app.exception_handler(ValueError)
async def _value(_: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": {"error": "invalid_configuration", "message": str(exc)}})
