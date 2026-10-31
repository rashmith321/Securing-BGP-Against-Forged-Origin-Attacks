# Architecture
Frontend (React/Vite) calls the FastAPI REST API; all routing, validation, selection, forwarding and metrics run in
`backend/app/core`. Experiments in `backend/app/experiments` orchestrate many engine runs and return raw observations
plus aggregates. `store.py` saves each run as JSON (never overwritten); `exports.py` and `plots.py` build CSV/PNG only
from saved dicts. The engine could later be swapped for an FRR/Routinator driver behind the same `run_scenario` result shape.
Seven concepts are separate: advertisement (`routes`, `Announcement`), propagation (`propagation`), RPKI validation (`rpki`),
accept/reject (`BGPSim._import`), best route (`route_selection`), forwarding (`traffic`), metrics (`metrics`).
