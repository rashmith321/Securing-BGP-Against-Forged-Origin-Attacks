# Securing BGP Against Forged-Origin Attacks: web simulation

An interactive **simulation** (not a real BGP testbed) of the project in `abstract_cn.pdf` and
`BGP_Gap1_Implementation_Guide_v2.docx`. It shows that ROV blocks a Type-0 origin hijack but not a
Type-1 forged-origin hijack, how diversion changes as ROV adoption grows, whether *which* ASes adopt matters,
and how a simplified ASPA-style path-end check closes the gap. All results are computed by the Python
backend; the React UI only displays them. **No FRR, Mininet, Routinator or real BGP session is used.**

## Architecture
```
React + Vite + Recharts  --REST-->  FastAPI (api/)  -->  experiments/  -->  core/ (engine)
                                                              |
                                                     store.py (JSON runs), exports.py, plots.py
```
core/ modules: `topology` (ASes, links), `routes` (advertisement), `propagation` (tick-based path-vector
propagation, import filters), `rpki` (Valid/Invalid/NotFound), `path_end`, `route_selection`, `traffic`
(hop-by-hop longest-prefix forwarding, probes), `metrics`, `engine` (baseline + attack orchestration).
`experiments/`: attack_comparison, rov_adoption, placement, path_end_adoption, subprefix, suite, summary.

## Prerequisites
Python 3.10+ (tested 3.12), Node 18+ (tested 22). Tested only on Linux in a sandbox; Ubuntu and Windows should work but are untested.

## Run
```bash
# backend
cd backend
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000
# frontend (second terminal)
cd frontend
npm install
npm run dev          # http://localhost:5173 (proxies /api to :8000)
```
Tests: `cd backend && python -m pytest -q`.
Headless bundle of all outputs: `cd backend && python run_all.py` (writes `results/outputs/<id>/`).

## Experiments (UI page / endpoint)
| Experiment | Page | Endpoint |
|---|---|---|
| Single scenario, baseline | Attack simulator | `POST /api/simulate`, `POST /api/baseline` |
| Type-0 vs Type-1 | Type-0 vs Type-1 | `POST /api/experiments/attack-comparison` |
| ROV sweep k=0..6 | ROV adoption | `POST /api/experiments/rov-adoption` |
| Placement, E(k) | Placement | `POST /api/experiments/placement` |
| Path-end sweep | Path-end validation | `POST /api/experiments/path-end` |
| Sub-prefix (optional) | Type-0 vs Type-1 | `POST /api/experiments/subprefix` |
| Everything + files | Results and export | `POST /api/experiments/full-suite` |

Other endpoints: `GET /api/health|topology|config`, `GET /api/results`, `/api/results/{id}`, `/csv?table=`, `/json`, `/files/{name}`.
Example:
```bash
curl -X POST localhost:8000/api/simulate -H 'Content-Type: application/json' \
  -d '{"attack":"type1","rov_set":[65100,65200,65300,65400,65500,65600]}'
curl -X POST localhost:8000/api/experiments/rov-adoption -H 'Content-Type: application/json' \
  -d '{"policy":{"mode":"order","order":[65400,65600,65200,65500,65100,65300]}}'
```
Set policies: `all` (every combination, default), `sample` (seeded), `order` (first k of an order), `explicit`.
A 409 `baseline_unhealthy` means not all six ASes reach the victim before the attack.

## Output files (in `results/outputs/<suite-id>/`)
results.csv, summary.csv, gap1_adoption_curves.png, placement.csv (+ placement_effect.csv, placement_sets.csv),
gap1_placement.png, vulnerability.csv, path_end_results.csv (+ rejections, summary), attack_comparison.csv,
subprefix.csv, versions.txt, README.md. Charts and CSVs are generated from saved run data.

## Metrics
- **D** = (measured ASes whose probe is answered by AS65800) / 6. Steps of 16.7 points. Unreachable ASes are counted separately (U).
- protection = 100(D(0)-D(k)); relative reduction = (D(0)-D(k))/D(0) (n/a if D(0)=0); marginal gain = 100(D(k-1)-D(k)); residual = D(6).
- **p** = number of attacker providers (r400, r600) among adopters. **E(k)** = 100(D(k,p_min)-D(k,p_max)), positive = providers adopting helps.
  **E_set(k)** = 100(D worst set - D best set) >= 0 (the prompt's "best vs worst placement" reading). Both are reported.

## Assumptions and limitations
See `docs/methodology.md` and `docs/limitations.md`. In short: 8 ASes / 6 measured; Gao-Rexford policy; ties broken by
route age (assumption mirroring FRR, not validated against real FRR); path-end is ASPA-inspired, not standards-compliant;
do not generalise to the Internet.

## Troubleshooting
- "Backend not reachable": start uvicorn on port 8000 first.
- Fonts missing offline: the UI falls back to system fonts.
- 409 baseline_unhealthy: inspect the ROA (e.g. a ROA not authorising AS65700 rejects the legitimate route).
- To reset saved runs delete `backend/results/runs/`.
