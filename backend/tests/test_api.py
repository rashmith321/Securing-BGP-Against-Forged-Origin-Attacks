import csv
import io

from fastapi.testclient import TestClient

from app.main import app

c = TestClient(app)


def test_health_topology_config():
    assert c.get("/api/health").json()["status"] == "ok"
    t = c.get("/api/topology").json()
    assert len(t["ases"]) == 8 and t["victim"] == 65700 and t["attacker"] == 65800
    assert c.get("/api/config").json()["defaults"]["roas"][0]["max_length"] == 24


def test_simulate_validation_and_conflict():
    assert c.post("/api/simulate", json={"attack": "type1", "rov_set": [1]}).status_code == 422
    assert c.post("/api/simulate", json={"attack": "bogus"}).status_code == 422
    bad = {"attack": "type1", "roas": [{"prefix": "10.10.0.0/24", "origin": 65999, "max_length": 24}],
           "rov_set": [65100, 65200, 65300, 65400, 65500, 65600]}
    r = c.post("/api/simulate", json=bad)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "baseline_unhealthy"
    ok = c.post("/api/simulate", json={**bad, "require_healthy_baseline": False, "save": False})
    assert ok.status_code == 200 and ok.json()["result"]["baseline"]["healthy"] is False


def test_run_saved_and_csv_agrees_with_result():
    r = c.post("/api/experiments/rov-adoption", json={}).json()
    rid = r["run_id"]
    saved = c.get(f"/api/results/{rid}").json()
    assert saved["result"]["curves"] == r["result"]["curves"]
    assert "random_seed" in saved["metadata"] and saved["metadata"]["simulated"] is True
    rows = list(csv.DictReader(io.StringIO(c.get(f"/api/results/{rid}/csv?table=results.csv").text)))
    assert {"run_id", "exp", "scenario", "k", "rov_set", "pe_set", "client", "baseline", "after"} <= set(rows[0])
    # per-(exp,k) diversion computed from the CSV equals the stored curve
    for exp, curve in r["result"]["curves"].items():
        for point in curve:
            sub = [x for x in rows if x["exp"] == exp and int(x["k"]) == point["k"]]
            runs = {}
            for x in sub:
                runs.setdefault(x["run_id"], []).append(x["after"] == "AS65800")
            d = sum(sum(v) / len(v) for v in runs.values()) / len(runs)
            assert abs(d - point["D_mean"]) < 1e-9
    summ = list(csv.DictReader(io.StringIO(c.get(f"/api/results/{rid}/csv?table=summary.csv").text)))
    assert len(summ) == 14                                  # 2 attacks x 7 levels
    assert c.get("/api/results/nope").status_code == 404
    assert c.get(f"/api/results/{rid}/csv?table=zzz.csv").status_code == 404


def test_other_experiments_and_runs_not_overwritten():
    a = c.post("/api/experiments/placement", json={}).json()["run_id"]
    b = c.post("/api/experiments/placement", json={}).json()["run_id"]
    assert a != b and c.get(f"/api/results/{a}").status_code == 200
    pe = c.post("/api/experiments/path-end", json={}).json()
    assert len(pe["result"]["curve"]) == 7
    t = c.get(f"/api/results/{pe['run_id']}/csv?table=path_end_results.csv").text
    assert len(list(csv.DictReader(io.StringIO(t)))) == 64            # every subset of 6 ASes
    assert c.post("/api/experiments/attack-comparison", json={}).status_code == 200
    assert c.post("/api/experiments/subprefix").status_code == 200
    assert c.post("/api/experiments/rov-adoption", json={"policy": {"mode": "order", "order": [65400]}}).status_code == 400


def test_full_suite_writes_deliverables():
    r = c.post("/api/experiments/full-suite", json={}).json()
    need = {"results.csv", "summary.csv", "gap1_adoption_curves.png", "placement.csv", "gap1_placement.png",
            "vulnerability.csv", "path_end_results.csv", "versions.txt", "README.md"}
    assert need <= set(r["files"])
    f = c.get(f"/api/results/{r['suite_run_id']}/files/gap1_adoption_curves.png")
    assert f.status_code == 200 and f.content[:4] == b"\x89PNG"
    assert c.get(f"/api/results/{r['suite_run_id']}/files/..%2Fx").status_code in (404, 422)
    assert "random_seed" in c.get(f"/api/results/{r['suite_run_id']}/files/versions.txt").text
