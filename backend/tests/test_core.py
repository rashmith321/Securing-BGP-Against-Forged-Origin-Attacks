"""Research-critical behaviour tests. Expected outcomes follow the model's *stated rules*, not magic numbers
(except where the guide's own hand analysis states them: 4/6 diverted with no defence)."""
import itertools

import pytest

from app.core import metrics as M
from app.core.engine import BaselineUnhealthy, ScenarioConfig, run_scenario
from app.core.path_end import validate_path_end
from app.core.rpki import ROA, roas_from_dicts, rov_decision, validate_origin
from app.core.topology import load_topology
from app.experiments import attack_comparison, path_end_adoption, placement, rov_adoption
from app.experiments.common import observe, select_sets

T = load_topology()
ALL = frozenset(T.measured)
V, A = T.victim, T.attacker


def test_topology_matches_reference():
    assert len(T.ases) == 8 and len(T.links) == 8 and len(T.measured) == 6
    assert (V, A) == (65700, 65800) and T.prefix == "10.10.0.0/24"
    assert sorted(T.attacker_providers) == [65400, 65600]
    assert set(T.neighbors(A)) == {(65400, "provider"), (65600, "provider")}
    assert T.neighbors(V) == [(65300, "provider")]


# 1
def test_default_roa_authorises_victim():
    roas = roas_from_dicts(T.roas)
    assert roas == [ROA("10.10.0.0/24", 65700, 24)]
    assert validate_origin("10.10.0.0/24", 65700, roas)[0] == "Valid"


# 2
def test_type0_is_invalid():
    state, why, _ = validate_origin("10.10.0.0/24", A, roas_from_dicts(T.roas))
    assert state == "Invalid" and "AS65800" in why


# 3
def test_type1_passes_origin_validation_despite_forged_path():
    res = run_scenario(ScenarioConfig("type1", ALL))
    mr = res["malicious_route"]
    assert mr["advertised_as_path"] == [65800, 65700]
    assert mr["claimed_origin"] == 65700 and mr["actual_originator"] == 65800
    assert mr["rpki_state"] == "Valid"
    assert res["metrics"]["accepting_attack_route"] > 0       # ROV let it in
    assert res["metrics"]["diverted_count"] > 0               # and traffic really goes to the attacker


# 4
def test_rov_rejects_invalid_and_notfound_policy_is_configurable():
    assert rov_decision("Invalid", True)[0] is False
    assert rov_decision("Invalid", False)[0] is True
    assert rov_decision("NotFound", True)[0] is True
    assert rov_decision("NotFound", True, reject_notfound=True)[0] is False
    res = run_scenario(ScenarioConfig("type0", ALL))
    assert res["metrics"]["accepting_attack_route"] == 0
    assert all(r["reject_by"] == "ROV" for r in res["rejected_routes"]) and res["rejected_routes"]


def test_notfound_not_rejected_by_default_engine():
    # ROA for a different prefix => victim route NotFound everywhere; ROV must not blackhole the network
    roas = (ROA("192.0.2.0/24", 65700, 24),)
    res = run_scenario(ScenarioConfig("none", ALL, frozenset(), roas))
    assert res["baseline"]["healthy"]


# 5
def test_path_end_checks_upstream_authorisation():
    reg = T.path_end_registry
    assert validate_path_end([65300, 65700], reg)[0] is True      # authorised upstream
    assert validate_path_end([65700], reg)[0] is True             # straight from the origin
    ok, why = validate_path_end([65800, 65700], reg)              # attacker is not an authorised upstream
    assert ok is False and "AS65800" in why
    assert validate_path_end([65800], reg)[0] is True             # origin 65800 has no record -> not evaluated
    # attacker-provider links alone are NOT proof: r400/r600 are not in the victim's record
    assert 65400 not in reg[65700] and 65600 not in reg[65700] and 65800 not in reg[65700]
    res = run_scenario(ScenarioConfig("type1", ALL, ALL))
    assert res["metrics"]["diversion_rate"] == 0
    assert {r["reject_by"] for r in res["rejected_routes"]} == {"PATH-END"}


# 6
@pytest.mark.parametrize("rov", [frozenset(), ALL])
def test_baseline_healthy(rov):
    res = run_scenario(ScenarioConfig("none", rov, rov))
    assert res["baseline"]["healthy"] and res["baseline"]["victims_reached"] == 6
    assert res["metrics"]["diverted_count"] == 0


def test_unhealthy_baseline_detected_and_explained():
    bad = (ROA("10.10.0.0/24", 65999, 24),)       # ROA no longer authorises the victim
    res = run_scenario(ScenarioConfig("type1", ALL, frozenset(), bad))
    assert not res["baseline"]["healthy"] and res["baseline"]["failing"]
    assert "rejected" in res["baseline"]["failing"][0]["likely_reason"]
    with pytest.raises(BaselineUnhealthy):
        observe(ScenarioConfig("type1", ALL, frozenset(), bad), "x", 6, True)


# 7
def test_diversion_metric():
    assert M.diversion_rate(4, 6) == pytest.approx(2 / 3)
    assert M.protection_pp(2 / 3, 1 / 3) == pytest.approx(100 / 3)
    assert M.relative_reduction(0.0, 0.0) is None
    assert M.relative_reduction(0.5, 0.25) == pytest.approx(0.5)
    res = run_scenario(ScenarioConfig("type1"))
    m = res["metrics"]
    assert m["diversion_rate"] == m["diverted_count"] / 6
    assert m["diverted_count"] == sum(1 for v in res["per_as"].values() if v["probe"]["endpoint"] == "AS65800")
    assert m["victim_probe_successes"] + m["diverted_count"] + m["unreachable_count"] == 6


def test_no_defence_matches_guide_hand_analysis():
    for atk in ("type0", "type1"):
        res = run_scenario(ScenarioConfig(atk))
        assert res["metrics"]["diverted_asns"] == [65200, 65400, 65500, 65600]   # guide: ~4 of 6


def test_route_selection_is_policy_driven_not_shortest_path():
    res = run_scenario(ScenarioConfig("type1"))
    r200 = res["per_as"]["65200"]
    # AS65200 prefers the longer-or-equal customer route (local-pref 200) over the provider route (100)
    assert r200["best_route"]["relationship"] == "customer" and r200["best_route"]["local_pref"] == 200
    # r100 keeps the legitimate route: same local-pref, shorter path
    assert res["per_as"]["65100"]["best_route"]["as_path"] == [65300, 65700]


def test_longest_prefix_match_subprefix():
    strict = run_scenario(ScenarioConfig("subprefix"))                      # no defences: /25 wins everywhere
    assert strict["malicious_route"]["rpki_state"] == "Invalid"
    assert strict["metrics"]["diverted_count"] == 6
    blocked = run_scenario(ScenarioConfig("subprefix", ALL))
    assert blocked["metrics"]["diverted_count"] == 0
    loose = run_scenario(ScenarioConfig("subprefix", ALL, frozenset(), (ROA("10.10.0.0/24", 65700, 25),)))
    assert loose["malicious_route"]["rpki_state"] == "Valid" and loose["metrics"]["diverted_count"] == 6


# 8
def test_adoption_sweep_has_all_seven_levels_and_all_combinations():
    r = rov_adoption.run()
    for exp, curve in r["curves"].items():
        assert [c["k"] for c in curve] == list(range(7))
        assert [c["runs"] for c in curve] == [1, 6, 15, 20, 15, 6, 1]    # C(6,k): exhaustive
    assert r["curves"]["type0_rov"][-1]["D_mean"] == 0
    assert all(c["D_mean"] == r["curves"]["type1_rov"][0]["D_mean"] for c in r["curves"]["type1_rov"])


def test_sweep_order_and_explicit_policies():
    order = [65400, 65600, 65200, 65500, 65100, 65300]
    r = rov_adoption.run({"mode": "order", "order": order}, attacks=("type0",))
    assert [c["runs"] for c in r["curves"]["type0_rov"]] == [1] * 7
    assert r["curves"]["type0_rov"][2]["D_mean"] == 0                      # r400+r600 first => bottled up
    e = rov_adoption.run({"mode": "explicit", "explicit": [65400, 65600]}, attacks=("type0",))
    assert [c["k"] for c in e["curves"]["type0_rov"]] == [2]


# 9
def test_placement_compares_equal_k_only():
    r = placement.run()
    for exp, res in r["results"].items():
        for pk in res["per_k"]:
            ks = {o["k"] for o in r["observations"] if o["exp"] == exp and o["k"] == pk["k"]}
            assert ks == {pk["k"]}
            sets = [o["adopters"] for o in r["observations"] if o["exp"] == exp and o["k"] == pk["k"]]
            assert all(len(s) == pk["k"] for s in sets) and len(sets) == pk["n_sets"]
    k2 = next(x for x in r["results"]["type0_rov"]["per_k"] if x["k"] == 2)
    both = [g for g in k2["groups"] if g["p"] == 2][0]
    none = [g for g in k2["groups"] if g["p"] == 0][0]
    assert both["D_mean"] == 0 and none["D_mean"] > 0
    assert k2["E_provider_pp"] == pytest.approx(100 * (none["D_mean"] - both["D_mean"]))
    assert k2["E_provider_pp"] > 0 and k2["E_set_pp"] >= 0
    assert all(pk["E_set_pp"] in (0.0, None) for pk in r["results"]["type1_rov"]["per_k"])   # ROV cannot help Type-1


# 10
def test_path_end_results_derive_from_route_and_probe_outcomes():
    r = path_end_adoption.run()
    assert [c["k"] for c in r["curve"]] == list(range(7))
    assert r["rov_only"]["D_mean"] > 0
    for o in r["observations"]:
        assert o["D"] == sum(1 for row in o["rows"] if row["after"] == "AS65800") / 6
        # every rejected route is a path-end rejection by a path-end adopter
        for rej in o["rejected"]:
            assert rej["reject_by"] == "PATH-END" and rej["receiver"] in o["pe_set"]
    assert r["full_adoption"]["D_mean"] == 0 and r["hypothesis"]["supported"]
    # providers-only path-end already closes the gap (they are the attacker's only entry points)
    two = [o for o in r["observations"] if o["pe_set"] == [65400, 65600]][0]
    assert two["D"] == 0


# 11
def test_reproducible():
    a = rov_adoption.run({"mode": "sample", "max_sets": 3, "seed": 7})
    b = rov_adoption.run({"mode": "sample", "max_sets": 3, "seed": 7})
    assert a["observations"] == b["observations"] and a["curves"] == b["curves"]
    c = rov_adoption.run({"mode": "sample", "max_sets": 3, "seed": 8})
    # a different seed may pick other sets, but every sampled set must still have exactly k adopters
    assert all(len(o["rov_set"]) == o["k"] for o in c["observations"])
    assert all(1 <= pt["runs"] <= 3 for cv in c["curves"].values() for pt in cv)
    s1, _ = select_sets(T.measured, 2, {"mode": "sample", "max_sets": 3, "seed": 7})
    s2, _ = select_sets(T.measured, 2, {"mode": "sample", "max_sets": 3, "seed": 7})
    assert s1 == s2 and len(s1) == 3
    x = run_scenario(ScenarioConfig("type1", frozenset({65200})))
    y = run_scenario(ScenarioConfig("type1", frozenset({65200})))
    assert x == y


def test_attack_comparison_hypotheses():
    r = attack_comparison.run()
    rows = {(x["attack"], x["rov_policy"]): x for x in r["rows"]}
    assert rows[("type0", "ROV enabled")]["rpki_state"] == "Invalid"
    assert rows[("type1", "ROV enabled")]["rpki_state"] == "Valid"
    assert rows[("type0", "ROV enabled")]["diverted_count"] < rows[("type0", "ROV disabled")]["diverted_count"]
    assert rows[("type1", "ROV enabled")]["diverted_count"] == rows[("type1", "ROV disabled")]["diverted_count"]
    assert all(h["supported"] for h in r["hypotheses"])


def test_unreachable_is_reported_not_hidden():
    # ROV at a stub whose only provider forwards the Invalid route: filtered update replaces the old route
    res = run_scenario(ScenarioConfig("type0", frozenset({65500})))
    assert res["per_as"]["65500"]["endpoint"] == "unreachable"
    assert res["metrics"]["unreachable_count"] == 1
    assert res["metrics"]["victim_probe_successes"] + res["metrics"]["diverted_count"] + 1 == 6


def test_invalid_adopters_rejected():
    with pytest.raises(ValueError):
        run_scenario(ScenarioConfig("type1", frozenset({65700})))


def test_attacker_providers_are_not_interchangeable_at_k1():
    """Measured, not assumed: protecting r600 alone beats protecting r400 alone against Type-0."""
    d = {a: run_scenario(ScenarioConfig("type0", frozenset({a})))["metrics"] for a in (65400, 65600)}
    assert d[65400]["diverted_asns"] == [65200, 65500, 65600]      # r600's branch still feeds r200 -> r500
    assert d[65600]["diverted_asns"] == [65400]                    # r400's route is out-ranked at r100 (shorter legit path)
    notes = placement.run(exps=("type0_rov",))["notes"]
    assert any("not interchangeable" in n and "r400 alone -> D=50.0%" in n for n in notes)
