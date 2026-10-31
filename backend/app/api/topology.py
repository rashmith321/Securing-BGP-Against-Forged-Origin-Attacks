from fastapi import APIRouter

from ..core.topology import load_topology
from ..experiments.common import SET_POLICY_TEXT
from ..store import environment_metadata

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "service": "bgp-forged-origin-simulator", "simulated": True}


@router.get("/topology")
def topology():
    t = load_topology().to_dict()
    t["description"] = ("Reference topology from the implementation guide: 8 ASes, 8 provider->customer links. "
                        "r400 and r600 are the attacker's providers.")
    return t


@router.get("/config")
def config():
    t = load_topology()
    return {
        "defaults": {
            "prefix": t.prefix, "roas": t.roas, "rov_policy": "reject RPKI Invalid; accept Valid and NotFound",
            "rov_reject_notfound": False, "path_end_registry": {str(k): v for k, v in t.path_end_registry.items()},
            "local_pref": t.local_pref, "probe": f"{t.probe_ip}:{t.probe_port}", "measured": t.measured,
        },
        "route_selection_order": ["locally originated", "highest local-pref (customer 200 > peer 150 > provider 100)",
                                  "shortest AS path", "oldest route (arrival tick)", "lowest neighbour router-id"],
        "export_policy": "Gao-Rexford: customer routes to everyone; peer/provider routes only to customers.",
        "set_policies": SET_POLICY_TEXT,
        "path_convention": "AS path is listed from the most recent AS to the claimed origin (last element).",
        "reproducibility": environment_metadata(),
    }
