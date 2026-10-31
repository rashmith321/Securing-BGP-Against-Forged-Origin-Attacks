"""Topology: ASes, links and business relationships (loaded from config/topology.json).

The reference topology comes from the implementation guide (section 1 / topo.py LINKS):
8 ASes, 8 provider->customer links.  Relationships are viewed from one AS towards a neighbour:
"customer" (neighbour is my customer), "provider" (neighbour is my provider), "peer".
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Tuple

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "topology.json"


@dataclass(frozen=True)
class ASInfo:
    asn: int
    router: str
    role: str          # measured | victim | attacker
    label: str
    router_id: int


@dataclass
class Topology:
    prefix: str
    subprefix: str
    probe_ip: str
    probe_port: int
    victim: int
    attacker: int
    measured: List[int]
    attacker_providers: List[int]
    ases: Dict[int, ASInfo]
    # links: (provider, customer)
    links: List[Tuple[int, int]]
    roas: List[dict]
    path_end_registry: Dict[int, List[int]]
    local_pref: Dict[str, int]
    model_version: str
    _nbrs: Dict[int, List[Tuple[int, str]]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        nb: Dict[int, List[Tuple[int, str]]] = {a: [] for a in self.ases}
        for prov, cust in self.links:
            nb[prov].append((cust, "customer"))
            nb[cust].append((prov, "provider"))
        self._nbrs = {a: sorted(v) for a, v in nb.items()}

    def neighbors(self, asn: int) -> List[Tuple[int, str]]:
        """[(neighbour_asn, relationship_of_neighbour_to_asn)]"""
        return self._nbrs[asn]

    def relationship(self, asn: int, neighbor: int) -> str:
        for n, rel in self._nbrs[asn]:
            if n == neighbor:
                return rel
        raise KeyError(f"AS{asn} and AS{neighbor} are not adjacent")

    def router_id(self, asn: int) -> int:
        return self.ases[asn].router_id

    def name(self, asn: int) -> str:
        return self.ases[asn].router

    def to_dict(self) -> dict:
        return {
            "model_version": self.model_version,
            "prefix": self.prefix,
            "subprefix": self.subprefix,
            "probe_ip": self.probe_ip,
            "probe_port": self.probe_port,
            "victim": self.victim,
            "attacker": self.attacker,
            "measured": self.measured,
            "attacker_providers": self.attacker_providers,
            "ases": [a.__dict__ for a in self.ases.values()],
            "links": [{"provider": p, "customer": c} for p, c in self.links],
            "roas": self.roas,
            "path_end_registry": {str(k): v for k, v in self.path_end_registry.items()},
            "local_pref": self.local_pref,
        }


def _load_raw() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def load_topology() -> Topology:
    raw = _load_raw()
    ases = {a["asn"]: ASInfo(**a) for a in raw["ases"]}
    return Topology(
        prefix=raw["prefix"],
        subprefix=raw["subprefix"],
        probe_ip=raw["probe_ip"],
        probe_port=raw["probe_port"],
        victim=raw["victim"],
        attacker=raw["attacker"],
        measured=list(raw["measured"]),
        attacker_providers=list(raw["attacker_providers"]),
        ases=ases,
        links=[(l["provider"], l["customer"]) for l in raw["links"]],
        roas=list(raw["roas"]),
        path_end_registry={int(k): list(v) for k, v in raw["path_end_registry"].items()},
        local_pref=dict(raw["local_pref"]),
        model_version=raw["model_version"],
    )
