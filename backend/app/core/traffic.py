"""Traffic forwarding and HTTP probes (concept 6).

Hop-by-hop forwarding: at each AS the longest-prefix match among that AS's *own* best routes is
used (a FIB), the packet moves to the neighbour the route was learned from, and the walk ends at
an AS that originates the matched prefix.  The endpoint reached is whichever AS terminates the
walk (victim service or the attacker's look-alike service), so diversion is a data-plane result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .propagation import BGPSim
from .route_selection import longest_prefix_match

MAX_HOPS = 32


@dataclass
class ProbeResult:
    source_asn: int
    destination_ip: str
    destination_port: int
    matched_prefix: Optional[str]
    selected_as_path: List[int]       # control-plane path of the source's best route
    selected_route: Optional[dict]
    forwarding_path: List[int]        # data-plane hops, source first
    endpoint: str                     # "AS65700" | "AS65800" | "unreachable"
    reply_received: bool
    reached_victim: bool
    diverted: bool
    failure_reason: Optional[str]
    route_choice: Optional[str] = None

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def probe(sim: BGPSim, source: int, dst_ip: str, dst_port: int) -> ProbeResult:
    topo = sim.topo
    path = [source]
    cur = source
    seen = set()
    matched_first = None
    first_route = None
    endpoint, reason = "unreachable", None
    for _ in range(MAX_HOPS):
        prefixes = [p for p, r in sim.best[cur].items() if r is not None]
        m = longest_prefix_match(dst_ip, prefixes)
        if m is None:
            reason = f"no route to {dst_ip} at AS{cur}"
            break
        route = sim.best[cur][m]
        if matched_first is None:
            matched_first, first_route = m, route
        if (cur, m) in seen:
            reason = f"forwarding loop at AS{cur}"
            break
        seen.add((cur, m))
        if route.local:
            endpoint = f"AS{cur}"
            break
        cur = route.learned_from
        path.append(cur)
    else:
        reason = "hop limit exceeded"
    reply = endpoint != "unreachable"
    victim = endpoint == f"AS{topo.victim}"
    diverted = endpoint == f"AS{topo.attacker}"
    return ProbeResult(
        source_asn=source, destination_ip=dst_ip, destination_port=dst_port, matched_prefix=matched_first,
        selected_as_path=list(first_route.as_path) if first_route else [],
        selected_route=first_route.to_dict() if first_route else None,
        forwarding_path=path, endpoint=endpoint, reply_received=reply, reached_victim=victim,
        diverted=diverted, failure_reason=reason,
    )
