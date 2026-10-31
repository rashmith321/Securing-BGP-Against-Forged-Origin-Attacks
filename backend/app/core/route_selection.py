"""Best-route selection (concept 5) and longest-prefix match.

Ranking policy (documented assumption; mirrors the FRR lab, NOT "shortest path always wins"):
  1. locally originated route beats any learned route (FRR weight 32768)
  2. highest local preference  (customer 200 > peer 150 > provider 100)      <- business policy first
  3. shortest AS path
  4. oldest route (smaller arrival tick): FRR prefers the older eBGP route; this is why r100 keeps
     the legitimate route when a Type-0 hijack ties on local-pref and length
  5. lowest neighbour router-id (deterministic final tie-break)
"""
from __future__ import annotations

import ipaddress
from typing import Callable, Iterable, List, Optional

from .routes import Route


def rank_key(route: Route, neighbor_router_id: Callable[[int], int]):
    if route.local:
        return (0, 0, 0, 0, 0)
    return (1, -route.local_pref, route.length, route.arrived_tick, neighbor_router_id(route.learned_from))


def select_best(candidates: Iterable[Route], neighbor_router_id: Callable[[int], int]) -> Optional[Route]:
    cands: List[Route] = [c for c in candidates if c.accepted]
    if not cands:
        return None
    return min(cands, key=lambda r: rank_key(r, neighbor_router_id))


def explain_choice(candidates: Iterable[Route], best: Route, neighbor_router_id: Callable[[int], int]) -> str:
    cands = [c for c in candidates if c.accepted]
    if best.local:
        return "Locally originated route (highest preference)."
    if len(cands) == 1:
        return "Only one accepted route."
    others = [c for c in cands if c is not best]
    reasons = []
    for o in others:
        if o.local_pref != best.local_pref:
            reasons.append("higher local-pref")
        elif o.length != best.length:
            reasons.append("shorter AS path")
        elif o.arrived_tick != best.arrived_tick:
            reasons.append("older route")
        else:
            reasons.append("lower neighbour router-id")
    # report the most decisive (first-in-order) reason across competitors
    order = ["higher local-pref", "shorter AS path", "older route", "lower neighbour router-id"]
    for r in order:
        if r in reasons:
            return f"Won on {r} against {len(others)} other accepted route(s)."
    return "Selected by ranking policy."


def longest_prefix_match(ip: str, prefixes: Iterable[str]) -> Optional[str]:
    addr = ipaddress.ip_address(ip)
    best = None
    for p in prefixes:
        net = ipaddress.ip_network(p, strict=True)
        if addr in net and (best is None or net.prefixlen > ipaddress.ip_network(best).prefixlen):
            best = p
    return best
