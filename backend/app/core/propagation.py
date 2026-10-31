"""Route propagation (concept 2), import filtering (concepts 3-4) and the per-AS RIBs.

The simulator is a synchronous, tick-based path-vector model:
  * each tick every AS (a) picks its best route per prefix, (b) computes what it advertises to each
    neighbour under Gao-Rexford export rules, (c) neighbours import the changes (loop check,
    ROV, path-end, local-pref by relationship).
  * it stops when no import/withdrawal changes anything.  Arrival ticks give "route age".
The attack is injected *after* the baseline has converged (as the guide's runner does), so the
legitimate route is older than the hijack route and wins last-resort age ties.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

from .path_end import validate_path_end
from .route_selection import select_best
from .routes import Route
from .rpki import ROA, rov_decision, validate_origin
from .topology import Topology

Prefix = str


@dataclass
class Announcement:
    """An origination at an AS.  `forged_tail` is prepended *after* the origin ASN on export.

    Type-0: forged_tail=()      -> advertised path [attacker]
    Type-1: forged_tail=(V,)    -> advertised path [attacker, V]  (claimed origin V)
    """
    asn: int
    prefix: Prefix
    forged_tail: Tuple[int, ...] = ()
    malicious: bool = False


class BGPSim:
    def __init__(self, topo: Topology, roas: List[ROA], rov: FrozenSet[int], path_end: FrozenSet[int],
                 rov_reject_notfound: bool = False, max_ticks: int = 200) -> None:
        self.topo = topo
        self.roas = roas
        self.rov = rov
        self.path_end = path_end
        self.rov_reject_notfound = rov_reject_notfound
        self.max_ticks = max_ticks
        self.tick = 0
        self.announcements: List[Announcement] = []
        # adj_in[asn][prefix][neighbor] -> accepted Route ; rejected_in same shape for filtered routes
        self.adj_in: Dict[int, Dict[Prefix, Dict[int, Route]]] = {a: {} for a in topo.ases}
        self.rejected_in: Dict[int, Dict[Prefix, Dict[int, Route]]] = {a: {} for a in topo.ases}
        self.local: Dict[int, Dict[Prefix, Route]] = {a: {} for a in topo.ases}
        self.best: Dict[int, Dict[Prefix, Optional[Route]]] = {a: {} for a in topo.ases}
        self._sent: Dict[Tuple[int, int, Prefix], Tuple[int, ...]] = {}
        self.loop_drops = 0
        self.converged_at: Optional[int] = None

    # ---- concept 1: advertisement ------------------------------------------------------------
    def originate(self, ann: Announcement) -> None:
        self.announcements.append(ann)
        r = Route(prefix=ann.prefix, as_path=(), learned_from=None, relationship=None,
                  local_pref=10**6, arrived_tick=self.tick, local=True)
        self.local[ann.asn][ann.prefix] = r

    def _nid(self, asn: int) -> int:
        return self.topo.router_id(asn)

    def _announcement_for(self, asn: int, prefix: Prefix) -> Optional[Announcement]:
        for a in self.announcements:
            if a.asn == asn and a.prefix == prefix:
                return a
        return None

    # ---- concept 5: best route ---------------------------------------------------------------
    def _recompute_best(self) -> None:
        for asn in self.topo.ases:
            prefixes = set(self.local[asn]) | set(self.adj_in[asn])
            for p in prefixes:
                cands = list(self.adj_in[asn].get(p, {}).values())
                if p in self.local[asn]:
                    cands.append(self.local[asn][p])
                self.best[asn][p] = select_best(cands, self._nid)

    # ---- export policy (Gao-Rexford) ---------------------------------------------------------
    def _advertised(self) -> Dict[Tuple[int, int, Prefix], Tuple[int, ...]]:
        out: Dict[Tuple[int, int, Prefix], Tuple[int, ...]] = {}
        for asn in self.topo.ases:
            for prefix, route in self.best[asn].items():
                if route is None:
                    continue
                for nbr, rel in self.topo.neighbors(asn):
                    if route.learned_from == nbr:
                        continue                                  # never send a route back to its source
                    if rel != "customer" and not (route.local or route.relationship == "customer"):
                        continue                                  # peers/providers only get customer/own routes
                    if route.local:
                        ann = self._announcement_for(asn, prefix)
                        tail = ann.forged_tail if ann else ()
                        out[(asn, nbr, prefix)] = (asn,) + tail   # forged tail only matters for the attacker
                    else:
                        out[(asn, nbr, prefix)] = (asn,) + route.as_path
        return out

    # ---- concepts 3-4: import processing, acceptance / rejection ------------------------------
    def _import(self, receiver: int, sender: int, prefix: Prefix, path: Tuple[int, ...]) -> bool:
        """Return True if RIB state changed."""
        rel = self.topo.relationship(receiver, sender)
        if receiver in path:
            self.loop_drops += 1
            return self._drop(receiver, sender, prefix)
        state, why, _ = validate_origin(prefix, path[-1], self.roas)
        route = Route(prefix=prefix, as_path=path, learned_from=sender, relationship=rel,
                      local_pref=self.topo.local_pref[rel], rpki_state=state)
        ok, rov_why = rov_decision(state, receiver in self.rov, self.rov_reject_notfound)
        if not ok:
            route.accepted, route.reject_by, route.reject_reason = False, "ROV", f"RPKI {state}: {why}"
        elif receiver in self.path_end:
            pe_ok, pe_why = validate_path_end(path, self.topo.path_end_registry)
            if not pe_ok:
                route.accepted, route.reject_by, route.reject_reason = False, "PATH-END", pe_why
        if route.accepted:
            old = self.adj_in[receiver].get(prefix, {}).get(sender)
            route.arrived_tick = old.arrived_tick if (old and old.as_path == path) else self.tick
            changed = old is None or old.as_path != path
            self.adj_in[receiver].setdefault(prefix, {})[sender] = route
            rej = self.rejected_in[receiver].get(prefix, {})
            changed |= rej.pop(sender, None) is not None
            return changed
        route.arrived_tick = self.tick
        old_rej = self.rejected_in[receiver].get(prefix, {}).get(sender)
        changed = old_rej is None or old_rej.as_path != path
        self.rejected_in[receiver].setdefault(prefix, {})[sender] = route
        changed |= self.adj_in[receiver].get(prefix, {}).pop(sender, None) is not None
        return changed

    def _drop(self, receiver: int, sender: int, prefix: Prefix) -> bool:
        a = self.adj_in[receiver].get(prefix, {}).pop(sender, None)
        r = self.rejected_in[receiver].get(prefix, {}).pop(sender, None)
        return a is not None or r is not None

    # ---- concept 2: propagation loop ---------------------------------------------------------
    def converge(self) -> bool:
        for _ in range(self.max_ticks):
            self.tick += 1
            self._recompute_best()
            new_sent = self._advertised()
            changed = False
            for key in sorted(set(new_sent) | set(self._sent)):
                old, new = self._sent.get(key), new_sent.get(key)
                if old == new:
                    continue
                sender, receiver, prefix = key
                if new is None:
                    changed |= self._drop(receiver, sender, prefix)
                else:
                    changed |= self._import(receiver, sender, prefix, new)
            self._sent = new_sent
            if not changed:
                self._recompute_best()
                self.converged_at = self.tick
                return True
        self._recompute_best()
        return False

    # ---- read-only helpers -------------------------------------------------------------------
    def best_route(self, asn: int, prefix: Prefix) -> Optional[Route]:
        return self.best[asn].get(prefix)

    def all_candidates(self, asn: int, prefix: Prefix) -> List[Route]:
        return list(self.adj_in[asn].get(prefix, {}).values())

    def rejected(self, asn: int, prefix: Prefix) -> List[Route]:
        return list(self.rejected_in[asn].get(prefix, {}).values())
