"""Route representation (concept 1: advertisement).

Path convention (same as BGP / the guide's FRR output): `as_path` is listed from the most recent
AS to the origin, so as_path[0] is the neighbour that sent the route and as_path[-1] is the
*claimed origin*.  A Type-1 forged route from AS65800 therefore reads [65800, 65700] when it
leaves the attacker: the real originator is 65800 but the claimed origin is 65700.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

STATE_VALID = "Valid"
STATE_INVALID = "Invalid"
STATE_NOTFOUND = "NotFound"


@dataclass
class Route:
    prefix: str
    as_path: Tuple[int, ...]          # path as received (receiver's own ASN not yet prepended)
    learned_from: Optional[int]       # neighbour ASN, None for locally originated
    relationship: Optional[str]       # customer | peer | provider, None for local
    local_pref: int = 100
    arrived_tick: int = 0             # logical time the route (this exact path) first arrived
    rpki_state: str = STATE_NOTFOUND
    accepted: bool = True
    reject_reason: Optional[str] = None
    reject_by: Optional[str] = None   # "ROV" | "PATH-END" | "LOOP"
    local: bool = False               # locally originated at this AS

    @property
    def origin(self) -> int:
        return self.as_path[-1]

    @property
    def length(self) -> int:
        return len(self.as_path)

    def path_str(self) -> str:
        return " ".join(str(a) for a in self.as_path) if self.as_path else "(local)"

    def to_dict(self) -> dict:
        return {
            "prefix": self.prefix,
            "as_path": list(self.as_path),
            "path": self.path_str(),
            "claimed_origin": self.origin if self.as_path else None,
            "learned_from": self.learned_from,
            "relationship": self.relationship,
            "local_pref": self.local_pref,
            "rpki_state": self.rpki_state,
            "accepted": self.accepted,
            "reject_reason": self.reject_reason,
            "reject_by": self.reject_by,
            "local": self.local,
        }
