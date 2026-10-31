"""Simplified ASPA-style *path-end* validation (educational model, NOT standards-compliant ASPA).

Rule (mirrors the PE-BAD AS-path filter in the guide's topo.py): for a route whose claimed origin
V has a registered upstream list U(V):
  * path == [V]                      -> OK  (received straight from V)
  * path[-2] in U(V)                 -> OK  (last hop before the origin is an authorised upstream)
  * otherwise                        -> INVALID: that neighbour of V is not authorised to precede it.
Routes whose origin has no registry entry are not evaluated (OK, "not covered").
Only the AS immediately preceding the claimed origin is checked; earlier hops are not.
"""
from __future__ import annotations

from typing import Dict, List, Sequence, Tuple


def validate_path_end(as_path: Sequence[int], registry: Dict[int, List[int]]) -> Tuple[bool, str]:
    """Return (ok, explanation)."""
    if not as_path:
        return True, "Empty path (locally originated)."
    origin = as_path[-1]
    if origin not in registry:
        return True, f"AS{origin} has no path-end record: not evaluated."
    allowed = registry[origin]
    if len(as_path) == 1:
        return True, f"Route received directly from origin AS{origin}."
    prev = as_path[-2]
    allowed_s = ", ".join(f"AS{a}" for a in allowed)
    if prev in allowed:
        return True, f"AS{prev} is an authorised upstream of AS{origin} (record: {allowed_s})."
    return False, (
        f"AS{prev} directly precedes claimed origin AS{origin} but is not in AS{origin}'s authorised "
        f"upstream record ({allowed_s}): forged or unauthorised path end."
    )
