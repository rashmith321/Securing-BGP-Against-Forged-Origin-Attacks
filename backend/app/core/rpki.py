"""Simplified RPKI Route Origin Validation (concept 3), following RFC 6811 semantics.

VALID    : at least one ROA covers the prefix, the ROA's origin equals the route's claimed
           origin, and prefix length <= ROA max_length.
INVALID  : at least one ROA covers the prefix, but no covering ROA matches (wrong origin
           and/or prefix longer than max_length).
NOTFOUND : no ROA covers the prefix.
ROV policy (rov_reject_notfound=False by default, as in the guide): reject Invalid only.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .routes import STATE_INVALID, STATE_NOTFOUND, STATE_VALID


@dataclass(frozen=True)
class ROA:
    prefix: str
    origin: int
    max_length: int

    def to_dict(self) -> dict:
        return {"prefix": self.prefix, "origin": self.origin, "max_length": self.max_length}


def roas_from_dicts(items: List[dict]) -> List[ROA]:
    return [ROA(i["prefix"], int(i["origin"]), int(i["max_length"])) for i in items]


def covers(roa: ROA, prefix: str) -> bool:
    net = ipaddress.ip_network(prefix, strict=True)
    roa_net = ipaddress.ip_network(roa.prefix, strict=True)
    return net.version == roa_net.version and net.subnet_of(roa_net)


def validate_origin(prefix: str, claimed_origin: int, roas: List[ROA]) -> Tuple[str, str, List[dict]]:
    """Return (state, explanation, applicable_roas)."""
    net = ipaddress.ip_network(prefix, strict=True)
    covering = [r for r in roas if covers(r, prefix)]
    applicable = [r.to_dict() for r in covering]
    if not covering:
        return STATE_NOTFOUND, f"No ROA covers {prefix}.", applicable
    for r in covering:
        if r.origin == claimed_origin and net.prefixlen <= r.max_length:
            return (
                STATE_VALID,
                f"ROA {r.prefix} max /{r.max_length} authorises AS{r.origin}; the route's claimed origin is "
                f"AS{claimed_origin} and its length /{net.prefixlen} is allowed.",
                applicable,
            )
    reasons = []
    for r in covering:
        if r.origin != claimed_origin:
            reasons.append(f"claimed origin AS{claimed_origin} != ROA origin AS{r.origin}")
        if net.prefixlen > r.max_length:
            reasons.append(f"/{net.prefixlen} is longer than ROA max length /{r.max_length}")
    return STATE_INVALID, "Covered by a ROA but not authorised: " + "; ".join(reasons) + ".", applicable


def rov_decision(state: str, rov_enabled: bool, reject_notfound: bool = False) -> Tuple[bool, str]:
    """(accepted, explanation) for a receiving AS."""
    if not rov_enabled:
        return True, "ROV not enabled at this AS: route is not filtered on RPKI state."
    if state == STATE_INVALID:
        return False, "ROV enabled and route is RPKI Invalid: rejected."
    if state == STATE_NOTFOUND and reject_notfound:
        return False, "ROV enabled, policy rejects NotFound: rejected."
    return True, f"ROV enabled; RPKI {state} is accepted by the configured policy."
