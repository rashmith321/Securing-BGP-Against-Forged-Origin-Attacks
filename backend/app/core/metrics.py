"""Experiment metrics (concept 7). Formulas follow the guide, section 2.4 / 2.5."""
from __future__ import annotations

import math
from typing import Dict, Iterable, List, Optional, Sequence


def diversion_rate(diverted: int, measured: int) -> float:
    return diverted / measured if measured else 0.0


def pct(x: float) -> float:
    return round(100.0 * x, 4)


def protection_pp(d0: float, dk: float) -> float:
    """100 x (D(0) - D(k)): percentage points of diversion removed."""
    return 100.0 * (d0 - dk)


def relative_reduction(d0: float, dk: float) -> Optional[float]:
    """(D(0)-D(k))/D(0); None when D(0)=0 (comparison meaningless)."""
    return None if d0 == 0 else (d0 - dk) / d0


def marginal_gain_pp(d_prev: float, d_k: float) -> float:
    """100 x (D(k-1) - D(k)): what the k-th adopter added (on average)."""
    return 100.0 * (d_prev - d_k)


def mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def sd(xs: Sequence[float]) -> float:
    """Sample standard deviation (n-1), 0 for n<2 (matches pandas .std() filled with 0)."""
    n = len(xs)
    if n < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1))


def placement_effect_pp(d_lo_p: float, d_hi_p: float) -> float:
    """E(k) = 100 x (D(k,p_min) - D(k,p_max)); positive => more attacker providers adopting reduces diversion."""
    return 100.0 * (d_lo_p - d_hi_p)
