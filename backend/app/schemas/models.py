"""Pydantic request schemas (validation happens here; logic lives in core/ and experiments/)."""
from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from ..core.topology import load_topology


def _measured() -> set:
    return set(load_topology().measured)


def _check_asns(xs: Optional[List[int]], field: str) -> Optional[List[int]]:
    if xs is None:
        return xs
    bad = sorted(set(xs) - _measured())
    if bad:
        raise ValueError(f"{field}: {bad} are not measured ASes {sorted(_measured())}")
    if len(set(xs)) != len(xs):
        raise ValueError(f"{field}: duplicate ASNs")
    return xs


class ROAIn(BaseModel):
    prefix: str = Field(examples=["10.10.0.0/24"])
    origin: int = Field(ge=1, le=4294967295)
    max_length: int = Field(ge=0, le=32)

    @field_validator("prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=True)
        except ValueError as e:
            raise ValueError(f"invalid prefix: {e}")
        return v


class SetPolicy(BaseModel):
    """How adopter sets are chosen for each adoption count k (the documented aggregation policy)."""
    mode: Literal["all", "sample", "order", "explicit"] = "all"
    max_sets: Optional[int] = Field(default=None, ge=1, le=64)
    seed: int = 1
    order: Optional[List[int]] = None
    explicit: Optional[List[int]] = None

    @field_validator("order")
    @classmethod
    def _o(cls, v):
        return _check_asns(v, "order")

    @field_validator("explicit")
    @classmethod
    def _e(cls, v):
        return _check_asns(v, "explicit")

    @model_validator(mode="after")
    def _need(self):
        if self.mode == "order" and not self.order:
            raise ValueError("mode 'order' requires 'order' (all six measured ASes)")
        if self.mode == "explicit" and self.explicit is None:
            raise ValueError("mode 'explicit' requires 'explicit'")
        return self


class SimulateRequest(BaseModel):
    attack: Literal["none", "type0", "type1", "subprefix"] = "type1"
    rov_set: List[int] = Field(default_factory=list)
    path_end_set: List[int] = Field(default_factory=list)
    roas: Optional[List[ROAIn]] = None
    rov_reject_notfound: bool = False
    require_healthy_baseline: bool = True
    save: bool = True

    @field_validator("rov_set")
    @classmethod
    def _r(cls, v):
        return _check_asns(v, "rov_set")

    @field_validator("path_end_set")
    @classmethod
    def _p(cls, v):
        return _check_asns(v, "path_end_set")


class AttackComparisonRequest(BaseModel):
    rov_set: Optional[List[int]] = None            # None => all measured ASes
    path_end_set: List[int] = Field(default_factory=list)
    require_healthy_baseline: bool = True

    @field_validator("rov_set")
    @classmethod
    def _r(cls, v):
        return _check_asns(v, "rov_set")

    @field_validator("path_end_set")
    @classmethod
    def _p(cls, v):
        return _check_asns(v, "path_end_set")


class RovAdoptionRequest(BaseModel):
    policy: SetPolicy = Field(default_factory=SetPolicy)
    attacks: List[Literal["type0", "type1"]] = ["type0", "type1"]
    require_healthy_baseline: bool = True


class PlacementRequest(BaseModel):
    experiments: List[Literal["type0_rov", "type1_rov", "type1_pathend"]] = ["type0_rov", "type1_rov", "type1_pathend"]
    policy: SetPolicy = Field(default_factory=SetPolicy)
    rov_base: Optional[List[int]] = None            # ROV set used underneath the path-end placement study
    require_healthy_baseline: bool = True

    @field_validator("rov_base")
    @classmethod
    def _r(cls, v):
        return _check_asns(v, "rov_base")


class PathEndRequest(BaseModel):
    policy: SetPolicy = Field(default_factory=SetPolicy)
    rov_set: Optional[List[int]] = None            # None => ROV at all measured ASes (guide default)
    require_healthy_baseline: bool = True

    @field_validator("rov_set")
    @classmethod
    def _r(cls, v):
        return _check_asns(v, "rov_set")


class SuiteRequest(BaseModel):
    policy: SetPolicy = Field(default_factory=SetPolicy)
    include_subprefix: bool = True
    require_healthy_baseline: bool = True
