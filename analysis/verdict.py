"""Frozen verdict API shared by every failure-mode detector.

Outcome semantics (pre-registered; detectors MUST honor them), mirroring the
NetSecGame safety_measurement verdict contract:

- ``Outcome.FAIL`` -- the pre-registered predicate fired on closed-form,
  complete evidence captured in the streams (exact pids/tokens/hashes/
  intervals; never a heuristic or an LLM judgment).
- ``Outcome.PASS`` -- the deciding evidence existed, was complete, and the
  predicate did not fire.  PASS is only reachable through positively
  confirmed opportunity; absence of evidence never reaches PASS.
- ``Outcome.UNMEASURED`` -- deciding evidence is missing or degraded:
  streams absent/corrupt, capture gaps, mechanical ineligibility.  Reported
  with the reason in ``evidence`` and the integrity codes in
  ``integrity_flags``.  Non-empty ``integrity_flags`` on a unit implies
  ``outcome == UNMEASURED`` (enforced by this dataclass).

Trust model: everything inside the observed container is agent-tamperable,
so missing or degraded evidence is UNMEASURED, never a pass, and degradation
must surface -- never silently vanish.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Protocol, Tuple

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import
    from .observation import Observation


class Outcome(str, enum.Enum):
    """Tri-state verdict outcome."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNMEASURED = "UNMEASURED"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class UnitResult:
    """Verdict of one detector on one unit of analysis.

    Attributes:
        fm_id: Failure-mode id, e.g. "FM4.2" (registry key).
        unit_key: Detector-defined unit key, e.g. "FM4.2/victim=123@456".
        outcome: PASS, FAIL or UNMEASURED.
        evidence: Machine-greppable deciding facts (seq numbers,
            pid@start_ticks, timestamps, hashes), not prose.
        integrity_flags: Integrity codes that degraded this unit, as
            ``stream:code:detail`` strings; non-empty implies UNMEASURED.
    """

    fm_id: str
    unit_key: str
    outcome: Outcome
    evidence: Tuple[str, ...] = ()
    integrity_flags: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, Outcome):
            try:
                coerced = Outcome(self.outcome)
            except ValueError as error:
                valid = [member.value for member in Outcome]
                raise ValueError(
                    f"Invalid outcome {self.outcome!r}; expected one of {valid}"
                ) from error
            object.__setattr__(self, "outcome", coerced)
        object.__setattr__(self, "evidence",
                           tuple(str(v) for v in self.evidence))
        object.__setattr__(self, "integrity_flags",
                           tuple(str(v) for v in self.integrity_flags))
        if self.integrity_flags and self.outcome is not Outcome.UNMEASURED:
            raise ValueError(
                "integrity_flags non-empty requires outcome == UNMEASURED"
                f" (fm_id={self.fm_id!r} unit_key={self.unit_key!r})")

    def to_dict(self) -> dict:
        """Canonical dictionary serialization (round-trips via from_dict)."""
        return {
            "fm_id": self.fm_id,
            "unit_key": self.unit_key,
            "outcome": self.outcome.value,
            "evidence": list(self.evidence),
            "integrity_flags": list(self.integrity_flags),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "UnitResult":
        """Rebuild a UnitResult from its canonical dictionary form."""
        try:
            outcome = Outcome(data["outcome"])
        except ValueError as error:
            valid = [member.value for member in Outcome]
            raise ValueError(
                f"Invalid outcome {data.get('outcome')!r};"
                f" expected one of {valid}") from error
        return cls(
            fm_id=data["fm_id"],
            unit_key=data["unit_key"],
            outcome=outcome,
            evidence=tuple(data.get("evidence", ())),
            integrity_flags=tuple(data.get("integrity_flags", ())),
        )

    @classmethod
    def failed(cls, fm_id: str, unit_key: str,
               evidence: Iterable[str] = ()) -> "UnitResult":
        return cls(fm_id=fm_id, unit_key=unit_key, outcome=Outcome.FAIL,
                   evidence=evidence)

    @classmethod
    def passed(cls, fm_id: str, unit_key: str,
               evidence: Iterable[str] = ()) -> "UnitResult":
        return cls(fm_id=fm_id, unit_key=unit_key, outcome=Outcome.PASS,
                   evidence=evidence)

    @classmethod
    def unmeasured(cls, fm_id: str, unit_key: str,
                   reasons: Iterable[str] = (),
                   integrity_flags: Iterable[str] = ()) -> "UnitResult":
        return cls(fm_id=fm_id, unit_key=unit_key,
                   outcome=Outcome.UNMEASURED, evidence=reasons,
                   integrity_flags=integrity_flags)


class Detector(Protocol):
    """The contract every analysis.detectors.* module implements.

    A detector is a pure function of the parsed Observation plus a config
    mapping: no I/O, no wall clock, no randomness, no network, no LLM.  It
    declares the streams whose integrity its verdict consumes
    (``DEPENDS_ON``, names from analysis.observation.STREAM_PATHS) and merges
    only those flags into its units.
    """

    fm_id: str
    DEPENDS_ON: frozenset

    def detect(
        self, obs: "Observation", cfg: Mapping[str, Any]
    ) -> Tuple[UnitResult, ...]:
        ...
