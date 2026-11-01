"""Explainable risk score for one detection finding.

The score is an integer from 0 through 100. It is a project heuristic. It is
not a probability that an account was compromised, and the bands are not an
industry standard.

Bands:

- 0–20 LOW
- 21–50 MEDIUM
- 51–75 HIGH
- 76–100 CRITICAL

Base points come from the severity the rule already chose, so the base itself
lands in that severity's band:

| Severity | Base | Band |
| --- | --- | --- |
| INFO | 10 | LOW |
| LOW | 15 | LOW |
| MEDIUM | 35 | MEDIUM |
| HIGH | 65 | HIGH |
| CRITICAL | 85 | CRITICAL |

``CRITICAL`` is on the scale. No current detection rule emits it, and
registration rejects a rule that declares it. An ordinary finding therefore
stays at or below 75.

Two capped extras may be added.

- Failures above the threshold: 2 points each, capped at 8. This term is used
  only when the rule counts failures, which is ``brute-force-same-account``
  and ``success-after-failures``. Password spraying and the distributed
  heuristic count usernames in ``observed_count``. They do not receive this
  term, so those usernames are not scored once as failures and again as
  accounts.
- Affected accounts: 1 point per distinct account named on the finding,
  capped at 6. The term is omitted when the finding names no account.
  A username listed both as ``affected_username`` and inside
  ``affected_usernames`` counts once.

There is no success-after-failure bonus. A brute-force finding keeps the
MEDIUM base its rule chose. A success-after-failures finding scores higher
only because that rule already chose HIGH. An unfamiliar source address adds
nothing. The total is capped at the top of the severity band (and at 100),
so a single MEDIUM finding stays inside 21–50 and a single HIGH finding stays
inside 51–75. The listed points are the points actually awarded, and they
sum to the score.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

from loginguard.detection.finding import Finding, Severity

_BASE_POINTS = {
    Severity.INFO: 10,
    Severity.LOW: 15,
    Severity.MEDIUM: 35,
    Severity.HIGH: 65,
    Severity.CRITICAL: 85,
}

_BAND_CEILING = {
    Severity.INFO: 20,
    Severity.LOW: 20,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 100,
}

_FAILURE_COUNT_RULES = frozenset(
    {
        "brute-force-same-account",
        "success-after-failures",
    }
)

_POINTS_PER_EXTRA_FAILURE = 2
_MAX_FAILURE_EXTRA_POINTS = 8
_POINTS_PER_ACCOUNT = 1
_MAX_ACCOUNT_POINTS = 6

_SEVERITY_BAND_TEXT = {
    Severity.INFO: "0–20",
    Severity.LOW: "0–20",
    Severity.MEDIUM: "21–50",
    Severity.HIGH: "51–75",
    Severity.CRITICAL: "76–100",
}


class RiskBand(StrEnum):
    """Project band for a 0–100 heuristic score.

    These names match the words used for finding severity. They are not a
    second detection result. A MEDIUM finding is built to score inside the
    MEDIUM band. ``CRITICAL`` is part of the scale and is unused by current
    rules.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskScoreError(ValueError):
    """Raised when a score cannot be placed on the 0–100 scale."""


@dataclass(frozen=True, slots=True)
class ScoreComponent:
    """One term in a risk score.

    ``points`` is the amount actually awarded. The components of one score
    sum to that score.
    """

    code: str
    points: int
    reason: str


@dataclass(frozen=True, slots=True)
class RiskScore:
    """A bounded, explainable score for one finding."""

    score: int
    band: RiskBand
    components: tuple[ScoreComponent, ...]
    explanation: str

    def __post_init__(self) -> None:
        if isinstance(self.score, bool) or not isinstance(self.score, int):
            raise RiskScoreError("score must be an integer from 0 through 100")
        if self.score < 0 or self.score > 100:
            raise RiskScoreError("score must be an integer from 0 through 100")
        total = 0
        for component in self.components:
            if isinstance(component.points, bool) or not isinstance(component.points, int):
                raise RiskScoreError("component points must be a non-negative integer")
            if component.points < 0:
                raise RiskScoreError("component points must be a non-negative integer")
            total += component.points
        if total != self.score:
            raise RiskScoreError("risk score breakdown does not sum to the score")
        if band_for_score(self.score) is not self.band:
            raise RiskScoreError("risk band does not match the score")
        if not isinstance(self.explanation, str) or "not a probability" not in self.explanation:
            raise RiskScoreError("explanation must state that the score is not a probability")


def band_for_score(score: int) -> RiskBand:
    """Return the project band for ``score``.

    Boundaries are inclusive on the low side of the next band: 20 is LOW,
    21 is MEDIUM, 50 is MEDIUM, 51 is HIGH, 75 is HIGH, and 76 is CRITICAL.

    Raises:
        RiskScoreError: ``score`` is not an integer from 0 through 100.
    """
    if isinstance(score, bool) or not isinstance(score, int):
        raise RiskScoreError("score must be an integer from 0 through 100")
    if score < 0 or score > 100:
        raise RiskScoreError("score must be an integer from 0 through 100")
    if score <= 20:
        return RiskBand.LOW
    if score <= 50:
        return RiskBand.MEDIUM
    if score <= 75:
        return RiskBand.HIGH
    return RiskBand.CRITICAL


def score_finding(finding: Finding, *, unfamiliar_ip: bool = False) -> RiskScore:
    """Score one finding.

    ``unfamiliar_ip`` is accepted and ignored. An address that has not been
    seen before is not evidence in this project, and it does not change the
    score. The source address stored on the finding does not add points either.

    The result is deterministic. This function does not read the clock and
    does not use the network.

    Raises:
        TypeError: ``finding`` is not a ``Finding``, or ``unfamiliar_ip``
            is not a bool.
    """
    if not isinstance(finding, Finding):
        raise TypeError("score_finding expects a Finding")
    if not isinstance(unfamiliar_ip, bool):
        raise TypeError("unfamiliar_ip must be a bool")

    severity = finding.severity
    room = _BAND_CEILING[severity] - _BASE_POINTS[severity]
    components = [_severity_component(severity)]

    failure_points, failure_reason = _failure_extra(finding)
    if failure_points > 0:
        awarded = min(failure_points, room)
        room -= awarded
        components.append(
            ScoreComponent(
                "failures_above_threshold",
                awarded,
                _awarded_reason(failure_reason, awarded, failure_points),
            )
        )

    account_points, account_reason = _account_extra(finding)
    if account_points > 0:
        awarded = min(account_points, room)
        room -= awarded
        components.append(
            ScoreComponent(
                "affected_accounts",
                awarded,
                _awarded_reason(account_reason, awarded, account_points),
            )
        )

    awarded_components = tuple(components)
    score = sum(component.points for component in awarded_components)
    band = band_for_score(score)
    return RiskScore(
        score=score,
        band=band,
        components=awarded_components,
        explanation=_explanation(finding, score, band, awarded_components),
    )


def _severity_component(severity: Severity) -> ScoreComponent:
    points = _BASE_POINTS[severity]
    reason = (
        f"Base points for severity {severity.value}. "
        f"A {severity.value} finding starts inside {_SEVERITY_BAND_TEXT[severity]}."
    )
    if severity is Severity.CRITICAL:
        reason += " No current detection rule emits CRITICAL."
    return ScoreComponent("severity", points, reason)


def _failure_extra(finding: Finding) -> tuple[int, str]:
    """Return capped points for failures above the threshold, or (0, "").

    Username-count rules are skipped so the same accounts are not scored
    again as if they were extra failures. Brute force does not receive a
    success bonus here; only failures above its own threshold are counted.
    """
    if finding.rule_id not in _FAILURE_COUNT_RULES:
        return 0, ""
    extra = finding.observed_count - finding.threshold
    if extra <= 0:
        return 0, ""
    raw = extra * _POINTS_PER_EXTRA_FAILURE
    points = min(raw, _MAX_FAILURE_EXTRA_POINTS)
    unit = "failure" if extra == 1 else "failures"
    reason = (
        f"{extra} {unit} above the threshold of {finding.threshold}, "
        f"at {_POINTS_PER_EXTRA_FAILURE} points each, "
        f"capped at {_MAX_FAILURE_EXTRA_POINTS}"
    )
    return points, reason


def _account_extra(finding: Finding) -> tuple[int, str]:
    """Return capped points for accounts named on the finding, or (0, "")."""
    count = _distinct_account_count(finding)
    if count == 0:
        return 0, ""
    raw = count * _POINTS_PER_ACCOUNT
    points = min(raw, _MAX_ACCOUNT_POINTS)
    unit = "account" if count == 1 else "accounts"
    reason = (
        f"{count} distinct {unit} named on the finding, "
        f"at {_POINTS_PER_ACCOUNT} point each, capped at {_MAX_ACCOUNT_POINTS}. "
        "Points are added only when the finding names an account"
    )
    return points, reason


def _awarded_reason(reason: str, awarded: int, requested: int) -> str:
    if awarded == requested:
        return f"{reason}. Awarded {awarded}"
    return f"{reason}. Awarded {awarded} so the finding stays inside its severity band"


def _distinct_account_count(finding: Finding) -> int:
    seen: set[str] = set()
    if finding.affected_username is not None:
        seen.add(finding.affected_username)
    for username in finding.affected_usernames:
        seen.add(username)
    return len(seen)


def _explanation(
    finding: Finding,
    score: int,
    band: RiskBand,
    components: tuple[ScoreComponent, ...],
) -> str:
    breakdown = "; ".join(
        f"{component.code} {component.points} ({component.reason})" for component in components
    )
    return (
        f"Score {score} of 100 is in the {band.value} band. "
        f"Rule {finding.rule_id} observed {finding.observed_count} "
        f"against a threshold of {finding.threshold} inside {_format_window(finding.window)}. "
        "This score is a project heuristic, not a probability of compromise, "
        "and the bands are not an industry standard. "
        f"Breakdown: {breakdown}."
    )


def _format_window(window: timedelta) -> str:
    total = window.total_seconds()
    if total.is_integer():
        seconds = int(total)
        if seconds % 3600 == 0:
            hours = seconds // 3600
            unit = "hour" if hours == 1 else "hours"
            return f"{hours} {unit}"
        if seconds % 60 == 0:
            minutes = seconds // 60
            unit = "minute" if minutes == 1 else "minutes"
            return f"{minutes} {unit}"
        unit = "second" if seconds == 1 else "seconds"
        return f"{seconds} {unit}"
    return f"{total:g} seconds"
