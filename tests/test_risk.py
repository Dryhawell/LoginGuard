"""Bounded risk scores for one finding at a time.

Times are fixed. Nothing in this module reads the clock or the network.
The score is a project heuristic, not a probability.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginguard.detection import Severity, build_default_engine
from loginguard.detection.brute_force import RULE_ID as BRUTE_FORCE_RULE_ID
from loginguard.detection.finding import Finding
from loginguard.ingestion import parse_jsonl
from loginguard.risk import RiskBand, RiskScoreError, band_for_score, score_finding

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "auth_logs.jsonl"
_START = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
_END = datetime(2026, 9, 10, 10, 4, tzinfo=timezone.utc)


def _finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "finding_id": "finding-1",
        "rule_id": BRUTE_FORCE_RULE_ID,
        "title": "Repeated failed logins",
        "severity": Severity.MEDIUM,
        "description": (
            "Observed 5 LOGIN_FAILURE events. Threshold is 5 failures inside "
            "5 minutes. This is a suspicion, not proof of an attack."
        ),
        "recommendation": "Review the account activity with the owner.",
        "observed_count": 5,
        "threshold": 5,
        "window": timedelta(minutes=5),
        "related_event_ids": ("evt-1",),
        "first_event_time": _START,
        "last_event_time": _END,
        "affected_username": None,
        "affected_usernames": (),
        "source_ip": None,
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def _points(scored: object, code: str) -> int:
    from loginguard.risk import RiskScore

    assert isinstance(scored, RiskScore)
    matches = [component.points for component in scored.components if component.code == code]
    assert len(matches) == 1
    return matches[0]


def test_explanation_names_the_rule_and_is_not_a_probability() -> None:
    scored = score_finding(_finding(observed_count=6, affected_username="alice"))

    assert "not a probability" in scored.explanation
    assert "not an industry standard" in scored.explanation
    assert "brute-force-same-account" in scored.explanation
    assert "observed 6" in scored.explanation
    assert "threshold of 5" in scored.explanation
    assert "inside 5 minutes" in scored.explanation
    assert "Breakdown:" in scored.explanation
    assert sum(component.points for component in scored.components) == scored.score


@pytest.mark.parametrize(
    ("severity", "expected_score", "expected_band"),
    [
        (Severity.INFO, 10, RiskBand.LOW),
        (Severity.LOW, 15, RiskBand.LOW),
        (Severity.MEDIUM, 35, RiskBand.MEDIUM),
        (Severity.HIGH, 65, RiskBand.HIGH),
        (Severity.CRITICAL, 85, RiskBand.CRITICAL),
    ],
)
def test_severity_base_lands_in_its_band(
    severity: Severity,
    expected_score: int,
    expected_band: RiskBand,
) -> None:
    scored = score_finding(
        _finding(rule_id="test.no-extras", severity=severity, observed_count=5, threshold=5)
    )

    assert scored.score == expected_score
    assert scored.band is expected_band
    assert [component.code for component in scored.components] == ["severity"]
    assert scored.score == sum(component.points for component in scored.components)
    if severity is not Severity.CRITICAL:
        assert scored.score < 76
    else:
        assert "No current detection rule emits CRITICAL." in scored.components[0].reason


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0, RiskBand.LOW),
        (20, RiskBand.LOW),
        (21, RiskBand.MEDIUM),
        (50, RiskBand.MEDIUM),
        (51, RiskBand.HIGH),
        (75, RiskBand.HIGH),
        (76, RiskBand.CRITICAL),
        (100, RiskBand.CRITICAL),
    ],
)
def test_band_boundaries(score: int, band: RiskBand) -> None:
    assert band_for_score(score) is band


def test_band_rejects_values_outside_the_scale() -> None:
    with pytest.raises(RiskScoreError):
        band_for_score(-1)
    with pytest.raises(RiskScoreError):
        band_for_score(101)
    with pytest.raises(RiskScoreError):
        band_for_score(True)  # type: ignore[arg-type]


def test_breakdown_sums_to_the_score_for_each_extra() -> None:
    scored = score_finding(
        _finding(observed_count=8, threshold=5, affected_username="alice")
    )

    assert _points(scored, "severity") == 35
    assert _points(scored, "failures_above_threshold") == 6
    assert _points(scored, "affected_accounts") == 1
    assert scored.score == 42
    assert scored.band is RiskBand.MEDIUM
    assert scored.score == sum(component.points for component in scored.components)


def test_only_failures_above_the_threshold_are_scored() -> None:
    exact = score_finding(_finding(observed_count=5, threshold=5, affected_username="alice"))
    one_over = score_finding(_finding(observed_count=6, threshold=5, affected_username="alice"))
    many_over = score_finding(_finding(observed_count=40, threshold=5, affected_username="alice"))

    assert "failures_above_threshold" not in {component.code for component in exact.components}
    assert _points(one_over, "failures_above_threshold") == 2
    assert _points(many_over, "failures_above_threshold") == 8
    assert many_over.score == 35 + 8 + 1


def test_spray_does_not_score_usernames_as_extra_failures() -> None:
    names = ("ann", "bob", "cara", "dina", "erik", "fay")
    scored = score_finding(
        _finding(
            rule_id="password-spray-distinct-usernames",
            title="Failures across distinct usernames",
            observed_count=6,
            threshold=5,
            window=timedelta(minutes=10),
            affected_username=None,
            affected_usernames=names,
            source_ip="203.0.113.50",
        )
    )

    codes = [component.code for component in scored.components]
    assert codes == ["severity", "affected_accounts"]
    assert _points(scored, "severity") == 35
    assert _points(scored, "affected_accounts") == 6
    assert scored.score == 41
    assert scored.band is RiskBand.MEDIUM


def test_repeated_username_counts_once_and_missing_accounts_add_nothing() -> None:
    repeated = score_finding(
        _finding(
            affected_username="alice",
            affected_usernames=("alice", "bob"),
        )
    )
    unnamed = score_finding(_finding())

    assert _points(repeated, "affected_accounts") == 2
    assert "affected_accounts" not in {component.code for component in unnamed.components}
    assert unnamed.score == 35


def test_brute_force_does_not_receive_success_points() -> None:
    description = (
        "Successful login after repeated failures. Observed 8 LOGIN_FAILURE events. "
        "Threshold is 5 failures inside 5 minutes. This is a suspicion, not proof of an attack."
    )
    brute = score_finding(
        _finding(
            rule_id=BRUTE_FORCE_RULE_ID,
            severity=Severity.MEDIUM,
            description=description,
            observed_count=8,
            threshold=5,
            affected_username="alice",
        )
    )
    same_counts_on_the_success_rule = score_finding(
        _finding(
            rule_id="success-after-failures",
            severity=Severity.MEDIUM,
            title="Successful login after repeated failures",
            description=description,
            observed_count=8,
            threshold=5,
            affected_username="alice",
        )
    )
    high_success = score_finding(
        _finding(
            rule_id="success-after-failures",
            severity=Severity.HIGH,
            title="Successful login after repeated failures",
            description=description,
            observed_count=8,
            threshold=5,
            affected_username="alice",
        )
    )

    assert "success" not in {component.code for component in brute.components}
    assert [component.code for component in brute.components] == [
        component.code for component in same_counts_on_the_success_rule.components
    ]
    assert [component.points for component in brute.components] == [
        component.points for component in same_counts_on_the_success_rule.components
    ]
    assert brute.score == same_counts_on_the_success_rule.score
    assert high_success.score - brute.score == 65 - 35
    assert brute.band is RiskBand.MEDIUM
    assert high_success.band is RiskBand.HIGH
    assert brute.score < 76
    assert high_success.score < 76


def test_unfamiliar_ip_and_stored_source_address_add_nothing() -> None:
    named = _finding(observed_count=6, affected_username="alice", source_ip="192.0.2.10")
    without_address = _finding(observed_count=6, affected_username="alice", source_ip=None)

    familiar = score_finding(named, unfamiliar_ip=False)
    unfamiliar = score_finding(named, unfamiliar_ip=True)
    no_address = score_finding(without_address, unfamiliar_ip=True)

    assert familiar == unfamiliar == no_address
    assert "unfamiliar" not in {component.code for component in familiar.components}
    joined = " ".join(component.reason for component in familiar.components)
    assert "192.0.2.10" not in joined
    assert "alice" not in joined


def test_ordinary_findings_stay_inside_their_band_and_below_76() -> None:
    medium = score_finding(
        _finding(
            observed_count=100,
            threshold=5,
            affected_username="alice",
            affected_usernames=tuple(f"user-{index}" for index in range(20)),
        )
    )
    high = score_finding(
        _finding(
            rule_id="success-after-failures",
            severity=Severity.HIGH,
            title="Successful login after repeated failures",
            observed_count=100,
            threshold=5,
            affected_username="nora",
            affected_usernames=tuple(f"user-{index}" for index in range(20)),
        )
    )
    low = score_finding(
        _finding(
            rule_id="distributed-failure-heuristic",
            severity=Severity.LOW,
            title="Distributed authentication failures",
            observed_count=12,
            threshold=5,
            window=timedelta(minutes=15),
            affected_usernames=tuple(f"user-{index}" for index in range(12)),
        )
    )

    assert 21 <= medium.score <= 50
    assert medium.band is RiskBand.MEDIUM
    assert 51 <= high.score <= 75
    assert high.band is RiskBand.HIGH
    assert high.score < 76
    assert 0 <= low.score <= 20
    assert low.band is RiskBand.LOW
    assert low.score == 20
    for scored in (medium, high, low):
        assert scored.score == sum(component.points for component in scored.components)
        assert scored.score <= 100


def test_same_finding_scores_the_same_result_twice() -> None:
    finding = _finding(observed_count=7, affected_username="alice", source_ip="198.51.100.20")

    assert score_finding(finding) == score_finding(finding)


def test_sample_findings_stay_below_the_critical_band() -> None:
    findings = build_default_engine().run(parse_jsonl(_SAMPLE).events)
    bands = {
        Severity.LOW: RiskBand.LOW,
        Severity.MEDIUM: RiskBand.MEDIUM,
        Severity.HIGH: RiskBand.HIGH,
    }

    assert findings
    for finding in findings:
        assert finding.severity is not Severity.CRITICAL
        scored = score_finding(finding)
        again = score_finding(finding, unfamiliar_ip=True)
        assert scored == again
        assert scored.score == sum(component.points for component in scored.components)
        assert scored.score < 76
        assert scored.band is bands[finding.severity]
        assert "not a probability" in scored.explanation
        assert finding.rule_id in scored.explanation
