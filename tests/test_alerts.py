"""Alerts built from findings.

Times are fixed. Nothing in this module reads the clock or the network.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginguard.detection import Severity, build_default_engine
from loginguard.detection.finding import Finding
from loginguard.ingestion import parse_jsonl
from loginguard.models import (
    Alert,
    AlertStatus,
    AlertValidationError,
    alert_from_finding,
    alerts_from_findings,
)

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "auth_logs.jsonl"
_START = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
_END = datetime(2026, 9, 10, 10, 4, tzinfo=timezone.utc)


def _finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "finding_id": "finding-1",
        "rule_id": "brute-force-same-account",
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
        "related_event_ids": ("evt-1", "evt-2"),
        "first_event_time": _START,
        "last_event_time": _END,
        "affected_username": "alice",
        "source_ip": "192.0.2.10",
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def test_alert_explains_the_rule_count_threshold_and_window() -> None:
    alert = alert_from_finding(_finding())

    assert alert.status is AlertStatus.OPEN
    assert alert.severity is Severity.MEDIUM
    assert alert.rule_id == "brute-force-same-account"
    assert "brute-force-same-account" in alert.evidence
    assert "observed 5" in alert.evidence
    assert "threshold of 5" in alert.evidence
    assert "inside 5 minutes" in alert.evidence
    assert alert.evidence in alert.description
    assert "not proof of compromise" in alert.description
    assert alert.recommended_action == "Review the account activity with the owner."
    assert alert.related_event_ids == ("evt-1", "evt-2")
    assert alert.timestamp == _END
    assert alert.first_event_time == _START
    assert alert.last_event_time == _END


def test_repr_hides_username_and_source_address() -> None:
    alert = alert_from_finding(_finding())
    text = repr(alert)

    assert alert.affected_username == "alice"
    assert alert.source_ip == "192.0.2.10"
    assert "alice" not in text
    assert "192.0.2.10" not in text
    assert "evt-1" not in text


def test_alert_is_frozen_and_rejects_a_closed_status() -> None:
    alert = alert_from_finding(_finding())

    with pytest.raises(FrozenInstanceError):
        alert.status = AlertStatus.OPEN  # type: ignore[misc]

    with pytest.raises(AlertValidationError) as exc:
        Alert(
            alert_id="alert-1",
            rule_id="brute-force-same-account",
            timestamp=_END,
            title="Repeated failed logins",
            severity=Severity.MEDIUM,
            description="Rule brute-force-same-account observed 5 against a threshold of 5 inside 5 minutes.",
            evidence="Rule brute-force-same-account observed 5 against a threshold of 5 inside 5 minutes.",
            recommended_action="Review the account activity with the owner.",
            status="CLOSED",  # type: ignore[arg-type]
        )

    assert "status: only OPEN is used" in exc.value.messages[0]


def test_naive_timestamp_and_secret_assignment_are_rejected() -> None:
    with pytest.raises(AlertValidationError) as naive:
        alert_from_finding(_finding(), timestamp=datetime(2026, 9, 10, 10, 0))

    assert "timestamp: naive timestamps are rejected" in naive.value.messages[0]

    with pytest.raises(AlertValidationError) as secret:
        Alert(
            alert_id="alert-1",
            rule_id="brute-force-same-account",
            timestamp=_END,
            title="Repeated failed logins",
            severity=Severity.MEDIUM,
            description="password=hunter2",
            evidence="Rule brute-force-same-account observed 5 against a threshold of 5 inside 5 minutes.",
            recommended_action="Review the account activity with the owner.",
        )

    assert secret.value.messages == ("description: refusing to store a secret assignment",)


def test_offset_timestamp_is_stored_as_utc() -> None:
    offset = timezone(timedelta(hours=3))
    alert = alert_from_finding(
        _finding(),
        timestamp=datetime(2026, 9, 10, 13, 4, tzinfo=offset),
    )

    assert alert.timestamp == _END
    assert alert.timestamp.tzinfo is timezone.utc


def test_missing_event_times_require_an_explicit_timestamp() -> None:
    finding = _finding(first_event_time=None, last_event_time=None)

    with pytest.raises(AlertValidationError) as exc:
        alert_from_finding(finding)

    assert "timestamp:" in exc.value.messages[0]

    alert = alert_from_finding(finding, timestamp=_END)
    assert alert.timestamp == _END
    assert alert.first_event_time is None
    assert alert.last_event_time is None


def test_alerts_keep_finding_order_and_do_not_merge() -> None:
    first = _finding(finding_id="finding-a", rule_id="brute-force-same-account")
    second = _finding(
        finding_id="finding-b",
        rule_id="success-after-failures",
        severity=Severity.HIGH,
        title="Successful login after repeated failures",
    )

    alerts = alerts_from_findings((second, first))

    assert [alert.rule_id for alert in alerts] == [
        "success-after-failures",
        "brute-force-same-account",
    ]
    assert alerts[0].alert_id == "alert-finding-b"
    assert alerts[1].alert_id == "alert-finding-a"


def test_long_finding_id_still_produces_a_stable_alert_id() -> None:
    finding_id = "f" * 128
    alert = alert_from_finding(_finding(finding_id=finding_id))
    again = alert_from_finding(_finding(finding_id=finding_id))

    assert len(alert.alert_id) <= 128
    assert alert.alert_id.startswith("alert-")
    assert alert == again


def test_sample_findings_become_alerts_without_raising_severity() -> None:
    findings = build_default_engine().run(parse_jsonl(_SAMPLE).events)

    assert findings
    alerts = alerts_from_findings(findings)
    assert len(alerts) == len(findings)
    for finding, alert in zip(findings, alerts, strict=True):
        assert alert.severity is finding.severity
        assert alert.severity is not Severity.CRITICAL
        assert alert.status is AlertStatus.OPEN
        assert finding.rule_id in alert.evidence
        assert f"observed {finding.observed_count}" in alert.evidence
        assert f"threshold of {finding.threshold}" in alert.evidence
        assert "not proof of compromise" in alert.description
        text = repr(alert)
        assert finding.affected_username == alert.affected_username
        assert finding.source_ip == alert.source_ip
        if finding.affected_username is not None:
            assert finding.affected_username not in text
        if finding.source_ip is not None:
            assert finding.source_ip not in text
