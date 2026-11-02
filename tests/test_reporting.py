"""Report renderings stay tied to the summary that was recorded.

Times in these tests are fixed. The clock is not read. Counts come from the
objects under test, not from a baked-in sample.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginguard.models.alert import Alert, AlertStatus
from loginguard.models.auth_event import AuthEvent
from loginguard.reporting import (
    ReportError,
    ReportFinding,
    SummaryStore,
    build_summary,
    render_csv,
    render_text,
    summary_from_snapshot,
)
from loginguard.detection.finding import Finding, Severity
from loginguard.risk import score_finding
from loginguard.storage import StorageError

_SECRET = "stored-secret-value"
_START = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
_END = datetime(2026, 9, 10, 12, 0, 2, tzinfo=timezone.utc)


def _event() -> AuthEvent:
    return AuthEvent.create(
        event_id="evt-1",
        timestamp="2026-09-10T10:00:00Z",
        event_type="LOGIN_FAILURE",
        username="alice",
        source_ip="192.0.2.10",
        raw_source="auth.jsonl",
    )


def _finding() -> Finding:
    return Finding(
        finding_id="finding-1",
        rule_id="brute-force-same-account",
        title="=HYPERLINK()",
        severity=Severity.MEDIUM,
        description="Repeated failed logins. This is a suspicion, not proof of an attack.",
        recommendation="Review the account activity with the owner.",
        observed_count=5,
        threshold=5,
        window=timedelta(minutes=5),
        related_event_ids=("evt-1",),
        first_event_time=_START,
        last_event_time=_END,
        affected_username="alice",
        source_ip="192.0.2.10",
    )


def _alert() -> Alert:
    return Alert(
        alert_id="alert-1",
        rule_id="brute-force-same-account",
        timestamp=_END,
        title="=HYPERLINK()",
        severity=Severity.MEDIUM,
        description="Repeated failed logins. A finding is a suspicion, not proof of compromise.",
        evidence="Rule brute-force-same-account observed 5 against a threshold of 5 inside 5 minutes.",
        recommended_action="Review the account activity with the owner.",
        affected_username="+alice",
        source_ip="192.0.2.10",
        first_event_time=_START,
        last_event_time=_END,
        related_event_ids=("evt-1",),
        status=AlertStatus.OPEN,
    )


def test_text_csv_and_json_round_trip_without_inventing_invalid_lines(tmp_path: Path) -> None:
    finding = _finding()
    summary = build_summary(
        input_name="auth.jsonl",
        events=(_event(),),
        invalid_events=2,
        findings=(finding,),
        alerts=(_alert(),),
        scores=(score_finding(finding),),
        started_at=_START,
        completed_at=_END,
    )
    store = SummaryStore(tmp_path / "analysis_summary.json")
    sibling = tmp_path / "notes.txt"
    sibling.write_text("keep", encoding="utf-8")
    store.save(summary)
    loaded = store.load()
    assert loaded is not None

    text = render_text(loaded)
    csv_text = render_csv(loaded)

    assert "Records processed: 3" in text
    assert "Valid events: 1" in text
    assert "Invalid events: 2" in text
    assert "Started: 2026-09-10T12:00:00Z" in text
    assert "not a probability" in text
    assert "not proof of compromise" in text
    assert "'=HYPERLINK()" in csv_text
    assert "'+alice" in csv_text
    assert sibling.read_text(encoding="utf-8") == "keep"
    assert store.load() == loaded


def test_a_snapshot_without_a_run_does_not_call_invalid_lines_zero() -> None:
    summary = summary_from_snapshot((_event(),), (), input_name=None)
    text = render_text(summary)

    assert "Invalid events: (not recorded)" in text
    assert "Records processed: (not recorded)" in text
    assert "Started: (not recorded)" in text
    assert "No alerts in the stored snapshot." in text


def test_malformed_summary_does_not_quote_the_body(tmp_path: Path) -> None:
    path = tmp_path / "analysis_summary.json"
    path.write_text("{not-json " + _SECRET, encoding="utf-8")

    with pytest.raises(StorageError) as exc:
        SummaryStore(path).load()

    assert str(exc.value) == "malformed JSON"
    assert _SECRET not in str(exc.value)


def test_naive_summary_timestamp_is_rejected(tmp_path: Path) -> None:
    finding = _finding()
    summary = build_summary(
        input_name="auth.jsonl",
        events=(_event(),),
        invalid_events=0,
        findings=(finding,),
        alerts=(_alert(),),
        scores=(score_finding(finding),),
        started_at=_START,
        completed_at=_END,
    )
    store = SummaryStore(tmp_path / "analysis_summary.json")
    store.save(summary)
    document = json.loads(store.path.read_text(encoding="utf-8"))
    document["started_at"] = "2026-09-10T12:00:00"
    store.path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(StorageError) as exc:
        store.load()

    assert "timezone" in str(exc.value)
    assert "2026-09-10T12:00:00" not in str(exc.value)


def test_a_changed_total_is_rejected(tmp_path: Path) -> None:
    finding = _finding()
    summary = build_summary(
        input_name="auth.jsonl",
        events=(_event(),),
        invalid_events=0,
        findings=(finding,),
        alerts=(_alert(),),
        scores=(score_finding(finding),),
        started_at=_START,
        completed_at=_END,
    )
    store = SummaryStore(tmp_path / "analysis_summary.json")
    store.save(summary)
    document = json.loads(store.path.read_text(encoding="utf-8"))
    document["valid_events"] = 99
    store.path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ReportError) as exc:
        store.load()

    assert "99" not in str(exc.value)


def test_summary_equality_uses_the_recorded_fields() -> None:
    finding = _finding()
    kwargs = dict(
        input_name="auth.jsonl",
        events=(_event(),),
        invalid_events=0,
        findings=(finding,),
        alerts=(_alert(),),
        scores=(score_finding(finding),),
        started_at=_START,
        completed_at=_END,
    )
    assert build_summary(**kwargs) == build_summary(**kwargs)
    assert isinstance(build_summary(**kwargs).findings[0], ReportFinding)
