"""Correlation groups and alert deduplication.

Times are fixed. Nothing here reads the clock or the network.
"""

from datetime import datetime, timedelta, timezone

import pytest

from loginguard.correlation import correlate_events, dedupe_alerts, dedupe_findings
from loginguard.detection import Severity
from loginguard.detection.finding import Finding
from loginguard.models import AuthEvent, EventType

_WINDOW = timedelta(minutes=5)
_START = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)


def _event(
    event_id: str,
    *,
    minutes: int = 0,
    seconds: int = 0,
    username: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    event_type: str = "LOGIN_FAILURE",
) -> AuthEvent:
    return AuthEvent.create(
        timestamp=_START + timedelta(minutes=minutes, seconds=seconds),
        event_type=event_type,
        event_id=event_id,
        username=username,
        source_ip=source_ip,
    )


def _finding(
    finding_id: str,
    *,
    minutes: int,
    duration_minutes: int = 0,
    rule_id: str = "brute-force-same-account",
    username: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    window: timedelta = _WINDOW,
) -> Finding:
    first = _START + timedelta(minutes=minutes)
    last = first + timedelta(minutes=duration_minutes)
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        title="Repeated failed logins",
        severity=Severity.MEDIUM,
        description="Observed 5 LOGIN_FAILURE events inside 5 minutes.",
        recommendation="Review the account activity with the owner.",
        observed_count=5,
        threshold=5,
        window=window,
        first_event_time=first,
        last_event_time=last,
        affected_username=username,
        source_ip=source_ip,
        related_event_ids=(finding_id,),
    )


def test_same_username_groups_together_even_when_input_is_reversed() -> None:
    events = (
        _event("e3", minutes=4),
        _event("e1", minutes=0),
        _event("e2", minutes=2),
    )

    groups = correlate_events(events, window=_WINDOW, by_username=True)
    reversed_groups = correlate_events(tuple(reversed(events)), window=_WINDOW, by_username=True)

    assert groups == reversed_groups
    assert len(groups) == 1
    assert tuple(event.event_id for event in groups[0].events) == ("e1", "e2", "e3")
    assert groups[0].username == "alice"
    assert "alice" not in repr(groups[0])
    assert "192.0.2.10" not in repr(groups[0])


def test_duplicate_event_id_is_kept_once() -> None:
    early = _event("same", minutes=1)
    late = _event("same", minutes=3)

    groups = correlate_events((late, early), window=_WINDOW, by_username=True)

    assert len(groups) == 1
    assert tuple(event.event_id for event in groups[0].events) == ("same",)
    assert groups[0].events[0].timestamp == early.timestamp


def test_a_gap_larger_than_the_window_splits_the_group() -> None:
    events = (
        _event("early", minutes=0),
        _event("late", minutes=5, seconds=0),
        _event("after", minutes=10, seconds=1),
    )

    groups = correlate_events(events, window=_WINDOW, by_username=True)

    assert tuple(tuple(event.event_id for event in group.events) for group in groups) == (
        ("early", "late"),
        ("after",),
    )


def test_different_users_and_missing_usernames_stay_apart() -> None:
    events = (
        _event("alice-1", username="alice"),
        _event("bob-1", username="bob"),
        _event("blank", username=None),
    )

    groups = correlate_events(events, window=_WINDOW, by_username=True)

    assert tuple(group.username for group in groups) == ("alice", "bob")
    assert all(event.username is not None for group in groups for event in group.events)


def test_source_address_can_be_the_grouping_key() -> None:
    events = (
        _event("a", username="alice", source_ip="192.0.2.10"),
        _event("b", username="bob", source_ip="192.0.2.10"),
        _event("c", username="carol", source_ip="198.51.100.20"),
        _event("d", username="dave", source_ip=None),
    )

    groups = correlate_events(events, window=_WINDOW, by_username=False, by_source_ip=True)

    assert tuple(group.source_ip for group in groups) == ("192.0.2.10", "198.51.100.20")
    assert tuple(event.event_id for event in groups[0].events) == ("a", "b")


def test_event_type_splits_success_from_failure() -> None:
    events = (
        _event("fail", event_type="LOGIN_FAILURE"),
        _event("ok", event_type="LOGIN_SUCCESS"),
    )

    groups = correlate_events(
        events,
        window=_WINDOW,
        by_username=True,
        by_event_type=True,
    )

    assert tuple(group.event_type for group in groups) == (
        EventType.LOGIN_FAILURE,
        EventType.LOGIN_SUCCESS,
    )


def test_dedup_drops_a_repeat_inside_the_window_and_keeps_a_later_incident() -> None:
    first = _finding("first", minutes=0, duration_minutes=4)
    overlap = _finding("overlap", minutes=6)
    later = Finding(
        finding_id="later",
        rule_id=first.rule_id,
        title=first.title,
        severity=first.severity,
        description=first.description,
        recommendation=first.recommendation,
        observed_count=first.observed_count,
        threshold=first.threshold,
        window=first.window,
        first_event_time=first.last_event_time + first.window + timedelta(microseconds=1),
        last_event_time=first.last_event_time + first.window + timedelta(minutes=1),
        affected_username=first.affected_username,
        source_ip=first.source_ip,
        related_event_ids=("later",),
    )

    kept = dedupe_findings((overlap, later, first))

    assert tuple(finding.finding_id for finding in kept) == ("first", "later")
    alerts = dedupe_alerts((overlap, later, first))
    assert tuple(alert.alert_id for alert in alerts) == (
        f"alert-{first.finding_id}",
        f"alert-{later.finding_id}",
    )


def test_dedup_keeps_a_different_rule_user_or_address() -> None:
    base = _finding("base", minutes=0)
    other_rule = _finding("rule", minutes=1, rule_id="password-spray-distinct-usernames")
    other_user = _finding("user", minutes=1, username="bob")
    other_ip = _finding("ip", minutes=1, source_ip="198.51.100.8")

    kept = dedupe_findings((base, other_rule, other_user, other_ip))

    assert {finding.finding_id for finding in kept} == {"base", "rule", "user", "ip"}


def test_exact_window_edge_stays_one_incident() -> None:
    first = _finding("first", minutes=0, duration_minutes=0)
    edge = Finding(
        finding_id="edge",
        rule_id=first.rule_id,
        title=first.title,
        severity=first.severity,
        description=first.description,
        recommendation=first.recommendation,
        observed_count=first.observed_count,
        threshold=first.threshold,
        window=first.window,
        first_event_time=first.last_event_time + first.window,
        last_event_time=first.last_event_time + first.window,
        affected_username=first.affected_username,
        source_ip=first.source_ip,
        related_event_ids=("edge",),
    )

    assert tuple(finding.finding_id for finding in dedupe_findings((first, edge))) == ("first",)


def test_correlation_requires_a_key_and_a_positive_window() -> None:
    with pytest.raises(ValueError):
        correlate_events((_event("e"),), window=_WINDOW, by_username=False)
    with pytest.raises(ValueError):
        correlate_events((_event("e"),), window=timedelta(0), by_username=True)
