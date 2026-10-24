"""Brute-force suspicion: repeated failures for one account and one source IP.

Times are fixed. Nothing in this module reads the clock.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from loginguard.detection import (
    DetectionConfig,
    DetectionEngine,
    RuleRegistry,
    Severity,
    build_default_engine,
)
from loginguard.detection.brute_force import RULE_ID, BruteForceRule, register_brute_force
from loginguard.ingestion import parse_jsonl
from loginguard.models import AuthEvent

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "auth_logs.jsonl"
_WINDOW = timedelta(minutes=5)
_BASE = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)


def _failure(
    event_id: str,
    at: datetime,
    *,
    username: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    event_type: str = "LOGIN_FAILURE",
) -> AuthEvent:
    return AuthEvent.create(
        timestamp=at,
        event_type=event_type,
        event_id=event_id,
        username=username,
        source_ip=source_ip,
    )


def _burst(
    count: int,
    *,
    start: datetime = _BASE,
    step: timedelta = timedelta(minutes=1),
    username: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    prefix: str = "f",
) -> list[AuthEvent]:
    return [
        _failure(
            f"{prefix}-{index}",
            start + step * index,
            username=username,
            source_ip=source_ip,
        )
        for index in range(count)
    ]


def _engine(config: DetectionConfig | None = None) -> DetectionEngine:
    registry = RuleRegistry()
    register_brute_force(registry)
    return DetectionEngine(registry, config)


def test_exactly_five_failures_inside_the_window_produce_one_finding() -> None:
    findings = _engine().run(_burst(5))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity is Severity.MEDIUM
    assert finding.observed_count == 5
    assert finding.threshold == 5
    assert finding.window == _WINDOW
    assert finding.affected_username == "alice"
    assert finding.source_ip == "192.0.2.10"
    assert finding.related_event_ids == ("f-0", "f-1", "f-2", "f-3", "f-4")
    assert finding.first_event_time == _BASE
    assert finding.last_event_time == _BASE + timedelta(minutes=4)
    assert "not proof of an attack" in finding.description
    assert "alice" not in repr(finding)
    assert "192.0.2.10" not in repr(finding)


def test_six_failures_in_one_burst_do_not_emit_one_finding_per_failure() -> None:
    findings = _engine().run(_burst(6))

    assert len(findings) == 1
    assert findings[0].observed_count == 6


def test_one_below_the_threshold_does_not_trigger() -> None:
    assert _engine().run(_burst(4)) == ()


def test_failure_just_outside_the_window_is_not_counted() -> None:
    inside = _burst(4)
    outside = _failure("outside", _BASE + _WINDOW + timedelta(microseconds=1))

    assert _engine().run([*inside, outside]) == ()


def test_failure_exactly_at_the_window_edge_is_counted() -> None:
    events = [
        *_burst(4),
        _failure("edge", _BASE + _WINDOW),
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert findings[0].last_event_time == _BASE + _WINDOW


def test_successful_logins_are_not_counted() -> None:
    events = [
        *_burst(4),
        _failure("ok-1", _BASE + timedelta(seconds=30), event_type="LOGIN_SUCCESS"),
        _failure("ok-2", _BASE + timedelta(seconds=50), event_type="LOGOUT"),
    ]

    assert _engine().run(events) == ()


def test_two_usernames_are_not_merged() -> None:
    events = [
        *_burst(5, username="alice", prefix="a"),
        *_burst(5, username="bob", prefix="b"),
    ]

    findings = _engine().run(events)

    assert {finding.affected_username for finding in findings} == {"alice", "bob"}
    assert all(finding.observed_count == 5 for finding in findings)


def test_username_comparison_keeps_case() -> None:
    events = [
        *_burst(5, username="alice", prefix="lower"),
        *_burst(5, username="Alice", prefix="upper"),
    ]

    names = {finding.affected_username for finding in _engine().run(events)}

    assert names == {"alice", "Alice"}


def test_two_source_addresses_are_not_merged() -> None:
    events = [
        *_burst(5, source_ip="192.0.2.10", prefix="a"),
        *_burst(5, source_ip="192.0.2.11", prefix="b"),
    ]

    addresses = {finding.source_ip for finding in _engine().run(events)}

    assert addresses == {"192.0.2.10", "192.0.2.11"}


def test_missing_username_or_source_ip_does_not_form_a_bucket() -> None:
    nameless = _burst(5, username=None, prefix="noname")
    addressless = _burst(5, source_ip=None, prefix="noip")

    assert _engine().run([*nameless, *addressless]) == ()


def test_duplicate_event_ids_are_counted_once() -> None:
    events = _burst(4)
    events.append(_failure("f-0", _BASE + timedelta(seconds=10)))

    assert _engine().run(events) == ()

    counted = _engine().run([*events, _failure("f-4", _BASE + timedelta(minutes=4))])

    assert len(counted) == 1
    assert counted[0].observed_count == 5
    assert counted[0].related_event_ids.count("f-0") == 1


def test_a_later_burst_can_still_produce_a_second_finding() -> None:
    later = _BASE + timedelta(hours=2)
    events = [
        *_burst(5, prefix="early"),
        *_burst(5, start=later, prefix="late"),
    ]

    findings = _engine().run(events)

    assert len(findings) == 2
    assert findings[0].first_event_time == _BASE
    assert findings[1].first_event_time == later


def test_engine_sorts_out_of_order_events_before_the_rule_runs() -> None:
    class RecordingRule(BruteForceRule):
        def __init__(self) -> None:
            self.seen: list[str] = []

        def evaluate(self, events, config):  # type: ignore[no-untyped-def]
            self.seen = [event.event_id for event in events]
            return super().evaluate(events, config)

    events = list(reversed(_burst(5)))
    rule = RecordingRule()
    registry = RuleRegistry()
    registry.register(rule)

    findings = DetectionEngine(registry).run(events)

    assert [event.event_id for event in events] == ["f-4", "f-3", "f-2", "f-1", "f-0"]
    assert rule.seen == ["f-0", "f-1", "f-2", "f-3", "f-4"]
    assert len(findings) == 1
    assert findings[0].related_event_ids == ("f-0", "f-1", "f-2", "f-3", "f-4")
    assert findings[0].first_event_time == _BASE


def test_threshold_and_window_come_from_config() -> None:
    config = DetectionConfig(
        brute_force_min_failures=2,
        brute_force_window=timedelta(minutes=1),
    )
    close = [
        _failure("c-0", _BASE),
        _failure("c-1", _BASE + timedelta(seconds=30)),
    ]
    far = [
        _failure("far-0", _BASE),
        _failure("far-1", _BASE + timedelta(minutes=2)),
    ]

    assert len(_engine(config).run(close)) == 1
    assert _engine(config).run(far) == ()
    assert BruteForceRule().threshold(config) == 2
    assert BruteForceRule().window(config) == timedelta(minutes=1)


def test_importing_the_package_does_not_register_the_rule() -> None:
    assert RULE_ID not in RuleRegistry()


def test_sample_log_flags_alice_and_not_bob() -> None:
    result = parse_jsonl(_SAMPLE)
    findings = [
        finding
        for finding in build_default_engine().run(result.events)
        if finding.rule_id == RULE_ID
    ]
    by_user = {finding.affected_username: finding for finding in findings}

    assert by_user["alice"].source_ip == "192.0.2.10"
    assert by_user["alice"].observed_count == 6
    assert "bob" not in by_user
    assert by_user["nora"].observed_count == 5
    assert set(by_user) == {"alice", "nora"}
