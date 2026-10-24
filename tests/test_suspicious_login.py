"""Suspicious success: failures for one account, then a login that works.

Times are fixed. Nothing in this module reads the clock. The window is the
lookback that ends at the success: a failure counts when it is at most
``window`` before that success, including the exact boundary.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loginguard.detection import (
    DetectionConfig,
    DetectionConfigError,
    DetectionEngine,
    RuleRegistry,
    Severity,
    build_default_engine,
)
from loginguard.detection.brute_force import RULE_ID as BRUTE_FORCE_RULE_ID
from loginguard.detection.password_spraying import RULE_ID as SPRAY_RULE_ID
from loginguard.detection.suspicious_login import (
    RULE_ID,
    SuspiciousLoginRule,
    register_suspicious_login,
)
from loginguard.ingestion import parse_jsonl
from loginguard.models import AuthEvent

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "auth_logs.jsonl"
_WINDOW = timedelta(minutes=10)
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


def _success(
    event_id: str,
    at: datetime,
    *,
    username: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
) -> AuthEvent:
    return _failure(
        event_id,
        at,
        username=username,
        source_ip=source_ip,
        event_type="LOGIN_SUCCESS",
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
    register_suspicious_login(registry)
    return DetectionEngine(registry, config)


def test_exactly_five_failures_then_a_success_inside_the_window_triggers() -> None:
    success_at = _BASE + timedelta(minutes=4)
    findings = _engine().run(
        [*_burst(5), _success("ok", success_at, source_ip="192.0.2.40")]
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity is Severity.HIGH
    assert finding.severity is not Severity.CRITICAL
    assert finding.observed_count == 5
    assert finding.threshold == 5
    assert finding.window == _WINDOW
    assert finding.affected_username == "alice"
    assert finding.source_ip == "192.0.2.40"
    assert finding.related_event_ids == ("f-0", "f-1", "f-2", "f-3", "f-4", "ok")
    assert finding.first_event_time == _BASE
    assert finding.last_event_time == success_at
    assert "not proof of compromise" in finding.description
    assert "192.0.2.10" in finding.description
    assert "192.0.2.40" in finding.description
    assert "Investigate the account" in finding.recommendation
    assert "right password" in finding.recommendation
    assert "source of the success" in finding.recommendation
    assert "confirmed takeover" in finding.recommendation
    assert "Do not guess passwords" in finding.recommendation
    assert "alice" not in repr(finding)
    assert "192.0.2.40" not in repr(finding)
    assert "192.0.2.10" not in repr(finding)


def test_four_failures_then_a_success_does_not_trigger() -> None:
    events = [*_burst(4), _success("ok", _BASE + timedelta(minutes=4))]

    assert _engine().run(events) == ()


def test_success_just_outside_the_window_does_not_trigger() -> None:
    events = [
        *_burst(5, step=timedelta(0)),
        _success("ok", _BASE + _WINDOW + timedelta(microseconds=1)),
    ]

    assert _engine().run(events) == ()


def test_failure_exactly_window_before_the_success_counts() -> None:
    success_at = _BASE + _WINDOW
    findings = _engine().run([*_burst(5, step=timedelta(0)), _success("ok", success_at)])

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert findings[0].first_event_time == _BASE
    assert findings[0].last_event_time == success_at


def test_failures_older_than_the_lookback_are_not_counted() -> None:
    success_at = _BASE + _WINDOW + timedelta(minutes=1)
    inside = success_at - timedelta(minutes=2)
    events = [
        _failure("old", _BASE),
        *_burst(4, start=inside, prefix="in", step=timedelta(seconds=10)),
        _success("ok", success_at),
    ]

    assert _engine().run(events) == ()


def test_failures_after_the_success_do_not_count() -> None:
    events = [
        _success("ok", _BASE),
        *_burst(5, start=_BASE + timedelta(minutes=1)),
    ]

    assert _engine().run(events) == ()


def test_success_with_no_prior_failures_does_not_trigger() -> None:
    assert _engine().run([_success("ok", _BASE)]) == ()


def test_ordinary_two_mistakes_then_success_does_not_trigger() -> None:
    events = [
        _failure("b-0", _BASE, username="bob", source_ip="198.51.100.25"),
        _failure(
            "b-1",
            _BASE + timedelta(seconds=40),
            username="bob",
            source_ip="198.51.100.25",
        ),
        _success(
            "b-ok",
            _BASE + timedelta(seconds=70),
            username="bob",
            source_ip="198.51.100.25",
        ),
    ]

    assert _engine().run(events) == ()


def test_failures_for_a_different_username_do_not_count() -> None:
    events = [
        *_burst(5, username="bob", prefix="b"),
        *_burst(4, username="alice", prefix="a"),
        _success("alice-ok", _BASE + timedelta(minutes=5), username="alice"),
    ]

    assert _engine().run(events) == ()


def test_username_comparison_keeps_case() -> None:
    events = [
        *_burst(5, username="Alice", prefix="A"),
        _success("lower", _BASE + timedelta(minutes=6), username="alice"),
        _success(
            "same",
            _BASE + timedelta(minutes=6),
            username="Alice",
            source_ip="192.0.2.40",
        ),
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].affected_username == "Alice"
    assert findings[0].source_ip == "192.0.2.40"


def test_missing_username_does_not_merge() -> None:
    nameless = [
        _failure(f"n-{index}", _BASE + timedelta(minutes=index), username=None)
        for index in range(6)
    ]
    events = [
        *nameless,
        _success("n-ok", _BASE + timedelta(minutes=7), username=None),
        *_burst(4, username="alice", prefix="a"),
        _success("a-ok", _BASE + timedelta(minutes=5), username="alice"),
    ]

    assert _engine().run(events) == ()


def test_duplicate_failure_event_ids_are_not_double_counted() -> None:
    short = [
        *_burst(4),
        _failure("f-0", _BASE + timedelta(minutes=3)),
        _success("ok", _BASE + timedelta(minutes=4)),
    ]
    assert _engine().run(short) == ()

    counted = [
        *_burst(5),
        _failure("f-0", _BASE + timedelta(seconds=30)),
        _success("ok", _BASE + timedelta(minutes=6)),
    ]
    findings = _engine().run(counted)

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert findings[0].related_event_ids.count("f-0") == 1


def test_duplicate_success_event_id_produces_one_finding() -> None:
    events = [
        *_burst(5),
        _success("ok", _BASE + timedelta(minutes=5)),
        _success("ok", _BASE + timedelta(minutes=6)),
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].last_event_time == _BASE + timedelta(minutes=5)
    assert findings[0].related_event_ids.count("ok") == 1


def test_successes_are_not_counted_as_failures() -> None:
    events = [
        *_burst(4),
        _success("early-1", _BASE + timedelta(seconds=10)),
        _success("early-2", _BASE + timedelta(seconds=20)),
        _success("early-3", _BASE + timedelta(seconds=30)),
        _success("final", _BASE + timedelta(minutes=4)),
    ]

    assert _engine().run(events) == ()


def test_other_event_types_do_not_count_as_failures() -> None:
    events = [
        *_burst(4),
        _failure("lock", _BASE + timedelta(seconds=15), event_type="ACCOUNT_LOCKED"),
        _failure("out", _BASE + timedelta(seconds=20), event_type="LOGOUT"),
        _failure("chg", _BASE + timedelta(seconds=25), event_type="PASSWORD_CHANGE"),
        _success("ok", _BASE + timedelta(minutes=4)),
    ]

    assert _engine().run(events) == ()


def test_a_new_ip_alone_does_not_trigger() -> None:
    events = [
        _success("carol", _BASE, username="carol", source_ip="198.51.100.10"),
        _success("dave", _BASE + timedelta(minutes=1), username="dave", source_ip="203.0.113.77"),
        _success("only", _BASE + timedelta(minutes=2), username="nora", source_ip="192.0.2.99"),
    ]

    assert _engine().run(events) == ()


def test_success_from_a_different_ip_still_counts_username_failures() -> None:
    events = [
        _failure("f-0", _BASE, source_ip="192.0.2.10"),
        _failure("f-1", _BASE + timedelta(minutes=1), source_ip="192.0.2.11"),
        _failure("f-2", _BASE + timedelta(minutes=2), source_ip="192.0.2.10"),
        _failure("f-3", _BASE + timedelta(minutes=3), source_ip=None),
        _failure("f-4", _BASE + timedelta(minutes=4), source_ip="198.51.100.8"),
        _success("ok", _BASE + timedelta(minutes=5), source_ip="203.0.113.40"),
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.observed_count == 5
    assert finding.source_ip == "203.0.113.40"
    assert "192.0.2.10" in finding.description
    assert "192.0.2.11" in finding.description
    assert "198.51.100.8" in finding.description
    assert "203.0.113.40" in finding.description
    assert "203.0.113.40" not in repr(finding)


def test_each_qualifying_success_produces_its_own_finding() -> None:
    events = [
        *_burst(5),
        _success("s1", _BASE + timedelta(minutes=6), source_ip="192.0.2.10"),
        _success("s2", _BASE + timedelta(minutes=7), source_ip="198.51.100.25"),
    ]

    findings = _engine().run(events)

    assert len(findings) == 2
    assert [finding.related_event_ids[-1] for finding in findings] == ["s1", "s2"]
    assert findings[0].observed_count == 5
    assert findings[1].observed_count == 5
    assert "s2" not in findings[0].related_event_ids
    assert "s1" not in findings[1].related_event_ids
    assert findings[0].last_event_time == _BASE + timedelta(minutes=6)
    assert findings[1].last_event_time == _BASE + timedelta(minutes=7)


def test_related_ids_are_capped_at_one_hundred() -> None:
    findings = _engine().run(
        [
            *_burst(101, step=timedelta(seconds=1)),
            _success("ok", _BASE + timedelta(seconds=120)),
        ]
    )

    assert len(findings) == 1
    assert findings[0].observed_count == 101
    assert len(findings[0].related_event_ids) == 100
    assert findings[0].related_event_ids[0] == "f-0"
    assert findings[0].related_event_ids[-1] == "ok"
    assert "f-98" in findings[0].related_event_ids
    assert "f-99" not in findings[0].related_event_ids
    assert "success event id" in findings[0].description


def test_engine_sorts_out_of_order_events_before_the_rule_runs() -> None:
    class RecordingRule(SuspiciousLoginRule):
        def __init__(self) -> None:
            self.seen: list[str] = []

        def evaluate(self, events, config):  # type: ignore[no-untyped-def]
            self.seen = [event.event_id for event in events]
            return super().evaluate(events, config)

    events = list(reversed([*_burst(5), _success("ok", _BASE + timedelta(minutes=5))]))
    rule = RecordingRule()
    registry = RuleRegistry()
    registry.register(rule)

    findings = DetectionEngine(registry).run(events)

    assert [event.event_id for event in events] == ["ok", "f-4", "f-3", "f-2", "f-1", "f-0"]
    assert rule.seen == ["f-0", "f-1", "f-2", "f-3", "f-4", "ok"]
    assert len(findings) == 1
    assert findings[0].related_event_ids == ("f-0", "f-1", "f-2", "f-3", "f-4", "ok")
    assert findings[0].first_event_time == _BASE


def test_threshold_and_window_come_from_config() -> None:
    config = DetectionConfig(
        success_after_failure_min_failures=2,
        success_after_failure_window=timedelta(minutes=1),
    )
    close = [
        _failure("c-0", _BASE),
        _failure("c-1", _BASE + timedelta(seconds=20)),
        _success("ok", _BASE + timedelta(seconds=40)),
    ]
    far = [
        _failure("far-0", _BASE),
        _failure("far-1", _BASE + timedelta(seconds=20)),
        _success("late", _BASE + timedelta(minutes=2)),
    ]

    findings = _engine(config).run(close)

    assert len(findings) == 1
    assert findings[0].threshold == 2
    assert findings[0].window == timedelta(minutes=1)
    assert findings[0].observed_count == 2
    assert _engine(config).run(far) == ()
    assert SuspiciousLoginRule().threshold(DetectionConfig()) == 5
    assert SuspiciousLoginRule().window(DetectionConfig()) == _WINDOW


def test_non_positive_success_settings_are_rejected() -> None:
    with pytest.raises(DetectionConfigError):
        DetectionConfig(success_after_failure_min_failures=0)
    with pytest.raises(DetectionConfigError):
        DetectionConfig(success_after_failure_window=timedelta(0))


def test_importing_the_module_does_not_register_the_rule() -> None:
    assert RULE_ID not in RuleRegistry()
    assert DetectionEngine(RuleRegistry()).run(
        [*_burst(5), _success("ok", _BASE + timedelta(minutes=5))]
    ) == ()


def test_default_engine_registers_the_rule_beside_the_others() -> None:
    registry = build_default_engine().registry

    assert RULE_ID in registry
    assert BRUTE_FORCE_RULE_ID in registry
    assert SPRAY_RULE_ID in registry
    assert DetectionEngine(RuleRegistry()).run(
        [*_burst(5), _success("ok", _BASE + timedelta(minutes=5))]
    ) == ()


def test_sample_log_flags_nora_and_not_alice_or_bob() -> None:
    result = parse_jsonl(_SAMPLE)
    findings = [
        finding
        for finding in build_default_engine().run(result.events)
        if finding.rule_id == RULE_ID
    ]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.affected_username == "nora"
    assert finding.source_ip == "192.0.2.40"
    assert finding.observed_count == 5
    assert finding.threshold == 5
    assert finding.window == timedelta(minutes=10)
    assert finding.severity is Severity.HIGH
    assert finding.first_event_time == datetime(2026, 9, 10, 12, 10, tzinfo=timezone.utc)
    assert finding.last_event_time == datetime(2026, 9, 10, 12, 12, 5, tzinfo=timezone.utc)
    assert finding.related_event_ids == (
        "auth_logs.jsonl:23",
        "auth_logs.jsonl:24",
        "auth_logs.jsonl:25",
        "auth_logs.jsonl:26",
        "auth_logs.jsonl:27",
        "auth_logs.jsonl:28",
    )
    assert "not proof of compromise" in finding.description
    assert {item.affected_username for item in findings} == {"nora"}
