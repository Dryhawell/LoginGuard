"""Password-spraying suspicion: one source IP, many distinct usernames.

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
from loginguard.detection.brute_force import RULE_ID as BRUTE_FORCE_RULE_ID
from loginguard.detection.password_spraying import (
    RULE_ID,
    PasswordSprayRule,
    register_password_spraying,
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


def _spray(
    count: int,
    *,
    start: datetime = _BASE,
    step: timedelta = timedelta(minutes=1),
    source_ip: str | None = "192.0.2.10",
    prefix: str = "u",
    username_prefix: str = "user",
) -> list[AuthEvent]:
    return [
        _failure(
            f"{prefix}-{index}",
            start + step * index,
            username=f"{username_prefix}-{index}",
            source_ip=source_ip,
        )
        for index in range(count)
    ]


def _engine(config: DetectionConfig | None = None) -> DetectionEngine:
    registry = RuleRegistry()
    register_password_spraying(registry)
    return DetectionEngine(registry, config)


def test_exactly_five_distinct_usernames_inside_the_window_produce_one_finding() -> None:
    findings = _engine().run(_spray(5))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity is Severity.MEDIUM
    assert finding.observed_count == 5
    assert finding.threshold == 5
    assert finding.window == _WINDOW
    assert finding.affected_username is None
    assert finding.affected_usernames == ("user-0", "user-1", "user-2", "user-3", "user-4")
    assert finding.source_ip == "192.0.2.10"
    assert finding.related_event_ids == ("u-0", "u-1", "u-2", "u-3", "u-4")
    assert finding.first_event_time == _BASE
    assert finding.last_event_time == _BASE + timedelta(minutes=4)
    assert "not proof of an attack" in finding.description
    assert "Do not guess passwords" in finding.recommendation
    assert "solely on this signal" in finding.recommendation
    assert "user-0" not in repr(finding)
    assert "192.0.2.10" not in repr(finding)


def test_six_usernames_do_not_emit_one_finding_per_username() -> None:
    findings = _engine().run(_spray(6))

    assert len(findings) == 1
    assert findings[0].observed_count == 6


def test_observed_count_is_distinct_usernames_not_failures() -> None:
    events = [
        *_spray(5, prefix="a"),
        *_spray(5, prefix="b", start=_BASE + timedelta(seconds=20)),
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert len(findings[0].related_event_ids) == 10


def test_one_below_the_threshold_does_not_trigger() -> None:
    assert _engine().run(_spray(4)) == ()


def test_failure_just_outside_the_window_is_not_counted() -> None:
    inside = _spray(4)
    outside = _failure(
        "outside",
        _BASE + _WINDOW + timedelta(microseconds=1),
        username="user-4",
    )

    assert _engine().run([*inside, outside]) == ()


def test_failure_exactly_at_the_window_edge_is_counted() -> None:
    events = [
        *_spray(4),
        _failure("edge", _BASE + _WINDOW, username="user-4"),
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert findings[0].last_event_time == _BASE + _WINDOW
    assert findings[0].affected_usernames[-1] == "user-4"


def test_successful_logins_are_not_counted() -> None:
    events = [
        *_spray(4),
        _failure(
            "ok-1",
            _BASE + timedelta(seconds=30),
            username="user-4",
            event_type="LOGIN_SUCCESS",
        ),
        _failure(
            "ok-2",
            _BASE + timedelta(seconds=50),
            username="user-0",
            event_type="LOGOUT",
        ),
    ]

    assert _engine().run(events) == ()


def test_a_success_does_not_erase_failures_or_raise_severity() -> None:
    events = [
        *_spray(5),
        _failure(
            "ok",
            _BASE + timedelta(seconds=30),
            username="user-0",
            event_type="LOGIN_SUCCESS",
        ),
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].observed_count == 5
    assert "ok" not in findings[0].related_event_ids


def test_repeated_failures_against_one_username_do_not_trigger() -> None:
    events = [
        _failure(f"f-{index}", _BASE + timedelta(minutes=index), username="alice")
        for index in range(8)
    ]

    assert _engine().run(events) == ()


def test_username_comparison_keeps_case() -> None:
    names = ("alice", "Alice", "bob", "carol", "dave")
    events = [
        _failure(f"c-{index}", _BASE + timedelta(minutes=index), username=name)
        for index, name in enumerate(names)
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].affected_usernames == names


def test_two_case_variants_do_not_reach_the_threshold() -> None:
    events = [
        _failure(f"c-{index}", _BASE + timedelta(seconds=index), username=name)
        for index, name in enumerate(["alice", "Alice"] * 4)
    ]

    assert _engine().run(events) == ()


def test_two_source_addresses_are_not_combined() -> None:
    below = [
        *_spray(4, source_ip="192.0.2.10", prefix="a", username_prefix="left"),
        *_spray(4, source_ip="192.0.2.11", prefix="b", username_prefix="right"),
    ]
    assert _engine().run(below) == ()

    above = [
        *_spray(5, source_ip="192.0.2.10", prefix="a", username_prefix="left"),
        *_spray(5, source_ip="192.0.2.11", prefix="b", username_prefix="right"),
    ]
    findings = _engine().run(above)

    assert len(findings) == 2
    assert {finding.source_ip for finding in findings} == {"192.0.2.10", "192.0.2.11"}
    assert {finding.observed_count for finding in findings} == {5}


def test_missing_source_ip_does_not_trigger_or_merge() -> None:
    real = _spray(4, source_ip="192.0.2.10", prefix="real", username_prefix="real")
    missing = _spray(5, source_ip=None, prefix="miss", username_prefix="miss")

    assert _engine().run([*real, *missing]) == ()


def test_missing_username_is_not_counted() -> None:
    events = _spray(4)
    events.extend(
        _failure(f"blank-{index}", _BASE + timedelta(seconds=index + 1), username=None)
        for index in range(6)
    )

    assert _engine().run(events) == ()


def test_duplicate_event_ids_are_counted_once() -> None:
    events = _spray(4)
    events.append(_failure("u-0", _BASE + timedelta(minutes=3), username="other"))

    assert _engine().run(events) == ()

    counted = [*events, _failure("u-4", _BASE + timedelta(minutes=4), username="user-4")]
    findings = _engine().run(counted)

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert findings[0].related_event_ids.count("u-0") == 1
    assert "user-0" in findings[0].affected_usernames
    assert "other" not in findings[0].affected_usernames
    assert "user-4" in findings[0].affected_usernames


def test_a_later_burst_can_still_produce_a_second_finding() -> None:
    later = _BASE + timedelta(hours=2)
    events = [
        *_spray(5, prefix="early"),
        *_spray(5, start=later, prefix="late"),
    ]

    findings = _engine().run(events)

    assert len(findings) == 2
    assert findings[0].observed_count == 5
    assert findings[1].observed_count == 5
    assert findings[0].first_event_time == _BASE
    assert findings[0].last_event_time < later
    assert findings[1].first_event_time == later


def test_related_ids_and_usernames_are_capped_at_one_hundred() -> None:
    findings = _engine().run(_spray(101, step=timedelta(seconds=1)))

    assert len(findings) == 1
    assert findings[0].observed_count == 101
    assert len(findings[0].related_event_ids) == 100
    assert len(findings[0].affected_usernames) == 100
    assert findings[0].related_event_ids[0] == "u-0"
    assert findings[0].affected_usernames[0] == "user-0"
    assert findings[0].affected_usernames[-1] == "user-99"


def test_engine_sorts_out_of_order_events_before_the_rule_runs() -> None:
    class RecordingRule(PasswordSprayRule):
        def __init__(self) -> None:
            self.seen: list[str] = []

        def evaluate(self, events, config):  # type: ignore[no-untyped-def]
            self.seen = [event.event_id for event in events]
            return super().evaluate(events, config)

    events = list(reversed(_spray(5)))
    rule = RecordingRule()
    registry = RuleRegistry()
    registry.register(rule)

    findings = DetectionEngine(registry).run(events)

    assert [event.event_id for event in events] == ["u-4", "u-3", "u-2", "u-1", "u-0"]
    assert rule.seen == ["u-0", "u-1", "u-2", "u-3", "u-4"]
    assert len(findings) == 1
    assert findings[0].related_event_ids == ("u-0", "u-1", "u-2", "u-3", "u-4")
    assert findings[0].first_event_time == _BASE


def test_threshold_and_window_come_from_config() -> None:
    config = DetectionConfig(
        password_spray_min_usernames=2,
        password_spray_window=timedelta(minutes=1),
    )
    close = [
        _failure("c-0", _BASE, username="ann"),
        _failure("c-1", _BASE + timedelta(seconds=30), username="bea"),
    ]
    far = [
        _failure("far-0", _BASE, username="ann"),
        _failure("far-1", _BASE + timedelta(minutes=2), username="bea"),
    ]

    findings = _engine(config).run(close)

    assert len(findings) == 1
    assert findings[0].threshold == 2
    assert findings[0].window == timedelta(minutes=1)
    assert findings[0].observed_count == 2
    assert _engine(config).run(far) == ()
    assert PasswordSprayRule().threshold(config) == 2
    assert PasswordSprayRule().window(config) == timedelta(minutes=1)


def test_importing_the_package_does_not_register_the_rule() -> None:
    assert RULE_ID not in RuleRegistry()
    assert DetectionEngine(RuleRegistry()).run(_spray(5)) == ()


def test_default_engine_registers_the_spray_rule_beside_brute_force() -> None:
    registry = build_default_engine().registry

    assert RULE_ID in registry
    assert BRUTE_FORCE_RULE_ID in registry


def test_sample_log_flags_the_spray_and_not_single_user_groups() -> None:
    result = parse_jsonl(_SAMPLE)
    findings = build_default_engine().run(result.events)
    sprays = [finding for finding in findings if finding.rule_id == RULE_ID]

    assert len(sprays) == 1
    spray = sprays[0]
    assert spray.rule_id == RULE_ID
    assert spray.rule_id != BRUTE_FORCE_RULE_ID
    assert spray.source_ip == "203.0.113.50"
    assert spray.observed_count == 6
    assert spray.severity is Severity.MEDIUM
    assert set(spray.affected_usernames) == {
        "frank",
        "grace",
        "heidi",
        "ivan",
        "judy",
        "mallory",
    }
    assert "alice" not in spray.affected_usernames
    assert "bob" not in spray.affected_usernames
    assert {finding.source_ip for finding in sprays} == {"203.0.113.50"}

    brute = [finding for finding in findings if finding.rule_id == BRUTE_FORCE_RULE_ID]
    assert any(
        finding.affected_username == "alice" and finding.source_ip == "192.0.2.10"
        for finding in brute
    )
    assert all(finding.rule_id != RULE_ID for finding in brute)
