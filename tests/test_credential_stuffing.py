"""Distributed-failure heuristic. Times are fixed. Nothing here reads the clock.

A single source address and many usernames stays with the spray rule.
This module does not treat that shape as credential stuffing.
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
from loginguard.detection.credential_stuffing import (
    RULE_ID,
    CredentialStuffingRule,
    register_credential_stuffing,
)
from loginguard.detection.password_spraying import RULE_ID as SPRAY_RULE_ID
from loginguard.detection.suspicious_login import RULE_ID as SUCCESS_RULE_ID
from loginguard.ingestion import parse_jsonl
from loginguard.models import AuthEvent, EventType

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "auth_logs.jsonl"
_WINDOW = timedelta(minutes=15)
_BASE = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
_IPS = ("192.0.2.10", "198.51.100.20", "203.0.113.30")


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


def _distributed(
    count: int,
    *,
    source_ips: int = 3,
    start: datetime = _BASE,
    step: timedelta = timedelta(minutes=1),
    prefix: str = "d",
) -> list[AuthEvent]:
    addresses = _IPS[:source_ips]
    return [
        _failure(
            f"{prefix}-{index}",
            start + step * index,
            username=f"user-{index}",
            source_ip=addresses[index % len(addresses)],
        )
        for index in range(count)
    ]


def _engine(config: DetectionConfig | None = None) -> DetectionEngine:
    registry = RuleRegistry()
    register_credential_stuffing(registry)
    return DetectionEngine(registry, config)


def _scenario(events: tuple[AuthEvent, ...], name: str) -> list[AuthEvent]:
    return [event for event in events if event.metadata.get("scenario") == name]


def _ordered_names(events: list[AuthEvent]) -> tuple[str, ...]:
    ordered = sorted(events, key=lambda event: (event.timestamp, event.event_id))
    seen: set[str] = set()
    names: list[str] = []
    for event in ordered:
        if event.event_type is not EventType.LOGIN_FAILURE:
            continue
        if event.username is None or event.source_ip is None or event.username in seen:
            continue
        seen.add(event.username)
        names.append(event.username)
    return tuple(names)


def test_five_usernames_and_three_ips_inside_the_window_produce_one_finding() -> None:
    findings = _engine().run(_distributed(5))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity is Severity.LOW
    assert finding.observed_count == 5
    assert finding.threshold == 5
    assert finding.window == _WINDOW
    assert finding.affected_username is None
    assert finding.source_ip is None
    assert finding.affected_usernames == ("user-0", "user-1", "user-2", "user-3", "user-4")
    assert finding.related_event_ids == ("d-0", "d-1", "d-2", "d-3", "d-4")
    assert finding.first_event_time == _BASE
    assert finding.last_event_time == _BASE + timedelta(minutes=4)
    assert "Credential-stuffing-like or distributed guessing" in finding.title
    assert "cannot show a leak" in finding.title
    assert (
        "consistent with credential-stuffing-like or distributed guessing behavior"
        in finding.description
    )
    assert "cannot show whether any password came from a leak" in finding.description
    assert "5 distinct usernames and 3 distinct source addresses" in finding.description
    assert "not proof of credential stuffing" in finding.description
    assert "Investigate the source addresses" in finding.recommendation
    assert "Do not assume a breach" in finding.recommendation
    assert "Do not guess passwords" in finding.recommendation
    assert "user-0" not in repr(finding)
    assert "192.0.2.10" not in repr(finding)
    assert "198.51.100.20" not in repr(finding)
    assert "203.0.113.30" not in repr(finding)


def test_six_usernames_do_not_emit_one_finding_per_username_or_ip() -> None:
    findings = _engine().run(_distributed(6))

    assert len(findings) == 1
    assert findings[0].observed_count == 6


def test_five_usernames_and_one_ip_do_not_trigger() -> None:
    events = _distributed(5, source_ips=1)

    assert _engine().run(events) == ()

    findings = build_default_engine().run(events)

    assert findings
    assert all(finding.rule_id != RULE_ID for finding in findings)
    assert any(finding.rule_id == SPRAY_RULE_ID for finding in findings)
    assert all(finding.rule_id != BRUTE_FORCE_RULE_ID for finding in findings)


def test_four_usernames_and_three_ips_do_not_trigger() -> None:
    assert _engine().run(_distributed(4)) == ()


def test_failure_just_outside_the_window_is_not_counted() -> None:
    inside = _distributed(4)
    outside = _failure(
        "outside",
        _BASE + _WINDOW + timedelta(microseconds=1),
        username="user-4",
        source_ip=_IPS[1],
    )

    assert _engine().run([*inside, outside]) == ()


def test_failure_exactly_at_the_window_edge_is_counted() -> None:
    events = [
        *_distributed(4),
        _failure("edge", _BASE + _WINDOW, username="user-4", source_ip=_IPS[2]),
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert findings[0].last_event_time == _BASE + _WINDOW
    assert "user-4" in findings[0].affected_usernames
    assert "3 distinct source addresses" in findings[0].description


def test_successes_are_not_counted() -> None:
    short = [
        *_distributed(4, source_ips=2),
        _failure(
            "ok-user",
            _BASE + timedelta(minutes=4),
            username="user-4",
            source_ip=_IPS[2],
            event_type="LOGIN_SUCCESS",
        ),
    ]
    assert _engine().run(short) == ()

    qualifying = [
        *_distributed(5),
        _failure(
            "ok",
            _BASE + timedelta(seconds=30),
            username="user-0",
            source_ip=_IPS[0],
            event_type="LOGIN_SUCCESS",
        ),
    ]
    findings = _engine().run(qualifying)

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert "ok" not in findings[0].related_event_ids


def test_missing_source_ip_does_not_merge() -> None:
    events = [
        *_distributed(5, source_ips=2),
        _failure("miss-0", _BASE + timedelta(seconds=10), username="extra-0", source_ip=None),
        _failure("miss-1", _BASE + timedelta(seconds=20), username="extra-1", source_ip=None),
        _failure("miss-2", _BASE + timedelta(seconds=30), username="extra-2", source_ip=None),
        _failure("noname", _BASE + timedelta(seconds=40), username=None, source_ip=_IPS[2]),
    ]

    assert _engine().run(events) == ()


def test_username_comparison_keeps_case() -> None:
    names = ("ann", "Ann", "bob", "Bob", "cara")
    events = [
        _failure(
            f"c-{index}",
            _BASE + timedelta(minutes=index),
            username=name,
            source_ip=_IPS[index % 3],
        )
        for index, name in enumerate(names)
    ]

    findings = _engine().run(events)

    assert len(findings) == 1
    assert findings[0].affected_usernames == names
    assert findings[0].observed_count == 5


def test_duplicate_event_ids_are_counted_once() -> None:
    events = _distributed(4)
    events.append(
        _failure(
            "d-0",
            _BASE + timedelta(minutes=4),
            username="other",
            source_ip=_IPS[1],
        )
    )

    assert _engine().run(events) == ()

    counted = [
        *events,
        _failure("d-4", _BASE + timedelta(minutes=5), username="user-4", source_ip=_IPS[2]),
    ]
    findings = _engine().run(counted)

    assert len(findings) == 1
    assert findings[0].observed_count == 5
    assert findings[0].related_event_ids.count("d-0") == 1
    assert "user-0" in findings[0].affected_usernames
    assert "other" not in findings[0].affected_usernames
    assert "user-4" in findings[0].affected_usernames


def test_engine_sorts_out_of_order_events_before_the_rule_runs() -> None:
    class RecordingRule(CredentialStuffingRule):
        def __init__(self) -> None:
            self.seen: list[str] = []

        def evaluate(self, events, config):  # type: ignore[no-untyped-def]
            self.seen = [event.event_id for event in events]
            return super().evaluate(events, config)

    events = list(reversed(_distributed(5)))
    rule = RecordingRule()
    registry = RuleRegistry()
    registry.register(rule)

    findings = DetectionEngine(registry).run(events)

    assert [event.event_id for event in events] == ["d-4", "d-3", "d-2", "d-1", "d-0"]
    assert rule.seen == ["d-0", "d-1", "d-2", "d-3", "d-4"]
    assert len(findings) == 1
    assert findings[0].related_event_ids == ("d-0", "d-1", "d-2", "d-3", "d-4")
    assert findings[0].first_event_time == _BASE


def test_a_later_burst_can_still_produce_a_second_finding() -> None:
    later = _BASE + timedelta(hours=2)
    events = [
        *_distributed(5, prefix="early"),
        *_distributed(5, start=later, prefix="late"),
    ]

    findings = _engine().run(events)

    assert len(findings) == 2
    assert findings[0].observed_count == 5
    assert findings[1].observed_count == 5
    assert findings[0].first_event_time == _BASE
    assert findings[0].last_event_time < later
    assert findings[1].first_event_time == later


def test_related_ids_and_usernames_are_capped_at_one_hundred() -> None:
    findings = _engine().run(_distributed(101, step=timedelta(seconds=1)))

    assert len(findings) == 1
    assert findings[0].observed_count == 101
    assert len(findings[0].related_event_ids) == 100
    assert len(findings[0].affected_usernames) == 100
    assert findings[0].related_event_ids[0] == "d-0"
    assert findings[0].affected_usernames[0] == "user-0"
    assert findings[0].affected_usernames[-1] == "user-99"
    assert "101 distinct usernames and 3 distinct source addresses" in findings[0].description


def test_threshold_and_window_come_from_config() -> None:
    config = DetectionConfig(
        distributed_min_usernames=2,
        distributed_min_source_ips=2,
        distributed_window=timedelta(minutes=1),
    )
    close = _distributed(2, source_ips=2, step=timedelta(seconds=30))
    far = _distributed(2, source_ips=2, step=timedelta(minutes=2))

    findings = _engine(config).run(close)

    assert len(findings) == 1
    assert findings[0].threshold == 2
    assert findings[0].window == timedelta(minutes=1)
    assert findings[0].observed_count == 2
    assert "2 distinct usernames and 2 distinct source addresses" in findings[0].description
    assert _engine(config).run(far) == ()
    assert CredentialStuffingRule().threshold(config) == 2
    assert CredentialStuffingRule().window(config) == timedelta(minutes=1)
    assert CredentialStuffingRule().threshold(DetectionConfig()) == 5
    assert CredentialStuffingRule().window(DetectionConfig()) == _WINDOW


def test_non_positive_distributed_settings_are_rejected() -> None:
    with pytest.raises(DetectionConfigError):
        DetectionConfig(distributed_min_usernames=0)
    with pytest.raises(DetectionConfigError):
        DetectionConfig(distributed_min_source_ips=0)
    with pytest.raises(DetectionConfigError):
        DetectionConfig(distributed_window=timedelta(0))
    with pytest.raises(DetectionConfigError):
        DetectionConfig(distributed_min_usernames=True)  # type: ignore[arg-type]


def test_importing_the_package_does_not_register_the_rule() -> None:
    assert RULE_ID not in RuleRegistry()
    assert DetectionEngine(RuleRegistry()).run(_distributed(5)) == ()


def test_default_engine_registers_the_rule_beside_the_others() -> None:
    registry = build_default_engine().registry

    assert RULE_ID in registry
    assert BRUTE_FORCE_RULE_ID in registry
    assert SPRAY_RULE_ID in registry
    assert SUCCESS_RULE_ID in registry
    assert DetectionEngine(RuleRegistry()).run(_distributed(5)) == ()


def test_sample_log_flags_the_distributed_scenario_and_not_the_single_ip_patterns() -> None:
    result = parse_jsonl(_SAMPLE)
    distributed = _scenario(result.events, "distributed_failures")
    expected_names = _ordered_names(distributed)
    expected_ips = {event.source_ip for event in distributed if event.source_ip}
    ordered = sorted(
        (
            event
            for event in distributed
            if event.event_type is EventType.LOGIN_FAILURE
            and event.username is not None
            and event.source_ip is not None
        ),
        key=lambda event: (event.timestamp, event.event_id),
    )
    expected_ids = tuple(event.event_id for event in ordered)

    only_this_rule = _engine()
    assert only_this_rule.run(_scenario(result.events, "password_spraying")) == ()
    assert only_this_rule.run(_scenario(result.events, "repeated_failures")) == ()
    assert only_this_rule.run(_scenario(result.events, "failure_then_success")) == ()

    findings = [
        finding
        for finding in build_default_engine().run(result.events)
        if finding.rule_id == RULE_ID
    ]

    assert len(expected_names) >= 5
    assert len(expected_ips) >= 3
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.LOW
    assert finding.observed_count == len(expected_names)
    assert finding.affected_usernames == expected_names
    assert finding.related_event_ids == expected_ids
    assert finding.source_ip is None
    assert f"{len(expected_ips)} distinct source addresses" in finding.description
    assert "frank" not in finding.affected_usernames
    assert "alice" not in finding.affected_usernames
    assert "nora" not in finding.affected_usernames
    for name in expected_names:
        assert name not in repr(finding)
    for source_ip in expected_ips:
        assert source_ip not in repr(finding)
