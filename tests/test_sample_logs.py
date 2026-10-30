"""The checked-in sample log is synthetic and matches the JSONL parser.

Counts describe what is in the file. They are not detection results.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import ipaddress

from loginguard.ingestion import parse_jsonl
from loginguard.models import EventType

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "auth_logs.jsonl"
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def _scenario(events: tuple, name: str) -> list:
    return [event for event in events if event.metadata.get("scenario") == name]


def test_sample_file_is_labeled_synthetic_and_parses() -> None:
    text = _SAMPLE.read_text(encoding="utf-8")

    assert "SYNTHETIC" in text
    assert "password=" not in text.lower()
    assert "hunter2" not in text.lower()

    result = parse_jsonl(_SAMPLE)

    assert result.source_name == "auth_logs.jsonl"
    assert result.valid_count == 38
    assert result.invalid_count == 6
    assert all(event.metadata.get("dataset") == "synthetic" for event in result.events)
    assert all(event.timestamp.tzinfo is not None for event in result.events)
    codes = Counter(issue.code for issue in result.issues)
    assert codes["malformed_json"] == 3
    assert codes["not_an_object"] == 1
    assert codes["invalid_event"] == 2
    assert all("hunter2" not in str(issue) for issue in result.issues)


def test_sample_addresses_stay_inside_documentation_ranges() -> None:
    result = parse_jsonl(_SAMPLE)

    for event in result.events:
        if event.source_ip is None:
            continue
        address = ipaddress.ip_address(event.source_ip)
        assert any(address in network for network in _DOCUMENTATION_NETWORKS)


def test_sample_scenarios_have_the_intended_shapes() -> None:
    result = parse_jsonl(_SAMPLE)
    events = result.events

    normal = _scenario(events, "normal_success")
    assert len({event.username for event in normal}) >= 3
    assert len({event.source_ip for event in normal if event.source_ip}) >= 3
    assert any(event.event_type is EventType.LOGOUT for event in normal)
    assert any(event.source_ip == "2001:db8::10" for event in normal)
    wendy = next(event for event in normal if event.username == "wendy")
    assert wendy.timestamp == datetime(2026, 9, 10, 8, 40, tzinfo=timezone.utc)

    mistakes = _scenario(events, "ordinary_mistakes")
    mistake_failures = [event for event in mistakes if event.event_type is EventType.LOGIN_FAILURE]
    assert len(mistake_failures) == 2
    assert any(event.event_type is EventType.LOGIN_SUCCESS for event in mistakes)
    assert {event.username for event in mistakes} == {"bob"}

    burst = _scenario(events, "repeated_failures")
    assert len(burst) >= 5
    assert {event.event_type for event in burst} == {EventType.LOGIN_FAILURE}
    assert {event.username for event in burst} == {"alice"}
    assert {event.source_ip for event in burst} == {"192.0.2.10"}
    assert max(event.timestamp for event in burst) - min(event.timestamp for event in burst) <= timedelta(minutes=5)

    spray = _scenario(events, "password_spraying")
    assert {event.event_type for event in spray} == {EventType.LOGIN_FAILURE}
    assert len({event.username for event in spray}) >= 5
    assert {event.source_ip for event in spray} == {"203.0.113.50"}
    assert max(event.timestamp for event in spray) - min(event.timestamp for event in spray) <= timedelta(minutes=10)

    followed = _scenario(events, "failure_then_success")
    failures = [event for event in followed if event.event_type is EventType.LOGIN_FAILURE]
    successes = [event for event in followed if event.event_type is EventType.LOGIN_SUCCESS]
    assert len(failures) >= 5
    assert len(successes) == 1
    assert {event.username for event in followed} == {"nora"}
    assert {event.source_ip for event in followed} == {"192.0.2.40"}
    assert successes[0].timestamp > max(event.timestamp for event in failures)

    missing = _scenario(events, "missing_optional")
    assert any(event.username is None and event.source_ip is None for event in missing)
    assert any(event.username == "sam" and event.source_ip is None for event in missing)

    unordered = _scenario(events, "out_of_order")
    assert unordered[0].timestamp > unordered[1].timestamp
    assert [event.timestamp for event in events] != sorted(event.timestamp for event in events)

    duplicates = _scenario(events, "duplicate")
    assert len(duplicates) == 2
    assert duplicates[0] == duplicates[1]
    assert duplicates[0].event_id == "synthetic-dup-1"

    distributed = _scenario(events, "distributed_failures")
    assert {event.event_type for event in distributed} == {EventType.LOGIN_FAILURE}
    distributed_users = {event.username for event in distributed}
    distributed_ips = {event.source_ip for event in distributed}
    assert len(distributed_users) >= 5
    assert len(distributed_ips) >= 3
    assert None not in distributed_users
    assert None not in distributed_ips
    span = max(event.timestamp for event in distributed) - min(event.timestamp for event in distributed)
    assert span <= timedelta(minutes=15)
    for source_ip in distributed_ips:
        names_from_ip = {event.username for event in distributed if event.source_ip == source_ip}
        assert len(names_from_ip) < 5

    usernames = {event.username for event in events if event.username}
    addresses = {event.source_ip for event in events if event.source_ip}
    assert len(usernames) >= 10
    assert len(addresses) >= 8
