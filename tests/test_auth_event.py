"""AuthEvent validation, event-type normalization, and safe field handling."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from loginguard.models import AuthEvent, AuthEventValidationError, EventType, normalize_event_type

_TS = "2026-09-10T10:00:00Z"


def _event(**overrides: object) -> AuthEvent:
    values: dict[str, object] = {
        "timestamp": _TS,
        "event_type": "LOGIN_FAILURE",
        "event_id": "evt-1",
        "username": "alice",
        "source_ip": "192.0.2.10",
    }
    values.update(overrides)
    return AuthEvent.create(**values)  # type: ignore[arg-type]


def test_minimal_event_keeps_required_fields_and_leaves_optional_fields_empty() -> None:
    event = AuthEvent.create(timestamp=_TS, event_type="LOGIN_FAILURE", event_id="evt-1")

    assert event.timestamp == datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
    assert event.event_type is EventType.LOGIN_FAILURE
    assert event.username is None
    assert event.source_ip is None
    assert event.failure_reason is None
    assert event.metadata == {}


def test_same_instant_with_different_offsets_compares_equal() -> None:
    later_offset = _event(timestamp="2026-09-10T13:00:00+03:00")
    utc = _event(timestamp="2026-09-10T10:00:00Z")

    assert later_offset == utc


def test_event_type_aliases_normalize_to_one_set() -> None:
    samples = {
        "login_success": EventType.LOGIN_SUCCESS,
        "LOGON SUCCESS": EventType.LOGIN_SUCCESS,
        "login-failure": EventType.LOGIN_FAILURE,
        "invalid_credentials": EventType.LOGIN_FAILURE,
        "logoff": EventType.LOGOUT,
        "account lockout": EventType.ACCOUNT_LOCKED,
        "password-changed": EventType.PASSWORD_CHANGE,
        "unknown": EventType.UNKNOWN,
    }

    for label, expected in samples.items():
        assert normalize_event_type(label) is expected


def test_unrecognized_label_is_unknown_and_the_original_text_is_kept() -> None:
    event = _event(event_type="  Kerberos_Error  ")

    assert event.event_type is EventType.UNKNOWN
    assert event.original_event_type == "Kerberos_Error"


def test_explicit_unknown_does_not_invent_an_original_label() -> None:
    event = _event(event_type=EventType.UNKNOWN)

    assert event.original_event_type is None


def test_blank_event_type_is_rejected() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        _event(event_type="  ")

    assert "event_type: a value is required" in exc.value.messages


def test_missing_required_fields_are_reported_together() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        AuthEvent.from_mapping({})

    assert "timestamp: A timestamp value is required." in exc.value.messages
    assert "event_type: a value is required" in exc.value.messages


def test_blank_optional_text_becomes_none_and_username_case_is_preserved() -> None:
    event = _event(username="  Ayşe  ", source_ip="  ", hostname="")

    assert event.username == "Ayşe"
    assert event.source_ip is None
    assert event.hostname is None


def test_invalid_ip_is_rejected_and_ipv6_is_canonical() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        _event(source_ip="192.0.2.010")

    assert exc.value.messages == ("source_ip: not a valid IP address",)

    event = _event(source_ip="2001:0DB8:0000:0000:0000:0000:0000:0001")
    assert event.source_ip == "2001:db8::1"


def test_ordinary_failure_reason_is_kept_and_secret_assignment_is_refused() -> None:
    event = _event(failure_reason="password expired")
    assert event.failure_reason == "password expired"

    with pytest.raises(AuthEventValidationError) as exc:
        _event(failure_reason="password = hunter2")

    assert "hunter2" not in str(exc.value)
    assert "failure_reason: refusing to store a secret assignment" in exc.value.messages


def test_secret_metadata_and_top_level_secret_fields_are_refused() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        _event(metadata={"password": "hunter2", "site": "lab"})

    assert "hunter2" not in str(exc.value)
    assert "metadata.password: refusing to store a secret field" in exc.value.messages

    with pytest.raises(AuthEventValidationError) as exc_top:
        AuthEvent.from_mapping(
            {
                "timestamp": _TS,
                "event_type": "LOGIN_FAILURE",
                "password": "hunter2",
            }
        )

    assert "hunter2" not in str(exc_top.value)
    assert "password: refusing to store a secret field" in exc_top.value.messages


def test_metadata_is_copied_and_read_only() -> None:
    source = {"site": "lab"}
    event = _event(metadata=source)
    source["site"] = "changed"

    assert event.metadata["site"] == "lab"
    with pytest.raises(TypeError):
        event.metadata["site"] = "other"  # type: ignore[index]


def test_event_fields_are_frozen() -> None:
    event = _event()

    with pytest.raises(FrozenInstanceError):
        event.username = "bob"  # type: ignore[misc]


def test_authentication_method_is_lowercased() -> None:
    event = _event(authentication_method=" Password ")

    assert event.authentication_method == "password"


def test_generated_ids_differ_when_the_caller_does_not_supply_one() -> None:
    first = AuthEvent.create(timestamp=_TS, event_type="LOGIN_SUCCESS")
    second = AuthEvent.create(timestamp=_TS, event_type="LOGIN_SUCCESS")

    assert first.event_id != second.event_id


def test_round_trip_preserves_the_normalized_event() -> None:
    event = _event(
        authentication_method="NTLM",
        hostname="DC01",
        application="vpn",
        failure_reason="invalid credentials",
        raw_source="data/samples/auth_logs.jsonl",
        metadata={"site": "lab"},
    )

    restored = AuthEvent.from_mapping(event.to_dict())

    assert restored == event
    assert restored.to_dict()["timestamp"] == "2026-09-10T10:00:00Z"


def test_unknown_original_label_survives_a_round_trip() -> None:
    event = _event(event_type="Kerberos_Error")

    restored = AuthEvent.from_mapping(event.to_dict())

    assert restored.event_type is EventType.UNKNOWN
    assert restored.original_event_type == "Kerberos_Error"


def test_unexpected_field_and_invalid_timestamp_are_both_reported() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        AuthEvent.from_mapping(
            {
                "timestamp": "yesterday",
                "event_type": "LOGIN_FAILURE",
                "note": "not a field",
            }
        )

    joined = " ".join(exc.value.messages)
    assert "note: unexpected field" in joined
    assert "timestamp:" in joined
    assert "yesterday" in joined


def test_non_string_event_id_is_rejected() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        AuthEvent.from_mapping(
            {
                "timestamp": _TS,
                "event_type": "LOGIN_FAILURE",
                "event_id": 15,
            }
        )

    assert "event_id: expected text or null" in exc.value.messages


def test_control_characters_and_overlong_source_labels_are_rejected() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        _event(username="alice\nroot")

    assert "username: control characters are not allowed" in exc.value.messages

    with pytest.raises(AuthEventValidationError) as exc_source:
        _event(raw_source="x" * 129)

    assert "raw_source: longer than 128 characters" in exc_source.value.messages


def test_naive_timestamp_on_an_event_is_rejected() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        _event(timestamp=datetime(2026, 9, 10, 10, 0))

    assert "not assumed to be UTC" in str(exc.value)


def test_repr_omits_identity_fields() -> None:
    event = _event(failure_reason="invalid credentials")
    text = repr(event)

    assert "evt-1" in text
    assert "LOGIN_FAILURE" in text
    assert "alice" not in text
    assert "192.0.2.10" not in text
    assert "invalid credentials" not in text


def test_unrecognized_event_type_cannot_carry_a_secret() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        _event(event_type="password=hunter2")

    assert "hunter2" not in str(exc.value)
    assert "event_type: refusing to store a secret assignment" in exc.value.messages


def test_non_mapping_record_is_rejected() -> None:
    with pytest.raises(AuthEventValidationError) as exc:
        AuthEvent.from_mapping(["not", "a", "record"])  # type: ignore[arg-type]

    assert exc.value.messages == ("record: expected a mapping of event fields",)


def test_documented_offset_example_matches_utc() -> None:
    event = AuthEvent.from_mapping(
        {
            "timestamp": "2026-09-10T10:00:00Z",
            "username": "alice",
            "source_ip": "192.0.2.10",
            "event_type": "LOGIN_FAILURE",
            "event_id": "sample-1",
        }
    )
    shifted = AuthEvent.create(
        timestamp=datetime(2026, 9, 10, 12, 0, tzinfo=timezone(timedelta(hours=2))),
        event_type="failure",
        event_id="sample-1",
        username="alice",
        source_ip="192.0.2.10",
    )

    assert event.event_type is EventType.LOGIN_FAILURE
    assert shifted.timestamp == event.timestamp
