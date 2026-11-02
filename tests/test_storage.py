"""Local JSON storage for events and alerts.

Paths stay inside pytest's temporary directory. Nothing here reads the clock
or the network, and nothing writes into data/events or data/reports.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loginguard.models import AlertStatus, AuthEvent
from loginguard.models.alert import Alert
from loginguard.detection.finding import Severity
from loginguard.storage import SCHEMA, AlertStore, EventStore, StorageError

_WHEN = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
_LATER = datetime(2026, 9, 10, 10, 4, tzinfo=timezone.utc)
_SECRET = "stored-secret-value"


def _event(event_id: str, **overrides: object) -> AuthEvent:
    values: dict[str, object] = {
        "event_id": event_id,
        "timestamp": "2026-09-10T10:00:00Z",
        "event_type": "LOGIN_FAILURE",
        "username": "alice",
        "source_ip": "192.0.2.10",
        "raw_source": "events.jsonl",
    }
    values.update(overrides)
    return AuthEvent.create(**values)  # type: ignore[arg-type]


def _alert(alert_id: str = "alert-1") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="brute-force-same-account",
        timestamp=_LATER,
        title="Repeated failed logins",
        severity=Severity.MEDIUM,
        description="Repeated failed logins. A finding is a suspicion, not proof of compromise.",
        evidence="Rule brute-force-same-account observed 5 against a threshold of 5 inside 5 minutes.",
        recommended_action="Review the account activity with the owner.",
        affected_username="alice",
        source_ip="192.0.2.10",
        first_event_time=_WHEN,
        last_event_time=_LATER,
        related_event_ids=("evt-1", "evt-2"),
        status=AlertStatus.OPEN,
    )


def test_events_round_trip_and_a_second_append_keeps_the_first(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events" / "events.jsonl")
    first = _event("evt-1")
    second = _event("evt-2", timestamp="2026-09-10T10:01:00Z")

    assert store.append((first,)) == 1
    assert store.append((second,)) == 1

    loaded = store.load()
    assert loaded.issues == ()
    assert [event.event_id for event in loaded.events] == ["evt-1", "evt-2"]
    assert loaded.events[0] == first
    assert loaded.events[1] == second


def test_missing_event_file_loads_as_empty_and_empty_append_creates_nothing(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = EventStore(path)

    loaded = store.load()

    assert loaded.events == ()
    assert loaded.issues == ()
    assert store.append(()) == 0
    assert not path.exists()


def test_a_malformed_event_line_does_not_hide_its_neighbors_or_the_secret(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps(_event("evt-1").to_dict()),
                f'{{"password":"{_SECRET}"}}',
                "{not-json",
                json.dumps(_event("evt-2").to_dict()),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    loaded = EventStore(path).load()
    text = " ".join(str(issue) for issue in loaded.issues)

    assert [event.event_id for event in loaded.events] == ["evt-1", "evt-2"]
    assert len(loaded.issues) == 2
    assert _SECRET not in text


def test_duplicate_event_ids_stay_in_the_file(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.jsonl")
    store.append((_event("same"), _event("same", timestamp="2026-09-10T10:02:00Z")))

    loaded = store.load()

    assert [event.event_id for event in loaded.events] == ["same", "same"]


def test_event_store_refuses_a_directory_and_does_not_touch_a_sibling(tmp_path: Path) -> None:
    directory = tmp_path / "events.jsonl"
    directory.mkdir()
    sibling = tmp_path / "notes.txt"
    sibling.write_text("keep", encoding="utf-8")

    with pytest.raises(StorageError) as exc:
        EventStore(directory).append((_event("evt-1"),))

    assert str(exc.value) == "events.jsonl: expected a file"
    assert sibling.read_text(encoding="utf-8") == "keep"


def test_append_refuses_a_file_that_is_not_utf8(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(StorageError) as exc:
        EventStore(path).append((_event("evt-1"),))

    assert "not valid UTF-8" in str(exc.value)
    assert path.read_bytes() == b"\xff\xfe"


def test_alerts_round_trip_and_a_missing_file_is_empty(tmp_path: Path) -> None:
    path = tmp_path / "reports" / "alerts.json"
    store = AlertStore(path)
    alert = _alert()

    assert store.load() == ()
    store.save((alert,))
    loaded = store.load()

    assert loaded == (alert,)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["schema"] == SCHEMA
    assert "alice" not in repr(loaded[0])


def test_saving_alerts_replaces_only_that_file(tmp_path: Path) -> None:
    store = AlertStore(tmp_path / "alerts.json")
    sibling = tmp_path / "analysis_summary.json"
    sibling.write_text("{}\n", encoding="utf-8")
    store.save((_alert("alert-1"),))
    store.save((_alert("alert-2"),))

    assert [alert.alert_id for alert in store.load()] == ["alert-2"]
    assert sibling.read_text(encoding="utf-8") == "{}\n"


def test_a_failed_replace_keeps_the_previous_alert_document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = AlertStore(tmp_path / "alerts.json")
    store.save((_alert("alert-1"),))
    original = store.path.read_text(encoding="utf-8")

    def fail_replace(source: str | Path, destination: str | Path) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("loginguard.storage.files.os.replace", fail_replace)

    with pytest.raises(StorageError):
        store.save((_alert("alert-2"),))

    assert store.path.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob("*.tmp")) == []
    assert store.load()[0].alert_id == "alert-1"


def test_malformed_alert_json_does_not_quote_the_body(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    path.write_text("{not-json " + _SECRET, encoding="utf-8")

    with pytest.raises(StorageError) as exc:
        AlertStore(path).load()

    assert str(exc.value) == "malformed JSON"
    assert _SECRET not in str(exc.value)


def test_alert_document_rejects_a_secret_field_and_the_wrong_schema(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps({"schema": SCHEMA, "alerts": [{"password": _SECRET}]}), encoding="utf-8")

    with pytest.raises(StorageError) as exc:
        AlertStore(path).load()

    assert _SECRET not in str(exc.value)
    path.write_text(json.dumps([{"alert_id": "alert-1"}]), encoding="utf-8")
    with pytest.raises(StorageError) as schema_error:
        AlertStore(path).load()
    assert SCHEMA in str(schema_error.value)


def test_sequences_must_be_the_right_type(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        EventStore(tmp_path / "events.jsonl").append("nope")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        AlertStore(tmp_path / "alerts.json").save((_alert(), "nope"))  # type: ignore[arg-type]
