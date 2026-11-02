"""Local JSON storage for alerts.

The alert file is one document, replaced as a whole. The write goes to a
temporary file in the same directory and then replaces the destination, so a
failed write keeps the previous document. Other files in that directory are
left alone.

A missing file loads as an empty collection. Malformed JSON, a document with
a different schema, and an invalid alert fail the whole load. The error does
not quote the file body.

The document shape is ``{"schema": "loginguard.alerts.v1", "alerts": [...]}``.
There is no locking. Two overlapping saves can lose one of the writes. This
is not a database, and it does not keep alert history between saves.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from loginguard.models.alert import Alert, AlertValidationError
from loginguard.storage.errors import StorageError
from loginguard.storage.files import replace_text
from loginguard.utils.time_utils import TimestampParseError, format_timestamp, parse_timestamp

SCHEMA = "loginguard.alerts.v1"

_FIELDS = (
    "alert_id",
    "rule_id",
    "timestamp",
    "title",
    "severity",
    "description",
    "evidence",
    "recommended_action",
    "affected_username",
    "source_ip",
    "first_event_time",
    "last_event_time",
    "related_event_ids",
    "status",
)
_REQUIRED = (
    "alert_id",
    "rule_id",
    "timestamp",
    "title",
    "severity",
    "description",
    "evidence",
    "recommended_action",
    "status",
)
_OPTIONAL = (
    "affected_username",
    "source_ip",
    "first_event_time",
    "last_event_time",
)
_SECRET_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "cookie",
        "passwd",
        "password",
        "pwd",
        "secret",
        "session",
        "token",
    }
)


class AlertStore:
    """Read and replace the alert document at one path."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def save(self, alerts: Sequence[Alert]) -> None:
        """Replace the document with ``alerts``.

        An empty sequence writes a valid document with no alerts. The caller's
        sequence is not modified.

        Raises:
            TypeError: ``alerts`` is not a sequence of ``Alert`` values.
            StorageError: the file or its directory cannot be written.
        """
        replace_text(self.path, render_alerts(alerts))

    def load(self) -> tuple[Alert, ...]:
        """Return the alerts in the document.

        A missing file returns an empty tuple.

        Raises:
            StorageError: the file cannot be read, the JSON is malformed, or
                an alert record cannot be stored safely.
        """
        if not self.path.exists():
            return ()
        if self.path.is_dir():
            raise StorageError(f"{self.path.name}: expected a file")
        try:
            text = self.path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise StorageError(f"{self.path.name}: file is not valid UTF-8") from None
        except PermissionError:
            raise StorageError(f"{self.path.name}: permission denied") from None
        except OSError:
            raise StorageError(f"{self.path.name}: unable to read the file") from None
        return alerts_from_document(text)


def render_alerts(alerts: Sequence[Alert]) -> str:
    """Return the alert document. An empty sequence is a valid empty document."""
    records = _require_alerts(alerts)
    document = {
        "schema": SCHEMA,
        "alerts": [alert_to_dict(alert) for alert in records],
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def alert_to_dict(alert: Alert) -> dict[str, object]:
    """Return a JSON-ready mapping. Null optional fields are omitted."""
    payload: dict[str, object] = {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "timestamp": format_timestamp(alert.timestamp),
        "title": alert.title,
        "severity": alert.severity.value,
        "description": alert.description,
        "evidence": alert.evidence,
        "recommended_action": alert.recommended_action,
        "related_event_ids": list(alert.related_event_ids),
        "status": alert.status.value,
    }
    if alert.affected_username is not None:
        payload["affected_username"] = alert.affected_username
    if alert.source_ip is not None:
        payload["source_ip"] = alert.source_ip
    if alert.first_event_time is not None:
        payload["first_event_time"] = format_timestamp(alert.first_event_time)
    if alert.last_event_time is not None:
        payload["last_event_time"] = format_timestamp(alert.last_event_time)
    return payload


def alerts_from_document(text: str) -> tuple[Alert, ...]:
    """Parse one alert document.

    Raises:
        StorageError: the text is not the ``loginguard.alerts.v1`` document.
    """
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        raise StorageError("malformed JSON") from None
    if not isinstance(decoded, dict) or decoded.get("schema") != SCHEMA:
        raise StorageError(f"alert file schema is not {SCHEMA}")
    alerts = decoded.get("alerts")
    if not isinstance(alerts, list):
        raise StorageError("alerts: expected a list")
    unexpected = set(decoded) - {"schema", "alerts"}
    if unexpected:
        raise StorageError("alert file contains an unexpected field")
    return tuple(_alert_at(index, item) for index, item in enumerate(alerts))


def _alert_at(index: int, item: object) -> Alert:
    try:
        return alert_from_mapping(item)
    except (AlertValidationError, TimestampParseError, StorageError) as exc:
        raise StorageError(f"alerts[{index}]: {exc}") from None


def alert_from_mapping(data: object) -> Alert:
    """Build an alert from one stored object.

    Raises:
        StorageError: the object is not a mapping of known alert fields.
        AlertValidationError: a field cannot be stored safely.
        TimestampParseError: a timestamp is missing or not timezone-aware.
    """
    if isinstance(data, (str, bytes)) or not isinstance(data, Mapping):
        raise StorageError("expected a mapping of alert fields")
    for key in data:
        if not isinstance(key, str):
            raise StorageError("field names must be text")
        if key.lower() in _SECRET_KEYS:
            raise StorageError("refusing to store a secret field")
        if key not in _FIELDS:
            raise StorageError("unexpected field")
    missing = [name for name in _REQUIRED if name not in data or data[name] is None]
    if missing:
        raise StorageError("a required field is missing")
    times = {
        name: parse_timestamp(data[name])
        for name in ("timestamp", "first_event_time", "last_event_time")
        if name in data and data[name] is not None
    }
    optional = {name: data[name] for name in _OPTIONAL if name in data}
    return Alert(
        alert_id=data["alert_id"],  # type: ignore[arg-type]
        rule_id=data["rule_id"],  # type: ignore[arg-type]
        timestamp=times["timestamp"],
        title=data["title"],  # type: ignore[arg-type]
        severity=data["severity"],  # type: ignore[arg-type]
        description=data["description"],  # type: ignore[arg-type]
        evidence=data["evidence"],  # type: ignore[arg-type]
        recommended_action=data["recommended_action"],  # type: ignore[arg-type]
        related_event_ids=data.get("related_event_ids", ()),  # type: ignore[arg-type]
        status=data["status"],  # type: ignore[arg-type]
        affected_username=optional.get("affected_username"),  # type: ignore[arg-type]
        source_ip=optional.get("source_ip"),  # type: ignore[arg-type]
        first_event_time=times.get("first_event_time"),
        last_event_time=times.get("last_event_time"),
    )


def _require_alerts(alerts: Sequence[Alert]) -> tuple[Alert, ...]:
    if isinstance(alerts, (str, bytes)) or not isinstance(alerts, Sequence):
        raise TypeError("alerts must be a sequence of Alert values")
    records = tuple(alerts)
    for alert in records:
        if not isinstance(alert, Alert):
            raise TypeError("alerts must be a sequence of Alert values")
    return records
