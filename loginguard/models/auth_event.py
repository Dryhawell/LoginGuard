"""Normalized authentication event.

An ``AuthEvent`` is the unit later detection rules will count. It stores the
fields needed to explain a login pattern and refuses raw log lines, passwords,
tokens, and cookies.

Required fields are the timestamp and the event type. Username, source IP, and
the other descriptive fields may be missing. A missing optional field stays
``None``. An invalid required field, an invalid IP, or a secret value raises
``AuthEventValidationError`` instead of producing a half-built event.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType

from loginguard.utils.time_utils import TimestampParseError, format_timestamp, parse_timestamp

_MAX_EVENT_ID = 128
_MAX_USERNAME = 256
_MAX_METHOD = 64
_MAX_HOSTNAME = 253
_MAX_APPLICATION = 128
_MAX_FAILURE_REASON = 200
_MAX_RAW_SOURCE = 128
_MAX_ORIGINAL_TYPE = 80
_MAX_METADATA_ITEMS = 16
_MAX_METADATA_KEY = 64
_MAX_METADATA_VALUE = 200

_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "passwd",
        "password",
        "password_hash",
        "pwd",
        "raw_line",
        "raw_log",
        "refresh_token",
        "secret",
        "session",
        "token",
    }
)

_SECRET_LABELS = (
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
)

_EVENT_TYPE_ALIASES = {
    "LOGIN_SUCCESS": "LOGIN_SUCCESS",
    "SUCCESS": "LOGIN_SUCCESS",
    "SUCCESSFUL_LOGIN": "LOGIN_SUCCESS",
    "LOGON_SUCCESS": "LOGIN_SUCCESS",
    "ACCEPTED": "LOGIN_SUCCESS",
    "LOGIN_FAILURE": "LOGIN_FAILURE",
    "FAILURE": "LOGIN_FAILURE",
    "FAILED": "LOGIN_FAILURE",
    "LOGIN_FAILED": "LOGIN_FAILURE",
    "LOGON_FAILURE": "LOGIN_FAILURE",
    "REJECTED": "LOGIN_FAILURE",
    "INVALID_CREDENTIALS": "LOGIN_FAILURE",
    "LOGOUT": "LOGOUT",
    "LOGOFF": "LOGOUT",
    "SIGN_OUT": "LOGOUT",
    "SIGNOUT": "LOGOUT",
    "ACCOUNT_LOCKED": "ACCOUNT_LOCKED",
    "LOCKED": "ACCOUNT_LOCKED",
    "LOCKOUT": "ACCOUNT_LOCKED",
    "ACCOUNT_LOCKOUT": "ACCOUNT_LOCKED",
    "PASSWORD_CHANGE": "PASSWORD_CHANGE",
    "PASSWORD_CHANGED": "PASSWORD_CHANGE",
    "PWD_CHANGE": "PASSWORD_CHANGE",
    "UNKNOWN": "UNKNOWN",
}

_ALLOWED_KEYS = frozenset(
    {
        "application",
        "authentication_method",
        "event_id",
        "event_type",
        "failure_reason",
        "hostname",
        "metadata",
        "original_event_type",
        "raw_source",
        "source_ip",
        "timestamp",
        "username",
    }
)


class EventType(StrEnum):
    """Controlled authentication outcomes.

    ``UNKNOWN`` means the source label was missing from the known set or was
    explicitly unknown. It is not a successful login and it is not evidence
    that the attempt was benign.
    """

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    UNKNOWN = "UNKNOWN"


class AuthEventValidationError(ValueError):
    """Raised when one or more event fields cannot be stored safely."""

    def __init__(self, messages: tuple[str, ...]):
        if not messages:
            raise ValueError("messages must not be empty")
        self.messages = messages
        super().__init__("; ".join(messages))


@dataclass(frozen=True, slots=True, repr=False)
class AuthEvent:
    """One normalized authentication event.

    ``timestamp`` is always timezone-aware UTC after construction. ``metadata``
    is a read-only mapping. The object itself cannot be modified, so a later
    detection pass cannot change evidence in place.

    ``raw_source`` is a short origin label such as a file name. It is not a
    copy of the log line.
    """

    timestamp: datetime
    event_type: EventType
    event_id: str
    username: str | None = None
    source_ip: str | None = None
    authentication_method: str | None = None
    hostname: str | None = None
    application: str | None = None
    failure_reason: str | None = None
    raw_source: str | None = None
    original_event_type: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        """Return a short label without usernames, IP addresses, or reasons.

        Those fields stay on the object for detection. They are omitted here so
        a routine log of the object does not copy identity data.
        """
        return (
            f"AuthEvent(event_id={self.event_id!r}, "
            f"event_type={self.event_type.value}, "
            f"timestamp={format_timestamp(self.timestamp)})"
        )

    def __post_init__(self) -> None:
        errors: list[str] = []
        timestamp = _coerce_timestamp(self.timestamp, errors)
        event_type, derived_original = _coerce_event_type(self.event_type, errors)
        original = _resolve_original(event_type, derived_original, self.original_event_type, errors)
        event_id = _coerce_event_id(self.event_id, errors)
        username = _optional_text("username", self.username, max_length=_MAX_USERNAME, errors=errors)
        source_ip = _coerce_ip(self.source_ip, errors)
        method = _optional_text(
            "authentication_method",
            self.authentication_method,
            max_length=_MAX_METHOD,
            errors=errors,
        )
        if method is not None:
            method = method.lower()
        hostname = _optional_text("hostname", self.hostname, max_length=_MAX_HOSTNAME, errors=errors)
        application = _optional_text(
            "application",
            self.application,
            max_length=_MAX_APPLICATION,
            errors=errors,
        )
        failure_reason = _optional_text(
            "failure_reason",
            self.failure_reason,
            max_length=_MAX_FAILURE_REASON,
            errors=errors,
        )
        raw_source = _optional_text(
            "raw_source",
            self.raw_source,
            max_length=_MAX_RAW_SOURCE,
            errors=errors,
        )
        metadata = _coerce_metadata(self.metadata, errors)
        if errors:
            raise AuthEventValidationError(tuple(errors))

        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "original_event_type", original)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "source_ip", source_ip)
        object.__setattr__(self, "authentication_method", method)
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "application", application)
        object.__setattr__(self, "failure_reason", failure_reason)
        object.__setattr__(self, "raw_source", raw_source)
        object.__setattr__(self, "metadata", metadata)

    @classmethod
    def create(
        cls,
        *,
        timestamp: datetime | str,
        event_type: EventType | str,
        event_id: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        authentication_method: str | None = None,
        hostname: str | None = None,
        application: str | None = None,
        failure_reason: str | None = None,
        raw_source: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> AuthEvent:
        """Build an event from already separated fields.

        ``event_id`` is generated when omitted. The id is random, so two
        identical calls do not produce equal events unless the caller passes
        the same id.
        """
        return cls(
            timestamp=timestamp,  # type: ignore[arg-type]
            event_type=event_type,  # type: ignore[arg-type]
            event_id=event_id if event_id is not None else str(uuid.uuid4()),
            username=username,
            source_ip=source_ip,
            authentication_method=authentication_method,
            hostname=hostname,
            application=application,
            failure_reason=failure_reason,
            raw_source=raw_source,
            metadata=dict(metadata) if metadata is not None else {},
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> AuthEvent:
        """Build an event from a field mapping.

        Unknown fields and secret field names are errors. Optional fields may
        be absent or null. ``event_id`` is generated when it is absent or null.
        """
        if isinstance(data, (str, bytes)) or not isinstance(data, Mapping):
            raise AuthEventValidationError(("record: expected a mapping of event fields",))

        errors: list[str] = []
        for key in data:
            if not isinstance(key, str):
                errors.append("record: field names must be text")
            elif key.lower() in _SENSITIVE_KEYS:
                errors.append(f"{key}: refusing to store a secret field")
            elif key not in _ALLOWED_KEYS:
                errors.append(f"{key}: unexpected field")

        if "event_id" not in data or data["event_id"] is None:
            event_id: object = str(uuid.uuid4())
        else:
            event_id = data["event_id"]
        metadata = data["metadata"] if "metadata" in data else {}
        try:
            event = cls(
                timestamp=data.get("timestamp"),  # type: ignore[arg-type]
                event_type=data.get("event_type"),  # type: ignore[arg-type]
                event_id=event_id,  # type: ignore[arg-type]
                username=data.get("username"),  # type: ignore[arg-type]
                source_ip=data.get("source_ip"),  # type: ignore[arg-type]
                authentication_method=data.get("authentication_method"),  # type: ignore[arg-type]
                hostname=data.get("hostname"),  # type: ignore[arg-type]
                application=data.get("application"),  # type: ignore[arg-type]
                failure_reason=data.get("failure_reason"),  # type: ignore[arg-type]
                raw_source=data.get("raw_source"),  # type: ignore[arg-type]
                original_event_type=data.get("original_event_type"),  # type: ignore[arg-type]
                metadata=metadata,  # type: ignore[arg-type]
            )
        except AuthEventValidationError as exc:
            errors.extend(exc.messages)
            event = None
        if errors:
            raise AuthEventValidationError(tuple(errors))
        if event is None:
            raise AuthEventValidationError(("record: could not build an event",))
        return event

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready mapping.

        Null optional fields are omitted. The timestamp is UTC ISO 8601 with
        a ``Z`` suffix. Secret fields cannot appear because construction
        already rejected them.
        """
        payload: dict[str, object] = {
            "event_id": self.event_id,
            "timestamp": format_timestamp(self.timestamp),
            "event_type": self.event_type.value,
        }
        _put_if_present(payload, "username", self.username)
        _put_if_present(payload, "source_ip", self.source_ip)
        _put_if_present(payload, "authentication_method", self.authentication_method)
        _put_if_present(payload, "hostname", self.hostname)
        _put_if_present(payload, "application", self.application)
        _put_if_present(payload, "failure_reason", self.failure_reason)
        _put_if_present(payload, "raw_source", self.raw_source)
        _put_if_present(payload, "original_event_type", self.original_event_type)
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


def normalize_event_type(value: object) -> EventType:
    """Map a source label to a canonical event type.

    Unrecognized non-empty labels become ``EventType.UNKNOWN``. Blank values
    raise, because a missing type and an explicit unknown label are different.
    The original unrecognized label is not returned here; ``AuthEvent`` keeps
    it on ``original_event_type``.
    """
    errors: list[str] = []
    event_type, _original = _interpret_event_type(value, errors)
    if errors:
        raise AuthEventValidationError(tuple(errors))
    return event_type


def _interpret_event_type(value: object, errors: list[str]) -> tuple[EventType, str | None]:
    if isinstance(value, EventType):
        return value, None
    if value is None:
        errors.append("event_type: a value is required")
        return EventType.UNKNOWN, None
    if not isinstance(value, str):
        errors.append("event_type: expected text")
        return EventType.UNKNOWN, None
    trimmed = value.strip()
    if not trimmed:
        errors.append("event_type: a value is required")
        return EventType.UNKNOWN, None
    token = trimmed.upper().replace("-", "_").replace(" ", "_")
    while "__" in token:
        token = token.replace("__", "_")
    token = token.strip("_")
    canonical = _EVENT_TYPE_ALIASES.get(token)
    if canonical is None:
        if _has_control_char(trimmed):
            errors.append("event_type: control characters are not allowed")
            return EventType.UNKNOWN, None
        if _contains_secret_assignment(trimmed):
            errors.append("event_type: refusing to store a secret assignment")
            return EventType.UNKNOWN, None
        if len(trimmed) > _MAX_ORIGINAL_TYPE:
            errors.append(
                f"event_type: unrecognized label is longer than {_MAX_ORIGINAL_TYPE} characters"
            )
            return EventType.UNKNOWN, None
        return EventType.UNKNOWN, trimmed
    return EventType(canonical), None


def _coerce_timestamp(value: object, errors: list[str]) -> datetime:
    try:
        return parse_timestamp(value)
    except TimestampParseError as exc:
        errors.append(f"timestamp: {exc}")
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _coerce_event_type(value: object, errors: list[str]) -> tuple[EventType, str | None]:
    return _interpret_event_type(value, errors)


def _resolve_original(
    event_type: EventType,
    derived_original: str | None,
    supplied: object,
    errors: list[str],
) -> str | None:
    if event_type is not EventType.UNKNOWN:
        return None
    if derived_original is not None:
        return derived_original
    return _optional_text(
        "original_event_type",
        supplied,
        max_length=_MAX_ORIGINAL_TYPE,
        errors=errors,
    )


def _coerce_event_id(value: object, errors: list[str]) -> str:
    text = _optional_text("event_id", value, max_length=_MAX_EVENT_ID, errors=errors)
    if text is None:
        if not any(message.startswith("event_id:") for message in errors):
            errors.append("event_id: a value is required")
        return "invalid"
    return text


def _coerce_ip(value: object, errors: list[str]) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        errors.append("source_ip: expected text or null")
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        errors.append("source_ip: not a valid IP address")
        return None


def _coerce_metadata(value: object, errors: list[str]) -> Mapping[str, str]:
    if value is None:
        return MappingProxyType({})
    if isinstance(value, (str, bytes)) or not isinstance(value, Mapping):
        errors.append("metadata: expected a mapping of text to text")
        return MappingProxyType({})
    if len(value) > _MAX_METADATA_ITEMS:
        errors.append(f"metadata: at most {_MAX_METADATA_ITEMS} entries are allowed")
        return MappingProxyType({})

    cleaned: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            errors.append("metadata: keys must be non-empty text")
            continue
        key_text = key.strip()
        if key_text.lower() in _SENSITIVE_KEYS:
            errors.append(f"metadata.{key_text}: refusing to store a secret field")
            continue
        if _has_control_char(key_text) or len(key_text) > _MAX_METADATA_KEY:
            errors.append("metadata: a key is empty, too long, or contains control characters")
            continue
        if not isinstance(item, str):
            errors.append(f"metadata.{key_text}: expected text")
            continue
        before = len(errors)
        text = _optional_text(
            f"metadata.{key_text}",
            item,
            max_length=_MAX_METADATA_VALUE,
            errors=errors,
        )
        if text is None and len(errors) == before:
            errors.append(f"metadata.{key_text}: expected non-empty text")
            continue
        if text is not None:
            cleaned[key_text] = text
    return MappingProxyType({key: cleaned[key] for key in sorted(cleaned)})


def _optional_text(field_name: str, value: object, *, max_length: int, errors: list[str]) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        errors.append(f"{field_name}: expected text or null")
        return None
    text = value.strip()
    if not text:
        return None
    if _has_control_char(text):
        errors.append(f"{field_name}: control characters are not allowed")
        return None
    if len(text) > max_length:
        errors.append(f"{field_name}: longer than {max_length} characters")
        return None
    if _contains_secret_assignment(text):
        errors.append(f"{field_name}: refusing to store a secret assignment")
        return None
    return text


def _contains_secret_assignment(value: str) -> bool:
    """Return whether text looks like ``password=...`` or ``bearer <token>``.

    A failure reason such as "password expired" does not match, because the
    word is not followed by an assignment.
    """
    lowered = value.lower()
    for label in _SECRET_LABELS:
        start = 0
        while True:
            index = lowered.find(label, start)
            if index < 0:
                break
            after = lowered[index + len(label) :].lstrip(" \t")
            if after.startswith(("=", ":")):
                return True
            if label == "bearer" and after[:1].isalnum():
                return True
            start = index + len(label)
    return False


def _has_control_char(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _put_if_present(payload: dict[str, object], key: str, value: str | None) -> None:
    if value is not None:
        payload[key] = value
