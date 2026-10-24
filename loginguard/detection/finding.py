"""A structured detection finding.

A finding means a rule saw a pattern worth investigating. It does not prove
that an attack occurred and it does not compromise an account.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum

_MAX_TITLE = 120
_MAX_TEXT = 500
_MAX_ID = 128
_MAX_RELATED = 100
_MAX_USERNAME = 256

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


class Severity(StrEnum):
    """How urgently a finding should be reviewed.

    ``CRITICAL`` is reserved for a later, documented exceptional condition.
    The foundation does not emit it. Ordinary rules stay within INFO through HIGH.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingValidationError(ValueError):
    """Raised when a finding cannot be stored safely."""

    def __init__(self, messages: tuple[str, ...]):
        if not messages:
            raise ValueError("messages must not be empty")
        self.messages = messages
        super().__init__("; ".join(messages))


@dataclass(frozen=True, slots=True, repr=False)
class Finding:
    """Explainable output of one rule evaluation.

    ``description`` states why the finding exists, including the observed count,
    the threshold, and the time window the rule used. ``affected_username``,
    ``affected_usernames``, and ``source_ip`` stay on the object for later
    triage. ``repr`` omits usernames and source addresses.
    """

    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    observed_count: int
    threshold: int
    window: timedelta
    related_event_ids: tuple[str, ...] = ()
    first_event_time: datetime | None = None
    last_event_time: datetime | None = None
    affected_username: str | None = None
    affected_usernames: tuple[str, ...] = ()
    source_ip: str | None = None

    def __repr__(self) -> str:
        """Return a short label without usernames or source addresses."""
        return (
            f"Finding(finding_id={self.finding_id!r}, rule_id={self.rule_id!r}, "
            f"severity={self.severity.value}, observed_count={self.observed_count})"
        )

    def __post_init__(self) -> None:
        errors: list[str] = []
        finding_id = _required_text("finding_id", self.finding_id, _MAX_ID, errors)
        rule_id = _required_text("rule_id", self.rule_id, _MAX_ID, errors)
        title = _required_text("title", self.title, _MAX_TITLE, errors)
        description = _required_text("description", self.description, _MAX_TEXT, errors)
        recommendation = _required_text("recommendation", self.recommendation, _MAX_TEXT, errors)
        severity = _coerce_severity(self.severity, errors)
        observed = _non_negative_int("observed_count", self.observed_count, errors)
        threshold = _positive_int("threshold", self.threshold, errors)
        window = _positive_window(self.window, errors)
        related = _related_ids(self.related_event_ids, errors)
        first = _aware_time("first_event_time", self.first_event_time, errors)
        last = _aware_time("last_event_time", self.last_event_time, errors)
        username = _optional_text("affected_username", self.affected_username, _MAX_USERNAME, errors)
        usernames = _usernames(self.affected_usernames, errors)
        source_ip = _optional_ip(self.source_ip, errors)
        if first is not None and last is not None and last < first:
            errors.append("last_event_time: earlier than first_event_time")
        if errors:
            raise FindingValidationError(tuple(errors))

        object.__setattr__(self, "finding_id", finding_id)
        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "recommendation", recommendation)
        object.__setattr__(self, "observed_count", observed)
        object.__setattr__(self, "threshold", threshold)
        object.__setattr__(self, "window", window)
        object.__setattr__(self, "related_event_ids", related)
        object.__setattr__(self, "first_event_time", first)
        object.__setattr__(self, "last_event_time", last)
        object.__setattr__(self, "affected_username", username)
        object.__setattr__(self, "affected_usernames", usernames)
        object.__setattr__(self, "source_ip", source_ip)


def _coerce_severity(value: object, errors: list[str]) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.strip().upper())
        except ValueError:
            errors.append("severity: expected INFO, LOW, MEDIUM, HIGH, or CRITICAL")
            return Severity.INFO
    errors.append("severity: expected a Severity value")
    return Severity.INFO


def _required_text(name: str, value: object, max_length: int, errors: list[str]) -> str:
    text = _optional_text(name, value, max_length, errors)
    if text is None and not any(message.startswith(f"{name}:") for message in errors):
        errors.append(f"{name}: a value is required")
        return "invalid"
    return text or "invalid"


def _optional_text(name: str, value: object, max_length: int, errors: list[str]) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        errors.append(f"{name}: expected text")
        return None
    text = value.strip()
    if not text:
        return None
    if _has_control_char(text):
        errors.append(f"{name}: control characters are not allowed")
        return None
    if len(text) > max_length:
        errors.append(f"{name}: longer than {max_length} characters")
        return None
    if _contains_secret_assignment(text):
        errors.append(f"{name}: refusing to store a secret assignment")
        return None
    return text


def _non_negative_int(name: str, value: object, errors: list[str]) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(f"{name}: expected an integer of zero or greater")
        return 0
    return value


def _positive_int(name: str, value: object, errors: list[str]) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        errors.append(f"{name}: expected a positive integer")
        return 1
    return value


def _positive_window(value: object, errors: list[str]) -> timedelta:
    if not isinstance(value, timedelta) or value <= timedelta(0):
        errors.append("window: expected a positive duration")
        return timedelta(minutes=1)
    return value


def _aware_time(name: str, value: object, errors: list[str]) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        errors.append(f"{name}: expected a timezone-aware datetime")
        return None
    offset = value.tzinfo.utcoffset(value) if value.tzinfo is not None else None
    if offset is None:
        errors.append(f"{name}: naive timestamps are rejected and are not assumed to be UTC")
        return None
    return value.astimezone(timezone.utc)


def _related_ids(value: object, errors: list[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, tuple | list):
        errors.append("related_event_ids: expected a sequence of event ids")
        return ()
    if len(value) > _MAX_RELATED:
        errors.append(f"related_event_ids: at most {_MAX_RELATED} ids are allowed")
        return ()
    cleaned: list[str] = []
    for item in value:
        text = _optional_text("related_event_ids", item, _MAX_ID, errors)
        if text is None and not any(message.startswith("related_event_ids:") for message in errors):
            errors.append("related_event_ids: ids must be non-empty text")
            return ()
        if text is not None:
            cleaned.append(text)
    return tuple(cleaned)


def _usernames(value: object, errors: list[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, tuple | list):
        errors.append("affected_usernames: expected a sequence of usernames")
        return ()
    if len(value) > _MAX_RELATED:
        errors.append(f"affected_usernames: at most {_MAX_RELATED} usernames are allowed")
        return ()
    cleaned: list[str] = []
    for item in value:
        text = _optional_text("affected_usernames", item, _MAX_USERNAME, errors)
        if text is None:
            if not any(message.startswith("affected_usernames:") for message in errors):
                errors.append("affected_usernames: usernames must be non-empty text")
            return ()
        cleaned.append(text)
    return tuple(cleaned)


def _optional_ip(value: object, errors: list[str]) -> str | None:
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


def _contains_secret_assignment(value: str) -> bool:
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
