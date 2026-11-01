"""An alert built from a detection finding.

An alert is the triage view of one finding. It records why the rule spoke:
the rule id, the observed count, the threshold, the window, and the evidence.
It does not detect a new pattern, and it does not prove that an account was
compromised. A finding remains a suspicion.

``status`` is ``OPEN``. LoginGuard does not assign, acknowledge, or close
alerts. Correlation and deduplication are a later phase, so one finding
becomes one alert even when two findings share events.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum

from loginguard.detection.finding import Finding, Severity

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


class AlertStatus(StrEnum):
    """The only review state stored on an alert.

    ``OPEN`` means the alert was recorded. There is no assignment,
    acknowledgement, escalation, or closure in this phase.
    """

    OPEN = "OPEN"


class AlertValidationError(ValueError):
    """Raised when an alert cannot be stored safely."""

    def __init__(self, messages: tuple[str, ...]):
        if not messages:
            raise ValueError("messages must not be empty")
        self.messages = messages
        super().__init__("; ".join(messages))


@dataclass(frozen=True, slots=True, repr=False)
class Alert:
    """Explainable triage record for one finding.

    ``description`` and ``evidence`` state the rule id, the observed count,
    the threshold, and the window. ``affected_username`` and ``source_ip``
    stay on the object for an investigator. ``repr`` omits both. The object
    does not store passwords, tokens, cookies, or raw log lines.

    ``severity`` is the severity the detection rule already chose. This model
    does not raise it. ``CRITICAL`` exists on the shared scale and no current
    rule emits it.
    """

    alert_id: str
    rule_id: str
    timestamp: datetime
    title: str
    severity: Severity
    description: str
    evidence: str
    recommended_action: str
    affected_username: str | None = None
    source_ip: str | None = None
    first_event_time: datetime | None = None
    last_event_time: datetime | None = None
    related_event_ids: tuple[str, ...] = ()
    status: AlertStatus = AlertStatus.OPEN

    def __repr__(self) -> str:
        """Return a short label without usernames or source addresses."""
        return (
            f"Alert(alert_id={self.alert_id!r}, rule_id={self.rule_id!r}, "
            f"severity={self.severity.value}, status={self.status.value})"
        )

    def __post_init__(self) -> None:
        errors: list[str] = []
        alert_id = _required_text("alert_id", self.alert_id, _MAX_ID, errors)
        rule_id = _required_text("rule_id", self.rule_id, _MAX_ID, errors)
        timestamp = _required_time("timestamp", self.timestamp, errors)
        title = _required_text("title", self.title, _MAX_TITLE, errors)
        description = _required_text("description", self.description, _MAX_TEXT, errors)
        evidence = _required_text("evidence", self.evidence, _MAX_TEXT, errors)
        action = _required_text("recommended_action", self.recommended_action, _MAX_TEXT, errors)
        severity = _coerce_severity(self.severity, errors)
        username = _optional_text("affected_username", self.affected_username, _MAX_USERNAME, errors)
        source_ip = _optional_ip(self.source_ip, errors)
        first = _aware_time("first_event_time", self.first_event_time, errors)
        last = _aware_time("last_event_time", self.last_event_time, errors)
        related = _related_ids(self.related_event_ids, errors)
        status = _coerce_status(self.status, errors)
        if first is not None and last is not None and last < first:
            errors.append("last_event_time: earlier than first_event_time")
        if errors:
            raise AlertValidationError(tuple(errors))

        object.__setattr__(self, "alert_id", alert_id)
        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "recommended_action", action)
        object.__setattr__(self, "affected_username", username)
        object.__setattr__(self, "source_ip", source_ip)
        object.__setattr__(self, "first_event_time", first)
        object.__setattr__(self, "last_event_time", last)
        object.__setattr__(self, "related_event_ids", related)
        object.__setattr__(self, "status", status)


def alert_from_finding(finding: Finding, *, timestamp: datetime | None = None) -> Alert:
    """Build one alert from one finding.

    The alert copies the rule, the severity, the recommendation, the related
    event ids, and the optional account and source address. It does not run
    a detector. ``timestamp`` defaults to the finding's last event time, then
    its first event time. The clock is not read. Pass an aware datetime when
    the finding has neither time.

    Raises:
        TypeError: ``finding`` is not a ``Finding``.
        AlertValidationError: the finding has no event time and ``timestamp``
            was omitted, or a field cannot be stored safely.
    """
    if not isinstance(finding, Finding):
        raise TypeError("alert_from_finding expects a Finding")
    when = _chosen_timestamp(finding, timestamp)
    evidence = _evidence_text(finding)
    return Alert(
        alert_id=_alert_id(finding.finding_id),
        rule_id=finding.rule_id,
        timestamp=when,
        title=finding.title,
        severity=finding.severity,
        description=_description_text(finding.title, evidence),
        evidence=evidence,
        recommended_action=finding.recommendation,
        affected_username=finding.affected_username,
        source_ip=finding.source_ip,
        first_event_time=finding.first_event_time,
        last_event_time=finding.last_event_time,
        related_event_ids=finding.related_event_ids,
        status=AlertStatus.OPEN,
    )


def alerts_from_findings(findings: Sequence[Finding]) -> tuple[Alert, ...]:
    """Build one alert per finding, in the same order.

    Findings are not merged and they are not dropped. Deduplication is a
    later phase.
    """
    if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence):
        raise TypeError("alerts_from_findings expects a sequence of Finding values")
    return tuple(alert_from_finding(finding) for finding in findings)


def _chosen_timestamp(finding: Finding, timestamp: datetime | None) -> datetime:
    if timestamp is not None:
        return timestamp
    if finding.last_event_time is not None:
        return finding.last_event_time
    if finding.first_event_time is not None:
        return finding.first_event_time
    raise AlertValidationError(
        ("timestamp: a timezone-aware datetime is required when the finding has no event time",)
    )


def _alert_id(finding_id: str) -> str:
    candidate = f"alert-{finding_id}"
    if len(candidate) <= _MAX_ID:
        return candidate
    digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:20]
    return f"alert-{digest}"


def _evidence_text(finding: Finding) -> str:
    return (
        f"Rule {finding.rule_id} observed {finding.observed_count} "
        f"against a threshold of {finding.threshold} "
        f"inside {_format_window(finding.window)}."
    )


def _description_text(title: str, evidence: str) -> str:
    heading = title[:-1] if title.endswith(".") else title
    return f"{heading}. {evidence} A finding is a suspicion, not proof of compromise."


def _format_window(window: timedelta) -> str:
    total = window.total_seconds()
    if total.is_integer():
        seconds = int(total)
        if seconds % 3600 == 0:
            hours = seconds // 3600
            unit = "hour" if hours == 1 else "hours"
            return f"{hours} {unit}"
        if seconds % 60 == 0:
            minutes = seconds // 60
            unit = "minute" if minutes == 1 else "minutes"
            return f"{minutes} {unit}"
        unit = "second" if seconds == 1 else "seconds"
        return f"{seconds} {unit}"
    return f"{total:g} seconds"


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


def _coerce_status(value: object, errors: list[str]) -> AlertStatus:
    if isinstance(value, AlertStatus):
        return value
    if isinstance(value, str) and value.strip().upper() == AlertStatus.OPEN.value:
        return AlertStatus.OPEN
    errors.append("status: only OPEN is used; this project has no alert workflow")
    return AlertStatus.OPEN


def _required_time(name: str, value: object, errors: list[str]) -> datetime:
    parsed = _aware_time(name, value, errors)
    if parsed is None and not any(message.startswith(f"{name}:") for message in errors):
        errors.append(f"{name}: a timezone-aware datetime is required")
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    return parsed or datetime(1970, 1, 1, tzinfo=timezone.utc)


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
        if text is None:
            if not any(message.startswith("related_event_ids:") for message in errors):
                errors.append("related_event_ids: ids must be non-empty text")
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
