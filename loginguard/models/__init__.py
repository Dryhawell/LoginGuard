"""Structured records used by LoginGuard."""

from loginguard.models.alert import (
    Alert,
    AlertStatus,
    AlertValidationError,
    alert_from_finding,
    alerts_from_findings,
)
from loginguard.models.auth_event import (
    AuthEvent,
    AuthEventValidationError,
    EventType,
    normalize_event_type,
)

__all__ = [
    "Alert",
    "AlertStatus",
    "AlertValidationError",
    "AuthEvent",
    "AuthEventValidationError",
    "EventType",
    "alert_from_finding",
    "alerts_from_findings",
    "normalize_event_type",
]
