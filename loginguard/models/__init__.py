"""Structured records used by LoginGuard."""

from loginguard.models.auth_event import (
    AuthEvent,
    AuthEventValidationError,
    EventType,
    normalize_event_type,
)

__all__ = [
    "AuthEvent",
    "AuthEventValidationError",
    "EventType",
    "normalize_event_type",
]
