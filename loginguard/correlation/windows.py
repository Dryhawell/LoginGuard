"""Time ordering for correlation.

Duplicate ``event_id`` values are processed once. The earliest copy is kept.
Later copies are dropped before grouping, so a repeated log line does not
become a second event. Input order does not matter: events are sorted by
timestamp, then by ``event_id``.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta

from loginguard.models.auth_event import AuthEvent


def unique_ordered_events(events: Sequence[AuthEvent]) -> tuple[AuthEvent, ...]:
    """Return events sorted by time, with one copy of each ``event_id``.

    Raises:
        TypeError: ``events`` is not a sequence of ``AuthEvent`` values.
    """
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise TypeError("events must be a sequence of AuthEvent values")
    earliest: dict[str, AuthEvent] = {}
    for event in events:
        if not isinstance(event, AuthEvent):
            raise TypeError("events must be a sequence of AuthEvent values")
        current = earliest.get(event.event_id)
        if current is None or event.timestamp < current.timestamp:
            earliest[event.event_id] = event
    ordered = sorted(earliest.values(), key=lambda event: (event.timestamp, event.event_id))
    return tuple(ordered)


def gap_exceeds(previous: datetime, current: datetime, window: timedelta) -> bool:
    """Return whether ``current`` starts a new group after ``previous``.

    A gap equal to ``window`` stays in the same group. One microsecond more
    starts a new group.
    """
    return current - previous > window
