"""Group related authentication events.

Groups are split by the fields you select: username, source address, and
event type. An event that lacks a selected field is left out. Missing
usernames are not placed in one shared bucket, and missing addresses are
not either.

Inside one key, a new group starts when the next event is later than the
previous event by more than the window. Events are ordered first, so an
out-of-order list produces the same groups. A chain of small gaps can form
one long group. That is the simple reading of "these events belong together."
A stricter cap on the whole span can wait until a real dataset needs it.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta

from loginguard.correlation.windows import gap_exceeds, unique_ordered_events
from loginguard.models.auth_event import AuthEvent, EventType


@dataclass(frozen=True, slots=True, repr=False)
class EventGroup:
    """Related events that share a key and sit inside one gap window.

    ``username`` and ``source_ip`` stay on the object for an investigator.
    ``repr`` omits both.
    """

    events: tuple[AuthEvent, ...]
    username: str | None = None
    source_ip: str | None = None
    event_type: EventType | None = None

    def __repr__(self) -> str:
        """Return a short label without usernames or source addresses."""
        event_ids = tuple(event.event_id for event in self.events)
        return f"EventGroup(size={len(self.events)}, event_ids={event_ids!r})"


def correlate_events(
    events: Sequence[AuthEvent],
    *,
    window: timedelta,
    by_username: bool = True,
    by_source_ip: bool = False,
    by_event_type: bool = False,
) -> tuple[EventGroup, ...]:
    """Group events by the selected keys and a gap window.

    At least one of ``by_username``, ``by_source_ip``, and ``by_event_type``
    must be true. Duplicate ``event_id`` values count once.

    Raises:
        ValueError: no grouping field was selected, or ``window`` is not positive.
        TypeError: ``events`` is not a sequence of ``AuthEvent`` values.
    """
    if not any((by_username, by_source_ip, by_event_type)):
        raise ValueError("select at least one correlation key")
    if not isinstance(window, timedelta) or window <= timedelta(0):
        raise ValueError("window must be a positive duration")

    grouped: dict[tuple[object, ...], list[AuthEvent]] = defaultdict(list)
    for event in unique_ordered_events(events):
        key = _key(event, by_username, by_source_ip, by_event_type)
        if key is None:
            continue
        grouped[key].append(event)

    groups: list[EventGroup] = []
    for key in sorted(grouped, key=_sort_key):
        username, source_ip, event_type = _unpack(key, by_username, by_source_ip, by_event_type)
        for cluster in _split(grouped[key], window):
            groups.append(
                EventGroup(
                    events=cluster,
                    username=username,
                    source_ip=source_ip,
                    event_type=event_type,
                )
            )
    return tuple(groups)


def _key(
    event: AuthEvent,
    by_username: bool,
    by_source_ip: bool,
    by_event_type: bool,
) -> tuple[object, ...] | None:
    parts: list[object] = []
    if by_username:
        if event.username is None:
            return None
        parts.append(event.username)
    if by_source_ip:
        if event.source_ip is None:
            return None
        parts.append(event.source_ip)
    if by_event_type:
        parts.append(event.event_type)
    return tuple(parts)


def _unpack(
    key: tuple[object, ...],
    by_username: bool,
    by_source_ip: bool,
    by_event_type: bool,
) -> tuple[str | None, str | None, EventType | None]:
    index = 0
    username = None
    source_ip = None
    event_type = None
    if by_username:
        username = key[index]
        index += 1
    if by_source_ip:
        source_ip = key[index]
        index += 1
    if by_event_type:
        event_type = key[index]
    return (
        username if isinstance(username, str) else None,
        source_ip if isinstance(source_ip, str) else None,
        event_type if isinstance(event_type, EventType) else None,
    )


def _split(events: Sequence[AuthEvent], window: timedelta) -> tuple[tuple[AuthEvent, ...], ...]:
    clusters: list[tuple[AuthEvent, ...]] = []
    current: list[AuthEvent] = []
    for event in events:
        if current and gap_exceeds(current[-1].timestamp, event.timestamp, window):
            clusters.append(tuple(current))
            current = []
        current.append(event)
    if current:
        clusters.append(tuple(current))
    return tuple(clusters)


def _sort_key(key: tuple[object, ...]) -> tuple[str, ...]:
    return tuple(str(part) for part in key)
