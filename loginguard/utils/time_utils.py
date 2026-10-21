"""Timestamp parsing for authentication events.

LoginGuard stores every event instant as a timezone-aware UTC datetime.
A timestamp without an offset is ambiguous: it might be the server's local
time, the collector's time, or UTC. Those values are rejected. They are never
treated as UTC.

The original numeric offset is not kept after conversion. ``10:00+03:00`` and
``07:00Z`` become the same instant. Later reports show that instant in UTC.
"""

from __future__ import annotations

from datetime import datetime, timezone

_MAX_PREVIEW = 60


class TimestampParseError(ValueError):
    """Raised when a timestamp cannot be interpreted safely."""


def parse_timestamp(value: object) -> datetime:
    """Return ``value`` as a timezone-aware UTC datetime.

    Accepts an aware ``datetime`` or an ISO 8601 string with ``Z`` or a
    numeric offset such as ``+00:00``. ``None``, naive datetimes, date-only
    strings, and Unix epoch numbers are rejected.

    Raises:
        TimestampParseError: ``value`` is missing, naive, or not ISO 8601.
    """
    if value is None:
        raise TimestampParseError("A timestamp value is required.")
    if isinstance(value, datetime):
        return _require_aware(value)
    if isinstance(value, str):
        return _parse_text(value)
    raise TimestampParseError(
        "Expected an ISO 8601 string with a timezone, or a timezone-aware datetime. "
        "Unix timestamps are not accepted."
    )


def format_timestamp(value: datetime) -> str:
    """Format an aware datetime as UTC ISO 8601 ending in ``Z``."""
    utc = _require_aware(value)
    text = utc.isoformat()
    if text.endswith("+00:00"):
        return text[:-6] + "Z"
    return text


def _require_aware(value: datetime) -> datetime:
    offset = value.tzinfo.utcoffset(value) if value.tzinfo is not None else None
    if offset is None:
        raise TimestampParseError(
            "Naive timestamps are rejected and are not assumed to be UTC. "
            "Include an explicit offset such as Z or +00:00."
        )
    return value.astimezone(timezone.utc)


def _parse_text(value: str) -> datetime:
    text = value.strip()
    if not text:
        raise TimestampParseError("A timestamp value is required.")
    if len(text) >= 2 and text[-1] in "zZ" and text[-2].isdigit():
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise TimestampParseError(
            f"Could not parse {_preview(value)} as an ISO 8601 timestamp with a timezone."
        ) from None
    try:
        return _require_aware(parsed)
    except TimestampParseError:
        raise TimestampParseError(
            f"{_preview(value)} has no timezone offset and is not assumed to be UTC."
        ) from None


def _preview(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    if len(text) > _MAX_PREVIEW:
        return text[:_MAX_PREVIEW] + "..."
    return repr(text)
