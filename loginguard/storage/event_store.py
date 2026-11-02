"""JSON Lines storage for normalized authentication events.

``append`` adds a batch at the end and does not rewrite earlier lines.
``replace`` writes a fresh snapshot for one analysis run. One malformed line
stays an issue; the valid lines around it are still returned.

This is a single-process file. Two writers can interleave lines, and a crash
during a write can leave a partial last line. That partial line is reported
as malformed JSON on the next load. There is no file lock and no database.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from loginguard.ingestion import IngestionError, ParseResult, parse_jsonl
from loginguard.models.auth_event import AuthEvent
from loginguard.storage.errors import StorageError
from loginguard.storage.files import append_text, replace_text


class EventStore:
    """Read, append, and replace ``AuthEvent`` records at one JSON Lines path."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, events: Sequence[AuthEvent]) -> int:
        """Append ``events`` as one JSON object per line.

        An empty sequence writes nothing and does not create a file. The
        caller's sequence is not modified. Duplicate ``event_id`` values are
        stored as separate lines; detection decides which copy counts.

        Returns:
            The number of events written.

        Raises:
            TypeError: ``events`` is not a sequence of ``AuthEvent`` values.
            StorageError: the file or its directory cannot be written.
        """
        records = _require_events(events)
        if not records:
            return 0
        append_text(self.path, render_events(records))
        return len(records)

    def replace(self, events: Sequence[AuthEvent]) -> int:
        """Replace the file with ``events``.

        The analyze command uses this so a second run stores that run only.
        ``append`` still keeps earlier lines. An empty sequence writes an
        empty file, which removes a previous snapshot. The write goes through
        a temporary file in the same directory.

        Returns:
            The number of events written.

        Raises:
            TypeError: ``events`` is not a sequence of ``AuthEvent`` values.
            StorageError: the file or its directory cannot be written.
        """
        records = _require_events(events)
        replace_text(self.path, render_events(records))
        return len(records)

    def load(self) -> ParseResult:
        """Return stored events and per-line issues.

        A missing file is an empty result. A directory, a permission failure,
        or a file that is not UTF-8 raises ``StorageError``. One bad line
        does not discard the rest of the file.

        Raises:
            StorageError: the file itself cannot be read.
        """
        if not self.path.exists():
            return ParseResult(events=(), issues=(), source_name=self.path.name)
        try:
            return parse_jsonl(self.path)
        except IngestionError as exc:
            raise StorageError(str(exc)) from None


def render_events(events: Sequence[AuthEvent]) -> str:
    """Return JSON Lines for ``events``. An empty sequence is an empty string."""
    records = _require_events(events)
    if not records:
        return ""
    lines = [
        json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"))
        for event in records
    ]
    return "\n".join(lines) + "\n"


def _require_events(events: Sequence[AuthEvent]) -> tuple[AuthEvent, ...]:
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise TypeError("events must be a sequence of AuthEvent values")
    records = tuple(events)
    for event in records:
        if not isinstance(event, AuthEvent):
            raise TypeError("events must be a sequence of AuthEvent values")
    return records
