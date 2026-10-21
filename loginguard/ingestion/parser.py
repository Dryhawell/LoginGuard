"""Parse authentication logs into ``AuthEvent`` records.

JSON Lines is the first format: one JSON object per physical line. A future
format can implement ``LineParser`` and be passed to ``parse_log_file``.
Parsing uses ``json.JSONDecoder``. It never uses ``eval``.

Blank lines are skipped. A malformed line, a JSON value that is not an
object, or an object that fails ``AuthEvent`` validation becomes a
``ParseIssue`` and the parser continues. Issue text never includes the raw
line.

When a record omits ``event_id``, the id is ``<file name>:<line number>`` so
the same file parses to the same ids. That id is unique for one file name,
not for two directories that happen to contain the same file name. A supplied
``event_id`` is kept. ``raw_source`` defaults to the file name, not the line.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from loginguard.ingestion.log_reader import read_text_lines
from loginguard.ingestion.validators import RecordShapeError, require_json_object
from loginguard.models import AuthEvent, AuthEventValidationError

_MAX_EVENT_ID = 128
_MAX_RAW_SOURCE = 128


class MalformedJsonError(ValueError):
    """A physical line is not exactly one JSON value."""


class LineParser(Protocol):
    """Parse one physical line into an event, an issue, or a skip."""

    def parse_line(
        self,
        line_number: int,
        text: str,
        *,
        source_name: str,
    ) -> AuthEvent | ParseIssue | None:
        """Return an event, an issue, or ``None`` when the line is blank."""


@dataclass(frozen=True, slots=True)
class ParseIssue:
    """One rejected line.

    ``messages`` describes the problem without quoting the line. ``code`` is a
    stable label for tests and later reports: ``malformed_json``,
    ``not_an_object``, or ``invalid_event``.
    """

    line_number: int
    code: str
    messages: tuple[str, ...]

    def __str__(self) -> str:
        detail = "; ".join(self.messages)
        return f"line {self.line_number}: {detail}"


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Valid events and rejected lines from one file."""

    events: tuple[AuthEvent, ...]
    issues: tuple[ParseIssue, ...]
    source_name: str

    @property
    def valid_count(self) -> int:
        return len(self.events)

    @property
    def invalid_count(self) -> int:
        return len(self.issues)


class JsonlParser:
    """Parse a JSON Lines authentication log."""

    def parse_line(
        self,
        line_number: int,
        text: str,
        *,
        source_name: str,
    ) -> AuthEvent | ParseIssue | None:
        if not text.strip():
            return None
        try:
            decoded = _decode_json_value(text)
        except MalformedJsonError as exc:
            return ParseIssue(line_number, "malformed_json", (str(exc),))
        try:
            record = require_json_object(decoded)
        except RecordShapeError as exc:
            return ParseIssue(line_number, "not_an_object", (str(exc),))

        payload = dict(record)
        if payload.get("event_id") is None:
            payload["event_id"] = _default_event_id(source_name, line_number)
        supplied_source = payload.get("raw_source")
        if supplied_source is None or (isinstance(supplied_source, str) and not supplied_source.strip()):
            safe_source = _safe_label(source_name, _MAX_RAW_SOURCE)
            if safe_source is not None:
                payload["raw_source"] = safe_source
        try:
            return AuthEvent.from_mapping(payload)
        except AuthEventValidationError as exc:
            return ParseIssue(line_number, "invalid_event", exc.messages)


def parse_jsonl(path: str | Path) -> ParseResult:
    """Parse a UTF-8 JSON Lines file."""
    return parse_log_file(path, JsonlParser())


def parse_log_file(path: str | Path, parser: LineParser) -> ParseResult:
    """Parse ``path`` with ``parser``, continuing after rejected lines.

    Raises:
        IngestionError: the file itself cannot be read.
    """
    file_path = Path(path)
    events: list[AuthEvent] = []
    issues: list[ParseIssue] = []
    for line_number, text in read_text_lines(file_path):
        outcome = parser.parse_line(line_number, text, source_name=file_path.name)
        if outcome is None:
            continue
        if isinstance(outcome, ParseIssue):
            issues.append(outcome)
            continue
        events.append(outcome)
    return ParseResult(
        events=tuple(events),
        issues=tuple(issues),
        source_name=file_path.name,
    )


def _decode_json_value(text: str) -> object:
    stripped = text.strip()
    decoder = json.JSONDecoder()
    try:
        value, index = decoder.raw_decode(stripped)
    except json.JSONDecodeError:
        raise MalformedJsonError("malformed JSON") from None
    if stripped[index:].strip():
        raise MalformedJsonError("line contains more than one JSON value") from None
    return value


def _default_event_id(source_name: str, line_number: int) -> str:
    candidate = f"{source_name}:{line_number}"
    safe = _safe_label(candidate, _MAX_EVENT_ID)
    if safe is not None:
        return safe
    return f"line-{line_number}"


def _safe_label(value: str, max_length: int) -> str | None:
    if len(value) > max_length:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value
