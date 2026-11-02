"""Analysis summary stored beside the alert document.

The summary is one JSON document, schema ``loginguard.analysis.v1``. It
records when the run started and finished, the input file name, the parse
counts, and the alerts with their heuristic scores. Usernames are not stored
as a directory. A finding may name the accounts it already named.

Counts are derived from that run. They are checked again when the file is
read, so a hand-edited total cannot disagree with the findings. A missing
file means the run was not recorded. Invalid-line counts are then left
unknown rather than shown as zero.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from loginguard.detection import Severity, build_default_engine
from loginguard.detection.finding import Finding
from loginguard.models.alert import Alert
from loginguard.models.auth_event import AuthEvent, EventType
from loginguard.risk import RiskScore, band_for_score
from loginguard.storage.alert_store import alert_from_mapping, alert_to_dict
from loginguard.storage.errors import StorageError
from loginguard.storage.files import replace_text
from loginguard.utils.time_utils import TimestampParseError, format_timestamp, parse_timestamp

SCHEMA = "loginguard.analysis.v1"

LIMITATIONS = (
    "A finding is a suspicion, not proof of compromise.",
    "The heuristic score is not a probability.",
    "The score is kept in the analysis summary. The alert file does not store it.",
    "File storage has no lock and keeps only the latest alert document.",
    "LoginGuard does not replace an enterprise SIEM.",
    "Figures come from the log that was analyzed. Sample numbers are not built into the report.",
)

_SEVERITIES = tuple(item.value for item in Severity)
_EVENT_TYPES = tuple(item.value for item in EventType)
_SECRET_KEYS = frozenset(
    {
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
    }
)
_OMITTED = object()

_SUMMARY_FIELDS = frozenset(
    {
        "schema",
        "started_at",
        "completed_at",
        "input_name",
        "records_processed",
        "valid_events",
        "invalid_events",
        "event_counts",
        "unique_usernames",
        "unique_source_ips",
        "alerts_by_severity",
        "alerts_by_rule",
        "highest_score",
        "highest_score_band",
        "limitations",
        "findings",
    }
)


class ReportError(ValueError):
    """A summary cannot be built or does not agree with its findings."""


@dataclass(frozen=True, slots=True)
class ReportFinding:
    """One alert plus the score recorded for that same finding."""

    alert: Alert
    affected_usernames: tuple[str, ...] = ()
    score: int | None = None
    score_band: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.alert, Alert):
            raise ReportError("finding alert is missing")
        names = _username_tuple(self.affected_usernames)
        score, band = _score_pair(self.score, self.score_band)
        object.__setattr__(self, "affected_usernames", names)
        object.__setattr__(self, "score", score)
        object.__setattr__(self, "score_band", band)


@dataclass(frozen=True, slots=True)
class AnalysisSummary:
    """Counts and findings from one analysis run."""

    input_name: str | None
    valid_events: int
    invalid_events: int | None
    event_counts: Mapping[str, int]
    unique_usernames: int
    unique_source_ips: int
    findings: tuple[ReportFinding, ...]
    started_at: datetime | None = None
    completed_at: datetime | None = None
    records_processed: int | None = None
    alerts_by_severity: object = _OMITTED
    alerts_by_rule: object = _OMITTED
    highest_score: object = _OMITTED
    highest_score_band: object = _OMITTED
    limitations: tuple[str, ...] = LIMITATIONS

    def __post_init__(self) -> None:
        input_name = _optional_label(self.input_name)
        valid = _count("valid_events", self.valid_events)
        invalid = None if self.invalid_events is None else _count("invalid_events", self.invalid_events)
        processed = None if self.records_processed is None else _count("records_processed", self.records_processed)
        if (invalid is None) != (processed is None):
            raise ReportError("records processed must be recorded with the invalid-line count")
        if processed is not None and invalid is not None and processed != valid + invalid:
            raise ReportError("records processed does not match the valid and invalid counts")
        started = _optional_time("started_at", self.started_at)
        completed = _optional_time("completed_at", self.completed_at)
        if (started is None) != (completed is None):
            raise ReportError("start and completion times must be recorded together")
        if started is not None and completed is not None and completed < started:
            raise ReportError("completion time is earlier than the start time")
        counts = _event_counts(self.event_counts, valid)
        usernames = _count("unique_usernames", self.unique_usernames)
        addresses = _count("unique_source_ips", self.unique_source_ips)
        if usernames > valid or addresses > valid:
            raise ReportError("unique counts cannot exceed the valid events")
        findings = _findings(self.findings)
        by_severity, by_rule, highest, band = _aggregates(findings)
        if self.alerts_by_severity is not _OMITTED:
            _reject_mismatch("alerts_by_severity", self.alerts_by_severity, by_severity)
        if self.alerts_by_rule is not _OMITTED:
            _reject_mismatch("alerts_by_rule", self.alerts_by_rule, by_rule)
        if self.highest_score is not _OMITTED or self.highest_score_band is not _OMITTED:
            if self.highest_score != highest or self.highest_score_band != band:
                raise ReportError("highest score does not match the findings")
        try:
            recorded_limitations = tuple(self.limitations)
        except TypeError:
            raise ReportError("limitations do not match this version of LoginGuard") from None
        if recorded_limitations != LIMITATIONS:
            raise ReportError("limitations do not match this version of LoginGuard")
        object.__setattr__(self, "input_name", input_name)
        object.__setattr__(self, "valid_events", valid)
        object.__setattr__(self, "invalid_events", invalid)
        object.__setattr__(self, "records_processed", processed)
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)
        object.__setattr__(self, "event_counts", counts)
        object.__setattr__(self, "unique_usernames", usernames)
        object.__setattr__(self, "unique_source_ips", addresses)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "alerts_by_severity", by_severity)
        object.__setattr__(self, "alerts_by_rule", by_rule)
        object.__setattr__(self, "highest_score", highest)
        object.__setattr__(self, "highest_score_band", band)
        object.__setattr__(self, "limitations", LIMITATIONS)


class SummaryStore:
    """Read and replace the analysis summary at one path."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def save(self, summary: AnalysisSummary) -> None:
        """Replace the document. A failed replace leaves the previous file."""
        if not isinstance(summary, AnalysisSummary):
            raise TypeError("summary must be an AnalysisSummary")
        replace_text(self.path, summary_to_json(summary))

    def load(self) -> AnalysisSummary | None:
        """Return the summary, or ``None`` when the file is absent.

        Raises:
            StorageError: the file cannot be read or is not this schema.
            ReportError: the document does not agree with its findings.
        """
        if not self.path.exists():
            return None
        if self.path.is_dir():
            raise StorageError(f"{self.path.name}: expected a file")
        try:
            text = self.path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise StorageError(f"{self.path.name}: file is not valid UTF-8") from None
        except PermissionError:
            raise StorageError(f"{self.path.name}: permission denied") from None
        except OSError:
            raise StorageError(f"{self.path.name}: unable to read the file") from None
        return summary_from_json(text)


def build_summary(
    *,
    input_name: str,
    events: Sequence[AuthEvent],
    invalid_events: int,
    findings: Sequence[Finding],
    alerts: Sequence[Alert],
    scores: Sequence[RiskScore],
    started_at: datetime,
    completed_at: datetime,
) -> AnalysisSummary:
    """Build the summary for one finished run.

    ``findings``, ``alerts``, and ``scores`` are parallel sequences from that
    run. The clock values are the ones the caller recorded.
    """
    finding_list = tuple(findings)
    alert_list = tuple(alerts)
    score_list = tuple(scores)
    event_list = tuple(events)
    if not (len(finding_list) == len(alert_list) == len(score_list)):
        raise ReportError("findings, alerts, and scores must stay in step")
    report_findings = tuple(
        ReportFinding(
            alert=alert,
            affected_usernames=finding.affected_usernames,
            score=score.score,
            score_band=score.band.value,
        )
        for finding, alert, score in zip(finding_list, alert_list, score_list, strict=True)
    )
    type_counts = Counter(event.event_type.value for event in event_list)
    return AnalysisSummary(
        input_name=input_name,
        valid_events=len(event_list),
        invalid_events=invalid_events,
        records_processed=len(event_list) + invalid_events,
        event_counts={name: type_counts[name] for name in _EVENT_TYPES},
        unique_usernames=len({event.username for event in event_list if event.username}),
        unique_source_ips=len({event.source_ip for event in event_list if event.source_ip}),
        findings=report_findings,
        started_at=started_at,
        completed_at=completed_at,
    )


def summary_from_snapshot(
    events: Sequence[AuthEvent],
    alerts: Sequence[Alert],
    *,
    input_name: str | None,
) -> AnalysisSummary:
    """Describe a snapshot that has no recorded analysis run.

    Invalid lines and the wall-clock times stay unknown. Scores stay unknown.
    Showing those as zero would invent a result.
    """
    event_list = tuple(events)
    type_counts = Counter(event.event_type.value for event in event_list)
    findings = tuple(
        ReportFinding(
            alert=alert,
            affected_usernames=(alert.affected_username,) if alert.affected_username else (),
        )
        for alert in alerts
    )
    return AnalysisSummary(
        input_name=input_name,
        valid_events=len(event_list),
        invalid_events=None,
        event_counts={name: type_counts[name] for name in _EVENT_TYPES},
        unique_usernames=len({event.username for event in event_list if event.username}),
        unique_source_ips=len({event.source_ip for event in event_list if event.source_ip}),
        findings=findings,
    )


def summary_to_json(summary: AnalysisSummary) -> str:
    """Return the summary as pretty-printed JSON ending in a newline."""
    return json.dumps(_to_document(summary), ensure_ascii=False, indent=2) + "\n"


def summary_from_json(text: str) -> AnalysisSummary:
    """Parse one summary document.

    Raises:
        StorageError: the text is not the ``loginguard.analysis.v1`` document.
        ReportError: a count or score does not agree with the findings.
    """
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        raise StorageError("malformed JSON") from None
    if not isinstance(decoded, dict):
        raise StorageError(f"analysis summary schema is not {SCHEMA}")
    for key in decoded:
        if not isinstance(key, str):
            raise StorageError("field names must be text")
        if key.lower() in _SECRET_KEYS:
            raise StorageError("refusing to store a secret field")
        if key not in _SUMMARY_FIELDS:
            raise StorageError("unexpected field")
    if decoded.get("schema") != SCHEMA:
        raise StorageError(f"analysis summary schema is not {SCHEMA}")
    missing = [name for name in _SUMMARY_FIELDS if name not in decoded]
    if missing:
        raise StorageError("a required field is missing")
    return AnalysisSummary(
        input_name=decoded["input_name"],
        started_at=_time_field(decoded["started_at"]),
        completed_at=_time_field(decoded["completed_at"]),
        records_processed=decoded["records_processed"],
        valid_events=decoded["valid_events"],
        invalid_events=decoded["invalid_events"],
        event_counts=decoded["event_counts"],
        unique_usernames=decoded["unique_usernames"],
        unique_source_ips=decoded["unique_source_ips"],
        alerts_by_severity=decoded["alerts_by_severity"],
        alerts_by_rule=decoded["alerts_by_rule"],
        highest_score=decoded["highest_score"],
        highest_score_band=decoded["highest_score_band"],
        limitations=tuple(decoded["limitations"]) if isinstance(decoded["limitations"], list) else decoded["limitations"],
        findings=tuple(_finding_from_mapping(item) for item in decoded["findings"])
        if isinstance(decoded["findings"], list)
        else decoded["findings"],
    )


def _to_document(summary: AnalysisSummary) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "started_at": _format_optional_time(summary.started_at),
        "completed_at": _format_optional_time(summary.completed_at),
        "input_name": summary.input_name,
        "records_processed": summary.records_processed,
        "valid_events": summary.valid_events,
        "invalid_events": summary.invalid_events,
        "event_counts": dict(summary.event_counts),
        "unique_usernames": summary.unique_usernames,
        "unique_source_ips": summary.unique_source_ips,
        "alerts_by_severity": dict(summary.alerts_by_severity),
        "alerts_by_rule": dict(summary.alerts_by_rule),
        "highest_score": summary.highest_score,
        "highest_score_band": summary.highest_score_band,
        "limitations": list(summary.limitations),
        "findings": [
            {
                "score": finding.score,
                "score_band": finding.score_band,
                "affected_usernames": list(finding.affected_usernames),
                "alert": alert_to_dict(finding.alert),
            }
            for finding in summary.findings
        ],
    }


def _finding_from_mapping(item: object) -> ReportFinding:
    if not isinstance(item, Mapping):
        raise StorageError("findings must be a list of objects")
    for key in item:
        if not isinstance(key, str):
            raise StorageError("field names must be text")
        if key.lower() in _SECRET_KEYS:
            raise StorageError("refusing to store a secret field")
        if key not in {"score", "score_band", "affected_usernames", "alert"}:
            raise StorageError("unexpected field")
    if "alert" not in item or "score" not in item or "score_band" not in item:
        raise StorageError("a required field is missing")
    try:
        alert = alert_from_mapping(item["alert"])
    except (StorageError, ReportError, TimestampParseError, ValueError) as exc:
        raise StorageError(f"finding alert cannot be read: {exc}") from None
    names = item.get("affected_usernames", ())
    return ReportFinding(
        alert=alert,
        affected_usernames=tuple(names) if isinstance(names, list) else names,  # type: ignore[arg-type]
        score=item["score"],  # type: ignore[arg-type]
        score_band=item["score_band"],  # type: ignore[arg-type]
    )


def _time_field(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        return parse_timestamp(value)
    except TimestampParseError:
        raise StorageError("a timestamp must include a timezone offset") from None


def _format_optional_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    return format_timestamp(value)


def _aggregates(
    findings: Sequence[ReportFinding],
) -> tuple[dict[str, int], dict[str, int], int | None, str | None]:
    severities = Counter(finding.alert.severity.value for finding in findings)
    rules = Counter(finding.alert.rule_id for finding in findings)
    by_severity = {name: severities[name] for name in _SEVERITIES}
    builtin = tuple(rule.rule_id for rule in build_default_engine().registry.rules())
    extra = tuple(sorted(set(rules) - set(builtin)))
    by_rule = {rule_id: rules[rule_id] for rule_id in builtin + extra}
    scored = [finding.score for finding in findings if finding.score is not None]
    if len(scored) != len(findings):
        return by_severity, by_rule, None, None
    if not scored:
        return by_severity, by_rule, None, None
    highest = max(scored)
    return by_severity, by_rule, highest, band_for_score(highest).value


def _reject_mismatch(name: str, supplied: object, expected: Mapping[str, int]) -> None:
    if not isinstance(supplied, Mapping) or dict(supplied) != dict(expected):
        raise ReportError(f"{name} does not match the findings")


def _event_counts(value: object, valid_events: int) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ReportError("event counts must be a mapping")
    if set(value) != set(_EVENT_TYPES):
        raise ReportError("event counts must name each event type once")
    counts = {name: _count(name, value[name]) for name in _EVENT_TYPES}
    if sum(counts.values()) != valid_events:
        raise ReportError("event counts do not match the valid events")
    return counts


def _findings(value: object) -> tuple[ReportFinding, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, tuple):
        raise ReportError("findings must be a sequence of report findings")
    for item in value:
        if not isinstance(item, ReportFinding):
            raise ReportError("findings must be a sequence of report findings")
    return value


def _username_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, tuple):
        raise ReportError("affected usernames must be a sequence of text")
    names: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip():
            raise ReportError("affected usernames must be non-empty text")
        names.append(item)
    return tuple(names)


def _score_pair(score: object, band: object) -> tuple[int | None, str | None]:
    if score is None and band is None:
        return None, None
    if isinstance(score, bool) or not isinstance(score, int) or not isinstance(band, str):
        raise ReportError("score must be an integer from 0 through 100")
    try:
        expected = band_for_score(score).value
    except ValueError:
        raise ReportError("score must be an integer from 0 through 100") from None
    if band != expected:
        raise ReportError("score band does not match the score")
    return score, band


def _count(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReportError(f"{name} must be a non-negative integer")
    return value


def _optional_time(name: str, value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise ReportError(f"{name} must be a timezone-aware datetime")
    try:
        return parse_timestamp(value)
    except TimestampParseError:
        raise ReportError(f"{name} must include a timezone offset") from None


def _optional_label(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ReportError("input name must be text")
    text = value.strip()
    if not text:
        return None
    if len(text) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ReportError("input name is empty, too long, or contains control characters")
    return text
