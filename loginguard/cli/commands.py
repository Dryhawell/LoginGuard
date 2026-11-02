"""Subcommands that run detection and read the local snapshot.

Stdout is the operator's report. Application logs stay on stderr and carry
counts only: no usernames, source addresses, or raw lines. Finding a pattern
is a successful run. A missing file or a storage failure is a runtime error.

JSON and CSV export are not implemented here.
"""

from __future__ import annotations

import argparse
import logging
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from loginguard import __app_name__, __description__, __version__
from loginguard.correlation import dedupe_findings
from loginguard.detection import Severity, build_default_engine
from loginguard.ingestion import parse_jsonl
from loginguard.ingestion.parser import ParseResult
from loginguard.models.alert import Alert, alerts_from_findings
from loginguard.models.auth_event import EventType
from loginguard.risk import RiskScore, score_finding
from loginguard.storage import DEFAULT_ALERT_PATH, DEFAULT_EVENT_PATH, AlertStore, EventStore
from loginguard.utils.logger import LOGGER_NAME, VALID_LEVELS

_SEVERITY_ORDER = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the LoginGuard command parser.

    Global options belong before the subcommand. ``--log-level`` selects the
    stderr log level. ``--version`` prints the version and exits.
    """
    parser = argparse.ArgumentParser(
        prog="loginguard",
        description=(
            f"{__app_name__}: {__description__} "
            "Commands analyze a local JSONL file, validate it, and read the "
            "stored snapshot. JSON and CSV export are not implemented yet."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__app_name__} {__version__}",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=VALID_LEVELS,
        help="Application log level written to stderr (default: INFO).",
    )
    subcommands = parser.add_subparsers(dest="command", metavar="command")

    analyze = subcommands.add_parser(
        "analyze",
        help="Detect patterns in a JSONL log and store the snapshot.",
        description=(
            "Parse a JSONL authentication log, run the built-in rules, "
            "deduplicate alerts, and replace the local event and alert files "
            "with this run. Prints a short summary. JSON export is not "
            "implemented yet."
        ),
    )
    _add_input(analyze)
    _add_store_paths(analyze)

    validate = subcommands.add_parser(
        "validate",
        help="Check a JSONL log without detection.",
        description=(
            "Parse a JSONL authentication log and report valid and invalid "
            "lines. Detection rules are not run and nothing is stored."
        ),
    )
    _add_input(validate)

    alerts = subcommands.add_parser(
        "alerts",
        help="List alerts from the stored snapshot.",
        description=(
            "List alerts saved by the last analyze command. "
            "Optional severity filter uses INFO, LOW, MEDIUM, HIGH, or CRITICAL."
        ),
    )
    alerts.add_argument(
        "--severity",
        type=str.upper,
        choices=[item.value for item in Severity],
        help="Show only alerts of this severity.",
    )
    alerts.add_argument(
        "--alerts",
        type=Path,
        default=DEFAULT_ALERT_PATH,
        help=f"Alert document to read (default: {DEFAULT_ALERT_PATH.as_posix()}).",
    )

    stats = subcommands.add_parser(
        "stats",
        help="Show counts from the stored snapshot.",
        description=(
            "Count stored events and alerts. Usernames and source addresses "
            "are counted, not listed."
        ),
    )
    _add_store_paths(stats)

    report = subcommands.add_parser(
        "report",
        help="Print a text report from the stored snapshot.",
        description=(
            "Print a human-readable report from the stored events and alerts. "
            "JSON and CSV export are not implemented yet."
        ),
    )
    _add_store_paths(report)
    return parser


def dispatch(args: argparse.Namespace) -> str | None:
    """Run the selected command and return text for stdout.

    ``None`` means the process should print the status lines instead.

    Raises:
        IngestionError: the input log cannot be read.
        StorageError: a snapshot file cannot be read or written.
    """
    command = args.command
    if command is None:
        return None
    if command == "analyze":
        return analyze(args.input, args.events, args.alerts)
    if command == "validate":
        return validate(args.input)
    if command == "alerts":
        return list_alerts(args.alerts, args.severity)
    if command == "stats":
        return statistics(args.events, args.alerts)
    if command == "report":
        return report(args.events, args.alerts)
    raise ValueError(f"Unknown command {command!r}.")


def status_lines() -> tuple[str, ...]:
    """Return the text printed when no subcommand is given."""
    return (
        f"{__app_name__} {__version__}",
        "Status: analyze, validate, alerts, stats, and a text report are ready.",
        "JSON and CSV export are not implemented yet.",
        "Next step: report formats (Phase 14).",
    )


def analyze(input_path: Path, event_path: Path, alert_path: Path) -> str:
    """Run the default rules and replace the stored snapshot."""
    parsed = parse_jsonl(input_path)
    findings = dedupe_findings(build_default_engine().run(parsed.events))
    alerts = alerts_from_findings(findings)
    scores = tuple(score_finding(finding) for finding in findings)
    EventStore(event_path).replace(parsed.events)
    AlertStore(alert_path).save(alerts)
    _log(
        "Analysis finished. valid=%s invalid=%s alerts=%s",
        parsed.valid_count,
        parsed.invalid_count,
        len(alerts),
    )
    return _analysis_text(input_path, event_path, alert_path, parsed, alerts, scores)


def validate(input_path: Path) -> str:
    """Parse one log and describe rejected lines without storing them."""
    parsed = parse_jsonl(input_path)
    _log(
        "Validation finished. valid=%s invalid=%s",
        parsed.valid_count,
        parsed.invalid_count,
    )
    lines = [
        "LoginGuard validation",
        f"Input: {input_path}",
        f"Valid events: {parsed.valid_count}",
        f"Invalid events: {parsed.invalid_count}",
    ]
    if parsed.issues:
        lines.append("Issues:")
        lines.extend(str(issue) for issue in parsed.issues)
    lines.append("Validation does not run detection rules.")
    return "\n".join(lines)


def list_alerts(alert_path: Path, severity: str | None) -> str:
    """List stored alerts, optionally limited to one severity."""
    alerts = AlertStore(alert_path).load()
    if severity is not None:
        alerts = tuple(alert for alert in alerts if alert.severity.value == severity)
    lines = ["LoginGuard alerts", f"Alerts: {len(alerts)}"]
    if not alerts:
        lines.append("No alerts matched.")
        return "\n".join(lines)
    for alert in alerts:
        lines.extend(_alert_lines(alert))
    return "\n".join(lines)


def statistics(event_path: Path, alert_path: Path) -> str:
    """Count the stored snapshot. Names and addresses are not listed."""
    parsed, alerts = _snapshot(event_path, alert_path)
    lines = ["LoginGuard statistics", *_count_lines(parsed, alerts)]
    return "\n".join(lines)


def report(event_path: Path, alert_path: Path) -> str:
    """Render a text report from the stored snapshot."""
    parsed, alerts = _snapshot(event_path, alert_path)
    labels = sorted({event.raw_source for event in parsed.events if event.raw_source})
    lines = [
        "LoginGuard Security Analysis",
        "============================",
        f"Input labels: {', '.join(labels) if labels else '(not recorded)'}",
        *_count_lines(parsed, alerts),
        "",
        "Findings:",
    ]
    if alerts:
        for alert in alerts:
            lines.extend(_alert_lines(alert))
            lines.append("")
    else:
        lines.append("No alerts in the stored snapshot.")
        lines.append("")
    lines.extend(
        (
            "Limitations:",
            "A finding is a suspicion, not proof of compromise.",
            "The heuristic score is not a probability and is not stored in the alert file.",
            "File storage has no lock and keeps only the latest alert document.",
            "LoginGuard does not replace an enterprise SIEM.",
        )
    )
    return "\n".join(lines)


def _analysis_text(
    input_path: Path,
    event_path: Path,
    alert_path: Path,
    parsed: ParseResult,
    alerts: Sequence[Alert],
    scores: Sequence[RiskScore],
) -> str:
    return "\n".join(
        (
            "LoginGuard analysis",
            f"Input: {input_path}",
            f"Valid events: {parsed.valid_count}",
            f"Invalid events: {parsed.invalid_count}",
            f"Alerts: {len(alerts)}",
            _highest_score(scores),
            f"Events stored: {event_path}",
            f"Alerts stored: {alert_path}",
            "A finding is a suspicion, not proof of compromise.",
        )
    )


def _highest_score(scores: Sequence[RiskScore]) -> str:
    if not scores:
        return "Highest heuristic score: none. The score is not a probability."
    best = max(scores, key=lambda item: item.score)
    return (
        f"Highest heuristic score: {best.score} ({best.band.value}). "
        "The score is not a probability."
    )


def _count_lines(parsed: ParseResult, alerts: Sequence[Alert]) -> list[str]:
    events = parsed.events
    type_counts = Counter(event.event_type for event in events)
    severity_counts = Counter(alert.severity for alert in alerts)
    rule_counts = Counter(alert.rule_id for alert in alerts)
    usernames = {event.username for event in events if event.username}
    addresses = {event.source_ip for event in events if event.source_ip}
    lines = [
        f"Stored events: {len(events)}",
        f"Stored event issues: {len(parsed.issues)}",
    ]
    for event_type in EventType:
        lines.append(f"{event_type.value}: {type_counts[event_type]}")
    lines.append(f"Unique usernames: {len(usernames)}")
    lines.append(f"Unique source addresses: {len(addresses)}")
    lines.append(f"Alerts: {len(alerts)}")
    lines.append("Alerts by severity:")
    for severity in _SEVERITY_ORDER:
        lines.append(f"{severity.value}: {severity_counts[severity]}")
    lines.append("Alerts by rule:")
    for rule_id in _rule_ids(rule_counts):
        lines.append(f"{rule_id}: {rule_counts[rule_id]}")
    return lines


def _rule_ids(seen: Counter[str]) -> tuple[str, ...]:
    builtin = tuple(rule.rule_id for rule in build_default_engine().registry.rules())
    extra = tuple(sorted(set(seen) - set(builtin)))
    return builtin + extra


def _alert_lines(alert: Alert) -> list[str]:
    account = alert.affected_username if alert.affected_username else "(not recorded)"
    source = alert.source_ip if alert.source_ip else "(not recorded)"
    return [
        f"{alert.severity.value} {alert.alert_id} {alert.rule_id}",
        alert.title,
        f"Account: {account}",
        f"Source: {source}",
        f"Evidence: {alert.evidence}",
        f"Recommendation: {alert.recommended_action}",
    ]


def _snapshot(event_path: Path, alert_path: Path) -> tuple[ParseResult, tuple[Alert, ...]]:
    return EventStore(event_path).load(), AlertStore(alert_path).load()


def _add_input(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="UTF-8 JSONL authentication log.",
    )


def _add_store_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--events",
        type=Path,
        default=DEFAULT_EVENT_PATH,
        help=f"Event snapshot to write or read (default: {DEFAULT_EVENT_PATH.as_posix()}).",
    )
    parser.add_argument(
        "--alerts",
        type=Path,
        default=DEFAULT_ALERT_PATH,
        help=f"Alert document to write or read (default: {DEFAULT_ALERT_PATH.as_posix()}).",
    )


def _log(message: str, *values: object) -> None:
    logging.getLogger(LOGGER_NAME).info(message, *values)
