"""Text, JSON, and CSV renderings of one analysis summary.

Each rendering uses the summary it is given. None of them looks up a sample
file or fills in demonstration counts. A missing invalid-line count stays
unrecorded. It is not printed as zero.

CSV cells that start with a spreadsheet formula marker are prefixed with a
single quote so a username or title is stored as text.
"""

from __future__ import annotations

import csv
import io

from loginguard.models.auth_event import EventType
from loginguard.reporting.summary import AnalysisSummary, ReportFinding, summary_to_json
from loginguard.utils.time_utils import format_timestamp

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_COLUMNS = (
    "record_type",
    "started_at",
    "completed_at",
    "input_name",
    "records_processed",
    "valid_events",
    "invalid_events",
    *(item.value for item in EventType),
    "unique_usernames",
    "unique_source_ips",
    "alerts",
    "highest_score",
    "highest_score_band",
    "severity",
    "rule_id",
    "alert_id",
    "title",
    "accounts",
    "source",
    "evidence",
    "recommendation",
    "score",
    "score_band",
    "limitations",
)


def render_json(summary: AnalysisSummary) -> str:
    """Return the summary document."""
    return summary_to_json(summary)


def render_text(summary: AnalysisSummary) -> str:
    """Return the human-readable report."""
    lines = [
        "LoginGuard Security Analysis",
        "============================",
        f"Started: {_time_label(summary.started_at)}",
        f"Completed: {_time_label(summary.completed_at)}",
        f"Input: {_label(summary.input_name)}",
        f"Records processed: {_number(summary.records_processed)}",
        f"Valid events: {summary.valid_events}",
        f"Invalid events: {_number(summary.invalid_events)}",
        f"Successful logins: {summary.event_counts['LOGIN_SUCCESS']}",
        f"Failed logins: {summary.event_counts['LOGIN_FAILURE']}",
    ]
    for name in ("LOGOUT", "ACCOUNT_LOCKED", "PASSWORD_CHANGE", "UNKNOWN"):
        lines.append(f"{name}: {summary.event_counts[name]}")
    lines.extend(
        (
            f"Unique usernames: {summary.unique_usernames}",
            f"Unique source addresses: {summary.unique_source_ips}",
            f"Alerts: {len(summary.findings)}",
            "Alerts by severity:",
        )
    )
    for name, count in summary.alerts_by_severity.items():
        lines.append(f"{name}: {count}")
    lines.append("Alerts by rule:")
    for name, count in summary.alerts_by_rule.items():
        lines.append(f"{name}: {count}")
    lines.extend(("", "Findings:"))
    if summary.findings:
        for finding in summary.findings:
            lines.extend(_finding_lines(finding))
            lines.append("")
    else:
        lines.append("No alerts in the stored snapshot.")
        lines.append("")
    lines.append("Limitations:")
    lines.extend(summary.limitations)
    return "\n".join(lines)


def render_csv(summary: AnalysisSummary) -> str:
    """Return one CSV document with a summary row and one row per finding."""
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    writer.writerow(_cells(_summary_row(summary)))
    for finding in summary.findings:
        writer.writerow(_cells(_finding_row(finding)))
    return buffer.getvalue()


def _finding_lines(finding: ReportFinding) -> list[str]:
    alert = finding.alert
    accounts = finding.affected_usernames
    if not accounts and alert.affected_username:
        accounts = (alert.affected_username,)
    account_label = ", ".join(accounts) if accounts else "(not recorded)"
    source = alert.source_ip if alert.source_ip else "(not recorded)"
    if finding.score is None:
        score = "Heuristic score: (not recorded). The score is not a probability."
    else:
        score = (
            f"Heuristic score: {finding.score} ({finding.score_band}). "
            "The score is not a probability."
        )
    return [
        f"{alert.severity.value} {alert.alert_id} {alert.rule_id}",
        alert.title,
        f"Accounts: {account_label}",
        f"Source: {source}",
        f"Evidence: {alert.evidence}",
        f"Recommendation: {alert.recommended_action}",
        score,
    ]


def _summary_row(summary: AnalysisSummary) -> dict[str, object]:
    row: dict[str, object] = {
        "record_type": "summary",
        "started_at": _time_label(summary.started_at) if summary.started_at else "",
        "completed_at": _time_label(summary.completed_at) if summary.completed_at else "",
        "input_name": summary.input_name or "",
        "records_processed": _blank_number(summary.records_processed),
        "valid_events": summary.valid_events,
        "invalid_events": _blank_number(summary.invalid_events),
        "unique_usernames": summary.unique_usernames,
        "unique_source_ips": summary.unique_source_ips,
        "alerts": len(summary.findings),
        "highest_score": _blank_number(summary.highest_score),
        "highest_score_band": summary.highest_score_band or "",
        "limitations": " | ".join(summary.limitations),
    }
    row.update(summary.event_counts)
    return row


def _finding_row(finding: ReportFinding) -> dict[str, object]:
    alert = finding.alert
    accounts = finding.affected_usernames or (
        (alert.affected_username,) if alert.affected_username else ()
    )
    return {
        "record_type": "finding",
        "severity": alert.severity.value,
        "rule_id": alert.rule_id,
        "alert_id": alert.alert_id,
        "title": alert.title,
        "accounts": "; ".join(accounts),
        "source": alert.source_ip or "",
        "evidence": alert.evidence,
        "recommendation": alert.recommended_action,
        "score": _blank_number(finding.score),
        "score_band": finding.score_band or "",
    }


def _cells(row: dict[str, object]) -> dict[str, object]:
    return {key: _csv_cell(value) for key, value in row.items()}


def _csv_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    if value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _time_label(value: object) -> str:
    if value is None:
        return "(not recorded)"
    if isinstance(value, str):
        return value
    from datetime import datetime

    if isinstance(value, datetime):
        return format_timestamp(value)
    return "(not recorded)"


def _number(value: int | None) -> str:
    if value is None:
        return "(not recorded)"
    return str(value)


def _blank_number(value: int | None) -> object:
    if value is None:
        return ""
    return value


def _label(value: str | None) -> str:
    if value:
        return value
    return "(not recorded)"
