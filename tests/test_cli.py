"""Command-line analyze, validate, alerts, stats, and reports.

Store paths stay inside pytest's temporary directory. Detection is a
successful exit. A missing file is a runtime failure.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from loginguard.correlation import dedupe_findings
from loginguard.detection import build_default_engine
from loginguard.ingestion import parse_jsonl
from loginguard.models import alerts_from_findings
from loginguard.storage import AlertStore, EventStore
from main import main

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "auth_logs.jsonl"
_SECRET = "super-secret-value"


def _paths(tmp_path: Path) -> tuple[str, str, str]:
    return (
        str(tmp_path / "events.jsonl"),
        str(tmp_path / "alerts.json"),
        str(tmp_path / "analysis_summary.json"),
    )


def _run(argv: list[str]) -> int:
    return main(["--log-level", "ERROR", *argv])


def test_status_describes_the_text_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run([]) == 0
    output = capsys.readouterr().out
    assert "text, JSON, and CSV reports are ready." in output
    assert "Phase 15" in output


def test_help_lists_commands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    for name in ("analyze", "validate", "alerts", "stats", "report"):
        assert name in output


def test_missing_input_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        _run(["analyze"])
    assert exc.value.code == 2


def test_validate_reports_a_bad_line_without_the_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "auth.jsonl"
    source.write_text(
        "\n".join(
            [
                '{"timestamp":"2026-09-10T10:00:00Z","event_type":"LOGIN_SUCCESS","username":"ada","source_ip":"192.0.2.20"}',
                f'{{"password":"{_SECRET}"}}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    events, alerts, summary = _paths(tmp_path)

    assert _run(["validate", "--input", str(source)]) == 0
    output = capsys.readouterr().out

    assert "Valid events: 1" in output
    assert "Invalid events: 1" in output
    assert "Validation does not run detection rules." in output
    assert _SECRET not in output
    assert not Path(events).exists()
    assert not Path(alerts).exists()
    assert not Path(summary).exists()


def test_missing_log_is_a_runtime_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "missing.jsonl"

    assert _run(["validate", "--input", str(missing)]) == 1
    error = capsys.readouterr().err

    assert "file not found" in error
    assert _SECRET not in error


def test_analyze_stores_one_snapshot_and_omits_identity_from_the_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events, alerts, summary = _paths(tmp_path)
    parsed = parse_jsonl(_SAMPLE)
    expected = alerts_from_findings(dedupe_findings(build_default_engine().run(parsed.events)))

    assert _run(["analyze", "--input", str(_SAMPLE), "--events", events, "--alerts", alerts, "--summary", summary]) == 0
    first = capsys.readouterr()

    assert "Valid events: 38" in first.out
    assert "Invalid events: 6" in first.out
    assert f"Alerts: {len(expected)}" in first.out
    assert "not a probability" in first.out
    assert "not proof of compromise" in first.out
    assert "alice" not in first.out
    assert "192.0.2." not in first.out
    assert [alert.alert_id for alert in AlertStore(alerts).load()] == [
        alert.alert_id for alert in expected
    ]
    assert EventStore(events).load().valid_count == 38

    assert _run(["analyze", "--input", str(_SAMPLE), "--events", events, "--alerts", alerts, "--summary", summary]) == 0
    assert EventStore(events).load().valid_count == 38


def test_application_log_omits_usernames_and_addresses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events, alerts, summary = _paths(tmp_path)

    assert main(
        [
            "--log-level",
            "INFO",
            "analyze",
            "--input",
            str(_SAMPLE),
            "--events",
            events,
            "--alerts",
            alerts,
            "--summary",
            summary,
        ]
    ) == 0
    captured = capsys.readouterr()

    assert "Analysis finished." in captured.err
    assert "alice" not in captured.err
    assert "192.0.2." not in captured.err
    assert "2001:db8:" not in captured.err


def test_alerts_can_filter_by_severity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    events, alerts, summary = _paths(tmp_path)
    assert _run(["analyze", "--input", str(_SAMPLE), "--events", events, "--alerts", alerts, "--summary", summary]) == 0
    capsys.readouterr()

    assert _run(["alerts", "--alerts", alerts, "--severity", "high"]) == 0
    output = capsys.readouterr().out

    assert "success-after-failures" in output
    assert "brute-force-same-account" not in output
    assert "Account:" in output


def test_stats_count_without_listing_accounts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events, alerts, summary = _paths(tmp_path)
    assert _run(["analyze", "--input", str(_SAMPLE), "--events", events, "--alerts", alerts, "--summary", summary]) == 0
    capsys.readouterr()

    assert _run(["stats", "--events", events, "--alerts", alerts]) == 0
    output = capsys.readouterr().out

    assert "Stored events: 38" in output
    assert "LOGIN_FAILURE:" in output
    assert "Unique usernames:" in output
    assert "Unique source addresses:" in output
    assert "brute-force-same-account:" in output
    assert "alice" not in output
    assert "192.0.2." not in output


def test_text_report_includes_evidence_and_limitations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events, alerts, summary = _paths(tmp_path)
    assert _run(["analyze", "--input", str(_SAMPLE), "--events", events, "--alerts", alerts, "--summary", summary]) == 0
    capsys.readouterr()

    assert _run(["report", "--events", events, "--alerts", alerts, "--summary", summary]) == 0
    output = capsys.readouterr().out

    assert "LoginGuard Security Analysis" in output
    assert "auth_logs.jsonl" in output
    assert "Evidence:" in output
    assert "Recommendation:" in output
    assert "not proof of compromise" in output
    assert "not a probability" in output
    assert "does not replace an enterprise SIEM" in output
    assert _SECRET not in output


def test_empty_snapshot_commands_succeed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    events, alerts, summary = _paths(tmp_path)

    assert _run(["stats", "--events", events, "--alerts", alerts]) == 0
    assert _run(["alerts", "--alerts", alerts]) == 0
    assert _run(["report", "--events", events, "--alerts", alerts, "--summary", summary]) == 0
    output = capsys.readouterr().out

    assert "Stored events: 0" in output
    assert "No alerts matched." in output
    assert "No alerts in the stored snapshot." in output


def test_a_single_success_is_not_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "one.jsonl"
    source.write_text(
        '{"timestamp":"2026-09-10T10:00:00Z","event_type":"LOGIN_SUCCESS","username":"ada","source_ip":"198.51.100.8"}\n',
        encoding="utf-8",
    )
    events, alerts, summary = _paths(tmp_path)

    assert _run(["analyze", "--input", str(source), "--events", events, "--alerts", alerts, "--summary", summary]) == 0
    output = capsys.readouterr().out

    assert "Alerts: 0" in output
    assert "Highest heuristic score: none." in output
    assert AlertStore(alerts).load() == ()


def test_json_and_csv_reports_use_the_recorded_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    events, alerts, summary = _paths(tmp_path)
    times = iter(
        (
            datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 9, 10, 12, 0, 2, tzinfo=timezone.utc),
        )
    )
    monkeypatch.setattr("loginguard.cli.commands.utc_now", lambda: next(times))
    parsed = parse_jsonl(_SAMPLE)

    assert _run(
        [
            "analyze",
            "--input",
            str(_SAMPLE),
            "--events",
            events,
            "--alerts",
            alerts,
            "--summary",
            summary,
            "--format",
            "json",
        ]
    ) == 0
    output = capsys.readouterr().out
    document = json.loads(output)

    assert document["schema"] == "loginguard.analysis.v1"
    assert document["input_name"] == "auth_logs.jsonl"
    assert document["valid_events"] == parsed.valid_count
    assert document["invalid_events"] == parsed.invalid_count
    assert document["records_processed"] == parsed.valid_count + parsed.invalid_count
    assert document["started_at"] == "2026-09-10T12:00:00Z"
    assert document["completed_at"] == "2026-09-10T12:00:02Z"
    assert "not a probability" in " ".join(document["limitations"])
    assert _SECRET not in output

    destination = tmp_path / "report.csv"
    sibling = tmp_path / "notes.txt"
    sibling.write_text("keep", encoding="utf-8")
    assert _run(
        [
            "report",
            "--events",
            events,
            "--alerts",
            alerts,
            "--summary",
            summary,
            "--format",
            "csv",
            "--output",
            str(destination),
        ]
    ) == 0
    written = destination.read_text(encoding="utf-8")

    assert "Report written." in capsys.readouterr().out
    assert "record_type" in written
    assert "auth_logs.jsonl" in written
    assert "2026-09-10T12:00:00Z" in written
    assert "not a probability" in written
    assert sibling.read_text(encoding="utf-8") == "keep"
