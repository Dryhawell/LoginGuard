"""One pass over the synthetic sample locks the pipeline together.

The counts come from parsing that file in this test. They are not copied
from a report example. A second build with the same recorded times matches
the first.
"""

import csv
import io
from datetime import datetime, timezone
from pathlib import Path

from loginguard.correlation import dedupe_findings
from loginguard.detection import Severity, build_default_engine
from loginguard.ingestion import parse_jsonl
from loginguard.models import alerts_from_findings
from loginguard.reporting import build_summary, render_csv, render_json, render_text, summary_from_json
from loginguard.risk import score_finding

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "auth_logs.jsonl"
_START = datetime(2026, 9, 10, 18, 0, tzinfo=timezone.utc)
_END = datetime(2026, 9, 10, 18, 0, 1, tzinfo=timezone.utc)


def test_sample_pipeline_keeps_one_finding_per_builtin_rule() -> None:
    parsed = parse_jsonl(_SAMPLE)
    engine = build_default_engine()
    declared = {rule.rule_id: rule.severity for rule in engine.registry.rules()}
    produced = engine.run(parsed.events)
    findings = dedupe_findings(produced)

    assert set(findings) == set(produced)
    assert {finding.rule_id for finding in findings} == set(declared)
    assert all(finding.severity is declared[finding.rule_id] for finding in findings)
    assert all(finding.severity is not Severity.CRITICAL for finding in findings)
    by_rule: dict[str, list] = {rule_id: [] for rule_id in declared}
    for finding in findings:
        by_rule[finding.rule_id].append(finding)
    brute = by_rule["brute-force-same-account"]
    success = by_rule["success-after-failures"]
    assert len(brute) == 2
    assert len({(item.affected_username, item.source_ip) for item in brute}) == 2
    assert len(success) == 1
    assert success[0].affected_username in {item.affected_username for item in brute}
    assert len(by_rule["password-spray-distinct-usernames"]) == 1
    assert len(by_rule["distributed-failure-heuristic"]) == 1

    alerts = alerts_from_findings(findings)
    scores = tuple(score_finding(finding) for finding in findings)
    for finding, alert, score in zip(findings, alerts, scores, strict=True):
        assert repr(finding) == (
            f"Finding(finding_id={finding.finding_id!r}, rule_id={finding.rule_id!r}, "
            f"severity={finding.severity.value}, observed_count={finding.observed_count})"
        )
        assert repr(alert) == (
            f"Alert(alert_id={alert.alert_id!r}, rule_id={alert.rule_id!r}, "
            f"severity={alert.severity.value}, status={alert.status.value})"
        )
        assert score.band.value == finding.severity.value
        assert score.score < 76
        assert "not a probability" in score.explanation
        assert alert.severity is finding.severity

    summary = build_summary(
        input_name=_SAMPLE.name,
        events=parsed.events,
        invalid_events=parsed.invalid_count,
        findings=findings,
        alerts=alerts,
        scores=scores,
        started_at=_START,
        completed_at=_END,
    )
    again = build_summary(
        input_name=_SAMPLE.name,
        events=parsed.events,
        invalid_events=parsed.invalid_count,
        findings=findings,
        alerts=alerts,
        scores=scores,
        started_at=_START,
        completed_at=_END,
    )
    assert again == summary
    assert summary_from_json(render_json(summary)) == summary

    text = render_text(summary)
    rows = list(csv.DictReader(io.StringIO(render_csv(summary))))
    assert rows[0]["record_type"] == "summary"
    assert rows[0]["valid_events"] == str(parsed.valid_count)
    assert rows[0]["invalid_events"] == str(parsed.invalid_count)
    assert f"Valid events: {parsed.valid_count}" in text
    assert f"Invalid events: {parsed.invalid_count}" in text
    assert f"Records processed: {parsed.valid_count + parsed.invalid_count}" in text
    assert "not proof of compromise" in text
    assert "does not replace an enterprise SIEM" in text
