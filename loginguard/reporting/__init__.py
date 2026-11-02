"""Text, JSON, and CSV reports for one analysis run.

The default summary path is ``data/reports/analysis_summary.json``.
"""

from pathlib import Path

from loginguard.reporting.clock import utc_now
from loginguard.reporting.exporters import render_csv, render_json, render_text
from loginguard.reporting.summary import (
    SCHEMA,
    AnalysisSummary,
    ReportError,
    ReportFinding,
    SummaryStore,
    build_summary,
    summary_from_snapshot,
)

DEFAULT_SUMMARY_PATH = Path("data/reports/analysis_summary.json")

__all__ = [
    "DEFAULT_SUMMARY_PATH",
    "SCHEMA",
    "AnalysisSummary",
    "ReportError",
    "ReportFinding",
    "SummaryStore",
    "build_summary",
    "render_csv",
    "render_json",
    "render_text",
    "summary_from_snapshot",
    "utc_now",
]
