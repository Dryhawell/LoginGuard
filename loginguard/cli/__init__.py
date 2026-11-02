"""Command-line commands for LoginGuard.

``analyze`` and ``validate`` read a JSONL file. ``alerts``, ``stats``, and
``report`` read the stored snapshot. JSON and CSV export belong to a later
reporting phase.
"""

from loginguard.cli.commands import build_parser, dispatch

__all__ = ["build_parser", "dispatch"]
