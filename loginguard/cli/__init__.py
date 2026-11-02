"""Command-line commands for LoginGuard.

``analyze`` and ``validate`` read a JSONL file. ``alerts`` and ``stats``
read the stored snapshot. ``report`` renders that run as text, JSON, or CSV.
"""

from loginguard.cli.commands import build_parser, dispatch

__all__ = ["build_parser", "dispatch"]
