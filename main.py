"""Command-line entry point for LoginGuard.

``analyze`` reads a JSONL log, runs the built-in rules, and stores the
snapshot. ``validate`` only parses. ``alerts``, ``stats``, and ``report``
read that snapshot. JSON and CSV export are a later phase.
"""

from __future__ import annotations

import sys

from loginguard import __app_name__, __version__
from loginguard.cli import build_parser, dispatch
from loginguard.cli.commands import status_lines
from loginguard.ingestion import IngestionError
from loginguard.storage import StorageError
from loginguard.utils.logger import configure_logging

MIN_PYTHON = (3, 12)


def main(argv: list[str] | None = None) -> int:
    """Run one LoginGuard command.

    Returns:
        0 when the command finishes. A detected pattern is still 0.
        1 when the interpreter is too old, or a file cannot be read or written.
        argparse exits with 2 when the command line is invalid.
    """
    if sys.version_info < MIN_PYTHON:
        required = ".".join(str(part) for part in MIN_PYTHON)
        current = ".".join(str(part) for part in sys.version_info[:3])
        print(
            f"{__app_name__} requires Python {required} or newer. Current interpreter: {current}.",
            file=sys.stderr,
        )
        return 1

    parser = build_parser()
    args = parser.parse_args(argv)
    logger = configure_logging(args.log_level)
    logger.info("%s %s started.", __app_name__, __version__)
    try:
        text = dispatch(args)
    except (IngestionError, StorageError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if text is None:
        print("\n".join(status_lines()))
        return 0
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
