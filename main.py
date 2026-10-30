"""Command-line entry point for LoginGuard.

The CLI still reports project status. JSONL ingestion, sample logs,
brute-force detection, password-spraying detection, suspicious
successful login detection, and the credential-stuffing heuristic are
available. The alert model and risk assessment are not.
"""

from __future__ import annotations

import argparse
import sys

from loginguard import __app_name__, __description__, __version__
from loginguard.utils.logger import VALID_LEVELS, configure_logging

MIN_PYTHON = (3, 12)


def build_parser() -> argparse.ArgumentParser:
    """Build the Phase 1 argument parser."""
    parser = argparse.ArgumentParser(
        prog="loginguard",
        description=(
            f"{__app_name__}: {__description__} "
            "Brute-force, password-spraying, suspicious-success, and the "
            "credential-stuffing heuristic are available. "
            "The alert model and risk assessment are not."
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
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the foundation CLI.

    Returns:
        0 when the process starts successfully.
        1 when the interpreter is older than Python 3.12.
        2 when argparse rejects the command line.
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

    print(f"{__app_name__} {__version__}")
    print("Status: credential-stuffing heuristic is ready.")
    print("The alert model and risk assessment are not implemented yet.")
    print("Next step: alert model and risk assessment (Phase 10).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
