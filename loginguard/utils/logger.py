"""Application logging for LoginGuard.

Operational messages go to stderr. Passwords, session cookies, tokens, and
raw log lines are never written here. Routine logs also omit usernames and
source IP addresses so a normal run does not copy identity data into the
application log.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "loginguard"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
VALID_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Configure the LoginGuard logger and return it.

    Stdout stays free for future reports. Reconfiguring replaces handlers so
    repeated calls do not duplicate messages.

    Raises:
        ValueError: ``level`` is not a recognized logging level name.
    """
    normalized = level.upper()
    if normalized not in VALID_LEVELS:
        allowed = ", ".join(VALID_LEVELS)
        raise ValueError(f"Unknown log level {level!r}. Choose one of: {allowed}.")

    logger = logging.getLogger(LOGGER_NAME)
    for existing in logger.handlers[:]:
        logger.removeHandler(existing)
        existing.close()
    logger.setLevel(normalized)
    logger.propagate = False

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(normalized)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(handler)
    return logger
