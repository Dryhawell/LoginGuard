"""Configurable thresholds for later detection rules.

The values below are demonstration defaults from the project specification.
They are not universal indicators of malicious activity. The brute-force rule
reads ``brute_force_min_failures`` and ``brute_force_window``. The password-spray
settings wait for a later phase.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

DEFAULT_BRUTE_FORCE_MIN_FAILURES = 5
DEFAULT_BRUTE_FORCE_WINDOW = timedelta(minutes=5)
DEFAULT_PASSWORD_SPRAY_MIN_USERNAMES = 5
DEFAULT_PASSWORD_SPRAY_WINDOW = timedelta(minutes=10)

_MAX_THRESHOLD = 100_000
_MAX_WINDOW = timedelta(days=366)


class DetectionConfigError(ValueError):
    """Raised when a detection setting is missing, mistyped, or out of range."""

    def __init__(self, messages: tuple[str, ...]):
        if not messages:
            raise ValueError("messages must not be empty")
        self.messages = messages
        super().__init__("; ".join(messages))


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Thresholds and time windows detection rules read.

    A time window is a duration, not a timestamp. Changing a value here does
    not detect anything until a rule that reads it is registered and run.
    """

    brute_force_min_failures: int = DEFAULT_BRUTE_FORCE_MIN_FAILURES
    brute_force_window: timedelta = DEFAULT_BRUTE_FORCE_WINDOW
    password_spray_min_usernames: int = DEFAULT_PASSWORD_SPRAY_MIN_USERNAMES
    password_spray_window: timedelta = DEFAULT_PASSWORD_SPRAY_WINDOW

    def __post_init__(self) -> None:
        errors: list[str] = []
        _check_threshold("brute_force_min_failures", self.brute_force_min_failures, errors)
        _check_threshold(
            "password_spray_min_usernames",
            self.password_spray_min_usernames,
            errors,
        )
        _check_window("brute_force_window", self.brute_force_window, errors)
        _check_window("password_spray_window", self.password_spray_window, errors)
        if errors:
            raise DetectionConfigError(tuple(errors))


def _check_threshold(name: str, value: object, errors: list[str]) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{name}: expected a positive integer")
        return
    if value < 1 or value > _MAX_THRESHOLD:
        errors.append(f"{name}: expected an integer from 1 to {_MAX_THRESHOLD}")


def _check_window(name: str, value: object, errors: list[str]) -> None:
    if not isinstance(value, timedelta):
        errors.append(f"{name}: expected a positive timedelta")
        return
    if value <= timedelta(0) or value > _MAX_WINDOW:
        errors.append(f"{name}: expected a duration from one microsecond through 366 days")
