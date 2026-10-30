"""Configurable thresholds for detection rules.

The values below are demonstration defaults from the project specification.
They are not universal indicators of malicious activity. The brute-force rule
reads ``brute_force_min_failures`` and ``brute_force_window``. The password-spray
rule reads ``password_spray_min_usernames`` and ``password_spray_window``. The
suspicious-success rule reads ``success_after_failure_min_failures`` and
``success_after_failure_window``. The distributed-failure heuristic reads
``distributed_min_usernames``, ``distributed_min_source_ips``, and
``distributed_window``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

DEFAULT_BRUTE_FORCE_MIN_FAILURES = 5
DEFAULT_BRUTE_FORCE_WINDOW = timedelta(minutes=5)
DEFAULT_PASSWORD_SPRAY_MIN_USERNAMES = 5
DEFAULT_PASSWORD_SPRAY_WINDOW = timedelta(minutes=10)
DEFAULT_SUCCESS_AFTER_FAILURE_MIN_FAILURES = 5
DEFAULT_SUCCESS_AFTER_FAILURE_WINDOW = timedelta(minutes=10)
DEFAULT_DISTRIBUTED_MIN_USERNAMES = 5
DEFAULT_DISTRIBUTED_MIN_SOURCE_IPS = 3
DEFAULT_DISTRIBUTED_WINDOW = timedelta(minutes=15)

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
    success_after_failure_min_failures: int = DEFAULT_SUCCESS_AFTER_FAILURE_MIN_FAILURES
    success_after_failure_window: timedelta = DEFAULT_SUCCESS_AFTER_FAILURE_WINDOW
    distributed_min_usernames: int = DEFAULT_DISTRIBUTED_MIN_USERNAMES
    distributed_min_source_ips: int = DEFAULT_DISTRIBUTED_MIN_SOURCE_IPS
    distributed_window: timedelta = DEFAULT_DISTRIBUTED_WINDOW

    def __post_init__(self) -> None:
        errors: list[str] = []
        _check_threshold("brute_force_min_failures", self.brute_force_min_failures, errors)
        _check_threshold(
            "password_spray_min_usernames",
            self.password_spray_min_usernames,
            errors,
        )
        _check_threshold(
            "success_after_failure_min_failures",
            self.success_after_failure_min_failures,
            errors,
        )
        _check_threshold(
            "distributed_min_usernames",
            self.distributed_min_usernames,
            errors,
        )
        _check_threshold(
            "distributed_min_source_ips",
            self.distributed_min_source_ips,
            errors,
        )
        _check_window("brute_force_window", self.brute_force_window, errors)
        _check_window("password_spray_window", self.password_spray_window, errors)
        _check_window(
            "success_after_failure_window",
            self.success_after_failure_window,
            errors,
        )
        _check_window("distributed_window", self.distributed_window, errors)
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
