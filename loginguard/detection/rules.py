"""Rule interface and registry.

The registry starts empty. Attack rules are added in later phases. A test can
register its own rule without that rule being a detector LoginGuard ships.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Protocol, runtime_checkable

from loginguard.detection.config import DetectionConfig
from loginguard.detection.finding import Finding, Severity
from loginguard.models import AuthEvent

_MAX_RULE_ID = 128


class DetectionError(ValueError):
    """Base error for rule registration and lookup."""


class DuplicateRuleError(DetectionError):
    """Raised when a second rule uses an id that is already registered."""

    def __init__(self, rule_id: str):
        self.rule_id = rule_id
        super().__init__(f"A rule with id {rule_id!r} is already registered.")


class UnknownRuleError(DetectionError):
    """Raised when a lookup asks for a rule that was not registered."""

    def __init__(self, rule_id: str):
        self.rule_id = rule_id
        super().__init__(f"No rule with id {rule_id!r} is registered.")


class InvalidRuleError(DetectionError):
    """Raised when an object does not satisfy the rule interface."""

    def __init__(self, message: str):
        super().__init__(message)


@runtime_checkable
class DetectionRule(Protocol):
    """One detection rule.

    ``threshold`` and ``window`` read the active configuration so limits are
    not buried in the rule body. ``evaluate`` returns findings, or an empty
    tuple when the rule declines to report anything.

    A finding is a suspicion with an explanation. It is not proof of an attack.
    """

    rule_id: str
    description: str
    severity: Severity
    recommendation: str

    def threshold(self, config: DetectionConfig) -> int:
        """Return the count this rule requires under ``config``."""

    def window(self, config: DetectionConfig) -> timedelta:
        """Return the duration this rule uses under ``config``."""

    def evaluate(
        self,
        events: Sequence[AuthEvent],
        config: DetectionConfig,
    ) -> tuple[Finding, ...]:
        """Inspect events and return findings, or an empty tuple."""


class RuleRegistry:
    """Ordered collection of detection rules.

    Registration order does not decide run order. ``rules`` returns rules
    sorted by id so a run is deterministic.
    """

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        """Add ``rule``.

        Raises:
            InvalidRuleError: the object is missing required attributes, or its
                severity is ``CRITICAL``.
            DuplicateRuleError: ``rule.rule_id`` is already present.
        """
        if not isinstance(rule, DetectionRule):
            raise InvalidRuleError("Expected an object with the detection rule interface.")
        rule_id = _require_rule_id(rule.rule_id)
        _require_rule_text("description", rule.description)
        _require_rule_text("recommendation", rule.recommendation)
        if not isinstance(rule.severity, Severity):
            raise InvalidRuleError("severity must be a Severity value.")
        if rule.severity is Severity.CRITICAL:
            raise InvalidRuleError(
                "CRITICAL is reserved. Foundation rules use INFO, LOW, MEDIUM, or HIGH."
            )
        if rule_id in self._rules:
            raise DuplicateRuleError(rule_id)
        self._rules[rule_id] = rule

    def get(self, rule_id: str) -> DetectionRule:
        """Return the rule registered under ``rule_id``."""
        try:
            return self._rules[rule_id]
        except KeyError:
            raise UnknownRuleError(rule_id) from None

    def __contains__(self, rule_id: object) -> bool:
        return isinstance(rule_id, str) and rule_id in self._rules

    def __len__(self) -> int:
        return len(self._rules)

    def rules(self) -> tuple[DetectionRule, ...]:
        """Return a snapshot of the registered rules, sorted by id."""
        return tuple(self._rules[key] for key in sorted(self._rules))


def _require_rule_id(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise InvalidRuleError("rule_id must be non-empty text without surrounding space.")
    if len(value) > _MAX_RULE_ID or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise InvalidRuleError("rule_id is too long or contains control characters.")
    return value


def _require_rule_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise InvalidRuleError(f"{name} must be non-empty text.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise InvalidRuleError(f"{name} contains control characters.")
