"""Run registered rules over normalized authentication events.

The engine does not decide what is suspicious. Each rule does. The engine
orders events by time, passes the active configuration through, and collects
findings. It does not slice time windows, deduplicate alerts, or score risk.
"""

from __future__ import annotations

from collections.abc import Sequence

from loginguard.detection.config import DetectionConfig
from loginguard.detection.finding import Finding, Severity
from loginguard.detection.rules import InvalidRuleError, RuleRegistry
from loginguard.models import AuthEvent


class DetectionEngine:
    """Apply every registered rule to one batch of events.

    The registry is read at the start of each ``run``. A rule registered
    during a run is not included until the next run.
    """

    def __init__(
        self,
        registry: RuleRegistry,
        config: DetectionConfig | None = None,
    ) -> None:
        if not isinstance(registry, RuleRegistry):
            raise TypeError("registry must be a RuleRegistry.")
        if config is None:
            config = DetectionConfig()
        elif not isinstance(config, DetectionConfig):
            raise TypeError("config must be a DetectionConfig.")
        self._registry = registry
        self._config = config

    @property
    def config(self) -> DetectionConfig:
        """Return the configuration this engine passes to every rule."""
        return self._config

    @property
    def registry(self) -> RuleRegistry:
        """Return the registry this engine reads."""
        return self._registry

    def run(self, events: Sequence[AuthEvent]) -> tuple[Finding, ...]:
        """Return findings from all registered rules.

        Events are ordered by timestamp, then by ``event_id``, before any rule
        sees them. The caller's sequence is left unchanged. An empty registry
        produces an empty result even when events are present.

        Raises:
            InvalidRuleError: a rule returns something other than findings, a
                finding names a different rule id, or a finding uses CRITICAL.
            TypeError: ``events`` contains a value that is not an ``AuthEvent``.
        """
        ordered = _order_events(events)
        findings: list[Finding] = []
        for rule in self._registry.rules():
            produced = rule.evaluate(ordered, self._config)
            findings.extend(_require_findings(rule.rule_id, produced))
        return tuple(findings)


def _order_events(events: Sequence[AuthEvent]) -> tuple[AuthEvent, ...]:
    if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
        raise TypeError("events must be a sequence of AuthEvent objects.")
    ordered: list[AuthEvent] = []
    for event in events:
        if not isinstance(event, AuthEvent):
            raise TypeError("events must be a sequence of AuthEvent objects.")
        ordered.append(event)
    ordered.sort(key=lambda event: (event.timestamp, event.event_id))
    return tuple(ordered)


def _require_findings(rule_id: str, produced: object) -> tuple[Finding, ...]:
    if isinstance(produced, (str, bytes)) or not isinstance(produced, Sequence):
        raise InvalidRuleError(f"Rule {rule_id!r} must return a sequence of findings.")
    findings: list[Finding] = []
    for item in produced:
        if not isinstance(item, Finding):
            raise InvalidRuleError(f"Rule {rule_id!r} returned a value that is not a Finding.")
        if item.rule_id != rule_id:
            raise InvalidRuleError(
                f"Rule {rule_id!r} returned a finding for rule {item.rule_id!r}."
            )
        if item.severity is Severity.CRITICAL:
            raise InvalidRuleError(
                f"Rule {rule_id!r} returned CRITICAL. That severity is reserved."
            )
        findings.append(item)
    return tuple(findings)
