"""Detection engine foundation.

The rule in this module is a test double. It counts events. It does not detect
an attack, and it is not registered by the package.
"""

from collections.abc import Sequence
from datetime import timedelta

import pytest

from loginguard.detection import (
    DetectionConfig,
    DetectionConfigError,
    DetectionEngine,
    DuplicateRuleError,
    Finding,
    FindingValidationError,
    InvalidRuleError,
    RuleRegistry,
    Severity,
    UnknownRuleError,
)
from loginguard.models import AuthEvent

_WINDOW = timedelta(minutes=5)


class EventCountRule:
    """Count events so the engine can be exercised. Not an attack detector."""

    description = "Counts events for the engine test. This is not an attack detector."
    severity = Severity.INFO
    recommendation = "No security action. This rule only exercises the engine."

    def __init__(self, rule_id: str = "test.event_count", *, emit: bool = True) -> None:
        self.rule_id = rule_id
        self.emit = emit
        self.seen: list[str] = []
        self.seen_config: DetectionConfig | None = None

    def threshold(self, config: DetectionConfig) -> int:
        return 1

    def window(self, config: DetectionConfig) -> timedelta:
        return _WINDOW

    def evaluate(
        self,
        events: Sequence[AuthEvent],
        config: DetectionConfig,
    ) -> tuple[Finding, ...]:
        self.seen = [event.event_id for event in events]
        self.seen_config = config
        if not self.emit or not events:
            return ()
        count = len(events)
        return (
            Finding(
                finding_id=f"{self.rule_id}:batch",
                rule_id=self.rule_id,
                title="Event count (test double)",
                severity=self.severity,
                description=(
                    f"Saw {count} events. The test threshold is {self.threshold(config)} "
                    f"and the test window is {_WINDOW}. This is not evidence of an attack."
                ),
                recommendation=self.recommendation,
                observed_count=count,
                threshold=self.threshold(config),
                window=self.window(config),
                related_event_ids=tuple(self.seen),
                first_event_time=events[0].timestamp,
                last_event_time=events[-1].timestamp,
                affected_username="alice",
                source_ip="192.0.2.10",
            ),
        )


def _event(event_id: str, timestamp: str) -> AuthEvent:
    return AuthEvent.create(
        timestamp=timestamp,
        event_type="LOGIN_SUCCESS",
        event_id=event_id,
        username="alice",
        source_ip="192.0.2.10",
    )


def test_registry_starts_empty_and_looks_up_a_registered_rule() -> None:
    registry = RuleRegistry()
    rule = EventCountRule()

    assert len(registry) == 0
    registry.register(rule)

    assert len(registry) == 1
    assert "test.event_count" in registry
    assert registry.get("test.event_count") is rule


def test_duplicate_rule_id_is_rejected() -> None:
    registry = RuleRegistry()
    registry.register(EventCountRule())

    with pytest.raises(DuplicateRuleError) as exc:
        registry.register(EventCountRule())

    assert exc.value.rule_id == "test.event_count"
    assert len(registry) == 1


def test_unknown_rule_lookup_is_rejected() -> None:
    with pytest.raises(UnknownRuleError) as exc:
        RuleRegistry().get("missing.rule")

    assert exc.value.rule_id == "missing.rule"


def test_critical_severity_is_rejected_at_registration() -> None:
    rule = EventCountRule()
    rule.severity = Severity.CRITICAL

    with pytest.raises(InvalidRuleError):
        RuleRegistry().register(rule)


def test_engine_emits_a_finding_and_a_rule_may_decline() -> None:
    registry = RuleRegistry()
    counter = EventCountRule()
    silent = EventCountRule("test.silent", emit=False)
    registry.register(silent)
    registry.register(counter)
    events = [
        _event("later", "2026-09-10T10:02:00Z"),
        _event("earlier", "2026-09-10T10:00:00Z"),
        _event("middle", "2026-09-10T10:01:00Z"),
    ]

    findings = DetectionEngine(registry).run(events)

    assert [event.event_id for event in events] == ["later", "earlier", "middle"]
    assert counter.seen == ["earlier", "middle", "later"]
    assert silent.seen == ["earlier", "middle", "later"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "test.event_count"
    assert finding.observed_count == 3
    assert finding.severity is Severity.INFO
    assert "not evidence of an attack" in finding.description
    assert finding.related_event_ids == ("earlier", "middle", "later")
    assert "alice" not in repr(finding)
    assert "192.0.2.10" not in repr(finding)


def test_rules_run_in_id_order() -> None:
    registry = RuleRegistry()
    registry.register(EventCountRule("test.b"))
    registry.register(EventCountRule("test.a"))

    findings = DetectionEngine(registry).run((_event("one", "2026-09-10T10:00:00Z"),))

    assert [finding.rule_id for finding in findings] == ["test.a", "test.b"]


def test_empty_registry_produces_no_findings() -> None:
    findings = DetectionEngine(RuleRegistry()).run((_event("one", "2026-09-10T10:00:00Z"),))

    assert findings == ()


def test_config_defaults_and_overrides_are_explicit() -> None:
    defaults = DetectionConfig()

    assert defaults.brute_force_min_failures == 5
    assert defaults.brute_force_window == timedelta(minutes=5)
    assert defaults.password_spray_min_usernames == 5
    assert defaults.password_spray_window == timedelta(minutes=10)
    assert defaults.success_after_failure_min_failures == 5
    assert defaults.success_after_failure_window == timedelta(minutes=10)
    assert defaults.distributed_min_usernames == 5
    assert defaults.distributed_min_source_ips == 3
    assert defaults.distributed_window == timedelta(minutes=15)

    custom = DetectionConfig(
        brute_force_min_failures=9,
        brute_force_window=timedelta(minutes=2),
    )
    rule = EventCountRule()
    registry = RuleRegistry()
    registry.register(rule)
    DetectionEngine(registry, custom).run((_event("one", "2026-09-10T10:00:00Z"),))

    assert rule.seen_config is custom
    assert rule.seen_config.brute_force_min_failures == 9
    assert rule.seen_config.brute_force_window == timedelta(minutes=2)
    assert rule.seen_config.password_spray_min_usernames == 5
    assert rule.seen_config.success_after_failure_min_failures == 5
    assert rule.seen_config.success_after_failure_window == timedelta(minutes=10)
    assert rule.seen_config.distributed_min_usernames == 5
    assert rule.seen_config.distributed_min_source_ips == 3
    assert rule.seen_config.distributed_window == timedelta(minutes=15)


def test_invalid_configuration_is_rejected() -> None:
    with pytest.raises(DetectionConfigError) as exc:
        DetectionConfig(brute_force_min_failures=0, password_spray_window=timedelta(0))

    joined = " ".join(exc.value.messages)
    assert "brute_force_min_failures:" in joined
    assert "password_spray_window:" in joined

    with pytest.raises(DetectionConfigError) as boolean_exc:
        DetectionConfig(password_spray_min_usernames=True)  # type: ignore[arg-type]

    assert "positive integer" in boolean_exc.value.messages[0]


def test_rule_must_return_findings_for_its_own_id() -> None:
    class BrokenRule(EventCountRule):
        def evaluate(self, events: Sequence[AuthEvent], config: DetectionConfig) -> tuple[Finding, ...]:
            return None  # type: ignore[return-value]

    registry = RuleRegistry()
    registry.register(BrokenRule())

    with pytest.raises(InvalidRuleError):
        DetectionEngine(registry).run((_event("one", "2026-09-10T10:00:00Z"),))


def test_engine_rejects_a_critical_finding() -> None:
    class CriticalFindingRule(EventCountRule):
        def evaluate(
            self,
            events: Sequence[AuthEvent],
            config: DetectionConfig,
        ) -> tuple[Finding, ...]:
            original = super().evaluate(events, config)[0]
            return (
                Finding(
                    finding_id=original.finding_id,
                    rule_id=self.rule_id,
                    title=original.title,
                    severity=Severity.CRITICAL,
                    description=original.description,
                    recommendation=original.recommendation,
                    observed_count=original.observed_count,
                    threshold=original.threshold,
                    window=original.window,
                ),
            )

    registry = RuleRegistry()
    registry.register(CriticalFindingRule())

    with pytest.raises(InvalidRuleError) as exc:
        DetectionEngine(registry).run((_event("one", "2026-09-10T10:00:00Z"),))

    assert "CRITICAL" in str(exc.value)


def test_finding_rejects_a_secret_assignment_without_echoing_it() -> None:
    with pytest.raises(FindingValidationError) as exc:
        Finding(
            finding_id="finding-1",
            rule_id="test.event_count",
            title="Event count (test double)",
            severity="LOW",
            description="password=hunter2",
            recommendation="Review the account.",
            observed_count=1,
            threshold=1,
            window=_WINDOW,
        )

    assert "hunter2" not in str(exc.value)
    assert "description: refusing to store a secret assignment" in exc.value.messages


def test_finding_rejects_a_naive_evidence_time() -> None:
    from datetime import datetime

    with pytest.raises(FindingValidationError) as exc:
        Finding(
            finding_id="finding-1",
            rule_id="test.event_count",
            title="Event count (test double)",
            severity=Severity.LOW,
            description="Saw 1 event. This is not evidence of an attack.",
            recommendation="No security action.",
            observed_count=1,
            threshold=1,
            window=_WINDOW,
            first_event_time=datetime(2026, 9, 10, 10, 0),
        )

    assert "not assumed to be UTC" in str(exc.value)
