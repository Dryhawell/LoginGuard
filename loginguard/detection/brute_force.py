"""Repeated failed logins against one account from one source address.

The rule groups ``LOGIN_FAILURE`` events by username and source IP. Usernames
are compared exactly, including case: ``Alice`` and ``alice`` are different
accounts because the event model preserves the source spelling.

Password spraying is a different rule. That rule is one source address and
many distinct usernames. Repeated failures for a single username stay here.

A failure with no username is not the same account as another nameless
failure. A failure with no source IP is not tied to a shared address. Those
events are skipped. They are not collected into a placeholder bucket.

Duplicate ``event_id`` values inside one group are counted once. The earliest
copy is kept. A rolling window is inclusive: the newest and oldest failure in
a cluster may be exactly ``window`` apart, and no further. When a cluster
meets the threshold, its events are consumed. A later burst for the same
account and address can still produce another finding. An overlapping window
that would reuse those events does not. That keeps one ongoing burst from
becoming one finding per failure. Richer alert deduplication is a later phase.

A finding is a suspicion. People mistype passwords, and scripts retry them.
Severity stays ``MEDIUM`` for that reason. ``HIGH`` is reserved for a later
rule that sees a stronger combination, such as a success after the burst.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from loginguard.detection.config import DetectionConfig
from loginguard.detection.engine import DetectionEngine
from loginguard.detection.finding import Finding, Severity
from loginguard.detection.password_spraying import register_password_spraying
from loginguard.detection.rules import RuleRegistry
from loginguard.models import AuthEvent, EventType
from loginguard.utils.time_utils import format_timestamp

RULE_ID = "brute-force-same-account"
_MAX_RELATED = 100

_DESCRIPTION = (
    "Flags repeated LOGIN_FAILURE events for one username and one source IP "
    "inside a rolling window. Usernames are compared case-sensitively. Events "
    "missing a username or source IP are skipped. A finding is a suspicion, "
    "not proof of an attack."
)
_RECOMMENDATION = (
    "Review the account activity with the owner. Check whether the failures "
    "are mistyped passwords or an automated retry. If the pattern continues, "
    "consider the organization's lockout and alerting policy."
)


class BruteForceRule:
    """Detect a burst of failures for one account from one source address.

    ``threshold`` and ``window`` come from ``DetectionConfig``. The evaluate
    method does not carry its own copies of those defaults.
    """

    rule_id = RULE_ID
    description = _DESCRIPTION
    severity = Severity.MEDIUM
    recommendation = _RECOMMENDATION

    def threshold(self, config: DetectionConfig) -> int:
        return config.brute_force_min_failures

    def window(self, config: DetectionConfig) -> timedelta:
        return config.brute_force_window

    def evaluate(
        self,
        events: Sequence[AuthEvent],
        config: DetectionConfig,
    ) -> tuple[Finding, ...]:
        """Return one finding per consumed failure cluster, or an empty tuple."""
        threshold = self.threshold(config)
        window = self.window(config)
        findings: list[Finding] = []
        for username, source_ip, group in _failure_groups(events):
            for cluster in _clusters(group, threshold, window):
                findings.append(_finding(username, source_ip, cluster, threshold, window))
        return tuple(findings)


def register_brute_force(registry: RuleRegistry) -> None:
    """Register the brute-force rule on ``registry``.

    Importing this module does not register the rule.
    """
    registry.register(BruteForceRule())


def register_builtin_rules(registry: RuleRegistry) -> None:
    """Register the attack rules implemented so far.

    Password-spraying detection is registered beside brute force. Later phases
    add their rules here deliberately. Importing a rule module does not
    register it.
    """
    register_brute_force(registry)
    register_password_spraying(registry)


def build_default_engine(config: DetectionConfig | None = None) -> DetectionEngine:
    """Return an engine with the shipped rules registered.

    The factory registers brute-force detection and password-spraying
    detection. An empty ``RuleRegistry`` passed to ``DetectionEngine`` still
    runs no rules.
    """
    registry = RuleRegistry()
    register_builtin_rules(registry)
    return DetectionEngine(registry, config)


def _failure_groups(
    events: Sequence[AuthEvent],
) -> tuple[tuple[str, str, tuple[AuthEvent, ...]], ...]:
    grouped: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.event_type is not EventType.LOGIN_FAILURE:
            continue
        if event.username is None or event.source_ip is None:
            continue
        grouped[(event.username, event.source_ip)].append(event)
    return tuple(
        (username, source_ip, _unique_by_event_id(grouped[username, source_ip]))
        for username, source_ip in sorted(grouped)
    )


def _unique_by_event_id(events: Sequence[AuthEvent]) -> tuple[AuthEvent, ...]:
    ordered = sorted(events, key=lambda event: (event.timestamp, event.event_id))
    seen: set[str] = set()
    unique: list[AuthEvent] = []
    for event in ordered:
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        unique.append(event)
    return tuple(unique)


def _clusters(
    events: Sequence[AuthEvent],
    threshold: int,
    window: timedelta,
) -> tuple[tuple[AuthEvent, ...], ...]:
    """Return non-overlapping clusters that meet ``threshold`` inside ``window``.

    ``events`` must already be unique and ordered by time. A cluster runs from
    a starting failure through the last later failure still inside the window.
    Those events are then consumed.
    """
    clusters: list[tuple[AuthEvent, ...]] = []
    start = 0
    count = len(events)
    while start < count:
        end = start
        while end + 1 < count and events[end + 1].timestamp - events[start].timestamp <= window:
            end += 1
        if end - start + 1 >= threshold:
            clusters.append(tuple(events[start : end + 1]))
            start = end + 1
        else:
            start += 1
    return tuple(clusters)


def _finding(
    username: str,
    source_ip: str,
    cluster: Sequence[AuthEvent],
    threshold: int,
    window: timedelta,
) -> Finding:
    observed = len(cluster)
    related = tuple(event.event_id for event in cluster[:_MAX_RELATED])
    first = cluster[0].timestamp
    last = cluster[-1].timestamp
    window_text = _format_window(window)
    description = (
        f"Repeated failed logins for the same username from the same source address. "
        f"Observed {observed} LOGIN_FAILURE events between {format_timestamp(first)} "
        f"and {format_timestamp(last)}. Threshold is {threshold} failures inside "
        f"{window_text}. This is a suspicion, not proof of an attack."
    )
    detailed = f"{description} Account {username!r} from {source_ip}."
    if len(detailed) <= 500:
        description = detailed
    if observed > _MAX_RELATED:
        note = f" The first {_MAX_RELATED} event ids are attached."
        if len(description) + len(note) <= 500:
            description = f"{description}{note}"
    return Finding(
        finding_id=_finding_id(username, source_ip, related),
        rule_id=RULE_ID,
        title="Repeated failed logins",
        severity=Severity.MEDIUM,
        description=description,
        recommendation=_RECOMMENDATION,
        observed_count=observed,
        threshold=threshold,
        window=window,
        related_event_ids=related,
        first_event_time=first,
        last_event_time=last,
        affected_username=username,
        source_ip=source_ip,
    )


def _finding_id(username: str, source_ip: str, event_ids: tuple[str, ...]) -> str:
    payload = "\n".join((username, source_ip, *event_ids)).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:20]
    return f"brute-force-{digest}"


def _format_window(window: timedelta) -> str:
    seconds = int(window.total_seconds())
    if seconds > 0 and seconds % 3600 == 0:
        hours = seconds // 3600
        unit = "hour" if hours == 1 else "hours"
        return f"{hours} {unit}"
    if seconds > 0 and seconds % 60 == 0:
        minutes = seconds // 60
        unit = "minute" if minutes == 1 else "minutes"
        return f"{minutes} {unit}"
    unit = "second" if seconds == 1 else "seconds"
    return f"{seconds} {unit}"
