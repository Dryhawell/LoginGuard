"""Failed logins for many accounts from one source address.

Brute force is many ``LOGIN_FAILURE`` events for the same username and the
same source IP. Password spraying is different: one source IP, many distinct
usernames, and failures inside the window. Repeated failures against one
username do not match this rule. Those stay with the brute-force rule.
Different source addresses are not collapsed into one group.

Only ``LOGIN_FAILURE`` events count. A successful login is not a failure.
A success for one of the usernames does not erase the failures and does not
raise the severity.

A failure with no username is skipped. A failure with no source IP is skipped.
Those events are not collected into a placeholder bucket, and a missing
address is not merged with a real one.

Usernames are compared exactly, including case. Duplicate ``event_id`` values
for one source address are counted once. The earliest copy is kept.

A rolling window is inclusive: the newest and oldest failure in a cluster may
be exactly ``window`` apart, and no further. The cluster counts distinct
usernames, not raw failures. When a cluster meets the threshold, its events
are consumed. One finding is emitted for that source IP and that cluster, not
one finding per username and not one per failure. A later burst from the same
address can still produce another finding. An overlapping window that would
reuse those events does not. This is narrower than the alert deduplication
planned for Phase 11.

A finding is a suspicion. A misconfigured client can try several accounts.
Severity stays ``MEDIUM`` for that reason, the same rationale as brute force.
A success after a burst of failures for one account is a separate rule.
``CRITICAL`` is not used.

``observed_count`` is the number of distinct usernames in the cluster.
``source_ip`` and ``affected_usernames`` hold the address and those names
because an investigator needs them. ``repr`` does not print either.
``affected_username`` stays empty: this pattern is not one account.
The stored username list and the related event ids are capped at 100, the
same cap the brute-force rule uses for event ids. ``observed_count`` still
reports the full distinct count.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from loginguard.detection.config import DetectionConfig
from loginguard.detection.finding import Finding, Severity
from loginguard.detection.rules import RuleRegistry
from loginguard.models import AuthEvent, EventType
from loginguard.utils.time_utils import format_timestamp

RULE_ID = "password-spray-distinct-usernames"
_MAX_RELATED = 100

_DESCRIPTION = (
    "Flags one source IP that produces LOGIN_FAILURE events for many distinct "
    "usernames inside a rolling window. Usernames are compared case-sensitively. "
    "Repeated failures for a single username are not this rule. Events missing a "
    "username or source IP are skipped. Different source addresses are not combined. "
    "One finding is emitted per source IP per consumed cluster, which is narrower "
    "than later alert deduplication. A finding is a suspicion, not proof of an attack."
)
_RECOMMENDATION = (
    "Review the source address and the accounts that failed. Check whether this "
    "is a misconfigured client or a password spray. Do not guess passwords. Do not "
    "block the source solely on this signal."
)


class PasswordSprayRule:
    """Detect one source address failing against many distinct usernames.

    ``threshold`` and ``window`` come from ``DetectionConfig``. The evaluate
    method does not carry its own copies of those defaults.
    """

    rule_id = RULE_ID
    description = _DESCRIPTION
    severity = Severity.MEDIUM
    recommendation = _RECOMMENDATION

    def threshold(self, config: DetectionConfig) -> int:
        return config.password_spray_min_usernames

    def window(self, config: DetectionConfig) -> timedelta:
        return config.password_spray_window

    def evaluate(
        self,
        events: Sequence[AuthEvent],
        config: DetectionConfig,
    ) -> tuple[Finding, ...]:
        """Return one finding per consumed username cluster, or an empty tuple."""
        threshold = self.threshold(config)
        window = self.window(config)
        findings: list[Finding] = []
        for source_ip, group in _failure_groups(events):
            for cluster in _clusters(group, threshold, window):
                findings.append(_finding(source_ip, cluster, threshold, window))
        return tuple(findings)


def register_password_spraying(registry: RuleRegistry) -> None:
    """Register the password-spraying rule on ``registry``.

    Importing this module does not register the rule.
    """
    registry.register(PasswordSprayRule())


def _failure_groups(
    events: Sequence[AuthEvent],
) -> tuple[tuple[str, tuple[AuthEvent, ...]], ...]:
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.event_type is not EventType.LOGIN_FAILURE:
            continue
        if event.username is None or event.source_ip is None:
            continue
        grouped[event.source_ip].append(event)
    return tuple(
        (source_ip, _unique_by_event_id(grouped[source_ip]))
        for source_ip in sorted(grouped)
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
    The threshold counts distinct usernames in that span. Those events are
    then consumed.
    """
    clusters: list[tuple[AuthEvent, ...]] = []
    start = 0
    count = len(events)
    while start < count:
        end = start
        while end + 1 < count and events[end + 1].timestamp - events[start].timestamp <= window:
            end += 1
        if len(_distinct_usernames(events[start : end + 1])) >= threshold:
            clusters.append(tuple(events[start : end + 1]))
            start = end + 1
        else:
            start += 1
    return tuple(clusters)


def _distinct_usernames(events: Sequence[AuthEvent]) -> tuple[str, ...]:
    seen: set[str] = set()
    names: list[str] = []
    for event in events:
        username = event.username
        if username is None or username in seen:
            continue
        seen.add(username)
        names.append(username)
    return tuple(names)


def _finding(
    source_ip: str,
    cluster: Sequence[AuthEvent],
    threshold: int,
    window: timedelta,
) -> Finding:
    names = _distinct_usernames(cluster)
    observed = len(names)
    stored_names = names[:_MAX_RELATED]
    related = tuple(event.event_id for event in cluster[:_MAX_RELATED])
    first = cluster[0].timestamp
    last = cluster[-1].timestamp
    window_text = _format_window(window)
    description = (
        f"Failed logins for distinct usernames from the same source address. "
        f"Observed {observed} distinct usernames between {format_timestamp(first)} "
        f"and {format_timestamp(last)}. Threshold is {threshold} distinct usernames "
        f"inside {window_text}. This is a suspicion, not proof of an attack."
    )
    formatted = ", ".join(repr(name) for name in stored_names)
    detailed = f"{description} Usernames {formatted} from {source_ip}."
    if len(detailed) <= 500:
        description = detailed
    notes: list[str] = []
    if len(cluster) > _MAX_RELATED:
        notes.append(f" The first {_MAX_RELATED} event ids are attached.")
    if observed > len(stored_names):
        notes.append(f" The first {len(stored_names)} usernames are attached.")
    for note in notes:
        if len(description) + len(note) <= 500:
            description = f"{description}{note}"
    return Finding(
        finding_id=_finding_id(source_ip, related),
        rule_id=RULE_ID,
        title="Failures across distinct usernames",
        severity=Severity.MEDIUM,
        description=description,
        recommendation=_RECOMMENDATION,
        observed_count=observed,
        threshold=threshold,
        window=window,
        related_event_ids=related,
        first_event_time=first,
        last_event_time=last,
        affected_usernames=stored_names,
        source_ip=source_ip,
    )


def _finding_id(source_ip: str, event_ids: tuple[str, ...]) -> str:
    payload = "\n".join((source_ip, *event_ids)).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:20]
    return f"password-spray-{digest}"


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
