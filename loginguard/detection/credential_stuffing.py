"""Distributed failures that can resemble credential stuffing.

Password spraying is one source IP and many distinct usernames. Brute force
is one username and one source IP. This rule asks a different question: did
many source addresses produce ``LOGIN_FAILURE`` events for many usernames
inside one window?

An authentication log cannot prove credential stuffing. It does not show the
password that was offered, and it cannot show that a password came from a
leak. This rule does not consult a breach corpus and does not invent breach
evidence. When the events are one source IP and many usernames, they stay
with the spray rule. This rule does not emit a second finding for that shape.

Severity is ``LOW``. The username minimum matches the spray rule, and the
window is longer than the spray window, so the bar is not clearly higher.
Requiring several source addresses changes the shape of the pattern. It does
not outweigh that comparison, or the fact that the log still cannot show a
leaked password. ``MEDIUM``, ``HIGH``, and ``CRITICAL`` are not used.

Only ``LOGIN_FAILURE`` events count. A successful login is not a failure.
A failure with no username is skipped. A failure with no source IP is
skipped. Those events are not collected into a placeholder bucket. Usernames
are compared exactly, including case. Duplicate ``event_id`` values are
counted once. The earliest copy is kept.

The window is inclusive. The newest and oldest failure in a cluster may be
exactly ``window`` apart, and no further. A cluster qualifies only when both
the distinct-username minimum and the distinct-source minimum are met. Those
events are then consumed. One finding is emitted for that cluster, not one
per address and not one per username. A later burst can still produce
another finding.

``observed_count`` is the distinct username count. ``threshold`` is the
username minimum. ``Finding`` has a single ``source_ip`` and no field for an
address count, so the distinct source count is written into the description
and ``source_ip`` stays empty. ``affected_username`` stays empty because the
pattern is not one account. ``affected_usernames`` and the related event ids
are capped at 100. ``repr`` does not print usernames or addresses.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime, timedelta

from loginguard.detection.config import DetectionConfig
from loginguard.detection.finding import Finding, Severity
from loginguard.detection.rules import RuleRegistry
from loginguard.models import AuthEvent, EventType
from loginguard.utils.time_utils import format_timestamp

RULE_ID = "distributed-failure-heuristic"
_MAX_RELATED = 100

_DESCRIPTION = (
    "Flags LOGIN_FAILURE events for many distinct usernames from many source "
    "addresses inside one rolling window. The pattern is consistent with "
    "credential-stuffing-like or distributed guessing behavior. The log cannot "
    "show whether any password came from a leak. A single source address stays "
    "with the password-spraying rule and does not produce this finding. "
    "Usernames are compared case-sensitively. Events missing a username or "
    "source IP are skipped. Duplicate event ids count once. One finding is "
    "emitted for the whole consumed cluster. Severity is LOW because the "
    "username minimum matches spraying and the window is longer, so the bar "
    "is not clearly higher than the spray rule."
)
_RECOMMENDATION = (
    "Investigate the source addresses and the accounts that failed. "
    "Do not assume a breach. Do not guess passwords."
)
_TITLE = "Credential-stuffing-like or distributed guessing; log cannot show a leak"


class CredentialStuffingRule:
    """Detect many addresses failing against many usernames in one window.

    The username minimum, the source-address minimum, and the window come
    from ``DetectionConfig``. The evaluate method does not carry its own
    copies of those defaults. ``threshold`` reports the username minimum.
    The address minimum is read from the same configuration.
    """

    rule_id = RULE_ID
    description = _DESCRIPTION
    severity = Severity.LOW
    recommendation = _RECOMMENDATION

    def threshold(self, config: DetectionConfig) -> int:
        return config.distributed_min_usernames

    def window(self, config: DetectionConfig) -> timedelta:
        return config.distributed_window

    def evaluate(
        self,
        events: Sequence[AuthEvent],
        config: DetectionConfig,
    ) -> tuple[Finding, ...]:
        """Return one finding per consumed cluster, or an empty tuple."""
        min_usernames = self.threshold(config)
        min_source_ips = config.distributed_min_source_ips
        window = self.window(config)
        findings: list[Finding] = []
        for cluster in _clusters(_failure_events(events), min_usernames, min_source_ips, window):
            findings.append(_finding(cluster, min_usernames, min_source_ips, window))
        return tuple(findings)


def register_credential_stuffing(registry: RuleRegistry) -> None:
    """Register the distributed-failure heuristic on ``registry``.

    Importing this module does not register the rule.
    """
    registry.register(CredentialStuffingRule())


def _failure_events(events: Sequence[AuthEvent]) -> tuple[AuthEvent, ...]:
    selected = [
        event
        for event in events
        if event.event_type is EventType.LOGIN_FAILURE
        and event.username is not None
        and event.source_ip is not None
    ]
    return _unique_by_event_id(selected)


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
    min_usernames: int,
    min_source_ips: int,
    window: timedelta,
) -> tuple[tuple[AuthEvent, ...], ...]:
    """Return non-overlapping clusters that meet both minimums inside ``window``.

    ``events`` must already be unique and ordered by time. A cluster runs from
    a starting failure through the last later failure still inside the window.
    Both distinct usernames and distinct source addresses must meet their
    minimums. Those events are then consumed.
    """
    clusters: list[tuple[AuthEvent, ...]] = []
    start = 0
    count = len(events)
    while start < count:
        end = start
        while end + 1 < count and events[end + 1].timestamp - events[start].timestamp <= window:
            end += 1
        span = events[start : end + 1]
        if (
            len(_distinct_usernames(span)) >= min_usernames
            and len(_distinct_source_ips(span)) >= min_source_ips
        ):
            clusters.append(tuple(span))
            start = end + 1
        else:
            start += 1
    return tuple(clusters)


def _distinct_usernames(events: Sequence[AuthEvent]) -> tuple[str, ...]:
    return _distinct(events, "username")


def _distinct_source_ips(events: Sequence[AuthEvent]) -> tuple[str, ...]:
    return _distinct(events, "source_ip")


def _distinct(events: Sequence[AuthEvent], field: str) -> tuple[str, ...]:
    seen: set[str] = set()
    values: list[str] = []
    for event in events:
        value = getattr(event, field)
        if value is None or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return tuple(values)


def _finding(
    cluster: Sequence[AuthEvent],
    min_usernames: int,
    min_source_ips: int,
    window: timedelta,
) -> Finding:
    names = _distinct_usernames(cluster)
    ips = _distinct_source_ips(cluster)
    observed = len(names)
    stored_names = names[:_MAX_RELATED]
    related = tuple(event.event_id for event in cluster[:_MAX_RELATED])
    description = _describe(
        observed=observed,
        source_count=len(ips),
        min_usernames=min_usernames,
        min_source_ips=min_source_ips,
        window=window,
        first=cluster[0].timestamp,
        last=cluster[-1].timestamp,
        names=stored_names,
        ips=ips,
        event_count=len(cluster),
        stored_name_count=len(stored_names),
    )
    return Finding(
        finding_id=_finding_id(related),
        rule_id=RULE_ID,
        title=_TITLE,
        severity=Severity.LOW,
        description=description,
        recommendation=_RECOMMENDATION,
        observed_count=observed,
        threshold=min_usernames,
        window=window,
        related_event_ids=related,
        first_event_time=cluster[0].timestamp,
        last_event_time=cluster[-1].timestamp,
        affected_usernames=stored_names,
    )


def _describe(
    *,
    observed: int,
    source_count: int,
    min_usernames: int,
    min_source_ips: int,
    window: timedelta,
    first: datetime,
    last: datetime,
    names: Sequence[str],
    ips: Sequence[str],
    event_count: int,
    stored_name_count: int,
) -> str:
    window_text = _format_window(window)
    base = (
        "The pattern is consistent with credential-stuffing-like or distributed "
        "guessing behavior. The log cannot show whether any password came from a "
        f"leak. Observed {observed} distinct usernames and {source_count} distinct "
        f"source addresses between {format_timestamp(first)} and {format_timestamp(last)}. "
        f"Threshold is {min_usernames} distinct usernames and {min_source_ips} distinct "
        f"source addresses inside {window_text}. This is not proof of credential "
        "stuffing or a breach."
    )
    text = _with_evidence(base, names, ips)
    notes: list[str] = []
    if event_count > _MAX_RELATED:
        notes.append(f" The first {_MAX_RELATED} event ids are attached.")
    if observed > stored_name_count:
        notes.append(f" The first {stored_name_count} usernames are attached.")
    for note in notes:
        if len(text) + len(note) <= 500:
            text = f"{text}{note}"
    return text


def _with_evidence(base: str, names: Sequence[str], ips: Sequence[str]) -> str:
    name_text = ", ".join(repr(name) for name in names)
    ip_text = ", ".join(ips)
    candidates = (
        f"{base} Usernames {name_text}. Source addresses {ip_text}.",
        f"{base} Source addresses {ip_text}.",
        base,
    )
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if len(candidate) <= 500:
            return candidate
    return base


def _finding_id(event_ids: tuple[str, ...]) -> str:
    payload = "\n".join((RULE_ID, *event_ids)).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:20]
    return f"distributed-failure-{digest}"


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
