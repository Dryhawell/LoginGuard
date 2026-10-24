"""A successful login after a burst of failures for the same account.

Brute force counts ``LOGIN_FAILURE`` events for one username and one source
IP, and it stops there. Password spraying counts distinct usernames from one
source IP. This rule asks a different question: did this username succeed
after enough recent failures?

The window ends at the ``LOGIN_SUCCESS`` timestamp and looks backward by
``success_after_failure_window``. A failure counts when its timestamp is
greater than or equal to ``success_time - window`` and less than or equal to
``success_time``. The boundary is inclusive. A failure exactly ``window``
before the success still counts. A failure any earlier does not. Failures
after the success are outside that success's window. The success event itself
is not a failure and is not added to the count. Only ``LOGIN_FAILURE`` events
count. Other event types are ignored.

Events are grouped by username only. Source IP is not part of the group key.
Failures may come from one address or from several. The success may come from
one of those addresses or from a different one. A missing source IP does not
drop the event. ``Finding.source_ip`` stores the success address when the
success has one. Failure addresses are written into the description when they
are present. The finding model keeps a single source address, so the failure
addresses live in that evidence text.

A missing username is skipped. Empty usernames are not collected into one
bucket. Usernames are compared exactly, including case, matching the other
rules. Duplicate ``event_id`` values are counted once. The earliest copy is
kept, so a duplicated success does not produce a second finding.

Each qualifying success produces one finding. Failures are not consumed.
Two successes that each meet the threshold produce two findings, even when
they share the same failures. Related event ids are the counted failure ids
in time order, then the success id, capped at 100. When that list would be
longer, the earliest 99 failure ids and the success id are kept.
``observed_count`` remains the full failure count.

This is an investigative signal, not proof of compromise. A person can
mistype a password and then type it correctly. Severity is ``HIGH`` because
a success after the burst is a stronger combination than failures alone.
``CRITICAL`` is not used.

An unfamiliar source IP is not, by itself, a finding. An address that has
not appeared before is not automatically an attack. Impossible travel is out
of scope: these logs have no geolocation, and this rule does not invent it.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta

from loginguard.detection.config import DetectionConfig
from loginguard.detection.finding import Finding, Severity
from loginguard.detection.rules import RuleRegistry
from loginguard.models import AuthEvent, EventType
from loginguard.utils.time_utils import format_timestamp

RULE_ID = "success-after-failures"
_MAX_RELATED = 100
_MAX_LISTED_IPS = 8

_DESCRIPTION = (
    "Flags one LOGIN_SUCCESS for a username that already has enough "
    "LOGIN_FAILURE events inside the window ending at that success. The window "
    "is inclusive and looks backward from the success. The success itself is not "
    "a failure. Usernames are compared case-sensitively and grouped without regard "
    "to source IP. A missing username is skipped. Duplicate event ids count once. "
    "One finding is emitted per qualifying success. An unfamiliar source IP is not "
    "by itself a finding, and impossible travel is out of scope because the logs "
    "have no geolocation. A finding is an investigative signal, not proof of compromise."
)
_RECOMMENDATION = (
    "Investigate the account. Check with the user whether they eventually "
    "typed the right password, and review the source of the success. "
    "Do not guess passwords. Do not treat this signal as a confirmed takeover "
    "or as automatic proof that the account should be blocked."
)


class SuspiciousLoginRule:
    """Detect a success that follows a recent burst of failures for one account.

    ``threshold`` and ``window`` come from ``DetectionConfig``. The evaluate
    method does not carry its own copies of those defaults.
    """

    rule_id = RULE_ID
    description = _DESCRIPTION
    severity = Severity.HIGH
    recommendation = _RECOMMENDATION

    def threshold(self, config: DetectionConfig) -> int:
        return config.success_after_failure_min_failures

    def window(self, config: DetectionConfig) -> timedelta:
        return config.success_after_failure_window

    def evaluate(
        self,
        events: Sequence[AuthEvent],
        config: DetectionConfig,
    ) -> tuple[Finding, ...]:
        """Return one finding per qualifying success, or an empty tuple."""
        threshold = self.threshold(config)
        window = self.window(config)
        findings: list[Finding] = []
        for username, group in _account_groups(events):
            for success, failures in _qualifying_successes(group, threshold, window):
                findings.append(_finding(username, success, failures, threshold, window))
        return tuple(findings)


def register_suspicious_login(registry: RuleRegistry) -> None:
    """Register the suspicious-success rule on ``registry``.

    Importing this module does not register the rule.
    """
    registry.register(SuspiciousLoginRule())


def _account_groups(
    events: Sequence[AuthEvent],
) -> tuple[tuple[str, tuple[AuthEvent, ...]], ...]:
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.username is None:
            continue
        if event.event_type not in (EventType.LOGIN_FAILURE, EventType.LOGIN_SUCCESS):
            continue
        grouped[event.username].append(event)
    return tuple(
        (username, _unique_by_event_id(grouped[username]))
        for username in sorted(grouped)
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


def _qualifying_successes(
    events: Sequence[AuthEvent],
    threshold: int,
    window: timedelta,
) -> tuple[tuple[AuthEvent, tuple[AuthEvent, ...]], ...]:
    """Pair each success with the failures inside its lookback window.

    ``events`` are unique and ordered by time. Failures are not consumed:
    a later success may use the same failures when they still fall inside
    its own window.
    """
    pairs: list[tuple[AuthEvent, tuple[AuthEvent, ...]]] = []
    for event in events:
        if event.event_type is not EventType.LOGIN_SUCCESS:
            continue
        failures = _failures_in_window(events, event, window)
        if len(failures) >= threshold:
            pairs.append((event, failures))
    return tuple(pairs)


def _failures_in_window(
    events: Sequence[AuthEvent],
    success: AuthEvent,
    window: timedelta,
) -> tuple[AuthEvent, ...]:
    start = success.timestamp - window
    return tuple(
        event
        for event in events
        if event.event_type is EventType.LOGIN_FAILURE
        and start <= event.timestamp <= success.timestamp
    )


def _finding(
    username: str,
    success: AuthEvent,
    failures: Sequence[AuthEvent],
    threshold: int,
    window: timedelta,
) -> Finding:
    observed = len(failures)
    related = _related_ids(failures, success)
    first = failures[0].timestamp
    failure_ips = _source_ips(failures)
    description = _describe(
        observed=observed,
        threshold=threshold,
        window=window,
        first=first,
        success_time=success.timestamp,
        username=username,
        success_ip=success.source_ip,
        failure_ips=failure_ips,
        capped=len(failures) + 1 > _MAX_RELATED,
    )
    return Finding(
        finding_id=_finding_id(username, related),
        rule_id=RULE_ID,
        title="Successful login after repeated failures",
        severity=Severity.HIGH,
        description=description,
        recommendation=_RECOMMENDATION,
        observed_count=observed,
        threshold=threshold,
        window=window,
        related_event_ids=related,
        first_event_time=first,
        last_event_time=success.timestamp,
        affected_username=username,
        source_ip=success.source_ip,
    )


def _related_ids(failures: Sequence[AuthEvent], success: AuthEvent) -> tuple[str, ...]:
    failure_ids = tuple(event.event_id for event in failures)
    if len(failure_ids) + 1 <= _MAX_RELATED:
        return (*failure_ids, success.event_id)
    kept = _MAX_RELATED - 1
    return (*failure_ids[:kept], success.event_id)


def _source_ips(events: Sequence[AuthEvent]) -> tuple[str, ...]:
    seen: set[str] = set()
    ips: list[str] = []
    for event in events:
        source_ip = event.source_ip
        if source_ip is None or source_ip in seen:
            continue
        seen.add(source_ip)
        ips.append(source_ip)
    return tuple(ips)


def _describe(
    *,
    observed: int,
    threshold: int,
    window: timedelta,
    first: datetime,
    success_time: datetime,
    username: str,
    success_ip: str | None,
    failure_ips: Sequence[str],
    capped: bool,
) -> str:
    window_text = _format_window(window)
    text = (
        "A successful login followed a burst of failures for the same username. "
        f"Observed {observed} LOGIN_FAILURE events between {format_timestamp(first)} "
        f"and {format_timestamp(success_time)}. Threshold is {threshold} failures "
        f"inside {window_text}. This is an investigative signal, not proof of compromise."
    )
    detailed = _with_evidence(text, username, success_ip, failure_ips)
    if capped:
        note = (
            f" The first {_MAX_RELATED - 1} failure event ids and the success "
            "event id are attached."
        )
        if len(detailed) + len(note) <= 500:
            return f"{detailed}{note}"
    return detailed


def _with_evidence(
    text: str,
    username: str,
    success_ip: str | None,
    failure_ips: Sequence[str],
) -> str:
    clauses = (
        _evidence_clause(username, success_ip, failure_ips, truncated=False),
        _evidence_clause(username, success_ip, failure_ips, truncated=True),
        _evidence_clause(username, success_ip, (), truncated=False),
        _evidence_clause(username, None, (), truncated=False),
    )
    seen: set[str] = set()
    for clause in clauses:
        if clause in seen:
            continue
        seen.add(clause)
        candidate = f"{text}{clause}"
        if len(candidate) <= 500:
            return candidate
    return text


def _evidence_clause(
    username: str,
    success_ip: str | None,
    failure_ips: Sequence[str],
    *,
    truncated: bool,
) -> str:
    parts = [f" Account {username!r}."]
    if success_ip is not None:
        parts.append(f" Success source {success_ip}.")
    if failure_ips and truncated and len(failure_ips) > _MAX_LISTED_IPS:
        listed = ", ".join(failure_ips[:_MAX_LISTED_IPS])
        parts.append(
            f" Failure sources {listed}. "
            f"{len(failure_ips)} failure addresses were seen; the first "
            f"{_MAX_LISTED_IPS} are listed."
        )
    elif failure_ips and not truncated:
        parts.append(f" Failure sources {', '.join(failure_ips)}.")
    return "".join(parts)


def _finding_id(username: str, event_ids: tuple[str, ...]) -> str:
    payload = "\n".join((username, *event_ids)).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:20]
    return f"success-after-{digest}"


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
