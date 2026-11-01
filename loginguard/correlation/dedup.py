"""Suppress repeated alerts for one ongoing detection.

The key is the rule id, the affected username when the finding has one, and
the source address when the finding has one. A later finding with that same
key is dropped when it starts before the kept finding has been quiet for the
window. A finding that starts after that quiet gap is a new incident and is
kept.

The tradeoff is deliberate. A second burst that overlaps the quiet gap, or
that starts inside it, does not raise another alert. A genuinely later
incident still does. Username and source address are compared as stored.
``None`` does not match a present value, so a finding with no address is not
folded into a finding that has one.

Findings that share a key but have no event time cannot be separated, so the
first one is kept and the rest are dropped.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from loginguard.detection.finding import Finding
from loginguard.models.alert import Alert, alerts_from_findings

_EARLIEST = datetime.min.replace(tzinfo=timezone.utc)


def dedupe_findings(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """Return findings with overlapping same-key incidents removed.

    Order is by first event time, then by ``finding_id``. The caller's
    sequence is not modified.

    Raises:
        TypeError: ``findings`` is not a sequence of ``Finding`` values.
    """
    if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence):
        raise TypeError("findings must be a sequence of Finding values")
    ordered = sorted(findings, key=_sort_key)
    for finding in ordered:
        if not isinstance(finding, Finding):
            raise TypeError("findings must be a sequence of Finding values")

    kept: list[Finding] = []
    for finding in ordered:
        if any(_same_incident(existing, finding) for existing in kept):
            continue
        kept.append(finding)
    return tuple(kept)


def dedupe_alerts(findings: Sequence[Finding]) -> tuple[Alert, ...]:
    """Build one alert for each finding that survives deduplication.

    This does not run detection. Ten findings for one ongoing window become
    one alert. A later incident remains an alert of its own.
    """
    return alerts_from_findings(dedupe_findings(findings))


def _same_incident(kept: Finding, candidate: Finding) -> bool:
    if _identity(kept) != _identity(candidate):
        return False
    if kept.first_event_time is None or candidate.first_event_time is None:
        return True
    kept_end = kept.last_event_time or kept.first_event_time
    quiet = kept.window if kept.window >= candidate.window else candidate.window
    return candidate.first_event_time <= kept_end + quiet


def _identity(finding: Finding) -> tuple[str, str | None, str | None]:
    return (finding.rule_id, finding.affected_username, finding.source_ip)


def _sort_key(finding: Finding) -> tuple[datetime, str]:
    return (finding.first_event_time or _EARLIEST, finding.finding_id)
