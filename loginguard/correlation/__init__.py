"""Group related authentication events and suppress duplicate alerts."""

from loginguard.correlation.correlator import EventGroup, correlate_events
from loginguard.correlation.dedup import dedupe_alerts, dedupe_findings
from loginguard.correlation.windows import gap_exceeds, unique_ordered_events

__all__ = [
    "EventGroup",
    "correlate_events",
    "dedupe_alerts",
    "dedupe_findings",
    "gap_exceeds",
    "unique_ordered_events",
]
