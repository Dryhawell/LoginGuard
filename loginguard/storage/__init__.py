"""Local JSON storage for events and alerts.

Default paths, relative to the working directory:

- ``data/events/events.jsonl`` for normalized events
- ``data/reports/alerts.json`` for the current alert document

``data/reports/analysis_summary.json`` belongs to reporting, which is a later
phase. File storage has no lock, no concurrent writers, and no history beyond
the event stream and the latest alert document.
"""

from pathlib import Path

from loginguard.storage.alert_store import SCHEMA, AlertStore
from loginguard.storage.errors import StorageError
from loginguard.storage.event_store import EventStore

DEFAULT_EVENT_PATH = Path("data/events/events.jsonl")
DEFAULT_ALERT_PATH = Path("data/reports/alerts.json")

__all__ = [
    "DEFAULT_ALERT_PATH",
    "DEFAULT_EVENT_PATH",
    "SCHEMA",
    "AlertStore",
    "EventStore",
    "StorageError",
]
