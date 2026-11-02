"""Clock used when an analysis run records its start and finish.

Report text is built from those stored instants. Rendering does not read the
clock again, so a later export shows the same times.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current instant as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)
