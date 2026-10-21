"""Shape checks for one decoded log record.

Field rules such as timestamps, event types, and IP addresses live on
``AuthEvent``. This module only decides whether a decoded JSON value is an
object that those rules can accept. A list, a string, or JSON null is an
invalid record, not a record with missing optional fields.
"""

from __future__ import annotations


class RecordShapeError(ValueError):
    """Raised when a decoded value is not a JSON object."""


def require_json_object(value: object) -> dict[str, object]:
    """Return ``value`` when it is a JSON object.

    Raises:
        RecordShapeError: ``value`` is not a ``dict``. The message does not
        include the value, so a rejected line cannot echo a secret.
    """
    if isinstance(value, dict):
        return value
    raise RecordShapeError("expected a JSON object")
