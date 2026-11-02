"""Errors for local JSON storage.

Messages name the file and the problem. They do not include file bytes,
raw log lines, passwords, tokens, or cookies.
"""


class StorageError(Exception):
    """A local store could not read or write its file.

    A single bad event line is not this error. The event store reports that
    line and keeps the valid events around it. A broken alert document is
    this error, because the alert file is one JSON document.
    """
