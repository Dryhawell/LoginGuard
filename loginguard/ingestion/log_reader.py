"""Line-oriented reading for local log files.

The reader yields physical lines and their 1-based line numbers. It does not
parse or validate them. Callers decide which lines are records.

Files must be UTF-8. A leading byte-order mark is accepted and stripped.
Invalid UTF-8, a missing file, or a directory stops the read. The error names
the file and the problem. It does not include file bytes or line text.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


class IngestionError(OSError):
    """A file could not be read as UTF-8 text.

    Per-line data problems are not this error. Those stay with the parser so
    one bad record does not hide the valid records around it.
    """


def read_text_lines(path: Path) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, text)`` for every physical line in ``path``.

    Line endings are removed. Other whitespace is kept. A decode error while
    iterating discards the read: the caller must not treat a partial result
    as a finished file.

    Raises:
        IngestionError: ``path`` is missing, not a file, or not valid UTF-8.
    """
    if path.is_dir():
        raise IngestionError(f"{path.name}: expected a file")
    if not path.is_file():
        raise IngestionError(f"{path.name}: file not found")

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for number, line in enumerate(handle, start=1):
                yield number, line.rstrip("\r\n")
    except UnicodeDecodeError:
        raise IngestionError(f"{path.name}: file is not valid UTF-8") from None
    except PermissionError:
        raise IngestionError(f"{path.name}: permission denied") from None
    except OSError:
        raise IngestionError(f"{path.name}: unable to read the file") from None
