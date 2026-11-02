"""Shared file handling for the local stores.

Event records are appended. Alert documents are replaced as a whole.
Replacement writes a temporary file in the same directory and then
``os.replace`` swaps it into place, so a failed write leaves the previous
document untouched. ``replace_many`` prepares every temporary copy before
the first destination changes. The stores do not delete sibling files.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Sequence
from pathlib import Path

from loginguard.storage.errors import StorageError


def ensure_parent(path: Path) -> None:
    """Create the parent directory when it is missing.

    Raises:
        StorageError: ``path`` is a directory, or the directory cannot be created.
    """
    if path.is_dir():
        raise StorageError(f"{path.name}: expected a file")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        raise StorageError(f"{path.name}: permission denied") from None
    except OSError:
        raise StorageError(f"{path.name}: unable to create the directory") from None


def require_utf8(path: Path) -> None:
    """Reject a file that is not valid UTF-8 before more text is added.

    Raises:
        StorageError: the file cannot be read as UTF-8.
    """
    try:
        with path.open("r", encoding="utf-8") as handle:
            while handle.read(65536):
                pass
    except UnicodeDecodeError:
        raise StorageError(f"{path.name}: file is not valid UTF-8") from None
    except PermissionError:
        raise StorageError(f"{path.name}: permission denied") from None
    except OSError:
        raise StorageError(f"{path.name}: unable to read the file") from None


def append_text(path: Path, text: str) -> None:
    """Append UTF-8 text without truncating the existing file.

    Raises:
        StorageError: the file cannot be opened or written.
    """
    ensure_parent(path)
    if path.is_file():
        require_utf8(path)
    try:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except PermissionError:
        raise StorageError(f"{path.name}: permission denied") from None
    except OSError:
        raise StorageError(f"{path.name}: unable to write the file") from None


def replace_text(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` via a same-directory temporary file.

    A crash or a failed replace leaves the previous file in place. The
    temporary file is removed when the replace does not complete.

    Raises:
        StorageError: the directory or the file cannot be written.
    """
    temporary: Path | None = None
    try:
        temporary = _write_temp(path, text)
        os.replace(temporary, path)
    except StorageError:
        raise
    except PermissionError:
        raise StorageError(f"{path.name}: permission denied") from None
    except OSError:
        raise StorageError(f"{path.name}: unable to write the file") from None
    finally:
        _discard(temporary)


def replace_many(items: Sequence[tuple[Path, str]]) -> None:
    """Replace several files only after every temporary copy is ready.

    Preparing the copies happens first. If that step fails, every destination
    still has its previous contents and the copies are removed. The final
    rename then moves each copy into place. A failure in that narrow rename
    can leave the earlier destinations already updated. Files that were not
    part of ``items`` are left alone.

    Raises:
        TypeError: ``items`` is not pairs of a path and text.
        StorageError: two destinations are the same file, or a file cannot be written.
    """
    pairs = _require_pairs(items)
    if not pairs:
        return
    seen: set[Path] = set()
    for path, _text in pairs:
        key = path.absolute()
        if key in seen:
            raise StorageError("snapshot paths must be distinct files")
        seen.add(key)

    staged: list[Path] = []
    index = 0
    try:
        for index, (path, text) in enumerate(pairs):
            staged.append(_write_temp(path, text))
        for index, ((path, _text), temporary) in enumerate(zip(pairs, staged, strict=True)):
            os.replace(temporary, path)
    except StorageError:
        raise
    except PermissionError:
        raise StorageError(f"{pairs[index][0].name}: permission denied") from None
    except OSError:
        raise StorageError(f"{pairs[index][0].name}: unable to write the file") from None
    finally:
        for temporary in staged:
            _discard(temporary)


def _write_temp(path: Path, text: str) -> Path:
    ensure_parent(path)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        _discard(temporary)
        raise
    return temporary


def _discard(temporary: Path | None) -> None:
    if temporary is None or not temporary.exists():
        return
    try:
        temporary.unlink()
    except OSError:
        return


def _require_pairs(items: Sequence[tuple[Path, str]]) -> tuple[tuple[Path, str], ...]:
    if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
        raise TypeError("items must be a sequence of path and text pairs")
    pairs: list[tuple[Path, str]] = []
    for item in items:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("items must be a sequence of path and text pairs")
        path, text = item
        if not isinstance(path, Path) or not isinstance(text, str):
            raise TypeError("items must be a sequence of path and text pairs")
        pairs.append((path, text))
    return tuple(pairs)
