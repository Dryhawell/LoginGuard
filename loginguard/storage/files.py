"""Shared file handling for the local stores.

Event records are appended. Alert documents are replaced as a whole.
Replacement writes a temporary file in the same directory and then
``os.replace`` swaps it into place, so a failed write leaves the previous
document untouched. The stores do not delete sibling files.
"""

from __future__ import annotations

import os
import uuid
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
    ensure_parent(path)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except PermissionError:
        raise StorageError(f"{path.name}: permission denied") from None
    except OSError:
        raise StorageError(f"{path.name}: unable to write the file") from None
    finally:
        if temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass
