# core/private_file.py
# Replaces a file whole and owner-only. The temp file is new and unique in the
# same folder, so a link or file left at a fixed name is never written through.

import os
import tempfile
from pathlib import Path


def replace_private(path, text: str, mode: int = 0o600) -> None:
    """Writes text next to path, then renames it over path. Raises OSError."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                               dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            try:
                os.fchmod(stream.fileno(), mode)
            except OSError:
                pass
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
