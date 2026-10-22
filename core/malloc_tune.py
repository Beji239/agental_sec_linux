# core/malloc_tune.py
# glibc gives busy threads their own malloc arenas, and memory freed in them
# is rarely handed back. With about 40 threads that held 70 MB. Two arenas,
# and a trim on each heartbeat, keep it small. Does nothing off glibc.

import ctypes
import logging
import os
import platform

logger = logging.getLogger(__name__)

M_ARENA_MAX = -8
ARENAS = 2
_libc = None


def _glibc():
    """The C library, or None when this is not glibc."""
    global _libc
    if _libc is None:
        _libc = False
        try:
            if platform.libc_ver()[0] == "glibc":
                _libc = ctypes.CDLL("libc.so.6")
        except OSError as e:
            logger.debug(f"malloc tuning off: {e}")
    return _libc or None


def limit_arenas(arenas: int = ARENAS) -> bool:
    """Cap the arenas. Call before any thread starts; MALLOC_ARENA_MAX in the
    environment wins."""
    if os.environ.get("MALLOC_ARENA_MAX"):
        return False
    libc = _glibc()
    if libc is None:
        return False
    try:
        return bool(libc.mallopt(M_ARENA_MAX, int(arenas)))
    except (AttributeError, OSError):
        return False


def trim() -> bool:
    """Hand freed memory back to the system. True when some was."""
    libc = _glibc()
    if libc is None:
        return False
    try:
        return bool(libc.malloc_trim(0))
    except (AttributeError, OSError):
        return False
