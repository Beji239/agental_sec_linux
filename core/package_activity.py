# core/package_activity.py
# Was a file change made by the package manager? A path counts as explained
# when a package owns it (or it links to a file a package owns), that package
# was installed or upgraded close to the change, and the file still matches
# the checksum dpkg recorded for it.

import hashlib
import logging
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

DPKG_LOG = "/var/log/dpkg.log"
DPKG_INFO = "/var/lib/dpkg/info"
DPKG_STATUS = "/var/lib/dpkg/status"
BEFORE = timedelta(minutes=90)     # a monitor can notice late
AFTER = timedelta(minutes=5)
ACTIONS = ("install", "upgrade", "configure", "trigproc")
# Merged /usr: dpkg may list the old spelling of a path.
MERGED = (("/usr/lib/", "/lib/"), ("/usr/bin/", "/bin/"),
          ("/usr/sbin/", "/sbin/"), ("/usr/lib64/", "/lib64/"))
LOG_CACHE_SECONDS = 30
# Names dpkg gives a file while it unpacks or keeps a conffile. No package
# owns them, so they are judged by the file they stand beside.
DPKG_TEMP = (".dpkg-new", ".dpkg-tmp", ".dpkg-old", ".dpkg-dist",
             ".dpkg-bak")

_log_cache = {"at": 0.0, "mtime": None, "rows": []}
# One dpkg-query loads the whole package database, a few seconds on a busy
# disk, so owners are asked in batches and kept until dpkg changes.
OWNER_CACHE_MAX = 5000
OWNER_QUERY_TIMEOUT = 30
_owner_cache = {"key": None, "owners": {}, "conffiles": {}}


def _spellings(path: str) -> list:
    out = [path]
    for new, old in MERGED:
        if path.startswith(new):
            out.append(old + path[len(new):])
        elif path.startswith(old):
            out.append(new + path[len(old):])
    return out


def dpkg_temp_base(path: str) -> str | None:
    """The real path behind one of dpkg's temporary names, else None."""
    for suffix in DPKG_TEMP:
        if path.endswith(suffix) and len(path) > len(suffix) and \
                not path[:-len(suffix)].endswith("/"):
            return path[:-len(suffix)]
    return None


def _known_owners() -> dict:
    """Owners asked so far, emptied when dpkg's database changes."""
    try:
        key = (os.stat(DPKG_STATUS).st_mtime, os.stat(DPKG_INFO).st_mtime)
    except OSError:
        key = None
    if key != _owner_cache["key"] or \
            len(_owner_cache["owners"]) > OWNER_CACHE_MAX:
        _owner_cache.update(key=key, owners={}, conffiles={})
    return _owner_cache["owners"]


def _conffiles(package: str) -> dict:
    """{path: md5} of a package's conffiles, asked once per package."""
    _known_owners()
    known = _owner_cache["conffiles"]
    if package in known:
        return known[package]
    try:
        r = subprocess.run(["dpkg-query", "-W", "-f=${Conffiles}\n", package],
                           capture_output=True, text=True,
                           timeout=OWNER_QUERY_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return {}
    sums = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            sums[parts[0]] = parts[1]
    known[package] = sums
    return sums


def _query_owners(paths: list) -> dict:
    """{path: package or None} from one dpkg-query; {} when it fails."""
    found = dict.fromkeys(paths)
    try:
        r = subprocess.run(["dpkg-query", "-S", *paths], capture_output=True,
                           text=True, timeout=OWNER_QUERY_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return {}
    for line in r.stdout.splitlines():
        pkgs, _, listed = line.partition(": ")
        listed = listed.strip()
        if listed in found and found[listed] is None and "," not in pkgs \
                and not pkgs.startswith("diversion"):
            found[listed] = pkgs.split(":")[0].strip()
    return found


def _prefetch(paths: list) -> None:
    """Look up the owners of many paths in one dpkg-query."""
    known = _known_owners()
    missing = list(dict.fromkeys(
        s for p in paths for s in _spellings(p.rstrip("/") or "/")
        if s not in known))
    if missing:
        known.update(_query_owners(missing))


def owner(path: str) -> str | None:
    """The package that owns this path, or None."""
    spellings = _spellings(path.rstrip("/") or "/")
    _prefetch(spellings)
    known = _owner_cache["owners"]
    for p in spellings:
        if known.get(p):
            return known[p]
    return None


def _actions() -> list:
    """(when, action, package) from dpkg's log, cached briefly."""
    now = time.monotonic()
    try:
        mtime = os.stat(DPKG_LOG).st_mtime
    except OSError:
        return []
    if _log_cache["mtime"] == mtime and now - _log_cache["at"] < \
            LOG_CACHE_SECONDS:
        return _log_cache["rows"]
    rows = []
    try:
        with open(DPKG_LOG, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4 or parts[2] not in ACTIONS:
                    continue
                try:
                    # dpkg writes local time with no zone.
                    when = datetime.strptime(f"{parts[0]} {parts[1]}",
                                             "%Y-%m-%d %H:%M:%S").astimezone()
                except ValueError:
                    continue
                rows.append((when, parts[2], parts[3].split(":")[0]))
    except OSError as e:
        logger.debug(f"package_activity: cannot read {DPKG_LOG}: {e}")
    _log_cache.update(at=now, mtime=mtime, rows=rows)
    return rows


def recent_action(package: str, times: list) -> dict | None:
    """The dpkg action on this package closest to one of the times."""
    best = None
    for when, action, pkg in _actions():
        if pkg != package:
            continue
        for t in times:
            if t - BEFORE <= when <= t + AFTER:
                gap = abs((t - when).total_seconds())
                if best is None or gap < best[0]:
                    best = (gap, when, action)
    if best is None:
        return None
    return {"action": best[2], "at": best[1].astimezone(timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S+00:00")}


def _recorded_md5(package: str, path: str) -> str | None:
    rels = {p.lstrip("/") for p in _spellings(path)}
    try:
        with open(os.path.join(DPKG_INFO, f"{package}.md5sums"),
                  encoding="utf-8", errors="replace") as f:
            for line in f:
                digest, _, rel = line.strip().partition("  ")
                if rel in rels:
                    return digest
    except OSError:
        pass
    sums = _conffiles(package)
    for p in _spellings(path):
        if p in sums:
            return sums[p]
    return None


def _matches_record(package: str, path: str) -> bool | None:
    """True or False against dpkg's checksum; None when none is recorded or
    the file cannot be read."""
    want = _recorded_md5(package, path)
    if not want:
        return None
    try:
        with open(path, "rb") as f:
            # dpkg records md5 only; this checks the package record, it is
            # not a tamper seal.
            got = hashlib.md5(f.read(), usedforsecurity=False).hexdigest()
    except OSError:
        return None
    return got == want


def explains(path: str, at: datetime = None) -> dict | None:
    """
    {"package", "action", "at", "how"} when a package install or upgrade
    explains this path, else None. A directory is explained by an entry in it
    that is. Never raises.
    """
    try:
        return _explains(path, at)
    except Exception as e:                                  # noqa: BLE001
        logger.debug(f"package_activity: {path}: {e}")
        return None


def _newest_entries(path: str) -> list:
    """The 20 most recently changed entries of a folder."""
    return sorted(os.scandir(path), key=lambda e: -e.stat(
        follow_symlinks=False).st_ctime)[:20]


def _owner_candidates(path: str, depth: int) -> list:
    """Every path _explains asks dpkg about under this folder, so one query
    answers the whole walk."""
    out = []
    try:
        entries = _newest_entries(path)
    except OSError:
        return out
    for e in entries:
        try:
            is_dir = e.is_dir(follow_symlinks=False)
            is_link = e.is_symlink()
        except OSError:
            continue
        if is_dir:
            if depth < 1:
                out += _owner_candidates(e.path, depth + 1)
            continue
        out.append(e.path)
        base = dpkg_temp_base(e.path)
        if base:
            out.append(base)
        if is_link and depth < 1:
            out.append(os.path.realpath(e.path))
    return out


def _explains(path: str, at: datetime = None, depth: int = 0) -> dict | None:
    if not path or depth > 2:
        return None
    path = path.rstrip("/") or "/"
    times = [(at or datetime.now(timezone.utc)).astimezone()]
    try:
        st = os.lstat(path)
        times.append(datetime.fromtimestamp(st.st_ctime).astimezone())
    except OSError:
        st = None
    if st is not None and os.path.isdir(path) and not os.path.islink(path):
        try:
            entries = _newest_entries(path)
        except OSError:
            return None
        if depth == 0:
            _prefetch(_owner_candidates(path, 0))
        for e in entries:
            hit = _explains(e.path, at, depth + 1)
            if hit:
                return dict(hit, how=f"holds {e.name}, " + hit["how"])
        return None
    if st is not None and os.path.islink(path):
        target = os.path.realpath(path)
        hit = _explains(target, at, depth + 1) if target != path else None
        if hit:
            return dict(hit, how=f"a link to {target}, " + hit["how"])
    base = dpkg_temp_base(path)
    if base:
        # Its content is the new version, which dpkg has not recorded yet,
        # so only the owner of the real file and its timing are checked.
        pkg = owner(base)
        act = recent_action(pkg, times) if pkg else None
        if not act:
            return None
        return {"package": pkg, "action": act["action"], "at": act["at"],
                "how": f"dpkg's temporary copy of {base}, owned by {pkg}, "
                       f"{act['action']} at {act['at']}"}
    pkg = owner(path)
    if not pkg:
        return None
    if _matches_record(pkg, path) is False:
        return None
    act = recent_action(pkg, times)
    if not act:
        return None
    return {"package": pkg, "action": act["action"], "at": act["at"],
            "how": f"owned by {pkg}, {act['action']} at {act['at']}"}
