"""
The app's own installed files, recognised by facts an attacker cannot write.

A file counts as the app's own only when it is root-owned, not writable by
group or others, and identical to what the project's installer writes. Names,
command lines and folders are never enough on their own.
"""
import grp
import hashlib
import logging
import os
import pwd
import re
import stat
from pathlib import Path

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UNIT_DIR = "/etc/systemd/system"
WANTS_DIR = f"{UNIT_DIR}/multi-user.target.wants"
SUDOERS_D = "/etc/sudoers.d"
CHECK_PREFIX = ".agentalsec-check."

# Where python3 can be when an installer asks `command -v python3` as root.
PYTHONS = ("/usr/bin/python3", "/usr/local/bin/python3", "/bin/python3")

# Installer, the heredoc it writes to a file, and where that file goes.
WRITTEN = (
    ("install_capture_service.sh", "NAMES_UNIT_CONTENT", "$UNIT_DIR/$NAMES_UNIT"),
    ("install_capture_service.sh", "CAPTURE_UNIT_CONTENT",
     "$UNIT_DIR/$CAPTURE_UNIT"),
    ("install_capture_service.sh", "RULE_CONTENT", "$RULE_FILE"),
    ("install_action_helper.sh", "UNIT_CONTENT", "$BOOT_UNIT_FILE"),
    ("install_ebpf_camera.sh", "UNIT_CONTENT", "$UNIT_PATH"),
    ("install_ebpf_camera.sh", "RULE_CONTENT", "$RULE_FILE"),
    ("install_read_helper.sh", "DROP_IN_CONTENT", "$SUDOERS_FILE"),
)
COPIERS = ("install_capture_service.sh", "install_action_helper.sh",
           "install_ebpf_camera.sh", "install_read_helper.sh")
_HARDENING = re.compile(r"/etc/systemd/system/(agentalsec-[\w.-]+)\.service\.d/"
                        r"hardening\.conf")


def hash16(data: bytes) -> str:
    """The same 16-character sha256 prefix the integrity sensor stores."""
    return hashlib.sha256(data).hexdigest()[:16]


def _owner(root: Path) -> tuple:
    user = pwd.getpwuid(root.stat().st_uid)
    try:
        group = grp.getgrgid(user.pw_gid).gr_name
    except KeyError:
        group = user.pw_name
    return user.pw_name, group


def _expand(value: str, known: dict):
    """$NAME and ${NAME} filled in from known values, or None if one is not."""
    missing = []

    def sub(m):
        name = m.group(1) or m.group(2)
        if name not in known:
            missing.append(name)
            return ""
        return known[name]
    out = re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", sub, value)
    return None if missing else out


def _variables(script: str, root: Path) -> dict:
    user, group = _owner(root)
    known = {"PROJECT_ROOT": str(root), "REAL_USER": user, "REAL_GROUP": group}
    for m in re.finditer(r'^([A-Z][A-Z0-9_]*)="([^"]*)"\s*$', script, re.M):
        name, value = m.groups()
        if name in known or "$(" in value or "`" in value:
            continue
        expanded = _expand(value, known)
        if expanded is not None:
            known[name] = expanded
    return known


_TOKEN = re.compile(r"\\([\\$`])|\$\(([^()\n]*)\)|\$\{([A-Za-z_]\w*)\}"
                    r"|\$([A-Za-z_]\w*)|\$(\d)")


class Rendered:
    """What an installer writes: a regex, and the exact text when nothing in
    it varies from one install to the next."""

    def __init__(self, regex, exact):
        self.regex, self.exact = regex, exact


def _pattern(body: str, known: dict):
    """The heredoc as a regex. A value only the install moment knows, such as
    a date, may only vary inside a comment line; anywhere else it refuses."""
    out, varies = [], False
    for line in body.split("\n"):
        comment = line.lstrip().startswith("#")
        pos, parts = 0, []
        for m in _TOKEN.finditer(line):
            parts.append(re.escape(line[pos:m.start()]))
            pos = m.end()
            if m.group(1):
                parts.append(re.escape(m.group(1)))
                continue
            name = m.group(3) or m.group(4)
            if name == "PYTHON":
                parts.append("(?:" + "|".join(map(re.escape, PYTHONS)) + ")")
                varies = True
            elif name in known:
                parts.append(re.escape(known[name]))
            elif comment:
                parts.append(r"[^\n]*")
                varies = True
            else:
                return None
        parts.append(re.escape(line[pos:]))
        out.append("".join(parts))
    text = "\n".join(out) + "\n"
    exact = None if varies else re.sub(r"\\(.)", r"\1", text, flags=re.S)
    return Rendered(re.compile(text), exact)


def _heredoc(script: str, var: str):
    m = re.search(rf'^{var}="\$\(cat <<EOF\n(.*?)\nEOF\n\)"', script,
                  re.M | re.S)
    return m.group(1).rstrip("\n") if m else None


_cache = {}
# Which installer writes each path, filled with the table.
INSTALLER = {}


def expected(root: Path = None) -> dict:
    """{installed path: ("file", Rendered) or ("copy", source path)} for every
    file the installers write. Rebuilt whenever an installer changes."""
    root = Path(root or PROJECT_ROOT)
    stamp = []
    for name in sorted(set(COPIERS) | {w[0] for w in WRITTEN}):
        try:
            stamp.append((root / "scripts" / name).stat().st_mtime_ns)
        except OSError:
            stamp.append(None)
    key = (str(root), tuple(stamp))
    if key not in _cache:
        _cache.clear()
        _cache[key] = _build(root)
    return _cache[key]


def _build(root: Path) -> dict:
    out = {}
    scripts = {}
    for name in set(COPIERS) | {w[0] for w in WRITTEN}:
        try:
            scripts[name] = (root / "scripts" / name).read_text()
        except OSError:
            continue
    for name, var, dest in WRITTEN:
        script = scripts.get(name)
        if script is None:
            continue
        try:
            known = _variables(script, root)
        except (OSError, KeyError):
            continue
        body, path = _heredoc(script, var), _expand(dest, known)
        rx = _pattern(body, known) if body is not None else None
        if path and rx:
            out[path] = ("file", rx)
            INSTALLER[path] = name
    for name in COPIERS:
        script = scripts.get(name)
        if script is None:
            continue
        try:
            known = _variables(script, root)
        except (OSError, KeyError):
            continue
        for var, src in known.items():
            dst = known.get(var[:-4] + "_DST") if var.endswith("_SRC") else None
            if dst:
                out[dst] = ("copy", src)
                INSTALLER[dst] = name
        for var in ("HELPER_DIR", "INSTALL_DIR"):
            if known.get(var, "").startswith("/usr/local/lib/agentalsec"):
                out[known[var]] = ("dir", None)
    for conf in sorted((root / "scripts" / "systemd-hardening").glob("*.conf")):
        out[f"{UNIT_DIR}/{conf.stem}.service.d/hardening.conf"] = ("copy",
                                                                    str(conf))
    return out


def _root_owned(st) -> bool:
    return st.st_uid == 0 and not (stat.S_IMODE(st.st_mode) & 0o022)


def _matches(how, data: bytes) -> bool:
    kind, want = how
    if kind == "file":
        return bool(want.regex.fullmatch(data.decode("utf-8", "replace")))
    try:
        return Path(want).read_bytes() == data
    except OSError:
        return False


def _digest_matches(how, digest: str) -> bool:
    """A hash against what the installer writes, when that is fixed text."""
    kind, want = how
    if kind == "copy":
        try:
            return hash16(Path(want).read_bytes()) == digest
        except OSError:
            return False
    return bool(want.exact) and hash16(want.exact.encode()) == digest


def _what(how, root: Path) -> str:
    if how[0] == "copy":
        return f"identical to {Path(how[1]).relative_to(root)}"
    return "exactly what the installer writes"


def by_digest(path: str, digest: str, root: Path = None):
    """Why a file the integrity sensor read (mode and owner already checked
    by the caller) is the app's own, from its hash alone, or None. Used where
    the sensor read the file through the root helper and this process
    cannot."""
    root = root or PROJECT_ROOT
    try:
        how = expected(root).get(str(path))
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"own_install: installers unreadable: {e}")
        return None
    if how is None or how[0] == "dir" or not digest:
        return None
    if _digest_matches(how, digest):
        return _what(how, root)
    if how[0] == "file":
        # Text that varies per install is read and matched instead.
        try:
            data = Path(path).read_bytes()
        except OSError:
            return None
        if hash16(data) == digest and _matches(how, data):
            return _what(how, root)
    return None


def reason(path: str, digest: str = None, root: Path = None):
    """Why this path, as it is on disk now, is the app's own install, or None.

    digest is the 16-character hash the integrity sensor read through its
    root helper, for files this process cannot read itself; when given, the
    file must match it as well."""
    root = root or PROJECT_ROOT
    path = str(path).rstrip("/") or "/"
    try:
        st = os.lstat(path)
    except OSError:
        return None
    try:
        table = expected(root)
    except Exception as e:                              # noqa: BLE001
        logger.debug(f"own_install: installers unreadable: {e}")
        return None

    if stat.S_ISLNK(st.st_mode):
        if st.st_uid != 0 or os.path.dirname(path) != WANTS_DIR:
            return None
        target = os.readlink(path)
        unit = f"{UNIT_DIR}/{os.path.basename(path)}"
        if target != unit or reason(unit, root=root) is None:
            return None
        return f"the boot link systemctl enable makes for {unit}, itself verified"

    how = table.get(path)
    if how is None or not _root_owned(st):
        return None
    if how[0] == "dir":
        return (f"the folder the app's installers put their helpers in, "
                f"root-owned and closed to other accounts"
                if stat.S_ISDIR(st.st_mode) else None)
    if not stat.S_ISREG(st.st_mode):
        return None
    what = _what(how, root)
    try:
        data = Path(path).read_bytes()
    except PermissionError:
        if digest and _digest_matches(how, digest):
            return f"{what}, checked by hash through the root helper"
        return None
    except OSError:
        return None
    if digest and hash16(data) != digest:
        return None
    return what if _matches(how, data) else None


def stale(root: Path = None) -> dict:
    """{installer: [paths]} for installed files that no longer match what
    the project's installer writes. A file this process cannot read is left
    out, not guessed at."""
    root = Path(root or PROJECT_ROOT)
    table = expected(root)
    out = {}
    for path in sorted(table):
        name = INSTALLER.get(path)
        if not name or not os.path.lexists(path):
            continue
        if not os.access(path, os.R_OK):
            continue
        if reason(path, root=root) is None:
            out.setdefault(name, []).append(path)
    return out


def inert_check_file(path: str):
    """The read helper installer's temporary file in /etc/sudoers.d. sudo
    never reads a file there whose name has a dot, so it grants nothing; the
    file it becomes is judged under its own name."""
    p = str(path)
    if (os.path.dirname(p) == SUDOERS_D
            and os.path.basename(p).startswith(CHECK_PREFIX)
            and "." in os.path.basename(p)):
        return ("the read helper installer's check file; sudo ignores any "
                "file in /etc/sudoers.d with a dot in its name, so it "
                "grants nothing")
    return None


# Open alerts raised about the installers' work before the sensors knew it.
RULES = ("AUD-1002", "LNX-2001", "LNX-4004")
OWN_MARK = "the app's own install:"


def _explain(did: str, value: str, raw: dict, children: dict):
    if did == "AUD-1002":
        from tools import auditd_monitor
        record = {"msg_id": (raw.get("msg_id"), raw.get("at")),
                  "fields": raw.get("fields") or {}}
        return auditd_monitor._own_explains(value, record, children)
    if did == "LNX-2001":
        from tools import local_integrity
        return local_integrity.own_file_check(value, raw.get("after"))
    if did == "LNX-4004" and os.path.dirname(value) == UNIT_DIR:
        from tools import autorun_monitor
        command = str(raw.get("command") or "")
        try:
            text = Path(value).read_text()
        except OSError:
            return None
        # The unit must still start what the alert saw it start.
        if not command or command not in text:
            return None
        return autorun_monitor._own_entry(
            {"kind": "systemd_service", "path": value, "detail": command})
    return None


def close_open_alerts() -> int:
    """Close open alerts the checks above now explain. Each keeps its reason,
    so the owner can still read what was closed and why."""
    import json
    from core import memory_engine as me
    marks = ",".join("?" * len(RULES))
    with me._get_conn() as conn:
        rows = conn.execute(
            f"SELECT id, detection_id, entity_value, raw_data, dismissed "
            f"FROM findings WHERE detection_id IN ({marks})", RULES).fetchall()
    children, todo = {}, []
    for r in rows:
        try:
            raw = json.loads(r["raw_data"] or "{}")
        except ValueError:
            continue
        f = raw.get("fields") or {}
        if r["detection_id"] == "AUD-1002" and f.get("nametype") not in (
                None, "PARENT") and str(f.get("name", "")).startswith("/"):
            children.setdefault((raw.get("msg_id"), raw.get("at")),
                                []).append(f["name"])
        if not r["dismissed"]:
            todo.append((r, raw))
    closed = []
    for r, raw in todo:
        try:
            why = _explain(r["detection_id"], r["entity_value"], raw, children)
        except Exception as e:                          # noqa: BLE001
            logger.debug(f"own_install: could not check {r['id']}: {e}")
            continue
        if why:
            closed.append((f"{OWN_MARK} {why}", r["id"]))
    if closed:
        with me._get_conn() as conn:
            conn.executemany(
                "UPDATE findings SET dismissed = 1, "
                "dismissed_at = CURRENT_TIMESTAMP, dismissed_reason = ? "
                "WHERE id = ? AND dismissed = 0", closed)
    return len(closed)
