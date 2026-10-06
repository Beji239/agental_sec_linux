# tools/av_scanner.py
# Malware scanning with ClamAV. Signatures, not a hash lookup: each file is
# read by the ClamAV engine against its own database, so a known family is
# found in a file nobody has uploaded anywhere. What it scans each pass:
#
#   the file of every running program, once per (path, size, mtime)
#   new or changed files in /tmp, /var/tmp, /dev/shm and each home's Downloads
#   any path asked for through scan_paths()
#
# It uses clamd when the daemon answers, and clamscan otherwise. Not
# installed is a state with the install command, never an empty "clean".
# A hit is AV-1001. What it cannot do: find malware ClamAV has no signature
# for, or read a file this account is not allowed to read.

import glob
import logging
import os
import pwd
import shutil
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

ROLE = "av_scanner"
INSTALL_COMMAND = "sudo apt install clamav clamav-daemon"
WATCH_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
HOME_WATCH = ("Downloads",)
DATABASE_DIR = "/var/lib/clamav"
CLAMD_SOCKETS = ("/var/run/clamav/clamd.ctl", "/run/clamav/clamd.ctl")
DEFAULTS = {"enabled": True, "max_file_mb": 100, "max_files_per_pass": 200,
            "scan_timeout_seconds": 600}
# A database older than this is said to be stale on the status.
STALE_DATABASE_DAYS = 7
# Files in a folder named by request_scan(folders=True), at most.
MAX_FOLDER_FILES = 200

# Scans asked for between passes, such as a file MalwareBazaar knows. The
# event wakes the scanner so they run now rather than at the next pass.
_pending = {}
_pending_lock = threading.Lock()
wake = threading.Event()


def request_scan(paths: list, folders: bool = False, reason: str = ""):
    """Queue files (and, with folders, the files beside them) for the next
    pass, and start that pass now."""
    with _pending_lock:
        for p in paths or []:
            if isinstance(p, str) and p.startswith("/"):
                _pending[p] = (folders, reason)
    wake.set()


def _expand(requested: dict, max_bytes: int) -> list:
    out = []
    for path, (folders, _) in requested.items():
        out.append(path)
        if folders:
            try:
                names = sorted(os.listdir(os.path.dirname(path)))[:MAX_FOLDER_FILES]
            except OSError:
                names = []
            for n in names:
                q = os.path.join(os.path.dirname(path), n)
                try:
                    if os.path.isfile(q) and not os.path.islink(q) \
                            and os.path.getsize(q) <= max_bytes:
                        out.append(q)
                except OSError:
                    pass
    return out


def bazaar(path: str) -> dict:
    """What MalwareBazaar says about this file's SHA-256. The hash comes from
    the process monitor's cache, so a file is hashed once."""
    try:
        from tools import process_monitor_linux as pm
        sha = pm.hash_file(path)
    except Exception as e:                              # noqa: BLE001
        return {"asked": False, "why": f"the file could not be hashed ({e})"}
    if not sha:
        return {"asked": False, "why": "the file could not be hashed"}
    try:
        from core import enrichment
        row = enrichment.read(sha, "hash")
        if row and not row.get("stale") and (row.get("fields") or {}).get("known_malware"):
            fields = row["fields"]
        else:
            # Asked directly, so "not asked" (no key, offline) and "no
            # record" are told apart.
            fields, _url, err = enrichment.src_malwarebazaar(sha)
            if err:
                return {"asked": False, "sha256": sha, "why": err}
            fields = fields or {}
    except Exception as e:                              # noqa: BLE001
        return {"asked": False, "sha256": sha, "why": str(e)}
    return {"asked": True, "sha256": sha,
            "known": bool(fields.get("known_malware")),
            "family": fields.get("malware_family"), "tags": fields.get("tags"),
            "first_seen": fields.get("first_seen")}


def settings(config: dict) -> dict:
    block = dict(DEFAULTS)
    block.update(((config or {}).get("sensors") or {}).get(ROLE) or {})
    return block


def engine() -> dict:
    """Which ClamAV is here and how fresh its signatures are."""
    clamdscan = shutil.which("clamdscan")
    clamscan = shutil.which("clamscan")
    daemon = bool(clamdscan) and any(os.path.exists(s) for s in CLAMD_SOCKETS)
    newest = None
    for f in glob.glob(os.path.join(DATABASE_DIR, "*.c[lv]d")):
        try:
            newest = max(newest or 0, os.path.getmtime(f))
        except OSError:
            pass
    age_days = round((time.time() - newest) / 86400, 1) if newest else None
    if daemon:
        tool = "clamdscan"
    elif clamscan:
        tool = "clamscan"
    else:
        tool = None
    return {"installed": bool(clamscan or clamdscan), "tool": tool,
            "daemon": daemon, "database_age_days": age_days,
            "database_stale": age_days is None or age_days > STALE_DATABASE_DAYS}


def _command(eng: dict, paths: list) -> list:
    if eng["tool"] == "clamdscan":
        # --fdpass hands clamd the open file, so it reads what this account can.
        return ["clamdscan", "--fdpass", "--no-summary", "--infected", "--"] + paths
    return ["clamscan", "--no-summary", "--infected", "--stdout", "--"] + paths


def scan_paths(paths: list, timeout: int = 600, eng: dict = None) -> dict:
    """Scan files. {"ok", "infected": [{path, signature}], "error", "tool"}.
    ok False means the scan itself failed and nothing may be read as clean."""
    eng = eng or engine()
    if not eng["installed"]:
        return {"ok": False, "infected": [], "tool": None,
                "error": f"ClamAV is not installed. Install it with: {INSTALL_COMMAND}"}
    paths = [p for p in paths if isinstance(p, str) and p.startswith("/")]
    if not paths:
        return {"ok": True, "infected": [], "tool": eng["tool"], "scanned": 0}
    try:
        proc = subprocess.run(_command(eng, paths), capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "infected": [], "tool": eng["tool"],
                "error": f"the scan did not finish within {timeout}s"}
    except OSError as e:
        return {"ok": False, "infected": [], "tool": eng["tool"], "error": str(e)}
    infected = []
    for line in proc.stdout.splitlines():
        if line.endswith(" FOUND") and ": " in line:
            path, _, sig = line[:-len(" FOUND")].rpartition(": ")
            infected.append({"path": path, "signature": sig.strip()})
    # 0 clean, 1 found, 2 an error (often one unreadable file among many).
    if proc.returncode == 2 and not infected:
        return {"ok": False, "infected": [], "tool": eng["tool"],
                "error": (proc.stderr or proc.stdout).strip()[:300] or "scanner error",
                "scanned": len(paths)}
    return {"ok": True, "infected": infected, "tool": eng["tool"],
            "scanned": len(paths),
            "warnings": (proc.stderr or "").strip()[:300] if proc.returncode == 2 else ""}


def _homes() -> list:
    out = []
    for pw in pwd.getpwall():
        if 1000 <= pw.pw_uid < 60000 and os.path.isdir(pw.pw_dir):
            out.append(pw.pw_dir)
    return out


def running_programs() -> dict:
    """{exe path: [pid, ...]} for every process whose file can be named."""
    try:
        import psutil
    except ImportError:
        return {}
    out = {}
    for p in psutil.process_iter(["pid", "exe"]):
        exe = p.info.get("exe")
        if exe and os.path.isfile(exe):
            out.setdefault(exe, []).append(p.info["pid"])
    return out


def watched_files(max_bytes: int) -> list:
    dirs = list(WATCH_DIRS) + [os.path.join(h, d) for h in _homes() for d in HOME_WATCH]
    files = []
    for d in dirs:
        for root, subdirs, names in os.walk(d, onerror=lambda e: None):
            # Two levels deep is where a dropped payload sits; deeper is a build tree.
            if root.count(os.sep) - d.count(os.sep) >= 2:
                subdirs[:] = []
            for n in names:
                path = os.path.join(root, n)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if os.path.isfile(path) and not os.path.islink(path) \
                        and 0 < st.st_size <= max_bytes:
                    files.append((path, st.st_size, st.st_mtime))
    return files


class Scanner:
    """The pass state: what was already scanned, so a file is read once."""

    def __init__(self, config: dict = None):
        self.cfg = settings(config)
        self.seen = {}           # path -> (size, mtime) last scanned
        self.state = {"passes": 0, "scanned": 0, "infected": 0, "last": None,
                      "last_error": None, "skipped_over_cap": 0}

    def candidates(self) -> tuple:
        max_bytes = int(self.cfg["max_file_mb"]) * 1024 * 1024
        programs = running_programs()
        with _pending_lock:
            requested = dict(_pending)
            _pending.clear()
        items = []
        for p in _expand(requested, max_bytes):
            try:
                st = os.stat(p)
            except OSError:
                continue
            items.append((p, st.st_size, st.st_mtime))
        for exe in programs:
            try:
                st = os.stat(exe)
            except OSError:
                continue
            if st.st_size <= max_bytes:
                items.append((exe, st.st_size, st.st_mtime))
        items += watched_files(max_bytes)
        if len(self.seen) > 50000:
            self.seen.clear()
        unique = {p: (p, s, m) for p, s, m in items}
        fresh = [v for p, v in unique.items() if self.seen.get(p) != v[1:]]
        cap = int(self.cfg["max_files_per_pass"])
        self.state["skipped_over_cap"] = max(0, len(fresh) - cap)
        return fresh[:cap], programs

    def run_pass(self) -> list:
        """One pass. Returns the findings to raise."""
        eng = engine()
        self.state["engine"] = eng
        self.state["passes"] += 1
        self.state["last"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        if not eng["installed"]:
            self.state["last_error"] = f"not installed: {INSTALL_COMMAND}"
            return []
        batch, programs = self.candidates()
        if not batch:
            self.state["last_error"] = None
            return []
        res = scan_paths([p for p, _, _ in batch],
                         timeout=int(self.cfg["scan_timeout_seconds"]), eng=eng)
        if not res["ok"]:
            self.state["last_error"] = res["error"]
            return []
        self.state["last_error"] = res.get("warnings") or None
        for p, s, m in batch:
            self.seen[p] = (s, m)
        self.state["scanned"] += res["scanned"]
        findings = []
        for hit in res["infected"]:
            pids = programs.get(hit["path"], [])
            self.state["infected"] += 1
            mb = bazaar(hit["path"])
            if mb.get("known"):
                second = (" MalwareBazaar also lists this file"
                          + (f" as {mb['family']}" if mb.get("family") else "")
                          + (f", first seen {mb['first_seen']}" if mb.get("first_seen") else "")
                          + ", so two independent sources agree.")
            elif mb.get("asked"):
                second = (" MalwareBazaar has no record of its hash, which is "
                          "common: most samples are never uploaded there.")
            else:
                second = f" MalwareBazaar could not be asked: {mb.get('why')}."
            findings.append({
                "detection_id": "AV-1001", "severity": "high",
                "entity_type": "file", "entity_value": hit["path"],
                "title": f"Malware found by ClamAV: {hit['signature']} in {hit['path']}",
                "description": (
                    f"ClamAV matched the signature {hit['signature']} in "
                    f"{hit['path']}."
                    + (f" It is running now as pid {', '.join(map(str, pids))}."
                       if pids else "")
                    + second
                    + " A signature match names a known malware family or "
                      "test file. Quarantine the file, and end the process if "
                      "it is running, after checking what it is."),
                "raw_data": {"signature": hit["signature"], "path": hit["path"],
                             "pids": pids, "engine": eng["tool"],
                             "database_age_days": eng["database_age_days"],
                             "malwarebazaar": mb,
                             "corroboration": ("corroborated" if mb.get("known")
                                               else "single_source")}})
        return findings

    def status(self) -> dict:
        eng = self.state.get("engine") or engine()
        if not eng["installed"]:
            headline = f"ClamAV is not installed, so no file is scanned. {INSTALL_COMMAND}"
        elif eng["database_stale"]:
            headline = (f"Scanning with {eng['tool']}, but its signatures are "
                        f"{eng['database_age_days']} days old (sudo freshclam).")
        else:
            headline = (f"Scanning with {eng['tool']}; {self.state['scanned']} "
                        f"file(s) scanned, {self.state['infected']} infected."
                        + ("" if eng["daemon"] else
                           " Without clamav-daemon each pass reloads the "
                           "signatures, which is slow."))
        # Not installed is a state with its command, not blindness (as auditd).
        return dict(self.state, engine=eng, headline=headline, blind=False,
                    installed=eng["installed"])
