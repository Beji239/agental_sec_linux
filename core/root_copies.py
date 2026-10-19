# core/root_copies.py
# The root-owned copies of the app's helpers, compared with the project. A
# helper that runs as root runs from its own copy outside the project folder,
# so an edit in the project cannot change what root runs. After an update the
# two can differ; this says so, with the command that brings the copy level.
# The app never rewrites a root copy itself: that would need root.

import hashlib
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALLED = Path("/usr/local/lib/agentalsec")

COPIES = (
    ("names helper", "tools/names_helper.py", "names_helper.py",
     "scripts/install_capture_service.sh --apply"),
    ("read helper", "tools/read_helper.py", "read_helper.py",
     "scripts/install_read_helper.sh --apply"),
    ("action helper", "tools/action_helper.py", "action_helper.py",
     "scripts/install_action_helper.sh --apply"),
    ("kernel camera", "ebpf/ebpf_monitor.py", "ebpf/ebpf_monitor.py",
     "scripts/install_ebpf_camera.sh --apply"),
)


def _digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def check(root: Path = ROOT, installed: Path = INSTALLED) -> list:
    """One row per helper: installed, matching the project, and the fix."""
    out = []
    for name, src, dst, fix in COPIES:
        mine, theirs = _digest(root / src), _digest(installed / dst)
        out.append({"helper": name, "installed": theirs is not None,
                    "matches": theirs is not None and mine == theirs,
                    "fix": f"sudo {root / fix}"})
    return out


class RootCopies:
    """A sensor row for the sensor watch: quiet while a root copy differs
    from the project, so the dashboard and the analyst both see it."""

    role = "root_helpers"
    CHECK_SECONDS = 600

    def __init__(self, root: Path = ROOT, installed: Path = INSTALLED):
        self.root, self.installed = root, installed
        self.label = None
        self._at, self._rows = 0.0, []

    def _current(self) -> list:
        if time.time() - self._at > self.CHECK_SECONDS:
            self._rows, self._at = check(self.root, self.installed), time.time()
        return self._rows

    def _others(self) -> dict:
        """Service files and other installed files, on the real system only;
        the four helpers above are reported by name."""
        if self.installed != INSTALLED:
            return {}
        try:
            from core import own_install
            helpers = {str(self.installed / dst) for _, _, dst, _ in COPIES}
            out = {}
            for name, paths in own_install.stale(self.root).items():
                rest = [p for p in paths if p not in helpers]
                if rest:
                    out[name] = rest
            return out
        except Exception:                                   # noqa: BLE001
            return {}

    def liveness(self) -> dict:
        self._current()
        return {"started": True, "running": True, "thread_alive": True,
                "interval": self.CHECK_SECONDS, "started_at": self._at,
                "last_ok_at": self._at, "consecutive_failures": 0}

    def status(self) -> dict:
        rows = self._current()
        stale = [r for r in rows if r["installed"] and not r["matches"]]
        others = self._others()
        st = {"running": True, "role": self.role, "copies": rows}
        if stale or others:
            st["blind"] = True
            st["blind_reason"] = (
                "; ".join([f"the installed {r['helper']} differs from the "
                           f"project, run {r['fix']}" for r in stale]
                          + [f"{', '.join(paths)} differs from what "
                             f"{name} writes" for name, paths in
                             others.items()])
                + f". One command updates them all: sudo "
                  f"{self.root / 'scripts/refresh_helpers.sh'} --apply")
        elif not any(r["installed"] for r in rows):
            st["idle_reason"] = "no root helper is installed"
        return st


def split() -> dict:
    """How the app runs without root: which part holds each right, and
    whether each part is there. installed is False when the capture service
    was never installed, which is the old, single-process way."""
    from core import capture_service
    parts = []

    def part(name, holds, ok, why):
        parts.append({"part": name, "holds": holds, "ok": bool(ok),
                      "why": None if ok else why})

    part("capture service", "packet capture, and only that",
         capture_service.reporting(),
         "it is not reporting; check: systemctl status "
         f"{capture_service.UNIT_NAME}")
    try:
        from tools import names_helper
        data, why = names_helper.read()
    except Exception as e:                                  # noqa: BLE001
        data, why = None, str(e)
    part("names helper", "which program owns each connection",
         data is not None, why)
    try:
        from tools import local_integrity
        st = local_integrity.helper_status()
        read_ok, read_why = st.get("available"), st.get("reason")
    except Exception as e:                                  # noqa: BLE001
        read_ok, read_why = False, str(e)
    part("read helper", "the files and listings only root can read",
         read_ok, read_why or "install it: sudo scripts/install_read_helper.sh "
                              "--apply")
    try:
        from tools import action_broker
        inst = action_broker.installed()
        act_ok, act_why = inst["installed"], "; ".join(inst["problems"])
    except Exception as e:                                  # noqa: BLE001
        act_ok, act_why = False, str(e)
    part("action helper", "the actions you approve, after your password",
         act_ok, act_why)
    return {"installed": capture_service.UNIT_PATH.exists(),
            "parts": parts, "ok": all(p["ok"] for p in parts)}
