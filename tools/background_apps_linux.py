# tools/background_apps_linux.py
# Background apps on Linux: what owns each running process (a systemd service,
# a timer, an autostart entry, a flatpak or snap), what it costs, and a tier
# saying whether it can be blocked or disabled. Read only.
#
# Tiers:
#   safe_to_block      nothing in the system leans on it
#   block_not_disable  cut its network, keep it running
#   leave              switching it off can break something. Unknown is leave.
#
# Tiers come from data/background_apps_list_linux.json plus the hard rules in
# verdict(). Nothing a caller passes in can raise a tier.
#
# A source that could not be read says so by name and is never handed on as
# an empty list: "not read" is not "nothing there".

import configparser
import fnmatch
import json
import logging
import os
import pathlib
import pwd
import shlex
import subprocess
import time

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:                                  # pragma: no cover
    psutil = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIST_PATH = ROOT / "data" / "background_apps_list_linux.json"

CMD_TIMEOUT = 20
DEFAULT_INTERVAL = 1.0   # seconds between the two CPU samples
DEFAULT_LIMIT = 40
MAX_LIMIT = 150
PROCS_PER_APP = 3
ANSWER_BUDGET = 60000    # characters of JSON; stays under sanitize's cap

TIERS = ("leave", "block_not_disable", "safe_to_block")   # most careful first
TIER_RANK = {t: i for i, t in enumerate(TIERS)}
TIER_LABELS = {
    "safe_to_block": "Safe to block",
    "block_not_disable": "Block, do not disable",
    "leave": "Leave it",
}
KINDS = {"service", "user_service", "timer", "autostart", "flatpak", "snap",
         "process"}
# Which list section an owner kind is judged by.
LIST_KIND = {"service": "service", "user_service": "service", "timer": "timer",
             "autostart": "autostart", "flatpak": "flatpak", "snap": "snap"}

SOURCE_WORDS = {
    "usage":     "CPU and RAM per process",
    "services":  "systemd services",
    "timers":    "systemd timers",
    "autostart": "desktop autostart entries",
    "flatpak":   "flatpak apps",
    "snap":      "snap apps",
    "list":      "the list of known apps",
}

AUTOSTART_SYSTEM_DIRS = ("/etc/xdg/autostart",)


def _unread(why: str) -> dict:
    return {"read": False, "items": [], "why_not": why}


def _run(argv, runner=None):
    """(rc, stdout, error_or_None). Never raises."""
    if runner is not None:
        return runner(argv)
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=CMD_TIMEOUT, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout or "", None
    except FileNotFoundError:
        return 127, "", f"{argv[0]} is not installed"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} did not answer within {CMD_TIMEOUT}s"
    except Exception as e:                            # noqa: BLE001
        return 1, "", f"{type(e).__name__}: {e}"


# The list

def validate_list(data) -> dict:
    """Keep well-formed entries; name every one that was dropped and why."""
    entries, rejected = [], []
    for i, e in enumerate((data or {}).get("entries") or []):
        if not isinstance(e, dict):
            rejected.append(f"entry {i}: not an object")
            continue
        kind, match, tier = e.get("kind"), e.get("match"), e.get("tier")
        if kind not in KINDS:
            rejected.append(f"entry {i}: unknown kind {kind!r}")
        elif not match or not isinstance(match, str):
            rejected.append(f"entry {i}: no match")
        elif tier not in TIERS:
            rejected.append(f"entry {i}: unknown tier {tier!r}")
        elif not (e.get("why") or "").strip():
            rejected.append(f"entry {i} ({match}): no reason given")
        else:
            entries.append({"kind": kind, "match": match, "tier": tier,
                            "why": e["why"].strip()})
    return {"read": True, "entries": entries, "rejected": rejected,
            "why_not": None}


def load_list(path=None) -> dict:
    p = pathlib.Path(path or LIST_PATH)
    try:
        return validate_list(json.loads(p.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return {**_unread(f"{p.name} is missing"), "entries": [], "rejected": []}
    except (OSError, ValueError) as e:
        return {**_unread(f"{p.name} could not be read ({e})"),
                "entries": [], "rejected": []}


def list_match(the_list: dict, kind: str, name: str):
    """The most careful list entry for (kind, name), or None."""
    if not name:
        return None
    n = name.lower()
    hits = [e for e in the_list.get("entries") or []
            if e["kind"] == kind and fnmatch.fnmatch(n, e["match"].lower())]
    return min(hits, key=lambda e: TIER_RANK[e["tier"]]) if hits else None


# systemd

def _systemctl_json(args, runner=None):
    rc, out, err = _run(["systemctl", *args, "--output=json", "--no-pager"],
                        runner)
    if err or rc != 0:
        return None, err or f"systemctl {' '.join(args)} exited {rc}"
    try:
        return json.loads(out or "[]"), None
    except ValueError as e:
        return None, f"systemctl did not return JSON ({e})"


# list-unit-files takes seconds, so one read serves services and timers and
# is kept briefly. invalidate_cache() runs after any change we make.
UNIT_FILES_TTL = 60
_unit_files = {"at": 0.0, "states": None, "error": None}


def invalidate_cache():
    _unit_files.update(at=0.0, states=None, error=None)


def _unit_file_states(runner=None):
    if runner is None and _unit_files["states"] is not None and \
            time.monotonic() - _unit_files["at"] < UNIT_FILES_TTL:
        return _unit_files["states"], None
    files, err = _systemctl_json(["list-unit-files", "--type=service,timer"],
                                 runner)
    if files is None:
        return None, err
    states = {f.get("unit_file"): f.get("state") for f in files}
    if runner is None:
        _unit_files.update(at=time.monotonic(), states=states, error=None)
    return states, None


def _read_units(kind: str, runner=None) -> dict:
    units, err = _systemctl_json(["list-units", f"--type={kind}", "--all"],
                                 runner)
    if units is None:
        return _unread(err)
    all_states, err2 = _unit_file_states(runner)
    suffix = "." + kind
    states = {k: v for k, v in (all_states or {}).items()
              if k and k.endswith(suffix)}
    files = all_states
    items = {}
    for u in units:
        name = u.get("unit")
        if not name:
            continue
        items[name] = {"name": name, "description": u.get("description"),
                       "active": u.get("active"), "sub": u.get("sub"),
                       "load": u.get("load"),
                       "unit_file_state": states.get(name)}
    # Enabled units that are not loaded right now are still worth knowing.
    for name, state in states.items():
        if name and name not in items and "@" not in name:
            items[name] = {"name": name, "description": None,
                           "active": "inactive", "sub": "dead", "load": None,
                           "unit_file_state": state}
    return {"read": True, "items": list(items.values()),
            "why_not": None if files is not None else
            f"unit file states not read ({err2})"}


def read_services(runner=None) -> dict:
    return _read_units("service", runner)


def read_timers(runner=None) -> dict:
    out = _read_units("timer", runner)
    if not out["read"] or not out["items"]:
        return out
    names = [t["name"] for t in out["items"]]
    rc, text, err = _run(["systemctl", "show", "-p", "Id,Triggers",
                          "--no-pager", *names], runner)
    triggers = {}
    if not err and rc == 0:
        for block in text.strip().split("\n\n"):
            props = dict(line.split("=", 1) for line in block.splitlines()
                         if "=" in line)
            if props.get("Id"):
                triggers[props["Id"]] = props.get("Triggers", "").split()
    for t in out["items"]:
        t["triggers"] = triggers.get(t["name"], [])
    return out


# Desktop autostart

def owner_account():
    """The desktop user this machine belongs to: sudo's caller, else the tree's owner."""
    name = os.environ.get("SUDO_USER")
    try:
        if name:
            return pwd.getpwnam(name)
        return pwd.getpwuid(ROOT.stat().st_uid)
    except (KeyError, OSError):
        return None


def user_autostart_dir(account=None):
    account = account or owner_account()
    if account is None:
        return None
    return pathlib.Path(account.pw_dir) / ".config" / "autostart"


def _desktop_entry(path: pathlib.Path) -> dict:
    cp = configparser.RawConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    cp.read_string(path.read_text(encoding="utf-8", errors="replace"))
    return dict(cp["Desktop Entry"]) if cp.has_section("Desktop Entry") else {}


def exec_program(exec_line: str):
    """The program an Exec= line runs, skipping env and sh -c wrappers."""
    try:
        parts = shlex.split(exec_line or "")
    except ValueError:
        parts = (exec_line or "").split()
    parts = [p for p in parts if not p.startswith("%")]
    while parts and (parts[0] == "env" or "=" in parts[0]):
        parts = parts[1:]
    if len(parts) >= 3 and os.path.basename(parts[0]) in ("sh", "bash") \
            and parts[1] == "-c":
        return exec_program(parts[2])
    return os.path.basename(parts[0]) if parts else None


def _truthy(value) -> bool:
    return str(value or "").strip().lower() == "true"


def read_autostart(system_dirs=AUTOSTART_SYSTEM_DIRS, user_dir=None) -> dict:
    """Every autostart entry, the user's copy overriding the system one by file name."""
    user_dir = user_dir if user_dir is not None else user_autostart_dir()
    found, errors = {}, []
    for source, d in [("system", pathlib.Path(x)) for x in system_dirs] + \
                     ([("user", pathlib.Path(user_dir))] if user_dir else []):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.desktop")):
            try:
                e = _desktop_entry(f)
            except Exception as ex:                   # noqa: BLE001
                errors.append(f"{f.name}: {ex}")
                continue
            stem = f.stem
            prev = found.get(stem)
            enabled = not _truthy(e.get("Hidden")) and \
                str(e.get("X-GNOME-Autostart-enabled", "true")).lower() != "false"
            found[stem] = {
                "name": stem, "file": f.name, "path": str(f),
                "source": ("user override" if source == "user" and prev
                           else source),
                "system_path": (prev or {}).get("system_path")
                               or (str(f) if source == "system" else None),
                "display": e.get("Name") or stem,
                "exec": e.get("Exec"),
                "program": exec_program(e.get("Exec") or "")
                           or (prev or {}).get("program"),
                "enabled": enabled,
                "only_show_in": e.get("OnlyShowIn"),
            }
    if user_dir is None:
        errors.append("the desktop user could not be found, so their own "
                      "autostart entries were not read")
    return {"read": True, "items": list(found.values()),
            "why_not": "; ".join(errors) or None}


# flatpak and snap

def read_flatpaks(runner=None) -> dict:
    rc, out, err = _run(["flatpak", "list", "--app",
                         "--columns=application,name"], runner)
    if rc == 127:
        return {"read": True, "items": [], "why_not": None, "absent": True}
    if err or rc != 0:
        return _unread(err or f"flatpak list exited {rc}")
    items = []
    for line in out.splitlines():
        parts = line.split("\t")
        if parts and parts[0].strip():
            items.append({"name": parts[0].strip(),
                          "display": parts[1].strip() if len(parts) > 1 else None})
    return {"read": True, "items": items, "why_not": None}


def read_snaps(runner=None) -> dict:
    rc, out, err = _run(["snap", "list"], runner)
    if rc == 127:
        return {"read": True, "items": [], "why_not": None, "absent": True}
    if err or rc != 0:
        return _unread(err or f"snap list exited {rc}")
    items = [{"name": line.split()[0], "display": None}
             for line in out.splitlines()[1:] if line.split()]
    return {"read": True, "items": items, "why_not": None}


# Processes

def read_cgroup(pid: int):
    try:
        with open(f"/proc/{int(pid)}/cgroup", "r") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(":", 2)
                if len(parts) == 3 and parts[0] == "0":
                    return parts[2]
    except (OSError, ValueError):
        pass
    return None


def owner_from_cgroup(path: str):
    """(kind, name) from a cgroup v2 path, or None."""
    if not path:
        return None
    segs = [s for s in path.split("/") if s]
    for s in segs:
        if s.startswith("snap."):
            return ("snap", s.split(".")[1])
        if s.startswith("app-flatpak-") and s.endswith(".scope"):
            # app-flatpak-<app id>-<number>.scope
            return ("flatpak", s[len("app-flatpak-"):-len(".scope")].rsplit("-", 1)[0])
    if len(segs) >= 2 and segs[0] == "system.slice" and segs[1].endswith(".service"):
        return ("service", segs[1])
    if "user.slice" in segs and any(s.startswith("user@") for s in segs):
        leaf = segs[-1]
        if leaf.endswith(".service") and not leaf.startswith("user@"):
            return ("user_service", leaf)
    return None


def _is_kernel_thread(p) -> bool:
    try:
        return p.pid == 2 or p.ppid() == 2
    except Exception:                                 # noqa: BLE001
        return False


def sample_usage(interval: float = DEFAULT_INTERVAL, procs=None) -> dict:
    """CPU (two samples, one would read 0.0 everywhere) and RAM per process."""
    if psutil is None:
        return _unread("psutil is not installed")
    procs = list(procs) if procs is not None else list(psutil.process_iter())
    armed = []
    for p in procs:
        if _is_kernel_thread(p):
            continue
        try:
            p.cpu_percent(None)
            armed.append(p)
        except Exception:                             # noqa: BLE001
            continue
    time.sleep(max(0.0, interval))
    cpus = psutil.cpu_count() or 1
    by_pid, unreadable = {}, 0
    for p in armed:
        try:
            with p.oneshot():
                cpu = p.cpu_percent(None) / cpus
                rss = p.memory_info().rss
                name = p.name()
                try:
                    exe = p.exe()
                except Exception:                     # noqa: BLE001
                    exe = None
                try:
                    cmd = p.cmdline()
                except Exception:                     # noqa: BLE001
                    cmd = []
        except Exception:                             # noqa: BLE001
            unreadable += 1
            continue
        by_pid[p.pid] = {"pid": p.pid, "name": name, "exe": exe,
                         "cmd0": os.path.basename(cmd[0]) if cmd else None,
                         "cpu_percent": round(cpu, 1),
                         "ram_mb": round(rss / 1048576, 1),
                         "cgroup": read_cgroup(p.pid)}
    return {"read": True, "by_pid": by_pid, "unreadable": unreadable,
            "interval": interval, "why_not": None}


# Hard rules

def _core_names():
    try:
        from tools import remediation_linux as rl
        return {n.lower() for n in rl.CRITICAL_PROCESSES}
    except Exception:                                 # noqa: BLE001
        return {"systemd", "init", "dbus-daemon", "xorg", "cinnamon"}


CORE_EXTRA = {"cinnamon", "cinnamon-session", "cinnamon-launcher", "muffin",
              "nemo-desktop", "pipewire", "pipewire-pulse", "wireplumber",
              "pulseaudio", "at-spi-bus-launcher", "at-spi2-registryd",
              "xdg-desktop-portal", "xdg-document-portal",
              "xdg-permission-store", "gvfsd", "csd-*", "gsd-*"}


def is_core(proc) -> bool:
    name = (proc.get("name") or "").lower()
    if name.startswith("systemd") or name in _core_names():
        return True
    if any(fnmatch.fnmatch(name, pat) for pat in CORE_EXTRA):
        return True
    return proc.get("pid") == os.getpid()


def verdict(kind, name, procs, the_list, unit=None) -> dict:
    """
    The tier for one owner and the words it rests on. Each rule can only pull
    the tier toward leave; only a list entry can put it above leave.
    """
    if not the_list.get("read"):
        return {"tier": "leave", "note": None,
                "basis": (f"the list could not be read "
                          f"({the_list.get('why_not')}), so nothing is called safe")}
    core = sorted({p["name"] for p in procs if is_core(p)})
    if core:
        return {"tier": "leave", "note": None,
                "basis": f"core system process ({', '.join(core)}), never touched"}
    if kind == "process":
        return {"tier": "leave", "note": None,
                "basis": ("no service, timer or autostart entry owns it, so "
                          "there is nothing to judge it by. Unknown is always leave")}
    e = list_match(the_list, LIST_KIND.get(kind, kind), name)
    if not e:
        return {"tier": "leave", "note": None,
                "basis": f"{name}: not on the list. Unknown is always leave"}
    tier, notes = e["tier"], [e["why"]]
    basis = f"{name}: on the list as {TIER_LABELS[tier].lower()}"
    # A process name is anyone's to choose, so it only ever makes this more careful.
    for p in procs:
        pe = list_match(the_list, "process", p.get("name"))
        if pe and TIER_RANK[pe["tier"]] < TIER_RANK[tier]:
            tier = pe["tier"]
            basis += (f"; {p['name']}: the process is on the list as "
                      f"{TIER_LABELS[tier].lower()}")
            notes.append(pe["why"])
    return {"tier": tier, "basis": basis, "note": " ".join(notes)}


# The answer

def _guard(fn, *a, **kw) -> dict:
    try:
        return fn(*a, **kw)
    except Exception as e:                            # noqa: BLE001
        return _unread(f"{type(e).__name__}: {e}")


def snapshot(usage=None, services=None, timers=None, autostart=None,
             flatpaks=None, snaps=None, the_list=None,
             limit: int = DEFAULT_LIMIT, name: str = None,
             owner_kind: str = None) -> dict:
    """
    Every running process grouped by what owns it, with its load and tier,
    plus listed owners that are enabled but not running. Read only. Every
    source can be handed in, which is how the tests run.
    """
    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    # The CPU sample sleeps, so the other reads happen during it.
    sampler = None
    if usage is None:
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(max_workers=1)
        sampler = pool.submit(_guard, sample_usage)
        pool.shutdown(wait=False)
    services = services if services is not None else _guard(read_services)
    timers = timers if timers is not None else _guard(read_timers)
    autostart = autostart if autostart is not None else _guard(read_autostart)
    flatpaks = flatpaks if flatpaks is not None else _guard(read_flatpaks)
    snaps = snaps if snaps is not None else _guard(read_snaps)
    the_list = the_list if the_list is not None else load_list()
    if sampler is not None:
        usage = sampler.result()

    svc_by = {s["name"]: s for s in services.get("items") or []}
    tmr_by = {t["name"]: t for t in timers.get("items") or []}
    auto_by_prog = {}
    for a in autostart.get("items") or []:
        if a.get("program"):
            auto_by_prog.setdefault(a["program"].lower(), a)
    flat_names = {f["name"] for f in flatpaks.get("items") or []}

    groups = {}
    for p in (usage.get("by_pid") or {}).values():
        owner = owner_from_cgroup(p.get("cgroup"))
        if owner is None:
            # Autostart programs run in the desktop session, matched by program.
            for key in (os.path.basename(p.get("exe") or ""), p.get("cmd0"),
                        p.get("name")):
                a = auto_by_prog.get((key or "").lower())
                if a:
                    owner = ("autostart", a["name"])
                    break
        owner = owner or ("process", p.get("name") or "?")
        groups.setdefault(owner, []).append(p)

    def target(kind, nm):
        if kind == "service":
            s = svc_by.get(nm) or {}
            return {"unit": nm, "unit_file_state": s.get("unit_file_state"),
                    "active": s.get("active")}
        if kind == "user_service":
            return {"unit": nm}
        if kind == "timer":
            t = tmr_by.get(nm) or {}
            return {"unit": nm, "unit_file_state": t.get("unit_file_state"),
                    "active": t.get("active"), "triggers": t.get("triggers")}
        if kind == "autostart":
            a = next((x for x in autostart.get("items") or []
                      if x["name"] == nm), {})
            return {"file": a.get("file"), "path": a.get("path"),
                    "source": a.get("source"), "enabled": a.get("enabled"),
                    "program": a.get("program")}
        return {"id": nm}

    def display(kind, nm):
        if kind == "service":
            return (svc_by.get(nm) or {}).get("description")
        if kind == "timer":
            return (tmr_by.get(nm) or {}).get("description")
        if kind == "autostart":
            a = next((x for x in autostart.get("items") or []
                      if x["name"] == nm), {})
            return a.get("display")
        if kind == "flatpak":
            f = next((x for x in flatpaks.get("items") or []
                      if x["name"] == nm), {})
            return f.get("display")
        return None

    def row(kind, nm, procs, state=None):
        v = verdict(kind, nm, procs, the_list)
        procs = sorted(procs, key=lambda p: p.get("cpu_percent") or 0,
                       reverse=True)
        return {"owner_kind": kind, "owner_name": nm,
                "display_name": display(kind, nm),
                "state": state,
                "processes": [{"pid": p["pid"], "name": p["name"],
                               "cpu_percent": p["cpu_percent"],
                               "ram_mb": p["ram_mb"]}
                              for p in procs[:PROCS_PER_APP]],
                "process_count": len(procs),
                "pids": [p["pid"] for p in procs],
                "cpu_percent": round(sum(p.get("cpu_percent") or 0 for p in procs), 1)
                               if procs else None,
                "ram_mb": round(sum(p.get("ram_mb") or 0 for p in procs), 1)
                          if procs else None,
                "tier": v["tier"], "tier_label": TIER_LABELS[v["tier"]],
                "tier_basis": v["basis"], "tier_note": v["note"],
                "target": target(kind, nm)}

    apps = [row(k, n, procs) for (k, n), procs in groups.items()]
    running = {(a["owner_kind"], a["owner_name"]) for a in apps}

    # Listed owners that are switched on but have nothing running now.
    not_running = []
    for s in services.get("items") or []:
        if ("service", s["name"]) in running:
            continue
        if s.get("unit_file_state") in ("enabled", "enabled-runtime") or \
                s.get("active") == "active":
            if list_match(the_list, "service", s["name"]):
                not_running.append(row("service", s["name"], [],
                                       state=s.get("unit_file_state")))
    for t in timers.get("items") or []:
        if t.get("unit_file_state") in ("enabled", "enabled-runtime") or \
                t.get("active") == "active":
            if list_match(the_list, "timer", t["name"]):
                not_running.append(row("timer", t["name"], [],
                                       state=t.get("active")))
    for a in autostart.get("items") or []:
        if ("autostart", a["name"]) in running or not a.get("enabled"):
            continue
        if list_match(the_list, "autostart", a["name"]):
            not_running.append(row("autostart", a["name"], [],
                                   state="starts at login"))
    for f in flat_names:
        if ("flatpak", f) not in running and list_match(the_list, "flatpak", f):
            not_running.append(row("flatpak", f, [], state="installed"))

    def _tiers(rows):
        return {t: sum(1 for a in rows if a["tier"] == t) for t in TIERS}
    kinds = {}
    for a in apps:
        kinds[a["owner_kind"]] = kinds.get(a["owner_kind"], 0) + 1
    machine_counts = {
        "running_apps": len(apps),
        "not_running_on_list": len(not_running),
        "owner_kinds": kinds,
        "tiers_running": _tiers(apps),
        "tiers_not_running": _tiers(not_running),
        "note": ("Counted over every running app on this machine, before any "
                 "name or owner_kind filter and before the size budget."),
    }

    if owner_kind:
        ok = owner_kind.strip().lower()
        apps = [a for a in apps if a["owner_kind"] == ok]
        not_running = [a for a in not_running if a["owner_kind"] == ok]
    if name:
        n = name.strip().lower()

        def hit(a):
            blob = " ".join([a["owner_name"], a.get("display_name") or ""]
                            + [p["name"] or "" for p in a["processes"]])
            return n in blob.lower()
        apps = [a for a in apps if hit(a)]
        not_running = [a for a in not_running if hit(a)]

    apps.sort(key=lambda a: (a["cpu_percent"] or 0, a["ram_mb"] or 0),
              reverse=True)

    # Everything worth acting on, never cut by the size budget.
    actionable = []
    for a in apps + not_running:
        if a["tier"] == "leave":
            continue
        actionable.append({k: a[k] for k in (
            "owner_kind", "owner_name", "display_name", "state", "cpu_percent",
            "ram_mb", "tier", "tier_label", "tier_basis", "tier_note",
            "target", "pids")} | {"running": bool(a["processes"])})
    actionable.sort(key=lambda a: (TIER_RANK[a["tier"]], a["running"]),
                    reverse=True)

    sources = {}
    for key, s in (("usage", usage), ("services", services), ("timers", timers),
                   ("autostart", autostart), ("flatpak", flatpaks),
                   ("snap", snaps), ("list", the_list)):
        count = (len(s.get("by_pid") or {}) if key == "usage"
                 else len(s.get("entries") or []) if key == "list"
                 else len(s.get("items") or []))
        sources[key] = {"read": bool(s.get("read")), "count": count,
                        "why_not": s.get("why_not")}
    sources["usage"]["unreadable_processes"] = usage.get("unreadable", 0)
    sources["list"]["rejected"] = the_list.get("rejected") or []

    incomplete = [k for k, s in sources.items() if not s["read"]]
    judged = [k for k in incomplete if k in ("services", "timers", "autostart",
                                             "flatpak", "snap", "list")]
    actionable_note = None
    if judged:
        actionable_note = ("Not complete: " + ", ".join(SOURCE_WORDS[k] for k in judged)
                           + " could not be read, so whatever they own could "
                             "not be judged and is not in this list.")
    note = None
    if incomplete:
        note = ("Not read: " + ", ".join(SOURCE_WORDS[k] for k in incomplete)
                + ". Anything those own shows as an unknown process and stays "
                  "Leave it. Not read is not the same as not there.")

    shown, nr = apps[:limit], not_running[:limit]
    asked = len(shown)
    while len(shown) > 1 and len(json.dumps({"a": shown, "n": nr},
                                            default=str)) > ANSWER_BUDGET:
        shown = shown[:max(1, int(len(shown) * 0.8))]
    shortened = None
    if len(shown) < asked:
        shortened = {"asked": asked, "returned": len(shown),
                     "note": (f"Shortened to fit one answer: {asked - len(shown)} "
                              f"of the lighter apps were left out. Ask with name "
                              f"or owner_kind to see them.")}

    return {
        "apps": shown,
        "returned": len(shown),
        "more": max(0, len(apps) - len(shown)),
        "shortened": shortened,
        "not_running": nr,
        "machine_counts": machine_counts,
        "actionable": actionable,
        "actionable_complete": not judged,
        "actionable_note": actionable_note,
        "sources": sources,
        "incomplete": incomplete,
        "incomplete_note": note,
        "sampled_over_seconds": usage.get("interval"),
        "how_to_read": (
            "tier is the app's call from its list and hard rules; nothing you "
            "pass in can raise it. safe_to_block means nothing in the system "
            "leans on it, block_not_disable means cut its network but keep it "
            "running, leave means do not touch it. Never promise nothing will "
            "break: say what the tier rests on (tier_basis) and what it "
            "affects (tier_note). cpu_percent is a share of the whole machine. "
            "None means not readable, never zero."),
    }
