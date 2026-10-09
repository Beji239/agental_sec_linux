# main.py
# AgentalSec Linux - Entry point
#
# Runs as a normal user. Packet capture, full journald access and firewall
# rules need root or capabilities; see _report_privileges().
#
# Boot order matters: config, secrets, migrations, sensors, agent, modules,
# init_registry, start(), sweepers, shutdown handler, then the web server.

import asyncio
import json
import logging
import os
import secrets
import signal
import sys
import threading
import time
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent

# Logging setup - same as Windows version
_LOG_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
_LOG_DIR    = PROJECT_ROOT / "logs"

logging.basicConfig(
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("agental_sec_linux")

try:
    from logging.handlers import RotatingFileHandler as _RFH

    class RotatingFileHandler(_RFH):
        """Every file it opens, rotation included, is 0640."""
        def _open(self):
            stream = super()._open()
            try:
                os.chmod(self.baseFilename, 0o640)
            except OSError:
                pass
            return stream

    # The log is private to its owner.
    _LOG_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        os.chmod(_LOG_DIR, 0o750)
    except OSError:
        pass
    _LOG_FILE = _LOG_DIR / "agental_sec_linux.log"

    # A log file left behind by a root run is not writable by the user, so
    # fall back to a per-run log and say where the record went.
    _file_handler = None
    _log_path = _LOG_FILE
    try:
        _file_handler = RotatingFileHandler(
            _LOG_FILE,
            maxBytes=20_000_000,
            backupCount=5,
            encoding="utf-8",
        )
    except (PermissionError, OSError) as _log_exc:
        fallback = _LOG_DIR / f"agental_sec_linux.{os.getpid()}.log"
        try:
            _file_handler = RotatingFileHandler(
                fallback, maxBytes=20_000_000, backupCount=2, encoding="utf-8")
            _log_path = fallback
        except Exception:
            pass

    if _file_handler is not None:
        _file_handler.setFormatter(
            logging.Formatter(_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
        )
        _file_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(_file_handler)
        LOG_FILE_ACTIVE = True
        if _log_path != _LOG_FILE:
            logger.warning(
                f"{_LOG_FILE} is not writable by this user, which usually "
                f"means it was created by an earlier run under sudo. Logging "
                f"to {_log_path} instead so this run still leaves a record. "
                f"To restore the usual file: sudo chown {os.environ.get('USER', 'you')} "
                f"{_LOG_FILE}")
    else:
        LOG_FILE_ACTIVE = False
except Exception as _log_exc:
    LOG_FILE_ACTIVE = False
    logger.error(
        f"FILE LOGGING UNAVAILABLE: could not open {_LOG_DIR / 'agental_sec_linux.log'} "
        f"({_log_exc}). This session will leave NO record once this console "
        f"closes."
    )

# Resolved so the atomic replace writes the real file, which in Docker sits
# behind a symlink into the /state volume.
CONFIG_PATH = (PROJECT_ROOT / "config.json").resolve()
ENV_PATH    = (PROJECT_ROOT / ".env").resolve()

# config.json holds SHAPE ONLY: hosts, ports, paths, model names. Secrets
# live in .env. Same split as the Windows version, for the same reason: it
# is what makes config.json safe to commit.
DEFAULT_CONFIG = {
    "provider": {
        "model":     "",
        "api_url":   "",
        "api_style": "auto"
    },
    "geoip": {
        "enabled":    True,
        "db_path":    "geoip/dbip-city-lite.mmdb",
        "home_lat":   None,
        "home_lon":   None,
        "home_label": None,
        "locate_online": True
    },
    "flask": {
        "host":              "127.0.0.1",
        "port":              5000,
        "auto_open_browser": True,
        "allowed_hosts":     []
    },
    "vpn": {
        "interface_patterns": []
    },
    "linux_monitor": {
        "enabled":         False,
        "strict_host_key": False,
        "hosts":           []
    },
    "presence_sweep": {
        "enabled":          True,
        "interval_minutes": 15
    },
    "probe": {
        "enabled":            True,
        "interval_days":      21,
        "max_hosts_per_pass": 25,
        "pacing_seconds":     2.0,
        "exclusion_list":     []
    },
    "sensor": {
        "position": "host",
        "label":    None
    },
    "dns_monitor": {
        "enabled":          True,
        "source":           "auto",
        "path":             "",
        "interval_minutes": 15,
        "label":            None
    },
    "router_monitor": {
        "enabled":          False,
        "backend":          "snmp",
        "host":             "",
        "port":             161,
        "timeout_seconds":  3,
        "interval_minutes": 10,
        "label":            None
    },
    "gateway": {
        "enabled":          False,
        "host":             "",
        "port":             22,
        "user":             "root",
        "interval_minutes": 5,
        "label":            None
    },
    "heartbeat": {
        "interval_minutes": 5
    },
    # Which module backs each sensor role. Empty means "use the default for
    # this platform", which is what almost every install wants. It exists as
    # config at all so that the Windows monitor and its Linux twin can be
    # swapped without editing code, which is a thing worth being able to do
    # while porting.
    "sensor_backends": {}
}

# WHICH MODULE ANSWERS FOR WHICH SENSOR ROLE
#
# The Windows tree has tools/process_monitor.py; this tree has BOTH that file
# and tools/process_monitor_linux.py. They are different designs, not two
# names for one thing: the Windows monitor knows about Defender, LOLBAS and
# registry persistence, the Linux one knows about GTFOBins-shaped argument
# patterns and Linux path conventions.
#
# Rather than pick one and delete the other, the role name is stable
# ("process_monitor", which is also the key tool_registry and sensor_health
# look up) and the CLASS behind it is what varies. sensor_backends in
# config.json overrides any of these.
#
# The Windows-derived module is the default where it already has a working
# Linux branch, because it is the one whose findings, dedup, cooldown and
# detection-id wiring have been exercised for months. The Linux-native one
# is the default where the Windows module has no Linux path at all.
_SENSOR_BACKENDS = {
    "linux": {
        "process_monitor": "tools.process_monitor_linux",
        "packet_sniffer":  "tools.packet_sniffer_linux",
        "event_monitor":   "tools.event_monitor_linux",
        # These two keep the Windows module: both write findings through the
        # register (PRC-1001 / NET-1001) and both already handle Linux, while
        # their Linux-named twins are module-level functions with no class,
        # no dedup and their database writes commented out.
        #
        # RE-READ AT THE host_info ROUND, 2026-09-25, because the argument for
        # keeping the Windows module is about FINDINGS and this role raises
        # none. Measured then: tools/host_info.py answers 21 keys and
        # tools/host_info_linux.py answers what that module cannot (hardware,
        # network, interfaces, login history, service state, sysctl, LSM,
        # firewall), and the adapter that bridges them used to drop the
        # uptime half. Both are now correct; the entry stays as it is because
        # `collected_at`/`scope`/`errors` are what the readiness page and the
        # description's language are written against. WHICH ONE SHOULD BACK
        # THIS ROLE IS AN OPERATOR'S CHOICE WITH A CONFIG KEY, and it is
        # recorded in the register rather than taken here.
        "host_info":          "tools.host_info",
        "software_inventory": "tools.software_inventory",
        # THE LINUX ANSWER, FLIPPED 2026-09-21. This pointed at
        # tools.registry_monitor, so the shipped Linux app read a WINDOWS
        # REGISTRY and printed "RegistryMonitor: not Windows, nothing to read"
        # on every boot, while tools/autorun_monitor.py and the
        # LinuxAutorunMonitor adapter that wraps it sat unreachable below.
        # Measured in this tree's own boot log, twice: "[OK] registry_monitor"
        # followed by "[tools.registry_monitor] INFO: RegistryMonitor: not
        # Windows, nothing to read."
        #
        # That is the L5 line in AGENTIC_PROGRAMME.md, and it is the worst
        # shape of the problem: not a missing feature but a present one
        # wearing the name of another platform, so the readiness page shows
        # the role as loaded and healthy and nothing anywhere says the
        # question was never asked. The module key stays "registry_monitor"
        # because core/sensor_health.DEPENDS names it that.
        "autoruns":           "tools.autorun_monitor",
        "remediation":        "tools.remediation_linux",
        # L3, 2026-09-22. The local-file sensor. Not a backend anyone would
        # swap: unlike the four above there is no Windows module it could be
        # pointed at, because "the integrity of the machine I am running on"
        # is not a thing the Windows tree ever had either. It is in this table
        # so the role is declared in one place like every other role.
        "local_integrity":    "tools.local_integrity",
        # T6, 2026-09-22. The kernel camera's READER. The camera itself is
        # ebpf/ebpf_monitor.py, which runs as root and writes a sidecar file;
        # this role is the module that reads that file as the operator. Same
        # argument as local_integrity for why it is in this table: there is no
        # Windows counterpart it could be pointed at, because the Windows tree
        # never had a kernel-event source either.
        "ebpf_events":        "tools.ebpf_events",
        # L4, 2026-09-22. THE KERNEL AUDIT FEED. Not a backend anyone would
        # swap: there is no Windows module it could be pointed at, and nothing
        # else in either tree reads auditd. It is in this table so the role is
        # declared in one place like every other role -- and declared
        # UNCONDITIONALLY, including on a host where auditd is not installed,
        # because the state a reader most needs from this role is the one
        # where the feed is absent. See its class comment in adapters.py.
        "auditd":             "tools.auditd_monitor",
    },
}


def _sensor_backend(config: dict, role: str) -> str:
    """
    Which module answers for this role on this platform.

    config.sensor_backends wins, then the platform table, then nothing (the
    caller skips the role and says so). Returning "" rather than raising is
    deliberate: an unknown role is a config typo, and a typo should cost one
    sensor with a log line, not the boot.

    A ROLE THAT CAN ONLY BE BACKED BY A KNOWN SET OF MODULES SHOULD SAY SO.
    host_info is the first one that does -- see _HOST_INFO_BACKENDS and the
    guard at its construction site in boot() -- because its `if role == ... /
    else ...` shape silently accepted ANY other value, including a misspelling
    of the module the operator meant (measured 2026-09-25).
    """
    override = (config.get("sensor_backends") or {}).get(role)
    if override:
        return str(override)
    platform = "linux" if sys.platform.startswith("linux") else None
    return (_SENSOR_BACKENDS.get(platform) or {}).get(role, "")


# The modules this tree carries for the host_info role. Named here so the
# boot can REFUSE anything else rather than silently taking the else arm;
# kept beside _SENSOR_BACKENDS because that table is what a reader checks
# first when asking which module answers for which role.
_HOST_INFO_BACKENDS = ("tools.host_info", "tools.host_info_linux", "linux")

# The same list for the software_inventory role, added 2026-09-26 (register
# section 12) for the same reason: the role's own `if / else` accepted any
# other value, so a typo in sensor_backends booted the Linux module without
# a word. Both entries are honest backends for this role on this platform.
_SOFTWARE_INVENTORY_BACKENDS = ("tools.software_inventory",
                                "tools.software_inventory_linux",
                                "linux")


def _report_privileges():
    """Report what this run can and cannot do based on privileges."""
    try:
        from core import privilege_linux as priv

        posture = priv.posture()

        logger.info("=" * 60)
        logger.info("AGENTALSEC LINUX - PRIVILEGE REPORT")
        logger.info("=" * 60)
        logger.info(posture["summary"])
        logger.info("")

        if posture["elevated"]:
            logger.info("Running as ROOT - all capabilities available")
        else:
            logger.info("Running unelevated:")
            for name, consequence in posture["unavailable_when_unelevated"]:
                logger.info(f"  - {name}: {consequence}")
            for name, consequence in posture["degraded_when_unelevated"]:
                logger.info(f"  - {name}: {consequence} (degraded)")

        logger.info("")
        logger.info(f"Packet capture: {'YES' if posture['can_capture_packets'] else 'NO'} - {posture['capture_reason']}")
        logger.info("=" * 60)

    except ImportError:
        logger.warning("privilege_linux module not found - cannot report capabilities")


def _check_dependencies():
    """Check for required and optional dependencies."""
    missing_critical = []
    missing_optional = []

    for module, label, critical in (
        ("flask",      "flask",                        True),
        ("flask_cors", "flask-cors",                   True),
        ("sqlite3",    "sqlite3",                      True),
        ("psutil",     "psutil (process monitoring)",  True),
        ("httpx",      "httpx (model calls)",          False),
        ("requests",   "requests (KEV feed, search)",  False),
        ("paramiko",   "paramiko (remote monitoring)", False),
        ("cryptography", "cryptography (secret encryption)", False),
        ("scapy.all",  "scapy (packet capture)",       False),
        ("maxminddb",  "maxminddb (threat map)",       False),
    ):
        try:
            __import__(module)
        except ImportError:
            (missing_critical if critical else missing_optional).append(label)

    if missing_critical:
        logger.error(f"MISSING CRITICAL DEPENDENCIES: {', '.join(missing_critical)}")
        logger.error("Install with: pip install -r requirements.txt")
        logger.error("On an externally-managed Python (PEP 668) add "
                     "--break-system-packages, or use a virtualenv.")
        return False

    if missing_optional:
        logger.warning(f"Missing optional dependencies: {', '.join(missing_optional)}")
        logger.warning("Some features will be unavailable")

    return True


def _write_config_file(text: str):
    """Replace config.json atomically, so a reader never sees half a file (BP-1)."""
    tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, CONFIG_PATH)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def _load_config() -> dict:
    """
    Read config.json, creating it from the template on first run, so a fresh
    install starts without being configured first.
    """
    if not CONFIG_PATH.exists():
        template = PROJECT_ROOT / "config.linux.example.json"
        try:
            if template.exists():
                _write_config_file(template.read_text(encoding="utf-8"))
                logger.info(f"config.json created from {template.name}.")
            else:
                _write_config_file(json.dumps(DEFAULT_CONFIG, indent=2))
                logger.info("config.json created with defaults.")
        except OSError as e:
            logger.error(f"Could not write config.json ({e}), using "
                         f"in-memory defaults. Nothing will be saved.")

    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"config.json could not be read ({e}). Falling back to "
                     f"defaults. Fix the file, this run will not save it.")
        return json.loads(json.dumps(DEFAULT_CONFIG))

    changed = False
    for key, value in DEFAULT_CONFIG.items():
        if key not in config:
            config[key] = json.loads(json.dumps(value))
            changed = True
    if changed:
        try:
            _write_config_file(json.dumps(config, indent=2))
            logger.info("config.json updated with new default blocks.")
        except OSError as e:
            logger.warning(f"Could not save the new defaults ({e}).")

    return config


def _make_private(db_path):
    """
    The store and its side files readable by the owner only (CC-5).

    They hold command lines, DNS names and chat history, and SQLite's -wal and
    -shm files take the main file's mode, so narrowing it keeps them private.
    """
    from pathlib import Path
    base = Path(db_path)
    for path in [base, *base.parent.glob(base.name + "*"),
                 base.parent / "config.json"]:
        try:
            mode = path.stat().st_mode & 0o777
            if path.is_file() and mode & 0o077:
                os.chmod(path, mode & 0o700)
                logger.info(f"{path.name} was mode {oct(mode)}; now "
                            f"{oct(mode & 0o700)}, readable by its owner only.")
        except OSError as e:
            logger.warning(f"Could not narrow {path.name}: {e}")


def _initialize_database():
    """Create or migrate the SQLite database."""
    from core import memory_engine as me
    from core import migrations

    db_path = me.DB_PATH
    logger.info(f"DB: {db_path}")
    _make_private(db_path)

    try:
        result = migrations.run_migrations(db_path)
    except Exception as e:
        logger.error(f"Schema migration failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        logger.error("Refusing to start on an un-migrated database.")
        return False

    status = result.get("status")
    if result.get("created"):
        logger.info(f"Database created and migrated to v{result.get('version')}.")
    elif status == "migrated":
        logger.info(f"Schema migrated {result.get('from_version')} -> "
                    f"{result.get('version')}.")
    elif status == "current":
        logger.info(f"Schema up to date (v{result.get('version')}).")
    else:
        logger.warning(f"Migration reported {status!r}: {result}")

    return True


# THE MODULE TABLE
#
# Every entry here is a class the tool registry will dispatch a tool to.
# The keys are the names core/sensor_health.py and core/tool_registry.py
# already use, so they are NOT free to rename.


def _load_modules(config: dict, session_id: str, rollup_engine) -> dict:
    """
    Build the modules dict, exactly as the Windows main.py does.

    try_load wraps every one. A module that fails to import becomes None and
    is listed as [SKIP] with its reason, because a sensor that is off and a
    sensor that is broken have to stay different sentences, and the boot log
    is where that is decided.
    """
    from core import tool_registry

    def try_load(name, loader):
        try:
            mod = loader()
            logger.info(f"[OK] {name}")
            return mod
        except Exception as e:
            logger.warning(f"[SKIP] {name}: {type(e).__name__}: {e}")
            return None

    def _cls(module_path):
        mod = __import__(module_path, fromlist=["*"])
        return mod

    modules = {}

    # host identity. Loaded first: several other paths want to know what
    # this host is, and it is pure introspection with nothing to fail against.
    #
    # AND THE `else` ARM IS A TYPO DOOR, measured 2026-09-25. Every other
    # value on this role -- including a MISSPELLED module name -- falls into
    # the Linux branch below without a word, because the only arm that is
    # checked has to equal "tools.host_info" exactly. `sensor_backends:
    # {"host_info": "tools.host_inf"}` therefore boots a DIFFERENT MODULE
    # from the one the operator wrote, silently, on a role whose payload the
    # model reads as this machine's identity. The names this role accepts are
    # named here, an unrecognised one is reported, and an absent key still
    # means the default.
    role = _sensor_backend(config, "host_info")
    if role not in _HOST_INFO_BACKENDS:
        logger.warning(
            f"[SKIP] host_info: config sensor_backends.host_info names "
            f"{role!r}, which is not a module this tree carries for this "
            f"role. Built from {_HOST_INFO_BACKENDS[0]!r} instead. Known: "
            f"{list(_HOST_INFO_BACKENDS)}")
        role = _HOST_INFO_BACKENDS[0]
    if role == "tools.host_info":
        modules["host_info"] = try_load("host_info", lambda: (
            _cls("tools.host_info").HostInfo(session_id)
        ))
    else:
        # The Linux module is module-level functions, not a class. Wrapped.
        from adapters import LinuxHostInfo
        modules["host_info"] = try_load("host_info",
                                        lambda: LinuxHostInfo(session_id))

    role = _sensor_backend(config, "software_inventory")
    # AND THE ELSE ARM IS A TYPO DOOR HERE TOO, the same shape HI-12 closed
    # for host_info (2026-09-25): without this guard, ANY unrecognised value
    # -- including a misspelling of the class the operator meant -- falls
    # into the Linux branch below and boots a different module in silence.
    # Register section 12, 2026-09-26.
    if role not in _SOFTWARE_INVENTORY_BACKENDS:
        # THE PHRASE "config sensor_backends.software_inventory" IS KEPT ON ONE
        # SOURCE LINE, deliberately: the HI-12 round's lesson was that a guard
        # whose words are wrapped across f-string literals cannot be read out
        # of the source by a text assertion, and this guard gets the same
        # treatment (tests/test_software_inventory_fixes.py section [12]).
        logger.warning(
            f"[SKIP] software_inventory: config sensor_backends.software_inventory"
            f" names {role!r}, which is not a module this tree carries for "
            f"this role. Built from {_SOFTWARE_INVENTORY_BACKENDS[0]!r} "
            f"instead. Known: {list(_SOFTWARE_INVENTORY_BACKENDS)}")
        role = _SOFTWARE_INVENTORY_BACKENDS[0]
    if role == "tools.software_inventory":
        # The class is the live backend: it reads the machine's package
        # manager directly and its rows are what local_integrity's package
        # checks are joined against (register section 12).
        modules["software_inventory"] = try_load("software_inventory", lambda: (
            _cls("tools.software_inventory").SoftwareInventory(session_id)
        ))
    else:
        # The Linux module is module-level functions, not a class. Wrapped.
        from adapters import LinuxSoftwareInventory
        modules["software_inventory"] = try_load(
            "software_inventory", lambda: LinuxSoftwareInventory(session_id))

    # persistence / autoruns. Key stays "registry_monitor" because
    # sensor_health.DEPENDS names it that, but the BACKEND is chosen above and
    # on this platform it is the Linux one: systemd units, cron, init.d and
    # shell startup files, read by tools/autorun_monitor.py. The Windows
    # registry class is not reachable from here any more. See the note on
    # _SENSOR_BACKENDS.
    role = _sensor_backend(config, "autoruns")
    if role != "tools.autorun_monitor":
        raise SystemExit(f"autoruns is configured to use {role!r}, which is "
                         f"not a module this tree carries. The Windows "
                         f"registry reader is Windows-only and is NOT in this "
                         f"tree: it is kept outside it, beside the two source "
                         f"folders, as "
                         f"agental_sec_win32_reference/tools/registry_monitor.py.")
    from adapters import LinuxAutorunMonitor
    # CONFIG IS PASSED, AND IT WAS NOT BEFORE. Until 2026-09-24 this lambda was
    # `LinuxAutorunMonitor(session_id)`, so the adapter ran on its built-in
    # defaults and could not have honoured `sensors.autorun_monitor.enabled`
    # even if it had tried -- the key was unreachable from the only place that
    # constructs this class. Every other Linux sensor below is handed the
    # config; this one was the exception, and the exception is exactly why AR-12
    # existed.
    modules["registry_monitor"] = try_load(
        "registry_monitor", lambda: LinuxAutorunMonitor(session_id, config))

    # the three sensors. THE WINDOWS BRANCHES ARE GONE, 2026-09-21.
    #
    # Each of these read as "if the Linux module, use it, else build the
    # Windows class", and the else arm named tools/event_monitor.py,
    # tools/remediation.py and tools/registry_monitor.py. On a Linux-only
    # tree those arms are unreachable BY CONFIG, which is not the same as
    # unreachable by accident: any future config edit that named the Windows
    # module would have taken the tree down with an ImportError rather than
    # saying the platform cannot do it. The modules are out of this tree
    # entirely now, so the arms are deleted rather than left to rot.
    role = _sensor_backend(config, "packet_sniffer")
    if role != "tools.packet_sniffer_linux":
        raise SystemExit(
            f"packet_sniffer is configured to use {role!r}, which is not a "
            f"module this tree carries. This is the Linux port: the capture "
            f"backend is tools.packet_sniffer_linux. Fix the platform entry "
            f"in main.py or the config, and do not point it at a Windows "
            f"module, which is not in this tree and cannot run here.")
    from adapters import LinuxPacketSniffer
    modules["packet_sniffer"] = try_load(
        "packet_sniffer", lambda: LinuxPacketSniffer(session_id, config))

    role = _sensor_backend(config, "process_monitor")
    if role != "tools.process_monitor_linux":
        raise SystemExit(f"process_monitor is configured to use {role!r}, "
                         f"which is not a module this tree carries.")
    from adapters import LinuxProcessMonitor
    modules["process_monitor"] = try_load(
        "process_monitor", lambda: LinuxProcessMonitor(session_id, config))

    role = _sensor_backend(config, "event_monitor")
    if role != "tools.event_monitor_linux":
        raise SystemExit(f"event_monitor is configured to use {role!r}, "
                         f"which is not a module this tree carries.")
    from adapters import LinuxEventMonitor
    modules["event_monitor"] = try_load(
        "event_monitor", lambda: LinuxEventMonitor(session_id, config))

    # local_integrity. L3, 2026-09-22. THE MACHINE THIS APP RUNS ON.
    #
    # Everything above either watches this host's live activity (packets,
    # processes, logs) or watches a REMOTE host over SSH. Nothing watched this
    # machine's own FILES, so an added authorized_keys, a widened sudoers or a
    # planted setuid binary produced no finding at all. This is that sensor.
    #
    # READ-ONLY AND UNPRIVILEGED. It needs no root to do the half it does, and
    # it reports the half it cannot rather than being switched off: /etc/sudoers
    # and /etc/sudoers.d are root-only on this host and the module says so on
    # every status read.
    #
    # IT HAS ITS OWN THREAD FOR THE FILESYSTEM SWEEP. Measured here at 30 to 40
    # seconds over 936,143 files; see the class and the module header. Loaded
    # whether or not the operator wants the sweep, because the tier A checks
    # cost about a second and are the half that catches a key being added.
    role = _sensor_backend(config, "local_integrity")
    if role != "tools.local_integrity":
        raise SystemExit(f"local_integrity is configured to use {role!r}, "
                         f"which is not a module this tree carries. This role "
                         f"has no Windows counterpart: it reads the machine "
                         f"the app is running on, and tools.local_integrity is "
                         f"the only implementation of it.")
    from adapters import LinuxLocalIntegrity
    modules["local_integrity"] = try_load(
        "local_integrity", lambda: LinuxLocalIntegrity(session_id, config))
    if modules["local_integrity"] is None:
        logger.warning(
            "local_integrity did not load, so NOTHING is watching this "
            "machine's own files: no authorized_keys check, no sudoers check, "
            "no setuid or capability sweep. The remote host checks in "
            "linux_monitor are a different sensor and do not cover this. "
            "query_local_integrity reports it as unloaded rather than as a "
            "clean host.")

    # THE KERNEL CAMERA. T6, 2026-09-22. THE FIVE-SECOND PROCESS.
    #
    # Everything above learns what is happening by ASKING: /proc once a poll,
    # journald in batches, a stat() per watched file. A program that starts,
    # acts and exits between two asks leaves NO ROW ANYWHERE, and the app
    # cannot even report that it might have missed it. This role reads the
    # events that ebpf/ebpf_monitor.py -- a separate, root-confined process --
    # caught at the moment the kernel did the thing.
    #
    # LOADED WHETHER OR NOT THE CAMERA IS INSTALLED, and it never raises for a
    # missing camera: most hosts will not have one, because it needs root and
    # an installer run. What it must never do is come up quietly and let a
    # camera that was never started read as a machine where nothing ran, so the
    # tool reports the absence in words and this block says which of the states
    # the boot found.
    role = _sensor_backend(config, "ebpf_events")
    if role != "tools.ebpf_events":
        raise SystemExit(f"ebpf_events is configured to use {role!r}, which is "
                         f"not a module this tree carries. This role has no "
                         f"Windows counterpart: it reads the event file written "
                         f"by ebpf/ebpf_monitor.py, and tools.ebpf_events is "
                         f"the only implementation of it.")
    from adapters import LinuxEbpfEvents
    modules["ebpf_events"] = try_load(
        "ebpf_events", lambda: LinuxEbpfEvents(session_id, config))
    if modules["ebpf_events"] is None:
        logger.warning(
            "ebpf_events did not load, so NO KERNEL EVENT IS BEING ANALYSED: "
            "no execution anywhere on this machine is being seen at the moment "
            "it happens, and the five-second process stays invisible. The "
            "process monitor, the event monitor and the local integrity "
            "sensor are different sensors and none of them covers this. "
            "query_ebpf_events reports it as unloaded rather than as a quiet "
            "machine.")
    else:
        _cam = modules["ebpf_events"].status()
        _cam_state = (_cam.get("camera") or {})
        if _cam_state.get("running"):
            logger.info(
                f"[OK] ebpf_events: the camera is recording "
                f"({_cam_state.get('total_events')} event(s), newest "
                f"{_cam_state.get('newest_event_age_seconds')}s old). THIS IS "
                f"THE ONLY SENSOR THAT SEES AN EXECUTION AT THE MOMENT IT "
                f"HAPPENS rather than at the next poll.")
        elif _cam_state.get("has_ever_run"):
            logger.warning(
                "\n" + "=" * 70 +
                "\n[SKIP] ebpf_events: THE CAMERA HAS STOPPED. Its file holds "
                f"{_cam_state.get('total_events')} event(s) but the newest is "
                f"{_cam_state.get('newest_event_age_seconds')}s old.\n"
                "NOTHING IS BEING RECORDED AT THE MOMENT THESE WORDS ARE "
                "WRITTEN, and unlike every polling sensor there is no later "
                "pass that will pick it up: an execution while the camera is "
                "stopped is not seen LATE, it is not seen at all.\n"
                "Restart it with: sudo systemctl start agentalsec-ebpf-camera"
                "\n" + "=" * 70)
        elif _cam_state.get("reachable"):
            logger.warning(
                "[SKIP] ebpf_events: the camera's file exists and is readable "
                "but holds NO EVENTS AT ALL. Either it was started and nothing "
                "has executed since, or it was started and failed before it "
                "attached. See ebpf/ebpf_monitor.py --check.")
        else:
            logger.info(
                "[SKIP] ebpf_events: no kernel camera on this host, so nothing "
                "is recorded at the moment it happens and the five-second "
                "process is invisible. This is the ordinary state on a host "
                "where the camera has not been installed, and it is a stated "
                "limit rather than a fault. Install it with: sudo "
                "scripts/install_ebpf_camera.sh --apply")

    # THE KERNEL AUDIT FEED. L4, 2026-09-22.
    #
    # LOADED UNCONDITIONALLY, INCLUDING ON THIS HOST WHERE AUDITD IS ABSENT.
    # That is the point of the tier rather than an oversight: the answer a
    # reader most needs from this role is the one where the feed does not
    # exist, because an empty findings list has to be readable as "nothing was
    # watching" rather than as "nothing happened". The owner's Q7 instruction
    # for this task was that the module reports "not installed, blind, here is
    # the one command" rather than pretending, and the boot log is where that
    # sentence belongs.
    #
    # It is NOT blind when auditd is simply not installed, and the module says
    # so at length: that is a state of the machine, not a fault in this app,
    # and a permanent blind flag would attach a caveat to every answer forever.
    # The one real blind case is the log existing and being unreadable by this
    # account, which is the DEFAULT on every install, and that is reported.
    role = _sensor_backend(config, "auditd")
    if role != "tools.auditd_monitor":
        raise SystemExit(f"auditd is configured to use {role!r}, which is not "
                         f"a module this tree carries. This role has no "
                         f"Windows counterpart: it reads the Linux kernel's "
                         f"own audit log, and tools.auditd_monitor is the only "
                         f"implementation of it.")
    # Malware scanning with ClamAV, off only when config.json says so.
    if (((config.get("sensors") or {}).get("av_scanner") or {})
            .get("enabled", True)):
        from adapters import LinuxAVScanner
        modules["av_scanner"] = try_load(
            "av_scanner", lambda: LinuxAVScanner(session_id, config))
    else:
        logger.info("av_scanner is switched off in config.json.")
    from adapters import LinuxAuditd
    modules["auditd"] = try_load("auditd",
                                 lambda: LinuxAuditd(session_id, config))
    if modules["auditd"] is None:
        logger.warning(
            "auditd did not load, so NOTHING is reading the kernel audit log: "
            "no reconfiguration of the audit rules and no watched-file hits "
            "will be reported, and query_audit_events reports it as unloaded "
            "rather than as a machine with no audit events.")
    else:
        _audit_state = (modules["auditd"].status().get("auditd") or {})
        _audit = _audit_state.get("state")
        if _audit == "OFF BY CONFIG":
            logger.info(
                "[SKIP] auditd: the audit reader is switched OFF in config "
                "(sensors.auditd.enabled = false), so NOTHING is reading the "
                "kernel audit log. That is an operator's choice and not a "
                f"fault. The machine itself: {_audit_state.get('note')}")
        elif _audit == "READABLE" and _audit_state.get("running"):
            logger.info(
                f"[OK] auditd: the kernel audit feed is being read "
                f"({_audit_state.get('log_path')}, newest record "
                f"{_audit_state.get('newest_record_age_seconds')}s old).")
        elif _audit == "READABLE":
            logger.warning(
                "[SKIP] auditd: the audit log is readable and its newest "
                "record is old, so THE RECORDING MAY HAVE STOPPED. Anything "
                "since that moment is unrecorded, and unlike a polling sensor "
                "there is no later pass that picks it up.")
        elif _audit == "CANNOT READ LOG":
            logger.warning(
                "[SKIP] auditd: the audit log EXISTS and this account cannot "
                "read it, so NOTHING has been examined. Auditd writes it "
                "root-only by default: run elevated (scripts/run_elevated.sh) "
                "to read the kernel feed. An empty findings list from this "
                "run is not a quiet machine.")
        elif _audit == "HALF INSTALLED":
            logger.warning(
                "[SKIP] auditd: the audit CONFIGURATION is on this machine "
                "and the audit TOOLS ARE NOT, so nothing is being recorded "
                "despite the machine looking configured. A daemon start will "
                f"not help. One command: {_audit_state.get('install_command')}")
        elif _audit == "NO LOG YET":
            logger.warning(
                "[SKIP] auditd: the audit tools are installed and there is no "
                "readable log yet, so nothing is being recorded. Restart it "
                "and ask whether it is recording: sudo systemctl restart "
                "auditd, then sudo systemctl status auditd")
        else:
            logger.info(
                "[SKIP] auditd: THE KERNEL AUDIT FEED IS NOT INSTALLED on "
                "this host, so NOTHING at kernel level is recorded: no "
                "syscall records, no file watches, no audit rule changes. "
                "This is a stated limit of the machine rather than a fault, "
                "and an absence of audit findings here means nothing was "
                "watching. One command to change that: "
                f"{_audit_state.get('install_command')}")

    # linux_monitor. One instance per configured host, keyed
    # "linux_monitor:<host>" so the status endpoint, the start loop and
    # tool_registry can all enumerate them.
    targets = _linux_targets(config)
    if not targets:
        logger.info("[SKIP] linux_monitor: no hosts enabled in config")

    for target in targets:
        key = f"linux_monitor:{target['host']}"
        modules[key] = try_load(key, lambda t=target: (
            _cls("tools.linux_monitor").LinuxMonitor(
                session_id,
                host=t["host"],
                user=t["user"],
                key_path=t["key_path"],
                port=t["port"],
                strict_host_key=t["strict_host_key"],
                failed_login_window=t["failed_login_window"],
                failed_login_finding=t["failed_login_finding"],
                failed_login_high=t["failed_login_high"],
                failed_then_success_min=t["failed_then_success_min"],
            )
        ))
        if modules[key] is not None:
            modules[key].label = target["label"]

    modules["vpn_state"] = try_load("vpn_state", lambda: (
        _cls("tools.vpn_state").VPNState(
            extra_patterns=(config.get("vpn") or {}).get("interface_patterns"),
        )
    ))

    modules["port_scanner"] = try_load("port_scanner", lambda: (
        _cls("tools.port_scanner").PortScanner(
            session_id,
            default_port_set=(config.get("port_scan") or {}).get(
                "default_set", "common"),
            # THE OPERATOR'S CONFIG, SO THE SWITCH CAN FIRE.
            #
            # sensors.port_scanner.enabled was documented and read by nothing
            # (register PS-14). The gate lives in the module, but a gate inside
            # the class cannot fire when the only place that builds the class
            # never hands it the config -- measured on the autoruns sensor in
            # the same shape. This line is the half that makes it work.
            config=config,
        )
    ))

    modules["network_scanner"] = try_load("network_scanner", lambda: (
        _cls("tools.network_scanner").NetworkScanner(session_id, config)
    ))

    modules["pcap_analyzer"] = try_load("pcap_analyzer", lambda: (
        _cls("tools.pcap_analyzer").PcapAnalyzer(session_id)
    ))

    # remediation. The Linux module is module-level functions and its
    # signatures do not match what tool_registry dispatches, so it is wrapped
    # rather than used raw. See adapters.py for what each difference is.
    role = _sensor_backend(config, "remediation")
    if role != "tools.remediation_linux":
        raise SystemExit(f"remediation is configured to use {role!r}, which is "
                         f"not a module this tree carries. The Windows "
                         f"remediation module is Windows-only and is NOT in "
                         f"this tree: it is kept outside it, beside the two "
                         f"source folders, as "
                         f"agental_sec_win32_reference/tools/remediation.py.")
    from adapters import LinuxRemediation
    modules["remediation"] = try_load(
        "remediation", lambda: LinuxRemediation(session_id))

    # the router agent. Any router running tools/gateway_agent.sh; what
    # it offers comes from what it reports. Off until config.json's gateway
    # block names a host, and saying so rather than looking blind.
    from adapters import LinuxGateway
    modules["gateway"] = try_load(
        "gateway", lambda: LinuxGateway(session_id, config))
    try:
        from tools import lan_live
        logger.info(f"Live LAN monitor: {lan_live.start(config, session_id)}")
    except Exception as e:
        logger.error(f"Live LAN monitor did not start: {e}")
    try:
        from tools import place_watch
        logger.info(f"Place learning: {place_watch.start(config, session_id)}")
    except Exception as e:
        logger.error(f"Place learning did not start: {e}")

    modules["runbook"] = try_load("runbook", lambda: (
        _cls("tools.runbook").Runbook(session_id)
    ))
    modules["ip_lookup"] = try_load("ip_lookup", lambda: (
        _cls("core.ip_lookup").IPLookup()
    ))
    modules["web_search"] = try_load("web_search", lambda: (
        _cls("core.web_search").WebSearch()
    ))

    # Tier 1 of the research worker. start() spawns one daemon thread that
    # drains the enrichment queue, one job at a time. Loaded after ip_lookup
    # and web_search because it is the same family of question, and before
    # init_registry so both tools are dispatchable on the first turn.
    modules["enrichment"] = try_load("enrichment", lambda: (
        _cls("core.enrichment").Enrichment(session_id)
    ))

    modules["rollup_engine"] = rollup_engine

    tool_registry.init_registry(session_id, modules)

    # THIS PROCESS IS THE APP, so approved root actions may open the root
    # session. Nothing else sets this; see tools/action_broker.LIVE.
    from tools import action_broker
    action_broker.LIVE = True

    for name, mod in modules.items():
        if mod and hasattr(mod, "start"):
            try:
                mod.start()
                logger.info(f"Started: {name}")
            except Exception as e:
                logger.warning(f"Failed to start {name}: {e}")

    return modules


def _linux_targets(config: dict) -> list[dict]:
    """
    Normalize the linux_monitor config block into a list of host dicts.

    Accepts both the multi-host shape and the older single-host one, and
    reads the brute-force defaults OUT OF the module rather than copying the
    numbers here, so the two cannot drift.
    """
    lm = config.get("linux_monitor") or {}
    if not lm.get("enabled"):
        return []

    hosts = lm.get("hosts")
    if not hosts:
        hosts = [{"host": lm["host"]}] if lm.get("host") else []

    def _bf(name, fallback):
        try:
            from tools import linux_monitor
            return int(getattr(linux_monitor, name))
        except Exception:
            return fallback

    normalized, seen = [], set()
    for entry in hosts:
        if not isinstance(entry, dict) or not entry.get("host"):
            continue
        host = entry["host"]
        if host in seen:
            logger.warning(f"linux_monitor: duplicate host {host}, skipping.")
            continue
        seen.add(host)
        normalized.append({
            "label":           entry.get("label") or host,
            "host":            host,
            "user":            entry.get("user", lm.get("user", "")),
            "key_path":        entry.get("key_path", lm.get("key_path", "")),
            "port":            int(entry.get("port", lm.get("port", 22))),
            "strict_host_key": bool(entry.get("strict_host_key",
                                              lm.get("strict_host_key", False))),
            "failed_login_window":     int(entry.get("failed_login_window",
                                           lm.get("failed_login_window",
                                                  _bf("FAILED_LOGIN_WINDOW", 600)))),
            "failed_login_finding":    int(entry.get("failed_login_finding",
                                           lm.get("failed_login_finding",
                                                  _bf("FAILED_LOGIN_FINDING", 5)))),
            "failed_login_high":       int(entry.get("failed_login_high",
                                           lm.get("failed_login_high",
                                                  _bf("FAILED_LOGIN_HIGH", 10)))),
            "failed_then_success_min": int(entry.get("failed_then_success_min",
                                           lm.get("failed_then_success_min",
                                                  _bf("FAILED_THEN_SUCCESS_MIN", 5)))),
        })
    return normalized


def _start_presence_sweeper(config: dict, network_scanner, session_id: str) -> None:
    """
    Sweep on a fixed tick, on a daemon thread, for as long as the app runs.

    The tick is the whole point. A presence record built from sweeps the
    model asked for is not a measurement, because the intervals are then
    chosen by the thing being measured.

    THE CLOCK AND THE SWITCH BOTH COME FROM THE MODULE, 2026-09-24. They used
    to be read here, out of one config block, while the module's own block
    (`sensors.network_scanner.poll_interval`) was read by nothing at all — a
    documented control with no consumer. One question, one reader: the module
    owns the interval and the enabled key and this function asks it.
    """
    from tools import network_scanner as ns

    enabled, which_key = ns.sweep_enabled(config)
    if not enabled:
        logger.info(
            f"[SKIP] presence sweeper: switched OFF in config ({which_key}). "
            f"No sweep will run and no sweep will be recorded, so an empty "
            f"presence answer is the switch rather than a quiet network.")
        return

    interval, interval_key = ns.sweep_interval_seconds(config)

    def loop():
        while True:
            try:
                network_scanner.sweep_presence(session_id)
            except Exception as e:
                logger.error(f"Presence sweep error: {e}")
            time.sleep(interval)

    threading.Thread(target=loop, name="presence-sweeper", daemon=True).start()
    logger.info(f"Presence sweeper started, every {interval // 60} minute(s) "
                f"({interval_key}).")


def _start_port_owner_sweeper(config: dict, session_id: str) -> None:
    """
    Correlate listening ports with the processes that own them, on a tick.

    THE OWNER'S INSTRUCTION, 2026-09-25: "python should execute the scan on set
    intervals and on top of that agent should be able to call python to execute
    a scan whenever it wants to complete a report".

    This function is the FIRST half of that sentence. The second half is
    tools/port_owner.sweep_now, which the duty loop calls before it builds a
    report prompt -- so a wake-up that happens between ticks still reports on a
    picture taken seconds ago rather than one taken up to an interval ago.

    THE CLOCK, THE SWITCH AND THE FLOOR ALL COME FROM THE MODULE. Same argument
    as _start_presence_sweeper above, and the same defect it was written for: a
    second reader of the same config key is a second answer to "how often",
    and the two drift the first time somebody edits one of them.
    tools/port_owner.sweep_interval_seconds also enforces a floor in code, so a
    config cannot ask for a permanently busy /proc walk.

    THE FIRST PASS RUNS IMMEDIATELY, BEFORE ANY SLEEP. A machine that has been
    up for a week has listeners that predate this app, and waiting five minutes
    to record them would mean the first duty tick of the session reports
    "nothing has swept yet". The pass is a seed: it records the state and
    raises NO arrivals (see record_sweep), because a listener that was already
    there is not news.

    IT DOES NOT WAIT FOR THE DUTY LOOP, deliberately. The duty loop can be
    switched off, refused by a budget, or waiting hours for its scheduled
    moment, and none of those are reasons for the port record to stop moving.

    A FAILURE HERE IS LOGGED AND THE THREAD KEEPS GOING. The inner call never
    raises (record_sweep catches its own), and this wrapper catches anyway so a
    bug in the wrapper cannot silently end the only thread that keeps the port
    record current -- a daemon thread that dies quietly is the shape this
    project has fixed three times.
    """
    from tools import port_owner

    enabled, which_key = port_owner.sweep_enabled(config)
    if not enabled:
        logger.info(
            f"[SKIP] port_owner sweeper: switched OFF in config ({which_key}). "
            f"No port will be correlated with a process and no sweep will be "
            f"recorded, so an empty listener answer is this switch rather than "
            f"a machine with nothing listening.")
        return

    interval, interval_key = port_owner.sweep_interval_seconds(config)

    def loop():
        first = True
        while True:
            try:
                result = port_owner.sweep_now(
                    session_id,
                    reason="startup seed" if first else "interval")
                if not result.get("ran"):
                    logger.warning(
                        f"Port ownership sweep did not run: "
                        f"{result.get('reason')}")
            except Exception as e:                           # noqa: BLE001
                logger.error(f"Port ownership sweep error: {e}")
            # Raw and packet sockets listen with no port; a staged holder
            # raises LNX-5001.
            try:
                from tools import socket_census
                socket_census.check_hidden(session_id)
            except Exception as e:                           # noqa: BLE001
                logger.error(f"Portless listener check error: {e}")
            first = False
            time.sleep(interval)

    threading.Thread(target=loop, name="port-owner-sweeper",
                     daemon=True).start()
    logger.info(f"Port ownership sweeper started, every {interval} second(s) "
                f"({interval_key}). First pass runs now and seeds the record "
                f"without reporting arrivals.")


def _start_port_scanner_clock(config: dict, modules: dict,
                              session_id: str) -> None:
    """
    The port scanner's background clock, on a daemon thread, for as long as
    the app runs.

    THE OWNER'S INSTRUCTION, 2026-09-25, in the owner's own words: "I want you to
    create that back ground clock". That is PS-14's option (a), which the
    register carried as PENDING THE OWNER'S WORD while the module ran pull-only and
    the switch refused the call; the switch and the refusal both stay, and
    OFF stops this clock too.

    WHAT IT DOES: every `sensors.port_scanner.poll_interval` seconds it runs
    the SHIPPED PortScanner.scan() against 127.0.0.1 -- the same call the
    Scan Host button and the model make -- so the port record keeps moving
    between the moments somebody happens to ask. The pass costs 0.54 s wall
    and writes 3 rows in port_scan_results plus 1 run row (measured on this
    host, 2026-09-25).

    THE CLOCK, THE SWITCH AND THE FLOOR ALL COME FROM THE MODULE. Same
    argument as _start_presence_sweeper and _start_port_owner_sweeper above:
    a second reader of the same config key is a second answer to "how often",
    and the two drift the first time somebody edits one of them. The module
    owns clock_interval_seconds() (which enforces the floor in code) and
    scan_enabled(), and this function asks it.

    THE FIRST PASS RUNS IMMEDIATELY, BEFORE ANY SLEEP, when the record shows
    no self-scan inside the window -- on a fresh install that is the first
    thing that ever looks at the machine, and waiting out an interval would
    mean the Ports tab sits on "No port scan results yet." for ten minutes.

    A PASS SOMEBODY ELSE TOOK POSTPONES THIS ONE. The due check reads when
    this host was last self-scanned out of the run table, so a Scan Host
    click or a model scan inside the window is not immediately duplicated --
    and a restart inside the window does not double-scan either, which is the
    property a process-owned counter cannot have.

    IT DOES NOT WAIT FOR THE DUTY LOOP. The duty loop can be switched off,
    refused by a budget, or hours away from its scheduled moment, and none of
    those are reasons for the port record to stop moving.

    A FAILURE HERE IS LOGGED AND THE THREAD KEEPS GOING. The tick never
    raises (it catches its own and counts it), and this wrapper catches
    anyway, so a bug in the wrapper cannot silently end the only thread that
    keeps the port record current -- a daemon thread that dies quietly is the
    shape this project has fixed three times.
    """
    scanner = modules.get("port_scanner")
    if scanner is None:
        logger.warning(
            "[SKIP] port scanner clock: the module did not load, so NOTHING "
            "runs a self-scan on a timer. A port record that stops moving is "
            "this, not a machine whose ports stopped changing.")
        return
    if not hasattr(scanner, "clock_tick"):
        logger.warning(
            "[SKIP] port scanner clock: the loaded module has no clock_tick, "
            "so this tree and its module disagree. Nothing will scan on a "
            "timer.")
        return

    from tools import port_scanner as ps
    enabled, which_key = ps.scan_enabled(config)
    if not enabled:
        logger.info(
            f"[SKIP] port scanner clock: switched OFF in config ({which_key}). "
            f"No self-scan will run and no row will be written, so an empty "
            f"port answer is this switch rather than a machine with nothing "
            f"exposed.")
        return

    interval, interval_key = ps.clock_interval_seconds(config)
    # The loop's RESOLUTION of the due check, not the cadence: a restart must
    # not push a due pass a whole ten minutes away, and a wake that decides
    # not to scan costs one SQL read.
    wake = min(interval, ps.CLOCK_WAKE_SECONDS)
    ps.set_clock_running(True, interval=interval, interval_key=interval_key)

    def loop():
        first = True
        while True:
            try:
                last = ps.last_self_scan_at(ps.SELF_SCAN_TARGET)
                due, waited = ps.clock_due(last, interval)
                if due:
                    scanner.clock_tick(
                        session_id,
                        reason=("startup" if first and waited is None
                                else "interval"))
            except Exception as e:                           # noqa: BLE001
                logger.error(f"Port scanner clock error: {e}")
            first = False
            time.sleep(wake)

    threading.Thread(target=loop, name="port-scanner-clock",
                     daemon=True).start()
    logger.info(
        f"Port scanner clock started: a self-scan of {ps.SELF_SCAN_TARGET} "
        f"every {interval} second(s) ({interval_key}), checked every {wake}s. "
        f"The first pass runs now if the record shows no recent one, and a "
        f"pass taken by anything else postpones the next.")


_dns_tracker = None


def _start_dns_importer(config: dict, dns_monitor, session_id: str) -> None:
    """
    Import from the resolver now, then on a timer, on a daemon thread.

    TODO 113.3, PORTED 2026-09-21: after each import pass that actually ran
    and finished the current batch, dns_inspector.analyse_once runs.
    Inspection runs after import so that the rows being analysed are already
    committed. When import says more_available (more rows waiting), we loop
    immediately to catch up first and inspect once the backlog is clear.

    THE CATCH-UP IS CAPPED, 2026-09-20. The backlog branch below used to
    `continue` with no sleep and no limit, so if more_available ever stuck on
    (an importer bug, a resolver writing faster than we read) this thread
    became a hot loop with a core pinned to it and no log line saying so.
    Twenty passes is a large backlog by any measure; past that it waits for
    the next interval and says what it is doing.

    SESSION_ID IS A PARAMETER AGAIN, 2026-09-26. The port dropped it from the
    signature while the loop body kept calling
    `dns_inspector.analyse_once(config, session_id)` -- so the call raised
    NameError on every pass, the except below logged it, and the SECOND HALF
    OF THIS SENSOR had never run on this host at all. MEASURED by extracting
    this function and running it: the log line reads
    "DNS inspection error: name 'session_id' is not defined" once per pass,
    and analyse_once is never reached. The Windows twin passes the value; the
    port dropped it.
    """
    from tools import dns_inspector

    from core.sensor_watch import LoopTracker

    block = config.get("dns_monitor", {}) or {}
    interval = max(1, int(block.get("interval_minutes", 15))) * 60
    MAX_CATCHUP_PASSES = 20

    def idle():
        st = dns_monitor.status(config)
        return None if st["available"] else st["reason"]

    global _dns_tracker
    _dns_tracker = live = LoopTracker(interval, idle=idle)

    def loop():
        catchup = 0
        waiting_said = False
        while True:
            try:
                # Waiting for a router or a resolver file is not a failure.
                why = idle()
                if why:
                    if not waiting_said:
                        logger.info(f"DNS importer: {why}.")
                        waiting_said = True
                    time.sleep(interval)
                    continue
                waiting_said = False
                result = dns_monitor.import_once(config)
                if result.get("ran"):
                    live.ok()
                else:
                    live.failed(result.get("reason"))
                if result.get("ran") and result.get("more_available"):
                    catchup += 1
                    if catchup < MAX_CATCHUP_PASSES:
                        # Backlog: catch up before inspecting.
                        continue
                    logger.warning(
                        f"DNS import still reports a backlog after "
                        f"{catchup} passes. Waiting for the next interval "
                        f"rather than spinning. Inspecting what is in so far.")
                catchup = 0
                if not result.get("ran"):
                    logger.warning(f"DNS import skipped: {result.get('reason')}")
                else:
                    # Batch complete, inspect the new rows now.
                    try:
                        ins = dns_inspector.analyse_once(config, session_id)
                        if not ins.get("ran"):
                            logger.warning(
                                f"DNS inspection skipped: {ins.get('reason')}")
                        elif ins.get("dga_findings") or ins.get("beacon_findings"):
                            logger.info(
                                f"DNS inspection: DGA={ins['dga_findings']}, "
                                f"beacon={ins['beacon_findings']}")
                    except Exception as ie:
                        logger.error(f"DNS inspection error: {ie}")
            except Exception as e:
                live.failed(e)
                logger.error(f"DNS import error: {e}")
            time.sleep(interval)

    t = threading.Thread(target=loop, name="dns-importer", daemon=True)
    t.start()
    live.begin(t)
    logger.info(f"DNS importer started, every {interval // 60} minute(s).")


def _firefox_profile_name(home=None):
    """
    The profile name Firefox itself would start, so the launch can NAME it.

    ,,,, WHY THIS EXISTS, AND IT IS NOT A NICETY. 2026-09-18 ,,,,

    On this machine a COLD `firefox <url>` — which is exactly the command
    line webbrowser.open() builds — does not open the URL. It opens
    Firefox's "Choose a profile" dialog. profiles.ini here has TWO sections
    claiming to be the default:

        [Install4F96D1932A9F858E]  Default=uPgFEPGY.Profile 1   Locked=1
        [Profile1]                 Name=default  Path=fnkih2cv.default  Default=1
        [Profile0]                 Name=default-release  Path=uPgFEPGY.Profile 1
                                   ShowSelector=1

    Firefox resolves that ambiguity by asking a human, and a human answering
    a profile dialog is not a dashboard.

    Measured 2026-09-18, cold, window titles read back with wmctrl:

        firefox    http://127.0.0.1:5000 -> "Firefox - Choose a profile"
        firefox -P default-release ...   -> "AgentalSec — <profile> — Mozilla Firefox"

    and the app logged "Opened http://127.0.0.1:5000 in your browser" for
    BOTH, because webbrowser.open() only reports that fork+exec succeeded.
    That is why seven boots of logs looked like a working browser launch.

    `home` is passed explicitly because an ELEVATED run has HOME=$HOME of
    the real user but a process environment that could say anything; the
    caller knows which home it means, so it says so.

    The name is READ rather than hardcoded: the profile belongs to the
    owner, and a name baked into this file would be wrong the first time the owner
    adds one or renames one. Returns None if it cannot be resolved, and the
    caller then falls back to the old behaviour and SAYS it did.
    """
    try:
        import configparser
        base = Path(home) if home else Path.home()
        ini = base / ".config" / "mozilla" / "firefox" / "profiles.ini"
        if not ini.is_file():
            return None
        cp = configparser.ConfigParser()
        cp.read(ini)
    except Exception:
        return None

    profiles, install_default, marked_default = {}, None, None
    for section in cp.sections():
        keys = cp[section]
        if section.lower().startswith("install"):
            # The install section names its default by PATH, not by name.
            install_default = keys.get("default") or install_default
            continue
        name, path = keys.get("name"), keys.get("path")
        if not name or not path:
            continue
        profiles[path] = name
        if keys.get("default") == "1" and marked_default is None:
            marked_default = name

    if install_default and install_default in profiles:
        return profiles[install_default]
    return marked_default


def _real_user_account():
    """
    (user, home, group, uid) for the human who started this, or None.

    None when we are NOT root (nothing to drop from) or when there is no
    believable human: SUDO_USER unset, or set to root itself, as happens for
    a run out of a root shell where there is no original user to borrow.
    """
    if os.geteuid() != 0:
        return None
    user = os.environ.get("SUDO_USER") or ""
    if not user or user == "root":
        return None
    try:
        import grp
        import pwd
        pw = pwd.getpwnam(user)
    except Exception:
        return None
    try:
        group = grp.getgrgid(pw.pw_gid).gr_name
    except Exception:
        group = str(pw.pw_gid)
    return (user, pw.pw_dir, group, pw.pw_uid)


def _x_display():
    """The DISPLAY this desktop is on, from the environment or from X itself."""
    display = os.environ.get("DISPLAY")
    if display:
        return display
    # sudo's env_reset does not keep DISPLAY on every configuration. Guessing
    # ":0" would be a guess; /tmp/.X11-unix/X0 is the socket actually being
    # listened on, so read the number off the socket that exists.
    try:
        socks = sorted(p.name for p in Path("/tmp/.X11-unix").glob("X*")
                       if p.name[1:].isdigit())
        if socks:
            return ":" + socks[0][1:]
    except Exception:
        pass
    return None


def _user_session_env(uid: int) -> dict:
    """The parts of a user's desktop session sudo strips and Firefox needs.

    Without the session bus and runtime directory a second Firefox cannot
    hand its URL to the one already open, and shows "Firefox is already
    running" instead. Measured 2026-10-01 with a throwaway profile: stripped
    environment, still on that box after 6 s; with these two, exit 0 at once.
    """
    out = {}
    runtime = f"/run/user/{uid}"
    if not os.path.isdir(runtime):
        return out
    out["XDG_RUNTIME_DIR"] = runtime
    bus = os.path.join(runtime, "bus")
    if os.path.exists(bus):
        out["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    try:
        sockets = sorted(n for n in os.listdir(runtime)
                         if n.startswith("wayland-") and not n.endswith(".lock"))
    except OSError:
        sockets = []
    if sockets:
        out["WAYLAND_DISPLAY"] = sockets[0]
    return out


def _user_has_firefox(uid: int) -> bool:
    """Is a Firefox already open for this user? Read from /proc."""
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                if os.stat(f"/proc/{pid}").st_uid != uid:
                    continue
                with open(f"/proc/{pid}/comm") as f:
                    if f.read().strip() in ("firefox", "firefox-bin"):
                        return True
            except OSError:
                continue
    except OSError:
        pass
    return False


def _browser_launch_plans(url):
    """
    Every honest way to put `url` on screen here, best first.

    A PLAN is (argv, env, who) where `who` is what the log will call it. The
    list is a fallback chain on purpose: each step is attempted and its
    outcome checked, because "I ran a command" and "a browser appeared" are
    different statements and this function exists because the code used to
    conflate them.

    ,,,, WHY DROPPING OUT OF ROOT IS THE FIRST CHOICE, NOT A FALLBACK ,,,,

    A browser started as root writes into ~/.config/mozilla — lock files,
    caches, session state — and leaves them owned by root. The next
    unelevated Firefox then meets files it cannot write and fails in ways
    that look like something else. This project has already been bitten by
    exactly that shape once: a root-owned log file silently disabled logging
    for every later run. A browser is also the most exposed program on a
    desktop and the last one that should hold uid 0.

    So: as the user if that is possible, as root only if it is not, and the
    log always says which one happened.
    """
    import shutil

    firefox = shutil.which("firefox")
    if not firefox:
        return []

    account = _real_user_account()
    home = account[1] if account else None
    profile = _firefox_profile_name(home)
    if profile:
        argv = [firefox, "-P", profile, url]
        described = f"Firefox, profile '{profile}'"
    else:
        # Name it plainly rather than pretending this is the good path.
        argv = [firefox, url]
        described = ("Firefox, default profile unknown, it may open its "
                     "profile chooser instead of the dashboard")

    env = os.environ.copy()
    display = _x_display()
    if display:
        env["DISPLAY"] = display

    if account:
        user, home, group, _uid = account
        env["HOME"] = home
        env["USER"] = user
        env["LOGNAME"] = user
        # env_reset does not keep XAUTHORITY and without it the X server
        # refuses the connection outright. The file lives in the home we
        # just set, so look there.
        xauth = os.path.join(home, ".Xauthority")
        if os.path.exists(xauth):
            env["XAUTHORITY"] = xauth
        env.update(_user_session_env(_uid))

        plans = []
        if shutil.which("setpriv"):
            # Two setpriv spellings, because --init-groups is the part that
            # can fail. Measured 2026-09-18 inside a uid-0 namespace:
            #     setpriv --reuid=<user> --regid=<user> --init-groups <cmd>
            #         -> "setpriv: setresuid failed: Invalid argument" /
            #            "initgroups failed: Operation not permitted"
            # while the same call WITHOUT --init-groups gets further. The
            # arguments parse (the error is operational, not a usage error),
            # so as real root the first one should work; --clear-groups is
            # the spelling that needs less privilege and still does not
            # leave root's supplementary groups on a browser process.
            plans.append((["setpriv", f"--reuid={user}", f"--regid={group}",
                           "--init-groups"] + argv, env,
                          f"{described}, dropped to {user}"))
            plans.append((["setpriv", f"--reuid={user}", f"--regid={group}",
                           "--clear-groups"] + argv, env,
                          f"{described}, dropped to {user} (groups cleared)"))
        if shutil.which("runuser"):
            plans.append((["runuser", "-u", user, "--"] + argv, env,
                          f"{described}, dropped to {user}"))
        # Last resort and marked as such: the wrong-owner files are a smaller
        # harm than a dashboard that never appears.
        plans.append((argv, env, f"{described}, but STILL AS ROOT, no way "
                                 f"to drop to {user} worked"))
        return plans

    # Not root: nothing to drop from and nothing to warn about. The phrasing
    # is deliberately different from the branch above, because "as root" in a
    # log line from an unelevated run would send the reader looking for a
    # privilege problem that is not there.
    who = f"{described}, running as {os.environ.get('USER') or 'the current user'}"
    if os.geteuid() == 0:
        who = f"{described}, as root (no original user to drop to)"
    return [(argv, env, who)]


def _launch_browser(url: str) -> None:
    """
    Open the dashboard and log what ACTUALLY happened.

    The log line this replaces said "Opened <url> in your browser" whenever
    webbrowser.open() returned True, which only means a process was forked.
    Firefox was forked onto a profile dialog seven times in a row and the
    log said the browser opened every time. So this now says which command
    ran and as whom, and when it cannot do the good thing it says that too.
    """
    import subprocess
    import webbrowser

    plans = _browser_launch_plans(url)
    account = _real_user_account()
    uid = account[3] if account else os.getuid()
    already_open = _user_has_firefox(uid)
    if not plans:
        try:
            if webbrowser.open(url):
                logger.info(f"Opened {url} (via the desktop's default browser).")
            else:
                logger.info(f"Could not open a browser automatically. Go to {url}")
        except Exception as e:
            logger.info(f"Could not open a browser ({e}). Go to {url}")
        return

    last_who = None
    for argv, env, who in plans:
        last_who = who
        try:
            proc = subprocess.Popen(argv, env=env, close_fds=True,
                                    start_new_session=True,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning(f"Could not run {argv[0]}: {e}")
            continue

        # A launch that dies immediately (setpriv refusing the groups, an X
        # connection refused) is indistinguishable from success unless the
        # exit is actually read. Firefox that finds a running instance also
        # exits at once — but it exits ZERO. Anything non-zero this fast
        # means the launch did not work and the next plan should be tried.
        try:
            if proc.wait(timeout=4) == 0:
                logger.info(f"Opened {url}, {who}.")
                return
            logger.warning(
                f"{who}: exited {proc.returncode} immediately, trying the "
                f"next way to open a browser.")
        except subprocess.TimeoutExpired:
            # With a Firefox already open, a working hand-off exits at once.
            # Still running means it is most likely showing "Firefox is
            # already running", so that is said rather than "Opened".
            if already_open:
                logger.warning(
                    f"{who}: a Firefox was already open and this one did not "
                    f"hand the URL to it within 4 s, so it is probably "
                    f"showing 'Firefox is already running'. Open {url} in "
                    f"the open Firefox.")
            else:
                logger.info(f"Opened {url}, {who}.")
            return

    logger.warning(
        f"No way to open a browser worked (last tried: {last_who}). "
        f"Open {url} yourself.")


def _open_browser_when_ready(host: str, port: int) -> None:
    """
    Open the dashboard once it actually answers, not after a fixed sleep.

    The Windows version sleeps 1.5s and calls webbrowser.open. That is fine
    there because its boot is quick, but this boot loads migrations, runs the
    module table and starts eight sensors first, and a browser opened at 1.5s
    on a slower start lands on a refused connection. So this polls the port
    until something is listening, then opens. Bounded, because a monitor that
    silently retries forever is worse than one that says it gave up.
    """
    import socket

    deadline = time.time() + 30.0
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                break
        except OSError:
            time.sleep(0.5)
    else:
        logger.warning(
            f"Dashboard did not answer on {host}:{port} within 30 seconds, so "
            f"no browser was opened. It may still be starting. Open "
            f"http://{host}:{port} yourself to check.")
        return

    _launch_browser(f"http://{host}:{port}")


def _socket_inodes_for_port(port: int) -> list:
    """
    The socket inode(s) listening on `port`, from /proc/net/tcp.

    WHY THIS EXISTS ALONGSIDE `ss`. `ss` is the better tool when it works —
    it is one process instead of a walk of /proc — but it is not on every
    install, and the refusal that names a pid is worth having regardless.
    /proc/net/tcp needs no privilege and /proc/<pid>/fd is readable for your
    own processes, so this pair is the fallback that keeps the message
    specific when iproute2 is absent.

    IT DOES NOT DEFEAT A USER NAMESPACE, and nothing does: a process in a
    child user namespace is refused ptrace access to a parent-namespace
    process, so /proc/<pid>/cwd and /proc/<pid>/fd both answer EACCES and the
    holder cannot be named from inside one. That is a property of the kernel,
    measured while proving this refusal — and it is why the elevated half is
    tested with the REAL root path as well, not only under `unshare -r`.
    """
    inodes = []
    try:
        with open("/proc/net/tcp", encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local, state = parts[1], parts[3]
                if state != "0A":                     # 0A = LISTEN
                    continue
                try:
                    if int(local.rsplit(":", 1)[1], 16) != int(port):
                        continue
                except (IndexError, ValueError):
                    continue
                inodes.append(parts[9])
    except OSError:
        pass
    return inodes


def _pid_for_inodes(inodes: list) -> int:
    """Which process holds one of these socket inodes. Best effort."""
    if not inodes:
        return 0
    wanted = {f"socket:[{i}]" for i in inodes}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return 0
    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            entries = os.listdir(fd_dir)
        except OSError:
            continue                              # another user's process
        for fd in entries:
            try:
                if os.readlink(f"{fd_dir}/{fd}") in wanted:
                    return int(pid)
            except OSError:
                continue
    return 0


def _port_holder(host: str, port: int) -> dict:
    """
    Who, if anyone, is listening on host:port.

    Returns {"taken": bool, "pid": int|None, "comm": str|None, "ours": bool}.

    WHY A CONNECT AND NOT A BIND TEST. A bind test answers whether THIS
    process could take the port, which depends on flags and privilege; a
    connect answers whether something is already there, which is the question
    a person has when a launcher says the port is in use. `ours` is set when
    the holder's working directory is this project, which is what turns a
    generic collision into the sentence the operator actually needs:
    "AgentalSec is already running".

    Best effort by design: if the holder cannot be named at all, the answer
    is still "taken" with the holder unnamed. It never raises, because a
    diagnostic that breaks the refusal is worse than no diagnostic.
    """
    import re
    import socket
    import subprocess

    out = {"taken": False, "pid": None, "comm": None, "ours": False}

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.75)
    try:
        probe.connect((host, port))
        out["taken"] = True
    except OSError:
        # Refused, unreachable, or an address family this probe does not
        # speak (an IPv6 host). "Not taken" here is provisional: the bind
        # below is the authoritative check and it will raise if it disagrees.
        return out
    finally:
        probe.close()

    try:
        res = subprocess.run(["ss", "-H", "-ltnp", f"sport = :{port}"],
                             capture_output=True, text=True, timeout=5,
                             stdin=subprocess.DEVNULL)
        match = re.search(r"pid=(\d+)", res.stdout or "")
        if match:
            out["pid"] = int(match.group(1))
    except Exception:
        pass

    if not out["pid"]:
        out["pid"] = _pid_for_inodes(_socket_inodes_for_port(port)) or None

    if out["pid"]:
        try:
            out["comm"] = Path(f"/proc/{out['pid']}/comm").read_text().strip()
        except OSError:
            pass
        try:
            if os.readlink(f"/proc/{out['pid']}/cwd") == str(PROJECT_ROOT):
                out["ours"] = True
        except OSError:
            pass
    return out


def _bind_listener(host: str, port: int):
    """
    Bind and listen on host:port, and hand the socket back.

    THIS IS WHAT MAKES "AgentalSec ready." A FACT RATHER THAN A HOPE. Fixed
    2026-09-18: the readiness line used to be logged and THEN waitress did its
    own bind, so a taken port produced a boot that ran to its last line,
    announced itself ready, and died with

        OSError: [Errno 98] Address already in use

    as a bare traceback — which the launcher reports, correctly, as "exited
    with code 1". Taking the port first means the failure happens where it can
    be caught, named and recorded, and the readiness line comes after it.

    Raises OSError on any failure, having closed the socket it opened.
    """
    import socket

    family, socktype, proto, _, sockaddr = socket.getaddrinfo(
        host, port, 0, socket.SOCK_STREAM)[0]
    listener = socket.socket(family, socktype, proto)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(sockaddr)
        listener.listen(1024)
    except OSError:
        listener.close()
        raise
    return listener


def _refuse_busy_port(host: str, port: int, held: dict, reason=None) -> int:
    """
    The named refusal a taken port deserves. Returns 1, for the caller to
    return.

    Printed with logger.error, which reaches BOTH the log file and the
    terminal the launcher keeps open on failure — so the window says why,
    instead of showing a Python stack trace and "exited with code 1".
    """
    who = held.get("comm") or "a process this user cannot identify"
    if held.get("pid"):
        who = f"{who}, pid {held['pid']}"

    if not held.get("taken"):
        logger.error("Could not start the dashboard on %s:%s: %s",
                     host, port, reason or "unknown reason")
        logger.error("Nothing else is listening on that address, so this is "
                     "NOT a collision. Common causes: a port below 1024 "
                     "without privilege, or a host name this machine does "
                     "not hold.")
        return 1

    if held.get("ours"):
        logger.error("AgentalSec is ALREADY RUNNING on http://%s:%s (%s).",
                     host, port, who)
        logger.error("Nothing was started: a second copy would fight the "
                     "first one for the database and for the dashboard.")
        logger.error("Use the copy that is running, its dashboard has a "
                     "Stop button, or change flask.port in config.json, "
                     "then start again.")
    else:
        logger.error("Port %s on %s is ALREADY IN USE by %s.", port, host, who)
        logger.error("Nothing was started. Stop whatever holds that port, or "
                     "change flask.port in config.json, then start again.")
    return 1


# Arguments are parsed before config, secrets or the database are touched,
# and an unknown argument is refused rather than read as "start". --check is
# read-only apart from its own log lines.

def _parse_args(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=("AgentalSec Linux. With no arguments, starts the "
                     "monitor, its sensors and the dashboard."))
    parser.add_argument(
        "--check", action="store_true",
        help=("report dependencies, privileges and whether config.json and "
              ".env are readable, then exit. Starts nothing, reads no "
              "secrets, opens no database, and writes nothing but its own "
              "lines to the log."))
    return parser.parse_args(argv)


def _launcher_hint():
    """
    A sentence telling the user how to install the launchers, or None when
    they are installed for this project folder (or in a container).
    """
    if os.environ.get("AGENTAL_IN_CONTAINER"):
        return None
    home = Path.home()
    user = os.environ.get("SUDO_USER") or os.environ.get("PKEXEC_UID")
    if os.geteuid() == 0 and user:
        try:
            import pwd
            entry = pwd.getpwuid(int(user)) if user.isdigit() else pwd.getpwnam(user)
            home = Path(entry.pw_dir)
        except (KeyError, ValueError):
            pass
    entry_file = home / ".local/share/applications/agentalsec.desktop"
    script = PROJECT_ROOT.resolve() / "scripts" / "install_launchers.sh"
    if not entry_file.exists():
        return ("The AgentalSec launchers are not installed yet. Run this once, "
                f"as your own user, not root: {script}  It adds AgentalSec and "
                "AgentalSec (privileged) to your app menu, your desktop and this "
                "folder.")
    try:
        points_here = str(PROJECT_ROOT.resolve()) in entry_file.read_text(encoding="utf-8")
    except OSError:
        points_here = True
    if not points_here:
        return ("The AgentalSec launchers point at a different folder, so they "
                f"would not start this copy. Run this once to update them: {script}")
    return None


def _run_check() -> int:
    """The --check path. Read-only by construction; see the block above."""
    ok = _check_dependencies()
    _report_privileges()

    hint = _launcher_hint()
    if hint:
        logger.warning(hint)
    elif not os.environ.get("AGENTAL_IN_CONTAINER"):
        logger.info("Launchers are installed for this folder.")

    if not CONFIG_PATH.exists():
        logger.warning(f"{CONFIG_PATH} does not exist. A normal start will "
                       f"create it from config.linux.example.json.")
    else:
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                json.load(f)
            logger.info(f"{CONFIG_PATH} parses.")
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"{CONFIG_PATH} could not be read: {e}")
            ok = False

    # Presence only. The file holds the secrets and --check does not read them.
    logger.info(f"{ENV_PATH} {'exists' if ENV_PATH.exists() else 'does NOT exist'}"
                f" (not read: --check never opens the secrets).")

    logger.info("Check complete: %s. Nothing was started.",
                "OK" if ok else "PROBLEMS FOUND, see above")
    return 0 if ok else 1


def main(argv=None):
    """Main entry point."""
    args = _parse_args(argv)
    if args.check:
        return _run_check()

    logger.info("=" * 70)
    logger.info(f"AgentalSec Linux starting. PID {os.getpid()}")
    logger.info("=" * 70)
    logger.info(f"Project root: {PROJECT_ROOT}")
    logger.info(f"Python {sys.version}")
    logger.info(f"Platform: {sys.platform}")
    if not LOG_FILE_ACTIVE:
        logger.warning("Running WITHOUT a durable log file. See the error above.")
    logger.info("")

    if not _check_dependencies():
        logger.error("Cannot start - missing critical dependencies")
        return 1

    # Before any module loads, so the reason a sensor is about to be missing
    # appears above the missing sensor rather than below it.
    _report_privileges()

    config = _load_config()

    # Secrets, from .env. This also mints an app API key if none exists, and
    # migrates anything still sitting in config.json out of it.
    from core import secret_store
    resolved = secret_store.resolve(config, PROJECT_ROOT)
    if not resolved["api_key"]:
        _env = PROJECT_ROOT / ".env"
        # Name the file that exists: a fresh install has no .env yet.
        logger.error(
            "No model API key. %s The analyst cannot answer without it, and "
            "the dashboard will show the model as unavailable until it is "
            "set. Everything else runs.",
            (f"Add AGENTAL_API_KEY to {_env}."
             if _env.exists() else
             f"There is no .env yet: copy .env.example to .env and add "
             f"AGENTAL_API_KEY, or set it on the Settings tab "
             f"({PROJECT_ROOT / '.env.example'})."))
    if resolved["legacy"]:
        logger.warning(f"Read from config.json (move these to .env): "
                       f"{', '.join(resolved['legacy'])}")

    session_id = str(uuid.uuid4())
    logger.info(f"Session ID: {session_id}")

    if not _initialize_database():
        logger.error("Cannot start - database initialization failed")
        return 1

    from core import memory_engine as me

    # Record what the policy is before anything runs under it.
    try:
        from core import integrity
        integrity.snapshot_config(reason="boot")
    except Exception as e:
        logger.error(f"Could not snapshot config at boot: {e}")

    # RETENTION. Boot reports, it never deletes: the sensors are about to
    # start writing and a VACUUM on a large file would hold the boot for
    # minutes. It asks once, on a terminal, and waits.
    try:
        from core import retention
        retention.first_run_prompt(me.DB_PATH)
        retention.boot_report(me.DB_PATH, log=logger,
                              current_session_id=session_id)
    except Exception as e:
        logger.error(f"Could not read retention state at boot: {e}")

    # Agent reports older than a week are deleted at boot, so a stopped app
    # does not keep them past the window.
    try:
        from core import duty as _duty_reports
        _duty_reports.expire_old_reports()
    except Exception as e:
        logger.error(f"Could not expire old agent reports at boot: {e}")

    # TODO 113.6, PORTED 2026-09-21. PAYLOAD RETENTION AT BOOT, and the reason
    # it is here as well as at shutdown is that a crash or a kill leaves no
    # shutdown at all, so old payload would sit there until the next clean
    # stop. It is an indexed DELETE on a table that is small by design, so
    # unlike the size-based retention above it costs nothing at boot.
    try:
        from tools import payload_ring
        pr_result = payload_ring.prune()
        if not pr_result.get("ran"):
            logger.warning(f"Payload prune did not run: "
                           f"{pr_result.get('reason')}. Captured payload is "
                           f"NOT being aged out.")
        elif pr_result.get("deleted"):
            logger.info(f"Payload prune at boot: {pr_result['deleted']} row(s) "
                        f"older than {pr_result.get('retention_days')} day(s).")
    except Exception as e:
        logger.error(f"Payload prune failed at boot: {e}")

    # The hardware vendor registry, said out loud at boot.
    #
    # THREE STATES, AND THE BRANCH ORDER IS THE FIX, 2026-09-21. `ready` now
    # means every prefix length is loaded, so testing `ready` first and
    # treating everything else as empty made a PARTIAL registry print "NO data
    # files" -- measured on this host, mas.csv absent, mam.csv and oui.csv
    # loaded, and the boot line said nothing was there while 46,804 prefixes
    # were answering questions. An operator who reads "NO data files" goes and
    # fetches what the owner already has; the honest line names the file that is
    # actually missing.
    try:
        from core import oui
        oui_state = oui.status()
        if not oui_state["loaded_lengths"]:
            logger.warning("Hardware vendor registry: NO data files. Device "
                           "makers will read as no_data until you run "
                           "scripts/update_oui.py.")
        elif oui_state["missing"]:
            logger.warning(
                f"Hardware vendor registry: PARTIAL, "
                f"{', '.join(oui_state['missing'])} missing. "
                f"{oui_state['prefixes']:,} prefixes loaded, but 28 and 36 bit "
                f"addresses are answered from their 24 bit parent until you "
                f"run scripts/update_oui.py. On the shipped data that parent "
                f"is usually the registering authority, not the maker.")
        else:
            logger.info(f"Hardware vendor registry: {oui_state['prefixes']:,} "
                        f"prefixes from {', '.join(oui_state['files'])}.")
    except Exception as e:
        logger.error(f"Could not read the hardware vendor registry: {e}")

    # Vantage point, before any collector runs, so every row written this
    # session can be stamped with where it was observed from.
    try:
        from core import sensors
        sensor_id = sensors.register_local(config)
        position = sensors.local_position(config)
        logger.info(f"Sensor {sensor_id} at position '{position}'.")
        if position == "host":
            logger.info(
                "Position 'host' means this instance cannot observe traffic "
                "between other devices, or from another device to the "
                "internet. It sees this host's own traffic plus broadcast "
                "and multicast, and nothing else.")
    except Exception as e:
        logger.error(f"Could not register this sensor: {e}")

    # DNS ingestion. On by default; it waits, without failing, until the
    # router agent is enrolled or a resolver file is set.
    try:
        from tools import dns_monitor
        dns_state = dns_monitor.status(config)
        if (config.get("dns_monitor") or {}).get("enabled"):
            _start_dns_importer(config, dns_monitor, session_id)
        if not dns_state["available"]:
            logger.info(f"DNS ingestion not reading: {dns_state['reason']}. "
                        f"This is the only sensor that covers devices this "
                        f"host cannot see.")
    except Exception as e:
        logger.error(f"Could not start DNS ingestion: {e}")

    # The router's own tables. Off unless an address and a read community
    # are both configured.
    try:
        from tools import router_monitor
        router_state = router_monitor.status(config)
        if router_state["available"]:
            router_monitor.ensure_collector(config, session_id)
        else:
            logger.info(f"Router collection off: {router_state['reason']}.")
    except Exception as e:
        logger.error(f"Could not start router collection: {e}")

    # the model. WITHOUT THIS CHAT CANNOT WORK AT ALL.
    from core import agent_loop
    agent_loop.init_agent(config,
                          api_key=resolved["api_key"])

    from core import geoip
    geo_status = geoip.init_geoip(config, PROJECT_ROOT)
    from core import home_location
    home_location.refresh_async(config)
    if not geo_status["ready"]:
        logger.info(f"[SKIP] geoip: {geo_status['status']}")

    # the module table, then the registry that dispatches to it.
    from core import rollup_engine
    rollup_engine.init_rollup(session_id)

    modules = _load_modules(config, session_id, rollup_engine)

    if modules.get("runbook"):
        try:
            modules["runbook"].sync_cisa_kev()
        except Exception as e:
            logger.warning(f"CISA KEV sync failed: {e}")

    rollup_engine.start_background_threads()

    # Started after the module start loop, so the first sweep runs against a
    # fully initialised scanner rather than racing it.
    if modules.get("network_scanner"):
        _start_presence_sweeper(config, modules["network_scanner"], session_id)

    # THE PORT OWNERSHIP SWEEP. T9, 2026-09-25.
    #
    # Which process owns which listening port, on a tick, plus a seed pass now.
    # Started unconditionally rather than behind a module check: unlike the
    # presence sweeper this needs no module from _load_modules -- it reads
    # /proc itself -- and it has to run even if every other sensor failed to
    # load, because "which process is listening on that port" is exactly the
    # question somebody asks when something else is broken.
    _start_port_owner_sweeper(config, session_id)

    # THE PORT SCANNER'S BACKGROUND CLOCK. PS-14 option (a), 2026-09-25, on
    # the owner's own instruction: "I want you to create that back ground
    # clock". Started after the module table so the first pass runs against a
    # fully initialised scanner, and unconditionally rather than behind the
    # usual module check -- the function itself reports the two cases where
    # nothing will run (the module did not load; the operator switched it
    # off), because "the clock is not running" and "the clock is running and
    # found nothing" have to stay different sentences in the boot log.
    _start_port_scanner_clock(config, modules, session_id)

    # THE FEED MATCHER, TODO 113.4, 2026-09-20, PORTED 2026-09-21.
    #
    # Started after the sensors so its first matching pass has something to
    # match. It does its own first refresh at boot rather than waiting out the
    # interval, because a machine that has been off for a week has a feed a
    # week out of date and should not spend six hours matching against it
    # quietly.
    #
    # The warning below matters more than it looks. feed_matcher checks every
    # outbound destination against the known-bad lists, so with nothing
    # loaded, an absence of feed findings means NOTHING LOOKED rather than
    # nothing matched, and the sentence has to say which.
    try:
        from tools.feed_matcher import FeedMatcher
        modules["feed_matcher"] = FeedMatcher(session_id, config)
        modules["feed_matcher"].start()
        logger.info("[OK] feed_matcher")
    except Exception as e:
        modules["feed_matcher"] = None
        logger.warning(f"[SKIP] feed_matcher: {type(e).__name__}: {e}")
        logger.warning(
            "feed_matcher did not load, so NOTHING is being checked against "
            "the known-bad feeds. An absence of feed findings from here on "
            "means nothing looked, not that nothing matched."
        )

    # THE CVSS BACKFILL IS BUILT HERE AND NOT STARTED. TODO 113.7, ported
    # 2026-09-21. The CISA feed carries no severity, so the mirror's ratings
    # have to be fetched one CVE at a time, which is ~1700 outbound lookups
    # and about three and a half hours of them without an NVD key.
    #
    # A monitoring tool should not open that much third party traffic because
    # somebody restarted it, so it waits for the button on the Runbook tab.
    # The module is loaded so that button has something to call and so
    # /api/runbook can answer with its state instead of "not loaded".
    try:
        from tools.kev_cvss import CvssBackfill
        modules["kev_cvss"] = CvssBackfill()
        logger.info("[OK] kev_cvss (idle until asked)")
    except Exception as e:
        modules["kev_cvss"] = None
        logger.warning(f"[SKIP] kev_cvss: {type(e).__name__}: {e}")

    # Started after the sweeper, because retirement reads the presence
    # series the sweeper writes.
    try:
        from tools.probe import DeviceProbe
        modules["probe"] = DeviceProbe(session_id, config)
        modules["probe"].start()
        logger.info("[OK] probe")
    except Exception as e:
        modules["probe"] = None
        logger.warning(f"[SKIP] probe: {type(e).__name__}: {e}")
        logger.warning(
            "network_scanner did not load, so no presence sweeps will run. "
            "query_presence will correctly report that nothing looked, rather "
            "than that nothing was there.")

    # CASE MEMORY. The patient file, 2026-09-22.
    #
    # IT IS A MODULE RATHER THAN A SILENT HELPER because its state is
    # something the operator has to be able to read: "case memory is behind by
    # 14 incidents" and "case memory is not indexed at all on this database"
    # are facts about how much history the agent is working with, and a fact
    # like that which exists only inside a prompt is a fact nobody can check.
    #
    # It is NOT a sensor and starts no thread: the index is brought up to date
    # by the watcher's tick below. It is registered here so status() reaches
    # /api/status and the readiness card, which is where a reader looks.
    #
    # REGISTERED BEFORE THE WATCHER, deliberately: the watcher's tick calls
    # case_memory.index_pending, so the module table must already know about
    # the memory when the first tick runs.
    try:
        from core import case_memory
        modules["case_memory"] = case_memory
        _cm = case_memory.status()
        logger.info(f"[OK] case_memory: {_cm.get('note') or 'ready'}")
        if _cm.get("blind"):
            logger.warning(f"[BLIND] case_memory: {_cm.get('blind_reason')}")
    except Exception as e:
        # NOT fatal, and NOT silent. The app works without a memory; what it
        # must not do is work without one and say nothing about it.
        logger.error(
            f"case memory failed to load: {e}. THE DUTY LOOP WILL INVESTIGATE "
            f"EVERY INCIDENT FROM A BLANK PAGE: no subject history, no similar "
            f"past incidents, and no `what was concluded last time` in its "
            f"prompt.")

    # the Duty Watch. Started after the sensors so its first tick reads a
    # findings table the sensors have already written to, and after the module
    # table exists so its coverage snapshot has something to look at.
    #
    # IT HAS NO MODEL DEPENDENCY AND THAT IS THE DESIGN. A watcher that only
    # worked while the model was reachable would be off every time a key
    # expired, and the incidents would stop appearing with nothing on screen
    # saying why.
    try:
        from core import incident
        if incident.start(session_id, modules):
            modules["incident_watcher"] = incident
            logger.info("[OK] incident_watcher")
        else:
            logger.warning(
                "[SKIP] incident_watcher: it did not start. NOTHING IS "
                "AGGREGATING FINDINGS INTO INCIDENTS. See the reason above, "
                "and query_sensor_health will report it as blind.")
    except Exception as e:
        logger.error(f"Incident watcher failed to start: {e}")
        logger.error("Findings are still being written; nothing is turning "
                     "them into incidents.")

    # the action executor. THE PIECE THAT DID NOT EXIST, and the reason
    # the 3am case was impossible before T3: a chat approval card dies with
    # the SSE stream that carries it, so the thing that would have run the
    # action is gone by the time anybody answers. This worker holds approved
    # requests and runs them OUTSIDE any chat turn.
    #
    # STARTED AFTER THE WATCHER, because the only thing that files requests
    # today is a model call or a tool call and both arrive after boot; and
    # started whatever the model does, because an approval that cannot run has
    # to be reported as blind rather than discovered by somebody waiting.
    try:
        from core import actions
        if actions.start(session_id):
            modules["action_executor"] = actions
            logger.info("[OK] action_executor")
        else:
            logger.warning(
                "[SKIP] action_executor: it did not start. AN APPROVED "
                "REQUEST WILL NOT RUN: the card will say approved and the "
                "action behind it will never happen. See the reason above, "
                "and query_action_requests reports it as blind.")
    except Exception as e:
        logger.error(f"Action executor failed to start: {e}")
        logger.error("Requests can still be filed and decided; none of them "
                     "will execute.")

    # the duty loop. T4's piece, and the one the whole programme was
    # approved for: SOMETHING HAS TO DO THE LOOKING when nobody is typing.
    # Before this, agent_loop.run() was called from /api/chat and nowhere
    # else, so if nobody asked the analyst a question the analyst did not
    # exist that hour.
    #
    # STARTED LAST, after the watcher has something in the ledger to look at
    # and the executor exists to file through. Started whatever the model's
    # state is: an unreachable model makes each tick an error it records, and
    # that is a visible fact about this app rather than a silent one.
    try:
        from core import duty
        if duty.start(session_id, modules):
            modules["duty_loop"] = duty
            logger.info("[OK] duty_loop")
        else:
            logger.warning(
                "[SKIP] duty_loop: it did not start. NOTHING IS INVESTIGATING "
                "INCIDENTS AND NO REGULAR REPORT WILL BE WRITTEN. See the "
                "reason above; query_agent_reports reports it as blind.")
    except Exception as e:
        logger.error(f"Duty loop failed to start: {e}")
        logger.error("The watcher still aggregates findings into incidents "
                     "and the executable queue still works; nothing is "
                     "assessing them unattended.")

    # The sensor watchdog: once a minute, says which sensors are collecting.
    try:
        from core import sensor_watch

        def _extra_sensors():
            from tools import lan_live, place_watch, router_monitor
            from core.sensor_watch import LoopTracker
            from tools import dns_monitor as _dm
            dns = _dns_tracker or LoopTracker(
                60, idle=lambda: _dm.status(config)["reason"]
                or "switched off in Settings")
            lan = lan_live.get() or LoopTracker(60, idle=lambda: (
                "switched off in config.json"
                if (config.get("gateway") or {}).get("enabled")
                else "no router agent is enrolled, so there is no live "
                     "router traffic to read"))
            return {"lan_live": lan,
                    "place_watch": place_watch.get(),
                    "dns_monitor": dns,
                    "router_monitor": router_monitor.tracker(config)}

        sensor_watch.start(modules, session_id, extras=_extra_sensors)
    except Exception as e:
        logger.error(f"Sensor watch did not start: {e}")

    # The clean shutdown. Two doors reach it: the signal handler below and
    # the dashboard's stop button.
    _shutdown_lock = threading.Lock()
    _shutdown_done = [False]

    # Background threads that write to the database, stopped before retention.
    _WRITER_MODULES = ("packet_sniffer", "process_monitor", "event_monitor",
                       "local_integrity", "ebpf_events", "auditd",
                       "registry_monitor", "gateway", "feed_matcher", "probe")

    def _quiet_writers(wait_seconds=3.0):
        # First, so the sensors stopping here are not reported as quiet.
        try:
            from core import sensor_watch
            sensor_watch.stop()
        except Exception as e:
            logger.warning(f"Sensor watch did not stop cleanly: {e}")
        try:
            from tools import lan_live
            if lan_live.get() is not None:
                lan_live.get().stop()
        except Exception as e:
            logger.warning(f"Live LAN monitor did not stop cleanly: {e}")
        try:
            from tools import place_watch
            if place_watch.get() is not None:
                place_watch.get().stop()
        except Exception as e:
            logger.warning(f"Place learning did not stop cleanly: {e}")
        threads = []
        for name in _WRITER_MODULES:
            mod = modules.get(name)
            if mod is None or not callable(getattr(mod, "stop", None)):
                continue
            try:
                mod.stop()
            except Exception as e:
                logger.warning(f"{name} did not stop cleanly: {e}")
            t = getattr(mod, "_thread", None)
            if isinstance(t, threading.Thread):
                threads.append(t)
        # A poll already under way is let finish; a thread asleep between
        # polls is not waited for past the shared deadline.
        deadline = time.time() + wait_seconds
        for t in threads:
            t.join(max(0.0, deadline - time.time()))

    def _clean_shutdown(reason="Shutdown signal received"):
        with _shutdown_lock:
            if _shutdown_done[0]:
                logger.info("Shutdown already running, ignoring the second ask.")
                return False
            _shutdown_done[0] = True

        logger.info(f"{reason}. Running final rollup...")

        # FIRST, before anything slow. Approval cards have no time cap, so a
        # card left open on a screen would otherwise hold its chat thread in
        # the model loop for as long as the process lives.
        try:
            from core import agent_loop as _al
            _al.begin_shutdown()
        except Exception as e:
            logger.warning(f"Could not release open permission cards: {e}")

        try:
            rollup_engine.shutdown_rollup()
        except Exception as e:
            logger.error(f"Final rollup failed: {e}")

        # The enrichment worker holds a write handle between jobs, so it stops
        # before retention touches the file.
        try:
            if modules.get("enrichment"):
                modules["enrichment"].stop()
        except Exception as e:
            logger.warning(f"Enrichment worker did not stop cleanly: {e}")

        # The watcher gets one last pass so findings since its last tick are
        # aggregated. Best effort.
        try:
            from core import incident as _inc
            _inc.stop()
            _inc.watch_once(session_id,
                            (_inc._watcher_state or {}).get("modules"))
        except Exception as e:
            logger.warning(f"Final watcher pass failed: {e}")

        # The executor stops without a final pass: a remediation should not
        # run as the process dies. Approvals are durable and run next boot.
        try:
            from core import actions as _acts
            _acts.stop()
            pending_exec = (_acts.status().get("awaiting_execution"))
            if pending_exec:
                logger.info(
                    "Action executor stopped with %s approved request(s) not "
                    "yet run. They are NOT lost and they are NOT cancelled: "
                    "they run on the next boot. An approval is durable.",
                    pending_exec)
        except Exception as e:
            logger.warning(f"Action executor did not stop cleanly: {e}")

        # The duty loop stops without a final pass, since a pass calls a model.
        # Its last 24 hours of spend is reported on the way out.
        try:
            from core import duty as _duty
            spend = _duty.spend_in_window(24)
            _duty.stop()
            if spend.get("available"):
                logger.info(
                    "Duty loop stopped. It ran %s time(s) in the last 24h, "
                    "%s of them producing work, and spent %s tokens%s.",
                    spend.get("runs"), spend.get("ran_work"),
                    f"{spend.get('spent'):,}",
                    " (some of that is ESTIMATED: the provider did not report "
                    "usage for every call)" if spend.get("estimated_rows")
                    else "")
        except Exception as e:
            logger.warning(f"Duty loop did not stop cleanly: {e}")

        # Every writer stops before retention, or its saves fail with
        # "database is locked" while the prune and VACUUM hold the file.
        _quiet_writers()

        # RETENTION RUNS HERE AND NOWHERE ELSE, once nothing else writes.
        # Payload rows are pruned first so the VACUUM reclaims their space
        # too (TODO 113.6). A retention failure never stops the shutdown.
        try:
            from tools import payload_ring
            pr_result = payload_ring.prune()
            if not pr_result.get("ran"):
                logger.warning(f"Payload prune did not run at shutdown: "
                               f"{pr_result.get('reason')}")
        except Exception as e:
            logger.error(f"Payload prune failed at shutdown: {e}")

        try:
            from core import retention
            retention.run_if_due(me.DB_PATH, current_session_id=session_id,
                                 log=logger)
        except Exception as e:
            logger.error(f"Retention failed at shutdown: {e}")

        logger.info("AgentalSec stopped cleanly.")
        return True

    def handle_shutdown(sig, frame):
        # Only the call that ran the shutdown exits. A second signal lands on
        # top of the first one's cleanup, and exiting there cut it short (PROC-14).
        if _clean_shutdown("Shutdown signal received"):
            sys.exit(0)

    def _shutdown_from_dashboard(reason):
        """
        The stop button's door.

        os._exit at the end, not sys.exit: sys.exit raises SystemExit in
        whatever thread calls it, and this is not the main thread, so it
        would kill this thread and leave the app running, which is the exact
        opposite of what the button says it does.
        """
        def run():
            time.sleep(0.4)          # let the HTTP response flush
            try:
                _clean_shutdown(reason)
            except Exception as e:
                logger.error(f"Shutdown from the dashboard failed: {e}")
            finally:
                os._exit(0)

        threading.Thread(target=run, name="dashboard-shutdown",
                         daemon=True).start()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # the dashboard.
    from api.server import create_app

    flask_cfg    = config.get("flask", {})
    host         = flask_cfg.get("host", "127.0.0.1")
    port         = int(flask_cfg.get("port", 5000))
    auto_browser = flask_cfg.get("auto_open_browser", True)

    if host != "127.0.0.1":
        logger.warning(f"WARNING: Flask bound to {host}, not localhost only. "
                       f"Add the name you browse to under flask.allowed_hosts "
                       f"or the Host check will answer 403.")

    app = create_app(config, modules, session_id, api_key=resolved["app_api_key"])
    app.config["AGENTAL_SHUTDOWN"] = _shutdown_from_dashboard

    if auto_browser:
        threading.Thread(target=_open_browser_when_ready,
                         args=(host, port), name="open-browser",
                         daemon=True).start()

    # Heartbeat. A run that lasts hours has to leave something behind to read.
    try:
        from core import heartbeat
        hb_minutes = (config.get("heartbeat", {}) or {}).get("interval_minutes", 5)
        if hb_minutes:
            heartbeat.start(hb_minutes)
    except Exception as e:
        logger.warning(f"Heartbeat did not start: {e}")

    # TAKE THE PORT BEFORE ANNOUNCING ANYTHING. 2026-09-18
    #
    # THE BUG THIS IS, in the operator's words: "the privileged launcher
    # exited with code 1". What actually happened is below, and every line of
    # it was true at the same time:
    #
    #   * the boot ran to its last line and logged "AgentalSec ready.";
    #   * waitress then tried to bind 127.0.0.1:5099, found it held, and died
    #     with a raw `OSError: [Errno 98] Address already in use` traceback;
    #   * the process exited 1;
    #   * the launcher said so, honestly, and its window held the reason;
    #   * and NOTHING in the app's own log file recorded the failure at all —
    #     the traceback went to stderr only, because the exception happened
    #     after the last logger call. The durable record of a fatal boot
    #     consisted of a "ready" line with nothing after it.
    #
    # A readiness announcement the program has not earned is exactly the
    # class of statement this app is built to refuse, and it was in the
    # readiness announcement itself. So the socket is taken HERE, before the
    # log line, and handed to waitress to serve on. A taken port now produces
    # a named refusal in the log AND on the terminal, and "AgentalSec ready."
    # is only reachable once the listener exists.
    try:
        listener = _bind_listener(host, port)
    except OSError as e:
        return _refuse_busy_port(host, port, _port_holder(host, port), reason=e)

    logger.info(f"Dashboard: http://{host}:{port}")
    logger.info("AgentalSec ready.")
    hint = _launcher_hint()
    if hint:
        logger.warning(hint)

    # waitress, not app.run(). app.run() is the Werkzeug development server,
    # which Flask's own documentation says not to deploy, and it is
    # single-threaded by default, which matters here: the sensors and the
    # rollup engine share this process, and one slow request must not be able
    # to hold the whole thing.
    #
    # waitress is a hard requirement in requirements.txt. The fallback stays
    # so an existing install does not stop booting because of a new
    # dependency, and it is loud about what it fell back to.
    try:
        from waitress import serve
    except ImportError:
        logger.error(
            "waitress is not installed, falling back to the Flask "
            "development server. It is single threaded and not meant to be "
            "exposed. Run: pip install -r requirements.txt   (on PEP 668 "
            "Python, add --break-system-packages or use a virtualenv)"
        )
        listener.close()
        app.run(host=host, port=port, debug=False, use_reloader=False,
                threaded=True)
    else:
        # Serve on the socket already taken, so no second bind can race.
        try:
            serve(app, sockets=[listener], threads=8, ident="AgentalSec")
        finally:
            try:
                listener.close()
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
