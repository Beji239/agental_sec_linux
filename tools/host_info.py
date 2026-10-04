# tools/host_info.py
# AgentalSec V2, what this host actually is.
#
# Exists because the runbook can now say "applies to Windows versions patched
# before March 2017" and nothing in the system could answer whether THIS host
# is one of those. The model had to infer an OS from a hostname, which is
# guessing dressed as analysis, and guessing is what produced a critical
# EternalBlue finding against a machine the vulnerability cannot touch.
#
# This module reports facts and nothing else. It does not decide whether a
# host is vulnerable, does not score anything, and does not filter what the
# model sees. It answers "what is this?" so the model can do the comparing.
#
# Universal by construction: every deployment has an operating system with a
# version. Nothing here is specific to any network, vendor or address.

import logging
import platform
import socket
import sys
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Host identity changes on reboots and patch cycles, not between queries.
# Re-reading the registry on every tool call would be wasted work in a loop
# that can run 25 rounds.
CACHE_TTL = 900


class HostInfo:

    def __init__(self, session_id: str = None):
        self.session_id = session_id
        self._cache = None
        self._cached_at = 0

    def start(self):
        info = self.collect()
        logger.info(
            f"HostInfo ready: {info.get('os_name') or 'unknown'} "
            f"{info.get('os_version') or '?'} "
            f"build {info.get('os_build') or '?'}, machine up "
            f"{info.get('uptime_human')}"
        )

    def status(self) -> dict:
        """
        This module's own health, as a READ rather than as a constant.

        MEASURED 2026-09-25: this used to return `{"ready": True, ...}`
        unconditionally, and a HostInfo whose /etc/os-release could not be
        read answered `os: 'Linux'` here while its own `errors` list held the
        refusal -- so the readiness card and core/sensor_health both read it
        as healthy (both call this method, and both were measured doing it).
        The keys below are now present only when they were READ, and `note`
        carries the reason when a reading failed.
        """
        info = self.collect()
        out = {"ready": True, "cached": info.get("cached")}
        if info.get("os_name"):
            out["os"] = info["os_name"]
        if info.get("os_build"):
            out["build"] = info["os_build"]
        if info.get("uptime_human"):
            out["uptime_human"] = info["uptime_human"]
        if info.get("agentalsec_uptime_human"):
            out["watched_human"] = info["agentalsec_uptime_human"]
        if info.get("errors"):
            out["note"] = ("partial: " + "; ".join(str(e) for e in info["errors"]))
        return out

    # UPTIME
    #
    # WHY THIS IS HERE, 2026-08-31.
    #
    # Asked how long since the last boot, the model correctly said it had no
    # tool for it, then correctly refused to guess from a burst of service
    # logons. Good behaviour, and a real gap: an unexpected reboot is a
    # security event, and this module already answers "what is this host".
    #
    # The number that matters more than either is the PAIR. AgentalSec can
    # measure nothing slower than one capture run, so knowing the machine has
    # been up for twenty days while the tool watched four hours of it turns
    # that limit from a sentence in a document into something the model can
    # check. Both numbers are reported together for that reason.
    #
    # NOT CACHED. Everything else in this module changes on reboots and patch
    # cycles, so a fifteen minute cache is free. An uptime served from a
    # fifteen minute old cache is just wrong, and wrong quietly.

    @staticmethod
    def _human_duration(seconds) -> str:
        if seconds is None:
            return "unknown"
        seconds = int(seconds)
        d, rem = divmod(seconds, 86400)
        h, rem = divmod(rem, 3600)
        m = rem // 60
        if d:
            return f"{d}d {h}h {m}m"
        if h:
            return f"{h}h {m}m"
        return f"{m}m"

    def _uptime(self, info: dict):
        """
        Machine boot time and uptime, plus how much of it this tool watched.

        Timestamps are UTC and say so in the field name. The dashboard has
        been bitten once already by a naive local-looking string that was
        actually UTC, and a boot time is exactly the kind of value somebody
        compares against an event timestamp.
        """
        info["boot_time_utc"] = None
        info["uptime_seconds"] = None
        info["uptime_human"] = "unknown"
        info["agentalsec_started_utc"] = None
        info["agentalsec_uptime_seconds"] = None
        info["agentalsec_uptime_human"] = "unknown"
        info["observed_fraction"] = None

        if not PSUTIL_AVAILABLE:
            info["errors"].append(
                "psutil unavailable, so boot time and uptime are unknown. "
                "That is a missing reading, not a machine that just started.")
            return

        now = time.time()
        try:
            boot = psutil.boot_time()
            info["boot_time_utc"] = datetime.fromtimestamp(
                boot, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            info["uptime_seconds"] = int(now - boot)
            info["uptime_human"] = self._human_duration(now - boot)
        except Exception as e:
            info["errors"].append(f"boot time unreadable: {e}")

        try:
            started = psutil.Process().create_time()
            info["agentalsec_started_utc"] = datetime.fromtimestamp(
                started, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            info["agentalsec_uptime_seconds"] = int(now - started)
            info["agentalsec_uptime_human"] = self._human_duration(
                now - started)
        except Exception as e:
            info["errors"].append(f"process start time unreadable: {e}")

        # The comparison, computed once here so nothing downstream has to do
        # arithmetic on two timestamps and get it subtly wrong.
        up = info["uptime_seconds"]
        watched = info["agentalsec_uptime_seconds"]
        # `is not None`, not truthiness. A run that started this second has
        # watched ZERO seconds, which is a real and meaningful answer, and a
        # falsy check silently reported it as unknown instead.
        if up is not None and watched is not None and up > 0:
            info["observed_fraction"] = round(min(watched / up, 1.0), 4)
            info["observation_note"] = (
                f"This machine has been up {info['uptime_human']}. "
                f"This run of AgentalSec has been watching for "
                f"{info['agentalsec_uptime_human']}, which is "
                f"{info['observed_fraction'] * 100:.0f}% of it. Anything that "
                f"happened while it was not running was not observed by this "
                f"sensor, and earlier runs are a separate question from this "
                f"one.")

    def collect(self, refresh: bool = False) -> dict:
        """
        Collect host identity, from cache when it is fresh.

        TWO CORRECTIONS, both measured 2026-09-25.

        (1) `collected_at` USED TO MOVE WHILE THE FACTS DID NOT. The cached
        path rewrote `collected_at` with the current time on every call
        while `os_name`, `os_version`, `os_build` and `detail` came back as
        the same dict object read up to fifteen minutes earlier. A reader --
        a person or the model -- checking that field to decide how current
        the answer is got the CURRENT TIME next to a fifteen-minute-old
        distribution name. `collected_at` now means what it says: when the
        FACTS were read. `served_at` carries the time of this answer, and
        `cache_age_seconds` says how old the facts are, so nothing has to be
        inferred from a timestamp again.

        (2) The uptime pair is genuinely live on every call -- the module's
        own comment promised that and `_uptime()` does re-run -- but the
        rest of the answer was silently up to CACHE_TTL old, with nothing on
        the payload saying which fields were which. Now the payload says.
        """
        if not refresh and self._cache and (time.time() - self._cached_at) < CACHE_TTL:
            self._uptime(self._cache)
            self._cache["served_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self._cache["cache_age_seconds"] = round(time.time() - self._cached_at, 3)
            self._cache["cached"] = True
            return self._cache

        info = {
            "hostname":     socket.gethostname(),
            "platform":     sys.platform,
            "os_family":    platform.system() or "unknown",
            "os_name":      None,
            "os_version":   None,
            "os_build":     None,
            "os_patch_level": None,
            "arch":         platform.machine(),
            "python":       platform.python_version(),
            "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "served_at":    None,
            "cache_age_seconds": 0.0,
            "cached":       False,
            "scope":        "local",   # this is the machine AgentalSec runs on
            "detail":       {},
            "errors":       [],
        }

        family = info["os_family"].lower()
        try:
            if family == "windows":
                self._windows(info)
            elif family == "linux":
                self._linux(info)
            elif family == "darwin":
                self._darwin(info)
            else:
                info["os_name"] = info["os_family"]
                info["os_version"] = platform.release()
        except Exception as e:
            # A partial answer beats no answer: the model can still reason
            # about whatever fields did populate, and the error says what is
            # missing rather than leaving a silent gap.
            info["errors"].append(f"{type(e).__name__}: {e}")
            logger.warning(f"HostInfo collection partial: {e}")

        self._uptime(info)

        self._cache, self._cached_at = info, time.time()
        return info

    # WINDOWS

    def _windows(self, info: dict):
        """
        Read identity from the registry rather than shelling out.

        No subprocess on purpose. wmic is deprecated, PowerShell startup is
        slow enough to matter inside a tool loop, and spawning a shell from a
        security monitor is a worse habit than reading a key.
        """
        import winreg

        info["os_name"] = "Windows"
        info["os_version"] = platform.release()

        cv = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        vals = self._read_reg(winreg.HKEY_LOCAL_MACHINE, cv, [
            "ProductName", "DisplayVersion", "ReleaseId",
            "CurrentBuild", "UBR", "EditionID", "InstallationType",
        ])

        build = str(vals.get("CurrentBuild") or "")
        ubr   = vals.get("UBR")

        # Windows 11 still reports ProductName "Windows 10" in the registry;
        # build >= 22000 is the actual discriminator. Getting this wrong is
        # exactly the class of error this module exists to prevent.
        product = vals.get("ProductName") or "Windows"
        try:
            if int(build) >= 22000 and "Windows 10" in product:
                product = product.replace("Windows 10", "Windows 11")
        except (TypeError, ValueError):
            pass

        info["os_name"]        = product
        info["os_build"]       = build
        info["os_patch_level"] = f"{build}.{ubr}" if ubr is not None else build
        info["os_version"]     = vals.get("DisplayVersion") or vals.get("ReleaseId") or platform.release()

        info["detail"]["edition"]           = vals.get("EditionID")
        info["detail"]["installation_type"] = vals.get("InstallationType")

        # SMBv1 presence, because a runbook entry now asks for it by name.
        # Reported as a tri-state: True, False, or None when it could not be
        # read. None must not be reported as False, "not installed" and
        # "could not check" are different answers.
        info["detail"]["smb1_server_enabled"] = self._smb1_state(winreg)

    def _smb1_state(self, winreg):
        key = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        vals = self._read_reg(winreg.HKEY_LOCAL_MACHINE, key, ["SMB1"])
        if "SMB1" in vals and vals["SMB1"] is not None:
            return bool(vals["SMB1"])

        # Absent value means the default applies, and the default flipped:
        # Windows 10 1709 (build 16299) and later ship without SMBv1.
        try:
            build = int(platform.win32_ver()[1].split(".")[2])
            return build < 16299
        except Exception:
            return None

    @staticmethod
    def _read_reg(hive, path, names) -> dict:
        import winreg
        out = {}
        try:
            with winreg.OpenKey(hive, path) as k:
                for n in names:
                    try:
                        out[n] = winreg.QueryValueEx(k, n)[0]
                    except FileNotFoundError:
                        out[n] = None
        except OSError:
            pass
        return out

    # LINUX

    def _linux(self, info: dict):
        """
        Linux identity from /etc/os-release.

        A REFUSED READ IS NOT A NAMELESS DISTRO, measured 2026-09-25: when
        the file could not be read this set `os_name = "Linux"` and left
        `os_version` empty, so the model got a plausible-looking OS name and
        no version, with the refusal recorded only in `errors` -- a field the
        description tells it to read, and a field that reads as a footnote
        beside a name that looks like an answer. The name is now null with
        the reason IN THE FIELD, and `os_family` (platform.system(), which
        does not need the file) is the fallback the description promises.
        """
        info["os_build"] = platform.release()      # kernel
        info["os_patch_level"] = platform.release()

        try:
            with open("/etc/os-release", encoding="utf-8") as f:
                rel = {}
                for line in f:
                    if "=" in line and not line.strip().startswith("#"):
                        k, _, v = line.strip().partition("=")
                        rel[k.strip()] = v.strip().strip('"')
        except OSError as e:
            info["errors"].append(f"/etc/os-release unreadable: {e}")
            info["os_name"] = None
            info["os_version"] = None
            info["detail"]["os_unknown_because"] = (
                f"/etc/os-release could not be read: {e}")
            info["detail"]["kernel"] = platform.release()
            info["detail"]["libc"] = " ".join(platform.libc_ver()).strip()
            return

        if not rel:
            info["errors"].append("/etc/os-release holds no KEY=VALUE lines")
            info["os_name"] = None
            info["os_version"] = None
            info["detail"]["os_unknown_because"] = (
                "/etc/os-release holds no KEY=VALUE lines")
        else:
            info["os_name"] = rel.get("NAME") or None
            info["os_version"] = rel.get("VERSION_ID") or rel.get("VERSION") or None
            info["detail"]["pretty_name"] = rel.get("PRETTY_NAME")
            info["detail"]["distro_id"] = rel.get("ID")
        info["detail"]["kernel"] = platform.release()
        info["detail"]["libc"] = " ".join(platform.libc_ver()).strip()

    # MACOS

    def _darwin(self, info: dict):
        info["os_name"]    = "macOS"
        ver                = platform.mac_ver()[0]
        info["os_version"] = ver
        info["os_build"]   = platform.release()
        info["os_patch_level"] = ver
        info["detail"]["kernel"] = platform.release()
