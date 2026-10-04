# tools/software_inventory.py
# AgentalSec V2, what software is installed, and at what version.
#
# The other half of query_host_info. Between them the model can finally
# evaluate a version-scoped claim instead of inferring one: host_info answers
# "what OS and patch level", this answers "what is installed and how old".
#
# DELIBERATELY NOT A MATCHER.
#
# The obvious next step is to join this against the runbook and emit "you are
# vulnerable to CVE-X". That step is not taken here, on purpose. Deciding that
# "Chrome 121.0.6167.140" matches a KEV entry reading "Google Chrome" is
# fuzzy, version-range-sensitive, and exactly the kind of judgement that,
# baked into Python, produced a critical EternalBlue finding against a machine
# the vulnerability cannot touch. A wrong matcher would be that failure with a
# bigger table behind it.
#
# So this module enumerates and stops. The model already has query_runbook and
# web_search; comparing an inventory against known vulnerabilities is
# reasoning, and reasoning is its job. Python's job is to make sure the facts
# it reasons from are real.
#
# Universal by construction: every OS has a package inventory. Nothing here
# names a vendor, a product or a network.

import gzip
import logging
import platform
import subprocess
import sys
import time

logger = logging.getLogger(__name__)

CACHE_TTL = 1800          # installs are rare; re-enumerating per tool call is waste
CMD_TIMEOUT = 20

# A BOUND ON THE ROWS AN ANSWER CARRIES, NOT ON THE SET THAT GETS SEARCHED.
# Measured 2026-09-26 (register section 12): this used to cap the STORED
# universe at 2000 and then search inside the capped list, so on this host --
# 2792 dpkg entries, 2756 of them installed -- the 792 packages past the
# alphabetical cut were unreachable: `search="node-isexe"` returned 0 rows
# while `dpkg-query -W node-isexe` answered, and the model was told the
# package was not installed. A false negative on the one question this tool
# exists for. The universe is now kept whole and only the RETURNED rows are
# bounded; the payload reports `matched` (everything the search selected) and
# `truncated` (whether this answer was cut) so the cut is visible.
MAX_ENTRIES = 2000

# dpkg's OWN PACKAGE LOG, newest first. Used to fill install_date with a real
# date where one exists: the platform keeps this history and the field used to
# be published empty on every Linux row. Nothing is guessed where there is no
# line -- a package older than the kept logs gets "", not a fabricated date.
# Rotated files may be gzipped; both shapes are read. Other distributions do
# not have this file and simply get no dates.
INSTALL_LOG_PATHS = (
    "/var/log/dpkg.log",
    "/var/log/dpkg.log.1",
    "/var/log/dpkg.log.2.gz",
    "/var/log/dpkg.log.3.gz",
    "/var/log/dpkg.log.4.gz",
)


class SoftwareInventory:

    def __init__(self, session_id: str = None):
        self.session_id = session_id
        self._cache = None
        self._cached_at = 0

    def start(self):
        inv = self.collect()
        logger.info(f"SoftwareInventory ready: {inv['total']} packages via {inv['source']}")

    def status(self) -> dict:
        """
        The readiness card's read, and it must not paint a FAILED read green.

        MEASURED 2026-09-26 (register section 12, SI-3): with every package
        manager missing or refusing, this used to answer
        {'ready': True, 'packages': 0, 'source': 'none-found'} -- the card
        drew [ok] "running." and the model was told nothing, which is the
        host_info lesson (HI-8) one module over. A key is now present only
        when it was READ: a failed enumeration reports `reachable: False`
        with the reason, the pair both surfaces already render (the card's
        "not answering" and core/sensor_health's "is NOT ANSWERING").
        """
        inv = self.collect()
        if inv["source"] in ("none-found", "unknown", ""):
            return {
                "ready": False,
                "reachable": False,
                "source": inv["source"],
                "last_error": "no package manager answered on this host, so "
                              "nothing here is known about what is "
                              "installed. "
                              + (inv["errors"][0] if inv.get("errors") else ""),
            }
        return {"ready": True, "packages": inv["total"], "source": inv["source"]}

    def collect(self, search: str = None, refresh: bool = False) -> dict:
        if refresh or not self._cache or (time.time() - self._cached_at) > CACHE_TTL:
            self._cache = self._enumerate()
            self._cached_at = time.time()

        data = self._cache
        items = data["software"]

        if search:
            needle = search.lower()
            # The row carries dpkg's own spelling ('bind9-libs:amd64'); a
            # bare needle ('bind9-libs') still finds it because this is a
            # substring test, and a needle in dpkg's spelling finds it too.
            # The naming direction is what matters: local_integrity and
            # dpkg -V report 'name:arch', and a search in THEIR spelling
            # used to miss the bare-named rows entirely (SI-8, 2026-09-26).
            items = [s for s in items
                     if needle in (s.get("name") or "").lower()
                     or needle in (s.get("publisher") or "").lower()]

        # THE SEARCH RUNS OVER THE WHOLE UNIVERSE; only the ANSWER is bounded.
        matched = len(items)
        truncated = False
        if len(items) > MAX_ENTRIES:
            items = items[:MAX_ENTRIES]
            truncated = True

        note = ("Inventory only. No vulnerability matching is performed here, "
                "compare against query_runbook and web_search yourself, and "
                "check query_host_info for the OS and patch level.")
        excluded = data.get("excluded") or {}
        if excluded:
            bits = ", ".join(f"{k} {v}" for k, v in sorted(excluded.items()))
            note += (f" NOT LISTED: {sum(excluded.values())} package(s) the "
                     f"package database still holds that are NOT installed "
                     f"(dpkg states: {bits}). They are not software on this "
                     f"machine.")
        if truncated:
            note += (f" THIS ANSWER IS CUT: {matched} row(s) matched and the "
                     f"first {MAX_ENTRIES} are listed. Narrow `search` to "
                     f"reach the rest, and do not read an absence in this "
                     f"list as an absence on the machine.")
        if data["errors"]:
            note += " It could not read everything it looked for: " \
                    + " ".join(data["errors"])

        return {
            "software":   items,
            "count":      len(items),
            "matched":    matched,
            "total":      data["count"],
            "source":     data["source"],
            "truncated":  truncated,
            "collected_at": data["collected_at"],
            "errors":     data["errors"],
            "note": note,
        }

    def _enumerate(self) -> dict:
        out = {
            "software": [], "count": 0, "source": "unknown",
            "excluded": {}, "errors": [],
            "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        family = (platform.system() or "").lower()
        try:
            if family == "windows":
                out["source"] = "windows-registry"
                out["software"] = self._windows()
            elif family == "linux":
                out["software"], out["source"], extra = self._linux()
                out["excluded"] = extra.get("excluded") or {}
                if out["source"] == "none-found" and extra.get("tried"):
                    out["errors"].append(
                        "no package manager answered this host; tried "
                        + ", ".join(sorted(set(extra["tried"]))))
            elif family == "darwin":
                out["software"], out["source"] = self._darwin()
            else:
                out["errors"].append(f"No inventory method for platform {family!r}")
        except Exception as e:
            out["errors"].append(f"{type(e).__name__}: {e}")
            logger.warning(f"Software inventory partial: {e}")

        # Deduplicate: 32- and 64-bit registry views list the same product,
        # and a package can appear in both a system and user scope.
        #
        # THE UNIVERSE IS KEPT WHOLE AND THE ANSWER IS BOUNDED LATER, IN
        # collect(). Truncating HERE is what made `search="node-isexe"` return
        # 0 rows on a machine where that package is installed (measured
        # 2026-09-26): the cut is 2000 rows and this host has 2756, so the
        # alphabetical tail -- 792 rows on this machine, most of the node-*
        # tree -- was unreachable by name. A bound that eats its own search
        # results is a filter pretending to be a limit.
        seen, unique = set(), []
        for s in out["software"]:
            key = ((s.get("name") or "").lower(), s.get("version") or "")
            if key in seen or not key[0]:
                continue
            seen.add(key)
            unique.append(s)

        unique.sort(key=lambda s: (s.get("name") or "").lower())
        out["software"] = unique
        out["count"] = len(unique)
        return out

    # WINDOWS

    WIN_KEYS = [
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    def _windows(self) -> list:
        import winreg
        hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
        found = []

        for hive_name, path in self.WIN_KEYS:
            try:
                root = winreg.OpenKey(hives[hive_name], path)
            except OSError:
                continue

            with root:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(root, sub) as k:
                            def val(n):
                                try:
                                    return winreg.QueryValueEx(k, n)[0]
                                except OSError:
                                    return None

                            # SystemComponent=1 marks redistributables and
                            # update stubs that Add/Remove Programs hides.
                            # Thousands of them drown the real inventory.
                            if val("SystemComponent") == 1:
                                continue
                            name = val("DisplayName")
                            if not name:
                                continue

                            found.append({
                                "name":         str(name),
                                "version":      str(val("DisplayVersion") or ""),
                                "publisher":    str(val("Publisher") or ""),
                                "install_date": str(val("InstallDate") or ""),
                                "architecture": str(val("Architecture") or ""),
                                "scope":        hive_name,
                                "registry_key": sub,
                            })
                    except OSError:
                        continue
        return found

    # LINUX

    def _linux(self):
        """
        (rows, source, extra). extra carries what was EXCLUDED and what was
        TRIED -- a search that returns nothing must be able to say whether it
        looked (SI-6): the old shape returned bare `none-found` with an empty
        errors list, so the model could not tell a host with no package
        manager from a host whose package manager refused.

        THE dpkg QUERY NOW ASKS FOR THREE MORE THINGS, each a measured
        defect on this host (2026-09-26):
          ${db:Status-Abbrev}  dpkg -W lists every entry in the package
                               database, INCLUDING `rc` ones -- removed with
                               their config files still on disk. This host has
                               36 of them, and the tool used to publish them
                               as installed software. Anything not `ii`
                               (installed, configured) is dropped and COUNTED
                               into extra["excluded"], which the note carries.
          ${Architecture}      the architecture was missing from every row.
          ${binary:Package}    dpkg's own spelling of a multiarch package
                               carries its architecture suffix. The port
                               published the bare ${Package} name instead,
                               while dpkg's own tools -- dpkg -V, dpkg-query,
                               and this tree's local_integrity, whose findings
                               are joined against this inventory -- name the
                               same package 'name:arch'. Measured 2026-09-26:
                               1075 of the 2792 entries in this host's dpkg
                               database carry the suffix (1063 of the 2756
                               INSTALLED ones), so a question asked in dpkg's
                               own spelling found nothing. The row now carries
                               ${binary:Package}; a bare name still matches,
                               because the search is a substring test.
                               CORRECTED 2026-09-26, in the closing pass:
                               this read "1075 of this host's 2756 entries",
                               which mixed the two sets -- 1075 is the count
                               across ALL 2792 database rows, and the
                               installed-only count is 1063 of 2756.

        install_date is filled from dpkg's own log where a line exists
        (SI-11): the field shipped empty on every Linux row while the platform
        kept the history.
        """
        tried = []
        for source, cmd, parse in (
            ("dpkg", ["dpkg-query", "-W",
                      "-f=${binary:Package}\\t${Version}\\t${Maintainer}"
                      "\\t${Architecture}\\t${db:Status-Abbrev}\\n"],
             self._parse_dpkg),
            ("rpm",  ["rpm", "-qa", "--queryformat",
                      "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t"
                      "%{ARCH}\\tinstalled\\n"],
             self._parse_tabbed),
            ("apk",  ["apk", "info", "-v"], self._parse_apk),
            ("pacman", ["pacman", "-Q"], self._parse_pacman),
        ):
            tried.append(source)
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=CMD_TIMEOUT)
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue
            if r.returncode == 0 and r.stdout.strip():
                rows, excluded = parse(r.stdout)
                extra = {"excluded": excluded, "tried": tried}
                if source == "dpkg":
                    self._fill_install_dates(rows)
                return rows, source, extra
        return [], "none-found", {"excluded": {}, "tried": tried}

    @staticmethod
    def _parse_dpkg(text: str):
        """(rows, excluded) from the five-field dpkg-query shape above."""
        out, excluded = [], {}
        for line in text.splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            name, version, publisher, arch, status = (p.strip() for p in parts[:5])
            state = status[:2]
            if not name:
                continue
            if state != "ii":
                # rc = removed, config files remain. iU/iF = a package an
                # unfinished dpkg run left half-installed. None of them is
                # installed software and none may be published as such.
                excluded[state or "??"] = excluded.get(state or "??", 0) + 1
                continue
            out.append({
                "name": name, "version": version, "publisher": publisher,
                "architecture": arch,
                "install_date": "", "scope": "system", "registry_key": "",
            })
        return out, excluded

    @classmethod
    def _fill_install_dates(cls, rows: list) -> None:
        """
        Fill install_date from dpkg's own log, in place, where the log holds a
        line for the package. Newest log first, first line wins; nothing is
        invented for a package the kept logs predate.
        """
        wanted = {}
        for row in rows:
            wanted.setdefault(row["name"].split(":")[0], []).append(row)
        if not wanted:
            return
        remaining = len(wanted)
        for path in INSTALL_LOG_PATHS:
            if not remaining:
                break
            for line in cls._log_lines(path):
                parts = line.split(" ")
                if len(parts) < 4 or parts[2] not in ("install", "upgrade"):
                    continue
                pkg = parts[3].split(":")[0]
                rows_here = wanted.pop(pkg, None)
                if not rows_here:
                    continue
                stamp = parts[0]
                for row in rows_here:
                    row["install_date"] = stamp
                remaining -= 1
                if not remaining:
                    break
            else:
                continue
            break

    @staticmethod
    def _log_lines(path: str):
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rt", errors="replace") as fh:
                    yield from fh.read().splitlines()
            else:
                with open(path, "r", errors="replace") as fh:
                    yield from fh.read().splitlines()
        except OSError:
            return

    @staticmethod
    def _parse_tabbed(text: str):
        """(rows, excluded) -- rpm's shape. Everything rpm -qa lists is
        installed, so nothing is excluded here."""
        out = []
        for line in text.splitlines():
            parts = line.split("\t")
            if not parts or not parts[0].strip():
                continue
            out.append({
                "name":      parts[0].strip(),
                "version":   parts[1].strip() if len(parts) > 1 else "",
                "publisher": parts[2].strip() if len(parts) > 2 else "",
                "architecture": parts[3].strip() if len(parts) > 3 else "",
                "install_date": "", "scope": "system", "registry_key": "",
            })
        return out, {}

    @staticmethod
    def _parse_pacman(text: str):
        """(rows, excluded) -- `pacman -Q` prints 'name version' per line."""
        out = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            out.append({
                "name": parts[0].strip(), "version": parts[1].strip(),
                "publisher": "", "architecture": "",
                "install_date": "", "scope": "system", "registry_key": "",
            })
        return out, {}

    @staticmethod
    def _parse_apk(text: str):
        """(rows, excluded). apk prints 'name-1.2.3-r0' with no separator, so
        the version is whatever follows the last two hyphen groups."""
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            name, sep, ver = line.rpartition("-")
            name2, sep2, ver2 = name.rpartition("-")
            if sep2 and ver2 and ver2[0].isdigit():
                name, ver = name2, f"{ver2}-{ver}"
            out.append({"name": name or line, "version": ver if sep else "",
                        "publisher": "", "install_date": "", "scope": "system",
                        "registry_key": "", "architecture": ""})
        return out, {}

    # MACOS

    def _darwin(self):
        try:
            r = subprocess.run(["system_profiler", "SPApplicationsDataType", "-json"],
                               capture_output=True, text=True, timeout=CMD_TIMEOUT)
            if r.returncode == 0:
                import json
                data = json.loads(r.stdout).get("SPApplicationsDataType", [])
                return [{
                    "name": a.get("_name", ""), "version": a.get("version", ""),
                    "publisher": a.get("info", ""), "install_date": a.get("lastModified", ""),
                    "scope": "system", "registry_key": "", "architecture": "",
                } for a in data], "system_profiler"
        except Exception:
            pass
        return [], "none-found"
