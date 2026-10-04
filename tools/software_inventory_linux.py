# tools/software_inventory_linux.py
# AgentalSec Linux - Software inventory via dpkg, rpm, apk, pacman
#
# Linux equivalent of Windows software_inventory.py
# Enumerates installed packages across major package managers
#
# Read-only. Does not modify system state.

import importlib.metadata
import importlib.util
import logging
import shutil
import subprocess
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _run_command(cmd: list, timeout: int = 30) -> tuple[bool, str]:
    """
    Run a command and return (success, output).

    THE EXCEPT ARM MUST NOT RAISE. Measured 2026-09-26 (register section 12):
    `_run_command([None])` left this helper as
    `TypeError: sequence item 0: expected str instance, NoneType found`,
    because the log line joined the command with ' '.join() -- the HI-13
    shape one module over. Every caller here is written for a (bool, str)
    return, so a malformed command list now comes back as a VALUE like any
    other failure, and stderr is kept rather than discarded, so 'refused' and
    'answered nothing' can be told apart.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError,
            TypeError, ValueError) as e:
        logger.debug(f"Command failed: {cmd!r} - {e}")
        return False, str(e)
    if result.returncode == 0:
        return True, result.stdout
    return False, (result.stderr or f"exited {result.returncode}")


def get_dpkg_packages() -> list[dict]:
    """
    Get installed packages via dpkg (Debian/Ubuntu).

    Returns list of dicts with package info.

    MEASURED 2026-09-26 (register section 12, SI-10): the shipped parse was
    `dpkg -l` split on whitespace with a `startswith('ii')` filter. On this
    host that parse happened to agree with the machine-readable answer
    (both 2756 rows, zero name or version differences, stdout piped), so
    this change is a CAPABILITY ADOPTION rather than a repair -- but the
    question is asked of dpkg's own format now, because `dpkg -l` sizes its
    columns for a human at a terminal while this output never is, and the
    row can carry the fields the old shape could not (the maintainer went
    into description-adjacent prose and the state is now READ per row rather
    than inferred from a two-letter prefix). The status test is kept and
    made explicit: anything dpkg does not call installed-and-configured
    (`rc` = removed with config files left behind, `iU`/`iF` = unfinished)
    is NOT software on this machine.
    """
    packages = []

    success, output = _run_command(
        ["dpkg-query", "-W",
         "-f=${binary:Package}\t${Version}\t${Architecture}\t${Maintainer}"
         "\t${binary:Summary}\t${db:Status-Abbrev}\n"])
    if not success:
        return packages

    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        name, version, arch, maintainer, summary, status = \
            (p.strip() for p in parts[:6])
        if not name or status[:2] != "ii":
            continue
        packages.append({
            "name": name,
            "version": version,
            "architecture": arch,
            "description": summary,
            "publisher": maintainer,
            "manager": "dpkg",
        })

    return packages


def get_rpm_packages() -> list[dict]:
    """
    Get installed packages via rpm (RHEL/CentOS/Fedora).
    
    Returns list of dicts with package info.
    """
    packages = []
    
    success, output = _run_command(["rpm", "-qa", "--qf", "%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SUMMARY}"])
    if not success:
        return packages
    
    for line in output.strip().split('\n'):
        parts = line.split('|')
        if len(parts) >= 5:
            packages.append({
                "name": parts[0],
                "version": parts[1],
                "release": parts[2],
                "architecture": parts[3],
                "description": parts[4],
                "manager": "rpm",
            })
    
    return packages


def get_apk_packages() -> list[dict]:
    """
    Get installed packages via apk (Alpine Linux).

    Returns list of dicts with package info.

    MEASURED 2026-09-26 (register section 12, SI-9): the regex here was
    r'^(.+)-(\\d+[\\d\\.]*-\\d+)$', and against every real apk package line
    ('busybox-1.36.1-r5', 'zlib-1.3.1-r0', 'musl-1.2.4_git20230717-r4',
    'ca-certificates-20240226-r0') it matched NOTHING, so this function
    returned an empty list on a real Alpine host while reporting success.
    The class module beside it (tools/software_inventory.py) parses these
    lines by splitting on the last two hyphens; that method is kept here
    verbatim so the two inventories cannot disagree again.
    """
    packages = []

    success, output = _run_command(["apk", "info", "-v"])
    if not success:
        return packages

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # apk prints "name-1.2.3-r0"; the version is whatever follows the
        # last two hyphen groups.
        name, _sep, ver = line.rpartition("-")
        name2, sep2, ver2 = name.rpartition("-")
        if sep2 and ver2 and ver2[0].isdigit():
            name, ver = name2, f"{ver2}-{ver}"
        packages.append({
            "name": name or line,
            "version": ver if _sep else "",
            "description": "",
            "manager": "apk",
        })

    return packages


def get_pacman_packages() -> list[dict]:
    """
    Get installed packages via pacman (Arch Linux).
    
    Returns list of dicts with package info.
    """
    packages = []
    
    success, output = _run_command(["pacman", "-Q"])
    if not success:
        return packages
    
    for line in output.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 2:
            packages.append({
                "name": parts[0],
                "version": parts[1],
                "description": "",
                "manager": "pacman",
            })
    
    return packages


def get_flatpak_applications() -> list[dict]:
    """
    Get installed Flatpak applications.

    MEASURED 2026-09-26 (register section 12, SI-12): the shipped call was
    `flatpak list --app`, whose first column is the DISPLAY NAME, and it was
    published under the key `id`. On this host the one installed app came
    back as {'id': 'WhatsApp for Linux'} -- a name, no version, and an
    application ID the operator cannot paste into `flatpak run`. The
    platform's own column selection answers this properly:
    application (the ID), name, version, origin.
    """
    apps = []

    success, output = _run_command(
        ["flatpak", "list", "--app", "--columns=application,name,version,origin"])
    if not success:
        return apps

    for line in output.splitlines():
        if not line.strip():
            continue
        parts = (line.split("\t") + ["", "", ""])[:4]
        app_id, name, version, origin = (p.strip() for p in parts)
        if not app_id and not name:
            continue
        apps.append({
            "id": app_id or name,
            "name": name or app_id,
            "version": version,
            "publisher": origin,
            "manager": "flatpak",
            "type": "flatpak",
        })

    return apps


def get_snap_packages() -> list[dict]:
    """
    Get installed snap packages.

    MEASURED 2026-09-26 (register section 12, SI-13): on a host with snapd
    installed and nothing from the store, `snap list` prints its header and
    the sentence "No snaps are installed yet. Try 'snap find' to see
    available snaps." The shipped parser read every line after the header as
    a package, so that sentence became a row named 'No' at version 'snaps'
    -- an invented package, which is the worst thing an inventory can
    produce. A line is now accepted only when it has at least three fields
    AND its first field is not a sentence word: real snap names contain no
    spaces, so the test is whitespace-free plus the header/footer words.
    """
    packages = []

    success, output = _run_command(["snap", "list"])
    if not success:
        return packages

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        if name.lower() in ("name", "no"):        # header / "No snaps ..."
            continue
        if any(ch.isspace() for ch in name):
            continue
        if name.endswith("."):                     # a sentence's last word
            continue
        packages.append({
            "name": name,
            "version": parts[1],
            "revision": parts[2],
            "manager": "snap",
            "type": "snap",
        })

    return packages


def get_python_packages() -> list[dict]:
    """
    Get installed Python packages for THE INTERPRETER THAT RUNS THIS APP.

    MEASURED 2026-09-26 (register section 12, SI-11):
      * the shipped call was bare `pip list`, which runs whatever `pip` is
        first on PATH -- on a PEP 668 host that may be a different
        interpreter from this app's own, and the two inventories can
        disagree with no sign of why;
      * it cost 8.4 s as a subprocess. importlib.metadata reads the same
        installed-distribution metadata IN-PROCESS: 416 rows, 1.5 s, and
        the version it reports is the one this process's imports actually
        resolve to. One distribution can be present in several site
        directories (this host: three copies of blinker), and first-wins in
        sys.path order is the one `import blinker` gets; a dict built
        last-wins would name a shadowed copy.
    """
    packages = []
    try:
        seen = set()
        for dist in importlib.metadata.distributions():
            try:
                name = (dist.metadata["Name"] or "").strip()
            except Exception:
                continue
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            packages.append({
                "name": name,
                "version": (dist.version or "").strip(),
                "manager": "pip",
                "type": "python",
            })
    except Exception as e:
        logger.debug(f"importlib.metadata failed: {e}")
    packages.sort(key=lambda p: p["name"].lower())
    return packages


def detect_package_managers() -> list[str]:
    """
    Detect which package managers are available.

    MEASURED 2026-09-26 (register section 12, SI-14): the old shape probed
    a hardcoded /usr/bin path per manager and then ran `pip --version` as a
    SUBPROCESS -- 2.4-2.7 s every call, on a function `get_status()` calls
    each time the readiness card refreshes, for an answer that is about
    binaries that do not move. shutil.which honours PATH (the platform's
    own answer, and it finds the same binaries the collection functions will
    exec), and pip's presence for THIS interpreter is an import test rather
    than a subprocess: same answer, 0.0004 s.
    """
    managers = []

    for name, binary in (("dpkg", "dpkg-query"), ("rpm", "rpm"),
                         ("apk", "apk"), ("pacman", "pacman"),
                         ("flatpak", "flatpak"), ("snap", "snap")):
        if shutil.which(binary):
            managers.append(name)

    # pip IS this interpreter's ability to see distributions, which
    # get_python_packages reads through importlib.metadata.
    try:
        if importlib.util.find_spec("pip") is not None:
            managers.append("pip")
    except (ImportError, ValueError):
        pass

    return managers


def get_all_software() -> dict:
    """
    Enumerate all installed software across all package managers.
    
    Returns comprehensive dict with packages by manager.
    """
    start_time = datetime.now(timezone.utc)
    
    managers = detect_package_managers()
    logger.info(f"Detected package managers: {managers}")
    
    result = {
        "timestamp": start_time.isoformat(),
        "managers_detected": managers,
        "packages": [],
        "summary": {},
    }
    
    # Collect from each manager
    if "dpkg" in managers:
        dpkg_packages = get_dpkg_packages()
        result["packages"].extend(dpkg_packages)
        result["summary"]["dpkg"] = len(dpkg_packages)
    
    if "rpm" in managers:
        rpm_packages = get_rpm_packages()
        result["packages"].extend(rpm_packages)
        result["summary"]["rpm"] = len(rpm_packages)
    
    if "apk" in managers:
        apk_packages = get_apk_packages()
        result["packages"].extend(apk_packages)
        result["summary"]["apk"] = len(apk_packages)
    
    if "pacman" in managers:
        pacman_packages = get_pacman_packages()
        result["packages"].extend(pacman_packages)
        result["summary"]["pacman"] = len(pacman_packages)
    
    if "flatpak" in managers:
        flatpak_apps = get_flatpak_applications()
        result["packages"].extend(flatpak_apps)
        result["summary"]["flatpak"] = len(flatpak_apps)
    
    if "snap" in managers:
        snap_packages = get_snap_packages()
        result["packages"].extend(snap_packages)
        result["summary"]["snap"] = len(snap_packages)
    
    if "pip" in managers:
        pip_packages = get_python_packages()
        result["packages"].extend(pip_packages)
        result["summary"]["pip"] = len(pip_packages)
    
    # Total count
    result["summary"]["total"] = len(result["packages"])
    result["elapsed_seconds"] = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    logger.info(f"Software inventory: {result['summary']['total']} packages from {len(managers)} managers")
    
    return result


def find_packages_by_name(name_pattern: str) -> list[dict]:
    """
    Search for packages matching a name pattern.

    REMOVED 2026-09-26 (register section 12, SI-17). The tombstone stays so a
    reader who finds the name in an old note learns what happened to it.
    Three functions lived here with ZERO callers anywhere in the tree:

      find_packages_by_name   raised on a plausible input ('[' died of an
                              unterminated character set -- a raw regex
                              exception out of a module whose other public
                              functions return values), and re-enumerated
                              EVERY package manager on every call (2.4 s
                              measured) to answer a question the adapter
                              already answers in its cached
                              collect(search=...).
      get_vulnerable_packages returned [] with a comment saying it was a
                              placeholder for future integration. A function
                              NAMED for a vulnerability answer that returns
                              an empty list, reachable by anything that
                              imports the module, is a machine-wide clean
                              bill waiting to be wired to a page -- and the
                              module header this file carries states in
                              capitals that matching is deliberately NOT
                              done here.
      monitor_once            a sensor-shaped wrapper ("searched": True --
                              nothing searched) that nothing ever called;
                              the adapter owns the one inventory path.

    The adapter (adapters.LinuxSoftwareInventory) is the surviving answer for
    all three questions, and it is the one the tool registry reaches.
    """
    raise NotImplementedError(
        "find_packages_by_name was removed 2026-09-26 (register section 12, "
        "SI-17): it had zero callers and raised on plain regex input. Use "
        "LinuxSoftwareInventory.collect(search=...) (adapters.py), which "
        "searches the cached inventory and answers in a value."
    )


def check_security_updates() -> dict:
    """
    Check for available updates, and which of them come from a SECURITY
    pocket.

    MEASURED 2026-09-26 (register section 12, SI-15): on this host
    `apt list --upgradable` listed 55 upgradable packages, 34 of them in a
    `-security` pocket, and this function answered `updates_available:
    False` with an empty `security_updates` list -- the flag was set in the
    rpm/dnf branch only, so a Debian host could never tell anyone it had
    updates at all, let alone security ones. The pocket is the archive's OWN
    classification (`curl/noble-updates,noble-security` in the first field),
    so the security subset is READ rather than guessed, and the version in
    hand and the version offered are both carried.
    """
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "updates_available": False,
        "security_updates": [],
        "by_manager": {},
    }

    managers = detect_package_managers()

    # dpkg/apt
    if "dpkg" in managers:
        success, output = _run_command(["apt", "list", "--upgradable"])
        if success and output.strip():
            total = 0
            security = 0
            for line in output.splitlines():
                if not line.strip() or line.startswith("Listing"):
                    continue
                fields = line.split()
                if len(fields) < 2:
                    continue
                source = fields[0]
                name, _, pockets = source.partition("/")
                total += 1
                if any(p.strip().endswith("-security")
                       for p in pockets.split(",")):
                    security += 1
                    current = ""
                    marker = "[upgradable from:"
                    if marker in line:
                        current = (line.split(marker, 1)[1]
                                   .strip().rstrip("]").strip())
                    result["security_updates"].append({
                        "name": name,
                        "version": fields[1],
                        "current": current,
                        "pockets": pockets,
                    })
            result["by_manager"]["apt"] = total
            result["by_manager"]["apt-security"] = security
            result["updates_available"] = total > 0

    # rpm/dnf
    if "rpm" in managers:
        success, output = _run_command(["dnf", "check-update", "--security"])
        if success and output.strip():
            updates = [line for line in output.strip().split('\n') if line]
            result["by_manager"]["dnf-security"] = len(updates)
            result["updates_available"] = True

    # apk
    if "apk" in managers:
        success, output = _run_command(["apk", "upgrade", "--simulate"])
        if success and output.strip():
            updates = [line for line in output.strip().split('\n') if line]
            result["by_manager"]["apk"] = len(updates)

    return result


def get_vulnerable_packages() -> list[dict]:
    """
    REMOVED 2026-09-26 (register section 12, SI-17), same round as
    find_packages_by_name above. This returned [] with a comment calling
    itself a placeholder for future integration. It never integrated and it
    never had a caller; the danger is the NEXT reader wiring the obvious
    name to a page, where an empty list renders as "no vulnerable packages
    on this host". The module's own header explains why matching belongs to
    the model (query_runbook + web_search) and not to Python here.
    """
    raise NotImplementedError(
        "get_vulnerable_packages was removed 2026-09-26 (register section "
        "12, SI-17): a placeholder that returned an empty list. Vulnerability "
        "matching is deliberately NOT done in this tree, see the module "
        "header of tools/software_inventory.py."
    )


def monitor_once() -> dict:
    """
    REMOVED 2026-09-26 (register section 12, SI-17), same round and same
    reason as the two above: zero callers in the tree, and its only
    sensor-shaped word ("searched": True) claimed a search nothing performed.
    The adapter is the single inventory path.
    """
    raise NotImplementedError(
        "monitor_once was removed 2026-09-26 (register section 12, SI-17): "
        "zero callers. Use adapters.LinuxSoftwareInventory.collect()."
    )


def get_status() -> dict:
    """
    Current software inventory status, and it must not claim a machine was
    READ when no package manager answered.

    MEASURED 2026-09-26 (register section 12, SI-16): this returned
    {'available': True, 'managers': []} on a host with no package database
    at all -- the HI-8 shape (a module that could not read the machine
    still reporting healthy), and its `last_inventory: None` was a field
    with a comment saying it "would track last run time" that nothing ever
    wrote. A key is now present only when it was read, and the empty case
    says WHY it is empty.
    """
    managers = detect_package_managers()

    if not managers:
        why = ("no package manager is present on this host, so nothing here "
               "is known about what is installed. An empty inventory is this "
               "fact, not a machine with no software.")
        return {
            "available": False,
            # `reason` is where settings._module_row reads the detail line
            # from while `note` rides beside it; both carry the sentence so
            # the card and the model path say the same thing.
            "reason": why,
            "managers": [],
            "note": why,
        }

    return {
        "available": True,
        "managers": managers,
    }
