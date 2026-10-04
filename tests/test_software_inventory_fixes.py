"""
tests/test_software_inventory_fixes.py — REGISTER SECTION 12, the
software_inventory round (2026-09-26).

ONE SECTION PER DEFECT (SI-1 .. SI-17), each asserted in the direction that
FAILS if the defect comes back. Every check drives the SHIPPED functions or
their own source text; none reimplements them.

The defects were measured on THIS host before they were fixed, unelevated,
by running the shipped code. The measurements are in bugfinder.md, section
"2026-09-26 — THE SOFTWARE INVENTORY ON LINUX, CAPABILITY ROUND", and the
register's section 12.

THE FIXTURES NAME NOBODY AND NO MACHINE. Account names, when needed, are read
at run time; addresses are RFC 5737 documentation ranges; the temp directory
is created here. A test that pinned one operator's account or one host's
packages would be wrong on every other box, which is the rule the leak gate
enforces.

WHAT THIS FILE CANNOT TEST HERE: a host with no dpkg, or an Alpine/pacman
host. Those branches are driven with fixtures shaped like the real output,
and each fixture's shape is quoted from `man dpkg-query` / apk / flatpak
documentation rather than from imagination.
"""

import importlib.metadata
import inspect
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
SCRATCH = _isolate_db.isolate()

# THE REAL RUNNER, CAPTURED BEFORE ANY FIXTURE TOUCHES IT. Two sections
# below patch `subprocess.run` through the module object
# (tools.software_inventory imports the module, so `sw.subprocess.run = x`
# assigns on the SHARED module), and a restore written as
# `sw.subprocess.run = subprocess.run` reads back the PATCHED value -- a
# self-assignment that silently leaves the fixture installed for every later
# section. First measured in this file's own first run: section [4]'s live
# cross-check compared against section [2]'s fake output and read 1 vs 0.
# Every restore in this file goes through REAL_RUN.
import subprocess as _subprocess_module               # noqa: E402
REAL_RUN = _subprocess_module.run

import tools.software_inventory as sw                  # noqa: E402
from tools.software_inventory import SoftwareInventory  # noqa: E402
from tools import software_inventory_linux as sil       # noqa: E402
import adapters                                         # noqa: E402
import main as main_module                              # noqa: E402
from core import settings, sensor_health                # noqa: E402

TMP = pathlib.Path(tempfile.mkdtemp(prefix="software_inventory_fixes_"))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, condition):
    check(label, bool(condition), True)


def check_in(label, needle, haystack):
    ok = needle in haystack
    print(f"  {'PASS' if ok else 'FAIL'}  [{label}]: {needle!r} in ..."
          + ("yes" if ok else f"NO, got {haystack!r}"))
    if not ok:
        fails.append(label)


def guard(fn, *a, **kw):
    """A call that can raise becomes a value, so a raising check prints FAIL
    instead of stopping every check after it (the negative-control rule: a
    subject that dies mid-file measures nothing)."""
    try:
        return fn(*a, **kw)
    except Exception as e:
        return f"RAISED {type(e).__name__}: {e}"


def fake_run(returncode=0, stdout="", stderr=""):
    class R:
        pass
    r = R()
    r.returncode = returncode
    r.stdout = stdout
    r.stderr = stderr
    return r


# ═════════════════════════════════════════════════════════════════════════
print("\n[1] SI-1 — a search could not reach past the 2000-row cut")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: on this host dpkg holds 2756 installed entries; the
# universe was truncated to 2000 rows BEFORE the search ran, so
# search="node-isexe" returned 0 rows while dpkg-query answered for the same
# package. An installed package reported as not installed.

ins = SoftwareInventory("t1")
_base = guard(ins.collect)
check_true("the live collect() answers", isinstance(_base, dict))

_cut = [s for s in _base["software"] if s["name"].lower() >= "node-isexe"]
check_true("the answer list is still bounded at MAX_ENTRIES",
           len(_base["software"]) <= sw.MAX_ENTRIES)
if _base["total"] > sw.MAX_ENTRIES:
    # RESTATED 2026-09-26, taught by the negative control: this read
    # `matched >= count`, which is TRUE for matched == count -- the exact
    # state the defect produces when the universe is cut before the search.
    # The label says ">", so it asserts ">" now.
    check_true("a cut answer says matched > count",
               _base["matched"] > _base["count"])
else:
    check_true("an uncut answer says matched == count",
               _base["matched"] == _base["count"])
check_true("total is the host's count, not the cut",
           _base["total"] >= _base["matched"])
if _base["total"] > sw.MAX_ENTRIES:
    check("truncated is True when the universe is bigger than the page",
          _base["truncated"], True)
    check_in("and the note SAYS the answer is cut",
             "THIS ANSWER IS CUT", _base["note"])
else:
    print("  SKIP  [the universe fits on one page on this host]")
    check("truncated is False when it fits", _base["truncated"], False)

# The headline, on REAL data: an installed package whose name sorts past the
# cut must still be findable by exact name.
_beyond = sorted(
    [s["name"] for s in _base["software"]], key=str.lower)[-1] \
    if len(_base["software"]) > sw.MAX_ENTRIES else None
q = guard(subprocess.run, ["dpkg-query", "-W", "-f=${binary:Package}\n"],
          capture_output=True, text=True)
_installed_names = sorted(set(q.stdout.splitlines()), key=str.lower) \
    if hasattr(q, "stdout") else []
if len(_installed_names) > sw.MAX_ENTRIES:
    _probe = _installed_names[-1].split(":")[0]
    _hit = guard(ins.collect, search=_probe)
    _hit_names = ([s.get("name", "").split(":")[0]
                   for s in _hit.get("software", [])]
                  if isinstance(_hit, dict) else [])
    # THE EXACT PACKAGE, NOT A SUBSTRING OF ANOTHER ONE. RESTATED 2026-09-26,
    # taught by the negative control: the first draft asserted
    # `_hit["count"] >= 1`, and the probe name here ('zstd') is a SUBSTRING
    # of 'libzstd1', which sorts well inside the cut -- so the check passed
    # against the PRE-fix code by finding a different package. A check that
    # cannot see the defect it was written for is worse than no check.
    check_true(f"an installed package past the cut ({_probe!r}) is searchable",
               _probe in _hit_names)
else:
    print(f"  SKIP  [this host has {len(_installed_names)} entries, "
          f"under the {sw.MAX_ENTRIES} cut]")

# ═════════════════════════════════════════════════════════════════════════
print("\n[2] SI-2 — the row named packages the way dpkg's own tools do not")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: the dpkg branch asked dpkg-query for ${Package}, the
# BARE name, while dpkg -V, dpkg-query -W and this tree's local_integrity
# (whose per-package findings are joined against this inventory) name a
# multiarch package 'name:arch'. 1075 of this host's 2792 database entries
# carry the suffix (1063 of the 2756 installed ones), so a search in dpkg's
# own spelling found nothing. The row now carries ${binary:Package} and a
# bare search still matches.
# CORRECTED 2026-09-26, in the closing pass: this read "1075 of this host's
# 2756 entries", mixing the two sets -- 1075 is across ALL 2792 database
# rows; installed-only is 1063 of 2756.

def _with_dpkg_output(rows):
    """Drive the SHIPPED collect() against a fixture, then restore the REAL
    runner. The restore names REAL_RUN, never `subprocess.run` -- reading the
    attribute back would return the FIXTURE, because sw.subprocess import
    binding IS the subprocess module (see the note at the top of this file)."""
    sw.subprocess.run = lambda *a, **k: fake_run(0, "\n".join(rows) + "\n")
    try:
        probe = SoftwareInventory("t2")
        return probe.collect()
    finally:
        sw.subprocess.run = REAL_RUN

_fake_rows = [
    "bind9-libs:amd64\t1:9.18\tISC\tamd64\tii ",
    "bash\t5.2\tUbuntu\tamd64\tii ",
]
_d2 = _with_dpkg_output(_fake_rows)
check("the fixture drives the shipped parser", _d2["count"], 2)
_d2_names = [s["name"] for s in _d2["software"]]
check_true("the row carries dpkg's own name, suffix and all",
           "bind9-libs:amd64" in _d2_names)

def _search_with_dpkg_output(rows, needle):
    sw.subprocess.run = lambda *a, **k: fake_run(0, "\n".join(rows) + "\n")
    try:
        probe = SoftwareInventory("t2s")
        probe.collect()                       # prime the cache under the fixture
        return probe.collect(search=needle)
    finally:
        sw.subprocess.run = REAL_RUN

got = _search_with_dpkg_output(_fake_rows, "bind9-libs")
check("a search in local_integrity's spelling finds it", got["count"], 1)
got2 = _search_with_dpkg_output(_fake_rows, "bind9-libs:amd64")
check("a search in dpkg-query's exact spelling finds it", got2["count"], 1)
got3 = _search_with_dpkg_output(_fake_rows, "bash")
check("a plain name still hits its plain row", got3["count"], 1)

# LIVE: the seam that matters -- a name taken from local_integrity's own
# package list must be findable through this inventory.
from tools import local_integrity as li                       # noqa: E402
_av = guard(li.dpkg_verifiable_packages)
_arch_names = [n for n in (_av.get("ok") or []) if ":" in n][:3] \
    if isinstance(_av, dict) else []
if _arch_names:
    _live_ins = SoftwareInventory("t2live")
    _live_ins.collect()
    _probe = _arch_names[0]
    _found = guard(_live_ins.collect, search=_probe)
    check_true(f"local_integrity's own spelling ({_probe!r}) is searchable",
               isinstance(_found, dict) and _found["count"] >= 1)
else:
    print("  SKIP  [no multiarch names in local_integrity's list here]")

# ═════════════════════════════════════════════════════════════════════════
print("\n[3] SI-3 — a FAILED enumeration reported ready: True")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: with every package manager missing, status() answered
# {'ready': True, 'packages': 0, 'source': 'none-found'} — green on the card.

_real_run = sw.subprocess.run
assert _real_run is REAL_RUN, "a fixture leaked past its section"
sw.subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
    FileNotFoundError("no such binary"))
try:
    dead = SoftwareInventory("t3")
    st = guard(dead.status)
    check_true("a dead enumeration no longer reports ready",
               isinstance(st, dict) and st.get("ready") is False)
    check("  and it says it could not reach the machine",
          st.get("reachable"), False)
    check_true("  with a reason, not a bare no",
               bool(st.get("last_error")))
    row = settings._module_row("software_inventory", dead)
    check_true("the CARD paints that red, not 'running.'",
               row["state"] == "problem")
    check_in("  and names the failure", "not answering", row["detail"])
    trouble = sensor_health._module_trouble("software_inventory", dead)
    check_true("the MODEL path is told too", bool(trouble) and
               "NOT ANSWERING" in str(trouble))
finally:
    sw.subprocess.run = _real_run

_ok = SoftwareInventory("t3b")
check("a WORKING enumeration still reports ready",
      guard(_ok.status).get("ready"), True)

# ═════════════════════════════════════════════════════════════════════════
print("\n[4] SI-4 — rc-state entries were published as installed software")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: `dpkg-query -W -f=${Package}...` lists every entry in the
# database, including 36 `rc` rows on this host (removed, config files left).
# The tool published them as installed. The state is now READ and filtered,
# and what was dropped is COUNTED and said.

sw.subprocess.run = lambda *a, **k: fake_run(0, (
    "containerd.io\t2.3.5\tm1\tamd64\tii \n"
    "containerd\t2.2.1\tm2\tamd64\trc \n"
    "docker.io\t27.0\tm3\tamd64\trc \n"
    "bash\t5.2\tm4\tamd64\tii \n"))
try:
    d = SoftwareInventory("t4").collect()
    names = [s["name"] for s in d["software"]]
    check_true("the installed one is listed", "containerd.io" in names)
    check_true("the rc one is NOT", "containerd" not in names)
    check_true("and neither is the other rc", "docker.io" not in names)
    check_in("the count of what was excluded is on the note",
             "NOT LISTED", d["note"])
    check_in("  and the dpkg state is named", "rc", d["note"])
finally:
    sw.subprocess.run = _real_run

# live cross-check: the count of ii rows on THIS host equals the total
q = guard(subprocess.run, ["dpkg-query", "-W",
                           "-f=${binary:Package}\t${db:Status-Abbrev}\n"],
          capture_output=True, text=True)
if hasattr(q, "stdout"):
    _ii = [l for l in q.stdout.splitlines()
           if len(l.split("\t")) > 1 and l.split("\t")[1].startswith("ii")]
    _all = [l for l in q.stdout.splitlines() if l.strip()]
    _live = guard(SoftwareInventory("t4b").collect)
    check("the live total equals dpkg's own installed count",
          _live["total"], len(_ii))
    check_true("  and is SMALLER than every row dpkg -W prints",
               len(_ii) <= len(_all))

# ═════════════════════════════════════════════════════════════════════════
print("\n[5] SI-5 — a cut LIST published the cap as the host's count")
# ═════════════════════════════════════════════════════════════════════════
# The class path: collect() bounds the ANSWER and total stays the universe.
_ins5 = SoftwareInventory("t5")
_d5 = guard(_ins5.collect)
if _d5["total"] > sw.MAX_ENTRIES:
    check("total is the host's count while count is the page",
          (_d5["count"], _d5["total"]), (sw.MAX_ENTRIES, _d5["total"]))
    check_true("matched says what the search selected",
               _d5["matched"] == _d5["total"])
else:
    print("  SKIP  [universe fits one page here]")

# The remote path: _collect_software keeps `seen` (what the host holds).
from tools import linux_monitor as lm                        # noqa: E402
mon = lm.LinuxMonitor.__new__(lm.LinuxMonitor)
mon.host = "fixture.invalid"
raw = "\n".join(f"pkg{i:03d}\t1.0\tm\tii " for i in range(12))
mon._run = lambda client, cmd: raw
mon.SOFTWARE_MAX_PACKAGES = 5
mon._software = None
mon._collect_software(None)
# READ GUARDED (.get). Under the reversion of _collect_software the `seen`
# key is absent entirely, and a check that dies of KeyError measures NOTHING
# -- the harness, correctly, reports the subject as crashed and sends the
# round after the module instead of after the check. This prints FAIL.
check("the remote path keeps the HOST's count when the list is cut",
      mon._software.get("seen"), 12)
check("  and count is the kept rows", mon._software.get("count"), 5)
check("  and truncated is True", mon._software.get("truncated"), True)

# ═════════════════════════════════════════════════════════════════════════
print("\n[6] SI-6 — 'no package manager answered' and 'no software' were the same answer")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: the linux module's get_status answered available: True
# with an empty managers list, and the adapter reported ready: True. An
# empty inventory is now a NAMED failure with the managers it tried.

_real_detect = sil.detect_package_managers
sil.detect_package_managers = lambda: []
try:
    st = guard(sil.get_status)
    check("no managers at all is available: False", st.get("available"), False)
    check_true("  with a sentence saying why",
               bool(st.get("reason")) and "no package manager" in st["reason"])
    ad = adapters.LinuxSoftwareInventory("t6")
    check("the adapter passes that through, not a fabricated ready",
          guard(ad.status).get("available"), False)
finally:
    sil.detect_package_managers = _real_detect

_ad = adapters.LinuxSoftwareInventory("t6b")
check_true("with managers present, available is True",
           guard(_ad.status).get("available") is True)
_six = _ad.collect()
check_in("the adapter's miss-is-not-a-clean-machine sentence travels",
         "a miss is close to meaningless", _six["note"])

# ═════════════════════════════════════════════════════════════════════════
print("\n[7] SI-7 — the adapter's search could not find a PUBLISHER")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: search="Ubuntu Developers" returned 0 rows through the
# adapter and 1782 through the class path — two backends, two answers to
# one question the tool description promises (filter by publisher).

def _adapter_with(rows):
    """Build an adapter and DRIVE it while the fixture is installed; the
    restore is scoped to the whole drive, not to the construction (the
    fixture that is restored before the code runs measures nothing -- the
    adapter collects lazily on the first collect() call)."""
    real_all = sil.get_all_software
    sil.get_all_software = lambda: {"packages": rows, "summary": {},
                                    "managers_detected": ["fixture"]}
    try:
        a = adapters.LinuxSoftwareInventory("t7")
        return a.collect(search="Some Publisher"), a
    finally:
        sil.get_all_software = real_all


_fixture = [{"name": "bash", "version": "5.2", "publisher": "Some Publisher",
             "description": "the shell", "manager": "dpkg"},
            {"name": "zsh", "version": "5.9", "publisher": "Other",
             "description": "", "manager": "dpkg"}]
_hit, _a7 = _adapter_with(_fixture)
check("a publisher search finds its rows through the adapter",
      _hit["count"], 1)
check("  and not the other one", _hit["software"][0]["name"], "bash")

# the same adapter, LIVE: publisher search must now agree with the class path
_live_ad = adapters.LinuxSoftwareInventory("t7b")
_live_ad.collect()
_pub = _live_ad.collect(search="Ubuntu Developers")
print(f"  (live publisher search through the adapter: "
      f"{_pub['count']} row(s))")
check_true("a real publisher search is not zero through the adapter",
           _pub["count"] > 0)

# ═════════════════════════════════════════════════════════════════════════
print("\n[8] SI-8 — the row did not carry the ARCHITECTURE")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: no row on either path carried an architecture field,
# while both the Windows path (registry) and the twin (dpkg -l) had one.
_r8 = SoftwareInventory("t8")
_d8 = guard(_r8.collect)
check_true("every live row carries architecture",
           all("architecture" in s for s in _d8["software"]))
check_true("  and at least one is a real architecture string",
           any(s["architecture"] for s in _d8["software"]))

sw.subprocess.run = lambda *a, **k: fake_run(0, (
    "bash\t5.2\tUbuntu\tamd64\tii \n"))
try:
    _d8b = SoftwareInventory("t8b").collect()
    check("the parser reads the architecture field",
          _d8b["software"][0]["architecture"], "amd64")
finally:
    sw.subprocess.run = _real_run

# ═════════════════════════════════════════════════════════════════════════
print("\n[9] SI-9 — the twin's apk regex matched NOTHING")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: against every real apk line ('busybox-1.36.1-r5' etc.)
# the shipped regex matched nothing, so an Alpine host would report an empty
# inventory with no error. The fixture is alpine's own printed shape.

_real_cmd = sil._run_command
sil._run_command = lambda cmd, timeout=30: (
    (True, "busybox-1.36.1-r5\nzlib-1.3.1-r0\nmusl-1.2.4_git20230717-r4\n")
    if cmd[:2] == ["apk", "info"] else (False, "no fixture"))
try:
    rows = guard(sil.get_apk_packages)
    check("apk lines produce rows", len(rows) if isinstance(rows, list) else rows, 3)
    check("  the name is right", rows[0]["name"], "busybox")
    check("  and the version keeps the -r suffix", rows[0]["version"],
          "1.36.1-r5")
    check("  a long git-hash version survives", rows[2]["version"],
          "1.2.4_git20230717-r4")
finally:
    sil._run_command = _real_cmd

# ═════════════════════════════════════════════════════════════════════════
print("\n[10] SI-10 — the twin's dpkg parse was human-formatted output")
# ═════════════════════════════════════════════════════════════════════════
# The twin now asks dpkg-query for its own format and reads the per-row
# state; rc rows are dropped (measured 36 on this host) and the maintainer
# and summary both come from named fields.
sil._run_command = lambda cmd, timeout=30: (
    (True, "bash\t5.2\tamd64\tUbuntu Devs\tshell\tii \n"
           "gone-pkg\t1.0\tamd64\tsomeone\tremoved\trc \n"
           "half\t2.0\tamd64\tsomeone\tunfinished\tiU \n")
    if cmd[0] == "dpkg-query" else (False, "no fixture"))
try:
    twin_rows = guard(sil.get_dpkg_packages)
    check("the dpkg parse keeps installed rows", len(twin_rows), 1)
    check("  with the summary as description", twin_rows[0]["description"],
          "shell")
    check("  and the maintainer as publisher", twin_rows[0]["publisher"],
          "Ubuntu Devs")
finally:
    sil._run_command = _real_cmd

_live_twin = guard(sil.get_dpkg_packages)
check("live: the twin drops rc rows the old parse kept",
      all("containerd" != p["name"] for p in
          (_live_twin if isinstance(_live_twin, list) else [])), True)

# ═════════════════════════════════════════════════════════════════════════
print("\n[11] SI-11 — the python-package source ran a DIFFERENT interpreter")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: `pip list` as a subprocess cost 8.4 s and inventories
# whatever `pip` is first on PATH. importlib.metadata answers for THIS
# process in 1.5 s, and first-wins in sys.path order is the copy `import X`
# resolves to.

_t0 = __import__("time").time()
py_rows = guard(sil.get_python_packages)
_elapsed = __import__("time").time() - _t0
check_true("the twin's python rows come from importlib.metadata",
           isinstance(py_rows, list) and len(py_rows) > 0)
check_true(f"  and it is not a subprocess anymore (took {_elapsed:.2f}s)",
           _elapsed < 6.0)
_meta = {p["name"].lower() for p in py_rows}
_direct = {(d.metadata["Name"] or "").lower()
           for d in importlib.metadata.distributions()}
check_true("  the names match the process's own distributions",
           _meta.issubset(_direct | {""}))

# install_date capability on the class path (SI-11's sibling for dpkg)
_dates = SoftwareInventory("t11").collect()
_dated = [s for s in _dates["software"] if s["install_date"]]
check_true("install_date is filled from dpkg's log where a line exists",
           len(_dated) > 0)
check_true("  and every filled value looks like a date",
           all(re.match(r"^\d{4}-\d{2}-\d{2}$", s["install_date"])
               for s in _dated))

# ═════════════════════════════════════════════════════════════════════════
print("\n[12] SI-12 — the boot's software_inventory arm accepted ANY value")
# ═════════════════════════════════════════════════════════════════════════
# The HI-12 typo door, one role over: `sensor_backends:
# {"software_inventory": "tools.software_inventory_lx"}` boots the Linux
# module in silence without the guard.
check_in("the accepted names are declared in one place",
         "_SOFTWARE_INVENTORY_BACKENDS", inspect.getsource(main_module))
check_true("the default is in that set",
           "tools.software_inventory" in main_module._SOFTWARE_INVENTORY_BACKENDS)
check_true("a misspelling is NOT in that set",
           "tools.software_inventory_lx" not in
           main_module._SOFTWARE_INVENTORY_BACKENDS)
_boot_src = inspect.getsource(main_module._load_modules)
check_in("the boot REFUSES an unrecognised value",
         "config sensor_backends.software_inventory", _boot_src)

# ═════════════════════════════════════════════════════════════════════════
print("\n[13] SI-13 — snap's 'No snaps are installed yet.' became a PACKAGE")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: the shipped parser read every line after the header, so
# snapd's own sentence produced a row named 'No' at version 'snaps'.

sil._run_command = lambda cmd, timeout=30: (
    (True, "Name  Version  Rev  Tracking  Publisher  Notes\n"
           "No snaps are installed yet. Try 'snap find' to see available "
           "snaps.\n") if cmd[:2] == ["snap", "list"] else (False, "x"))
try:
    check("the sentence does not become a package",
          guard(sil.get_snap_packages), [])
finally:
    sil._run_command = _real_cmd

sil._run_command = lambda cmd, timeout=30: (
    (True, "Name  Version  Rev  Tracking       Publisher   Notes\n"
           "core22  20240408  1380  latest/stable  canonical**  base\n")
     if cmd[:2] == ["snap", "list"] else (False, "x"))
try:
    rows = guard(sil.get_snap_packages)
    check("a real snap row still parses", len(rows), 1)
    check("  with its name", rows[0]["name"], "core22")
finally:
    sil._run_command = _real_cmd

# ═════════════════════════════════════════════════════════════════════════
print("\n[14] SI-14 — flatpak published a display NAME under the key `id`")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: {'id': 'WhatsApp for Linux'} — the display name where an
# application ID belongs, and no version anywhere.
sil._run_command = lambda cmd, timeout=30: (
    (True, "com.github.eneshecan.WhatsAppForLinux\tWhatsApp for Linux\t"
           "1.6.5\tflathub\n") if cmd[:2] == ["flatpak", "list"] else (False, "x"))
try:
    apps = guard(sil.get_flatpak_applications)
    check("flatpak rows carry the real application ID", apps[0]["id"],
          "com.github.eneshecan.WhatsAppForLinux")
    check("  the display name is kept, named as one", apps[0]["name"],
          "WhatsApp for Linux")
    check("  and the version is not lost", apps[0]["version"], "1.6.5")
finally:
    sil._run_command = _real_cmd

# ═════════════════════════════════════════════════════════════════════════
print("\n[15] SI-15 — a host with security updates answered updates_available: False")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: 55 upgradable / 34 in a security pocket on this host,
# and the flag was set in the rpm/dnf branch only, so a Debian host could
# never say it had anything.

sil._run_command = lambda cmd, timeout=30: (
    (True, "Listing...\n"
           "curl/noble-updates,noble-security 8.5.0-2ubuntu10.15 amd64 "
           "[upgradable from: 8.5.0-2ubuntu10.13]\n"
           "code/stable 1.139.1 amd64 [upgradable from: 1.138.0]\n")
     if cmd[:3] == ["apt", "list", "--upgradable"] else (False, "x"))
try:
    cu = guard(sil.check_security_updates)
    check("an apt host with updates says so", cu["updates_available"], True)
    check("  the total is counted", cu["by_manager"].get("apt"), 2)
    check("  the security pocket is counted separately",
          cu["by_manager"].get("apt-security"), 1)
    check("  and the security row is NAMED with both versions",
          (cu["security_updates"][0]["name"],
           cu["security_updates"][0]["current"]),
          ("curl", "8.5.0-2ubuntu10.13"))
finally:
    sil._run_command = _real_cmd

# ═════════════════════════════════════════════════════════════════════════
print("\n[16] SI-16 — the twin's status was a fabricated available: True")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: {'available': True, 'managers': [], 'last_inventory':
# None} on a host with no package database, and `last_inventory` was a field
# nothing ever wrote.
sil.detect_package_managers = lambda: []
try:
    st = guard(sil.get_status)
    check("no managers means available: False", st.get("available"), False)
    check_true("  the dead last_inventory field is gone",
               "last_inventory" not in st)
finally:
    sil.detect_package_managers = _real_detect
_live_st = guard(sil.get_status)
check("a real host still reports available: True", _live_st.get("available"), True)

# ═════════════════════════════════════════════════════════════════════════
print("\n[17] SI-17 — three dead/trap functions in the twin")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: find_packages_by_name raised on '[' and re-enumerated
# every manager per call (2.4 s); get_vulnerable_packages returned [] as a
# "placeholder"; monitor_once claimed "searched": True while nothing
# searched. All three had ZERO callers; all three now raise a tombstone.

for fn_name in ("find_packages_by_name", "get_vulnerable_packages",
                "monitor_once"):
    fn = getattr(sil, fn_name)
    try:
        fn("x") if fn_name == "find_packages_by_name" else fn()
        check(f"{fn_name} refuses loudly", "did not raise", "raises")
    except NotImplementedError as e:
        check_true(f"{fn_name} raises its own tombstone",
                   "removed 2026-09-26" in str(e))
    except Exception as e:
        check(f"{fn_name} raises NotImplementedError",
              f"{type(e).__name__}: {e}", "NotImplementedError")

# the helper itself: a malformed command list is a VALUE, not a raise
_junk = guard(sil._run_command, [None])
check_true("a malformed command list comes back as a VALUE",
           isinstance(_junk, tuple) and _junk[0] is False)
check_true("  and the reason names the real problem",
           "NoneType" in str(_junk[1]) or "expected" in str(_junk[1]))

# ═════════════════════════════════════════════════════════════════════════
print("\n[18] SI-18 — the remote path kept DUPLICATE rows and a cut list "
      "published the cap")
# ═════════════════════════════════════════════════════════════════════════
# The remote _collect_software kept a row whose (name, version) a previous
# row already held (measured on this fixture: three lines, three rows, the
# duplicate kept) and counted a cut list as the whole host (covered in [5]);
# the duplicate collapse is asserted here on the same fake client shape.
# READS GUARDED (.get): the reversion drops the keys entirely, so an
# unguarded read dies of KeyError and measures nothing.
#
# CORRECTED 2026-09-26, in the closing pass: this heading read "the remote
# path dropped the FIRST row and kept dupes". The "dropped the FIRST row"
# half was never measured -- it was an inherited claim -- and the pre-fix
# body, driven by this fixture in the negative control, keeps every line it
# reads (three lines in, three rows out, the first row present). The defect
# that IS measured is the duplicate and the cap arithmetic, and the heading
# now says only those.
mon2 = lm.LinuxMonitor.__new__(lm.LinuxMonitor)
mon2.host = "fixture.invalid"
mon2._run = lambda client, cmd: ("libfoo\t1.0\tm\tii \n"
                                 "libfoo\t1.0\tm\tii \n"
                                 "libbar\t2.0\tm\tii \n")
mon2._software = None
mon2.SOFTWARE_MAX_PACKAGES = 5000
mon2._collect_software(None)
check("a duplicate row is collapsed", mon2._software.get("count"), 2)
check("  seen counts what the host listed", mon2._software.get("seen"), 2)

# ═════════════════════════════════════════════════════════════════════════
print("\n[19] FOUND CLEAN, re-asserted so a regression shows")
# ═════════════════════════════════════════════════════════════════════════
check_true("the module still refuses to run as anything but read-only",
           # CORRECTED 2026-09-26, in the closing pass: this ended
           # `in inspect.getsource(sil) or True`, which is TRUE whatever the
           # module says. The sentence IS in the file (line 7), measured, so
           # dropping the escape hatch makes this a check that can fail
           # instead of decoration that reads as a check.
           "Read-only. Does not modify system state"
           in inspect.getsource(sil))
check_true("the Windows class path still exists and answers",
           isinstance(SoftwareInventory("t19").collect(), dict))
_r19 = SoftwareInventory("t19b").collect()
check("its rows still carry name/version/publisher",
      set(("name", "version", "publisher")).issubset(_r19["software"][0]), True)
check_true("no subprocess is spawned with shell=True in the class module",
           "shell=True" not in inspect.getsource(sw))
check_true("  nor in the twin",
           "shell=True" not in inspect.getsource(sil))
check_true("the class module still says matching is deliberately not done",
           "DELIBERATELY NOT A MATCHER" in inspect.getsource(sw))
check_true("the tool description still warns a miss means little",
           "a miss is close to meaningless"
           in inspect.getsource(__import__("core.tool_registry", fromlist=["x"])))
_tot = SoftwareInventory("t19c").collect()
check_true("total >= count on every live answer",
           _tot["total"] >= _tot["count"])

# ═════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
print(f"{len(fails)} failure(s)")
if fails:
    print("FAILURES:", fails)
    sys.exit(1)
print("ALL CHECKS PASSED")
sys.exit(0)
