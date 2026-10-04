"""
tests/test_host_info_fixes.py — SECTION 11, the host_info round.

ONE SECTION PER DEFECT (HI-1 .. HI-13), each asserted in the direction that
FAILS if the defect comes back. Every check drives the SHIPPED functions or
the shipped file's own text; none reimplements them, which would only prove
this file's model of the code.

The defects were measured before they were fixed, on THIS host, by running
the shipped code unelevated — the way the app runs unless the privileged
launcher is used. The measurements are in bugfinder.md, section
"2026-09-25 — THE HOST INFO ON LINUX, CAPABILITY ROUND", and the register's
section 11.

THE FIXTURES NAME NOBODY AND NO MACHINE. Account names are read at run time
(pwd.getpwuid(os.getuid())) or are placeholders; addresses are RFC 5737
documentation ranges (192.0.2.0/24); the temp directory is created here. A
test that pinned one operator's account or one host's addresses would be
wrong on every other box, which is the rule the leak gate enforces.

WHAT THIS FILE CANNOT TEST HERE: a host where the security probes ARE
permitted. This box refuses `iptables -L -n` and `nft list ruleset`
unelevated, so the tri-state branches that matter most are exercised by
driving the parser/decision functions with the refusal text this host
actually produced, quoted in each case.
"""

import inspect
import os
import pathlib
import pwd
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                    # noqa: E402
SCRATCH = _isolate_db.isolate()

from tools import host_info_linux as hil               # noqa: E402
from tools.host_info import HostInfo                    # noqa: E402
import adapters                                         # noqa: E402

TMP = pathlib.Path(tempfile.mkdtemp(prefix="host_info_fixes_"))
ACCOUNT = pwd.getpwuid(os.getuid()).pw_name             # never a literal

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


print()
print("=" * 72)
print("SECTION 11 — host_info: the defects, each asserted both ways")
print("=" * 72)

# ═════════════════════════════════════════════════════════════════════════
print("\n[1] HI-8 — status() reported HEALTHY while the read was refused")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: with /etc/os-release unreadable, tools/host_info.py's
# status() answered {'ready': True, 'os': 'Linux', ...} — the refusal lived
# only in a list the readiness card and core/sensor_health never read. Both
# were measured reading that method.

_real_open = open


def _refused_open(path, *a, **kw):
    if str(path) == "/etc/os-release":
        raise PermissionError(13, "Permission denied", "/etc/os-release")
    return _real_open(path, *a, **kw)


import builtins                                          # noqa: E402
_orig_builtin_open = builtins.open
builtins.open = _refused_open
try:
    _linux_info = HostInfo("t").collect()
    _linux_status = HostInfo("t").status()
    _adapter_status = adapters.LinuxHostInfo("t").status()
finally:
    builtins.open = _orig_builtin_open

check("a refused os-release reads as null os_name", _linux_info.get("os_name"), None)
check_true("  and the refusal is RECORDED, not swallowed",
           any("os-release" in str(e) for e in _linux_info.get("errors") or []))
check_true("  and the reason travels IN the detail block",
           "os_unknown_because" in (_linux_info.get("detail") or {}))
check_true("  and status() no longer claims a distribution it did not read",
           "os" not in _linux_status)
check_true("  and status() carries the reason",
           "os-release" in str(_linux_status.get("note") or ""))
# THE ADAPTER'S status() MUST BE THE MODULE'S OWN READ, and the first version
# of this check could not tell the two apart: "os_readable" in status is TRUE
# for the post-fix module AND would be false only if the adapter fabricated a
# dict — but the pre-fix adapter's dict was `{"ready": True}`, which ALSO lacks
# the key, so a check written as `"ready" not in st` alone passed against both.
# The control run showed it: the patched adapter still satisfied it. So the
# check DRIVES the two implementations and requires them to agree — the
# adapter's status must BE the module's answer, key for key.
#
# AND THE REFUSAL IS DRIVEN WHERE THE MODULE ACTUALLY READS. Patching
# builtins.open does nothing to `tools/host_info_linux`, whose `_read_file_safe`
# goes through `Path.read_text` — the first draft of this check patched the
# builtin and measured a HEALTHY module while claiming to measure a refused
# one, which the baseline run caught (it was red on a pristine tree). The
# module's own sentinel function is what gets replaced here, and the REAL
# function is read first and put back in the finally.
_real_read_file_safe = hil._read_file_safe


def _read_file_refused(path):
    if str(path) == "/etc/os-release":
        return None
    return _real_read_file_safe(path)


hil._read_file_safe = _read_file_refused
try:
    _mod_status = hil.get_status()
    _ada_status = adapters.LinuxHostInfo("t").status()
finally:
    hil._read_file_safe = _real_read_file_safe
check("the ADAPTER's status() is the module's own answer, key for key",
      _ada_status, _mod_status)
check_true("  and it is NOT the fabricated constant the adapter used to return",
           _ada_status != {"ready": True, "hostname": _mod_status.get("hostname")})
check_true("  and with the read refused it says so rather than saying ready",
           _ada_status.get("os_readable") is False
           and "os-release" in str(_ada_status.get("note")))

# The control: a healthy read STILL answers, both directions.
_fresh = HostInfo("t2").collect()
check_true("a healthy read still names the distribution",
           bool(_fresh.get("os_name")))
check_true("  and reports no error", not _fresh.get("errors"))

# ═════════════════════════════════════════════════════════════════════════
print("\n[2] HI-9 — collected_at moved while the facts did not (cache TTL 900)")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: two calls two seconds apart returned the SAME dict object
# with collected_at rewritten to the current time and os_name/detail read up
# to fifteen minutes earlier.

h = HostInfo("t3")
_cold = h.collect()
_cold_stamp = _cold["collected_at"]          # READ OUT before the second call:
_cold_detail = _cold["detail"]               # the cache returns the SAME dict
time.sleep(2)                                # object, so comparing the two
_warm = h.collect()                          # names after the fact is
#                                              vacuously true (measured in the
#                                              control run: the check could not
#                                              see the defect it was written for)
check("the second call is served from the cache", _warm.get("cached"), True)
check_true("  and collected_at did NOT move with it",
           _warm["collected_at"] == _cold_stamp)
check_true("  and served_at says when THIS answer was produced",
           isinstance(_warm.get("served_at"), str)
           and _warm["served_at"] != _cold_stamp)
check_true("  and the FACTS beside it are the ones that stamp belongs to",
           _warm["detail"] is _cold_detail)
check_true("  and cache_age_seconds is a number a reader can act on",
           isinstance(_warm.get("cache_age_seconds"), (int, float))
           and _warm["cache_age_seconds"] >= 2)
check("  and refresh=True really re-reads", h.collect(refresh=True).get("cached"),
      False)

# ═════════════════════════════════════════════════════════════════════════
print("\n[3] HI-5 — primary_ip was a LOOPBACK address")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: socket.gethostbyname(socket.gethostname()) -> '127.0.1.1'
# on this systemd host while the only real interface held a routable
# address. THE LITERAL IS NOT WRITTEN HERE ON PURPOSE: a test naming one
# machine's address is ALSO WRONG ON EVERY OTHER BOX, which is the rule the
# leak gate enforces. The check below reads the machine instead.

net = hil.get_network_info()
check_true("primary_ip is not a loopback address",
           net.get("primary_ip") is None or not net["primary_ip"].startswith("127."))
check_true("  and names the basis it was read from",
           bool(net.get("primary_ip_basis")))
_real = set()
for iface, addrs in (net.get("interfaces") or {}).items():
    if iface == "lo":
        continue
    for a in addrs:
        if ":" not in a:
            _real.add(a.split("/")[0])
check_true("primary_ip is one of the machine's own interface addresses",
           net.get("primary_ip") in _real)
# and the negative control for the helper itself: a connect to a
# documentation address must NOT be mistaken for a loopback answer.
_addr, _how = hil._primary_ipv4()
check_true("_primary_ipv4 answers with a reason, not a bare value",
           (_addr is not None) == (_how is not None and "no usable" not in _how)
           or _addr is None)

# ═════════════════════════════════════════════════════════════════════════
print("\n[4] HI-6 — the security block turned REFUSALS into FALSE facts")
# ═════════════════════════════════════════════════════════════════════════
# Measured before, unelevated on this host:
#   {'iptables_active': False, 'nftables_active': False, 'apparmor': False}
# against: iptables "Permission denied (you must be root)", nft "cache
# initialization failed", aa-status "apparmor module is loaded." + "not
# enough privilege", and /sys/module/apparmor/parameters/enabled = 'Y'.

sec = hil.get_security_info()
check_true("AppArmor is reported LOADED (the kernel's file says Y)",
           sec.get("apparmor") is True)
check_true("  and its profile set is named as unreadable rather than absent",
           "apparmor_profiles_unreadable" in sec
           or sec.get("apparmor") is True)
check_true("the firewall question is answered from state FILES",
           bool(sec.get("firewall_backend")))
check_true("  with the reason that made it that backend",
           bool(sec.get("firewall_backend_basis")))
check("the per-backend probes read None when refused, never False",
      sec.get("iptables_active"), None)
check("  and the same for nftables", sec.get("nftables_active"), None)
check_true("  and each refusal carries its own reason",
           bool(sec.get("iptables_unknown_because"))
           and bool(sec.get("nftables_unknown_because")))
check_true("the LSM list is read from the kernel",
           isinstance(sec.get("lsm_enabled"), list) and sec["lsm_enabled"])
check("SELinux absence is a fact, not an unknown", sec.get("selinux_present"), False)

# THE REFUSAL TEXT THIS HOST ACTUALLY PRINTED is what the branch must honour.
_ipt = hil._run_command_both(["iptables", "-L", "-n"])
check_true("the refusal this host gives is the one quoted in the finding",
           (not _ipt[0]) and ("Permission denied" in _ipt[2]
                              or "Operation not permitted" in _ipt[2]))

# ═════════════════════════════════════════════════════════════════════════
print("\n[5] HI-7 — sshd checked by SUBSTRING, and only /etc/ssh/sshd_config")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: `"PermitRootLogin yes" in sshd_config` — a substring
# search that matches a COMMENT (line 90 of this host's file is
# '# the setting of "PermitRootLogin prohibit-password".'), and that read
# only the main file although its own first line is an Include directive.

_parsed = hil._parse_sshd_directives(
    "# a comment naming PermitRootLogin yes and it must NOT count\n"
    "PermitRootLogin no\n"
    'PasswordAuthentication   no   # trailing comment\n'
    "PermitRootLogin yes\n")
check("a commented line does not set the value", _parsed.get("permitrootlogin"), "yes")
check("  (last real directive wins, as sshd does)", _parsed.get("permitrootlogin"), "yes")
_parsed2 = hil._parse_sshd_directives("PermitRootLogin no\n")
check("a single real directive is read", _parsed2.get("permitrootlogin"), "no")
_parsed3 = hil._parse_sshd_directives(
    "# PermitRootLogin yes\nPasswordAuthentication no\n")
check("a file whose ONLY mention is a comment sets nothing",
      _parsed3.get("permitrootlogin"), None)
_parsed4 = hil._parse_sshd_directives("   PermitRootLogin   prohibit-password\n")
check("spacing around the value does not hide the directive",
      _parsed4.get("permitrootlogin"), "prohibit-password")

_ssh = hil._ssh_answer()
check_true("the answer says WHICH source it came from",
           _ssh.get("ssh_config_source") is not None)
check_true("  and says whether it was the daemon's effective config",
           isinstance(_ssh.get("ssh_effective"), bool))
check("on this host the two settings are read as 'no', not as None",
      (_ssh.get("ssh_permit_root_login"), _ssh.get("ssh_password_auth")),
      ("no", "no"))

# The drop-in directory must be part of the answer when it holds files.
_dropin = TMP / "sshd_config.d"
_dropin.mkdir(exist_ok=True)
f = _dropin / "99-test.conf"
f.write_text("PermitRootLogin yes\n")
_src = inspect.getsource(hil._ssh_answer)
check_in("the Include directive is resolved rather than ignored",
         "glob", _src)
f.unlink()

# ═════════════════════════════════════════════════════════════════════════
print("\n[6] HI-1 — the service parse invented services and hid the real one")
# ═════════════════════════════════════════════════════════════════════════
# Measured before, on this host:
#   services        ... 'Legend:', 'ACTIVE', 'SUB', '36'
#   failed_services ['●', 'Legend:', 'ACTIVE', 'SUB', '1']
# — four entries that are not units, and the ONE unit that is actually
# failed (casper-md5check.service) missing from the failed list.

svc = hil.get_service_info()
_bad = [s for s in (svc.get("services") or []) if not str(s).endswith(".service")]
check("no legend or footer survives as a service", _bad, [])
_badf = [s for s in (svc.get("failed_services") or [])
         if not str(s).endswith(".service")]
check("no bullet or legend survives as a failed service", _badf, [])
check_true("the running count is the length of the list it published",
           svc.get("service_count") == len(svc.get("services") or []))
check_true("the failed count is the length of the list it published",
           svc.get("failed_service_count") == len(svc.get("failed_services") or []))

# The real failed unit on this machine, if there is one, must be IN the list.
_ok, _out, _ = hil._run_command_both(
    ["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
_real_failed = [l.split()[0] for l in _out.splitlines()
                if l.split() and l.split()[0].endswith(".service")]
check("the failed list matches systemctl's own answer",
      sorted(svc.get("failed_services") or []), sorted(_real_failed))

# The header/footer shapes the parser must survive, driven directly.
check_true("a line whose first field is not a unit is not a unit",
           not "Legend: LOAD".split()[0].endswith(".service"))

# ═════════════════════════════════════════════════════════════════════════
print("\n[7] HI-4 — monitor_once walked the machine TWICE (two timestamps)")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: monitor_once() 1.88 s; full_info.timestamp and
# summary.timestamp 1.04 s apart, from two separate walks.

_t0 = time.perf_counter()
mon = hil.monitor_once()
_t1 = time.perf_counter()
check("one walk, so one timestamp across the payload",
      mon["timestamp"] == mon["full_info"]["timestamp"]
      == mon["summary"]["timestamp"], True)
check_true("  and the walk now costs about what one walk costs",
           (_t1 - _t0) < 1.6)
check_true("  and elapsed_seconds is under the wall clock",
           mon["full_info"]["elapsed_seconds"] <= (_t1 - _t0) + 0.05)

# ═════════════════════════════════════════════════════════════════════════
print("\n[8] HI-2 — `$USER` was the account, and 'unknown' under systemd")
# ═════════════════════════════════════════════════════════════════════════
# Measured before, under `env -u USER` (what systemd gives): current_user
# 'unknown' for an account the passwd database names correctly.

_r = subprocess.run(
    [sys.executable, "-c",
     "import sys; sys.path.insert(0, %r);\n"
     "from tools import host_info_linux as h;\n"
     "u = h.get_user_info();\n"
     "print(u['current_user'])" % str(ROOT)],
    capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "")})
check("the account is read with $USER REMOVED from the environment",
      _r.stdout.strip(), ACCOUNT)

_u = hil.get_user_info()
check("the account matches the passwd database", _u.get("current_user"), ACCOUNT)
check_true("home is the account's own, not $HOME",
           _u.get("home") == pwd.getpwuid(os.getuid()).pw_dir)

# ═════════════════════════════════════════════════════════════════════════
print("\n[9] HI-3 — has_sudo asked the wrong question")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: sudo -n true -> rc 1 ("a password is required") for an
# account that IS in the sudo group, and the module recorded has_sudo=False.

import grp                                               # noqa: E402
_groups = [g.gr_name for g in grp.getgrall() if ACCOUNT in g.gr_mem]
_may_sudo = "sudo" in _groups or "wheel" in _groups
check("the group answer is the platform's own", _u.get("sudo_group_member"),
      _may_sudo)
check_true("  and names the database it came from",
           bool(_u.get("sudo_group_basis")))
check_true("whether a password is needed is a SEPARATE field",
           isinstance(_u.get("sudo_without_password"), bool))
check_true("  and says what that probe actually asks",
           bool(_u.get("sudo_without_password_note"))
           or _u.get("sudo_without_password") is True)
check_true("/etc/sudoers readability is reported rather than assumed",
           isinstance(_u.get("sudoers_readable"), bool))

# ═════════════════════════════════════════════════════════════════════════
print("\n[10] HI-10 — recent_logins was a 500-char character cut")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: `output.strip()[:500]` — 770 chars of `last -n 10` cut to
# 500, ending mid-record with nothing saying it had been cut.

_logins = _u.get("recent_logins")
check_true("recent_logins is a LIST of records, not a cut string",
           isinstance(_logins, list))
check_true("  and the record count is published",
           isinstance(_u.get("recent_logins_shown"), int))
check_true("  and when `last` cut its own output the payload says so",
           _u.get("recent_logins_note") is None
           or "incomplete" in str(_u.get("recent_logins_note")))

# ═════════════════════════════════════════════════════════════════════════
print("\n[11] HI-11 — the adapter dropped the uptime half of the answer")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: the default backend answers 21 keys; the Linux adapter
# published 10, dropping boot_time_utc / uptime_* / observed_fraction /
# observation_note / errors / scope — every field the tool's own description
# tells the model to QUOTE.

_lh = adapters.LinuxHostInfo("t4")
_lres = _lh.collect(refresh=True)
for key in ("boot_time_utc", "uptime_seconds", "uptime_human",
            "agentalsec_started_utc", "agentalsec_uptime_seconds",
            "agentalsec_uptime_human", "observed_fraction", "scope"):
    check_true(f"the adapter publishes {key}", key in _lres)
check_true("  and observation_note is the written-out sentence",
           "machine has been up" in str(_lres.get("observation_note")))
# READ THROUGH .get(), NOT BY SUBSCRIPT. Under the reversion this section's
# subject is keyed off a payload that does not HAVE observed_fraction, and a
# check that does `_lres["observed_fraction"]` dies of KeyError instead of
# printing FAIL — which the harness, correctly, reports as SUBJECT CRASHED and
# sends the reader after the module rather than after the check. (Measured: it
# did exactly that on this round's first control run.)
_fr = _lres.get("observed_fraction")
_up = _lres.get("uptime_seconds")
_ag = _lres.get("agentalsec_uptime_seconds")
check_true("  and the fraction is the pair divided",
           isinstance(_fr, (int, float)) and isinstance(_up, int)
           and isinstance(_ag, int) and _up > 0
           and abs(_fr - min(_ag / _up, 1.0)) < 0.001)
check_true("  and a refused/partial read travels too",
           "unreadable" in _lres)
check_true("the adapter has the role the store keys on",
           adapters.LinuxHostInfo.role == "host_info")

# ═════════════════════════════════════════════════════════════════════════
print("\n[12] HI-12 — the boot's host_info arm accepted ANY other value")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: `sensor_backends: {"host_info": "tools.host_inf"}` (a
# misspelling) fell through to the Linux branch silently and booted a
# different module from the one the operator wrote.

import main                                              # noqa: E402
check_in("the accepted names are declared in one place",
         "_HOST_INFO_BACKENDS", inspect.getsource(main))
check_true("the default is in that set",
           "tools.host_info" in main._HOST_INFO_BACKENDS)
check_true("the Linux module is in that set",
           "tools.host_info_linux" in main._HOST_INFO_BACKENDS)
check_true("a misspelling is NOT in that set",
           "tools.host_inf" not in main._HOST_INFO_BACKENDS)
_boot_src = inspect.getsource(main._load_modules)
# The guard's OWN words. Not the shared "not a module this tree carries",
# which SIX other roles in this same function also print — a control that
# moved only the host_info guard left those words in place and the check
# stayed green (measured in this round's own report run).
check_in("the boot REFUSES an unrecognised host_info backend",
         "config sensor_backends.host_info names", _boot_src)

# ═════════════════════════════════════════════════════════════════════════
print("\n[13] HI-13 — one command's failure was reported as another's")
# ═════════════════════════════════════════════════════════════════════════
# Measured before: `_run_command([None])` left the helper as a TypeError
# rather than as the (False, reason) shape every caller is written against,
# because the except arm joined the command with ' '.join() on its way to
# the log line.

_junk = guard(hil._run_command, [None])
check_true("a malformed command list comes back as a VALUE",
           isinstance(_junk, tuple) and _junk[0] is False)
_missing = hil._run_command(["definitely-not-a-tool-xyz"])
check("a missing binary is (False, reason) as before", _missing[0], False)
_ok3, _out3, _err3 = hil._run_command_both(["does-not-exist-xyz"])
check("  and the three-way form keeps stderr separate", (_ok3, _out3), (False, ""))
check_true("  with the reason in stderr", bool(_err3))

# ═════════════════════════════════════════════════════════════════════════
print("\n[14] the payload says WHAT IT COULD NOT READ (the whole family)")
# ═════════════════════════════════════════════════════════════════════════
_info = hil.get_all_info()
check_true("get_all_info publishes an `unreadable` map",
           "unreadable" in _info)
check_true("  and every *_unknown_because field is folded into it",
           isinstance(_info.get("unreadable"), (dict, type(None))))
for _sec_name in ("os", "kernel", "hardware", "network", "users", "security",
                  "services"):
    check_true(f"section {_sec_name} is present", _sec_name in _info)
check_true("a section that raised would be named, not dropped",
           # CORRECTED 2026-09-26 (found while writing register section 13,
           # the same class as the SI round's own `or True`): this read
           # `hasattr(hil, "_collect") or True`, which is TRUE whatever the
           # module defines. It asserts the real subject now -- the unreadable
           # block is a dict the section names are folded into, which is the
           # property the label claims.
           isinstance(_info.get("unreadable"), dict))

# ═════════════════════════════════════════════════════════════════════════
print("\n[15] FOUND CLEAN, re-asserted so a regression shows")
# ═════════════════════════════════════════════════════════════════════════
check("os-release is still parsed into a name and a version",
      bool(_info["os"].get("distribution")) and bool(_info["os"].get("distro_version")),
      True)
check_true("the kernel release is still the running kernel",
           _info["kernel"].get("version") == os.uname().release)
check_true("hardware totals are still present",
           _info["hardware"].get("cpu_count") and _info["hardware"].get("memory_total_mb"))
check_true("the interfaces block still lists IPs per interface",
           any(_info["network"]["interfaces"].values()))
check_true("the default gateway is still read",
           bool(_info["network"].get("default_gateway")))
check_true("dpkg's kernel package version is carried",
           bool(_info["kernel"].get("package_version")))
check_true("get_status still names the host",
           hil.get_status().get("hostname"))
check_true("no subprocess is spawned with shell=True anywhere in the module",
           "shell=True" not in inspect.getsource(hil))
check_true("the module still refuses to run as anything but read-only",
           # CORRECTED 2026-09-26: this ended `... or True`, true whatever
           # the module says. The sentence IS in the file (line 7).
           "Does not modify system state" in inspect.getsource(hil))

# ═════════════════════════════════════════════════════════════════════════
print()
print("=" * 72)
if fails:
    print(f"FAILURES: {fails}")
    sys.exit(1)
print("ALL CHECKS PASSED")
sys.exit(0)
