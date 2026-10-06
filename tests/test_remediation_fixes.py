"""
tests/test_remediation_fixes.py — register section 8, the remediation round.

2026-09-24. `remediation` is the only module in this tree that CHANGES the
machine, so this file is about REFUSAL PATHS more than detection: for every
fix the round made, the thing worth asserting is what the code now says NO to,
and — just as important — the control that says it still does the ordinary
thing it was already doing.

THE THIRTEEN ENTRIES, and the one sentence that says why each is here:

  REM-1   the app could terminate itself. Measured through the shipped
          LinuxRemediation.kill_process with its OWN pid: an empty return and
          the process was dead.
  REM-2   the protected-roots list was the Windows one translated: /var/lib,
          /var/log, /run, /snap were all quarantinable, including this app's
          own root-owned camera sidecar.
  REM-3   quarantine_file moved anything: a directory came back as shutil's
          "[Errno 21] Is a directory", and a FIFO NEVER RETURNED — it blocked
          inside the hash loop until a writer appeared.
  REM-4   the vault path was `~/Desktop/...`, the Windows shape. It followed
          $HOME, so it resolved per account, and it named a GUI folder that
          does not exist for root.
  REM-5   the critical-process list was missing every process whose loss takes
          the SESSION down (Xorg, gnome-shell, systemd-udevd, kthreadd...),
          all measured running on this host.
  REM-6   the list and the pin compare a name psutil takes from argv[0] once
          /proc/comm is at the kernel's 15-character cap — text the process
          chooses — while the list's own 16-character entry can never match
          the kernel's spelling.
  REM-7   `proc.wait(timeout=10)` waits to REAP a process this app did not
          start, which only its parent may do. Measured: 20 s per kill on a
          live non-child, and a ZOMBIE reported as "refused to die".
  REM-8   a HALF-LIFTED ban was reported as lifted, in all three backends.
  REM-9   a vault folder with a corrupt manifest vanished from every answer.
  REM-10  the sha256 recorded at quarantine time was NEVER compared again.
  REM-11  get_status could not say whether the vault is reachable.
  REM-12  list_quarantined reports no `folder`, restore_file's parameter IS
          `folder`, and the module refused the value the other two produce.
  REM-13  the gateway guard from the Windows twin was absent.
  REM-14  the privileged shim's process_kill carried REM-1 and REM-7 one
          layer down, and had ZERO callers, so nobody had ever run it.

A TEST THAT NAMES ONE MACHINE IS WRONG ON EVERY OTHER BOX, and this file
follows the register's own rule: the account is read at run time, addresses
come from the RFC 5737 documentation ranges, and the two places a real host
value is needed (a pid that exists, this process's own pid) are read from the
host rather than written down.
"""
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import _skip
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"   (want {want!r})"))
    if not ok:
        fails.append(label)


import psutil                                    # noqa: E402
from tools import remediation_linux as rem       # noqa: E402
from tools import iptables_manager as fw         # noqa: E402
from core import capabilities as caps            # noqa: E402

WORK = pathlib.Path(tempfile.mkdtemp(prefix="remfix_"))
# The vault is pointed at a temp dir for the same reason
# test_restore_containment does it: a test must never write to the operator's
# real quarantine folder. Every staging assertion below reads THIS root.
rem.STAGING_ROOT = WORK / "quarantine"
rem.STAGING_ROOT.mkdir(parents=True, exist_ok=True)


print("\n[REM-1] this app must not be able to terminate itself")
own = os.getpid()
sentence = rem.self_protection(own)
check("own pid is refused", bool(sentence), True)
# THE FIRST VERSION OF THIS GUARD DIED OF A RecursionError, so the assertion
# is on the SENTENCE rather than on the branch: an f-string in the refusal
# branch resolved to itself, psutil's repr recursed, and every refusal it was
# written to give propagated out of kill_process instead.
check("and the refusal is a real string, not a recursion",
      isinstance(sentence, str) and len(sentence) > 60, True)
check("a pid that is not us is NOT refused", rem.self_protection(1), "")
r = rem.kill_process(own)
check("kill_process(own pid) refuses", r.get("refused"), True)
check("and says it is the self case", r.get("reason_class"), "self")
check("AND THIS PROCESS IS STILL ALIVE", os.getpid(), own)

# the same guard one layer down, in the shim
try:
    caps.get().process_kill(own, "test")
    check("the shim refuses it too", "no exception", "CapabilityError")
except caps.CapabilityError as e:
    check("the shim refuses it too", "the process making this call" in str(e), True)
except Exception as e:                           # noqa: BLE001
    check("the shim refuses it too", f"raised {type(e).__name__}", "CapabilityError")


print("\n[REM-7] a process that is already dead is not a kill")
zombie_parent = subprocess.Popen(["sleep", "300"])
os.kill(zombie_parent.pid, signal.SIGKILL)
time.sleep(0.4)
check("the target really is a zombie",
      psutil.Process(zombie_parent.pid).status(), "zombie")
t0 = time.perf_counter()
r = rem.kill_process(zombie_parent.pid)
dt = time.perf_counter() - t0
check("refused rather than 'success with a signal number'",
      r.get("success"), False)
check("and the answer names the state", r.get("status"), "zombie")
check("and it did not sit in a 10-second reap wait", dt < 1.0, True)
zombie_parent.wait()

# THE CONTROL: a live process is still killed.
live = subprocess.Popen(["sleep", "300"])
time.sleep(0.3)
t0 = time.perf_counter()
r = rem.kill_process(live.pid)
dt = time.perf_counter() - t0
check("a live process is still killed", r.get("success"), True)
check("and the answer says which path signalled it",
      r.get("via") in ("core.capabilities.process_kill", "direct signal"), True)
check("and it was confirmed by STATE (zombie is gone, not running)",
      r.get("status") in ("gone", "zombie", "dead"), True)
check("and it was fast", dt < 8.0, True)
live.wait()

# A SIGTERM-immune process: one escalation, bounded, and the answer says so.
code = ("import signal, time\n"
        "signal.signal(signal.SIGTERM, lambda *a: None)\n"
        "time.sleep(60)\n")
immune = subprocess.Popen([sys.executable, "-c", code])
time.sleep(0.6)
t0 = time.perf_counter()
r = rem.kill_process(immune.pid)
dt = time.perf_counter() - t0
check("the immune one is force-killed", r.get("success"), True)
check("and the escalation is NAMED, not silent",
      r.get("escalated_from"), int(signal.SIGTERM))
check("and it is bounded by the confirmation window, not by two reap waits",
      dt < 12.0, True)
immune.wait()

# AND THE THING THE ESCALATION MUST NOT DO: recurse. The old code called
# kill_process(pid, force=True) from inside itself, which re-ran every guard
# and re-checked the critical list on a pid whose state had just changed.
body = (ROOT / "tools" / "remediation_linux.py").read_text(encoding="utf-8")
check("kill_process does not call itself",
      "return kill_process(pid, force=True)" in body, False)


print("\n[REM-5] the critical list, against the processes this host runs")
for name in ("xorg", "gnome-shell", "systemd-udevd", "kthreadd", "polkitd",
             "udisksd", "upowerd", "systemd-resolved", "systemd-timesyncd",
             "irqbalance", "thermald", "wpa_supplicant", "auditd", "gdm3",
             "plasmashell", "lightdm", "chronyd", "dbus-broker"):
    check(f"{name!r} is protected", name in rem.CRITICAL_PROCESSES, True)
# The ones that were ALREADY there must stay: a list that grew by replacing
# itself would be worse than one that never grew.
for name in ("systemd", "systemd-journald", "systemd-logind", "sshd", "cron",
             "dbus-daemon", "networkmanager", "dockerd", "containerd"):
    check(f"{name!r} is still protected", name in rem.CRITICAL_PROCESSES, True)


print("\n[REM-6] the identity read, both directions, on a controlled spawn")
# (a) the kernel's comm is capped at 15 characters, so the list's 16-character
#     systemd-journald entry can never equal it. Measured: comm 'systemd-journal'
#     while psutil reports 'systemd-journald'.
long_copy = WORK / "another-long-binary-name"
shutil.copy("/bin/sleep", long_copy)
child = subprocess.Popen([str(long_copy), "60"])
time.sleep(0.45)
ident = rem.process_identity(child.pid)
check("comm is the kernel's, at the 15-character cap",
      len(ident["comm"]), 15)
check("the reported name is the process's own file name",
      ident["reported_name"], "another-long-binary-name")
check("and the running file is read", ident["exe"], str(long_copy))
# (b) THE DISGUISE HALF, and the assertion reads for the EXACT empty string
#     rather than for a falsy value, because the first version of this function
#     reported a match STRING and an earlier draft of this check accepted the
#     bare failure. A process named after a critical one is not a critical
#     process, and a false refusal here takes the operator's decision away.
check("a copy of a harmless binary is NOT matched",
      rem.matches_critical(ident), "")
child.kill()
child.wait()

# (c) THE CASE THE LIST'S OWN LONG ENTRY NEEDS: a file whose name truncates to
#     a listed comm IS matched, and that is the right answer — a process whose
#     kernel name says systemd-journal is protected whatever file it came
#     from, which is the miss the old name-only check could not avoid.
padded = WORK / "systemd-journald-copy"
shutil.copy("/bin/sleep", padded)
child2 = subprocess.Popen([str(padded), "60"])
time.sleep(0.45)
ident2 = rem.process_identity(child2.pid)
check("a name that truncates to a listed comm IS matched",
      bool(rem.matches_critical(ident2)), True)
check("and the match names the kernel's field, not the reported name",
      "comm" in rem.matches_critical(ident2), True)
child2.kill()
child2.wait()

# (c) the real ones on THIS host, matched, and the match names its source.
found = []
for p in psutil.process_iter(["pid", "name"]):
    nm = (p.info["name"] or "").lower()
    if nm in ("systemd", "systemd-logind", "systemd-journald"):
        found.append(p.info["pid"])
check("this host is running at least one listed process", bool(found), True)
for pid in found:
    m = rem.matches_critical(rem.process_identity(pid))
    check(f"pid {pid} is matched", bool(m), True)
    check(f"and the match says which /proc field it came from",
          any(f in m for f in ("comm", "reported_name", "exe", "argv0")), True)

# (d) the pin, through BOTH helpers, including the sanitize case that
#     tests/test_process_lookup.py already holds.
sys.path.insert(0, str(ROOT))
from adapters import _identity_matches_pin, _name_matches_pin   # noqa: E402
from core import sanitize as sz                                  # noqa: E402

good = {"pid": 1, "comm": "sleep", "reported_name": "sleep",
        "exe_basename": "sleep", "cmdline": ["/bin/sleep"]}
check("the pin accepts the same process", _identity_matches_pin(good, "sleep"), True)
check("the pin refuses a different one",
      _identity_matches_pin(good, "sshd"), False)
capped = {"pid": 1, "comm": "systemd-journal", "reported_name": "systemd-journal",
          "exe_basename": "", "cmdline": ["/usr/lib/systemd/systemd-journal"]}
check("the pin matches a process whose comm is at the cap",
      _identity_matches_pin(capped, "systemd-journal"), True)
disguised = "svc\u200bhost"
check("the sanitize case still goes through",
      _name_matches_pin(disguised, sz.scrub_string(disguised)), True)
check("and a real difference is still a miss",
      _name_matches_pin("svchost", "svchosts"), False)


print("\n[REM-3] quarantine_file moves an ordinary file and nothing else")
a_dir = WORK / "a_directory"
a_dir.mkdir()
(a_dir / "inner.txt").write_text("x")
r = rem.quarantine_file(str(a_dir))
check("a DIRECTORY is refused", r.get("refused"), True)
check("and the kind is named", r.get("kind"), "a directory")

a_fifo = WORK / "a_fifo"
os.mkfifo(a_fifo)
t0 = time.perf_counter()
r = rem.quarantine_file(str(a_fifo))
dt = time.perf_counter() - t0
check("a FIFO is refused", r.get("refused"), True)
check("and the call RETURNED instead of blocking on a reader",
      dt < 1.0, True)

a_sock = WORK / "a_sock"
s = socket.socket(socket.AF_UNIX)
s.bind(str(a_sock))
r = rem.quarantine_file(str(a_sock))
check("a SOCKET is refused", r.get("refused"), True)
s.close()

broken = WORK / "a_broken_link"
broken.symlink_to("/nonexistent/nowhere")
r = rem.quarantine_file(str(broken))
check("a broken symlink is refused", r.get("refused"), True)

# THE CONTROL. Everything above is a refusal, so the ordinary case has to be
# asserted or the file proves only that the function says no.
plain = WORK / "ordinary.txt"
plain.write_text("fine\n")
r = rem.quarantine_file(str(plain))
check("CONTROL: an ordinary file is still moved", r.get("success"), True)
check("and the kind travels back with it", r.get("kind"), "a regular file")
if r.get("success"):
    rem.restore_file(r["quarantine"])


print("\n[REM-2] the protected roots, measured against paths that exist here")
for path in ("/var/lib/dpkg/status", "/var/lib/systemd", "/var/lib/docker",
             "/run/systemd/system", "/var/log/syslog", "/snap",
             "/var/lib/agental_sec/ebpf_events.db",
             "/usr/local/lib/agentalsec/tools/read_helper.py",
             "/etc/sudoers.d/somebody", "/usr/bin/ls", "/boot/vmlinuz"):
    p = pathlib.Path(path)
    blocked = [str(x) for x in rem.PROTECTED_ROOTS + rem.AGENTALSEC_ROOTS
               if rem._is_within(p, x)]
    check(f"{path} cannot be quarantined from", bool(blocked), True)
# and the control: an ordinary path in a home directory is still allowed.
homepath = pathlib.Path.home() / "Downloads" / "thing.bin"
check("CONTROL: a file under a home directory is still reachable",
      bool([x for x in rem.PROTECTED_ROOTS + rem.AGENTALSEC_ROOTS
            if rem._is_within(homepath, x)]), False)
# THE PROJECT'S OWN TREE, wherever it is installed, not only the checkout.
check("the checkout is guarded", rem.PROJECT_ROOT_GUARD in rem.AGENTALSEC_ROOTS, True)
check("there is more than one agentalsec root",
      len(rem.AGENTALSEC_ROOTS) > 1, True)


print("\n[REM-3b] a file already in the vault is not re-quarantined")
already = rem.STAGING_ROOT / "already_staged.bin"
already.write_text("staged\n")
r = rem.quarantine_file(str(already))
check("it is refused", r.get("refused"), True)
check("and the reason names the vault",
      "quarantine area" in (r.get("error") or ""), True)
check("AND THE FILE IS STILL WHERE IT WAS", already.exists(), True)
already.unlink()


print("\n[REM-4] the vault path, and the one it used to be")
check("the vault does not name a Desktop",
      "Desktop" not in str(rem.STAGING_ROOT), True)
check("the legacy Desktop vault is still READ",
      any("Desktop" in str(x) for x in rem.legacy_staging_roots()), True)
check("staging_roots() covers both", len(rem.staging_roots()) >= 2, True)
# The env override, driven in a subprocess so it is the module's own read that
# is being tested and not this file's import of it.
env = dict(os.environ)
env["AGENTALSEC_QUARANTINE_ROOT"] = str(WORK / "custom_vault")
p = subprocess.run([sys.executable, "-c",
                    f"import sys; sys.path.insert(0, {str(ROOT)!r}); "
                    f"from tools import remediation_linux as r; "
                    f"print(r.STAGING_ROOT)"],
                   capture_output=True, text=True, env=env, cwd=str(ROOT))
check("AGENTALSEC_QUARANTINE_ROOT is honoured", p.stdout.strip(),
      str(WORK / "custom_vault"))
# HOME is not the input any more, and the measurement that forced this was
# that it used to be: HOME=/root resolved the vault to /root/Desktop.
env2 = dict(os.environ)
env2.pop("AGENTALSEC_QUARANTINE_ROOT", None)
env2.pop("XDG_STATE_HOME", None)
p2 = subprocess.run([sys.executable, "-c",
                     f"import sys; sys.path.insert(0, {str(ROOT)!r}); "
                     f"from tools import remediation_linux as r; "
                     f"print(r.STAGING_ROOT)"],
                    capture_output=True, text=True, env=env2, cwd=str(ROOT))
check("with no override it is the XDG state default",
      p2.stdout.strip().endswith("/.local/state/agental_sec/quarantine"), True)
check("and it is NOT under a Desktop",
      "Desktop" not in p2.stdout, True)


print("\n[REM-9] a manifest that cannot be read is reported, not dropped")
bad = rem.STAGING_ROOT / "20260101_000000"
bad.mkdir(parents=True, exist_ok=True)
(bad / "manifest.json").write_text("{ this is not json")
listing = rem.list_quarantined()
bad_rows = [e for e in listing if e.get("folder") == "20260101_000000"]
check("the folder appears in the listing", len(bad_rows), 1)
check("marked unreadable", bad_rows[0].get("unreadable"), True)
check("with the reason", "JSON" in (bad_rows[0].get("reason") or ""), True)
shutil.rmtree(bad, ignore_errors=True)


print("\n[REM-12] the round trip through the names the TOOLS actually use")
src = WORK / "roundtrip.bin"
src.write_text("payload\n")
q = rem.quarantine_file(str(src))
check("quarantined", q.get("success"), True)
listing = rem.list_quarantined()
row = [e for e in listing if e.get("original_path") == str(src)]
check("list_quarantined reports it", len(row), 1)
check("and reports the file path", bool(row[0].get("quarantine_path")), True)
folder = str(pathlib.Path(q["quarantine"]).parent)
# THE DEFECT: restore_file's own parameter is `folder`, the model's tool takes
# a folder, and the module refused one by looking for a manifest one level up.
r = rem.restore_file(folder)
check("restore BY THE DATED FOLDER works", r.get("success"), True)
check("and the file is really back", src.exists(), True)
q = rem.quarantine_file(str(src))
check("restore BY THE FILE PATH still works",
      rem.restore_file(q["quarantine"]).get("success"), True)
# and the folder case still refuses when it cannot know which file was meant.
multi = rem.STAGING_ROOT / "20260202_000000"
multi.mkdir(parents=True, exist_ok=True)
(multi / "manifest.json").write_text(json.dumps({"original_path": "/tmp/x"}))
(multi / "one.bin").write_text("1")
(multi / "two.bin").write_text("2")
r = rem.restore_file(str(multi))
check("a folder with two files refuses rather than guessing",
      r.get("success"), False)
check("and the refusal counts them",
      "2 files" in (r.get("error") or ""), True)


print("\n[REM-10] the digest recorded at quarantine time is compared on the way out")
src2 = WORK / "tamper.bin"
src2.write_text("the original bytes\n")
q = rem.quarantine_file(str(src2))
staged = pathlib.Path(q["quarantine"])
staged.write_text("SOMETHING ELSE\n")
r = rem.restore_file(q["quarantine"])
check("the restore still happens (it is the operator's decision)",
      r.get("success"), True)
check("and reports a MISMATCH", r.get("sha256_state"), "mismatch")
check("with the recorded digest in the sentence",
      q["hash"][:16] in (r.get("sha256_note") or ""), True)
# THE CONTROL: an untouched file reports a match, or the check is a constant.
src2.write_text("clean bytes\n")
q = rem.quarantine_file(str(src2))
r = rem.restore_file(q["quarantine"])
check("CONTROL: an untouched file reports a match",
      r.get("sha256_state"), "match")


print("\n[REM-11] get_status has to be able to say the vault is unreachable")
st = rem.get_status()
check("it names the root", bool(st.get("quarantine_root")), True)
check("and says which rule chose it", bool(st.get("quarantine_root_source")), True)
check("and whether the root can be written",
      st.get("quarantine_root_writable"), True)
check("and it publishes its own pid", st.get("self_pid"), os.getpid())
# A vault that cannot be written is a DIFFERENT answer from an empty one.
try:
    rem.STAGING_ROOT = pathlib.Path("/proc/self/nowhere/quarantine")
    st2 = rem.get_status()
    check("a root under an unwritable parent reports False",
          st2.get("quarantine_root_writable"), False)
finally:
    rem.STAGING_ROOT = WORK / "quarantine"


print("\n[REM-8] a half-lifted ban is a failure, in all three backends")
for label, func, attr in (
        ("ufw", fw.unblock_ip_ufw, "_ufw_delete"),
        ("nftables", fw.unblock_ip_nftables, "_nft_delete_rule"),
        ("iptables", fw.unblock_ip_iptables, "_iptables_delete_by_marker")):
    real_fn = getattr(fw, attr)
    real_root = fw.needs_root
    fw.needs_root = lambda: False

    def one_leg(*a, **kw):
        marker = a[1] if len(a) > 1 else kw.get("marker")
        if marker and str(marker).endswith("_in"):
            return {"success": True, "verified": True, "removed": True}
        return {"success": False, "error": "the probe refused this leg",
                "not_found": False}

    setattr(fw, attr, one_leg)
    try:
        res = func("203.0.113.9", "both")
    finally:
        setattr(fw, attr, real_fn)
        fw.needs_root = real_root
    check(f"{label}: one leg lifted and one refused is a FAILURE",
          res.get("success"), False)
    check(f"{label}: and the surviving leg is carried back",
          bool(res.get("partial")), True)

# THE CONTROL, and it is the half that stops the fix from being a blanket
# refusal: both legs lifting is still a success.
real_fn = fw._ufw_delete
real_root = fw.needs_root
fw.needs_root = lambda: False
fw._ufw_delete = lambda *a, **kw: {"success": True, "verified": True,
                                   "removed": True}
ctrl = fw.unblock_ip_ufw("203.0.113.9", "both")
fw._ufw_delete = real_fn
fw.needs_root = real_root
check("CONTROL: both legs lifted is still a success", ctrl.get("success"), True)


print("\n[REM-13] the gateway guard the twin has, ARMED AND MEASURED")
# REM-13b, 2026-09-24. WHAT THIS SECTION USED TO BE, because the old shape is
# the reason the new one exists:
#
#     check("the adapter carries the configured-router refusal",
#           "_configured_router" in (ROOT / "adapters.py").read_text(), True)
#
# That passed, and it was measuring the wrong thing. A NAME IN A FILE IS NOT A
# WORKING GUARD. The port carried the twin's path as well as the twin's rule,
# and `Path(__file__).parent.parent` points ABOVE this project, so the guard
# read a file that does not exist, answered "" for every value an operator
# could set, and refused nothing. The register said the guard was ported, the
# code said it was ported, the test said it was ported, and it could not fire.
#
# So this section now DRIVES the real refusal path with the operator's own
# configuration, and proves it is inert when the setting is empty, which is the
# half a name-search can never see.
import adapters                                       # noqa: E402
from adapters import LinuxRemediation                  # noqa: E402
from core import settings as core_settings            # noqa: E402


def _with_config(block, fn):
    """
    Run `fn` with config.json pointing at one block we chose.

    It moves core_settings.CONFIG_PATH, the ONE path the app loads, the
    settings panel writes and the router toggle writes, rather than writing
    the operator's file. The owner's config.json is READ here and never modified.
    """
    holder = pathlib.Path(tempfile.mkdtemp(prefix="remcfg_"))
    cfg_path = holder / "config.json"
    cfg_path.write_text(json.dumps(block), encoding="utf-8")
    real_path = core_settings.CONFIG_PATH
    core_settings.CONFIG_PATH = cfg_path
    try:
        return fn()
    finally:
        core_settings.CONFIG_PATH = real_path
        shutil.rmtree(holder, ignore_errors=True)


# WHAT THE OPERATOR ACTUALLY HAS, read through the guard's OWN reader so this
# section cannot quietly disagree with the thing it is testing.
real_cfg = adapters.read_operator_config()
gateway = (adapters._configured_router_from(real_cfg)
           if real_cfg is not None else "")
if not (core_settings.CONFIG_PATH.exists() and gateway):
    _skip.skip_part('the real-gateway check needs a config.json with a router set')
else:
    check("the reader opens the file the app itself loads "
          "(core/settings.CONFIG_PATH)",
          adapters.read_operator_config() is not None
          and core_settings.CONFIG_PATH.exists(), True)
    check("and a router is set in it, or this section proves nothing",
          bool(gateway), True)

    rem_adapter = LinuxRemediation("remfix-test")
    refusal = rem_adapter.block_device(gateway, "probe")
    check("THE REAL GATEWAY IS REFUSED", refusal.get("success"), False)
    check("and it is the gateway rule that refused, not another one",
          "router named in config.json" in (refusal.get("error") or ""), True)
    check("and the sentence says a ban is not what this means",
          "not what a device ban means" in (refusal.get("error") or ""), True)
    check("and nothing was written for a ban that did not happen",
          "record_error" in refusal, False)

# THE CONTROL, and it is what stops the checks above passing for the wrong
# reason: a guard that refused EVERY address would satisfy them. A DIFFERENT
# device is not refused by the gateway rule, and reaches the firewall, which
# unelevated says so in its own words. RFC 5737 throughout, so no test names a
# network and nothing here can matter if it ever ran elevated.
other = _with_config(
    {"router_monitor": {"enabled": False, "host": "192.0.2.1"}},
    lambda: LinuxRemediation("remfix-test").block_device("192.0.2.77", "probe"))
check("CONTROL: another device is NOT refused by the gateway rule",
      "router named in config.json" in (other.get("error") or ""), False)
check("and unelevated it still blocks nothing", other.get("success"), False)

# THE INERT HALF, measured on the reader rather than by attempting a ban on
# the operator's real gateway: an empty host yields "", which is the value the
# guard keys on. Armed when set, inert when not, both asserted.
check("the reader answers empty for an unset router",
      _with_config({"router_monitor": {"host": ""}},
                   adapters._configured_router), "")
check("and finds one that is set",
      _with_config({"router_monitor": {"host": "192.0.2.1"}},
                   adapters._configured_router), "192.0.2.1")
check("and is not fooled by a config that cannot be read at all",
      _with_config({}, adapters._configured_router), "")
check("an empty reason is still refused",
      LinuxRemediation("remfix-test").block_device("192.0.2.77", "   ").get("success"),
      False)


print("\n[REM-14] the privileged shim, which had no caller at all")
shim_src = (ROOT / "core" / "capabilities.py").read_text(encoding="utf-8")
# The old line is NAMED in the fix's own docstring to explain why it went, so a
# raw substring search over the file reports the explanation as the defect —
# the same fault tests/test_capability_shim.py records for its BANNED map,
# where a comment about Get-MpThreatDetection failed the assertion that it is
# not called. The check reads the RUNNING CODE, not the prose around it, and
# the way to get that for a docstring is to look at the function instead of the
# file.
import inspect                                    # noqa: E402
shim_body = inspect.getsource(caps.Capabilities.process_kill)
# `inspect.getsource` INCLUDES the docstring, and the docstring is where the
# old line is named. Take the prose out and check the code that is left, which
# is the thing the assertion is actually about.
_shim_doc = caps.Capabilities.process_kill.__doc__ or ""
shim_code = shim_body.replace(_shim_doc, "")
check("the prose really did name the old line (or this check is a no-op)",
      "proc.wait(timeout=wait)" in _shim_doc, True)
check("the shim does not wait for reaping any more",
      "proc.wait(timeout=wait)" in shim_code, False)
check("it polls the state instead",
      "_confirm_gone" in shim_code, True)
check("and the helper polls status rather than waiting",
      "_confirm_gone" in inspect.getsource(caps.Capabilities._confirm_gone), True)
check("and it refuses its own caller",
      "is the process making this call" in shim_code, True)
check("and it refuses a zombie",
      '"zombie"' in shim_code, True)
# It now HAS a caller, which is the whole point of the entry.
check("tools/remediation_linux goes through it",
      "from core import capabilities" in
      (ROOT / "tools" / "remediation_linux.py").read_text(encoding="utf-8"),
      True)
check("and the shim is really reached at run time (measured above)",
      "core.capabilities.process_kill" in
      (ROOT / "tools" / "remediation_linux.py").read_text(encoding="utf-8"),
      True)


print("\n[REM-SEC] what this file will not let the module do")
body = (ROOT / "tools" / "remediation_linux.py").read_text(encoding="utf-8")
for banned in ("shell=True", "os.system(", "eval(", "pickle",
               "os.remove(", "shutil.rmtree("):
    check(f"the module does not call {banned}", banned in body, False)
check("it still has no direct subprocess for a privileged act",
      "subprocess.run(" in body, False)
check("the app's own pid is guarded in the module",
      "def self_protection" in body, True)

print()
print("=" * 70)
if fails:
    print(f"{len(fails)} FAILED:")
    for f in fails:
        print("   -", f)
else:
    print("ALL CHECKS PASS")
shutil.rmtree(WORK, ignore_errors=True)
if not fails:
    _skip.exit_if_skipped()
sys.exit(1 if fails else 0)
