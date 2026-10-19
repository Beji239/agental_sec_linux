"""
tests/test_own_install.py, the app recognises its own installers' work.

A file is the app's own only when it is root-owned, closed to other accounts
and identical to what the project's installer writes. The audit log, the file
checks and the startup monitor all ask the same question, so a reinstall does
not raise alarms about the app itself, and anything else still does.

Run it directly: python tests/test_own_install.py
"""
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from core import own_install as oi                      # noqa: E402
from tools import auditd_monitor as am                  # noqa: E402
from tools import autorun_monitor as ar                 # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


print("[1] each installer template renders as bash renders it")
if shutil.which("bash"):
    for name, var, dest in oi.WRITTEN:
        script = (ROOT / "scripts" / name).read_text()
        known = oi._variables(script, ROOT)
        m = re.search(rf'^{var}="\$\(cat <<EOF\n.*?\nEOF\n\)"', script,
                      re.M | re.S)
        prog = ("".join(f"{k}={shlex.quote(v)}\n" for k, v in known.items())
                + "PYTHON=/usr/bin/python3\n" + m.group(0)
                + f'\nprintf "%s\\n" "${var}"\n')
        out = subprocess.run(["bash", "-c", prog], capture_output=True,
                             text=True).stdout
        how = oi.expected(ROOT)[oi._expand(dest, known)][1]
        check(f"{name} {var}", bool(how.regex.fullmatch(out)), True)
        if how.exact:
            check(f"{name} {var} exactly", how.exact == out, True)
else:
    print("  SKIP  bash is not installed")
check("the sudoers drop-in has nothing that varies, so a hash can prove it",
      oi.expected(ROOT)["/etc/sudoers.d/agentalsec-read-helper"][1].exact
      is not None, True)

print("\n[2] a file on disk is judged by content, owner and mode")
work = pathlib.Path(tempfile.mkdtemp(prefix="owninstall."))
proj, units = work / "proj", work / "system"
(proj / "scripts").mkdir(parents=True)
(proj / "tools").mkdir()
units.mkdir()
helper = b"print('names')\n"
(proj / "tools" / "names_helper.py").write_bytes(helper)
real = (ROOT / "scripts" / "install_capture_service.sh").read_text()
fake = (real.replace('UNIT_DIR="/etc/systemd/system"', f'UNIT_DIR="{units}"')
        .replace('INSTALL_DIR="/usr/local/lib/agentalsec"',
                 f'INSTALL_DIR="{work}/lib"'))
(proj / "scripts" / "install_capture_service.sh").write_text(fake)
(work / "lib").mkdir()

known = oi._variables(fake, proj)
unit_text = oi.expected(proj)[f"{units}/agentalsec-names.service"][1].exact
unit = units / "agentalsec-names.service"
unit.write_text(unit_text)
os.chmod(unit, 0o644)
copied = work / "lib" / "names_helper.py"
copied.write_bytes(helper)
os.chmod(copied, 0o755)

real_owned = oi._root_owned
oi._root_owned = lambda st: (st.st_uid == os.getuid()
                             and not (st.st_mode & 0o022))
try:
    check("the unit the installer writes is the app's own",
          oi.reason(str(unit), root=proj), "exactly what the installer writes")
    check("the helper it copies is the app's own",
          oi.reason(str(copied), root=proj),
          "identical to tools/names_helper.py")
    os.chmod(unit, 0o666)
    check("not when other accounts can write it",
          oi.reason(str(unit), root=proj), None)
    os.chmod(unit, 0o644)
    unit.write_text(unit_text.replace("ExecStart=/usr/bin/python3",
                                      "ExecStart=/tmp/evil"))
    check("not when one line differs",
          oi.reason(str(unit), root=proj), None)
    copied.write_bytes(helper + b"import os\n")
    check("not when the helper differs from the project",
          oi.reason(str(copied), root=proj), None)
    check("a file no installer writes is never the app's own",
          oi.reason("/etc/passwd", root=proj), None)
    check("nor a folder outside the app's own install folder",
          oi.reason(str(work / "lib"), root=proj), None)
finally:
    oi._root_owned = real_owned

check("a dropped-in name alone proves nothing without root ownership",
      oi.reason(str(unit), root=proj), None)

print("\n[3] the audit log")
check("the installer's check file in sudoers.d is recognised",
      bool(oi.inert_check_file("/etc/sudoers.d/.agentalsec-check.Ab12Cd")),
      True)
check("another file there is not",
      oi.inert_check_file("/etc/sudoers.d/evil"), None)
check("nor the same name anywhere else",
      oi.inert_check_file("/etc/cron.d/.agentalsec-check.Ab12Cd"), None)


def rec(msg, item, name, nametype, inode="1"):
    return {"type": "PATH", "msg_id": msg, "at_iso": None,
            "fields": {"item": item, "name": name, "nametype": nametype,
                       "inode": inode}}


records = [
    rec(7, "0", "/etc/sudoers.d/", "PARENT"),
    rec(7, "1", "/etc/sudoers.d/.agentalsec-check.Ab12Cd", "CREATE"),
    rec(8, "0", "/etc/cron.d/", "PARENT"),
    rec(8, "1", "/etc/cron.d/planted", "CREATE"),
    rec(9, "0", "/etc/ssh/", "PARENT"),
]
real_pkg = am._package_explains
am._package_explains = lambda path, at: False
try:
    out, counts = am._findings_from(records)
finally:
    am._package_explains = real_pkg
raised = sorted(f["entity_value"] for f in out
                if f["detection_id"] == "AUD-1002")
check("a planted file is still raised, a folder alone too, and the installer's"
      " own steps are not", raised, ["/etc/cron.d/planted", "/etc/ssh/"])
check("what was held back is counted", counts.get("by_own_install"), 3)

print("\n[4] the startup monitor")
real_reason = oi.reason
oi.reason = lambda p, digest=None, root=None: (
    "exactly what the installer writes" if "agentalsec" in p else None)
try:
    own = {"kind": "systemd_service", "name": "agentalsec-names.service",
           "path": "/etc/systemd/system/agentalsec-names.service",
           "detail": "/usr/bin/python3 /usr/local/lib/agentalsec/names_helper.py"}
    other = {"kind": "systemd_service", "name": "backdoor.service",
             "path": "/etc/systemd/system/backdoor.service",
             "detail": "/tmp/x"}
    found = ar.change_findings({"added": [own, other], "changed": [],
                                "removed": []})
    check("a new unit of the app's own is not raised, another is",
          [f["name"] for f in found], ["backdoor.service"])
    found = ar.change_findings({"added": [], "changed": [],
                                "removed": [own]})
    check("a removed one is still reported, it could be an attack",
          len(found), 1)
finally:
    oi.reason = real_reason

print("\n[5] open alerts from before are closed at startup, with the reason")
from core import memory_engine as me                    # noqa: E402
from core import sensors as sn                          # noqa: E402
sn.register_local()


def aud(name, nametype, msg):
    return me.save_finding(
        session_id="t", source="auditd", severity="low", entity_type="file",
        entity_value=name, title=f"Audit watch touched: {name}",
        raw_data={"msg_id": msg, "at": "2026-10-19T02:00:00+00:00",
                  "fields": {"name": name, "nametype": nametype,
                             "inode": "1"}},
        detection_id="AUD-1002", reviewed="test")


aud("/etc/sudoers.d/.agentalsec-check.Zz9Yy8", "CREATE", 41)
aud("/etc/cron.d/planted", "CREATE", 42)
aud("/etc/cron.d/", "PARENT", 42)
check("two of three close", oi.close_open_alerts(), 2)
with me._get_conn() as conn:
    rows = {r["entity_value"]: (r["dismissed"], r["dismissed_reason"] or "")
            for r in conn.execute("SELECT entity_value, dismissed, "
                                  "dismissed_reason FROM findings")}
check("the planted file stays open",
      rows["/etc/cron.d/planted"][0], 0)
check("the check file closes and says why",
      rows["/etc/sudoers.d/.agentalsec-check.Zz9Yy8"][1].startswith(
          oi.OWN_MARK), True)
check("a second run closes nothing more", oi.close_open_alerts(), 0)

shutil.rmtree(work, ignore_errors=True)
print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
