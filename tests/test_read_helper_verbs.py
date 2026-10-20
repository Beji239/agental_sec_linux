"""
tests/test_read_helper_verbs.py, the root read helper's entry point and verbs.

Run as the owner, not root: the helper must refuse cleanly before reading
anything, and each verb's own reading and parsing is driven with stand-ins
where root or a long dpkg run would be needed. Nothing here runs as root.

Run it directly: python tests/test_read_helper_verbs.py
"""
import base64
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate_db                                      # noqa: E402
_isolate_db.isolate()

from tools import read_helper as rh                     # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def run(*argv):
    """main() as sudo would call it: (exit code, parsed reply or None)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            code = rh.main(["read_helper.py", *argv])
        except SystemExit as e:
            code = e.code
    text = out.getvalue().strip()
    try:
        return code, json.loads(text) if text else None
    except ValueError:
        return code, text


@contextlib.contextmanager
def patched(obj, **values):
    old = {k: getattr(obj, k) for k in values}
    for k, v in values.items():
        setattr(obj, k, v)
    try:
        yield
    finally:
        for k, v in old.items():
            setattr(obj, k, v)


ROOT_USER = os.geteuid() == 0

print("[1] the entry point refuses before it reads")
check("no argument prints the table and stops", run()[0], 2)
code, reply = run("sudoers", "/etc/shadow")
check("a second argument is refused, nothing read",
      (code, reply["ok"], "NOTHING WAS READ" in reply["refused"]),
      (1, False, True))
code, reply = run("--verbs")
check("--verbs lists exactly the table",
      (code, sorted(reply["verbs"])), (0, sorted(rh.VERBS)))
check("and says /etc/shadow must never be added",
      "MUST NOT BE ADDED" in reply["refuses"]["/etc/shadow"], True)
code, reply = run("shadow")
check("an unknown verb is refused by name",
      (code, "No verb named 'shadow'" in reply["refused"]), (1, True))
code, reply = run("sudoers")
check("run from a folder the owner can write, it refuses itself",
      (code, "could be replaced by a non-root account" in reply["refused"]),
      (1, True))
with patched(rh, assert_self_is_safe=lambda: None):
    if not ROOT_USER:
        code, reply = run("sudoers")
        check("installed safely but not elevated, it says so",
              (code, "not root" in reply["refused"]), (1, True))


def raises(exc):
    def f():
        raise exc
    return f


with patched(rh, assert_self_is_safe=lambda: None,
             assert_elevated=lambda: None):
    with patched(rh, HANDLERS=dict(rh.HANDLERS,
                                   sudoers=raises(rh.Refusal("no")))):
        check("a verb's own refusal is passed on", run("sudoers")[1]["refused"],
              "no")
    with patched(rh, HANDLERS=dict(rh.HANDLERS,
                                   sudoers=raises(KeyError("x")))):
        check("any other failure says the helper could not read, nothing more",
              "this helper could not read it" in
              run("sudoers")[1]["refused"], True)
    if not ROOT_USER:
        code, reply = run("sudoers")
        entry = reply["entries"]["/etc/sudoers"]
        check("unreadable here, the reply says why and claims no content",
              (code, reply["ok"], entry["readable"], entry["unreadable_reason"],
               reply["entries"]["content"]),
              (0, True, False, "permission denied", None))

print("\n[2] reading files")
work = pathlib.Path(tempfile.mkdtemp(prefix="readhelper."))
small = work / "small"
small.write_bytes(b"x" * 10)
check("a file is read", rh._read(small), (b"x" * 10, None))
check("a missing one is gone", rh._read(work / "none"), (None, "gone"))
check("one over the limit is not read",
      rh._read(small, limit=4), (None, "larger than 4 bytes, not read"))
if not ROOT_USER:
    locked = work / "locked"
    locked.write_bytes(b"secret")
    locked.chmod(0)
    check("one it may not open says so", rh._read(locked),
          (None, "permission denied"))
    locked.chmod(0o600)
(work / "link").symlink_to(small)
check("kinds", [rh._meta(p)["type"] for p in (small, work, work / "link")],
      ["file", "dir", "link"])
check("a missing path does not exist", rh._meta(work / "none"),
      {"exists": False})

print("\n[3] root's keys, parsed per key")
keys = (b"# admin keys\n\nssh-ed25519 AAAA1 ops@laptop\n"
        b"ssh-rsa AAAA2 backup server key\nssh-ed25519 AAAA3\n")
with patched(rh, _read=lambda p, limit=0: (keys, None),
             _meta=lambda p: {"exists": True}):
    out = rh.verb_root_ssh()
    check("every key line, comments and blanks left out",
          sorted((k["type"], k["comment"]) for k in out["keys"].values()),
          [("ssh-ed25519", ""), ("ssh-ed25519", "ops@laptop"),
           ("ssh-rsa", "backup server key")])
    with patched(rh, MAX_KEYS=2):
        check("a huge file is capped and says so",
              (len(rh.verb_root_ssh()["keys"]),
               rh.verb_root_ssh().get("keys_capped")), (2, True))
with patched(rh, _read=lambda p, limit=0: (None, "permission denied"),
             _meta=lambda p: {"exists": None}):
    check("unreadable, no keys are claimed",
          (rh.verb_root_ssh()["readable"], rh.verb_root_ssh()["keys"]),
          (False, {}))

print("\n[4] the drop-in folder, failed logins, processes")
d = rh.verb_sudoers_d()
check("every file in /etc/sudoers.d is listed",
      d["total"], len([n for n in os.listdir("/etc/sudoers.d")
                       if os.path.isfile(os.path.join("/etc/sudoers.d", n))]))
btmp = work / "btmp"
btmp.write_bytes(b"A" * 1000)
with patched(rh, VERBS=dict(rh.VERBS, btmp={"paths": [str(btmp)],
                                            "why": "test"}),
             BTMP_MAX=100):
    b = rh.verb_btmp()
    check("only the newest records are sent",
          (b["size"], b["start"], base64.b64decode(b["data_b64"])),
          (1000, 900, b"A" * 100))
with patched(rh, VERBS=dict(rh.VERBS, btmp={"paths": [str(work / "none")],
                                            "why": "test"})):
    try:
        rh.verb_btmp()
        refused = False
    except rh.Refusal:
        refused = True
    check("a missing log is a refusal", refused, True)
spool = work / "crontabs"
spool.mkdir()
(spool / "alice").write_text("*/5 * * * * /home/alice/sync.sh\n")
(spool / "big").write_text("#" * 200)
secret = work / "secret"
secret.write_text("root:hash:")
(spool / "mallory").symlink_to(secret)
with patched(rh, VERBS=dict(rh.VERBS, user_crontabs={"paths": [str(spool)],
                                                     "why": "test"}),
             CRONTAB_MAX_BYTES=100):
    c = rh.verb_user_crontabs()
    check("each account's crontab is read",
          c["entries"]["alice"]["content"], "*/5 * * * * /home/alice/sync.sh\n")
    check("a link in the spool is listed, never followed",
          ("mallory" in c["entries"], c["skipped"].get("mallory", "")[:22]),
          (False, "not a regular file (li"))
    check("an oversized crontab is skipped and says so",
          ("big" in c["entries"], "larger than" in c["skipped"].get("big", "")),
          (False, True))
with patched(rh, VERBS=dict(rh.VERBS, user_crontabs={
        "paths": [str(work / "nospool")], "why": "test"})):
    check("no spool at all is an empty answer, not an error",
          rh.verb_user_crontabs()["total"], 0)
p = rh.verb_proc_exe()
me = p["processes"].get(str(os.getpid()))
check("this process is listed with its file and start time",
      (bool(me and me["exe"]), isinstance(me["start_ticks"], int)),
      (True, True))
with patched(rh, MAX_PIDS=1):
    check("the list is capped and says so", rh.verb_proc_exe()["capped"], True)
check("a process that is gone has no start time",
      rh._start_ticks("999999999"), None)
with patched(rh, _read=lambda p, limit=0: (b"1 (a) b", None)):
    check("a short stat line has none either", rh._start_ticks("1"), None)

print("\n[5] the firewall and dpkg, fixed commands only")
with patched(rh, FIREWALL_COMMANDS=(("echo", ["/bin/echo", "rules"]),
                                    ("gone", ["/no/such/nft", "list"]))):
    fw = rh.verb_firewall_rules()
    check("a listing is returned with its exit code",
          (fw["echo"]["rc"], fw["echo"]["stdout"]), (0, "rules\n"))
    check("a tool that is not installed is None, not an error", fw["gone"],
          None)


class Done:
    def __init__(self, out="", rc=0):
        self.stdout, self.stderr, self.returncode = out, "", rc


calls = []


def fake_run(argv, **kw):
    calls.append(argv)
    if argv[0] == "dpkg-query":
        return Done("coreutils\tii \nno-such-package-x\tii \nold\trc \n")
    return Done("", 0)


with patched(rh.subprocess, run=fake_run):
    v = rh.verb_dpkg_verify()
check("only installed packages with a checksum list are verified",
      (v["ran"], v["packages_installed"], calls[-1][:2]),
      (True, 2, ["dpkg", "-V"]))
check("and the list comes from dpkg itself, never from the caller",
      calls[0][0], "dpkg-query")
with patched(rh.subprocess, run=lambda argv, **kw: Done("")):
    check("no packages, nothing run", rh.verb_dpkg_verify()["ran"], False)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
