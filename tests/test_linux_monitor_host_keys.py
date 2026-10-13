"""
tests/test_linux_monitor_host_keys.py, the Linux monitor pins host keys.

Trust on first use only means something if the first key is kept: the first
key a host shows is saved to the app's own known_hosts, and a host showing a
different key after that is refused. strict_host_key refuses unknown hosts.
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402
import _skip  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_isolate_db.isolate()

try:
    import paramiko
except ImportError:
    _skip.skip("needs paramiko")

from tools import linux_monitor as lm  # noqa: E402

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        print(f"        {detail}")


tmp = pathlib.Path(tempfile.mkdtemp())
lm.KNOWN_HOSTS = str(tmp / "conf" / "linux_monitor_known_hosts")
seen = {}


class FakeClient(paramiko.SSHClient):
    """A real SSHClient whose connect shows a chosen host key."""
    server_key = None

    def _log(self, *a, **k):
        pass

    def connect(self, hostname, port=22, **kw):
        seen["policy"] = type(self._policy).__name__
        server_key = FakeClient.server_key
        name = hostname if port == 22 else f"[{hostname}]:{port}"
        ours = self._host_keys.lookup(name) or {}
        known = ours.get(server_key.get_name())
        if known is None:
            self._policy.missing_host_key(self, name, server_key)
        elif known != server_key:
            raise paramiko.BadHostKeyException(name, server_key, known)


lm.paramiko.SSHClient = FakeClient
mon = lm.LinuxMonitor.__new__(lm.LinuxMonitor)
mon.host, mon.port, mon.user, mon.key_path = "203.0.113.30", 22, "u", None
mon.strict_host_key = False

print("First use")
key1 = paramiko.RSAKey.generate(1024)
FakeClient.server_key = key1
check("the first connection is accepted", mon._connect() is not None)
saved = paramiko.HostKeys(lm.KNOWN_HOSTS)
check("and its key is saved to the app's known_hosts",
      saved.lookup("203.0.113.30") is not None
      and saved.lookup("203.0.113.30")["ssh-rsa"] == key1, saved.keys())
mode = os.stat(lm.KNOWN_HOSTS).st_mode & 0o777
check("the file is readable by this user only", mode == 0o600, oct(mode))
check("its folder too",
      os.stat(os.path.dirname(lm.KNOWN_HOSTS)).st_mode & 0o777 == 0o700)

print("\nA changed key")
FakeClient.server_key = paramiko.RSAKey.generate(1024)
check("a host showing a different key is refused", mon._connect() is None)
check("and the saved key is not replaced",
      paramiko.HostKeys(lm.KNOWN_HOSTS).lookup("203.0.113.30")["ssh-rsa"]
      == key1)
FakeClient.server_key = key1
check("the original key still connects", mon._connect() is not None)

print("\nstrict_host_key")
mon.strict_host_key = True
mon.host = "203.0.113.31"
check("an unknown host is refused", mon._connect() is None)
check("with RejectPolicy", seen.get("policy") == "RejectPolicy", seen)
check("and nothing is saved for it",
      paramiko.HostKeys(lm.KNOWN_HOSTS).lookup("203.0.113.31") is None)

print(f"\n{'FAILED' if failures else 'ALL PASSED'}"
      f"{f': {len(failures)} check(s)' if failures else ''}")
sys.exit(1 if failures else 0)
