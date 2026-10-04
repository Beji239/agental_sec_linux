# tests/test_socket_activation_owner.py
# A port systemd holds for socket activation is named by its socket unit and
# the service it starts, read from the unit files and their drop-ins, so
# sshd on ssh.socket is not reported as "no SSH server".

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools import port_owner as po  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp())
lib, gen, etc = tmp / "lib", tmp / "generator", tmp / "etc"
for d in (lib, gen / "ssh.socket.d", etc):
    d.mkdir(parents=True)
(lib / "ssh.socket").write_text(
    "[Socket]\nListenStream=0.0.0.0:22\nListenStream=[::]:22\nAccept=no\n")
(gen / "ssh.socket.d" / "addresses.conf").write_text(
    "[Socket]\nListenStream=\nListenStream=0.0.0.0:50022\nListenStream=[::]:50022\n")
(lib / "cups.socket").write_text("[Socket]\nListenStream=/run/cups/cups.sock\n")
(lib / "web.socket").write_text("[Socket]\nListenStream=8080\nService=webapp.service\n")
(lib / "conn@.socket").write_text("[Socket]\nListenStream=9999\nAccept=yes\n")
po._UNIT_DIRS = (str(etc), str(gen), str(lib))
po._socket_units_cache["at"] = 0.0

units = po.socket_units()
check("the generated drop-in replaces the packaged port", units.get(50022),
      ("ssh.socket", "ssh.service"))
check("and the packaged port is gone", 22 in units, False)
check("a unix socket has no port", any(v[0] == "cups.socket" for v in units.values()), False)
check("Service= names the service it starts", units.get(8080), ("web.socket", "webapp.service"))
check("a per-connection template is left out", 9999 in units, False)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
