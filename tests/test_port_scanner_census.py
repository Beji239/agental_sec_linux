"""
tests/test_port_scanner_census.py, the kernel's view of what is listening.

    PS-21  a self-scan is checked against the kernel's listener table, and
           each listener the probes missed is named with the reason
    PS-22  raw and packet sockets (no port, invisible to any scan) are read,
           and a staged holder raises LNX-5001
    PS-23  UDP answers carry the exact ICMP type, code and sender (IP_RECVERR)
    PS-24  the firewall's verdict per listener, from iptables-save and nft

The parts that need real sockets or firewall rules run under `unshare -rn`
(a user namespace, no root) and are skipped with a note where that is not
available. Addresses are RFC 5737 / RFC 3849 documentation ranges.
"""
import os
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

import _isolate_db                                       # noqa: E402
_isolate_db.isolate()

from tools import port_scanner as ps                     # noqa: E402
from tools import socket_census as sc                    # noqa: E402

fails, skips = [], []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def in_namespace(script: str, setup: str = "") -> str | None:
    """Run python code inside `unshare -rn`; None when namespaces are refused."""
    if not shutil.which("unshare"):
        return None
    code = f"import sys; sys.path.insert(0, {ROOT!r})\n" + textwrap.dedent(script)
    cmd = f"ip link set lo up; {setup} python3 -c {shlex.quote(code)}"
    r = subprocess.run(["unshare", "-rn", "sh", "-c", cmd], capture_output=True,
                       text=True, timeout=120, cwd=ROOT)
    if r.returncode != 0 and "unshare" in (r.stderr or ""):
        return None
    if r.returncode != 0:
        print(f"  (namespace run failed, rc={r.returncode}: {r.stderr.strip()[-400:]})")
    return r.stdout + r.stderr


print("\n[1] PS-24: a ufw-shaped iptables-save ruleset")
UFW = textwrap.dedent("""\
    *filter
    :INPUT DROP [0:0]
    :FORWARD DROP [0:0]
    :OUTPUT ACCEPT [0:0]
    :ufw-before-input - [0:0]
    :ufw-user-input - [0:0]
    :ufw-not-local - [0:0]
    :ufw-user-limit - [0:0]
    :ufw-user-limit-accept - [0:0]
    -A INPUT -j ufw-before-input
    -A ufw-before-input -i lo -j ACCEPT
    -A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    -A ufw-before-input -m conntrack --ctstate INVALID -j DROP
    -A ufw-before-input -j ufw-not-local
    -A ufw-before-input -j ufw-user-input
    -A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN
    -A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN
    -A ufw-not-local -j DROP
    -A ufw-user-input -p tcp -m tcp --dport 22 -m comment --comment "'dapp_OpenSSH'" -j ACCEPT
    -A ufw-user-input -p udp -m multiport --dports 5353,1900 -j ACCEPT
    -A ufw-user-input -s 192.0.2.0/24 -p tcp -m tcp --dport 8080 -j ACCEPT
    -A ufw-user-input -p tcp -m tcp --dport 2222 -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource
    -A ufw-user-input -p tcp -m tcp --dport 2222 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 --name DEFAULT --mask 255.255.255.255 --rsource -j ufw-user-limit
    -A ufw-user-input -p tcp -m tcp --dport 2222 -j ufw-user-limit-accept
    -A ufw-user-input -p tcp -m tcp --dport 9999 -m weird --odd 1 -j ACCEPT
    -A ufw-user-limit -j REJECT --reject-with icmp-port-unreachable
    -A ufw-user-limit-accept -j ACCEPT
    COMMIT
    """)
fw = {"readable": True, "chainsets": sc.parse_iptables_save(UFW, "ip")}
for port, proto, want in [(22, "tcp", "allowed"), (80, "tcp", "blocked"),
                          (5353, "udp", "allowed"), (8080, "tcp", "allowed_from"),
                          (2222, "tcp", "allowed"), (9999, "tcp", "undetermined")]:
    check(f"ipv4 {proto}/{port}", sc.evaluate(fw, "ipv4", proto, port)["verdict"], want)
check("the source restriction is named",
      sc.evaluate(fw, "ipv4", "tcp", 8080)["only_from"], ["from 192.0.2.0/24"])
check("an unreadable match is named, not guessed",
      "-m weird" in " ".join(sc.evaluate(fw, "ipv4", "tcp", 9999)["why"]), True)
check("an IPv6 packet is not judged by the IPv4 rules",
      sc.evaluate(fw, "ipv6", "tcp", 80)["verdict"], "allowed")

print("\n[2] PS-24: exposure per listener")
check("a loopback listener is loopback_only",
      sc.exposure_for({"local_address": "127.0.0.53", "proto": "udp", "local_port": 53}, fw)["exposure"],
      "loopback_only")
check("a wildcard listener on a blocked port is firewalled",
      sc.exposure_for({"local_address": "0.0.0.0", "proto": "tcp", "local_port": 80}, fw)["exposure"],
      "firewalled")
check("and on an allowed port is reachable",
      sc.exposure_for({"local_address": "0.0.0.0", "proto": "tcp", "local_port": 22}, fw)["exposure"],
      "reachable")
hint = sc.exposure_for({"local_address": "0.0.0.0", "proto": "tcp", "local_port": 22},
                       {"readable": False, "ufw": {"present": True, "enabled": True,
                                                   "default_input_policy": "drop"}})
check("unreadable rules give unknown, not a guess", hint["exposure"], "unknown")
check("and say what ufw's readable files show", "default DROP" in hint["basis"], True)

print("\n[3] PS-24: native nftables through nft -j")
NFT = textwrap.dedent("""\
    table inet fw {
      set allowed_udp { type inet_service; elements = { 53, 123 } }
      chain svc { tcp dport 9000-9100 accept; return; }
      chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport { 22, 443 } accept
        ip saddr 192.0.2.0/24 tcp dport 3306 accept
        udp dport @allowed_udp accept
        tcp dport vmap { 80 : accept, 23 : drop }
        jump svc
      }
    }
    """)
nft_path = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"census_{os.getpid()}.nft")
with open(nft_path, "w") as fh:
    fh.write(NFT)
out = in_namespace("""
    from tools import socket_census as sc
    fw = sc.read_firewall()
    for fam, proto, port in [("ipv4","tcp",22),("ipv6","tcp",443),("ipv4","tcp",25),
                             ("ipv4","udp",53),("ipv4","tcp",80),("ipv4","tcp",23),
                             ("ipv4","tcp",9050),("ipv4","tcp",3306),("ipv6","tcp",3306)]:
        print("V", fam, proto, port, sc.evaluate(fw, fam, proto, port)["verdict"])
""", setup=f"nft -f {nft_path} &&")
os.unlink(nft_path)
if out is None:
    skips.append("native nftables (no user namespaces)")
else:
    got = {tuple(l.split()[1:4]): l.split()[4] for l in out.splitlines() if l.startswith("V ")}
    want = {("ipv4", "tcp", "22"): "allowed", ("ipv6", "tcp", "443"): "allowed",
            ("ipv4", "tcp", "25"): "blocked", ("ipv4", "udp", "53"): "allowed",
            ("ipv4", "tcp", "80"): "allowed", ("ipv4", "tcp", "23"): "blocked",
            ("ipv4", "tcp", "9050"): "allowed", ("ipv4", "tcp", "3306"): "allowed_from",
            ("ipv6", "tcp", "3306"): "blocked"}
    check("every nft verdict (sets, ranges, vmap, jump, family)", got, want)

print("\n[4] PS-23: the exact ICMP answer behind a UDP probe")


class FakeSock:
    def __init__(self, anc):
        self.anc = anc

    def recvmsg(self, *a):
        return b"", self.anc, 0, None


err = struct.pack("=IBBBBII", 113, 2, 3, 13, 0, 0, 0) + \
    struct.pack("=HH4s8x", socket.AF_INET, 0, socket.inet_aton("192.0.2.1"))
icmp = ps.read_icmp_error(FakeSock([(0, 11, err)]))
check("type, code, sender and meaning are read",
      (icmp["type"], icmp["code"], icmp["from"], icmp["meaning"]),
      (3, 13, "192.0.2.1", "communication administratively prohibited"))
out = in_namespace("""
    from tools import port_scanner as ps
    sc = ps.PortScanner("t")
    for h, p in (("192.0.2.1", 7777), ("192.0.2.1", 7779), ("2001:db8::1", 7777)):
        r = sc._check_udp_port(h, p)
        print("U", h, p, r["state"], (r.get("icmp") or {}).get("code"))
""", setup=("ip addr add 192.0.2.1/24 dev lo; ip -6 addr add 2001:db8::1/64 dev lo nodad;"
            " nft add table inet t && nft add chain inet t in '{ type filter hook input priority 0; }'"
            " && nft add rule inet t in udp dport 7777 reject with icmp type admin-prohibited"
            " && nft add rule inet t in udp dport 7777 reject with icmpv6 type admin-prohibited &&"))
if out is None:
    skips.append("IP_RECVERR against real ICMP (no user namespaces)")
else:
    got = [tuple(l.split()[1:]) for l in out.splitlines() if l.startswith("U ")]
    check("prohibited is filtered, port unreachable is closed, both families",
          got, [("192.0.2.1", "7777", "filtered", "13"), ("192.0.2.1", "7779", "closed", "3"),
                ("2001:db8::1", "7777", "filtered", "1")])

print("\n[5] PS-22: portless listeners and LNX-5001")
out = in_namespace("""
    import socket, os, shutil, subprocess, sys, time
    from tools import socket_census as sc
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, 253)
    rows = sc.hidden_listeners()["sockets"]
    mine = [x for x in rows if x.get("pid") == os.getpid()]
    print("MINE", sorted((x["kind"], x["protocol"]) for x in mine), all(not x["concern"] for x in mine))
    stage = "/dev/shm/census_test_py"
    shutil.copy(sys.executable, stage)
    child = subprocess.Popen([stage, "-c", "import socket, time; s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)); time.sleep(20)"],
                             env={"PYTHONHOME": sys.base_prefix})
    time.sleep(1.5)
    bad = sc.hidden_listeners()["concerning"]
    print("STAGED", [(x["pid"] == child.pid, x["protocol_name"], x["concern"]) for x in bad])
    child.kill(); os.unlink(stage)
""")
if out is None:
    skips.append("hidden sockets (no user namespaces)")
else:
    mine = next((l for l in out.splitlines() if l.startswith("MINE")), "")
    check("this process's packet and raw sockets are read and not a concern",
          mine, "MINE [('packet', 3), ('raw', 253)] True")
    staged = next((l for l in out.splitlines() if l.startswith("STAGED")), "")
    check("a packet socket held from /dev/shm is a concern",
          staged, "STAGED [(True, 'IPv4', 'it runs from /dev/shm/, a staging directory')]")

check("a deleted binary is a concern",
      sc.staged_location("/usr/sbin/sshd (deleted)"),
      "its binary has been deleted from disk while it runs")
check("a system binary is not", sc.staged_location("/usr/sbin/wpa_supplicant"), None)
from core import memory_engine as me                     # noqa: E402
from unittest import mock                                # noqa: E402
fake = {"sockets": [], "concerning": [{
    "kind": "packet", "protocol": 0x0800, "protocol_name": "IPv4",
    "interface": "any", "pid": 4242, "comm": "kworker", "exe": "/dev/shm/.x",
    "uid": "0", "inode": "1", "concern": "it runs from /dev/shm/, a staging directory"}],
    "unattributed": 0}
saved = []
with mock.patch.object(sc, "hidden_listeners", return_value=fake), \
        mock.patch.object(me, "save_finding", side_effect=lambda **kw: saved.append(kw) or {"id": 1}), \
        mock.patch.object(me, "is_dismissed", return_value=False):
    sc._reported_hidden.clear()
    first = sc.check_hidden("t")
    again = sc.check_hidden("t")
check("LNX-5001 is raised once per holder",
      ([k["detection_id"] for k in saved], first["raised"], again["raised"]),
      (["LNX-5001"], 1, 0))

print("\n[6] PS-21: what a self-scan missed, and why")
check("a wildcard v4 bind is reached by a v4 probe", ps._probe_reaches("0.0.0.0", {"127.0.0.1"}), True)
check("a bind to another loopback address is not", ps._probe_reaches("127.0.0.53", {"127.0.0.1"}), False)
check("::1 is not reached by a 127.0.0.1 probe", ps._probe_reaches("::1", {"127.0.0.1"}), False)
fake_census = {
    "listeners": [
        {"proto": "tcp", "local_address": "127.0.0.1", "local_port": 631, "comm": "cupsd",
         "exposure": "loopback_only", "basis": "b"},
        {"proto": "tcp", "local_address": "192.0.2.10", "local_port": 8000, "comm": "web",
         "exposure": "reachable", "basis": "b"},
        {"proto": "tcp", "local_address": "0.0.0.0", "local_port": 40000, "comm": "x",
         "exposure": "unknown", "basis": "b"},
        {"proto": "udp", "local_address": "0.0.0.0", "local_port": 5353, "comm": "avahi",
         "exposure": "unknown", "basis": "b"},
        {"proto": "sctp", "local_address": "0.0.0.0", "local_port": 3868, "comm": "d",
         "exposure": "unknown", "basis": "b"}],
    "hidden": {"sockets": [], "concerning": []}, "firewall": {}, "sctp_note": None,
    "coverage": "c"}
with mock.patch.object(sc, "census", return_value=fake_census):
    open_rows = [{"port": 631, "protocol": "tcp"}]
    view = ps.kernel_view("127.0.0.1", [22, 631, 5353], [5353], open_rows, [], "common")
why = {(m["proto"], m["port"]): m["why_missed"] for m in view["missed_by_probe"]}
check("a LAN-only bind is named", why[("tcp", 8000)].startswith("bound to 192.0.2.10 only"), True)
check("a port outside the set is named", why[("tcp", 40000)], "port 40000 is outside the 'common' tcp set")
check("a silent UDP service is named", why[("udp", 5353)], "a UDP service that did not answer the probe")
check("SCTP is named as not probed", why[("sctp", 3868)], "SCTP is not probed by this scanner")
check("the open port carries its exposure", open_rows[0].get("exposure"), "loopback_only")

print("\n" + "=" * 62)
if skips:
    print("SKIPPED (not failed): " + "; ".join(skips))
if fails:
    print(f"{len(fails)} FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL CHECKS PASSED")
