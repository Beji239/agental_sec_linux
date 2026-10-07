"""
tests/test_gateway_messages_iptables.py: messages on a router whose nft has
no nat, as on OpenWrt 21.02 with fw3.

Runs the agent the way tests/test_gateway_messages.py does, behind an nft
stand-in that refuses any nat chain with the kernel's own error. The agent
must fall back to marking in nft and redirecting with iptables, and put the
iptables half back after a firewall restart drops it.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

if os.environ.get("GW_TEST_IN_NS") != "1":
    if not all(shutil.which(t) for t in ("unshare", "busybox", "nft", "iptables")):
        print("SKIP: unshare, busybox, nft or iptables is not available")
        sys.exit(0)
    env = dict(os.environ, GW_TEST_IN_NS="1")
    sys.exit(subprocess.run(["unshare", "-rn", sys.executable, __file__],
                            env=env).returncode)

sys.path.insert(0, str(ROOT))
from tools import gateway as gw  # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def sh(*argv):
    return subprocess.run(argv, check=False, capture_output=True, text=True)


DEVICE = "00:00:5e:00:53:01"
sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "br-lan", "type", "veth", "peer", "name", "lanpeer")
sh("ip", "addr", "add", "192.0.2.1/24", "dev", "br-lan")
sh("ip", "link", "set", "br-lan", "up")
sh("ip", "link", "set", "lanpeer", "up")
sh("ip", "route", "add", "default", "via", "192.0.2.254")
sh("ip", "neigh", "add", "192.0.2.10", "lladdr", DEVICE, "dev", "br-lan")

tmp = pathlib.Path(tempfile.mkdtemp())
state = tmp / "state"
bin_dir = tmp / "bin"
bin_dir.mkdir()
pidfile = tmp / "uhttpd.pid"
fake = bin_dir / "uhttpd"
fake.write_text(f"""#!/bin/sh
case " $* " in *" -h "*) [ $# -eq 1 ] && {{ echo "  -E string  404 error handler"; exit 0; }} ;; esac
( while :; do sleep 1; done ) </dev/null >/dev/null 2>&1 &
echo $! > {pidfile}
""")
fake.chmod(0o755)

# nft as on the router: everything works except a nat chain.
real_nft = shutil.which("nft")
nft = bin_dir / "nft"
nft.write_text(f"""#!/bin/sh
prev=""
for a in "$@"; do
    case "$a" in *"type nat"*) nat=1 ;; esac
    [ "$prev" = -f ] && [ -f "$a" ] && grep -q "type nat" "$a" && nat=1
    prev=$a
done
if [ -n "$nat" ]; then
    echo "$prev:5:11-16: Error: Could not process rule: No such file or directory" >&2
    exit 1
fi
exec {real_nft} "$@"
""")
nft.chmod(0o755)

src = (ROOT / "tools" / "gateway_agent.sh").read_text()
src = src.replace("/etc/agentalsec", str(state))
src = src.replace("PATH=/usr/sbin:", f"PATH={bin_dir}:/usr/sbin:", 1)
src = src.replace("for p in $(pidof uhttpd 2>/dev/null); do",
                  f"for p in $(cat {pidfile} 2>/dev/null); do", 1)
src = src.replace("if have logread; then", "if false; then")
src = src.replace("elif have journalctl; then", "elif false; then")
agent = tmp / "agent.sh"
agent.write_text(src)
PATH = f"{bin_dir}:{os.environ['PATH']}"


def run(command):
    env = {"SSH_ORIGINAL_COMMAND": command, "SSH_CLIENT": "192.0.2.50 40000 22",
           "SSH_CONNECTION": "192.0.2.50 40000 192.0.2.1 22", "PATH": PATH}
    return subprocess.run(["busybox", "sh", str(agent)], env=env,
                          capture_output=True, text=True, timeout=60).stdout


def portal_chain():
    return sh(real_nft, "list", "chain", "inet", "agentalsec_gw", "portal").stdout


def ipt_nat():
    return sh("iptables", "-t", "nat", "-S").stdout


g = gw.Gateway({"gateway": {"host": "192.0.2.1"}}, transport=run)

print("\n[1] the probe still offers messages, through iptables")
probe = run("probe")
check("message is a capability", "cap=message" in probe, True)
check("and says how it redirects", "message_redirect=iptables" in probe, True)

print("\n[2] a message to one device")
out = g.message(DEVICE, "Dinner is ready.")
check("it is in force and read back", (out.get("target"), out.get("verified")), (DEVICE, "read_back"))
chain = portal_chain()
check("nft marks, it does not redirect",
      ("type filter" in chain, "meta mark set" in chain, "dnat" in chain), (True, True, False))
check("before nat, so iptables sees the mark", "priority mangle" in chain or "-150" in chain, True)
check("for the devices in the set", "@msgmac" in chain, True)
nat = ipt_nat()
check("iptables redirects marked port 80 to the page",
      "-A AGENTALSEC_MSG -p tcp -m tcp --dport 80 -m mark --mark 0x10000000/0x10000000 "
      "-j DNAT --to-destination 192.0.2.1:2050" in nat, True)
check("from the top of PREROUTING", "-A PREROUTING -j AGENTALSEC_MSG" in nat, True)

print("\n[3] every device")
g.message("all", "The internet goes off at 22:00.")
chain = portal_chain()
check("the all rule marks too",
      any('comment "msgall"' in l and "meta mark set" in l for l in chain.splitlines()), True)
g.unmessage("all")
check("lifting it removes the rule", 'comment "msgall"' in portal_chain(), False)

print("\n[4] a firewall restart drops the iptables half; counters puts it back")
sh("iptables", "-t", "nat", "-F")
sh("iptables", "-t", "nat", "-X")
check("gone", "AGENTALSEC_MSG" in ipt_nat(), False)
run("counters")
nat = ipt_nat()
check("redirect back", ("-A PREROUTING -j AGENTALSEC_MSG" in nat,
                        "--to-destination 192.0.2.1:2050" in nat), (True, True))
run("counters")
check("added once, not again on every poll",
      ipt_nat().count("-A PREROUTING -j AGENTALSEC_MSG"), 1)

print("\n[5] restore after a reboot")
sh(real_nft, "delete", "table", "inet", "agentalsec_gw")
sh("iptables", "-t", "nat", "-F")
sh("iptables", "-t", "nat", "-X")
r = run("restore")
check("restore answers", r.startswith("OK restore"), True)
check("device back in the set",
      DEVICE in sh(real_nft, "list", "set", "inet", "agentalsec_gw", "msgmac").stdout, True)
check("and the iptables redirect", "-A PREROUTING -j AGENTALSEC_MSG" in ipt_nat(), True)

print("\n[6] a real packet from the device is redirected")
import socket, struct  # noqa: E402


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xffff)
    return ~(s + (s >> 16)) & 0xffff


def syn_from(mac, src, dst):
    tcp = struct.pack("!HHIIBBHHH", 40000, 80, 1, 0, 5 << 4, 0x02, 64240, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    link = sh("ip", "-o", "link", "show", "br-lan").stdout.split()
    lan_mac = link[link.index("link/ether") + 1]
    eth = bytes.fromhex(lan_mac.replace(":", "")) + bytes.fromhex(mac.replace(":", "")) + b"\x08\x00"
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("lanpeer", 0))
    s.send(eth + ip + tcp)
    s.close()


def dnat_packets():
    out = sh("iptables", "-t", "nat", "-L", "AGENTALSEC_MSG", "-v", "-n", "-x").stdout
    rows = [l.split() for l in out.splitlines() if "DNAT" in l]
    return int(rows[0][0]) if rows else -1


before = dnat_packets()
syn_from(DEVICE, "192.0.2.10", "198.51.100.80")
check("the device's SYN to port 80 hits the redirect", dnat_packets() - before, 1)
syn_from("00:00:5e:00:53:99", "192.0.2.12", "198.51.100.80")
check("another device's does not", dnat_packets() - before, 1)

print("\n[7] neither nat: refused with a reason, not a half rule")
sh(real_nft, "delete", "table", "inet", "agentalsec_gw")
noipt = bin_dir / "iptables"
noipt.write_text("#!/bin/sh\necho 'iptables: Table does not exist' >&2\nexit 1\n")
noipt.chmod(0o755)
check("probe stops offering messages", "cap=message" in run("probe"), False)
r = run("message " + DEVICE + " 41")
check("a message is refused", r.startswith("ERR") and "no nat" in r, True)
noipt.unlink()

try:
    os.kill(int(pidfile.read_text()), 9)
except (OSError, ValueError):
    pass
shutil.rmtree(tmp, ignore_errors=True)
print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
