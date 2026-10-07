# tests/test_gateway_v2.py
# Router agent version 2 against real nftables in a private network
# namespace: hardware address blocks, the saved state, restore after the
# table is lost, per-device counters, and the upgrade from a version 1 table.

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

if os.environ.get("GW_TEST_IN_NS") != "1":
    if not (shutil.which("unshare") and shutil.which("busybox") and shutil.which("nft")):
        print("SKIP: unshare, busybox or nft is not available")
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


sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "br-lan", "type", "dummy")
sh("ip", "link", "set", "br-lan", "address", "02:00:00:00:00:01")
sh("ip", "addr", "add", "172.22.0.1/24", "dev", "br-lan")
sh("ip", "link", "set", "br-lan", "up")

tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "dhcp.leases").write_text(
    "1790000000 aa:bb:cc:00:00:01 172.22.0.10 console *\n"
    "1790000000 aa:bb:cc:00:00:02 172.22.0.11 phone *\n"
    "1790000000 aa:bb:cc:00:00:03 203.0.113.9 not-lan *\n")
state_dir = tmp / "state"

src = (ROOT / "tools" / "gateway_agent.sh").read_text()
src = src.replace('LEASE_FILES="', f'LEASE_FILES="{tmp / "dhcp.leases"} ', 1)
src = src.replace("STATE_DIR=/etc/agentalsec", f"STATE_DIR={state_dir}", 1)
src = src.replace("if have logread; then", "if false; then")
src = src.replace("elif have journalctl; then", "elif false; then")
agent = tmp / "agent.sh"
agent.write_text(src)


def run(command):
    env = {"SSH_ORIGINAL_COMMAND": command,
           "SSH_CLIENT": "172.22.0.50 40000 22", "PATH": os.environ["PATH"]}
    return subprocess.run(["busybox", "sh", str(agent)], env=env,
                          capture_output=True, text=True, timeout=60).stdout


g = gw.Gateway({"gateway": {"host": "172.22.0.1"}}, transport=run)

print("\n[probe]")
p = g.probe()
check("version 2 capabilities", [c for c in ("blockmac", "counters", "persist") if c in p["capabilities"]],
      ["blockmac", "counters", "persist"])
import re as _re
check("agent version", p["agent_version"],
      _re.search(r"^VERSION=(\d+)", (ROOT / "tools" / "gateway_agent.sh").read_text(), _re.M).group(1))
check("portal tools listed", isinstance(p["portal_tools"], list), True)

print("\n[hardware address blocks]")
out = g.block_mac("AA:BB:CC:00:00:01")
check("blocked and read back", out.get("verified"), "read_back")
check("in the block list", "aa:bb:cc:00:00:01" in g.blocks(), True)
check("saved to the state file", (state_dir / "blocks").read_text(), "mac aa:bb:cc:00:00:01\n")
check("again says already", g.block_mac("aa:bb:cc:00:00:01").get("already"), "yes")
check("state not doubled", (state_dir / "blocks").read_text().count("aa:bb"), 1)
for mac, why in (("02:00:00:00:00:01", "the router's own interface"),
                 ("ff:ff:ff:ff:ff:ff", "broadcast")):
    try:
        g.block_mac(mac)
        check(f"{why} is refused", "not refused", "refused")
    except gw.GatewayError as e:
        check(f"{why} is refused", "refused" in str(e), True)
try:
    g.block_mac("not-a-mac")
    check("garbage refused before sending", "sent", "refused")
except gw.GatewayError:
    check("garbage refused before sending", "refused", "refused")
rules = sh("nft", "list", "chain", "inet", "agentalsec_gw", "prerouting").stdout
check("blocked device keeps DNS and DHCP", "dport { 53, 67 } accept" in rules, True)

sh("nft", "delete", "chain", "inet", "agentalsec_gw", "prerouting")
c = g.counters()
check("missing hardware address rules are put back on the next call",
      (c["mac_rules"], "dport { 53, 67 }" in sh("nft", "list", "chain", "inet", "agentalsec_gw", "prerouting").stdout),
      (True, True))

print("\n[ip blocks are saved too]")
g.block("172.22.0.11")
check("ip saved", "ip 172.22.0.11" in (state_dir / "blocks").read_text(), True)

print("\n[restore after the table is lost]")
sh("nft", "delete", "table", "inet", "agentalsec_gw")
c = g.counters()
check("counters notice and restore", c["restored"], True)
check("both blocks are back", sorted(g.blocks()), ["172.22.0.11", "aa:bb:cc:00:00:01"])
check("restore verb", g.restore().get("restored"), "2")

print("\n[counters]")
c = g.counters()
check("one entry per LAN lease, public address left out", sorted(c["devices"]),
      ["172.22.0.10", "172.22.0.11"])
check("counters start at zero", c["devices"]["172.22.0.10"],
      {"up_packets": 0, "up_bytes": 0, "down_packets": 0, "down_bytes": 0})
check("second call is not a restore", c["restored"], False)
sh("nft", "flush", "chain", "inet", "agentalsec_gw", "devcount")
sh("nft", "add", "rule", "inet", "agentalsec_gw", "devcount", "ip", "saddr", "172.22.0.10",
   "counter", "packets", "3", "bytes", "300")
sh("nft", "add", "rule", "inet", "agentalsec_gw", "devcount", "ip", "daddr", "172.22.0.10",
   "counter", "packets", "7", "bytes", "7000")
check("counter values are read back per direction", g.counters()["devices"]["172.22.0.10"],
      {"up_packets": 3, "up_bytes": 300, "down_packets": 7, "down_bytes": 7000})
check("no duplicate counters on a second call",
      sh("nft", "list", "chain", "inet", "agentalsec_gw", "devcount").stdout.count("ip saddr 172.22.0.10 "), 1)

print("\n[unblock clears the saved state]")
check("unblock mac", g.unblock_mac("aa:bb:cc:00:00:01").get("was_blocked"), "yes")
check("unblock ip", g.unblock("172.22.0.11").get("was_blocked"), "yes")
check("state file empty", (state_dir / "blocks").read_text(), "")
sh("nft", "delete", "table", "inet", "agentalsec_gw")
g.counters()
check("nothing comes back after a reboot", g.blocks(), [])

print("\n[upgrade from a version 1 table]")
sh("nft", "delete", "table", "inet", "agentalsec_gw")
v1 = subprocess.run(["nft", "-f", "-"], input=(
    "table inet agentalsec_gw {\n set blocked4 { type ipv4_addr; }\n"
    " set blocked6 { type ipv6_addr; }\n set blockedmac { type ether_addr; }\n}\n"),
    text=True, capture_output=True)
(state_dir / "blocks").write_text("ip 172.22.0.10\n")
c = g.counters()
check("old table rebuilt and refilled", (c["restored"], g.blocks()), (True, ["172.22.0.10"]))

shutil.rmtree(tmp, ignore_errors=True)
print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
