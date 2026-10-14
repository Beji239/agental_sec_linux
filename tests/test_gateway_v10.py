# tests/test_gateway_v10.py
# Router agent version 10 against real nftables in a private network
# namespace: a counter on each block, the blockhits verb, the upgrade from a
# version 9 table, and a router whose nft refuses set counters.

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
TABLE = "agentalsec_gw"


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def sh(*argv, stdin=None):
    return subprocess.run(argv, check=False, capture_output=True, text=True, input=stdin)


sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "br-lan", "type", "dummy")
sh("ip", "link", "set", "br-lan", "address", "02:00:00:00:00:01")
sh("ip", "addr", "add", "192.0.2.1/24", "dev", "br-lan")
sh("ip", "link", "set", "br-lan", "up")

tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "dhcp.leases").write_text(
    "1790000000 aa:bb:cc:00:00:01 192.0.2.10 console *\n"
    "1790000000 aa:bb:cc:00:00:02 192.0.2.11 phone *\n")


def make_agent(name, refuse_counters=False):
    state = tmp / f"state-{name}"
    src = (ROOT / "tools" / "gateway_agent.sh").read_text()
    src = src.replace('LEASE_FILES="', f'LEASE_FILES="{tmp / "dhcp.leases"} ', 1)
    src = src.replace("STATE_DIR=/etc/agentalsec", f"STATE_DIR={state}", 1)
    src = src.replace("if have logread; then", "if false; then")
    src = src.replace("elif have journalctl; then", "elif false; then")
    if refuse_counters:
        # An older nft that does not know a counter on a set element.
        shim = ('nft() { if [ "$1" = -f ] && grep -q "addr; counter;" "$2"; then '
                'echo "Error: syntax error, unexpected counter" >&2; return 1; fi; '
                'command nft "$@"; }\n')
        src = src.replace("export PATH LC_ALL=C\n", "export PATH LC_ALL=C\n" + shim, 1)
    path = tmp / f"agent-{name}.sh"
    path.write_text(src)

    def run(command):
        env = {"SSH_ORIGINAL_COMMAND": command,
               "SSH_CLIENT": "192.0.2.50 40000 22", "PATH": os.environ["PATH"]}
        return subprocess.run(["busybox", "sh", str(path)], env=env,
                              capture_output=True, text=True, timeout=60).stdout
    return gw.Gateway({"gateway": {"host": "192.0.2.1"}}, transport=run), state


g, state = make_agent("main")

print("\n[probe]")
p = g.probe()
check("version 10", p["agent_version"], "10")
check("offers block hits", "blockhits" in p["capabilities"], True)

print("\n[upgrade from a version 9 table]")
old = f"""table inet {TABLE} {{
    set blocked4 {{ type ipv4_addr; }}
    set blocked6 {{ type ipv6_addr; }}
    set blockedmac {{ type ether_addr; }}
    chain forward {{
        type filter hook forward priority -5; policy accept;
        ip saddr @blocked4 drop
        ip daddr @blocked4 drop
    }}
    chain devcount {{
        type filter hook forward priority 5; policy accept;
    }}
}}
"""
check("old table loads", sh("nft", "-f", "-", stdin=old).returncode, 0)
sh("nft", "add", "element", "inet", TABLE, "blocked4", "{ 198.51.100.7 }")
state.mkdir(parents=True, exist_ok=True)
(state / "blocks").write_text("ip 198.51.100.7\nmac aa:bb:cc:00:00:02\n")
c = g.counters()
check("the old table is made again and refilled", c["restored"], True)
check("the sets now count", "counter" in sh("nft", "list", "set", "inet", TABLE, "blocked4").stdout, True)
check("both blocks are back", sorted(g.blocks()), ["198.51.100.7", "aa:bb:cc:00:00:02"])
check("a second call keeps the table", g.counters()["restored"], False)

print("\n[block hits]")
h = g.block_hits()
check("counted", h["counted"], True)
check("each block starts at zero", h["hits"],
      {"198.51.100.7": {"packets": 0, "bytes": 0},
       "aa:bb:cc:00:00:02": {"packets": 0, "bytes": 0}})
sh("nft", "delete", "element", "inet", TABLE, "blocked4", "{ 198.51.100.7 }")
sh("nft", "add", "element", "inet", TABLE, "blocked4",
   "{ 198.51.100.7 counter packets 12 bytes 840 }")
check("a caught packet is read back", g.block_hits()["hits"]["198.51.100.7"],
      {"packets": 12, "bytes": 840})
g.block("2001:db8::7")
check("IPv6 blocks count too", g.block_hits()["hits"].get("2001:db8::7"),
      {"packets": 0, "bytes": 0})
check("the block list holds only addresses", sorted(g.blocks()),
      ["198.51.100.7", "2001:db8::7", "aa:bb:cc:00:00:02"])
check("unblock still finds the address", g.unblock("198.51.100.7").get("was_blocked"), "yes")
check("blocking a counted set reads back", g.block("198.51.100.8").get("verified"), "read_back")
check("parser skips junk", gw.parse_block_hits(["x", "198.51.100.9 1 2", "a b c", "1.2.3.4 1"]),
      {"198.51.100.9": {"packets": 1, "bytes": 2}})
sh("nft", "delete", "table", "inet", TABLE)

print("\n[a router whose nft refuses set counters]")
g2, state2 = make_agent("old-nft", refuse_counters=True)
g2.probe()
check("blocking still works", g2.block("198.51.100.7").get("verified"), "read_back")
check("the refusal is kept", (state2 / "no_set_counters").exists(), True)
check("hardware address rules still load", g2.block_mac("aa:bb:cc:00:00:01").get("verified"), "read_back")
h = g2.block_hits()
check("hits say not counted", (h["counted"], h["hits"]), (False, {}))
check("the probe stops offering block hits", "blockhits" in g2.probe()["capabilities"], False)
check("blocks list as before", sorted(g2.blocks()), ["198.51.100.7", "aa:bb:cc:00:00:01"])
sh("nft", "delete", "table", "inet", TABLE)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{'ALL PASS' if not fails else str(len(fails)) + ' FAILED: ' + ', '.join(fails)}")
sys.exit(1 if fails else 0)
