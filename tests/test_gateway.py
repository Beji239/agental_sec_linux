"""
tests/test_gateway.py: the router agent and the app's client, brand-free.

Runs the agent under busybox sh (the shell OpenWrt and most embedded routers
ship) inside one private network namespace (`unshare -rn`), so every block
lands in a firewall nobody else uses. Fixture files stand in for a router's
lease file and log. The same agent is run three ways, as three different
routers would present it:

  A. nftables, dnsmasq leases, a syslog file with DNS query lines
  B. iptables only, Kea leases, no DNS log
  C. no packet filter and no resolver: read-only

and the client must offer exactly what each one reported, nothing more.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

if os.environ.get("GW_TEST_IN_NS") != "1":
    if not (shutil.which("unshare") and shutil.which("busybox")):
        print("SKIP: unshare or busybox is not available")
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
    subprocess.run(argv, check=False, capture_output=True)


# A ROUTER'S OWN ADDRESSES, inside the namespace.
sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "br-lan", "type", "dummy")
sh("ip", "addr", "add", "192.0.2.1/24", "dev", "br-lan")
sh("ip", "link", "set", "br-lan", "up")
sh("ip", "route", "add", "default", "via", "192.0.2.254")

tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "dhcp.leases").write_text(
    "1790000000 aa:bb:cc:00:00:01 192.0.2.10 living-room-tv 01:aa:bb:cc:00:00:01\n"
    "1790000000 aa:bb:cc:00:00:02 192.0.2.11 * *\n"
    "junk line\n")
(tmp / "kea.csv").write_text(
    "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n"
    "192.0.2.20,aa:bb:cc:00:00:03,,3600,1790000000,1,0,0,laptop,0\n")
(tmp / "messages").write_text(
    "Sep 29 10:00:00 router dnsmasq[123]: query[A] evil.example from 192.0.2.10\n"
    "Sep 29 10:00:00 router dnsmasq[123]: forwarded evil.example to 1.1.1.1\n"
    "Sep 29 10:00:01 router kernel: something unrelated\n")
(tmp / "confdir").mkdir()


def agent_variant(name, *, nft=True, iptables=True, leases="dhcp.leases",
                  dns=True):
    src = (ROOT / "tools" / "gateway_agent.sh").read_text()
    src = src.replace('LEASE_FILES="', f'LEASE_FILES="{tmp / leases} ', 1)
    src = src.replace('LOG_FILES="', f'LOG_FILES="{tmp / "messages"} ', 1)
    src = src.replace("if have logread; then", "if false; then")
    src = src.replace("elif have journalctl; then", "elif false; then")
    if not nft:
        src = src.replace("if have nft &&", "if false &&")
    if not iptables:
        src = src.replace("elif have iptables &&", "elif false &&")
    src = src.replace("elif have pfctl &&", "elif false &&").replace(
        "elif have pfctl; then echo pf_unreferenced", "elif false; then echo pf_unreferenced")
    if dns:
        src = src.replace("dnsmasq_confdir() {",
                          f"dnsmasq_confdir() {{ echo {tmp / 'confdir'}; return; ", 1)
        src = src.replace("restart_dnsmasq() {", "restart_dnsmasq() { return 0; ", 1)
    else:
        src = src.replace("dnsmasq_confdir() {", "dnsmasq_confdir() { return; ", 1)
        src = src.replace("elif have unbound-control", "elif false", 1)
    path = tmp / f"agent_{name}.sh"
    path.write_text(src)
    return path


def transport_for(script):
    def run(command):
        env = {"SSH_ORIGINAL_COMMAND": command,
               "SSH_CLIENT": "192.0.2.50 40000 22", "PATH": os.environ["PATH"]}
        res = subprocess.run(["busybox", "sh", str(script)], env=env,
                             capture_output=True, text=True, timeout=60)
        return res.stdout
    return run


print("\n[A] nftables, dnsmasq leases, DNS query log")
g = gw.Gateway({"gateway": {"host": "192.0.2.1"}},
               transport=transport_for(agent_variant("a")))
caps = g.probe()["capabilities"]
check("it reports what it can do, no brand needed", caps,
      ["block", "blockmac", "counters", "dnslog", "leases", "log", "neighbors",
       "persist", "sinkhole"])
check("the firewall it found", g.probe_result["firewall"], "nft")
leases = g.leases()
check("dnsmasq leases parse, junk skipped",
      [(x["ip"], x["mac"], x["hostname"]) for x in leases],
      [("192.0.2.10", "aa:bb:cc:00:00:01", "living-room-tv"),
       ("192.0.2.11", "aa:bb:cc:00:00:02", None)])
check("the DNS log carries the query lines only",
      len(g.dnslog(50)), 2)
out = g.block("192.0.2.10")
check("a device is blocked and read back", (out.get("verified"), out.get("backend")),
      ("read_back", "nft"))
check("blocking it again says so", g.block("192.0.2.10").get("already"), "yes")
g.block("2001:db8::10")
check("the list names both", sorted(g.blocks()), ["192.0.2.10", "2001:db8::10"])
check("unblock lifts it", g.unblock("192.0.2.10").get("was_blocked"), "yes")
check("unblocking what is not blocked says so",
      g.unblock("192.0.2.10").get("was_blocked"), "no")
for ip, why in (("192.0.2.1", "the router itself"),
                ("192.0.2.254", "its upstream gateway"),
                ("192.0.2.50", "the AgentalSec host asking"),
                ("127.0.0.1", "loopback"), ("224.0.0.1", "multicast"),
                ("fe80::1", "link-local")):
    try:
        g.block(ip)
        check(f"{why} is refused", "not refused", "refused")
    except gw.GatewayError as e:
        check(f"{why} is refused", "refused" in str(e), True)
try:
    g._run("block", "192.0.2.10;reboot")
    check("a shell metacharacter never leaves the app", False, True)
except gw.GatewayError as e:
    check("a shell metacharacter never leaves the app",
          "not an argument" in str(e), True)
check("the agent refuses it too, if it got that far",
      transport_for(tmp / "agent_a.sh")("block 1.2.3.4;reboot").split("\n")[0],
      "ERR the request holds a character this agent does not accept")
out = g.sinkhole("evil.example")
check("a domain is sinkholed and read back", out.get("backend"), "dnsmasq")
check("the resolver entry is written for both families",
      (tmp / "confdir" / "agentalsec-sinkhole.conf").read_text(),
      "address=/evil.example/0.0.0.0\naddress=/evil.example/::\n")
check("the list names it", g.sinkholes(), ["evil.example"])
check("unsinkhole removes it", g.unsinkhole("evil.example").get("was_sinkholed"), "yes")
check("and the list is empty", g.sinkholes(), [])
for bad in ("not a domain", "-x.example", "localhost"):
    try:
        g.sinkhole(bad)
        check(f"{bad!r} is refused", "not refused", "refused")
    except gw.GatewayError:
        check(f"{bad!r} is refused", "refused", "refused")


print("\n[B] iptables only, Kea leases")
sh("nft", "flush", "ruleset")
g = gw.Gateway({}, transport=transport_for(
    agent_variant("b", nft=False, leases="kea.csv")))
g.probe()
check("the firewall it found", g.probe_result["firewall"], "iptables")
check("Kea CSV leases parse", [(x["ip"], x["hostname"]) for x in g.leases()],
      [("192.0.2.20", "laptop")])
out = g.block("198.51.100.7")
check("iptables block is read back", (out.get("verified"), out.get("backend")),
      ("read_back", "iptables"))
check("listed", g.blocks(), ["198.51.100.7"])
check("unblocked", g.unblock("198.51.100.7").get("was_blocked"), "yes")
check("and gone", g.blocks(), [])


print("\n[C] a router that can only be read")
g = gw.Gateway({}, transport=transport_for(
    agent_variant("c", nft=False, iptables=False, dns=False)))
caps = g.probe()["capabilities"]
check("no block and no sinkhole offered", ("block" in caps, "sinkhole" in caps),
      (False, False))
for call in (lambda: g.block("198.51.100.7"), lambda: g.sinkhole("evil.example")):
    try:
        call()
        check("an unreported capability is refused by the app", False, True)
    except gw.GatewayError as e:
        check("an unreported capability is refused by the app",
              "did not report" in str(e), True)
desc = gw.describe_capabilities(caps)
check("and what it can do is said in words", desc["can_do"], [])


print("\n[D] parsers")
check("ip neigh", gw.parse_neighbors(
    ["192.0.2.10 dev br-lan lladdr aa:bb:cc:00:00:01 REACHABLE",
     "192.0.2.99 dev br-lan  FAILED"], "ip"),
    [{"ip": "192.0.2.10", "mac": "aa:bb:cc:00:00:01", "interface": "br-lan",
      "entry_type": "neighbor_reachable", "source": "gateway"}])
check("BSD arp", gw.parse_neighbors(
    ["? (192.0.2.10) at aa:bb:cc:00:00:01 on igb1 expires in 1199 seconds [ethernet]"],
    "bsd")[0]["ip"], "192.0.2.10")
ct = gw.parse_conntrack([
    "ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.10 dst=203.0.113.5 sport=5000 dport=443",
    "ipv4     2 udp      17 29 src=192.0.2.10 dst=1.1.1.1 sport=5353 dport=53",
    "ipv4     2 tcp      6 100 ESTABLISHED src=192.0.2.11 dst=203.0.113.5 sport=5001 dport=443"])
check("conntrack counts per source", ct["busiest_sources"][0], {"ip": "192.0.2.10", "connections": 2})
check("and per protocol", ct["by_protocol"], {"tcp": 2, "udp": 1})
check("pf states", gw.parse_conntrack(
    ["all tcp 192.0.2.10:5000 -> 203.0.113.5:443       ESTABLISHED:ESTABLISHED"],
    "pf")["busiest_sources"], [{"ip": "192.0.2.10", "connections": 1}])
check("a hostname is kept printable and short",
      gw.parse_leases(["1 aa:bb:cc:00:00:09 192.0.2.9 " + "x" * 200 + "\x1b[31m"])[0]["hostname"],
      "x" * 64)

print("\n[E] the adapter, end to end against a scratch database")
import sqlite3  # noqa: E402
from core import memory_engine as me  # noqa: E402
me.DB_PATH = tmp / "t.db"
c = sqlite3.connect(me.DB_PATH)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()
from core import migrations  # noqa: E402
migrations.run_migrations(me.DB_PATH)
import adapters  # noqa: E402

off = adapters.LinuxGateway("t", {})
st = off.status()
check("not configured is said, and is not blind", (st["enabled"], st["blind"]),
      (False, False))
check("and a tool call says how to enroll one",
      "install_gateway_agent.sh" in off.query("capabilities")["error"], True)

sh("nft", "flush", "ruleset")
cfg = {"gateway": {"enabled": True, "host": "192.0.2.1"}}
a = adapters.LinuxGateway("t", cfg, transport=transport_for(tmp / "agent_a.sh"))
a.poll()
with me._get_readonly_conn() as conn:
    clients = conn.execute("SELECT ip, hostname FROM router_clients "
                           "ORDER BY ip").fetchall()
    raised = conn.execute("SELECT COUNT(*) FROM findings WHERE "
                          "detection_id = 'RTR-1001'").fetchone()[0]
check("the router's leases land in the router client store",
      [tuple(r) for r in clients],
      [("192.0.2.10", "living-room-tv"), ("192.0.2.11", None)])
check("and each new device is raised once", raised, 2)
a.poll()
with me._get_readonly_conn() as conn:
    check("a second poll raises nothing new", conn.execute(
        "SELECT COUNT(*) FROM findings WHERE detection_id = 'RTR-1001'"
    ).fetchone()[0], 2)
with me._get_readonly_conn() as conn:
    can_see = conn.execute("SELECT can_see FROM sensors WHERE sensor_id "
                           "LIKE 'gw-%'").fetchone()[0]
check("the sensor names what this router lets it see",
      "DHCP leases" in can_see, True)
check("a block needs a reason",
      a.block_device("192.0.2.10", "")["success"], False)
out = a.block_device("192.0.2.10", "the user did not recognise it")
check("a block at the router succeeds and says where",
      (out["success"], out["enforcement_point"]), (True, "gateway"))
with me._get_readonly_conn() as conn:
    check("and is recorded as REM-1009", conn.execute(
        "SELECT COUNT(*) FROM findings WHERE detection_id = 'REM-1009'"
    ).fetchone()[0], 1)
check("blocking it again changes nothing and records nothing",
      a.block_device("192.0.2.10", "again").get("note", "").startswith("nothing"), True)
check("unblock lifts it", a.unblock_device("192.0.2.10", "known after all")["success"], True)
check("unblocking again is not a success",
      a.unblock_device("192.0.2.10", "again")["success"], False)
out = a.sinkhole_domain("Evil.Example", "listed by a malware feed")
check("a sinkhole is lower-cased and applied", (out["success"], out.get("domain")),
      (True, "evil.example"))
check("the query tool lists it", a.query("sinkholes")["sinkholed"], ["evil.example"])
check("and the capabilities read as sentences",
      len(a.query("capabilities")["can_do"]), 3)

shutil.rmtree(tmp, ignore_errors=True)
print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("all passed")
