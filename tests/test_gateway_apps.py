# tests/test_gateway_apps.py
# Router agent version 8: one app blocked on one device, against real
# nftables in a private network namespace. Both ways the sets are filled
# (dnsmasq nftset, and the query log), the resolver file, the saved state,
# restore after the table is lost, and the refusals.

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
sh("ip", "addr", "add", "203.0.113.1/24", "dev", "br-lan")
sh("ip", "link", "set", "br-lan", "up")

tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "dhcp.leases").write_text("1790000000 aa:bb:cc:00:00:01 203.0.113.10 phone *\n")
(tmp / "messages").write_text(
    "Oct  1 10:00:00 router dnsmasq[1]: query[A] g.whatsapp.net from 203.0.113.10\n"
    "Oct  1 10:00:00 router dnsmasq[1]: reply g.whatsapp.net is 157.240.1.53\n"
    "Oct  1 10:00:01 router dnsmasq[1]: cached whatsapp.com is 2a03:2880:f201::1\n"
    "Oct  1 10:00:02 router dnsmasq[1]: reply notwhatsapp.net is 198.51.100.7\n"
    "Oct  1 10:00:03 router dnsmasq[1]: reply wa.me is 0.0.0.0\n"
    "Oct  1 10:00:04 router dnsmasq[1]: reply example.com is 203.0.113.5\n")
(tmp / "confdir").mkdir()
state_dir = tmp / "state"
restarts = tmp / "restarts"


def agent(name, nftset):
    src = (ROOT / "tools" / "gateway_agent.sh").read_text()
    src = src.replace('LEASE_FILES="', f'LEASE_FILES="{tmp / "dhcp.leases"} ', 1)
    src = src.replace('LOG_FILES="', f'LOG_FILES="{tmp / "messages"} ', 1)
    src = src.replace("STATE_DIR=/etc/agentalsec", f"STATE_DIR={state_dir}", 1)
    src = src.replace("if have logread; then", "if false; then")
    src = src.replace("elif have journalctl; then", "elif false; then")
    src = src.replace("dnsmasq_confdir() {", f"dnsmasq_confdir() {{ echo {tmp / 'confdir'}; return; ", 1)
    src = src.replace("restart_dnsmasq() {", f"restart_dnsmasq() {{ echo x >> {restarts}; return 0; ", 1)
    src = src.replace("dnsmasq_nftset() {", f"dnsmasq_nftset() {{ return {0 if nftset else 1}; ", 1)
    src = src.replace("app_seed() {", "app_seed() { return 0; ", 1)
    path = tmp / f"agent_{name}.sh"
    path.write_text(src)

    def run(command):
        env = {"SSH_ORIGINAL_COMMAND": command,
               "SSH_CLIENT": "203.0.113.50 40000 22", "PATH": os.environ["PATH"]}
        return subprocess.run(["busybox", "sh", str(path)], env=env,
                              capture_output=True, text=True, timeout=60).stdout
    return gw.Gateway({"gateway": {"host": "203.0.113.1"}}, transport=run)


def elements(name):
    return sh("nft", "list", "set", "inet", "agentalsec_gw", name).stdout


conf = tmp / "confdir" / "agentalsec-apps.conf"
MAC = "aa:bb:cc:00:00:01"

print("\n[probe, with a dnsmasq that fills nft sets]")
g = agent("nftset", True)
p = g.probe()
import re as _re
check("agent version", p["agent_version"],
      _re.search(r"^VERSION=(\d+)", (ROOT / "tools" / "gateway_agent.sh").read_text(), _re.M).group(1))
check("appblock offered", "appblock" in p["capabilities"], True)
check("mode", p["appblock"], "nftset")
check("the apps it knows", "whatsapp" in p["apps"] and "telegram" in p["apps"], True)

print("\n[block WhatsApp on one phone]")
out = g.block_app("AA:BB:CC:00:00:01", "whatsapp")
check("blocked and read back", (out.get("verified"), out.get("mode")), ("read_back", "nftset"))
rules = sh("nft", "list", "chain", "inet", "agentalsec_gw", "appblock").stdout
check("drop rule for that device and the app's v4 set",
      f"ether saddr {MAC} ip daddr @app_whatsapp4 drop" in rules, True)
check("and v6", f"ether saddr {MAC} ip6 daddr @app_whatsapp6 drop" in rules, True)
check("DNS over TLS dropped for that device", "tcp dport 853 drop" in rules and "udp dport 853 drop" in rules, True)
check("no rule names any other device", rules.count("ether saddr") , 4)
check("the resolver fills the sets",
      conf.read_text().strip(),
      "nftset=/whatsapp.com/whatsapp.net/wa.me/4#inet#agentalsec_gw#app_whatsapp4,6#inet#agentalsec_gw#app_whatsapp6")
check("the log's answers for the app are in, others and sinkhole answers are not",
      ("157.240.1.53" in elements("app_whatsapp4"), "2a03:2880:f201::1" in elements("app_whatsapp6"),
       "198.51.100.7" in elements("app_whatsapp4"), "0.0.0.0" in elements("app_whatsapp4")),
      (True, True, False, False))
check("saved", (state_dir / "blocks").read_text(), f"app {MAC} whatsapp\n")
check("again says already", g.block_app(MAC, "whatsapp").get("already"), "yes")
a = g.app_blocks()
check("listed per device", a["blocks"], {MAC: ["whatsapp"]})
check("addresses learned", a["learned"].get("whatsapp"), 2)

print("\n[Telegram brings its fixed networks]")
g.block_app(MAC, "telegram")
check("its network set holds the published ranges", "149.154.160.0/20" in elements("appnet_telegram4"), True)
rules = sh("nft", "list", "chain", "inet", "agentalsec_gw", "appblock").stdout
check("one DNS over TLS rule pair per device, not per app", rules.count("dport 853"), 2)
check("both apps in the resolver file", conf.read_text().count("nftset="), 2)

print("\n[refusals]")
for args, why in ((("aa:bb:cc:00:00:01", "myspace"), "an app it does not know"),
                  (("02:00:00:00:00:01", "whatsapp"), "the router's own interface")):
    try:
        g.block_app(*args)
        check(f"{why} is refused", "not refused", "refused")
    except gw.GatewayError as e:
        check(f"{why} is refused", "refused" in str(e), True)
check("a second argument on a one-argument verb is refused",
      g._transport("block 203.0.113.10 extra").startswith("ERR too many"), True)

print("\n[restore after the table is lost]")
sh("nft", "delete", "table", "inet", "agentalsec_gw")
conf.unlink()
c = g.counters()
check("counters notice and restore", c["restored"], True)
check("both app blocks are back", g.app_blocks()["blocks"], {MAC: ["telegram", "whatsapp"]})
check("and the resolver file", conf.exists(), True)

print("\n[allow again]")
out = g.unblock_app(MAC, "whatsapp")
check("lifted and read back", (out.get("was_blocked"), out.get("verified")), ("yes", "read_back"))
check("only Telegram left", g.app_blocks()["blocks"], {MAC: ["telegram"]})
check("WhatsApp's sets are gone", elements("app_whatsapp4"), "")
check("and its resolver line", "whatsapp" in conf.read_text(), False)
check("DNS over TLS still dropped while an app is blocked",
      "dport 853" in sh("nft", "list", "chain", "inet", "agentalsec_gw", "appblock").stdout, True)
g.unblock_app(MAC, "telegram")
rules = sh("nft", "list", "chain", "inet", "agentalsec_gw", "appblock").stdout
check("the last one takes the DNS over TLS rules with it", "ether saddr" in rules, False)
check("the resolver file is removed", conf.exists(), False)
check("state empty", (state_dir / "blocks").read_text(), "")
check("allowing what is not blocked says so", g.unblock_app(MAC, "whatsapp").get("was_blocked"), "no")

print("\n[a dnsmasq without nftset: the query log fills the sets]")
sh("nft", "delete", "table", "inet", "agentalsec_gw")
g = agent("log", False)
check("mode", g.probe()["appblock"], "log")
out = g.block_app(MAC, "whatsapp")
check("blocked", (out.get("verified"), out.get("mode")), ("read_back", "log"))
check("no resolver file is written", conf.exists(), False)
check("addresses copied from the log", out.get("addresses"), "2")
with open(tmp / "messages", "a") as f:
    f.write("Oct  1 10:05:00 router dnsmasq[1]: reply mmg.whatsapp.net is 157.240.9.9\n")
check("apprefresh picks up a new answer", g.app_refresh().get("addresses"), "3")
check("and it is in the set", "157.240.9.9" in elements("app_whatsapp4"), True)

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
