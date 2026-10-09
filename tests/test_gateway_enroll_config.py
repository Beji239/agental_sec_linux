"""
tests/test_gateway_enroll_config.py, enrolment finishes the setup itself.

--enroll switches the gateway block on in config.json and sets the DNS source
to auto, unless a Pi-hole or AdGuard file was set up on purpose; --remove
switches it off; the router-side script turns on dnsmasq's query log on
OpenWrt and the remove script puts it back. No router and no network.
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = (ROOT / "scripts" / "install_gateway_agent.sh").read_text(encoding="utf-8")
fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def function(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", SCRIPT, re.S | re.M)
    return m.group(0)


def run_set_config(cfg: dict, enabled: str, host="192.0.2.1"):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="enroll_"))
    path = tmp / "config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    sh = ("say() { printf '%s\\n' \"$*\"; }\n" + function("set_config")
          + f'CONFIG="{path}" HOST="{host}" PORT=22 USER_NAME=root\n'
          + f"set_config {enabled}\n")
    r = subprocess.run(["bash", "-c", sh], capture_output=True, text=True)
    return r, json.loads(path.read_text(encoding="utf-8"))


print("\n[1] enroll switches the gateway on and DNS to auto")
r, cfg = run_set_config({"flask": {"port": 5000},
                         "dns_monitor": {"enabled": False, "source": "pihole",
                                         "path": ""}}, "1")
check("exit code", r.returncode, 0)
check("gateway on with host", (cfg["gateway"]["enabled"], cfg["gateway"]["host"]),
      (True, "192.0.2.1"))
check("DNS on and auto", (cfg["dns_monitor"]["enabled"],
                          cfg["dns_monitor"]["source"]), (True, "auto"))
check("other blocks kept", cfg["flask"], {"port": 5000})

print("\n[2] a Pi-hole set up on purpose is left alone")
_, cfg = run_set_config({"dns_monitor": {"enabled": True, "source": "pihole",
                                         "path": "/srv/pihole-FTL.db"}}, "1")
check("source still pihole", cfg["dns_monitor"]["source"], "pihole")

print("\n[3] remove switches it off, but only for that router")
_, cfg = run_set_config({"gateway": {"enabled": True, "host": "192.0.2.1"}}, "0")
check("switched off", cfg["gateway"]["enabled"], False)
_, cfg = run_set_config({"gateway": {"enabled": True, "host": "192.0.2.9"}}, "0")
check("another router is left on", cfg["gateway"]["enabled"], True)

print("\n[4] the router-side scripts parse and carry the query log steps")
sh = ("HOST_TAG=t; AGENT_SRC=/dev/null\n" + function("remote_install_script")
      + "remote_install_script 'ssh-ed25519 AAAA t'\n")
out = subprocess.run(["bash", "-c", sh], capture_output=True, text=True).stdout
check("install script parses as sh",
      subprocess.run(["sh", "-n"], input=out, text=True).returncode, 0)
check("it turns on logqueries", "dhcp.@dnsmasq[0].logqueries=1" in out, True)
check("and records that it did", "dnslog_enabled_by_agent" in out, True)
remove = function("remove")
check("remove puts logqueries back", "logqueries=0" in remove, True)
check("remove switches config off", "set_config 0" in remove, True)

print()
if fails:
    print(f"FAILED: {len(fails)}")
    sys.exit(1)
print("ALL PASSED")
