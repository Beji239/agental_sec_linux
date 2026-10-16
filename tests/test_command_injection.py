"""
tests/test_command_injection.py, outside text cannot become a command or an
option.

1. Static, over every Python file the app ships: no shell=True, no
   os.system or os.popen, and no subprocess call handed one string.
2. Live, with every subprocess call recorded instead of run: hostile values
   (a leading dash, ; $( ) and backticks, a newline, ../) go through the
   entry points that take outside or model input. Each value is refused
   before anything runs, or sits where it cannot be read as an option:
   after the end-of-options marker, or as the value of an option that
   takes one.
"""
import ast
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_isolate_db.isolate()

fails = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        fails.append(label)
        print(f"        {str(detail)[:600]}")


SHIPPED = sorted(p for d in ("core", "tools", "api", "scripts")
                 for p in (ROOT / d).glob("*.py")) + [ROOT / "adapters.py",
                                                     ROOT / "main.py"]
CALLS = {"run", "Popen", "call", "check_output", "check_call"}

print("1. Every subprocess call in the shipped code")
shell, system, strings = [], [], []
for p in SHIPPED:
    tree = ast.parse(p.read_text(encoding="utf-8"))
    rel = p.relative_to(ROOT)
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
        owner = (f.value.id if isinstance(f, ast.Attribute)
                 and isinstance(f.value, ast.Name) else "")
        if owner == "os" and name in ("system", "popen"):
            system.append(f"{rel}:{n.lineno}")
        for k in n.keywords:
            if k.arg == "shell" and not (isinstance(k.value, ast.Constant)
                                         and k.value.value is False):
                shell.append(f"{rel}:{n.lineno}")
        if owner in ("subprocess", "sp") and name in CALLS and n.args:
            a = n.args[0]
            if isinstance(a, (ast.Constant, ast.JoinedStr)) or (
                    isinstance(a, ast.BinOp) and isinstance(a.op, ast.Mod)):
                strings.append(f"{rel}:{n.lineno}")
check("no shell=True", not shell, shell)
check("no os.system or os.popen", not system, system)
check("no command handed over as one string", not strings, strings)
check("the scan read the files", len(SHIPPED) > 100, len(SHIPPED))


# Every call is recorded, nothing runs.
RAN = []


class _Done:
    def __init__(self, argv):
        self.args, self.returncode, self.stdout, self.stderr = argv, 1, "", ""
        self.pid = 0

    def communicate(self, *a, **k):
        return "", ""

    def wait(self, *a, **k):
        return 1

    def kill(self):
        pass


def _record(argv, *a, **k):
    RAN.append((argv, k))
    if k.get("check"):
        raise subprocess.CalledProcessError(1, argv)
    return _Done(argv)


for fn in CALLS:
    setattr(subprocess, fn, _record)

HOSTILE = ["--version", "-rf", "-oG/tmp/x", "a;id", "$(id)", "`id`",
           "a\nb", "../../etc/passwd", "-"]


def placed_safely(argv, value):
    """No word of the command is the hostile value in a place where it would
    be read as an option: it must follow the end-of-options marker, or be
    the value of the option just before it. Inside a longer word
    (--since=x, /tmp/x) it is data."""
    if not isinstance(argv, (list, tuple)):
        return False
    for i, part in enumerate(argv):
        if part != value:
            continue
        if "--" in argv[:i] or (i and argv[i - 1] in TAKES_VALUE):
            continue
        return False
    return True


# Options whose next word is their value, not another option.
TAKES_VALUE = {"-e", "--grep", "-m", "-c", "-W", "-n", "-p", "--since"}


def _call(fn, value):
    RAN.clear()
    try:
        fn(value)
        return False
    except Exception:                                       # noqa: BLE001
        return True


def run_case(label, fn, value):
    # What the code runs with a harmless value (a version probe, say) is
    # its own command, not something the value put there.
    _call(fn, "zzharmless")
    own = {tuple(a) for a, _ in RAN if isinstance(a, (list, tuple))}
    refused = _call(fn, value)
    bad = [argv for argv, k in RAN
           if (not placed_safely(argv, value)
               and tuple(argv) not in own) or k.get("shell")]
    strs = [argv for argv, k in RAN if isinstance(argv, str)]
    return refused, bad, strs


def suite(label, fn, values=HOSTILE):
    problems = []
    for v in values:
        refused, bad, strs = run_case(label, fn, v)
        if bad or strs:
            problems.append((v, bad or strs))
    check(label, not problems, problems)


print("\n2. Hostile values through the entry points")
from tools import av_scanner  # noqa: E402
ENG = {"installed": True, "tool": "clamscan"}
suite("virus scan: a path is always after --",
      lambda v: av_scanner.scan_paths([v, "/tmp/" + v], eng=ENG))
ENG2 = {"installed": True, "tool": "clamdscan"}
suite("virus scan through clamd: the same",
      lambda v: av_scanner.scan_paths([v, "/tmp/" + v], eng=ENG2))

from tools import event_monitor_linux as eml  # noqa: E402
eml._get_log_file_paths = lambda: {"journald": True, "auth": "/var/log/auth.log"}
suite("log search: the pattern is the value of -e or --grep",
      lambda v: eml.search_logs(v))
suite("log search: since stays inside its option",
      lambda v: eml.search_logs("sshd", since=v))

from tools import network_scanner as ns  # noqa: E402
suite("ping: an address that is not one is refused", ns._probe)

from tools import systemd_units as su  # noqa: E402
for name in ("unit_properties", "stop_unit", "user_unit_known",
             "disable_user_unit", "enable_user_unit"):
    suite(f"systemd {name}: a unit name is refused or after --",
          getattr(su, name),
          HOSTILE + ["--all", "-.mount", "ssh", "x.service --now"])

from tools import iptables_manager as ipm  # noqa: E402
# Act as root, or the root check refuses first and nothing below is tested.
ipm.needs_root = lambda: False
BAD_IPS = HOSTILE + ["1.2.3.4 -j ACCEPT", "192.0.2.1;id", " 192.0.2.1",
                     "192.0.2.0/24", "fe80::1%-rf"]
BAD_PORTS = HOSTILE + ["22;id", "-1", " 22", "0", "65536"]
for be in ("ufw", "nftables", "iptables"):
    for verb in ("block_ip_address", "unblock_ip_address"):
        suite(f"firewall {be} {verb}: an address that is not one is refused",
              lambda v, f=getattr(ipm, verb), b=be: f(v, backend=b), BAD_IPS)
    for verb in ("block_port", "unblock_port"):
        suite(f"firewall {be} {verb}: a port that is not one is refused",
              lambda v, f=getattr(ipm, verb), b=be: f(v, "inbound", backend=b),
              BAD_PORTS)
RAN.clear()
ipm.block_port(True, "inbound", backend="iptables")
check("firewall: True is not port 1", not RAN, RAN)
RAN.clear()
ipm.block_port(22, "inbound", "tcp --version", backend="iptables")
check("firewall: a protocol that is not tcp or udp is refused", not RAN, RAN)
RAN.clear()
ipm.block_ip_address("192.0.2.1", backend="iptables")
check("firewall: a real address still reaches the rule",
      any("192.0.2.1" in a for a, _ in RAN if isinstance(a, list)), RAN)

from tools import remediation_linux as rl  # noqa: E402
suite("kill: a pid that is not one is refused",
      lambda v: rl.kill_process(v), HOSTILE + ["-1", "1 2", "0"])

from tools import gateway as gw  # noqa: E402
g = gw.Gateway({"gateway": {"host": "192.0.2.1"}},
               transport=lambda cmd: RAN.append((cmd, {})) or "OK x\n")


def gw_case(v):
    for verb in ("block", "unblock", "conntrack", "sinkhole"):
        try:
            g._run(verb, v)
        except gw.GatewayError:
            pass


bad = []
for v in HOSTILE + ["192.0.2.1 x", "x$IFS"]:
    RAN.clear()
    gw_case(v)
    if any(isinstance(c, str) and v in c for c, _ in RAN):
        bad.append(v)
check("router agent: a value with a space, a quote or a shell sign is "
      "refused before it is sent", all(v in ("--version", "-rf", "-oG/tmp/x",
                                             "../../etc/passwd", "-")
                                       for v in bad), bad)

print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILED'}")
sys.exit(1 if fails else 0)
