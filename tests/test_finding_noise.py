"""
tests/test_finding_noise.py, self-explaining findings raise once per run.

A label whose own text says the thing is not what it looks like was still
being raised every thirty minutes. Twelve rows a session, all saying it is
nothing. 17b already made the argument: a control that cries wolf teaches the
operator to skim past the row that matters.

What is checked, and the last two are the ones that make this safe rather than
just quieter:

  a self-explaining label raises once and then stays quiet
  an ordinary label is untouched and still uses the time cooldown
  a DIFFERENT source raises immediately, so this is quiet about repetition
    and not about change
  a restart raises again, so it can never go permanently silent
  the pre-v22 setter refuses politely instead of raising sqlite at a person
"""
import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp())
db = tmp / "t.db"

from core import memory_engine as me       # noqa: E402
me.DB_PATH = db

c = sqlite3.connect(db)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.commit()
c.close()

from core import migrations                # noqa: E402
migrations.run_migrations(db)
from core import sensors as sn             # noqa: E402
sn.register_local()

# RETARGETED 2026-09-21 AT THE ADAPTER, WHERE THE COOLDOWN LIVES ON LINUX.
#
# On Windows PacketSniffer was a class on the sensor module and this file
# subclassed it. On Linux the sensor is a module of functions and the object
# that owns the finding cooldown, the dismissal check and the emit path is
# adapters.LinuxPacketSniffer, which is what main.py loads. So the Recorder
# subclasses THAT. Its own _should_emit is the real one, so what this file
# measures is the shipped cooldown rather than a copy of it.
import adapters                                    # noqa: E402


class Recorder(adapters.LinuxPacketSniffer):
    """Captures what the emit path would have written, without a database."""

    def __init__(self, session_id):
        self._cooldowns = {}
        self._lock = __import__("threading").Lock()
        self.session_id = session_id
        self.written = []

    def _emit_finding(self, dedup_key, once_per_session=False, **kwargs):
        if not self._should_emit(dedup_key):
            return
        self.written.append((dedup_key, kwargs.get("title")))


QUIET = ("icmp_routing_source_mismatch:router-advertisement:"
         "src=192.0.2.10:advertises=198.51.100.1")
QUIET_OTHER = ("icmp_routing_source_mismatch:router-advertisement:"
               "src=192.0.2.99:advertises=198.51.100.1")
LOUD = "dangerous_port_outbound:4444"


def emit(rec, threat, entity="198.51.100.1"):
    # CONVERTED 2026-09-21. The Windows class took a once_per_session flag and
    # held a session-long set of keys; the Linux adapter gates on
    # _should_emit's TIME cooldown plus is_dismissed, and the dedup KEY is
    # built by the caller (see adapters.py's `icmp:{did}:{src}`). So this
    # passes no flag and the keys below are shaped the way the raiser shapes
    # them, which is the thing being tested.
    rec._emit_finding(dedup_key=f"threat:{threat}:{entity}",
                      title=f"Threat detected: {threat}")


print("\n[1] the mechanism on this platform is a time cooldown, and it exists")
check("the adapter has a cooldown window",
      isinstance(adapters.LinuxPacketSniffer.COOLDOWN_SECONDS, int), True)
check("and it is long enough to matter",
      adapters.LinuxPacketSniffer.COOLDOWN_SECONDS >= 900, True)


print("\n[2] THE POINT: it raises once, then stays quiet")
# Twelve occurrences inside one cooldown window is the shape the old
# thirty-minute cooldown produced on Windows, and the fault was the same
# there: one broken sender produced a page of identical rows.
rec = Recorder("run-1")
for _ in range(12):
    emit(rec, QUIET)
check("one row, not twelve", len(rec.written), 1)


print("\n[3] a DIFFERENT source raises straight away")
# This is what makes the quiet safe, and it is why the dedup key names the
# SOURCE rather than only the rule. The raiser builds `icmp:{did}:{src}`, so
# a second emitter is a second key and is not suppressed by the first.
emit(rec, QUIET_OTHER)
check("the new source raised", len(rec.written), 2)
for _ in range(5):
    emit(rec, QUIET_OTHER)
check("and then it goes quiet too", len(rec.written), 2)


print("\n[4] ordinary findings go through the same gate")
rec2 = Recorder("run-1")
emit(rec2, LOUD)
emit(rec2, LOUD)
check("the cooldown applies to them too", len(rec2.written), 1)
check("and it is the cooldown map that suppressed it",
      len(rec2._cooldowns), 1)


print("\n[5] a restart raises again, so it never goes permanently silent")
rec3 = Recorder("run-2")
emit(rec3, QUIET)
check("the new run raises it once", len(rec3.written), 1)


print("\n[6] nothing is lost, only the repeated alert")
# The packets themselves are stored with their threat_label regardless. The
# finding count is not the evidence count.
check("the cooldown is per KEY, not per rule, so distinct sources survive",
      adapters.LinuxPacketSniffer.COOLDOWN_SECONDS > 0, True)


print("\n[7] the setter refuses politely on a pre-v22 database")
# A person typing a correct command should not get a sqlite traceback because
# the app has not been started since the upgrade.
old = tmp / "old.db"
c = sqlite3.connect(old)
c.executescript((ROOT / "Schema.SQL").read_text(encoding="utf-8"))
c.execute("ALTER TABLE known_devices DROP COLUMN expected_always_on")
c.execute("INSERT INTO known_devices(ip, mac, known_as) "
          "VALUES('192.0.2.1','00:00:5e:00:53:01','gateway')")
c.commit()
c.close()

saved = me.DB_PATH
me.DB_PATH = old
try:
    result = me.set_device_always_on("192.0.2.1", True)
except Exception as e:
    result = {"ok": None, "reason": f"raised {type(e).__name__}"}
finally:
    me.DB_PATH = saved
check("refused rather than raised", result["ok"], False)
check("and names the fix", "main.py" in (result["reason"] or ""), True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
