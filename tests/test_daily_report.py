"""
tests/test_daily_report.py, the daily security report.

Facts are counted from the database, the status follows them, the HTML keeps
the app's punctuation rules, one report per day, the window carries on from
the previous evening's report, a first start writes only the latest missed
day, the 21:00 wake writes the report instead of a routine one, and a catch-up
does not use up a regular wake hour. Runs on a scratch database with made-up
data and a stubbed model.
"""
import json
import pathlib
import sqlite3
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp(prefix="dailyreport_"))
DB = tmp / "t.db"
DB.write_text("")
sqlite3.connect(DB).executescript(
    (ROOT / "Schema.SQL").read_text(encoding="utf-8"))

from core import memory_engine as me            # noqa: E402
me.DB_PATH = DB
from core import migrations                     # noqa: E402
migrations.run_migrations(DB)
from core import agent_loop, daily_report as dr, duty  # noqa: E402

dr._state["started"] = 0            # the sensor watch wait is over
model = {"n": 0, "prompt": None}


def fake_complete(system, prompt):
    model["n"] += 1
    model["prompt"] = prompt
    return {"text": json.dumps({
                "assessment": "A quiet day — one real event. It failed.",
                "recommendations": ["Allow only key logins for SSH."]}),
            "usage": {"calls": 1, "prompt_tokens": 900,
                      "completion_tokens": 100, "total_tokens": 1000,
                      "estimated": False},
            "error": None}


agent_loop.complete_once = fake_complete

DAY = date.today() - timedelta(days=2)
START, END = dr.day_bounds(DAY)


def at(h, m=0, day=DAY):
    """UTC SQL time for a local hour on a day."""
    return dr._sql(datetime(day.year, day.month, day.day, h, m).astimezone())


def iso(h, m=0, day=DAY):
    return dr._iso(datetime(day.year, day.month, day.day, h, m).astimezone())


with sqlite3.connect(DB) as c:
    tables = {r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    c.execute("INSERT INTO sensor_watch_beat (id, at, first_at) VALUES (1, ?, ?)",
              (0, int((START - timedelta(days=5)).timestamp())))
    for h in range(0, 24):
        c.execute("INSERT INTO watcher_run (session_id, ran_at, outcome) "
                  "VALUES ('s', ?, 'ok')", (at(h, 5),))
    c.execute("INSERT INTO sensor_gaps (sensor, reason, started_at, ended_at) "
              "VALUES ('agentalsec', 'AgentalSec was not running', ?, ?)",
              (at(2, 6), at(4, 26)))
    c.execute("INSERT INTO sensor_gaps (sensor, reason, started_at, ended_at) "
              "VALUES ('packet_sniffer', 'could not open the network card', ?, ?)",
              (at(13, 5), at(13, 20)))
    ev = ("INSERT INTO events (session_id, occurred_at, source, event_type, "
          "username, src_ip, description) VALUES ('s', ?, 'auth.log', ?, ?, ?, ?)")
    for i in range(5):
        c.execute(ev, (at(3, 12 + i), "failed_login", "root", "203.0.113.45",
                       "sshd[1]: Failed password for root"))
    c.execute(ev, (at(9), "successful_login", "ada", None,
                   "pam_unix(lightdm:session): session opened for user ada"))
    c.execute(ev, (at(9, 30), "successful_login", "root", None,
                   "pam_unix(cron:session): session opened for user root"))
    c.execute(ev, (at(10), "successful_login", "ada", "198.51.100.7",
                   "sshd[2]: Accepted publickey for ada"))
    fi = ("INSERT INTO findings (session_id, found_at, source, severity, "
          "entity_type, entity_value, title, detection_id, dismissed) "
          "VALUES ('s', ?, ?, ?, 'ip', ?, ?, ?, ?)")
    c.execute(fi, (at(9, 40), "lan_live", "medium", "192.0.2.149",
                   "Contact with a listed address", "LAN-1010", 1))
    c.execute(fi, (at(20, 35), "lan_live", "high", "192.0.2.125",
                   "New device on the network: 192.0.2.125", "LAN-1008", 0))
    c.execute(fi, (at(11), "process_monitor", "medium", "/tmp/x",
                   "Running from suspicious location: /tmp/x", "LNX-1101", 0))
    inc = ("INSERT INTO incident (incident_key, detection_id, entity_type, "
           "entity_value, source, severity, severity_rank, title, "
           "first_seen_at, last_seen_at, finding_count, status, status_at) "
           "VALUES (?, ?, 'ip', ?, 'x', ?, ?, ?, ?, ?, ?, ?, ?)")
    c.execute(inc, ("k1", "LNX-1002", "203.0.113.45", "high", 3,
                    "SSH password guessing", at(3, 12), at(3, 19), 5,
                    "triaged", at(3, 20)))
    c.execute(inc, ("k2", "LAN-1008", "192.0.2.125", "high", 3,
                    "New device joined the network", at(20, 35), at(20, 35), 1,
                    "new", at(20, 35)))
    c.execute(inc, ("k3", "LAN-1010", "192.0.2.149", "medium", 2,
                    "Laptop contacted a listed address", at(9, 40), at(9, 40),
                    1, "triaged", at(9, 41)))
    c.execute(inc, ("k4", "LAN-1010", "192.0.2.150", "medium", 2,
                    "Laptop contacted a listed address", at(18, 2), at(18, 2),
                    1, "triaged", at(18, 3)))
    rep = ("INSERT INTO duty_report (session_id, created_at, kind, trigger, "
           "incident_id, verdict, saw, body) VALUES ('s', ?, 'incident', "
           "'regular', ?, ?, 'x', 'b')")
    c.execute(rep, (at(3, 21), 1, "real"))
    c.execute(rep, (at(9, 42), 3, "benign"))
    c.execute(rep, (at(18, 4), 4, "benign"))
    c.execute("INSERT INTO action_request (session_id, created_at, verb, "
              "target, params_json, evidence_json, reason, evidence_fingerprint, proposed_by, incident_id, "
              "state) VALUES ('s', ?, 'block_device', '192.0.2.125', '{}', '{}', 'r', 'f', "
              "'model', 2, 'pending')", (at(20, 40),))
    c.execute("INSERT INTO port_owner_change (sweep_id, detected_at, kind, "
              "proto, scope, local_address, local_port, comm) VALUES "
              "(1, ?, 'appeared', 'tcp', 'listen', '0.0.0.0', 8080, 'python3')",
              (at(12),))
    c.execute("INSERT INTO port_owner_change (sweep_id, detected_at, kind, "
              "proto, scope, local_address, local_port, comm) VALUES "
              "(1, ?, 'appeared', 'tcp', 'listen', '127.0.0.1', 9090, 'x')",
              (at(12),))
    c.execute("INSERT INTO lan_traffic_minute (minute, ip, mac, up_bytes, "
              "down_bytes, up_packets, down_packets) VALUES (?, ?, '', ?, 0, 1, 1)",
              (iso(15), "192.0.2.149", 1_200_000_000))

check("the migration made daily_report",
      {"daily_report", "daily_tally"} <= tables, True)
check("schema is v63 or later", migrations.SCHEMA_VERSION >= 63, True)

dr.tally("av_passes", 3, note="2026-10-09 06:14", day=DAY)
dr.tally("av_passes", 2, day=DAY)
dr.tally("av_files", 40, day=DAY)
with me._get_readonly_conn() as conn:
    t = dr._tallies(conn, DAY)
check("tallies add up", t["av_passes"]["value"], 5)
check("and the note survives a later pass without one",
      t["av_passes"]["note"], "2026-10-09 06:14")

print("\nfacts")
written = END - timedelta(hours=3)          # 21:00 on the day
f = dr.collect(DAY, written)
check("window runs to the time of writing", f["end"], written)
check("failed logins counted", f["logins"]["failed_total"], 5)
check("by service", f["logins"]["failed"], {"SSH": 5})
check("cron sessions are not logins", f["logins"]["success"], 2)
check("a login from another address is named",
      list(f["logins"]["remote"]), ["198.51.100.7"])
check("a loopback listener is not a new open port",
      [p["local_port"] for p in f["new_ports"]], [8080])
check("app off time is a gap", len(f["coverage"]["off"]), 1)
check("a quiet sensor is listed", len(f["coverage"]["quiet"]), 1)
check("watched time leaves out the 2 h 20 min off",
      round(f["coverage"]["window_seconds"] - f["coverage"]["watched_seconds"]),
      140 * 60)
kinds = {r["id"]: r["kind"] for r in f["incidents"]["rows"]}
check("incident outcomes from verdicts and cards",
      kinds, {1: "real", 2: "decision", 3: "harmless", 4: "harmless"})
harmless = [g for g in f["folded"] if g["kind"] == "harmless"]
check("harmless repeats fold into one row", [g["times"] for g in harmless], [2])
check("a real incident makes the day red", f["status"]["level"], "red")
check("the brief has at most three lines", len(f["brief"]) <= 3, True)
check("the virus scan passes are read", dr._malware_rows(f)[0][1][0],
      "5 passes, 40 files")

print("\nrendering")
a = dr._parse_assessment(fake_complete("", "")["text"])
check("model dashes become commas", a["text"],
      "A quiet day, one real event. It failed.")
page = dr.render(f, dict(a, usage={"total_tokens": 1000}))
for word in ("The day in brief", "Needs your decision", "Coverage",
             "Incidents", "Attempts to get in", "Malware and suspicious",
             "Your network", "Actions", "The agent's assessment"):
    check(f"section {word}", word in page or word.replace("'", "&#x27;") in page,
          True)
check("no em or en dash in the page",
      any(ch in page for ch in "—–"), False)
check("no pipe in the page text", " | " in page, False)
check("titles are escaped", "<script" in dr.render(
    dict(f, folded=[dict(harmless[0], title="<script>x</script>")]), a), False)

print("\nwriting")
model["n"] = 0
r = dr.write(DAY, "s", trigger="manual", now=written)
check("written", r["outcome"], "reported")
check("assessed by one model call", (r["assessed"], model["n"]), (True, 1))
check("the digest has the facts", "SSH password guessing" in model["prompt"], True)
check("a second write does nothing", dr.write(DAY, "s")["outcome"], "exists")
with sqlite3.connect(DB) as c:
    run = c.execute("SELECT trigger, outcome, tokens_spent, detail FROM duty_run "
                    "ORDER BY id DESC LIMIT 1").fetchone()
check("the spend is on a duty run row", run[:3], ("manual", "reported", 1000))
check("tagged as a catch-up", run[3].startswith(dr.CATCH_UP_TAG), True)
listed = dr.list_reports()
check("latest only by default", len(listed), 1)
check("the page can be read back", "Daily security report" in
      dr.get_html(listed[0]["id"]), True)

print("\nthe next day's window")
NEXT = DAY + timedelta(days=1)
with sqlite3.connect(DB) as c:
    c.execute("INSERT INTO watcher_run (session_id, ran_at, outcome) "
              "VALUES ('s', ?, 'ok')", (at(10, 0, NEXT),))
with me._get_readonly_conn() as conn:
    w = dr.window_for(conn, NEXT, dr.day_bounds(NEXT)[1])
check("starts where the evening report ended", w[0], written)

print("\nmissed days")
dr.expire()
with sqlite3.connect(DB) as c:
    c.execute("DELETE FROM daily_report")
OLD = DAY - timedelta(days=6)
with sqlite3.connect(DB) as c:
    c.execute("INSERT INTO watcher_run (session_id, ran_at, outcome) "
              "VALUES ('s', ?, 'ok')", (at(10, 0, OLD),))
now = datetime.now(timezone.utc)
check("with no report yet, only the latest missed day",
      dr.missing_days(now), [NEXT])
with sqlite3.connect(DB) as c:
    c.execute("INSERT INTO daily_report (day, window_start, window_end, "
              "created_at, status, html) VALUES (?, ?, ?, ?, 'green', 'x')",
              (OLD.isoformat(), at(0, 0, OLD), at(21, 0, OLD), at(21, 0, OLD)))
check("after a report, every later day the app ran",
      dr.missing_days(now), [DAY, NEXT])
f2 = dr.collect(DAY, written)
check("the off stretch before the day is stated once",
      bool(f2["off_before"]), True)
check("and names the days with no report",
      f2["off_before"]["skipped"][0], OLD + timedelta(days=1))
with sqlite3.connect(DB) as c:
    c.execute("INSERT INTO daily_report (day, window_start, window_end, "
              "created_at, status, html) VALUES (?, ?, ?, ?, 'green', 'x')",
              ((date.today() - timedelta(days=40)).isoformat(), "a", "b", "c"))
check("reports older than 30 days are deleted", dr.expire(), 1)

print("\nthe schedule")
check("the default wake hours drop 9", duty.DEFAULT_WAKE_HOURS, (13, 17, 21))
duty._wake_hours = lambda: (13, 17, 21)
today = date.today()


def local_at(h, m=0):
    return datetime(today.year, today.month, today.day, h, m).astimezone(
        timezone.utc)


with sqlite3.connect(DB) as c:
    c.execute("DELETE FROM duty_run")
    c.execute("INSERT INTO duty_run (session_id, ran_at, ended_at, trigger, "
              "outcome, detail) VALUES ('s', ?, ?, 'manual', 'reported', ?)",
              (dr._sql(local_at(13, 2)), dr._sql(local_at(13, 2)),
               dr.CATCH_UP_TAG + "x] green"))
check("a catch-up row does not use the 13:00 wake",
      duty._next_regular_moment(local_at(13, 10))["due_now"], True)
check("21:00 is the daily hour",
      duty._next_regular_moment(local_at(21, 1))["daily_hour"], True)

from core import sensor_health              # noqa: E402
sensor_health.warnings_for = lambda tool, modules: []
duty.emergency_check = lambda *a, **k: {"emergency": False}
duty.urgent_incident = lambda now=None: None
ran = {"regular": 0}
duty.run_once = lambda *a, **k: ran.__setitem__("regular", ran["regular"] + 1) \
    or {"outcome": "reported"}
with sqlite3.connect(DB) as c:
    c.execute("DELETE FROM daily_report")
    c.execute("DELETE FROM duty_run")
    c.execute("DELETE FROM watcher_run")
    c.execute("INSERT INTO watcher_run (session_id, ran_at, outcome) "
              "VALUES ('s', ?, 'ok')", (dr._sql(local_at(20, 50)),))
dr._state["next_catch_up"] = 0
out = duty._tick_once("s", modules={}, now=local_at(21, 0))
check("the 21:00 poll writes the daily report", (out.get("kind"),
      out.get("day")), ("daily", today.isoformat()))
check("and not a routine report", ran["regular"], 0)
with sqlite3.connect(DB) as c:
    trig = c.execute("SELECT trigger FROM duty_run ORDER BY id DESC").fetchone()
check("its run row serves the 21:00 hour", trig[0], "regular")
out = duty._tick_once("s", modules={}, now=local_at(21, 1))
check("the next poll is not a wake", out.get("outcome"), "not_due")

print("\nwhat was done about it")
D3 = DAY - timedelta(days=1)
with sqlite3.connect(DB) as c:
    c.execute(inc, ("k9", "LNX-1002", "203.0.113.99", "high", 3,
                    "SSH password guessing", at(4, 0, D3), at(4, 5, D3), 9,
                    "resolved", at(4, 20, D3)))
    nine = c.execute("SELECT MAX(id) FROM incident").fetchone()[0]
    c.execute(rep, (at(4, 10, D3), nine, "real"))
    c.execute("INSERT INTO action_request (session_id, created_at, verb, "
              "target, params_json, reason, evidence_fingerprint, proposed_by, "
              "incident_id, state, decided_at, executed_at, outcome) VALUES "
              "('s', ?, 'block_device', '203.0.113.99', '{}', 'r', 'f', "
              "'model', ?, 'executed', ?, ?, 'success')",
              (at(4, 11, D3), nine, at(4, 15, D3), at(4, 16, D3)))
    c.execute(fi, (at(4, 16, D3), "remediation", "info", "203.0.113.99",
                   "Device blocked at this host: 203.0.113.99", "REM-1004", 0))
f3 = dr.collect(D3, dr.day_bounds(D3)[1])
row = next(r for r in f3["incidents"]["rows"] if r["id"] == nine)
check("a real incident that was dealt with stays real",
      (row["kind"], row["outcome"]), ("real", "real, dealt with"))
check("the day is amber, not red, once it was dealt with",
      f3["status"]["level"], "amber")
check("and the sentence says so",
      "1 real problem found, and dealt with." in f3["status"]["sentence"], True)
check("the action is listed as taken",
      [a["text"] for a in f3["actions"]["taken"]],
      ["Device blocked at this host: 203.0.113.99"])
page3 = dr.render(f3, {"text": "", "error": "x"})
check("the red card names the action", "block device 203.0.113.99, executed"
      in page3, True)
with sqlite3.connect(DB) as c:
    c.execute("INSERT INTO findings (session_id, found_at, source, severity, "
              "entity_type, entity_value, title, detection_id, dismissed) "
              "VALUES ('s', ?, 'av_scanner', 'high', 'file', '/tmp/x.bin', "
              "'Malware found by ClamAV', 'AV-1001', 0)", (at(6, 0, D3),))
f4 = dr.collect(D3, dr.day_bounds(D3)[1])
check("malware not yet quarantined is said plainly",
      ("Malware found." in f4["status"]["sentence"], f4["status"]["level"]),
      (True, "red"))
with sqlite3.connect(DB) as c:
    c.execute("INSERT INTO findings (session_id, found_at, source, severity, "
              "entity_type, entity_value, title, detection_id, dismissed) "
              "VALUES ('s', ?, 'remediation', 'info', 'file', '/tmp/x.bin', "
              "'File quarantined: /tmp/x.bin', 'REM-1006', 0)", (at(6, 5, D3),))
f5 = dr.collect(D3, dr.day_bounds(D3)[1])
check("quarantined malware says so, and the day stays red",
      ("Malware found and quarantined." in f5["status"]["sentence"],
       f5["status"]["level"]), (True, "red"))

print("\nno tools for the assessment call")
check("an empty allowlist sends no tools", agent_loop._tools_payload(()), [])
check("no allowlist still sends them all",
      len(agent_loop._tools_payload()) > 10, True)

print("\ndismissing reports")
from api.server import create_app, allowed_hosts   # noqa: E402
KEY = "0" * 64
app = create_app({"flask": {"host": "127.0.0.1", "port": 5000}}, {}, "t",
                 api_key=KEY)
app.config["AGENTAL_ALLOWED_HOSTS"] = allowed_hosts({"flask": {"host": "127.0.0.1"}})
web = app.test_client()
H = {"X-API-Key": KEY}
with sqlite3.connect(DB) as c:
    c.execute("DELETE FROM daily_report")
    for back in (3, 2, 1):
        d = (date.today() - timedelta(days=back)).isoformat()
        c.execute("INSERT INTO daily_report (day, window_start, window_end, "
                  "created_at, status, html) VALUES (?, 'a', 'b', 'c', 'green', "
                  "'<p>x</p>')", (d,))
    ids = [r[0] for r in c.execute("SELECT id FROM daily_report ORDER BY day")]
check("the schema has the dismissal columns",
      {"dismissed", "dismissed_at"} <= {r[1] for r in sqlite3.connect(DB).execute(
          "PRAGMA table_info(daily_report)")}, True)
r = web.post("/api/daily-reports/dismiss", headers=H,
             json={"report_ids": [ids[2], ids[1]]})
check("two ticked reports are dismissed", (r.status_code,
      r.get_json().get("changed")), (200, 2))
listed = web.get("/api/daily-reports?older=1", headers=H).get_json()
check("the list hides them", [x["id"] for x in listed["reports"]], [ids[0]])
check("and counts them", listed["dismissed_count"], 2)
check("the latest shown is the newest one left",
      [x["id"] for x in web.get("/api/daily-reports", headers=H).get_json()["reports"]],
      [ids[0]])
gone = web.get("/api/daily-reports?dismissed=1", headers=H).get_json()
check("Show dismissed lists them, newest first",
      [x["id"] for x in gone["reports"]], [ids[2], ids[1]])
check("nothing was deleted", sqlite3.connect(DB).execute(
    "SELECT COUNT(*) FROM daily_report").fetchone()[0], 3)
check("a dismissed day is not written again", dr.exists(
    date.today() - timedelta(days=1)), True)
r = web.post("/api/daily-reports/dismiss", headers=H,
             json={"report_ids": [ids[2]], "restore": True})
check("restore brings one back", r.get_json().get("changed"), 1)
check("an empty tick list is refused", web.post(
    "/api/daily-reports/dismiss", headers=H, json={"report_ids": []}).status_code, 400)
ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("each report has a tick box and the button posts the ticked ids",
      all(x in ui for x in ('class="daily-tick"', "dismissDailyReports()",
                            "/api/daily-reports/dismiss", "daily-show-dismissed",
                            "restoreDailyReport(")), True)

print("\nwording")
d17 = date(2026, 10, 17)
eve = datetime(2026, 10, 16, 21, 0).astimezone()
check("a window from the evening before names both days",
      dr._span(eve, eve + timedelta(days=1), d17),
      "Fri 16 Oct 21:00 to Sat 17 Oct 21:00")
check("an old incident seen again today names both days",
      dr._span(datetime(2026, 10, 1, 0, 19).astimezone(),
               datetime(2026, 10, 17, 2, 21).astimezone(), d17),
      "Thu 1 Oct 00:19 to Sat 17 Oct 02:21")
check("a midnight window stays as it was",
      dr._span(datetime(2026, 10, 17).astimezone(),
               datetime(2026, 10, 18).astimezone(), d17), "00:00 to 24:00")
check("a span inside the day stays short",
      dr._span(datetime(2026, 10, 17, 3, 52).astimezone(),
               datetime(2026, 10, 17, 4, 6).astimezone(), d17), "03:52 to 04:06")
noon = datetime(2026, 10, 17, 12, 0).astimezone()
stamp = noon.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
check("a UTC stamp in the model's words becomes local time",
      dr._local_times(f"A device joined the LAN at {stamp}.", d17),
      "A device joined the LAN at 12:00.")
check("text without a stamp is left alone",
      dr._local_times("joined at 19:14, no stamp", d17), "joined at 19:14, no stamp")
html = dr.render(dict(f, day=d17), {"text": f"Seen at {stamp}.",
                                    "recommendations": [f"Check {stamp}."]})
check("the rendered assessment carries local times only",
      stamp not in html and "Seen at 12:00." in html and "Check 12:00." in html,
      True)
check("an acronym keeps its capitals mid-sentence",
      dr._lower_first("DGA-profile domain queried"), "DGA-profile domain queried")
check("an ordinary title is lowercased",
      dr._lower_first("New file in a watched directory"),
      "new file in a watched directory")
cid = "bb99a268d947" + "0" * 52
port = dr._port_words({"proto": "tcp", "local_port": 43824, "comm": "java",
                       "exe": "/usr/bin/java", "pid": 7,
                       "origin": {"unit": f"docker-{cid}.scope"}}, d17)
check("a container id is cut to the 12 docker ps shows",
      "in docker-bb99a268d947.scope" in port and cid not in port, True)

print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
