"""
tests/test_query_totals.py, a list that does not say its own size. TODO 94.

WHERE THIS CAME FROM, 2026-09-13. The owner asked one question after the process
list was fixed: does the model now get everything the app could give it. The
answer was no, and it was no in about twenty places.

core/memory_engine.py has 22 query_ functions and not one of them reported a
total or said what it held back. Measured on the owner's database: 14,676 active
findings behind a default limit of 50. The model asks what is wrong with the
machine, gets the newest fifty, and nothing anywhere says the other 14,626
exist. A capped answer and a complete one were the same shape, the same
length, and the same silence.

The owner's second point is the one that makes it worse than a counting bug. The right
number of rows is a property of the NETWORK, not of the app. Fifty rows on a
noisy night is one repeated detection and nothing else; the same fifty on a
quiet network is the whole picture. A fixed default cannot be right for both,
and saying nothing about which one you got is what makes it dangerous rather
than merely limited.

So the rule being tested here is the owner's rule two: a function must not assert a
fact it could not check. "Here are the findings" and "here are the fifty
newest of 14,676" are different sentences.

Runs anywhere. Builds its own database from the real Schema.SQL.
"""
import io
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


from core import memory_engine as me            # noqa: E402

# The whole schema, not a retyped table. A broken Schema.SQL fails here rather
# than on somebody's first boot.
SCHEMA = io.open(ROOT / "Schema.SQL", encoding="utf-8").read()
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
me.DB_PATH = _tmp.name
_c = sqlite3.connect(me.DB_PATH)
_c.executescript(SCHEMA)
_c.commit()
_c.close()


def add_finding(n, severity="high", dismissed=0, session="s1"):
    with me._get_conn() as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO findings (session_id, severity, entity_type, "
                "entity_value, title, dismissed, found_at) VALUES "
                "(?,?,'process',?,?,?,?)",
                (session, severity, f"p{i}.exe", f"finding {i}", dismissed,
                 f"2026-09-13T10:{i % 60:02d}:00"))


def add_event(n, session="s1"):
    with me._get_conn() as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO events (session_id, event_type, severity, "
                "occurred_at, description) VALUES (?,?,?,?,?)",
                (session, "logon_failed", "medium",
                 f"2026-09-13T11:{i % 60:02d}:00", f"event {i}"))


print("\n[1] THE FAILURE CASE. A capped list must not read as the whole list.")
# 120 findings behind a limit of 50. This is the owner's 14,676 behind 50, shrunk to
# something a test can build in a second.
add_finding(120)

capped = me.query_findings(limit=50, with_total=True)
check("the rows come back", len(capped["findings"]), 50)
check("and it says how many it returned", capped["returned"], 50)
check("and how many actually matched", capped["matching_total"], 120)
check("and it says plainly that this is not all of them",
      capped["complete"], False)
check("the note says so in words too",
      "THIS IS NOT EVERYTHING" in capped["note"], True)
check("and both numbers are in the note",
      "120 row(s) match" in capped["note"] and "seeing 50" in capped["note"],
      True)
check("and it says what to do about it",
      "Raise limit" in capped["note"] and "narrow the filter" in capped["note"],
      True)
# The sentence that matters most on a security tool.
check("and it says not to describe the machine from a partial list",
      "not describe the machine from this list alone" in capped["note"], True)


print("\n[2] a complete answer says so, and carries no warning")
full = me.query_findings(limit=500, with_total=True)
check("every row is there", full["returned"], 120)
check("total agrees", full["matching_total"], 120)
check("complete is true", full["complete"], True)
check("and there is no note to ignore", "note" in full, False)

# Exactly at the boundary, which is where an off by one would live.
exact = me.query_findings(limit=120, with_total=True)
check("a limit exactly equal to the total is complete", exact["complete"], True)
check("and one below it is not",
      me.query_findings(limit=119, with_total=True)["complete"], False)


print("\n[3] the count answers the SAME question as the rows")
# The real trap in this design. A count built from a second, similar looking
# WHERE would be right most of the time and wrong exactly when a filter is
# used, which is when somebody is investigating something.
add_finding(7, severity="critical")
crit = me.query_findings(severity="critical", limit=5, with_total=True)
check("the filter applies to the rows", len(crit["findings"]), 5)
check("and to the count, not to the whole table", crit["matching_total"], 7)
check("so it is not the unfiltered total", crit["matching_total"] != 127, True)

add_finding(4, dismissed=1)
live = me.query_findings(limit=500, with_total=True)
check("dismissed rows are outside the default filter", live["matching_total"], 127)
gone = me.query_findings(dismissed=True, limit=500, with_total=True)
check("and counted correctly when asked for", gone["matching_total"], 4)

sess = me.query_findings(session_id="other", limit=500, with_total=True)
check("a session filter counts that session only", sess["matching_total"], 0)
check("and an empty answer is still marked complete", sess["complete"], True)


print("\n[4] nothing changed for the callers that did not ask")
# The dashboard reads memory_engine directly. If the default return shape
# moved, the screen would break, so the default has to stay a plain list.
plain = me.query_findings(limit=10)
check("the default is still a bare list", isinstance(plain, list), True)
check("with the rows in it", len(plain), 10)
check("query_events default is a list too",
      isinstance(me.query_events(limit=10), list), True)
check("query_port_scan default is a list too",
      isinstance(me.query_port_scan(limit=10), list), True)


print("\n[5] the same rule on events and port scans")
add_event(75)
ev = me.query_events(limit=50, with_total=True)
check("events are capped and say so", ev["complete"], False)
check("with the real total", ev["matching_total"], 75)
check("and the rows live under their own name", len(ev["events"]), 50)

ev_all = me.query_events(limit=500, with_total=True)
check("and complete when they all fit", ev_all["complete"], True)

ps = me.query_port_scan(limit=500, with_total=True)
check("an empty port scan table is complete, not unknown", ps["complete"], True)
check("and says zero rather than saying nothing", ps["matching_total"], 0)
check("rows under their own name here too", ps["ports"], [])


print("\n[6] a count that could not run says so, and does NOT say complete")
# Rule two, the one the owner named. "I did not check" and "there is nothing else"
# have to stay different sentences, so a broken count must never read as a
# complete answer.
class _BrokenConn:
    def execute(self, *a, **k):
        raise sqlite3.OperationalError("no such table: findings")

broken = me._with_total(_BrokenConn(), [{"id": 1}], "findings", "", [], 50,
                        "findings")
check("it does not claim completeness", broken["complete"], None)
check("it does not invent a total", "matching_total" in broken, False)
check("it says the count failed", "Could not count" in broken["note"], True)
check("it names what it does know", broken["returned"], 1)
check("and warns against reading it as complete",
      "Do not read this as a complete answer" in broken["note"], True)


print("\n[7] the second batch, 94.4 and 94.6 through 94.10")
# Each one gets the same two questions asked of it, because a helper that is
# right in one place and mis-wired in another is the drift this project keeps
# finding. Failure case first every time: cap it below the real count and
# check it admits that, then let it fit and check it stops warning.

def add_dns(n):
    with me._get_conn() as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO dns_queries (client_ip, domain, queried_at, "
                "blocked, source, source_row_id) VALUES (?,?,?,0,'pihole',?)",
                ("192.0.2.5", f"host{i}.example",
                 f"2026-09-13T12:{i % 60:02d}:00", f"row{i}"))


def add_deviation(n, resolved=None, severity="high"):
    with me._get_conn() as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO behavioral_deviation (session_id, entity_type, "
                "entity_value, behavior_key, severity, detected_at, "
                "resolved_as) VALUES ('s1','ip',?,?,?,?,?)",
                (f"10.0.0.{i % 250}", "port_set", severity,
                 f"2026-09-13T13:{i % 60:02d}:00", resolved))


def add_runbook(n):
    with me._get_conn() as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO runbook (cve_id, vulnerability, description, "
                "severity, date_added) VALUES (?,?,?,?,?)",
                (f"CVE-2026-{10000+i}", f"thing {i}", "a described weakness",
                 "high", "2026-09-01"))


# 94.4 dns
add_dns(130)
d_cap = me.query_dns(limit=100, with_total=True)
check("dns capped is not complete", d_cap["complete"], False)
check("dns knows the real total", d_cap["matching_total"], 130)
check("dns rows are under their own name", len(d_cap["queries"]), 100)
check("dns complete when it fits",
      me.query_dns(limit=500, with_total=True)["complete"], True)
check("and the dns filter moves the count too",
      me.query_dns(domain="host7.example", limit=500,
                   with_total=True)["matching_total"], 1)

# 94.7 deviations
add_deviation(60)
dev = me.query_behavioral_deviation(limit=50, with_total=True)
check("deviations capped is not complete", dev["complete"], False)
check("deviations total is real", dev["matching_total"], 60)
check("deviation rows under their own name", len(dev["deviations"]), 50)

# 94.6 review queue. These are the ones the silence timer closed unreviewed,
# so an answer that quietly stops short understates how much nobody looked at.
add_deviation(40, resolved="unreviewed", severity="critical")
rq = me.query_review_queue(limit=10, with_total=True)
check("review queue capped is not complete", rq["complete"], False)
check("review queue total is real", rq["matching_total"], 40)
check("review rows under their own name", len(rq["awaiting_review"]), 10)
check("review queue complete when it fits",
      me.query_review_queue(limit=500, with_total=True)["complete"], True)
# include_all widens the filter, so the count must widen with it.
add_deviation(5, resolved="unreviewed", severity="low")
check("the default filter excludes low severity",
      me.query_review_queue(limit=500, with_total=True)["matching_total"], 40)
check("and include_all counts them in",
      me.query_review_queue(limit=500, include_all=True,
                            with_total=True)["matching_total"], 45)

# 94.9 runbook. A cut off search here produces "not in the runbook", which is
# a confident negative, which is the one shape of wrong answer nobody checks.
add_runbook(35)
rb = me.query_runbook(limit=20, with_total=True)
check("runbook capped is not complete", rb["complete"], False)
check("runbook total is real", rb["matching_total"], 35)
check("runbook rows under their own name", len(rb["entries"]), 20)
check("an unfiltered runbook fits at a bigger limit",
      me.query_runbook(limit=500, with_total=True)["complete"], True)
# The search path has its own where, so it gets its own check.
one = me.query_runbook(search_term="CVE-2026-10007", limit=500, with_total=True)
check("a search counts only what it matched", one["matching_total"], 1)
check("and still says it is complete", one["complete"], True)
none = me.query_runbook(search_term="CVE-1999-0001", limit=500, with_total=True)
check("a search with no hits is complete, not unknown", none["complete"], True)
check("and says zero rather than saying nothing", none["matching_total"], 0)

# 94.8 suppressed baselines. A cut off suppression list understates how much
# of the machine is being silenced, which is the wrong direction to be wrong.
with me._get_conn() as conn:
    for i in range(30):
        conn.execute(
            "INSERT INTO behavioral_baseline (entity_type, entity_value, "
            "behavior_key, alert_suppressed, last_updated) "
            "VALUES ('ip',?,?,1,?)",
            (f"10.0.0.{i}", "port_set", f"2026-09-13T14:{i % 60:02d}:00"))
    for i in range(4):
        conn.execute(
            "INSERT INTO behavioral_baseline (entity_type, entity_value, "
            "behavior_key, alert_suppressed, last_updated) "
            "VALUES ('ip',?,?,0,?)",
            (f"10.0.1.{i}", "port_set", "2026-09-13T14:00:00"))
sup = me.query_suppressed_baselines(limit=10, with_total=True)
check("suppression list capped is not complete", sup["complete"], False)
check("and counts only the suppressing ones, not every baseline",
      sup["matching_total"], 30)
check("suppression rows under their own name",
      len(sup["suppressing_baselines"]), 10)

# 94.10 pcap results
with me._get_conn() as conn:
    for i in range(14):
        conn.execute(
            "INSERT INTO pcap_results (session_id, file_path, analyzed_at) "
            "VALUES ('s1',?,?)",
            (f"C:/caps/file{i}.pcap", f"2026-09-13T15:{i % 60:02d}:00"))
pc = me.query_pcap_results(limit=10, with_total=True)
check("pcap results capped is not complete", pc["complete"], False)
check("pcap total is real", pc["matching_total"], 14)
check("pcap rows under their own name", len(pc["results"]), 10)
# The sensor labelling runs after the fitting, so it has to survive it. This
# nearly broke: the rows are edited in place after the wrapper is built.
check("and the unknown-vantage label still reaches the rows",
      pc["results"][0]["position"], "unrecorded")
check("pcap complete when it fits",
      me.query_pcap_results(limit=500, with_total=True)["complete"], True)


print("\n[8] every converted function still returns a bare list by default")
# The dashboard reads these directly. One missed default and a screen breaks.
for fn, kw in ((me.query_findings, {}), (me.query_events, {}),
               (me.query_port_scan, {}), (me.query_dns, {}),
               (me.query_behavioral_deviation, {}),
               (me.query_review_queue, {}), (me.query_runbook, {}),
               (me.query_suppressed_baselines, {}),
               (me.query_pcap_results, {})):
    check(f"{fn.__name__} default is a list",
          isinstance(fn(**kw), list), True)


print("\n[9] the dict shaped answers, 94.11, 94.14 and 94.15")
# These three already returned a dict with their own count and their own note,
# both of which say something the model needs. So the completeness fields are
# merged in and the warning is PREPENDED to the note that is already there.
# One place to look. A second note beside the first is a second thing to miss.

with me._get_conn() as conn:
    for i in range(40):
        conn.execute(
            "INSERT INTO router_clients (router_host, ip, mac, hostname, "
            "last_seen, source) VALUES ('192.0.2.1',?,?,?,?,'arp')",
            (f"192.0.2.{i}", f"aa:bb:cc:00:00:{i:02x}", f"dev{i}",
             f"2026-09-13T16:{i % 60:02d}:00"))
    for i in range(25):
        conn.execute(
            "INSERT INTO router_config (router_host, setting, value, "
            "last_seen, source) VALUES ('192.0.2.1',?,?,?,'snmp')",
            (f"setting_{i}", f"value {i}", "2026-09-13T16:00:00"))

# 94.14 router clients. FAILURE CASE FIRST.
rc = me.query_router_clients(limit=10, with_total=True)
check("router clients capped is not complete", rc["complete"], False)
check("with the real total", rc["matching_total"], 40)
check("its own count field is untouched", rc["count"], 10)
check("the warning is at the FRONT of the note",
      rc["note"].startswith("THIS IS NOT EVERYTHING"), True)
# The note it already had has to survive. It carries the sentence about a
# neighbour table aging out, which is the thing that stops absence being read
# as a finding.
check("and the note it already had is still there",
      "PRESENCE HERE MEANS RECENT CONTACT" in rc["note"], True)
check("clients are still under their own name", len(rc["clients"]), 10)

rc_all = me.query_router_clients(limit=500, with_total=True)
check("complete when it fits", rc_all["complete"], True)
check("and then the note does not start with a warning",
      rc_all["note"].startswith("THIS IS NOT EVERYTHING"), False)
check("and the filter moves the count",
      me.query_router_clients(ip="192.0.2.7", limit=500,
                              with_total=True)["matching_total"], 1)

# 94.15 router config
cfg = me.query_router_config(limit=5, with_total=True)
check("router config capped is not complete", cfg["complete"], False)
check("with the real total", cfg["matching_total"], 25)
check("the warning is at the front here too",
      cfg["note"].startswith("THIS IS NOT EVERYTHING"), True)
check("and its own note survived",
      "NO SEVERITY IS ATTACHED" in cfg["note"], True)
check("settings under their own name", len(cfg["settings"]), 5)
check("complete when it fits",
      me.query_router_config(limit=500, with_total=True)["complete"], True)
# changed_only narrows the filter, so the count must narrow with it.
check("changed_only counts only changed settings",
      me.query_router_config(changed_only=True, limit=500,
                             with_total=True)["matching_total"], 0)

# 94.11 query_important. TWO lists, so two counts, and the test is mostly
# about them not being merged into one misleading number.
with me._get_conn() as conn:
    conn.execute("UPDATE findings SET promoted = 1, promoted_at = "
                 "'2026-09-13T17:00:00' WHERE id <= 30")
    conn.execute("UPDATE findings SET nominated_at = '2026-09-13T17:00:00' "
                 "WHERE id > 40 AND id <= 55")
imp = me.query_important(limit=10, with_total=True)
check("promoted is capped", imp["promoted_count"], 10)
check("and knows its real total", imp["promoted_total"], 30)
check("and says it is not complete", imp["promoted_complete"], False)
check("nominations are capped separately", imp["waiting_count"], 10)
check("with their own total", imp["nominated_total"], 15)
check("and their own completeness", imp["nominated_complete"], False)
check("the warning leads the note",
      imp["note"].startswith("THIS IS NOT EVERYTHING"), True)
check("and the note it already had survived",
      "Promotion lives on the finding itself" in imp["note"], True)

# The case the two counts exist for: one list complete, the other not.
imp2 = me.query_important(limit=20, with_total=True)
check("a fitting nomination list is complete", imp2["nominated_complete"], True)
check("while the promoted list still is not", imp2["promoted_complete"], False)
check("so one number could never have described both",
      imp2["promoted_total"] != imp2["nominated_total"], True)

both = me.query_important(limit=500, with_total=True)
check("everything fits at a big limit", both["promoted_complete"], True)
check("both halves", both["nominated_complete"], True)
check("and no warning is prepended then",
      both["note"].startswith("THIS IS NOT EVERYTHING"), False)

# include_nominations off must not report a nomination count it did not look
# for. Rule two: not asked is not the same as none.
off = me.query_important(limit=10, include_nominations=False, with_total=True)
check("nominations were not fetched", off["waiting_count"], 0)
check("and the promoted half still counts properly", off["promoted_total"], 30)


print("\n[10] a dict answer whose count fails does not claim completeness")
class _BrokenConn2:
    def execute(self, *a, **k):
        raise sqlite3.OperationalError("database is locked")

extra = me._completeness(_BrokenConn2(), "router_clients", "", [], 7)
check("complete is None, never True", extra["complete"], None)
check("no total is invented", "matching_total" in extra, False)
merged = me._merge_completeness({"note": "the original sentence."}, extra)
check("the failure leads the note",
      merged["note"].startswith("COULD NOT COUNT"), True)
check("and the original note is kept",
      "the original sentence." in merged["note"], True)
check("and it says not to read it as complete",
      "Do not read this as a complete answer" in merged["note"], True)


print("\n[11] the per client domain lists, 94.17, and a real bug in them")
# query_dns_clients caps two lists PER CLIENT at top, and neither said so.
# Worse, new_domain_count was len(new_domains), which is the capped list. So a
# client with 200 newly seen domains, which is what a DGA or a device that has
# just started beaconing looks like, reported 15. The most interesting number
# in the answer was clamped to the display limit and read as a measurement.
#
# FAILURE CASE FIRST: many domains, a small top, and check the COUNT is right
# even though the list is short.
with me._get_conn() as conn:
    for i in range(40):
        conn.execute(
            "INSERT INTO dns_queries (client_ip, domain, queried_at, blocked, "
            "source, source_row_id) VALUES ('192.0.2.32',?,?,0,'pihole',?)",
            (f"new{i}.example", "2026-09-13T18:00:00", f"n{i}"))

dc = me.query_dns_clients(client_ip="192.0.2.32", top=5,
                          new_since="2026-09-01T00:00:00", with_total=True)
row = dc["clients"][0]
check("the domain list is cut at top", len(row["top_domains"]), 5)
check("but the distinct count is the real one", row["distinct_domains"], 40)
check("the new domain list is cut too", len(row["new_domains"]), 5)
check("AND THE NEW DOMAIN COUNT IS THE REAL ONE, not the list length",
      row["new_domain_count"], 40)
check("the row says its domain list is not whole",
      row["top_domains_complete"], False)
check("and its new domain list is not whole",
      row["new_domains_complete"], False)
check("and it says so in words, with the numbers",
      "40 distinct domain(s)" in row["note"] and "top=5" in row["note"], True)
check("and says the counts are the trustworthy part",
      "The COUNTS are exact" in row["note"], True)

# The whole picture at a bigger top. Both lists complete, no note.
dc2 = me.query_dns_clients(client_ip="192.0.2.32", top=100,
                           new_since="2026-09-01T00:00:00", with_total=True)
row2 = dc2["clients"][0]
check("everything fits at a bigger top", len(row2["top_domains"]), 40)
check("and the row says so", row2["top_domains_complete"], True)
check("and the new list too", row2["new_domains_complete"], True)
check("and the row carries no warning then", "note" in row2, False)

# The CLIENT list itself has no limit, so it is always complete, and the
# answer has to keep those two facts apart.
check("the client list itself is complete", dc["complete"], True)
check("while naming the clients whose lists were cut",
      dc["clients_with_cut_lists"], ["192.0.2.32"])
check("and the top level note says which half is cut",
      "Every client is here" in dc["note"], True)
check("no clients are named when nothing was cut",
      "clients_with_cut_lists" in dc2, False)

# new_since is a real filter, so the count has to move with it.
none_new = me.query_dns_clients(client_ip="192.0.2.32", top=100,
                                new_since="2026-12-01T00:00:00",
                                with_total=True)["clients"][0]
check("a later cutoff means nothing is new", none_new["new_domain_count"], 0)
check("and the empty list is complete, not cut",
      none_new["new_domains_complete"], True)


print("\n[12] the queries with no limit at all, 94.18, 94.19, 94.20")
# Not truncation. The same missing sentence: a list that never states its own
# size cannot be told apart from an empty one by anything reading it later.
#
# complete is True here because the SQL has no LIMIT clause. That is a fact
# about the query, not an assumption about the data, and it is the only
# reason these are allowed to claim completeness without counting.
with me._get_conn() as conn:
    for i in range(12):
        conn.execute(
            "INSERT INTO known_devices (ip, mac, first_seen, last_seen) "
            "VALUES (?,?,?,?)",
            (f"10.0.5.{i}", f"bb:cc:dd:00:00:{i:02x}",
             "2026-09-13T10:00:00", "2026-09-13T19:00:00"))
    for i in range(9):
        conn.execute(
            "INSERT INTO dismissed_findings (entity_type, entity_value, "
            "reason, dismissed_at) VALUES ('ip',?,?,?)",
            (f"10.0.6.{i}", "known good", "2026-09-13T19:00:00"))

kd = me.query_known_devices(with_total=True)
check("known devices says how many", kd["returned"], 12)
check("and that it is everything", kd["complete"], True)
check("total equals returned when nothing is capped",
      kd["matching_total"], kd["returned"])
check("and the note says an empty list would mean no match",
      "means nothing matched" in kd["note"], True)
check("rows under their own name", len(kd["devices"]), 12)

dis = me.query_dismissed(with_total=True)
check("dismissed says how many", dis["returned"], 9)
check("and that it is everything", dis["complete"], True)
check("filtered dismissed counts the filter",
      me.query_dismissed(entity_type="ip", with_total=True)["returned"], 9)
check("a filter that matches nothing is complete and empty",
      me.query_dismissed(entity_type="process",
                         with_total=True)["returned"], 0)

bl = me.query_behavioral_baseline(with_total=True)
check("baselines say how many", bl["returned"], 34)
check("and that it is everything", bl["complete"], True)
check("rows under their own name", len(bl["baselines"]), 34)

# And all three still return a bare list when nobody asked.
for fn in (me.query_known_devices, me.query_dismissed,
           me.query_behavioral_baseline):
    check(f"{fn.__name__} default is still a list",
          isinstance(fn(), list), True)


print("\n[13] the last four, 94.12, 94.13, 94.16 and 94.3b")

# 94.13 behavioral_session. It already reported superseded_hidden, which is a
# DIFFERENT number: observations deliberately withdrawn. The count must not
# quietly fold those back in.
with me._get_conn() as conn:
    for i in range(70):
        conn.execute(
            "INSERT INTO behavioral_session (session_id, entity_type, "
            "entity_value, behavior_key, behavior_value, observed_at) VALUES "
            "('s1','ip',?,'port_set','443',?)",
            (f"10.0.7.{i % 200}", f"2026-09-13T20:{i % 60:02d}:00"))

bs = me.query_behavioral_session(session_id="all", limit=50, with_total=True)
check("observations capped is not complete", bs["complete"], False)
check("with the real total", bs["matching_total"], 70)
check("its own count field is untouched", bs["count"], 50)
check("the warning leads the note",
      bs["note"].startswith("THIS IS NOT EVERYTHING"), True)
check("complete when it fits",
      me.query_behavioral_session(session_id="all", limit=500,
                                  with_total=True)["complete"], True)

# Withdrawn observations are excluded from the rows, so they must be excluded
# from the count as well, or the two numbers describe different questions.
with me._get_conn() as conn:
    conn.execute("UPDATE behavioral_session SET superseded_by = 'x' "
                 "WHERE id <= 20")
after = me.query_behavioral_session(session_id="all", limit=500,
                                    with_total=True)
check("withdrawn rows leave the answer", after["count"], 50)
check("and leave the count with them", after["matching_total"], 50)
check("and are reported separately, not silently", after["superseded_hidden"], 20)
check("and it is still complete, because 50 of 50 is everything shown",
      after["complete"], True)

# 94.12 presence. Every rate in that answer is a fraction of sweeps_counted.
with me._get_conn() as conn:
    for i in range(60):
        conn.execute(
            "INSERT INTO presence_sweep (session_id, method, swept_at, "
            "outcome) VALUES ('s1','icmp+arp',?,'ok')",
            (f"2026-09-13T21:{i % 60:02d}:00",))
    for i in range(3):
        conn.execute(
            "INSERT INTO presence_sweep (session_id, method, swept_at, "
            "outcome) VALUES ('s1','icmp+arp',?,'failed')",
            ("2026-09-13T21:00:00",))

pr = me.query_presence(max_sweeps=10, with_total=True)
w = pr["window"]
check("the window took only what it was allowed", w["sweeps_counted"], 10)
check("and says how many usable sweeps exist", w["usable_sweeps_in_range"], 60)
check("and that this is not the whole range", w["complete"], False)
check("failed sweeps are still counted separately",
      w["sweeps_failed_and_excluded"], 3)
check("the note leads with the window warning",
      pr["note"].startswith("THIS IS A WINDOW"), True)
check("and says every rate is a fraction of it",
      "fraction of those" in pr["note"], True)

pr_all = me.query_presence(max_sweeps=500, with_total=True)
check("a window covering everything is complete",
      pr_all["window"]["complete"], True)
check("and carries no window warning",
      pr_all["note"].startswith("THIS IS A WINDOW"), False)
check("and asking without the flag adds no fields",
      "complete" in me.query_presence(max_sweeps=10)["window"], False)

# 94.16 threat map, and 94.3b, are both in tool_registry rather than here, so
# they are checked as source: the fields exist and the wording is there.
#
# BOUNDED BY THE FUNCTION'S OWN END, 2026-09-23. This was `[:9000]`, and when
# _query_threat_map grew by a block of comments the two checks below stopped
# finding their strings and FAILED -- which is the safe direction. The unsafe
# direction is the one that shipped twice already (LOOP-2, PROC-2): a window
# big enough for the strings but too small for the function silently stops
# asserting everything past the cut. No character count can be right for a
# function that grows, so this uses its end.
def _fn_body(text, opener):
    import re
    if opener not in text:
        return ""
    tail = text.split(opener)[1]
    end = re.search(r"\n(?:def |class |@app\.route|@require_api_key)", tail)
    return tail[:end.start()] if end else tail


reg = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
tm = _fn_body(reg, "def _query_threat_map")
check("the window really holds the whole function",
      "attribution" in tm, True)
check("the map computes endpoint completeness",
      "endpoints_complete = len(out) <= limit" in tm, True)
check("and unlocated completeness separately",
      "unlocated_complete = len(no_geo) <= 50" in tm, True)
check("and returns all three", '"complete":        endpoints_complete' in tm, True)
check("and says it in words when the map is cut",
      "AND THIS MAP IS CUT" in tm, True)
check("and says the counts are the exact part",
      "The COUNT is " in tm and "exact, the list is not" in tm, True)

print("\n[14] 94.3b, a packet search cut by its LIMIT now says so")
# packet_search_scope already counted, but its hint branch was guarded by
# `not all_sessions`. So asking across every session and hitting the limit
# printed a total and said nothing, leaving the reader to compare two numbers
# themselves, which nobody does.
with me._get_conn() as conn:
    for i in range(40):
        conn.execute(
            "INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, "
            "protocol) VALUES ('s1',?,?,?, 'TCP')",
            (f"2026-09-13T22:{i % 60:02d}:00", "192.0.2.5", "8.8.8.8"))

wide = me.packet_search_scope(session_id="s1", all_sessions=True,
                              src_ip="192.0.2.5", returned=10)
check("a wide search that was cut is not complete", wide["complete"], False)
# WORDING UPDATED 2026-09-14 with TODO 98, which rebuilt this function so the
# count uses the same filters the rows did. The sentence is the same fact and
# the same branch; it now says LIMIT in capitals and names the filter, because
# "40 match" had to stop meaning "40 rows exist somewhere".
check("and now says the limit did it",
      "The LIMIT cut this" in wide.get("hint", ""), True)
check("and says which numbers it is comparing",
      "40 packet(s) match this exact filter" in wide["hint"]
      and "you have 10" in wide["hint"], True)
check("and warns against reading it as everything",
      "Do NOT read this as all the matching traffic" in wide["hint"], True)

whole = me.packet_search_scope(session_id="s1", all_sessions=True,
                               src_ip="192.0.2.5", returned=40)
check("a wide search that got everything is complete", whole["complete"], True)
check("and carries no limit hint", "hint" in whole, False)

# The older branch still has to work, and my first version of this check was
# wrong: it asked for returned=40 against a total of 40, so there was nothing
# elsewhere to report and the branch could never fire. The test was wrong, not
# the code. It needs returned BELOW the total for the message to have anything
# to say.
narrow = me.packet_search_scope(session_id="s1", all_sessions=False,
                                src_ip="192.0.2.5", returned=10)

# THIS CHECK USED TO ASSERT THE BUG, and it is worth leaving the story here.
#
# All forty rows above are in session s1, so there is nothing in any earlier
# run at all. The old code printed the earlier-runs sentence anyway, because
# its branch fired on `total > returned`, and `total` was an unfiltered count
# that also moved when the LIMIT cut the answer. So this check passed by
# reading the two facts as one, and a test that passes on a merged claim is
# how the claim survived. See TODO 98 and tests/test_packet_scope_filters.py.
#
# What is true for this data: the limit cut it, and there is no elsewhere.
check("the limit sentence fires", "The LIMIT cut this" in narrow.get("hint", ""), True)
check("and there is no elsewhere to point at", "elsewhere" in narrow, False)
check("so nothing sends the reader to all_sessions",
      "all_sessions=true" in narrow.get("hint", ""), False)

# And with a row that really IS in an earlier run, both sentences appear and
# they stay two sentences.
with me._get_conn() as conn:
    conn.execute(
        "INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, "
        "protocol) VALUES ('s0','2026-09-01T10:00:00','192.0.2.5','8.8.8.8','TCP')")
both = me.packet_search_scope(session_id="s1", all_sessions=False,
                              src_ip="192.0.2.5", returned=10)
check("now there is an elsewhere", both["elsewhere"], 1)
check("the earlier-runs sentence is back", "all_sessions=true" in both["hint"], True)
check("the limit sentence is still there too",
      "The LIMIT cut this" in both["hint"], True)
check("and the two are not merged into one claim",
      both["hint"].count("Do NOT read") >= 2, True)


print("\n[15] the model is told what the fields mean")
from core import tool_registry as tr            # noqa: E402
man = {t["name"]: t for t in tr.TOOL_MANIFEST}
CONVERTED = ("query_findings", "query_events", "query_port_scan", "query_dns",
             "query_runbook", "query_behavioral_deviation",
             "query_pcap_results", "query_suppressed_baselines",
             "query_review_queue", "query_router_clients",
             "query_router_config", "query_dns_clients",
             "query_known_devices", "query_dismissed",
             "query_behavioral_baseline", "query_presence",
             "query_behavioral_session")
# query_presence is the one that does not use the name matching_total, and
# that is right rather than an oversight: it does not return a row list, it
# returns a WINDOW of sweeps, and calling that a matching total would invite
# the reader to treat sweeps as rows. It is checked on its own fields below.
for tool in [t for t in CONVERTED if t != "query_presence"]:
    d = man[tool]["description"]
    check(f"{tool} description names matching_total", "matching_total" in d, True)
    check(f"{tool} description names complete", "complete" in d, True)

pres_d = man["query_presence"]["description"]
check("query_presence names its own window fields",
      "usable_sweeps_in_range" in pres_d and "sweeps_counted" in pres_d, True)
check("and names complete", "complete" in pres_d, True)
check("and says what a partial window does to every rate",
      "fraction of sweeps_counted" in pres_d, True)

# And the dispatch really asks for it. A manifest that promises the field
# while the dispatch never requests it is the drift this project keeps finding.
src = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
# query_known_devices is the one exception and it is deliberate. Its dispatch
# already builds a rich answer out of the bare list, counting identified and
# transient rows, so it sets the three fields there rather than asking the
# engine to wrap a list it is about to unwrap again. Checked for what it
# actually produces, not for the flag it does not use.
for tool in [t for t in CONVERTED if t != "query_known_devices"]:
    block = src.split(f'if name == "{tool}":')[1][:600]
    check(f"the {tool} dispatch asks for the total",
          "with_total=True" in block, True)

# The dispatch carries a long note before its return, so the slice has
# to reach past it. Sized from the real file, not guessed.
kd_block = src.split('if name == "query_known_devices":')[1][:4500]
for field in ('"returned": len(devices)', '"matching_total": len(devices)',
              '"complete": True'):
    check(f"the known_devices dispatch sets {field.split(':')[0]}",
          field in kd_block, True)
check("and says why it may claim completeness",
      "has a LIMIT clause" in kd_block, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
