"""
tests/test_ui_wiring.py, the dashboard actually reaches the features.

WHY THIS FILE EXISTS, and it is the same lesson as section 32.

Five things were built and then never surfaced: the always-on flag (28), the
event monitor backlog (31), the pcap origin (26), the integrity journal (17)
and retention (32). Every one of them worked. Every one of them had passing
tests. None of them was reachable by a person, because nothing in the UI
called them.

A backend test cannot see that gap. This file reads api/routes.py and
ui/index.html as text and checks that the wiring exists in both directions:
the route is defined, and something in the page calls it.

It does NOT render the page or click anything. It catches the failure that
actually keeps happening here, which is a feature with no way in.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


ROUTES = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")
UI     = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")

DEFINED = set(re.findall(r'@app\.route\("([^"]+)"', ROUTES))
CALLED  = {u.split("?")[0]
           for u in re.findall(r"fetch\('(/api/[^']+)'", UI)}


# A ROUTE WITH A PATH PARAMETER, 2026-09-17.
#
# The page builds those by concatenation, fetch('/api/agent/run/' + id), so
# what this file scrapes is the static prefix "/api/agent/run/" while the rule
# is "/api/agent/run/<int:run_id>". A literal comparison calls that a missing
# route, which is wrong, and "make the test pass" here would have meant
# changing a working page to please a string match.
#
# The prefix has to match a rule whose remainder is EXACTLY ONE parameter
# segment. Anything looser (a plain startswith) would let a typo through by
# matching some unrelated longer route, which is the whole thing this check is
# for. The first parameterised route in this app arrived with the agent tab;
# before that the literal comparison was right by accident.
PARAM_PREFIXES = {
    rule.split("<", 1)[0]: rule
    for rule in DEFINED
    if "<" in rule and rule.split("<", 1)[1].count("/") == 0
}


def is_defined(url: str) -> bool:
    return url in DEFINED or url in PARAM_PREFIXES


print("\n[1] every route the page calls actually exists")
# The cheapest possible catch for a typo in a URL, which fails silently in a
# browser and shows an empty panel rather than an error.
check("no UI call points at a missing route",
      sorted(u for u in CALLED if not is_defined(u)), [])
# And the matcher itself is not a rubber stamp: a URL that looks like a
# parameterised call but names no real rule still has to fail.
check("a made up path is still caught",
      is_defined("/api/agent/nonsense/"), False)


print("\n[2] the five features are reachable, not just built")
for route, why in [
        ("/api/devices/always-on", "28.4, the availability flag"),
        ("/api/retention/status",  "32, database size"),
        ("/api/retention/settings", "32, choosing a budget"),
        ("/api/integrity/status",  "17, verify against an anchor"),
        ("/api/integrity/anchor",  "17, taking an anchor"),
]:
    check(f"route exists ({why})", route in DEFINED, True)
    check(f"and the page calls it ({why})", route in CALLED, True)


print("\n[3] 28.4: permanent and always-on are shown as DIFFERENT things")
# The bug v22 was written to fix was the code treating these as one claim. A
# UI that shows only one of them re-creates it for the person reading it.
check("the table has an always-on column", "Always on?" in UI, True)
check("there is a toggle", "setAlwaysOn(" in UI, True)
# 2026-09-21, the owner's catch: the cell showed "yes" next to a button reading
# "not always", so it read "yes not always". The column asks a yes or no
# question and must answer with one word. Failure checks first.
check("the old action-label button is gone",
      "'not always' : 'always on'" in UI, False)
check("no button is labelled 'not always'", ">not always<" in UI, False)
check("the cell is a yes/no switch", "aon-switch" in UI, True)
check("both answers are offered",
      "seg(true, 'yes')" in UI and "seg(false, 'no')" in UI, True)
check("the current answer is not clickable (no flip by mistake)",
      "cur ? 'disabled" in UI, True)
check("and the note spells out the difference",
      "two different claims" in UI, True)
# The old colspan would leave a ragged empty-state row after adding a column.
check("the empty state spans the new column count",
      'colspan="8"' in UI and "No device is marked permanently present" in UI,
      True)


print("\n[4] 31: the event monitor backlog is visible")
# Section 30 in one sentence: the tile said "running" for a whole session
# while 31,000 records sat unread behind it. A status that cannot show that
# is the part that let it hide.
check("the module tile reads the backlog", "state.backlog" in UI, True)
check("it says how far behind", "behind" in UI, True)
check("and says so when there is nothing to drain",
      "log up to date" in UI, True)
# The figure has to be in the payload the page already fetches, or the tile
# renders nothing at all.
sys.path.insert(0, str(ROOT))
import tools.event_monitor_linux as em          # noqa: E402
# THE BACKLOG COMES FROM THE MODULE, NOT FROM A CLASS, since the class that
# carried it was the Windows monitor and this tree runs the Linux module. The
# assertion's meaning is unchanged: the payload the page fetches must carry the
# figure, or the tile renders nothing at all.
em._drain_remaining.clear()
em._report_progress("syslog", 5, 42, now=1.0)
check("status() carries the backlog", em.get_status()["backlog"], {"syslog": 42})
em._drain_remaining.clear()


print("\n[5] 26: the pcap origin is asked for, and passed through")
check("there is an origin box", 'id="pcap-origin"' in UI, True)
check("the route accepts it", 'data.get("origin")' in ROUTES, True)
# Origin is a CLAIM. Guessing it from the file contents is the failure the
# tool description already warns about, so the UI must say so too.
check("the page says leave it blank rather than guess",
      "Blank is honest" in UI, True)
check("and it is only sent when filled in", "origin ? {" in UI, True)


print("\n[6] 17: an unanchored chain is not presented as a clean bill")
# The section 19 failure in a new place. "Intact" with no anchor and "matches
# an anchor" are very different statements and must not both read green.
check("the page distinguishes them", "not anchored" in UI, True)
check("and explains why it is weaker",
      "rebuilt from scratch" in UI, True)
check("the route compares against the stored anchor",
      "expected_head=head" in ROUTES, True)
check("anchoring now writes the file",
      "out_path=_ANCHOR_PATH" in ROUTES, True)
# Anchoring automatically would bless a tampered chain. Staleness is shown
# instead, which is a nudge rather than a false assurance.
check("nothing anchors on a timer",
      "setInterval" in UI and "takeAnchor()" in UI
      and "setInterval(takeAnchor" in UI, False)
check("stale anchors are flagged instead", "worth taking a fresh one" in UI,
      True)


print("\n[7] 32: retention is readable but NOT prunable from the dashboard")
# 23.4: deletion is the only irreversible act here. It does not get a button
# on the page that also holds the chat window.
check("the size is shown", "retention-summary" in UI, True)
check("the budget can be set", "setRetention(" in UI, True)
check("there is no prune route at all",
      any("prune" in r for r in DEFINED), False)
check("and the page says why", "no prune button here" in UI, True)
check("it points at the script instead", "prune_db.py" in UI, True)
# The baselines surviving a prune is the thing people get wrong, so it is
# said on the card rather than left in a TODO file.
check("it says baselines are never pruned",
      "never</b> pruned" in UI, True)


print("\n[8] the UI does not hardcode numbers that live in the code")
# 27.3's lesson: wording that drifts from code is a comment with extra steps.
check("presets come from the server", "/api/retention/presets" in CALLED, True)
from core import retention as rt          # noqa: E402
check("and the server serves the real ones",
      "retention.PRESETS" in ROUTES, True)
check("smallest preset is still 2 GB",
      min(p["trigger"] for p in rt.PRESETS), 2_000_000_000)


print("\n[9] the new panels are actually loaded when the tab opens")
# A panel nobody calls is the same failure as a feature nobody wired.
review_hook = re.search(r"if \(name === 'review'\)\s*\{([^}]*)\}", UI)
body = review_hook.group(1) if review_hook else ""
check("review tab loads integrity", "loadIntegrity()" in body, True)
check("review tab loads retention", "loadRetention()" in body, True)


print("\n[10] the page is still valid enough to parse")
# Not a renderer. It catches an unbalanced tag or a broken script block,
# which is the realistic way a hand edit to a 3000 line file goes wrong.
scripts = re.findall(r"<script>(.*?)</script>", UI, re.S)
check("the main script block is intact", len(scripts) >= 1, True)
# Counted with a word-boundary regex, not a literal "<tr>". Most rows in this
# file carry attributes, so the literal form undercounts by four and the check
# fails on a perfectly balanced page. Caught by the check itself failing while
# the page was fine, which is the right way round for a test to be wrong.
check("table rows balance",
      len(re.findall(r"<tr\b", UI)), len(re.findall(r"</tr>", UI)))
opens  = len(re.findall(r"<div\b", UI))
closes = len(re.findall(r"</div>", UI))
check("div tags balance", opens, closes)


print("\n[11] 2.1: the blinding ceiling is visible before it is hit")
# The exact failure this whole file exists for, found again on 2026-09-03.
# The ceiling was built, tested, and exposed at a route, and then nothing ever
# asked for it. A limit only curl can see is not a control, it is a surprise
# waiting to happen.
check("the route exists", "/api/blinding-budget" in DEFINED, True)
check("and the page calls it", "/api/blinding-budget" in CALLED, True)
check("it is loaded when the Review tab opens",
      "loadBlindingBudget()" in body, True)
# Users are never charged and never refused. If the panel does not say that,
# somebody will read their own dismissals as spending the model's budget.
check("the panel says user dismissals are not charged",
      "not charged" in UI, True)


print("\n[12] 2026-09-03: the dashboard loads nothing from the internet")
# It used to load leaflet from unpkg, fonts from Google, and map tiles from
# OpenStreetMap, on a page that says everything runs on your machine. Tiles
# were the bad one: a tile request names the square of the world you are
# looking at, and on the threat map that is where your traffic went.
#
# Links a person CHOOSES to click are fine and are not counted here. What is
# banned is anything the browser fetches on its own.
auto_loaded = re.findall(
    r'<(?:link|script|img|iframe|source|video|audio)\b[^>]*?'
    r'(?:src|href)="(https?://[^"]+)"', UI)
check("nothing is auto-loaded from a remote host", auto_loaded, [])
check("leaflet is local", '"/ui/vendor/leaflet.js"' in UI, True)
check("the fonts are local", '"/ui/vendor/fonts.css"' in UI, True)
check("the base map is a shipped file, not tiles",
      "/ui/vendor/world.geojson" in UI, True)
check("no tile layer is left behind", "tileLayer" in UI, False)

for f in ["leaflet.js", "leaflet.css", "fonts.css", "world.geojson",
          "LICENSES.md"]:
    check(f"ui/vendor/{f} is actually there",
          (ROOT / "ui" / "vendor" / f).exists(), True)
check("the fonts are actually there",
      len(list((ROOT / "ui" / "vendor" / "fonts").glob("*.woff2"))), 6)

# The policy has to match what the page needs. A CSP listing hosts the page
# no longer uses is stale, and stale is how a policy quietly stops meaning
# anything.
for host in ["unpkg.com", "fonts.googleapis.com", "openstreetmap.org"]:
    check(f"CSP no longer allows {host}", host in ROUTES, False)


print("\n[13] 8.3: the VPN can be seen and cannot be touched")
# The tool used to be able to bring a WireGuard tunnel up and down, and both
# were model operable. Connecting a tunnel changes what every sensor on this
# host can see in one move, which is the blinding attack the whole threat
# model is about, reachable through a control we shipped ourselves.
#
# These checks are the fence around that decision. If any of them fail,
# somebody has put a VPN control back.
REGISTRY = (ROOT / "core" / "tool_registry.py").read_text(encoding="utf-8")
check("no VPN routes at all",
      sorted(r for r in DEFINED if "vpn" in r), [])
check("vpn_connect is not a tool", '"name": "vpn_connect"' in REGISTRY, False)
check("vpn_disconnect is not a tool", '"name": "vpn_disconnect"' in REGISTRY, False)
check("nothing dispatches a VPN action",
      'mod.connect()' in REGISTRY or 'mod.disconnect()' in REGISTRY, False)

# Reading the state stayed, because a packet captured through a tunnel is a
# different fact from one captured without.
check("the state module exists", (ROOT / "tools" / "vpn_state.py").exists(), True)
check("and it has no way to change anything",
      any(w in (ROOT / "tools" / "vpn_state.py").read_text(encoding="utf-8")
          for w in ["def connect", "def disconnect", "subprocess"]), False)
check("the packet sensor reads the new module",
      # THE STAMP MOVED TO THE ADAPTER, and that is where it belongs: on this
      # platform the capture path that writes packet rows is
      # adapters.LinuxPacketSniffer._on_packet, which is what main.py loads.
      # tools/vpn_state.py documents the stamp as packet_sniffer._flush's job;
      # on Linux the equivalent seam is the adapter's save_packet call.
      "vpn_state=vpn_state" in
      (ROOT / "adapters.py").read_text(encoding="utf-8"), True)
check("the pill reads it too", "modules?.vpn_state" in UI, True)
# 'unknown' must not be shown as 'off'. Not having looked and having looked
# and found nothing are different statements, and only one of them is news.
check("the pill has a third state for 'we could not look'",
      "VPN: UNKNOWN" in UI, True)

if (ROOT / "tools" / "vpn_manager.py").exists():
    print("  NOTE  tools/vpn_manager.py is still on disk and nothing imports "
          "it any more. Safe to delete, along with wg0.conf.")


print("\n[14] the last three things that were built and never reachable")
# Same failure as sections 2 and 11, found by a dead-code sweep on 09-03
# rather than by anyone noticing. All three worked. None could be reached.

# PCAP analysis was write only. Results went in, model_assessment was never
# once written, and nothing could read a past capture back.
check("query_pcap_results is a tool",
      '"name": "query_pcap_results"' in REGISTRY, True)
check("write_pcap_assessment is a tool",
      '"name": "write_pcap_assessment"' in REGISTRY, True)
SAN = (ROOT / "core" / "sanitize.py").read_text(encoding="utf-8")
check("and both are fenced, like every capture-derived result",
      '"query_pcap_results"' in SAN and '"write_pcap_assessment"' in SAN, True)
# The id has to reach the model or the write tool cannot be called.
check("run_pcap_analysis hands back the id to write against",
      'result["pcap_result_id"]' in
      (ROOT / "tools" / "pcap_analyzer.py").read_text(encoding="utf-8"), True)

# Merging: user only by design, and for a month that meant nobody at all.
for route in ["/api/devices/merge", "/api/devices/unmerge",
              "/api/devices/appearances"]:
    check(f"the page calls {route}", route in CALLED, True)
check("merging is loaded with the Inventory tab",
      "loadAppearances()" in UI, True)
# The card has to say WHY the agent cannot do this, or the restriction reads
# as an oversight and somebody helpfully adds a tool for it.
check("and the card explains why there is no tool for it",
      "blinding done by filing" in UI, True)
check("still no merge tool at any privilege",
      "merge_devices" in REGISTRY, False)

# The dead accessors, removed the same day.
AGENT = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
ME    = (ROOT / "core" / "memory_engine.py").read_text(encoding="utf-8")
OUI   = (ROOT / "core" / "oui.py").read_text(encoding="utf-8")
SNIFF = (ROOT / "tools" / "packet_sniffer_linux.py").read_text(encoding="utf-8")
for label, src, name in [
        ("agent_loop.get_mode", AGENT, "def get_mode"),
        ("agent_loop.get_history", AGENT, "def get_history"),
        ("memory_engine.get_all_preferences", ME, "def get_all_preferences"),
        ("oui.vendor_of", OUI, "def vendor_of"),
        ("packet_sniffer.get_threat_map_data", SNIFF, "def get_threat_map_data")]:
    check(f"{label} is gone", name in src, False)
# The ones that replaced them must still be there, or this was deletion for
# its own sake rather than a tidy-up.
# RENAMED 2026-09-14 with local mode, TODO 105. There is one backend, so
# there is no mode to report, and the route serves a description of the model
# rather than the state of a toggle.
check("model_status survived", "def model_status" in AGENT, True)
check("and the mode toggle is gone with it", "def set_mode" in AGENT, False)
check("get_preference survived", "def get_preference" in ME, True)
check("oui.lookup survived", "def lookup" in OUI, True)


print("\n[15] the port scanner actually completes a scan")
# Found by the owner on 2026-09-03 by pressing the button: every scan came back
# "Execution error: name 'port_set' is not defined". _record read port_set,
# ports and public, and all three are locals of scan(). So the scanner had
# been dead from the dashboard AND from the model, and it looked like a tool
# answering rather than a tool crashing.
#
# The port suite was green throughout. It covers _port_set, the severity
# table and the self/remote distinction, all of which were fine, and never
# ran a scan end to end. A green suite says the tested path works and says
# nothing about the path nobody wrote a test for. So here is that test.
import inspect                                    # noqa: E402
from tools.port_scanner import PortScanner        # noqa: E402
sig = inspect.signature(PortScanner._record).parameters
for arg in ["ports", "port_set", "public"]:
    check(f"_record is handed {arg} instead of reaching for it",
          arg in sig, True)
    # Required, not defaulted. A default lets this break again quietly, with
    # the scope line confidently describing the wrong port set.
    check(f"and {arg} has no default to hide a miss",
          sig[arg].default is inspect.Parameter.empty, True)


print("\n[16] 2026-09-03: a dead sensor looks dead, and the gate is not "
      "looser over HTTP")
LM   = (ROOT / "tools" / "linux_monitor.py").read_text(encoding="utf-8")
REM  = (ROOT / "tools" / "remediation_linux.py").read_text(encoding="utf-8")

# The failure that prompted this: the Linux box was off for an hour,
# linux_monitor logged a timeout every two minutes, and the tile said
# "running" throughout, because running only ever meant the thread was alive.
# Section 31 in a new module.
check("status separates running from reachable", '"reachable"' in LM, True)
check("and carries how long since it last worked",
      "last_success_age_seconds" in LM, True)
check("the tile reads reachable, not running",
      "'reachable' in state" in UI, True)
check("and paints a failing host red", "NOT ANSWERING" in UI, True)
# Three-valued on purpose. Never-tried is not failing.
check("not-tried is its own state", "not tried yet" in UI, True)

# 8.6: the Linux host can be inventoried, and neither inventory speaks for
# the other.
check("the tool takes a host", '"host":    {"type": "string"' in REGISTRY, True)
check("linux_monitor can answer for itself",
      "def collect_software" in LM, True)
check("the local answer says it is local only",
      "THIS IS THIS MACHINE ONLY" in REGISTRY, True)
# The miss is the dangerous half. A pip-installed service in a venv is not a
# system package, so "not in the inventory" must never read as "not there".
check("and the tool description says a miss means little",
      "a miss is close to meaningless" in REGISTRY, True)

# restore_file: the write-out is checked now, not just the read-in.
check("restore validates where it writes TO",
      "QUARANTINE_DENY_ROOTS" in REM.split("def restore_file")[1], True)
# The guard against conjuring a directory that was not there. The Linux
# function creates parents ONLY after the deny-root check, and says so; the
# Windows tree's sentence for the same rule is "Refusing to create
# directories". Either wording passes, because the RULE is what is being
# checked and this tree states it in its own words.
check("and will not build a path that was not there",
      ("Refusing to create directories" in REM
       or "parents are created ONLY after the deny-root check" in REM), True)

# The HTTP layer no longer scans strangers.
check("the port scan route refuses public targets",
      "will not scan a public address" in ROUTES, True)
check("and refuses a hostname rather than guessing",
      "change between the check and the scan" in ROUTES, True)
check("dismissals are provenance-logged",
      "DISMISS via HTTP" in ROUTES, True)


print("\n[17] 2026-09-04: the settings panel is reachable and stays a panel")
# 2.3 and 8.5 are one piece of work and this is the check that it did not
# quietly become a first-run wizard: the tab exists, it is always in the nav,
# and every writer behind it is wired at both ends.
for route, why in [
        ("/api/settings",          "2.3, what is off and why"),
        ("/api/settings/key",      "8.5, writing a key to .env"),
        ("/api/settings/app-key",  "8.5, generating the app key"),
        ("/api/settings/config",   "8.5, the non-secret shape"),
        ("/api/settings/name",     "8.5, what to call the operator"),
]:
    check(f"route exists ({why})", route in DEFINED, True)
    check(f"and the page calls it ({why})", route in CALLED, True)

check("there is a Settings tab, not a wizard",
      'data-page="settings"' in UI, True)
check("and the page is rendered from the API, not hardcoded",
      "_settingsData.config" in UI and "d.keys" in UI, True)

# Rule 2: never show a key we already hold. There is no read path for a value
# anywhere in the panel, so the page cannot render one even by accident.
SETTINGS = (ROOT / "core" / "settings.py").read_text(encoding="utf-8")
check("the catalogue reports the tail only", "def _last4" in SETTINGS, True)
_catalog_body = SETTINGS.split("def key_catalog")[1].split("\ndef ")[0]
check("and never puts a value in what it returns",
      '"value"' in _catalog_body, False)

# Rule 1, and it is the one worth fencing hardest. The config writer's
# allow-list is fixed, so no posted path can put a secret in config.json.
check("the config writer works from an allow-list",
      "CONFIG_FIELDS" in SETTINGS and "next((f for f in CONFIG_FIELDS" in SETTINGS,
      True)
check("no writable config path names a credential",
      [p for p in re.findall(r'"path": "([^"]+)"', SETTINGS)
       if any(w in p.lower() for w in ("key", "secret", "token", "community",
                                       "password"))],
      [])
check("the panel says which changes need a restart",
      "applies at the next start" in UI, True)

# 8.5 asked for a name the model can call you by, and the point of it is that
# the model actually receives it. A preference nothing reads is not a feature.
AGENT = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
check("the name reaches the prompt", "_operator_note()" in AGENT, True)
# 2026-09-05: this looked for the exact phrase "evidence of nothing". The
# prompt DOES say it and the source file does not contain it, because the
# sentence wraps across two f-string literals right between those two words.
# So it had been red since the day it was written and nothing ran the tests
# as a set to notice. Reading source text for a phrase that only exists after
# concatenation is the mistake. Assert on pieces that survive the wrap.
check("and is labelled as stated, not measured",
      "not something measured" in AGENT, True)
check("and the model is told not to reason from it",
      "never cite it" in AGENT and "never reason from it" in AGENT, True)


print("\n[18] 2026-09-04: 39.5 got its button, and the model still cannot press it")
for route, why in [
        ("/api/expected-ports",        "39.5, listing what is declared"),
        ("/api/expected-ports/remove", "39.5, withdrawing one"),
]:
    check(f"route exists ({why})", route in DEFINED, True)
    check(f"and the page calls it ({why})", route in CALLED, True)

check("the Review tab loads them", "loadExpectedPorts()" in UI, True)
check("there is a declare button", "declareExpectedPort(" in UI, True)
# A reason is the whole value of the column. A UI that lets you tab past it
# manufactures decisions nobody made.
check("the page refuses an empty reason",
      "A reason is required" in UI, True)
check("and so does the route", "A reason is required" in ROUTES, True)

# The rule from 39 that must not quietly lapse now that there is an HTTP path.
MEM = (ROOT / "core" / "memory_engine.py").read_text(encoding="utf-8")
check("declaring is still not a model tool",
      "declare_expected_port" in REGISTRY, False)
check("clearing is not a model tool either",
      "clear_port_findings" in REGISTRY, False)
# Clearing is a silencing act, so it is journaled like the dismissals are.
INTEG = (ROOT / "core" / "integrity.py").read_text(encoding="utf-8")
check("clearing findings is in the journal vocabulary",
      '"port_findings_cleared"' in INTEG, True)
# Over-clearing is the silent failure here, so the narrowness is fenced.
check("clearing is scoped to one device, not the whole entity",
      "dismiss_entity" in MEM.split("def clear_port_findings")[1].split("\ndef ")[0],
      True)

# 37.4: the prompt rule that says a fact you supplied yourself is not evidence.
AGENT = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")
check("the recall rule is in the system prompt",
      "TWO GUESSES THAT AGREE ARE STILL ONE GUESS" in AGENT, True)
check("and it names the failure it came from",
      "did not get from a tool is not evidence" in AGENT.lower(), True)

# 39.5 needed the finding to know which device it was about.
PORTS = (ROOT / "tools" / "port_scanner.py").read_text(encoding="utf-8")
check("a port finding records its host in raw_data",
      'entry["host"]' in PORTS, True)


print("\n[19] 2026-09-09: three things that were built and had to be REACHABLE")
# All three are the same failure this file exists for. Each one was written,
# each one worked, and each could have shipped with nothing on screen calling
# it. Section 33 all over again.

# TODO 80. retention.status() has ALWAYS returned measurement_limit and the
# page never read it, so the single most important caveat about what the
# capture can and cannot see lived in a JSON payload only the log ever saw.
check("the retention panel renders measurement_limit",
      "d.measurement_limit" in UI, True)
check("and the server still sends it",
      "measurement_limit" in (ROOT / "core" / "retention.py").read_text(encoding="utf-8"),
      True)
# The limit was reworded into advice. If it goes back to only stating the
# problem, somebody has undone the point of it.
RET = (ROOT / "core" / "retention.py").read_text(encoding="utf-8")
check("and it tells the owner what to DO, not just what is broken",
      "leave " in RET and "longer stretches" in RET, True)

# TODO 83. The approval warning, at the click rather than in a document.
check("there is one shared APPROVAL_WARNING constant",
      "const APPROVAL_WARNING" in UI, True)
check("the permission card uses it",
      UI.count("${APPROVAL_WARNING}") >= 1, True)
check("and so does the important-findings panel",
      UI.count("${APPROVAL_WARNING}") >= 2, True)
# The last line is the one that matters and it is the owner's. A warning that
# only says "be careful" teaches nothing; this one says what the mistake DOES.
#
# Matched against a whitespace-flattened copy, because the sentence is wrapped
# across source lines and is not one contiguous run of characters in the file.
# A check that fails on line wrapping is a check somebody deletes.
FLAT = " ".join(UI.split())
check("it says the mistake does not stay where you made it",
      "does not stay where you made it" in FLAT, True)
check("and names approving normal behaviour as the thing that starts it",
      "normal behaviour of your own ecosystem" in FLAT, True)
check("and tells the reader to go and look it up first",
      "Look it up before you approve or deny it" in FLAT, True)

# TODO 84. The list, and the half of it that is only a question.
check("the important panel is loaded when the alerts tab opens",
      UI.count("loadImportant()") >= 3, True)
check("a nomination is labelled as the model's opinion on screen",
      "The model says:" in UI, True)
check("and the panel says plainly that nothing is on the list yet",
      "They are not on the list yet." in UI, True)
# Removing a row must not silence the finding. If demote ever starts posting
# to the dismiss route, this is the check that should stop it.
check("remove calls demote, not dismiss",
      "/api/findings/demote" in UI, True)
check("and turning a nomination down calls reject, not dismiss",
      "/api/findings/reject" in UI, True)


print("\n[20] the Alerts screen says what it is actually showing")
# TODO 91, 2026-09-13. The card said "Active Findings" with a Dismiss All
# button next to it. What it actually shows is /api/findings, which passes
# session_id=sid and limit 50, so it is this run only and the newest fifty.
#
# The owner had 14,676 undismissed findings in the database while that screen sat
# empty. The owner's call on the fix, and it is the right one: this is a LABEL
# problem, not a behaviour problem. The scope is fine, the sentence was not.
check("the card names the scope", "Active Findings, this session" in UI, True)
check("and says the row cap out loud",
      "limited to this run, newest 50" in UI, True)
check("the dashboard tile is scoped too, since it reads the same route",
      'class="stat-lbl">Active Findings, this session<' in UI, True)
# The route is what makes the label true. If session_id ever comes off it, the
# label becomes the lie instead.
findings_route = ROUTES.split('@app.route("/api/findings")')[1][:400]
check("the route really is session scoped", "session_id=sid" in findings_route,
      True)
check("and really is capped", '_int_arg("limit", 50)' in findings_route, True)


print("\n[21] a refused chat request reaches the screen instead of vanishing")
# 2026-09-13. sendMessage never checked resp.ok. A 400 or a 401 comes back as
# JSON rather than SSE, so no line started with "data: ", every line was
# skipped, and the bubble ended up EMPTY with no reason anywhere. The catch
# only fires on a network error, which a refusal is not.
send = UI.split("async function sendMessage()")[1].split("\nfunction ")[0]

# THE FAILURE PATH FIRST. These three are the whole fix.
check("the response status is checked at all", "if (!resp.ok)" in send, True)
check("and the check comes BEFORE the stream is read",
      send.index("if (!resp.ok)") < send.index("resp.body.getReader()"), True)
check("the server's own reason is read out of the JSON",
      "err.error" in send and "err.detail" in send, True)

# An unreadable refusal and a known one have to stay different sentences,
# rule two. The page must not invent a reason it was not given.
check("a body that is not JSON is handled separately",
      "catch" in send.split("resp.json()")[1][:200], True)
check("and that case says the app did not say why",
      "did not say why" in send, True)
check("and says the status number so the log can be found",
      "resp.status" in send, True)

# Whatever branch it takes, the composer has to come back. A refusal that
# leaves the send button disabled is a dead chat box.
refusal_branch = send.split("if (!resp.ok)")[1].split("const reader")[0]
check("the refusal path re-enables the send button",
      "disabled = false" in refusal_branch, True)
check("and clears the streaming flag",
      "isStreaming = false" in refusal_branch, True)
check("and stops rather than falling through into the reader",
      "return;" in refusal_branch, True)

# The two server-side refusals this was written for, so the page and the
# routes cannot drift apart on what a refusal looks like.
check("the route still answers a long message with JSON",
      "Message too long" in ROUTES, True)
check("and there is a JSON handler for the size refusal too",
      "@app.errorhandler(413)" in ROUTES, True)


print("\n[22] the Processes page says when the findings were not read")
# TODO 98, 2026-09-14. The summary line said "None flagged" unconditionally,
# and that is a claim about the findings table. When the findings could not be
# read at all, the page said it anyway and every row drew on the signature
# alone. Third time this exact shape has been fixed on a screen, after the
# blind sniffer in 60 and the three surfaces in 60.5, so it is checked here
# rather than left to a look.
block = UI.split("function renderProcessBar")[1][:3000]
check("the page reads the flag the backend sets",
      "procData.findings_read === false" in block, True)
# Matched on the CODE spelling, single quoted with its trailing space. The
# comment above the branch names the same words and would satisfy a looser
# check, which is how a test passes for the wrong reason.
check("and 'None flagged' is behind it, not beside it",
      block.index("const findingsOut") < block.index("'None flagged. '"), True)
check("the failure line is red", "var(--red)" in block, True)
check("it says the colours are signature and path only",
      "signature and the path only" in block, True)
check("and it prints the backend's own note rather than inventing one",
      "procData.findings_note" in block, True)

# The backend really sends it. A screen reading a field nobody sets is the
# drift this file exists to catch.
PROC = (ROOT / "tools" / "process_monitor.py").read_text(encoding="utf-8")
check("process_table returns findings_read", '"findings_read": findings_read' in PROC, True)
check("and a note to go with it", '"findings_note"' in PROC, True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
