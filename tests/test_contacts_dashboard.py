"""
tests/test_contacts_dashboard.py, the dashboard's "which hosts get contacted".

Every outside contact is listed in plain words, every key row links to a
Settings field that exists, and a module tile can say a saved setting waits
for a restart. Runs with no app, no network and no database.
"""
import json
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import contacts, enrichment, settings as st   # noqa: E402
from core import agent_loop                              # noqa: E402
from tools import feed_matcher                           # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


CONFIG = {
    "provider": {"api_url": "https://api.example.com/v1/chat/completions"},
    "threat_feeds": {"enabled": True, "refresh_hours": 6},
    "gateway": {"enabled": True, "host": "192.0.2.1"},
    "router_monitor": {"enabled": False},
    "linux_monitor": {"enabled": False, "hosts": []},
    "geoip": {"enabled": True, "locate_online": True},
}
agent_loop._api_url = ""
cat = contacts.catalog(CONFIG)
rows = [r for g in cat["groups"] for r in g["rows"]]
by_source = {r.get("source"): r for r in rows}


print("\n[1] every outside contact the todo named is listed")
listed = {(r["group"], r.get("source")) for r in rows}
for name in feed_matcher.FEEDS:
    check(f"threat feed {name} is listed", ("lists", name) in listed, True)
for src in ("cisa_kev", "provider", "duckduckgo", "home_location", "gateway",
            "geoip_download", "oui_download"):
    check(f"{src} is listed", src in by_source, True)
check("the provider row names the configured host",
      by_source["provider"]["hosts"], ["api.example.com"])
check("every lookup source is in the lookups group",
      {s["source"] for s in enrichment.source_catalog()}
      <= {r["source"] for r in rows if r["group"] == "lookups"}, True)


print("\n[2] plain words, no developer terms, no dash punctuation")
JARGON = re.compile(r"ladder|rung|single_source|corroborat|enricher", re.I)
DASHES = re.compile(r"—|–| -- | - | \| ")
for r in rows:
    text = " ".join(str(r.get(k) or "") for k in
                    ("service", "sends", "returns", "why", "when",
                     "off_reason", "also"))
    for k in ("service", "sends", "returns", "why", "when"):
        if r["source"] in ("oui",) and k == "sends":
            continue
        if not r.get(k):
            check(f"{r['service']} has {k}", r.get(k), "something")
    if JARGON.search(text):
        check(f"{r['service']} avoids developer terms", JARGON.findall(text), [])
    if DASHES.search(text):
        check(f"{r['service']} avoids dash punctuation", DASHES.findall(text), [])
for line in enrichment.NEVER_SENT:
    check("never-sent line is plain", bool(JARGON.search(line) or DASHES.search(line)), False)
check("checked every row", len(rows) > 20, True)


print("\n[3] each Settings link points at a field the Settings tab draws")
key_ids = {"key-" + k["env"] for k in st.key_catalog()}
cfg_ids = {"cfg-" + f["path"].replace(".", "-") for f in st.CONFIG_FIELDS}
for r in rows:
    if r.get("settings"):
        check(f"{r['service']} link exists", r["settings"]["id"] in key_ids | cfg_ids, True)
check("the OTX key has a Settings field", "key-AGENTAL_OTX_KEY" in key_ids, True)
check("OTX is no longer template-only drift",
      "AGENTAL_OTX_KEY" in st.key_drift()["template_only"], False)
for mod, entries in st.MODULE_SETTINGS.items():
    for e in entries:
        check(f"{mod} entry {e} exists", st.settings_anchor(e) in key_ids | cfg_ids, True)


print("\n[4] a keyed row with no key is off and says which key")
import os                                                 # noqa: E402
saved = os.environ.pop("AGENTAL_OTX_KEY", None)
try:
    otx = {r["source"]: r for r in contacts.catalog(CONFIG)["groups"][1]["rows"]}.get("otx")
    check("otx is off without its key", otx["enabled"], False)
    check("and names the key", "AGENTAL_OTX_KEY" in otx["off_reason"], True)
    check("and links to it", otx["settings"]["id"], "key-AGENTAL_OTX_KEY")
finally:
    if saved is not None:
        os.environ["AGENTAL_OTX_KEY"] = saved
off_cfg = dict(CONFIG, threat_feeds={"enabled": False})
feodo = next(r for g in contacts.catalog(off_cfg)["groups"] for r in g["rows"]
             if r.get("source") == "feodo")
check("switched-off feeds say so", "switched off" in feodo["off_reason"], True)


print("\n[5] a model on this computer is called local")
local = dict(CONFIG, provider={"api_url": "http://localhost:1234/v1/chat/completions"})
prov = next(r for g in contacts.catalog(local)["groups"] for r in g["rows"]
            if r.get("source") == "provider")
check("localhost provider is local", prov["local_only"], True)
check("and says nothing leaves", "none of this leaves" in prov["why"], True)
check("a remote provider says it sees network details",
      "sees details of your network" in by_source["provider"]["why"], True)


print("\n[6] a saved setting waiting for a restart shows on its tile")
with tempfile.TemporaryDirectory() as tmp:
    path = pathlib.Path(tmp) / "config.json"
    path.write_text(json.dumps({"probe": {"enabled": False}}), encoding="utf-8")
    old = st.CONFIG_PATH
    st.CONFIG_PATH = path
    try:
        ms = st.module_settings({"probe": {"enabled": True}},
                                ["probe", "network_scanner", "packet_sniffer"])
    finally:
        st.CONFIG_PATH = old
check("probe waits for a restart", ms["modules"]["probe"]["pending"], ["Device probe"])
check("its link opens the probe switch", ms["modules"]["probe"]["anchor"], "cfg-probe-enabled")
check("an unchanged module waits for nothing", ms["modules"]["network_scanner"]["pending"], [])
check("a module with no setting gets no link", "packet_sniffer" in ms["modules"], False)
check("the overall list names the field",
      [p["label"] for p in ms["pending"]], ["Device probe"])


print("\n[7] the page carries the links")
page = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("openSettingsAt exists", "async function openSettingsAt(id)" in page, True)
check("the table reads the contacts groups", "_srcCatalog.contacts" in page, True)
check("the grid shows waiting saves", 'id="module-pending"' in page, True)
check("the old developer column is gone", "Why it is in the set" in page, False)


print()
if fails:
    print(f"FAILED  {len(fails)} check(s): {', '.join(fails)}")
    sys.exit(1)
print("all contacts dashboard checks passed")
