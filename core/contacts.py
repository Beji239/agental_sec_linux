"""
Every host this app contacts, grouped by what it is for, in plain words.

The enrichment lookups describe themselves in core/enrichment.py; this adds
the rest (threat lists, the model provider, web search, the map, the router)
from the same code and config that make the requests, so the list stays true.
"""

import ipaddress
import os
from urllib.parse import urlparse

GROUPS = [
    ("lookups",  "Looking up something the sensors saw"),
    ("lists",    "Keeping the malware and vulnerability lists up to date"),
    ("analyst",  "The analyst, the AI model that reads and answers"),
    ("search",   "Web search by the analyst"),
    ("map",      "The threat map"),
    ("lan",      "Devices on your own network"),
    ("manual",   "Downloads that run only when you start them"),
]

_PLAIN_DOWNLOAD = "a plain download request, nothing about your network"


def _host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def _is_local(host: str) -> bool:
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def _key_link(env: str | None) -> dict | None:
    return {"id": f"key-{env}", "env": env} if env else None


def _cfg_link(path: str) -> dict:
    return {"id": "cfg-" + path.replace(".", "-"), "path": path}


def _row(group, service, hosts, sends, returns, why, when, enabled,
         off_reason=None, settings=None, uses_key=None, **extra) -> dict:
    return {"group": group, "service": service, "hosts": list(hosts),
            "sends": sends, "returns": returns, "why": why, "when": when,
            "enabled": bool(enabled),
            "off_reason": None if enabled else off_reason,
            "settings": settings, "uses_key": uses_key, **extra}


def _has(env: str) -> bool:
    return bool(os.environ.get(env, "").strip())


def _lookup_rows() -> list[dict]:
    from core import enrichment
    rows = []
    for s in enrichment.source_catalog():
        env = s.get("env_var")
        if not s.get("documented"):
            why = ("UNDOCUMENTED. This source is wired up and has no "
                   "catalogue entry explaining it. Add one in "
                   "core/enrichment.py.")
        else:
            why = s.get("why") or ""
        rows.append(_row(
            "lookups", s.get("name") or s["source"],
            [s["host"]] if s.get("host") else [],
            s.get("sends") or "", s.get("answers") or "", why,
            "when a sensor sees something new; the answer is then saved",
            s.get("enabled"),
            off_reason=s.get("why_off"),
            settings=_key_link(env) if s.get("wired", True) else None,
            uses_key=env, local_only=not s.get("network"),
            documented=bool(s.get("documented")), source=s["source"],
            also=s.get("also")))
    return rows


_FEED_TEXT = {
    "feodo": ("Feodo Tracker, by abuse.ch",
              "the list of botnet control servers that are active now",
              "to notice a device on your network talking to a botnet's "
              "control server"),
    "urlhaus": ("URLhaus list, by abuse.ch",
                "the list of sites handing out malware now",
                "to notice a visit to a site that spreads malware"),
    "threatfox": ("ThreatFox, by abuse.ch",
                  "recent malware addresses, domains and file fingerprints, "
                  "with the malware family name",
                  "to catch connections to newly reported malware servers"),
    "misp": ("CIRCL threat reports (MISP feed)",
             "the newest published threat reports and the addresses in them",
             "to catch connections named in recent public reports"),
    "otx": ("AlienVault OTX",
            "threat reports shared by its community, with their addresses and "
            "domains",
            "to catch connections named in recent community reports"),
}


def _list_rows(config: dict) -> list[dict]:
    rows = []
    try:
        from tools import feed_matcher as fm
    except Exception:                            # pragma: no cover
        fm = None
    if fm is not None:
        block = (config or {}).get("threat_feeds") or {}
        on = block.get("enabled", True)
        hours = block.get("refresh_hours", fm.DEFAULT_REFRESH_HOURS)
        listed = block.get("feeds")
        chosen = list(fm.FEEDS) if listed is None else list(listed)
        for name, meta in fm.FEEDS.items():
            service, returns, why = _FEED_TEXT.get(
                name, (name, meta.get("gives", ""), "to keep the malware "
                       "lists up to date"))
            env, key, _problem = fm._key_for_feed(meta)
            if not on:
                off = "threat lists are switched off in config.json (threat_feeds)."
            elif name not in chosen:
                off = "not in the threat_feeds list in config.json."
            elif env and not key:
                off = f"needs a free key ({env})."
            else:
                off = None
            rows.append(_row(
                "lists", service, [_host(meta.get("url", ""))],
                _PLAIN_DOWNLOAD + (", with your key" if env else ""),
                returns, why, f"every {hours:g} hours",
                off is None, off_reason=off,
                settings=_key_link(env), uses_key=env, source=name))
    try:
        from tools import runbook
        kev_host = _host(runbook.CISA_KEV_URL)
    except Exception:                            # pragma: no cover
        kev_host = "www.cisa.gov"
    rows.append(_row(
        "lists", "CISA known exploited vulnerabilities", [kev_host],
        _PLAIN_DOWNLOAD,
        "the list of vulnerabilities attackers are known to be using",
        "so an out of date program with one of these is put first",
        "at each start", True, source="cisa_kev"))
    return rows


def _analyst_rows(config: dict) -> list[dict]:
    url = ""
    try:
        from core import agent_loop
        url = agent_loop._api_url or ""
    except Exception:                            # pragma: no cover
        pass
    if not url:
        url = ((config or {}).get("provider") or {}).get("api_url") or ""
    host = _host(url)
    local = _is_local(host)
    has_key = _has("AGENTAL_API_KEY")
    if not host:
        off = "no provider endpoint is set."
    elif not has_key:
        off = "no model provider key is set."
    else:
        off = None
    why = ("the analyst is a language model run by this provider, so it is "
           "the one service that sees details of your network. Point it at "
           "a model on this computer (LM Studio, Ollama) to keep all of it "
           "at home.")
    if local:
        why = "the model runs on this computer or your own network, so none "\
              "of this leaves your home."
    return [_row(
        "analyst", "Model provider", [host] if host else [],
        "your chat questions, and what the analyst reads to answer them: "
        "alerts, device names and addresses on your network, program names "
        "and connection details",
        "the analyst's answers, and the checks it decides to run",
        why, "when you chat, and when the background agent wakes up",
        off is None, off_reason=off,
        settings=(_key_link("AGENTAL_API_KEY") if host and not has_key
                  else _cfg_link("provider.api_url")),
        uses_key="AGENTAL_API_KEY",
        local_only=local, source="provider")]


def _search_rows() -> list[dict]:
    from core import web_search as ws
    sends = ("the search words the analyst chose, which can include an "
             "outside address, a domain or a program name")
    returns = "public web pages about it"
    why = ("to read what others have written about something it found, such "
           "as a vulnerability or a suspicious domain")
    names = {"google_cse": ("Google Programmable Search", "www.googleapis.com"),
             "tavily": ("Tavily", "api.tavily.com"),
             "serpapi": ("SerpApi", "serpapi.com")}
    rows = []
    for b in ws.keyed_backend_status():
        service, host = names.get(b["backend"], (b["backend"], ""))
        rows.append(_row(
            "search", service, [host] if host else [], sends, returns, why,
            "when the analyst searches", b["enabled"],
            off_reason=(f"needs a key ({b['env_var']})."
                        if not _has(b["env_var"])
                        else f"also needs {b.get('also_env')}."),
            settings=_key_link(b["env_var"]), uses_key=b["env_var"],
            source=b["backend"]))
    rows.append(_row(
        "search", "DuckDuckGo",
        [_host(ws.DDG_HTML_URL), _host(ws.DDG_LITE_URL),
         _host(ws.DDG_INSTANT_URL)],
        sends, returns, why,
        "when the analyst searches and no keyed service above answered",
        True, source="duckduckgo"))
    return rows


def _map_rows(config: dict) -> list[dict]:
    from core import home_location as hl
    geo = (config or {}).get("geoip") or {}
    on = geo.get("enabled", True) and geo.get("locate_online", True) is not False
    fixed = geo.get("home_lat") is not None and geo.get("home_lon") is not None
    if fixed:
        on = False
    off = ("the place is fixed by hand in Settings." if fixed
           else "the threat map is off." if not geo.get("enabled", True)
           else "Find location online is off, the timezone is used instead.")
    return [_row(
        "map", "Public address check", [_host(u) for u in hl.PUBLIC_IP_URLS],
        "a plain request. The service sees your public internet address, as "
        "any website you visit does",
        "your public internet address",
        "to place your home on the map. The address is placed with the "
        "GeoIP file on this computer, not by the service",
        f"at start, then at most every {hl.REFRESH_SECONDS // 60} minutes "
        f"while the map is in use", on, off_reason=off,
        settings=_cfg_link("geoip.home_lat" if fixed
                           else "geoip.enabled" if not geo.get("enabled", True)
                           else "geoip.locate_online"),
        source="home_location")]


def _lan_rows(config: dict) -> list[dict]:
    cfg = config or {}
    rows = []
    gw = cfg.get("gateway") or {}
    gw_host = gw.get("host") or ""
    rows.append(_row(
        "lan", "Your router, through the router agent",
        [f"{gw_host} (SSH)"] if gw_host else [],
        "commands that read the router's tables, and block rules only after "
        "you approve them",
        "which devices are connected, what they look up and where they "
        "connect",
        "the router sees every device on your network; this computer on its "
        "own sees only its own traffic",
        "around the clock, over one SSH login",
        bool(gw.get("enabled") and gw_host),
        off_reason=("not set up. Run scripts/install_gateway_agent.sh to "
                    "enrol a router."),
        source="gateway"))
    rm = cfg.get("router_monitor") or {}
    rm_host = rm.get("host") or ""
    rows.append(_row(
        "lan", "Your router, read over SNMP",
        [f"{rm_host} (SNMP)"] if rm_host else [],
        "read-only SNMP requests with the read community",
        "the router's own list of devices it has seen",
        "for routers without the router agent, a read-only way to list "
        "devices",
        f"every {rm.get('interval_minutes', 10)} minutes",
        bool(rm.get("enabled") and rm_host and _has("AGENTAL_ROUTER_COMMUNITY")),
        off_reason=("off in config.json (router_monitor)." if not rm.get("enabled")
                    else "needs the read community (AGENTAL_ROUTER_COMMUNITY)."),
        settings=(_key_link("AGENTAL_ROUTER_COMMUNITY")
                  if rm.get("enabled") else None),
        uses_key="AGENTAL_ROUTER_COMMUNITY", source="router_monitor"))
    lm = cfg.get("linux_monitor") or {}
    hosts = [h.get("host") for h in (lm.get("hosts") or [])
             if isinstance(h, dict) and h.get("host")
             and h.get("enabled", True)]
    rows.append(_row(
        "lan", "Other Linux computers you listed", [f"{h} (SSH)" for h in hosts],
        "read-only commands over SSH",
        "their logins, programs and open ports",
        "to watch computers this one cannot see from the outside",
        "on each poll", bool(lm.get("enabled") and hosts),
        off_reason=("off in Settings." if not lm.get("enabled")
                    else "no hosts are listed in config.json (linux_monitor)."),
        settings=(_cfg_link("linux_monitor.enabled")
                  if not lm.get("enabled") else None),
        source="linux_monitor"))
    try:
        from tools import network_scanner as ns
        sweep_on, _ = ns.sweep_enabled(cfg)
        secs, _ = ns.sweep_interval_seconds(cfg)
        when = f"every {max(1, int(secs) // 60)} minutes"
    except Exception:                            # pragma: no cover
        sweep_on, when = False, "on a timer"
    rows.append(_row(
        "lan", "Every device on your network, presence sweep",
        ["your local network"],
        "a ping and an address request (ARP) to each device",
        "whether each device is still there",
        "to tell a device that is asleep from one that has gone",
        when, sweep_on, off_reason="Presence sweep is off in Settings.",
        settings=_cfg_link("presence_sweep.enabled"), source="presence_sweep"))
    return rows


def _manual_rows() -> list[dict]:
    return [
        _row("manual", "GeoIP file download",
             ["cdn.jsdelivr.net", "unpkg.com", "registry.npmjs.org"],
             _PLAIN_DOWNLOAD,
             "the free DB-IP file that turns an address into a place",
             "the threat map needs it to place connections",
             "only when you run scripts/fetch_geoip.py", True,
             source="geoip_download"),
        _row("manual", "IEEE vendor list download",
             ["standards-oui.ieee.org"], _PLAIN_DOWNLOAD,
             "the official list of which company owns which hardware "
             "(MAC) address prefix",
             "to name the maker of each device without asking anyone online",
             "only when you run scripts/update_oui.py", True,
             source="oui_download"),
    ]


def catalog(config: dict) -> dict:
    """{groups: [{id, title, rows}]} for the dashboard."""
    rows = []
    for build in (_lookup_rows, lambda: _list_rows(config),
                  lambda: _analyst_rows(config), _search_rows,
                  lambda: _map_rows(config), lambda: _lan_rows(config),
                  _manual_rows):
        try:
            rows.extend(build())
        except Exception as e:                   # pragma: no cover
            rows.append(_row("manual", "Could not list this group", [],
                             "", "", f"{type(e).__name__}: {e}", "", False,
                             off_reason="the list could not be built."))
    groups = []
    for gid, title in GROUPS:
        g = [r for r in rows if r["group"] == gid]
        if g:
            groups.append({"id": gid, "title": title, "rows": g})
    return {"groups": groups}
