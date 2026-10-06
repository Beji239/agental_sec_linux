# core/settings.py
# AgentalSec V2, the settings panel's backend. TODO 2.3 + 8.5, built as one
# thing because they were always one thing.
#
# WHAT THIS FILE IS FOR, in one sentence: a fresh clone shows a dashboard of
# zeros, and zeros look like a clean network. Something has to say out loud
# which collectors are off, why, and what to type to turn them on.
#
# IT IS A PANEL, NOT A WIZARD. Decided 2026-09-03. A wizard is a screen you
# see once, while you know least about the tool, and cannot find again three
# weeks later when a key expires. The moment you most need it is never the
# moment it is showing.
#
# THREE RULES, and they are the reason this file exists instead of a couple
# of routes:
#
#   1. SECRETS GO TO .env. NEVER TO config.json. The split between the two is
#      the whole reason config.json is safe to commit, and a settings screen
#      that fills the wrong file undoes it silently. So the two writers here
#      are separate functions with separate allow-lists, and the config
#      writer physically cannot address a secret: its allow-list is a fixed
#      list of non-secret paths and anything else is refused. Fenced by
#      tests/test_settings_panel.py.
#
#   2. NEVER SHOW A KEY WE ALREADY HOLD. Present, absent, and the last four
#      characters are enough to tell somebody what to fix. The dashboard page
#      already carries one credential and that is one more than I would like,
#      so nothing here adds a second. There is no read path for a value.
#
#   3. THE NAME IS SOMETHING THE USER SAID, not something we measured. It
#      goes in with the same honesty as the rest of the schema: it is what
#      they typed and it is evidence of nothing.
#
# AND ONE RULE ABOUT DRIFT. The list of keys is already written down twice,
# in .env.example and in enrichment.KEYED_SOURCES. A third copy here would go
# stale the first week somebody adds a source, which is exactly what happened
# to the hardcoded chip row in 44. So the catalogue below READS both of those
# and holds only what neither of them knows: whether a key takes effect while
# the app is running, and whether the tool can generate it for you.

import json
import logging
import os
import re
import secrets as _secrets
import threading
from pathlib import Path

from core import secret_crypto as crypto

# HOW MANY FAILED POLLS IN A ROW MAKE A ROW RED. Read from the ONE place it is
# declared (core/sensor_health), so the card and the model path cannot disagree
# about the same sensor. A local copy would drift the first time either number
# moved, and the two surfaces would then disagree about a machine in front of
# one operator.
try:
    from core.sensor_health import CONSECUTIVE_FAILURE_FLOOR as _FAILING_POLLS_FLOOR
except Exception:                                    # pragma: no cover
    _FAILING_POLLS_FLOOR = 3

logger = logging.getLogger(__name__)

# ONE WRITER AT A TIME, ACROSS BOTH FILES.
#
# Every write here is a read-modify-write: pull the whole file in, change one
# line, put it back. Waitress serves this on eight threads, so two saves that
# overlap both read the same original and the second one writes it back
# without the first one's change. In config.json that loses a setting. In
# .env it loses a credential, silently, and the panel says both saves worked.
#
# 47.9 item 3 wrote this up as fixed on 2026-09-04 and the lock was not in
# this file on 2026-09-05. tests/test_settings_panel.py section 12 races
# sixteen writers and had been failing on every run since.
#
# One lock for both files rather than one each. They are never written in the
# same call, the writes are milliseconds, and two locks is two chances to take
# them in a different order later.
_write_lock = threading.Lock()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Resolved, because in the Docker image these are symlinks into the /state
# volume, and an atomic replace onto a symlink swaps the link, not the file.
ENV_PATH     = (PROJECT_ROOT / ".env").resolve()
ENV_EXAMPLE  = PROJECT_ROOT / ".env.example"
CONFIG_PATH  = (PROJECT_ROOT / "config.json").resolve()

DISPLAY_NAME_PREF = "operator_display_name"
DISPLAY_NAME_MAX  = 40

# A value written into .env has to survive being read back by a shell, by
# python-dotenv, and by our own parser in secret_store. Printable ASCII with
# no quote character keeps all three honest, and every credential any of
# these services issues is hex or base64 anyway.
_SAFE_VALUE = re.compile(r"^[\x20-\x21\x23-\x7e]*$")   # printable, no " and no #
_VALUE_MAX  = 512

# The floor on OUR key, and only ours. generate_app_key() mints 64 hex
# characters, so 32 refuses a typed word without refusing an older short one
# somebody is actually using.
_APP_KEY_MIN = 32
_APP_KEY_ENV = "AGENTAL_APP_API_KEY"


# WHAT .env.example ALREADY SAYS

def env_example_notes(path: Path | None = None) -> dict[str, str]:
    """
    {ENV_NAME: the comment block written above it in .env.example}.

    EVERY name in the template is a key here, with an empty string when it
    has no comment block. That matters for key_drift: a variable somebody
    added to the template without writing a note is still a variable in the
    template, and reporting it as absent would be the drift check hiding
    exactly the kind of half-finished edit it is there to catch.

    That file is already the place where "what is this key for" is written
    for a human, and it ships with the repo. Reading it means the panel says
    the same thing the file says, forever, instead of saying whatever
    somebody typed into a template six months ago.

    Never raises. A missing or unreadable template gives an empty dict and
    the catalogue falls back to the note enrichment carries.
    """
    src = path or ENV_EXAMPLE
    try:
        lines = src.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}

    notes, block = {}, []
    for raw in lines:
        line = raw.strip()
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            # A divider line of hashes is decoration, not prose.
            if body:
                block.append(body)
            continue
        if not line:
            block = []
            continue
        if "=" in line:
            name = line.split("=", 1)[0].strip()
            if name.startswith("export "):
                name = name[7:].strip()
            if name:
                notes[name] = " ".join(block)
        block = []
    return notes


# THE KEY CATALOGUE
#
# Only the things neither .env.example nor enrichment knows live here.
#
# effect: 'live'    the code reads os.environ on every use, so saving is
#                   enough and the change is real immediately
#         'restart' the value was read once at boot into a module global or
#                   into app.config, so it applies at the next start
#
# The distinction matters more than it looks. A panel that says "saved" and
# means "saved, and also nothing happened yet" is the same class of lie as a
# sensor tile that says running while nothing is being read.

_CODE_KEYS = [
    {
        "env":      "AGENTAL_APP_API_KEY",
        "label":    "Dashboard API key",
        "group":    "core",
        # NOT required, and that is not a slip. secret_store mints one when
        # there is none, so a fresh clone works. What it costs is stability:
        # the key changes at every restart. That is worth an amber row and it
        # is not worth a red one, and a panel that paints a working install
        # red teaches people to ignore red.
        "required": False,
        "effect":   "restart",
        "generate": True,
        "unlocks":  "every /api/* call the dashboard makes",
        "without":  ("a fresh one is minted at each start, so the dashboard "
                     "works but the key changes every restart"),
    },
    {
        "env":      "AGENTAL_API_KEY",
        # Whatever key the provider endpoint expects, Anthropic, OpenAI or a
        # gateway.
        "label":    "Model provider API key",
        "group":    "core",
        # FLIPPED TO REQUIRED 2026-09-14 with the removal of local mode.
        #
        # It was optional and that was correct while there was a second
        # backend that needed no key. There is one backend now, so a missing
        # key means the analyst cannot answer at all, and rendering that as an
        # amber "off" row would be the panel calling a broken install
        # configured. Red is the honest colour for it.
        "required": True,
        "effect":   "live",
        "generate": False,
        "unlocks":  "the analyst",
        "without":  ("The analyst cannot answer at all. The endpoint is "
                     "provider.api_url in config.json and can point at any "
                     "OpenAI-style or Anthropic Messages server, including "
                     "one on this machine, so this is whatever that server "
                     "expects"),
    },
    {
        "env":      "AGENTAL_ROUTER_COMMUNITY",
        "label":    "Router SNMP read community",
        "group":    "collector",
        "required": False,
        "effect":   "live",
        "generate": False,
        "unlocks":  "reading the router's own neighbour table",
        "without":  ("router_monitor stays off and says so, rather than "
                     "guessing at a default and probing a router you never "
                     "pointed it at"),
    },
]


def _last4(value: str) -> str:
    """The tail of a key, or empty. Four characters identify which key you
    pasted and reconstruct none of it."""
    v = (value or "").strip()
    return v[-4:] if len(v) >= 8 else ""


def key_catalog() -> list[dict]:
    """
    Every environment variable this codebase reads, with its state.

    NO VALUE IS EVER IN THIS LIST. present, last4 and the reason it matters.
    """
    notes = env_example_notes()

    entries = list(_CODE_KEYS)

    # The enrichment sources describe themselves. keyed_source_status()
    # already answers "is it on, and if not why not" for the dashboard, so
    # this reuses it rather than restating it.
    try:
        from core import enrichment
        for row in enrichment.keyed_source_status():
            entries.append({
                "env":      row["env_var"],
                "label":    row["source"].replace("_", ".") + " key",
                "group":    "enrichment",
                "required": False,
                "effect":   "live",
                "generate": False,
                "unlocks":  row.get("would_give") or "",
                "without":  row.get("why_off") or "",
            })
    except Exception as e:                       # pragma: no cover
        logger.warning(f"Could not read the enrichment source list: {e}")

    # The keyed search backends, TODO 53.1, same rule as above: the module
    # that uses the key describes it, the panel only renders. Two entries for
    # Google because a key without an engine id is not a credential.
    try:
        from core import web_search
        for row in web_search.keyed_backend_status():
            entries.append({
                "env":      row["env_var"],
                "label":    row["backend"].replace("_", ".") + " search key",
                "group":    "search",
                "required": False,
                "effect":   "live",
                "generate": False,
                "unlocks":  row.get("would_give") or "",
                "without":  row.get("why_off") or "",
            })
            if row.get("also_env"):
                entries.append({
                    "env":      row["also_env"],
                    "label":    row["backend"].replace("_", ".") + " engine id",
                    "group":    "search",
                    "required": False,
                    "effect":   "live",
                    "generate": False,
                    "unlocks":  "the search engine the key queries. Not a "
                                "secret, but it lives here because the key is "
                                "useless without it.",
                    "without":  "without it the key cannot be used.",
                })
    except Exception as e:                       # pragma: no cover
        logger.warning(f"Could not read the search backend list: {e}")

    out = []
    for e in entries:
        raw = os.environ.get(e["env"], "").strip()
        out.append({
            **e,
            "present":     bool(raw),
            "last4":       _last4(raw),
            "description": notes.get(e["env"], "") or e.get("without", ""),
            "in_template": e["env"] in notes,
        })
    return out


def key_drift() -> dict:
    """
    Where .env.example and the code disagree about which keys exist.

    Same job as SOURCE_CATALOG in 44: the answer is derived, so the panel
    reports the drift instead of quietly inheriting it. Shown small, at the
    bottom, because on a healthy tree both lists are empty.
    """
    in_code    = {e["env"] for e in key_catalog()}
    in_example = set(env_example_notes())
    return {
        "template_only": sorted(in_example - in_code),
        "code_only":     sorted(in_code - in_example),
    }


# WRITING .env

def set_key(env_name: str, value: str) -> dict:
    """
    Write one key into .env. Returns {ok, reason, effect, present, last4}.

    REFUSES rather than corrects, the same way retention.apply_choice does.
    An unknown variable name is not a typo to be helpful about: it is a
    request to write something into a secrets file that nothing in this
    codebase will ever read.

    An empty value CLEARS the key, and clearing has to stay easy. Revoking a
    credential should not require finding a text editor.
    """
    allowed = {e["env"]: e for e in key_catalog()}
    entry   = allowed.get((env_name or "").strip())
    if entry is None:
        return {"ok": False,
                "reason": (f"{env_name!r} is not a variable this codebase "
                           f"reads. Nothing was written.")}

    val = (value or "").strip()
    if len(val) > _VALUE_MAX:
        return {"ok": False,
                "reason": f"That value is longer than {_VALUE_MAX} characters."}
    if not _SAFE_VALUE.match(val):
        return {"ok": False,
                "reason": ("A key can only contain printable ASCII, and no "
                           "quote or # character. Check for a stray newline "
                           "from the copy and paste.")}

    # THE ONE KEY WITH A FLOOR, AND IT WAS MISSING.
    #
    # 47.9 item 5 wrote this up on 2026-09-04 as done, and on 2026-09-05 it
    # was not in this file. tests/test_settings_panel.py had been asserting it
    # and failing on every run since, and nothing ran the tests as a set, so
    # the write-up was the only place it existed. That is worse than not
    # having built it, because the note said it was handled.
    #
    # Every other key here was issued by somebody else and we are in no
    # position to judge its shape. This one is ours and it guards every route
    # on the dashboard, so a typed word is not a value to accept politely.
    # Clearing stays allowed, because "mint a fresh one at the next start" is
    # a legitimate thing to want.
    if entry["env"] == _APP_KEY_ENV and val and len(val) < _APP_KEY_MIN:
        return {"ok": False,
                "reason": (f"The application key must be at least "
                           f"{_APP_KEY_MIN} characters. It is the key that "
                           f"guards every route on this dashboard, so a typed "
                           f"word is not enough. Use Generate to mint one, or "
                           f"clear the box to have one minted at the next "
                           f"start.")}

    ok, err = _write_env_line(entry["env"], val)
    if not ok:
        return {"ok": False, "reason": err}

    # Keep the running process in step with the file. Everything marked
    # 'live' reads os.environ per call, so this is what makes saving real.
    if val:
        os.environ[entry["env"]] = val
    else:
        os.environ.pop(entry["env"], None)

    # The model key is held in a module global rather than re-read, so it
    # needs handing over explicitly. Doing it here is what lets the panel say
    # 'live' honestly for that row.
    if entry["env"] == "AGENTAL_API_KEY":
        try:
            from core import agent_loop
            agent_loop.apply_api_key(val)
        except Exception as e:                   # pragma: no cover
            logger.warning(f"Saved the key but could not hand it to the agent: {e}")
            return {"ok": True, "effect": "restart", "present": bool(val),
                    "last4": _last4(val),
                    "reason": "Saved to .env. Restart to pick it up."}

    logger.info(f"Settings panel wrote {entry['env']} "
                f"({'set' if val else 'cleared'}).")
    return {"ok": True, "effect": entry["effect"], "present": bool(val),
            "last4": _last4(val)}


def generate_app_key() -> dict:
    """
    Mint AGENTAL_APP_API_KEY rather than asking somebody to invent one.

    A person asked to produce a random hex string produces a bad one, and
    this particular string is what stands between another process on this box
    and every tool in the manifest.

    IT DOES NOT TAKE EFFECT NOW, ON PURPOSE. app.config holds the key this
    process started with and the open dashboard page carries it. Swapping it
    live would 401 the page the operator is looking at, which reads as the
    tool breaking.
    """
    key = _secrets.token_hex(32)
    ok, err = _write_env_line("AGENTAL_APP_API_KEY", key)
    if not ok:
        return {"ok": False, "reason": err}
    logger.info("Settings panel generated a new app API key. Takes effect at "
                "the next start.")
    return {"ok": True, "effect": "restart", "present": True,
            "last4": _last4(key),
            "reason": ("A new key is in .env. This session keeps the old one, "
                       "so nothing breaks until you restart.")}


def _own_read_only(path: Path) -> None:
    """
    Owner-only permissions, set on the TEMP file before the rename, so there
    is never a moment where .env exists with default permissions.

    THIS IS THE WHOLE PROTECTION ON THIS PLATFORM, and it is not decoration:
    a world-readable .env is a real finding here, unlike on Windows where the
    mode bit does almost nothing because permissions come from the folder ACL.
    Encryption (core/secret_crypto) sits on top of it rather than instead of
    it, and either one failing is not a reason to refuse to save a key.

    Best effort by design. A filesystem that will not take a mode is not a
    reason to refuse to save somebody's key.
    """
    try:
        os.chmod(path, 0o600)
    except OSError as e:                         # pragma: no cover
        logger.debug(f"Could not set owner-only permissions on {path}: {e}")


def _write_env_line(name: str, value: str) -> tuple[bool, str]:
    """
    Set NAME=value in .env, keeping every comment and every other line.

    Written as a text edit rather than a re-serialise because .env is a file
    a person also edits by hand, and the comments in it are half of what it
    is for. A writer that rewrites the file from a dict deletes all of that
    the first time it runs.

    The read and the write are inside one lock. See _write_lock: they are one
    operation, and holding the lock over only the write half would still let
    two callers read the same original.

    The temp file keeps its fixed name rather than getting a per-thread one.
    The lock means only one of these runs at a time, so there is nothing to
    collide with, and a generated name like ".env.4821.tmp" would fall outside
    whatever .gitignore covers, which is the trap the naming comment below is
    already about.
    """
    with _write_lock:
        try:
            text = ENV_PATH.read_text(encoding="utf-8") if ENV_PATH.exists() else ""
        except OSError as e:
            return False, f"Could not read .env: {e}"

        # ENCRYPTED ON THE WAY TO DISK, TODO 2.2. The caller passes the real
        # value and keeps using the real value, so nothing else in this file
        # changes. Encryption failing is not a reason to lose somebody's key,
        # so it falls back to plain and says so out loud rather than quietly.
        stored = value
        if value and crypto.enabled():
            try:
                stored = crypto.protect(value)
            except crypto.SecretCryptoError as e:          # pragma: no cover
                logger.warning(f"Could not encrypt {name} for .env, storing it "
                               f"in plain text: {e}")

        quoted = f'"{stored}"' if " " in stored else stored
        line   = f"{name}={quoted}"

        pattern = re.compile(rf"^[ \t]*(?:export[ \t]+)?{re.escape(name)}[ \t]*=.*$",
                             re.MULTILINE)
        if pattern.search(text):
            new = pattern.sub(line, text, count=1)
        else:
            # Appended with the template's own explanation, so a file grown by
            # this panel still reads like the one that shipped.
            note = env_example_notes().get(name, "")
            block = "\n" if text and not text.endswith("\n") else ""
            if note:
                block += f"\n# {note}\n"
            else:
                block += "\n"
            new = text + block + line + "\n"

        # Sibling temp file, named by hand rather than with_suffix: ENV_PATH is
        # ".env", which pathlib reads as all stem and no suffix, so with_suffix
        # would produce ".env.env.tmp" and quietly drop out of .gitignore's reach.
        tmp = ENV_PATH.with_name(ENV_PATH.name + ".tmp")
        try:
            tmp.write_text(new, encoding="utf-8")
            _own_read_only(tmp)
            os.replace(tmp, ENV_PATH)
        except OSError as e:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            return False, f"Could not write .env: {e}"
        return True, ""


# THE NON-SECRET SHAPE
#
# A fixed allow-list of dotted paths into config.json. This list is the
# guarantee in rule 1: there is no path here that names a secret, and
# set_config refuses everything not on it, so the config writer has no reach
# into .env territory even if somebody posts one.
#
# Not everything in config.json is here, and that is deliberate too. The
# linux_monitor host list, the probe exclusion list and the allowed_hosts
# array are structures rather than settings, and a text box is the wrong
# shape for them. They stay in the file, where a person editing them can see
# the comments explaining what they cost.

CONFIG_FIELDS = [
    # THE PROVIDER, FIRST. Added 2026-09-15.
    #
    # The key could already be changed from this panel and these two could
    # not, so moving from one provider to another meant editing config.json
    # and restarting. That is the wrong shape for the one setting somebody
    # else running this has to change on their first day, and it made the app
    # look tied to one vendor when the request path never was.
    #
    # Applied LIVE, like the key, which is why they carry their own effect
    # rather than the file-wide one below.
    {"path": "provider.api_url", "type": "url", "effect": "live",
     "testable": True, "label": "Provider endpoint",
     "why": ("Any service that speaks the OpenAI chat API (DeepSeek, OpenAI, "
             "a gateway like OpenRouter, a server on this machine) or the "
             "Anthropic Messages API, for example "
             "https://api.anthropic.com/v1/messages. The key for whichever "
             "one you point at goes in the keys section below.")},
    {"path": "provider.model", "type": "text", "effect": "live",
     "testable": True, "label": "Model",
     "why": ("Whatever the provider above calls the model you want, copied "
             "exactly. Nothing is assumed for you: leave it blank and the "
             "analyst says it has no model rather than picking one.")},
    {"path": "provider.api_style", "type": "choice", "effect": "live",
     "label": "API style", "choices": ["auto", "openai", "anthropic"],
     "why": ("Which wire format the endpoint speaks. Auto reads it from the "
             "endpoint address: a /messages address is the Anthropic API, "
             "anything else is the OpenAI chat shape. Set it only if auto "
             "guesses wrong.")},

    {"path": "sensor.position", "type": "choice", "label": "Sensor position",
     "why": ("Where this instance sits on the network. Every scope statement "
             "the model reads comes from here, so a wrong value makes the "
             "tool confidently describe a view it does not have. Change it "
             "only if the instance actually moved.")},
    {"path": "sensor.label", "type": "text", "label": "Sensor label",
     "why": "Optional name for this vantage point in the sensor table."},

    {"path": "presence_sweep.enabled", "type": "bool", "label": "Presence sweep",
     "why": ("The quiet ping and ARP sweep that answers 'is it still there'. "
             "Off means absence data stops, and absence is what the tool "
             "reads to tell asleep from gone.")},
    {"path": "presence_sweep.interval_minutes", "type": "int", "min": 1,
     "max": 1440, "label": "Sweep every (minutes)",
     "why": ("A trade between resolution and noise, not cost. Fifteen gives "
             "four samples an hour, enough to tell 'stopped answering an "
             "hour ago' from 'missed one sweep'.")},

    {"path": "probe.enabled", "type": "bool", "label": "Device probe",
     "why": ("The three-weekly fingerprint re-check. Answers 'is it still "
             "the same thing', which the sweep cannot.")},
    {"path": "probe.interval_days", "type": "int", "min": 1, "max": 365,
     "label": "Probe every (days)",
     "why": "21 is Microsoft Defender's published cadence, which is where the number came from."},

    {"path": "geoip.enabled", "type": "bool", "label": "Threat map geolocation",
     "why": "Off leaves the map empty and says why."},
    {"path": "geoip.locate_online", "type": "bool", "label": "Find location online",
     "why": ("The map's centre pin is this machine's own place, worked out at "
             "run time: the public address is read from a public service and "
             "placed with the GeoIP file, and checked against the timezone. "
             "Off uses the timezone alone.")},
    {"path": "geoip.home_lat", "type": "float", "min": -90, "max": 90,
     "label": "Fixed latitude",
     "why": ("Leave blank and the app finds its own place, wherever it runs. "
             "Set both only to pin the map to one place on purpose.")},
    {"path": "geoip.home_lon", "type": "float", "min": -180, "max": 180,
     "label": "Fixed longitude", "why": "See latitude."},
    {"path": "geoip.home_label", "type": "text", "label": "Fixed place name",
     "why": "The centre pin's name when the place is fixed by hand."},

    {"path": "dns_monitor.enabled", "type": "bool", "label": "Resolver ingest",
     "why": ("The only sensor here that covers devices this host cannot see. "
             "It needs a resolver you run; without one this stays off and "
             "reads nothing.")},
    {"path": "dns_monitor.source", "type": "choice", "label": "Resolver type",
     "choices": ["pihole", "adguard", "router"],
     "why": ("pihole reads pihole-FTL.db, adguard reads querylog.json, router "
             "reads the router's dnsmasq log through the gateway agent.")},
    {"path": "dns_monitor.path", "type": "text", "label": "Resolver database path",
     "why": "The file itself. Read-only; this tool never writes to it."},
    {"path": "dns_monitor.interval_minutes", "type": "int", "min": 1, "max": 1440,
     "label": "Import every (minutes)",
     "why": "The resolver is already recording. This only controls how fresh our copy is."},

    {"path": "linux_monitor.enabled", "type": "bool", "label": "Linux host monitor",
     "why": ("SSH-polled Linux hosts. The host list itself stays in "
             "config.json, where the comments explaining it are.")},

    {"path": "flask.port", "type": "int", "min": 1, "max": 65535,
     "label": "Dashboard port", "why": "Changing this changes the address you browse to."},
    {"path": "flask.auto_open_browser", "type": "bool",
     "label": "Open a browser at start", "why": ""},
]

# MOST fields above change a file that main.py reads once, at boot, so this
# is the default and the panel says so rather than implying otherwise. A
# field that really is applied live carries its own "effect" instead, and
# _LIVE_APPLY below is what makes that claim true. Nothing is live because a
# dict said so: if the handover raises, the save is still reported as needing
# a restart.
CONFIG_EFFECT = "restart"


def _apply_provider_field(path: str, value) -> tuple[bool, str]:
    """Hand a saved provider field to the running agent. (applied, why_not)."""
    from core import agent_loop
    if path == "provider.api_url":
        kwargs = {"api_url": value}
    elif path == "provider.api_style":
        kwargs = {"api_style_name": "auto" if value is None else value}
    else:
        # None means TWO different things either side of this line. Here it is
        # "the user cleared the box", in apply_provider it is "this argument
        # was not passed, leave it alone". Sending it straight through wrote
        # the blank to config.json and left the old model running, while the
        # panel said it was live. Found by section [5] of the test, and it is
        # the same shape as every other bug in this project: the happy path
        # was fine and clearing it lied.
        kwargs = {"model": "" if value is None else value}
    res = agent_loop.apply_provider(**kwargs)
    if not res.get("ok"):
        return False, res.get("reason", "the agent refused the value")
    return True, ""


# path -> the function that makes it true in the running process. A field
# with an effect of "live" and no entry here would be a label the code does
# not back, so config_fields refuses to call anything live without one.
_LIVE_APPLY = {
    "provider.api_url":   _apply_provider_field,
    "provider.model":     _apply_provider_field,
    "provider.api_style": _apply_provider_field,
}


def _choices_for(path: str) -> list[str]:
    if path == "sensor.position":
        try:
            from core import sensors
            return sorted(sensors.VALID_POSITIONS)
        except Exception:                        # pragma: no cover
            return ["host"]
    for f in CONFIG_FIELDS:
        if f["path"] == path:
            return list(f.get("choices") or [])
    return []


def _cfg_leaf(cfg: dict, block: str, leaf: str):
    """One config value."""
    return (cfg.get(block) or {}).get(leaf)


def config_fields(config: dict) -> list[dict]:
    """
    The allow-list, each field carrying its current value.

    THE VALUE COMES FROM THE FILE, NOT FROM THE BOOTED DICT.

    47.9 item 1 wrote this up as done on 2026-09-04 and it was not in this
    file on 2026-09-05. tests/test_settings_panel.py had been asserting it and
    failing every run since, and nothing ran the tests as a set, so the
    write-up was the only place the fix existed. The UI half WAS built: the
    page already renders running_value, it was just never being sent one.

    The bug it names: main.py holds the config it booted with, nothing
    updates that dict when the panel writes, so a successful save rendered the
    old number straight back and looked like it had done nothing.

    running_value is the other half of being honest about it. Most of these
    need a restart to take effect, so a saved value and a running value can
    legitimately differ and the panel has to say which is which. It is only
    attached where the two ACTUALLY differ, or every row wears a stale banner
    forever and nobody reads any of them.
    """
    try:
        on_disk = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if not isinstance(on_disk, dict):
            on_disk = None
    except (OSError, json.JSONDecodeError):
        # No file yet, or an unreadable one. The booted dict is then the only
        # thing there is, and showing it beats showing a page of blanks. No
        # running_value in that case: with nothing to compare against, a
        # difference cannot be claimed.
        on_disk = None

    booted = config or {}
    out = []
    for f in CONFIG_FIELDS:
        block, _, leaf = f["path"].partition(".")
        running = _cfg_leaf(booted, block, leaf)
        current = running if on_disk is None else _cfg_leaf(on_disk, block, leaf)

        # A field may only call itself live if something here actually
        # applies it. Otherwise it is a restart field wearing a better label.
        effect = f.get("effect", CONFIG_EFFECT)
        if effect == "live" and f["path"] not in _LIVE_APPLY:
            effect = CONFIG_EFFECT
        row = {**f, "value": current, "effect": effect}
        # A live field has no meaningful saved-versus-running gap: saving IS
        # applying. Claiming one would put a permanent amber "restart to pick
        # it up" under a row that already took effect.
        if effect != "live" and on_disk is not None and current != running:
            row["running_value"] = running
        if f["type"] == "choice":
            row["choices"] = _choices_for(f["path"])
        out.append(row)
    return out


def persist_config_value(block: str, leaf: str, value) -> str | None:
    """
    Set one key in config.json. Returns an error sentence, or None.

    Every writer goes through here (BP-1): the file is read fresh under
    _write_lock, so a concurrent save is not overwritten, and replaced
    atomically, so a reader never sees half a file.
    """
    with _write_lock:
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return f"Could not read config.json: {e}"

        raw.setdefault(block, {})
        if not isinstance(raw[block], dict):
            return f"config.json has no '{block}' block to write into."
        raw[block][leaf] = value

        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        try:
            tmp.write_text(json.dumps(raw, indent=2), encoding="utf-8")
            os.replace(tmp, CONFIG_PATH)
        except OSError as e:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            return f"Could not write config.json: {e}"
    return None


def set_config(path: str, value) -> dict:
    """
    Write one non-secret field into config.json. {ok, reason, value}.

    Reads the file fresh rather than editing the dict the app booted with, so
    a hand edit made while the app was running is not silently reverted by
    the panel saving something unrelated.
    """
    field = next((f for f in CONFIG_FIELDS if f["path"] == path), None)
    if field is None:
        return {"ok": False,
                "reason": (f"{path!r} is not a setting this panel writes. "
                           f"Secrets live in .env and are never written here.")}

    ok, clean, why = _coerce(field, value)
    if not ok:
        return {"ok": False, "reason": why}

    block, _, leaf = path.partition(".")
    err = persist_config_value(block, leaf, clean)
    if err:
        return {"ok": False, "reason": err}

    logger.info(f"Settings panel set {path} in config.json.")

    # HAND IT TO THE RUNNING PROCESS, for the fields that can take it now.
    # Reported honestly either way: a save that could not be applied says so
    # and asks for a restart, rather than leaving the panel claiming live.
    effect = field.get("effect", CONFIG_EFFECT)
    if effect == "live":
        apply = _LIVE_APPLY.get(path)
        if apply is None:
            effect = CONFIG_EFFECT
        else:
            try:
                applied, why = apply(path, clean)
            except Exception as e:               # pragma: no cover
                applied, why = False, str(e)
            if not applied:
                logger.warning(f"Saved {path} but could not apply it: {why}")
                return {"ok": True, "value": clean, "effect": "restart",
                        "reason": f"Saved to config.json, but this session "
                                  f"could not pick it up ({why}). Restart to "
                                  f"use it."}

    return {"ok": True, "value": clean, "effect": effect}


def _coerce(field: dict, value):
    """(ok, cleaned_value, reason). Refuses; never quietly rounds."""
    kind = field["type"]
    path = field["path"]

    if kind == "bool":
        if isinstance(value, bool):
            return True, value, ""
        return False, None, f"{path} is a yes/no setting."

    if kind in ("int", "float"):
        if value in (None, ""):
            if kind == "float":
                return True, None, ""       # blank latitude means 'not set'
            return False, None, f"{path} needs a number."
        try:
            num = int(value) if kind == "int" else float(value)
        except (TypeError, ValueError):
            return False, None, f"{path} needs a number."
        lo, hi = field.get("min"), field.get("max")
        if lo is not None and num < lo:
            return False, None, f"{path} must be {lo} or more."
        if hi is not None and num > hi:
            return False, None, f"{path} must be {hi} or less."
        return True, num, ""

    if kind == "choice":
        choices = _choices_for(path)
        if value in choices:
            return True, value, ""
        return False, None, f"{path} must be one of {', '.join(choices)}."

    # A URL is a text box with two things it must be. Separate from "text"
    # because blank is a legitimate value for a label and is not one for an
    # endpoint: every chat turn is posted at it.
    if kind == "url":
        text = "" if value is None else str(value).strip()
        if not text:
            return False, None, (f"{path} cannot be empty. It is the address "
                                 f"every question is sent to.")
        if not text.startswith(("http://", "https://")):
            return False, None, (f"{path} must start with http:// or "
                                 f"https://. Paste the provider's chat "
                                 f"endpoint URL.")
        if len(text) > 260 or any(ch in text for ch in (" ", "\n", "\r", "\x00")):
            return False, None, f"{path} does not look like a URL."
        return True, text, ""

    if kind == "text":
        if value is None:
            return True, None, ""
        text = str(value).strip()
        if len(text) > 260:
            return False, None, f"{path} is longer than 260 characters."
        if any(ch in text for ch in ("\n", "\r", "\x00")):
            return False, None, f"{path} cannot contain a line break."
        return True, (text or None), ""

    return False, None, f"{path} has an unknown type."


# THE NAME THE MODEL CALLS YOU

def _database_exists() -> bool:
    """
    Is there a database to read, without making one by asking?

    sqlite3.connect CREATES an empty file at a missing path. So on a fresh
    clone, merely OPENING this panel used to bring agental_sec.db into being,
    twice: once measuring its size and once reading the display name. An empty
    database is worse than no database, because it reads as a tool that looked
    and found nothing.

    47.9 item 4 wrote this up as fixed on 2026-09-04 and it was not in this
    file on 2026-09-05, same as the app key floor and config_fields. Found by
    tests/test_settings_panel.py section 14, which had been failing quietly.
    """
    try:
        from core import memory_engine as me
        return bool(me.DB_PATH) and os.path.exists(str(me.DB_PATH))
    except Exception:                            # pragma: no cover
        return False


def display_name() -> str:
    if not _database_exists():
        return ""
    try:
        from core import memory_engine as me
        return (me.get_preference(DISPLAY_NAME_PREF) or "").strip()
    except Exception:                            # pragma: no cover
        return ""


def set_display_name(name: str) -> dict:
    """
    Store what to call the operator. Blank clears it.

    Kept in user_preferences rather than config.json for one reason: it is a
    thing a person said about themselves, and user_preferences is already
    where that class of fact lives. It is not measured, it is not evidence,
    and nothing should ever reason from it.
    """
    clean = (name or "").strip()
    if len(clean) > DISPLAY_NAME_MAX:
        return {"ok": False,
                "reason": f"Keep it under {DISPLAY_NAME_MAX} characters."}
    if any(ch in clean for ch in ("\n", "\r", "\x00")):
        return {"ok": False, "reason": "A name cannot contain a line break."}
    try:
        from core import memory_engine as me
        me.set_preference(DISPLAY_NAME_PREF, clean)
    except Exception as e:
        return {"ok": False, "reason": f"Could not save it: {e}"}
    return {"ok": True, "value": clean}


# WHAT IS OFF, AND WHY. THE 2.3 HALF.
#
# Every collector's status() already returns a reason string written for a
# human. Nothing displayed them together, so a fresh install looked healthy
# and quiet while half of it was not running.
#
# THREE STATES, and they must not look alike:
#   ok       it is running and reading something
#   off      it is switched off or unconfigured. NOT a fault. A tool that
#            paints every unconfigured optional collector red teaches the
#            operator to ignore red.
#   problem  it is supposed to be working and is not. This is the one worth
#            a colour.
#
# Nothing in here raises. A status() that throws becomes a 'problem' row
# naming the exception, because a collector whose health check crashes is
# itself a finding, and swallowing it would put us back where 2.3 started.

def _row(area, title, state, detail, fix="", note=""):
    return {"area": area, "title": title, "state": state,
            "detail": detail, "fix": fix, "note": note}


def readiness(config: dict, modules: dict) -> list[dict]:
    rows = []
    rows += _model_rows()
    rows += _key_rows()
    rows += _privilege_rows()
    rows += _collector_rows(config, modules)
    rows += _map_rows()
    rows += _retention_rows()
    return rows


def _model_rows() -> list[dict]:
    try:
        from core import agent_loop
        st = agent_loop.model_status()
    except Exception as e:
        return [_row("Model", "Analyst backend", "problem",
                     f"Could not read the model state: {e}")]

    if st.get("available"):
        return [_row("Model", "Analyst backend", "ok",
                     f"{st.get('model') or 'model unset'}, "
                     f"{st.get('tool_count')} tools, "
                     f"{st.get('capability_label')}.")]
    return [_row("Model", "Analyst backend", "problem",
                 "There is no model API key, so the analyst cannot answer.",
                 "Set AGENTAL_API_KEY below. The endpoint it calls "
                 "is provider.api_url in config.json and can point at any "
                 "OpenAI-style or Anthropic Messages API.")]


def _key_rows() -> list[dict]:
    rows = []

    # HOW THE FILE ITSELF IS STORED. Put first because it is about every key
    # below it, and because "encrypted" and "plain" is exactly the kind of
    # thing that is true for a while and then quietly stops being true when
    # somebody edits .env by hand.
    #
    # THE PANEL WAS READING THE WRONG MODULE. Until 2026-09-25 this called
    # core.dpapi, the WINDOWS module (ctypes against crypt32.dll), which is
    # unavailable here by construction. So the row always said "Windows only.
    # Nothing to do on other systems." while core/secret_crypto -- Fernet,
    # and the module core/secret_store actually decrypts with -- was
    # available and working the whole time. A card telling the operator the owner's secrets are stored in plain
    # text, on a machine where they are encrypted, is the same class of wrong
    # as the two red rows above it.
    st = crypto.status()
    if st["enabled"]:
        rows.append(_row("Keys", "How .env is stored", "ok",
                         "Values written here are encrypted against this "
                         "machine and user. A key typed into the file by "
                         "hand still works."))
    else:
        rows.append(_row("Keys", "How .env is stored", "off", st["why"],
                         "On this platform that needs the 'cryptography' "
                         "package: pip install cryptography, and values "
                         "written here are encrypted for this machine and "
                         "user."))

    # A value this account cannot open is its own row. It is not a missing
    # key and it is not a bad key, and both of those readings send somebody
    # to rotate a credential that is fine.
    try:
        from core import secret_store
        for name, why in secret_store.decrypt_failures():
            rows.append(_row("Keys", f"{name} is unreadable", "problem", why,
                             "Re-enter it below on this machine and user."))
    except Exception as e:                          # pragma: no cover
        logger.debug(f"Could not read the decrypt failures: {e}")

    for k in key_catalog():
        if k["present"]:
            rows.append(_row("Keys", k["label"], "ok",
                             f"set, ending {k['last4']}."))
        elif k["required"]:
            rows.append(_row("Keys", k["label"], "problem",
                             k["without"], f"Set {k['env']} below."))
        else:
            rows.append(_row("Keys", k["label"], "off",
                             k["without"] or "not set.",
                             f"Set {k['env']} below."))
    return rows


# PRIVILEGED ACCESS, TODO 3.1
#
# The collector rows below say whether a module is running. These say whether
# the machine will LET it, which is a different question with a different
# answer, and today nothing asked it.
#
# It matters more after the privilege split. Once capture happens in a
# separate elevated helper, this process cannot tell by looking whether
# capture works. core/capabilities is the one place that knows, so this is
# where the card has to ask.
#
# Collapsed to one green row when everything is fine, one red row per problem
# when it is not. Eight always-visible rows saying "yes" trains somebody to
# stop reading the card, which is the same mistake as painting every
# unconfigured collector red.

_CAPABILITY_LABELS = {
    "capture":         "Packet capture",
    "firewall_write":  "Firewall rules",
    "firewall_read":   "Reading the firewall",
    "process_kill":    "Ending a process",
    "process_details": "Command lines for other accounts",
    "conn_table":      "Connection table",
}

# A FIX LINE IS ONLY EVER NEEDED WHERE THIS PLATFORM HAS THE THING.
#
# This map is why the card's permanent red rows existed, and the history is
# worth keeping: there used to be a Windows map ("pip install scapy, and
# install Npcap", "pip install pywin32") and a Linux one beside it, chosen by
# platform. The Linux entry for the Security channel said "add this user to the
# systemd-journal group, or start via ./scripts/run_elevated.sh" under a row
# that could never go green -- the capability was a Windows channel and did not
# exist here at all, and the row was red while the app WAS elevated.
#
# The capability is gone (core/capabilities.py, 2026-09-25), so the entry is
# gone with it. What is left is one map, for one platform, naming things this
# machine can actually grant.
_CAPABILITY_FIX = {
    "capture":      "grant it: sudo setcap cap_net_raw+ep $(readlink -f "
                    "$(which python3)), or add this user to the wireshark "
                    "group, or start via ./scripts/run_elevated.sh.",
}

# AND THE FIX LINE ON THE RIGHTS ROW ITSELF. It was the Windows one ("Start it
# from an Administrator prompt") until 2026-09-21, which is not a thing that
# exists on this platform and sent the reader after a prompt they cannot open.
_ELEVATION_FIX = {
    "posix": "start it via ./scripts/run_elevated.sh, which asks for the "
             "password, keeps HOME so files do not land in /root, and hands "
             "ownership back when the run ends.",
}


def _privilege_rows() -> list[dict]:
    rows = []

    # WHICH REGISTER, AND WHY THERE IS ONLY ONE NOW. Corrected 2026-09-21,
    # finished 2026-09-25.
    #
    # This module used to read `core.privilege` unconditionally, and on this
    # host that file was the WINDOWS register: byte-identical to the Windows
    # tree, listing Windows module names and Windows consequences. It was
    # repointed at core.privilege_linux, and this round the Windows file left
    # the tree entirely (agental_sec_win32_reference/core/privilege.py), so
    # there is nothing left to dispatch between.
    #
    # MEASURED before that first fix, by calling _privilege_rows() on this host
    # and reading the first row back:
    #
    #   'Not elevated. 3 module(s) unavailable, 1 degraded, ...'
    #   fix: 'Start it from an Administrator prompt.'
    #
    # The Linux register answers the same question with different numbers -- 2
    # unavailable, 4 degraded -- and there is no such thing as an
    # "Administrator prompt" here.
    from core import privilege_linux as _reg
    _fix_map = _CAPABILITY_FIX

    try:
        from core import capabilities
    except Exception as e:                          # pragma: no cover
        return [_row("Privileged access", "Capability check", "problem",
                     f"could not be read: {type(e).__name__}: {e}")]

    # WHAT THIS RUN HAS.
    #
    # ONE ROW, ONE ANSWER, and no dispatch. This row used to have a second
    # branch for the privilege split -- an unelevated app with a helper process
    # holding the rights -- and under it the card printed a contradiction on one
    # screen, 2026-09-08, first boot of step 4:
    #
    #   Administrator rights   RED    Not elevated, 3 modules unavailable.
    #                                 fix: Start it from an Administrator prompt.
    #   Capabilities           GREEN  all 8 available, running helper.
    #
    # That design is Windows (the helper, its protocol and its client are in
    # agental_sec_win32_reference/) and it was never what this platform does:
    # here the rights question is answered by CAPABILITIES on the binary or by
    # the launcher that asks for a password, so there is no second process for
    # this row to describe. `mode` is gone from core/capabilities.py.
    try:
        p = _reg.posture()
        state = {True: "ok", False: "problem", None: "off"}[p["elevated"]]
        rows.append(_row("Privileged access", "Administrator rights", state,
                         p["summary"],
                         "" if p["elevated"] else
                         _ELEVATION_FIX.get("posix", "")))
    except Exception as e:                          # pragma: no cover
        rows.append(_row("Privileged access", "Administrator rights", "problem",
                         f"could not be read: {type(e).__name__}: {e}"))

    # WHAT THE MACHINE WILL ALLOW, per capability.
    try:
        avail = capabilities.get().availability()
    except Exception as e:                          # pragma: no cover
        rows.append(_row("Privileged access", "Capability check", "problem",
                         f"could not be read: {type(e).__name__}: {e}"))
        return rows

    broken = {k: v for k, v in avail.items() if not v.get("available")}
    narrowed = {k: v for k, v in avail.items()
                if v.get("available") and v.get("limited")}

    # EVERY ROW HERE IS NOW A CAPABILITY THIS PLATFORM ACTUALLY HAS. 2026-09-25.
    #
    # The card used to print TWO PERMANENT ROWS that could never go green:
    #
    #   [problem] Privileged access / Defender detections
    #             Defender is a Windows component and does not exist on Linux
    #   [problem] Privileged access / Windows Security channel
    #             the Windows event channels do not exist on Linux; journald is
    #             the equivalent and it is reported under event_monitor
    #             fix: add this user to the systemd-journal group, or start via
    #                  ./scripts/run_elevated.sh
    #
    # MEASURED on this host before they were removed: 40 samples of
    # /api/settings over 13 minutes put both at [problem] in every single
    # sample, and the second one -- which named the event monitor, a sensor that
    # was working perfectly at the time -- is what made a reader conclude the
    # event monitor was the broken thing. That is the defect this round closes.
    #
    # The previous round split these out into an amber "not a fault" state and
    # kept them on the page, on the argument that a platform absence should stay
    # REPORTED. That argument holds for a capability this platform is supposed
    # to expose; it does not hold for one whose only possible value is "does
    # not exist here", painted on a card every time it loads, in words that name
    # a WORKING sensor as the explanation. The owner's ruling supersedes it:
    # Windows-only code does not belong in the Linux build. So the capability
    # left core/capabilities.py, the row left this function, and there is no
    # `not_on_this_platform` branch left to render.
    if not broken and not narrowed:
        rows.append(_row("Privileged access", "Capabilities", "ok",
                         f"all {len(avail)} available, "
                         f"running in-process."))
        return rows

    for name, row in sorted(broken.items()):
        # A fix line is only shown where the capability is ABSENT. The one
        # entry in _fix_map is a capability this platform HAS and is being held
        # back (capture: a library or a right). If a future gap arrives with no
        # fix, an empty fix is the honest thing to draw: "fix: " followed by
        # nothing is worse than no line at all. A red row with nothing under it
        # reads as a rights problem by default, and that reading is the RIGHT
        # one for every row that reaches this loop.
        fix = _fix_map.get(name, "")
        rows.append(_row("Privileged access",
                         _CAPABILITY_LABELS.get(name, name), "problem",
                         row.get("why_not") or "unavailable.", fix))

    # Amber, not red. These are working, on a smaller set of things. Painting
    # them red next to a capture that is genuinely dead would flatten the
    # difference between "narrower than usual" and "not happening at all".
    for name, row in sorted(narrowed.items()):
        rows.append(_row("Privileged access",
                         _CAPABILITY_LABELS.get(name, name), "off",
                         f"working, {row['limited']}."))

    ok = len(avail) - len(broken) - len(narrowed)
    if ok:
        rows.append(_row("Privileged access", "The rest", "ok",
                         f"{ok} of {len(avail)} fully available."))
    return rows


def _collector_rows(config: dict, modules: dict) -> list[dict]:
    rows = []

    # The two collectors whose status is a module-level function taking the
    # config, rather than a loaded object. Both are off by default and both
    # already write their own reason.
    for name, label, fn in _config_status_collectors():
        try:
            st = fn(config or {})
        except Exception as e:
            rows.append(_row("Collectors", label, "problem",
                             f"status() raised {type(e).__name__}: {e}"))
            continue
        if st.get("available"):
            rows.append(_row("Collectors", label, "ok", "configured and usable."))
        elif name == "router_monitor" and _gateway_on(config):
            # Off is correct here, so it is not drawn as a warning.
            rows.append(_row("Collectors", label, "ok",
                             "not needed: the router agent (gateway) reads "
                             "the router's leases and neighbour table over "
                             "SSH. This SNMP collector is for routers "
                             "without that agent."))
        else:
            rows.append(_row("Collectors", label, "off",
                             st.get("reason") or "not configured."))

    for name, mod in (modules or {}).items():
        rows.append(_module_row(name, mod))
    return rows


def _gateway_on(config: dict) -> bool:
    block = (config or {}).get("gateway") or {}
    return bool(block.get("enabled") and block.get("host"))


def _config_status_collectors():
    out = []
    try:
        from tools import dns_monitor
        out.append(("dns_monitor", "Resolver ingest", dns_monitor.status))
    except Exception:                            # pragma: no cover
        pass
    try:
        from tools import router_monitor
        out.append(("router_monitor", "Router tables", router_monitor.status))
    except Exception:                            # pragma: no cover
        pass
    return out


def _backlog_detail(backlog) -> str:
    """
    Records read and not yet written, as one sentence. Empty when there is
    no backlog, or when the shape is something this cannot read.

    BOTH SHAPES. This used to test isinstance(backlog, int) and nothing else,
    and event_monitor, the one module in the tree that publishes a backlog,
    publishes a dict of channel to remaining. So the check written after the
    "alive is not the same as working" lesson never fired once on the module
    it was written for: a stuck drain read 'running.' here while the
    dashboard tile beside it said 31,000 behind.

    bool is excluded before int on purpose. True is an int in Python and
    would otherwise print as one record behind.
    """
    if isinstance(backlog, bool):
        return ""
    if isinstance(backlog, int):
        return f"{backlog} records read but not yet stored." if backlog > 0 else ""
    if isinstance(backlog, dict):
        behind = [(str(k), int(v)) for k, v in backlog.items()
                  if isinstance(v, (int, float)) and not isinstance(v, bool)
                  and v > 0]
        if not behind:
            return ""
        behind.sort(key=lambda kv: -kv[1])
        return ("read but not yet stored: "
                + ", ".join(f"{k} {v}" for k, v in behind) + ".")
    return ""


def _module_row(name: str, mod) -> dict:
    """
    One loaded module, normalised.

    The shapes differ on purpose across the codebase, packet_sniffer reports
    running, linux_monitor separates running from reachable, enrichment
    reports ready, so this reads whichever of them is present rather than
    insisting they agree. Making them agree would be a refactor of fifteen
    files to serve one panel.

    THE COLLECTOR'S NOTE RIDES EVERY ROW. It used to ride exactly one, the
    not-answering branch, and the comment in that branch claimed the healthy
    rows had already been fixed. They had not: _row did not even have a note
    field, and the page has been rendering r.note, a key that could never
    exist, ever since. So web_search could report that its last five searches
    did not resolve and this page printed 'running.', which is the whole
    lesson happening on the one page that exists to answer what is not
    working.
    """
    label = name.replace("_", " ")
    if mod is None:
        return _row("Collectors", label, "off",
                    "not loaded. Either switched off in config.json or it "
                    "failed to import at boot, and the log says which.")
    if not hasattr(mod, "status"):
        # 'loaded.' on its own reads as a clean bill of health and is not
        # one. It means the import worked and nothing has been checked.
        return _row("Collectors", label, "ok",
                    "loaded. This module publishes no status(), so nothing "
                    "here has been checked beyond it being importable.")

    try:
        st = mod.status()
    except Exception as e:
        return _row("Collectors", label, "problem",
                    f"status() raised {type(e).__name__}: {e}")

    if not isinstance(st, dict):
        return _row("Collectors", label, "ok", str(st))

    # The collector's own sentence, carried through whatever verdict this
    # function reaches. Read once here so every return below can pass it.
    note = str(st.get("note") or "").strip()

    # A MODULE THAT KNOWS IT IS BROKEN, and says so in its own words.
    # Checked before the alive flags, because a worker whose thread has died
    # still leaves an object behind with a True next to its name. rollup
    # engine is the first user of this.
    fault = str(st.get("fault") or "").strip()
    if fault:
        return _row("Collectors", label, "problem", fault,
                    str(st.get("fix") or ""), note)

    # A sensor that cannot see has to say so, or its silence reads as a quiet
    # network. reachable is checked before running for exactly that reason.
    #
    # THIS BRANCH USED TO SAY TWO WORDS AND NOTHING ELSE.
    #
    # "not answering." That is all it said, while the collector underneath it
    # was holding the error, the number of failed polls in a row, and its own
    # sentence about what the silence means. Somebody looking at that row
    # cannot tell a host that is off from a host that is refusing us from a
    # host we are about to retry in ninety seconds, so they restart the app to
    # find out, which is the one action that hides the answer.
    if "reachable" in st and st.get("reachable") is False:
        parts = ["not answering"]

        fails = st.get("consecutive_failures")
        if isinstance(fails, int) and fails > 1:
            parts.append(f"{fails} polls in a row have failed")

        age = st.get("last_success_age_seconds")
        if age:
            parts.append(f"last worked {int(age // 60)} minutes ago")

        detail = ", ".join(parts) + "."

        # The collector's own explanation, whichever of the two it wrote.
        # last_error is the specific one, note is the wider sentence.
        reason = st.get("last_error") or st.get("note")
        if reason:
            detail += f" {str(reason).strip().rstrip('.')}."

        # Something to wait for. Without it, waiting and being broken look
        # identical, and the card already warns that it is a cached read.
        nxt = st.get("next_poll_in_seconds")
        interval = st.get("poll_interval_seconds")
        if isinstance(nxt, int):
            detail += (" Trying again now." if nxt <= 0
                       else f" Next try in about {nxt} seconds.")
        elif isinstance(interval, int):
            detail += f" Retries every {interval} seconds."

        return _row("Collectors", label, "problem", detail,
                    "Refresh after the next try, this page is a cached read."
                    if (isinstance(nxt, int) or isinstance(interval, int))
                    else "",
                    # Not twice. If last_error was missing, the note is
                    # already the last sentence of detail above.
                    note if st.get("last_error") else "")

    # ALIVE AND CANNOT SEE. Checked before running for the same reason
    # reachable is: a module reporting itself as running while the machine
    # refuses it the thing it exists to do is the worst row on this page.
    if st.get("blind"):
        return _row("Collectors", label, "problem",
                    f"running, but blind. {st.get('blind_reason') or 'reason not recorded'}.",
                    "See Privileged access above.", note)

    # ALIVE AND THROWING ON EVERY POLL IS NOT "running.". 2026-09-25.
    #
    # adapters._BaseAdapter counts consecutive failures and keeps the last
    # error, its status() publishes both, and this row read NEITHER unless the
    # module also published `reachable` -- which most of the Linux modules do
    # not. MEASURED with a module reporting 7 consecutive failures: this row
    # read [ok] "running.", identical to a healthy control, and the model was
    # told nothing either. The app's own log already holds one real instance
    # (local_integrity, 2026-09-22). A sensor that is up and measuring nothing
    # has to say so, on the page and to the model, or its silence reads as a
    # quiet machine -- which is the sentence this whole file exists for.
    #
    # CHECKED THIS EARLY ON PURPOSE: everything below it reads figures the
    # module published on its last SUCCESSFUL poll, and the counter is the
    # only live fact on the dict. Three failed polls in a row means the
    # backlog beside it is three polls old, so a stale "catching up" must not
    # get to speak first. Same precedence as blind, for the same reason.
    #
    # THE FLOOR IS IMPORTED, not restated: core/sensor_health declares it once
    # and the model path reads the same number, so the two surfaces cannot
    # drift apart. Three is the figure this tree already uses for a monitor
    # that is loaded, callable and getting nowhere.
    fails = st.get("consecutive_failures")
    alive_now = st.get("running", st.get("ready", st.get("available")))
    if (isinstance(fails, int) and not isinstance(fails, bool)
            and fails >= _FAILING_POLLS_FLOOR and alive_now is not False):
        return _row("Collectors", label, "problem",
                    f"last {fails} poll(s) in a row FAILED "
                    f"({st.get('last_error') or 'no reason recorded'}), so "
                    f"nothing has been measured by it since the first of "
                    f"them.",
                    "Refresh after the next poll, this page is a cached read.",
                    note)

    # A MODULE THAT ANSWERS IN `state`, AND SAYS WHETHER IT COULD MEASURE.
    #
    # vpn_state is the one module here whose status() carries no alive flag:
    # it reports state in connected / disconnected / unknown and a separate
    # `measured` boolean. Without this branch it fell all the way through to
    # the bare word 'loaded.', measured live on 2026-09-21, which means the
    # row could not show the one distinction its own docstring exists for:
    # "unknown" is WE COULD NOT LOOK and it must never read as a quiet no.
    #
    # Narrow on purpose. It needs a `state` string AND a `measured` boolean,
    # which is a shape no other module in the tree publishes.
    if isinstance(st.get("state"), str) and isinstance(st.get("measured"), bool):
        state = st["state"].strip().lower()
        if not st["measured"] or state == "unknown":
            return _row("Collectors", label, "problem",
                        f"could not look: {st.get('note') or 'reason not recorded'}.",
                        "See Privileged access above.", note)
        if state == "connected":
            return _row("Collectors", label, "ok",
                        (st.get("note") or "connected.").strip(), "", note)
        if state == "disconnected":
            return _row("Collectors", label, "ok",
                        (st.get("note") or "No tunnel interface is up.").strip(),
                        "", note)
        return _row("Collectors", label, "ok", state, "", note)

    backlog = _backlog_detail(st.get("backlog"))
    if backlog:
        # DRAINING IS NOT BROKEN. Every boot starts with a backlog, and this
        # row used to paint that red, so a normal two minute catch up read as
        # a dead sensor. Red now needs proof the drain is stuck. A module that
        # does not publish 'stalled' at all stays red, because then nobody has
        # checked, and "I could not tell" must not read as "it is fine".
        #
        # AND IT MEANS SOMETHING NOW, 2026-09-23. Until the cursor landed this
        # figure could only ever be zero, because the sensor read a 200-entry
        # window every poll and every source that read successfully reported
        # "nothing behind". What is behind now is real unread records, and a
        # source whose last read FAILED is named here through `stalled` rather
        # than reading as quiet.
        stalled = st.get("stalled")
        if not isinstance(stalled, (list, tuple, set)):
            return _row("Collectors", label, "problem", backlog, "", note)
        if stalled:
            detail = (backlog + " NOT going down: "
                      + ", ".join(str(c) for c in sorted(stalled)) + ".")
            unreadable = st.get("unreadable")
            if isinstance(unreadable, dict) and unreadable.get(
                    next(iter(sorted(stalled)), ""), None):
                detail += " " + str(unreadable[sorted(stalled)[0]])
            return _row("Collectors", label, "problem", detail,
                        "Look at the log for Event Monitor lines.", note)
        detail = "catching up, " + backlog
        if st.get("backlog_is_a_floor"):
            detail += (" (at least: the unread tail is long enough that the "
                       "count stopped at its bound)")
        return _row("Collectors", label, "busy", detail, "", note)

    # A SOURCE THAT WAS REFUSED IS NOT A SOURCE THAT WAS QUIET. EM-6.
    #
    # Checked before the healthy paths and after the backlog, because a
    # refused read puts the source in `stalled` AND in `unreadable` and the
    # backlog branch above is the more specific sentence. With no backlog, a
    # failure here is the whole story: every failure path in the reader used
    # to be a logger.debug, so "the file had no new lines" and "tail refused"
    # produced the same empty list and this page could not tell them apart.
    unreadable = st.get("unreadable")
    if isinstance(unreadable, dict) and unreadable:
        names = sorted(unreadable)
        return _row(
            "Collectors", label, "problem",
            ("could not read " + ", ".join(names) + ". "
             + str(unreadable[names[0]])),
            "A refused read is not a quiet log: anything written while it is "
            "refused is not in the events table.", note)

    # WHAT WAS RAISED AND WHAT WAS WRITTEN. EM-2, ON THIS PAGE.
    #
    # The audit's headline was that this sensor raised 134 findings in one
    # live poll, converted four event_types, stored NONE, and told nobody:
    # the log said "0 finding(s)" 119 times and the readiness row said
    # nothing at all. A count of raised-against-written is the difference
    # between a sensor that is quiet and a sensor whose findings have nowhere
    # to go.
    raised = st.get("findings_raised")
    written = st.get("findings_written")
    dropped = st.get("findings_events_only") or 0
    # THE TWO EXPLAINED REMAINDERS, 2026-09-25. Both are decisions the operator
    # made: an entity the owner dismissed, and a suppression rule that declined the
    # write. Neither is a fault and neither is unexplained, and the branch
    # below used to paint BOTH of them red with a sentence saying the gap had
    # no explanation -- MEASURED by driving the shipped adapter with the
    # entity dismissed: "last poll raised 1 finding(s) and only 0 were written,
    # while 0 are event types with no rule. The gap is unexplained and the log
    # names the reason." The dismissal WAS the explanation. A red row that
    # blames the sensor for the operator's own decision is the same class as
    # the two rows this round's other defect is about.
    dismissed = st.get("findings_dismissed") or 0
    suppressed = st.get("findings_suppressed") or 0
    if isinstance(raised, int) and isinstance(written, int):
        if raised and written == 0 and dropped + dismissed + suppressed >= raised:
            # Everything raised has a named destination. Amber: working, and
            # nothing on the findings page was expected from this poll.
            bits = []
            if dropped:
                bits.append(f"{dropped} are event types with no registered "
                            f"detection id, so they are stored as EVENTS "
                            f"only, by decision")
            if dismissed:
                bits.append(f"{dismissed} are about entities you dismissed, "
                            f"so they are not written again by design")
            if suppressed:
                bits.append(f"{suppressed} were declined by a suppression "
                            f"rule, which says so on the row it was declared")
            return _row(
                "Collectors", label, "busy",
                (f"last poll raised {raised} security-relevant event(s) and "
                 f"wrote 0 findings: " + "; ".join(bits) + ". Nothing is lost "
                 f"and nothing on the findings page was expected."),
                "See the Detections tab for which rules exist.", note)
        if raised and written + dropped + dismissed + suppressed < raised:
            unexplained = raised - written - dropped - dismissed - suppressed
            return _row(
                "Collectors", label, "problem",
                (f"last poll raised {raised} finding(s) and only {written} "
                 f"were written: {dropped} are event types with no rule, "
                 f"{dismissed} are about dismissed entities and {suppressed} "
                 f"were declined by a suppression rule, which leaves "
                 f"{unexplained} UNEXPLAINED. The log names the reason."),
                "", note)

    # LOADED, CALLABLE AND GETTING NOWHERE. web_search is the case: ready is
    # True for as long as the object exists, and whether anything it asks
    # actually answers lives in this counter. One unresolved search is
    # normal and gets no colour, which is why the floor is three, the same
    # figure the dashboard tile uses.
    unresolved = st.get("consecutive_unresolved")
    if isinstance(unresolved, int) and not isinstance(unresolved, bool) \
            and unresolved >= 3:
        return _row("Collectors", label, "problem",
                    f"loaded and callable, but the last {unresolved} "
                    f"attempts in a row did not resolve"
                    + (f" ({st.get('last_failure_kind')})."
                       if st.get("last_failure_kind") else "."),
                    "", note)

    alive = st.get("running", st.get("ready", st.get("available")))
    if alive is False:
        return _row("Collectors", label, "off",
                    st.get("reason") or "not running.", "", note)
    if alive is None:
        return _row("Collectors", label, "ok", "loaded.", "", note)

    # RUNNING, AND NOTHING MEASURED YET. Green, because nothing is wrong,
    # but it does not get to say the bare word 'running' as though the host
    # had answered. reachable is three-valued and None means we have not
    # tried, which is not the same claim as reachable.
    if "reachable" in st and st.get("reachable") is None:
        return _row("Collectors", label, "ok",
                    "running. It has not reached the host yet this run, so "
                    "nothing has been measured either way.", "", note)

    return _row("Collectors", label, "ok", "running.", "", note)


def _map_rows() -> list[dict]:
    try:
        from core import geoip
        st = geoip.status()
    except Exception as e:
        return [_row("Threat map", "Geolocation database", "problem", str(e))]
    if st.get("ready"):
        return [_row("Threat map", "Geolocation database", "ok",
                     f"loaded, {st.get('cached', 0)} lookups cached.")]
    return [_row("Threat map", "Geolocation database", "off",
                 st.get("status") or "not loaded.",
                 "python scripts/fetch_geoip.py")]


def _retention_rows() -> list[dict]:
    # Before anything opens it. See _database_exists.
    if not _database_exists():
        return [_row("Storage", "Database size", "off",
                     "No database yet. It is created the first time the app "
                     "runs, and this page does not create one by looking.")]
    try:
        from core import memory_engine as me
        from core import retention
        st = retention.status(me.DB_PATH)
    except Exception as e:
        return [_row("Storage", "Database size", "problem",
                     f"Could not measure it: {e}")]
    if not st.get("configured"):
        return [_row("Storage", "Database size", "off",
                     f"{st.get('size_human')} on disk, no budget set, so "
                     f"nothing will ever be pruned.",
                     "Pick a budget on the Review page.")]
    if st.get("over_trigger"):
        return [_row("Storage", "Database size", "problem",
                     f"{st.get('size_human')} is past the "
                     f"{st.get('trigger_human')} budget. The oldest whole "
                     f"capture runs go at the next clean shutdown.")]
    return [_row("Storage", "Database size", "ok",
                 f"{st.get('size_human')} of {st.get('trigger_human')}, "
                 f"{st.get('headroom_human')} spare.")]


def summary(rows: list[dict]) -> dict:
    """Counts for the headline. 'off' is not added to 'problem' anywhere."""
    return {
        "ok":      sum(1 for r in rows if r["state"] == "ok"),
        "off":     sum(1 for r in rows if r["state"] == "off"),
        "problem": sum(1 for r in rows if r["state"] == "problem"),
        # Working and moving, like a log catching up after boot. Amber on
        # the page, never in the red badge.
        "busy":    sum(1 for r in rows if r["state"] == "busy"),
    }
