# api/server.py
# AgentalSec V2, Flask app factory

import logging

from flask import Flask
from flask_cors import CORS

logger = logging.getLogger(__name__)

# Names a browser can legitimately use to reach a loopback-bound server.
# Anything else in the Host header means the request was aimed somewhere
# else and re-pointed here, see the rebinding guard in api/routes.py.
LOOPBACK_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}

# Biggest request body this server will read, in bytes. Default 1 MB.
#
# Added 2026-09-13. The chat route had a 2000 character check on the MESSAGE
# and nothing on the BODY, and those are not the same control. Flask parses
# the whole JSON body before any route code runs, so the character check
# could only ever fire after the work was already done. A 50 MB body was
# parsed in full and then politely told it was too long.
#
# This one is enforced by Werkzeug while the body is still being read, which
# is the only place a size limit does anything. Config: flask.max_body_mb.
DEFAULT_MAX_BODY_BYTES = 1 * 1024 * 1024


def max_body_bytes(config: dict) -> int:
    """
    Request body ceiling in bytes, from flask.max_body_mb.

    Clamped 1 to 64 MB. A zero or a negative here would mean "no limit" to
    Werkzeug, which is the opposite of what someone setting a limit meant, so
    an unusable value falls back to the default and says so rather than
    quietly turning the control off.
    """
    flask_cfg = config.get("flask") or {}
    raw = flask_cfg.get("max_body_mb")
    if raw is None:
        return DEFAULT_MAX_BODY_BYTES
    try:
        mb = float(raw)
    except (TypeError, ValueError):
        logger.warning(f"flask.max_body_mb is not a number ({raw!r}), "
                       f"using the 1 MB default.")
        return DEFAULT_MAX_BODY_BYTES
    if not 1 <= mb <= 64:
        logger.warning(f"flask.max_body_mb is {mb}, which is outside 1 to 64, "
                       f"using the 1 MB default.")
        return DEFAULT_MAX_BODY_BYTES
    return int(mb * 1024 * 1024)


def allowed_hosts(config: dict) -> set:
    """
    The Host header values this server will answer to.

    Derived from the bind address rather than hardcoded, because AgentalSec
    is meant to run on networks it has never seen: someone binding to a LAN
    address to reach the dashboard from a laptop is a normal thing to do and
    must not need a code change.

    "flask": {
        "host": "127.0.0.1",
        "port": 5000,
        "allowed_hosts": []      # extra names; [] means derive them
    }

    Turning the check off entirely is still possible, because someone behind a
    reverse proxy that already validates Host has a real reason to. It now
    takes TWO settings that agree, not one:

    "flask": {
        "allowed_hosts": null,
        "host_check_disabled_behind_proxy": true
    }

    One setting was not enough. `allowed_hosts: null` is reachable by
    accident, a JSON template with a null in it, a config generator that
    writes null for "unset", an editor that helpfully empties a field, and
    the Host check is the only control that makes embedding the dashboard's
    API key in the page safe. A silent failure whose consequence is the key
    should not be one keystroke away from the default. The second flag has no
    other purpose and no plausible accidental value, so setting it is a
    statement of intent rather than a side effect.

    null WITHOUT the flag is treated as a mistake: the check stays on, derived
    as normal, and the reason is logged at error level.
    """
    flask_cfg = config.get("flask") or {}

    if "allowed_hosts" in flask_cfg and flask_cfg["allowed_hosts"] is None:
        # `is True` on purpose. A truthy string or a 1 is exactly the kind of
        # near-miss this branch exists to refuse.
        if flask_cfg.get("host_check_disabled_behind_proxy") is True:
            logger.warning(
                "flask.allowed_hosts is null and "
                "flask.host_check_disabled_behind_proxy is true, Host header "
                "checking is OFF. The dashboard's API key is embedded in the "
                "page, so a rebinding attack can read it. This is only safe "
                "behind a proxy that validates Host itself."
            )
            return set()

        logger.error(
            "flask.allowed_hosts is null but "
            "flask.host_check_disabled_behind_proxy is not true, so Host "
            "header checking stays ON and the names below are derived as "
            "usual. Disabling the check needs both settings. If the dashboard "
            "returns 403, add the name you browse to under allowed_hosts "
            "rather than turning the check off."
        )

    hosts = set(LOOPBACK_NAMES)

    bind = str(flask_cfg.get("host", "127.0.0.1")).strip().lower()
    # 0.0.0.0 / :: are bind wildcards, not names a client ever sends.
    if bind and bind not in {"0.0.0.0", "::", ""}:
        hosts.add(bind)

    for extra in (flask_cfg.get("allowed_hosts") or []):
        name = str(extra).strip().lower().rstrip(".")
        if name:
            hosts.add(name)

    if bind in {"0.0.0.0", "::"} and not (flask_cfg.get("allowed_hosts") or []):
        logger.warning(
            f"Flask binds to {bind} but flask.allowed_hosts is empty, so only "
            f"localhost names are accepted. Add the address or hostname you "
            f"actually browse to, or the dashboard will return 403."
        )

    return hosts


def create_app(config: dict, modules: dict, session_id: str, api_key: str = "") -> Flask:
    app = Flask(__name__, static_folder="../ui", template_folder="../ui")

    # CORS stays for defence in depth, but it was never the thing protecting
    # the key: it governs cross-origin reads, and a rebinding attack is
    # same-origin by construction. The Host check in routes.py is what covers
    # that case. Origins are derived so a non-default port still works.
    flask_cfg = config.get("flask") or {}
    port = flask_cfg.get("port", 5000)
    origins = [f"http://127.0.0.1:{port}", f"http://localhost:{port}"]
    CORS(app, resources={r"/api/*": {"origins": origins}})

    # Enforced by Werkzeug as the body is read, before any route sees it.
    app.config["MAX_CONTENT_LENGTH"]    = max_body_bytes(config)

    app.config["AGENTAL_CONFIG"]        = config
    app.config["AGENTAL_MODULES"]       = modules
    app.config["AGENTAL_SESSION_ID"]    = session_id
    app.config["AGENTAL_ALLOWED_HOSTS"] = allowed_hosts(config)

    # Passed in from main.py via core.secret_store. No config.json fallback:
    # secrets do not live there, and a fallback that reads one is how the
    # un-migrated copy survives unnoticed.
    app.config["AGENTAL_API_KEY"] = api_key

    if not api_key:
        logger.error(
            "No API key available, every /api/* call will return 401. "
            "Set AGENTAL_APP_API_KEY in .env."
        )

    from api.routes import register_routes
    register_routes(app)

    return app
