# api/module_routes.py
# Routes for add-on modules. The tab's routes take the dashboard key like the
# rest of /api; the feed routes take only the token a module got for its run.
# They only read, except decide, open only to a module whose manifest asks.

import logging
import re
from pathlib import Path

from flask import Response, jsonify, request

from core import module_host

logger = logging.getLogger(__name__)

_NAME = re.compile(r"^[a-z][a-z0-9_]{1,30}$")
_SUBPATH = re.compile(r"^[A-Za-z0-9_/\-]{1,120}$")


def register(app, require_api_key, record_failure):

    def _known(name):
        return bool(_NAME.match(name or "")) and name in module_host.discover()

    @app.route("/api/module-host/list")
    @require_api_key
    def module_list():
        return jsonify({"modules": module_host.list_modules()})

    @app.route("/api/module-host/<name>/switch", methods=["POST"])
    @require_api_key
    def module_switch(name):
        if not _known(name):
            return jsonify({"ok": False, "reason": "No such module."}), 404
        body = request.get_json(silent=True) or {}
        on = body.get("on")
        if not isinstance(on, bool):
            return jsonify({"ok": False, "reason": "on must be true or false."}), 400
        result = module_host.switch(name, on)
        logger.info(f"Module {name} switched {'on' if on else 'off'} from the tab.")
        return jsonify({**result, "module": module_host.describe(name)}), \
            (200 if result.get("ok") else 400)

    @app.route("/api/module-host/<name>/secret", methods=["POST"])
    @require_api_key
    def module_secret(name):
        if not _known(name):
            return jsonify({"ok": False, "reason": "No such module."}), 404
        body = request.get_json(silent=True) or {}
        env, value = body.get("env"), body.get("value", "")
        if not isinstance(env, str) or not isinstance(value, str):
            return jsonify({"ok": False, "reason": "env and value must be text."}), 400
        result = module_host.set_secret(name, env, value)
        return jsonify(result), (200 if result.get("ok") else 400)

    @app.route("/api/module-host/<name>/call/<path:sub>", methods=["GET", "POST"])
    @require_api_key
    def module_call(name, sub):
        if not _known(name) or not _SUBPATH.match(sub):
            return jsonify({"error": "No such module route."}), 404
        path = "/" + sub
        if request.query_string:
            path += "?" + request.query_string.decode("ascii", "replace")
        body = request.get_json(silent=True) if request.method == "POST" else None
        status, data = module_host.call(name, request.method, path, body)
        return jsonify(data), status

    # The module's page code, a static file like the dashboard page itself.
    # A script tag cannot send the session header, so this holds nothing
    # that needs one; the data comes through the routes above.
    @app.route("/module-ui/<name>/ui.js")
    def module_ui(name):
        if not _known(name):
            return jsonify({"error": "No such module."}), 404
        path = module_host.ui_path(name)
        if not path:
            return jsonify({"error": "This module has no page."}), 404
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError:
            return jsonify({"error": "The module page could not be read."}), 500
        resp = Response(text, mimetype="application/javascript")
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    def _feed_caller():
        token = request.headers.get(module_host.TOKEN_HEADER, "")
        name = module_host.module_for_token(token) if token else None
        if not name and token:
            record_failure(request.remote_addr or "unknown")
        return name

    def _int(name, default=None):
        raw = request.args.get(name)
        try:
            return int(raw) if raw not in (None, "") else default
        except ValueError:
            return default

    @app.route("/api/module-feed/alerts")
    def module_feed_alerts():
        if not _feed_caller():
            return jsonify({"error": "Unauthorized"}), 401
        from core import module_feed
        since = request.args.get("since") or None
        if since and not re.match(r"^[0-9T:\- .+]{10,32}$", since):
            since = None
        return jsonify(module_feed.alerts(
            after_id=_int("after"), since=since,
            floor=request.args.get("floor", "high"), limit=_int("limit", 50)))

    @app.route("/api/module-feed/status")
    def module_feed_status():
        if not _feed_caller():
            return jsonify({"error": "Unauthorized"}), 401
        from core import module_feed
        return jsonify(module_feed.status())

    @app.route("/api/module-feed/pending")
    def module_feed_pending():
        if not _feed_caller():
            return jsonify({"error": "Unauthorized"}), 401
        from core import module_feed
        return jsonify(module_feed.pending(limit=_int("limit", 10)))

    @app.route("/api/module-feed/incident/<int:incident_id>")
    def module_feed_incident(incident_id):
        if not _feed_caller():
            return jsonify({"error": "Unauthorized"}), 401
        from core import module_feed
        return jsonify(module_feed.incident(incident_id))

    @app.route("/api/module-feed/decide", methods=["POST"])
    def module_feed_decide():
        name = _feed_caller()
        if not name:
            return jsonify({"error": "Unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        kind = body.get("kind")
        if not isinstance(kind, str) or not module_host.may_decide(name, kind):
            logger.warning(f"Module {name} asked to decide {kind!r}, which its "
                           f"manifest does not allow.")
            return jsonify({"ok": False, "detail": "This module may not decide that."}), 403
        ref, choice = body.get("ref"), body.get("choice")
        person, text = body.get("person"), body.get("text")
        if not isinstance(ref, (int, str)) or not isinstance(choice, str) \
                or not isinstance(person, str) or not isinstance(text, (str, type(None))):
            return jsonify({"ok": False, "detail": "Bad request."}), 400
        from core import module_feed
        out = module_feed.decide(kind, ref, choice, person, text)
        logger.info(f"Module {name}: {person[:40]!r} decided {kind} {str(ref)[:40]} "
                    f"{choice[:20]}: {'done' if out.get('ok') else 'refused'}")
        return jsonify(out), (200 if out.get("ok") else 409)
