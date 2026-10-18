# core/device_hold.py
# Hold new devices off the internet until the owner checks them in. A switch
# on the Devices tab, off by default. While it is on, a hardware address first
# seen after the switch went on, and not named by the owner, is blocked at the
# router until the owner names it. When the router cannot be reached the
# device stays online and the notice says so (the owner chose fail open).

import logging
import re
from datetime import datetime, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

PREF = "hold_new_devices"
PREF_SINCE = "hold_new_devices_since"
STATUSES = ("held", "not_held", "released")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

DDL = (
    """CREATE TABLE IF NOT EXISTS device_hold (
    mac          TEXT PRIMARY KEY,
    ip           TEXT,
    vendor       TEXT,
    hostname     TEXT,
    held_at      TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('held', 'not_held',
                                                 'released')),
    error        TEXT,
    released_at  TEXT,
    released_by  TEXT
)""",
)


def ensure_tables(conn) -> int:
    added = 0 if me._table_exists_ro(conn, "device_hold") else 1
    for ddl in DDL:
        conn.execute(ddl)
    return added


def _iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _sql_ts(value: str) -> str:
    """An ISO stamp in the shape CURRENT_TIMESTAMP columns hold."""
    return (value or "")[:19].replace("T", " ")


def is_on() -> bool:
    return me.get_preference(PREF, "off") == "on"


def _gateway():
    from core import tool_registry
    mod = tool_registry._modules.get("gateway")
    if mod is None or not getattr(mod, "enabled", False):
        return None
    return mod


def _journal(op, mac, payload):
    try:
        me._journal(op, "device_hold", mac, payload)
    except Exception as e:                                  # noqa: BLE001
        logger.error(f"Could not journal {op} for {mac}: {e}")


def state() -> dict:
    """The switch, when it went on, and every device it has held."""
    with me._get_conn() as conn:
        ensure_tables(conn)
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM device_hold ORDER BY status != 'held', "
            "status != 'not_held', held_at DESC LIMIT 200")]
    return {"on": is_on(), "since": me.get_preference(PREF_SINCE),
            "router": _gateway() is not None, "devices": rows,
            "waiting": sum(1 for r in rows if r["status"] == "held")}


def set_switch(on: bool, by: str = "owner") -> dict:
    """Turn the switch on or off. Turning it off lets every held device in."""
    if bool(on) == is_on():
        return {"success": True, "on": bool(on), "note": "already so"}
    if on:
        me.set_preference(PREF_SINCE, _iso())
        me.set_preference(PREF, "on")
        _journal("device_hold_on", "switch", {"by": by})
        return {"success": True, "on": True,
                "note": ("Devices already here keep their internet. A device "
                         "first seen from now on waits for you.")}
    me.set_preference(PREF, "off")
    released = [release(r["mac"], by=by)
                for r in state()["devices"] if r["status"] == "held"]
    _journal("device_hold_off", "switch", {"by": by,
                                           "released": len(released)})
    return {"success": True, "on": False, "released": released}


def _first_seen(conn, mac: str) -> str | None:
    seen = [r[0] for r in conn.execute(
        "SELECT MIN(first_seen) FROM router_clients WHERE lower(mac) = ? "
        "UNION ALL SELECT MIN(first_seen) FROM known_devices WHERE "
        "lower(mac) = ?", (mac, mac)) if r[0]]
    return min(seen) if seen else None


def _checked_in(conn, mac: str) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM known_devices WHERE lower(mac) = ? AND identified_by "
        "= 'user' AND merged_into IS NULL AND retired_at IS NULL LIMIT 1",
        (mac,)).fetchone())


def consider(client: dict, gateway=None) -> dict:
    """
    A device the router reports for the first time. Held when the switch is
    on, its hardware address first appeared after the switch went on, and
    the owner has not named it. Never raises.
    """
    try:
        return _consider(client, gateway)
    except Exception as e:                                  # noqa: BLE001
        logger.error(f"device hold: could not consider {client}: {e}")
        return {"held": False, "error": str(e)}


def _consider(client: dict, gateway) -> dict:
    if not is_on():
        return {"held": False, "why": "the switch is off"}
    mac = str(client.get("mac") or "").strip().lower()
    ip = client.get("ip")
    if not _MAC.match(mac):
        return {"held": False, "why": "no hardware address to hold it by"}
    since = me.get_preference(PREF_SINCE) or _iso()
    with me._get_conn() as conn:
        ensure_tables(conn)
        if conn.execute("SELECT 1 FROM device_hold WHERE mac = ?",
                        (mac,)).fetchone():
            return {"held": False, "why": "already decided"}
        if _checked_in(conn, mac):
            return {"held": False, "why": "the owner named it"}
        first = _first_seen(conn, mac)
        if first and first < _sql_ts(since):
            return {"held": False, "why": "here before the switch went on"}
    gw = gateway if gateway is not None else _gateway()
    if gw is None:
        status, error = "not_held", "no router agent is set up"
    else:
        out = gw.block_mac(mac, reason="new device, waiting for the owner "
                                       "to check it in", ip=ip)
        ok = out.get("success")
        status = "held" if ok else "not_held"
        error = None if ok else (out.get("error") or "the router refused")
    with me._get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO device_hold (mac, ip, vendor, "
                     "hostname, held_at, status, error) VALUES "
                     "(?,?,?,?,?,?,?)", (mac, ip, client.get("vendor"),
                                         client.get("hostname"), _iso(),
                                         status, error))
    _journal("device_held" if status == "held" else "device_not_held", mac,
             {"ip": ip, "error": error})
    _notice(mac, ip, client, status, error)
    return {"held": status == "held", "status": status, "error": error}


def _notice(mac, ip, client, status, error):
    from core import actions
    what = ", ".join(v for v in (client.get("hostname"), client.get("vendor"))
                     if v) or "nothing known yet"
    if status == "held":
        title = "A new device is waiting for you"
        body = (f"{ip or mac} ({mac}, {what}) has no internet until you "
                f"check it in on the Devices tab.")
    else:
        title = "A new device could not be held"
        body = (f"{ip or mac} ({mac}, {what}) is online: {error}. Check it "
                f"on the Devices tab.")
    try:
        actions.notify(title, body, urgency="critical")
    except Exception as e:                                  # noqa: BLE001
        logger.warning(f"device hold notice not sent: {e}")


def release(mac: str, by: str = "owner", gateway=None) -> dict:
    """Let a held device in. The block is lifted before the row says so."""
    mac = str(mac or "").strip().lower()
    with me._get_conn() as conn:
        ensure_tables(conn)
        row = conn.execute("SELECT * FROM device_hold WHERE mac = ?",
                           (mac,)).fetchone()
    if row is None or row["status"] == "released":
        return {"success": False, "mac": mac, "error": "not held"}
    if row["status"] == "held":
        gw = gateway if gateway is not None else _gateway()
        if gw is None:
            return {"success": False, "mac": mac,
                    "error": "the router agent is not reachable, so the "
                             "block is still on; try again"}
        out = gw.unblock_mac(mac, reason="checked in by the owner",
                             ip=row["ip"])
        if not out.get("success") and "held no block" not in \
                str(out.get("error") or ""):
            return {"success": False, "mac": mac,
                    "error": out.get("error") or "the router refused"}
    with me._get_conn() as conn:
        conn.execute("UPDATE device_hold SET status = 'released', "
                     "released_at = ?, released_by = ? WHERE mac = ?",
                     (_iso(), by, mac))
    _journal("device_released", mac, {"by": by})
    return {"success": True, "mac": mac}


def release_ip(ip: str, by: str = "owner") -> list:
    """The owner named the device at this address: let it in."""
    if not ip:
        return []
    with me._get_conn() as conn:
        if not me._table_exists_ro(conn, "device_hold"):
            return []
        held = {r[0]: r[1] for r in conn.execute(
            "SELECT mac, ip FROM device_hold WHERE status != 'released'")}
        known = {r[0].lower() for r in conn.execute(
            "SELECT mac FROM known_devices WHERE ip = ? AND mac IS NOT NULL",
            (ip,))}
    macs = {m for m, at in held.items() if at == ip} | (known & held.keys())
    return [release(m, by=by) for m in sorted(macs)]
