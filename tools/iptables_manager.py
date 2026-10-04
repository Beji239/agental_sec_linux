# tools/iptables_manager.py
# AgentalSec Linux — what is ACTUALLY blocking traffic on this host.
#
# REWRITTEN 2026-09-17 (task T1, "firewall truth").
#
# The receipts from what this file used to be, because a rewrite with no
# stated reason is just a diff:
#
#   1. detect_backend() asked `nft list ruleset` FIRST. On this machine that
#      succeeds elevated, so the backend chosen was "nftables" even though
#      ufw is active here and owns the ruleset. Every rule this app wrote
#      went somewhere `ufw status` could not show the owner — behind the back
#      of the tool the owner actually manages this box with.
#
#   2. block_port_nftables() created table `inet agental_sec` and then added
#      rules to chains named input/output that it created WITHOUT a type or
#      a hook. In nftables a chain with no hook is never traversed, so the
#      rule sat in a table attached to nothing. It then checked the exit
#      code — and the old remediation_linux.block_ip() did not even do that:
#      it ran two nft commands, ignored both return codes, and returned
#      {"success": True}. A block that does not exist, reported as done.
#
#   3. unblock_ip() was a stub that returned
#      {"success": True, "note": "Rule removal requires specific rule
#      identification"} having done NOTHING, and the adapter above it then
#      wrote an audit finding — "Device unblocked at this host" — for an
#      action that never happened.
#
#   4. Nothing was ever verified. "The command exited 0" is not "the rule is
#      there": ufw can queue a rule that a later reload drops, nft can accept
#      a rule into a dead chain, iptables' nf_tables shim can accept a rule
#      into a chain nothing reaches. Every action below now ends by READING
#      BACK the ruleset and reporting what it found.
#
# The rule this file now follows, and it is the rule the whole app is built
# on: NEVER RETURN SUCCESS WITHOUT EVIDENCE. A refusal with a reason is a
# good answer. "success": True over a rule that is not there is the one
# failure mode a security tool may not have, because the operator then
# believes they are protected.
#
# BACKEND ORDER, AND WHY.
#
#   ufw        first, WHENEVER it is installed and its own config says
#              ENABLED=yes. Not because it is better than nft — it is a
#              frontend to the same engine — but because it is a LAYER OF
#              RECORD. Rules written through ufw show up in `ufw status`,
#              survive `ufw reload`, and are what the owner reads and edits.
#              Rules written around it are invisible to all three.
#
#   nftables   when ufw is not active. Base chains are created WITH their
#              hooks now, and the chain is verified to be traversed before
#              any rule is called placed.
#
#   iptables   last, for hosts with neither. On modern Debian/Ubuntu this is
#              the nf_tables shim (v1.8.x says so in --version), which is fine
#              for us: comments work, so rules stay removable by name.
#
# Detection never needs root to DECIDE (it reads /etc/ufw/ufw.conf, which is
# world readable, and checks for binaries). Every MUTATING operation refuses
# without root, and says so with the command to run instead — never a silent
# no-op, never a success.
#
# NAMING. Every rule this app writes carries a marker in its comment:
#
#     AgentalSec_port_<direction>_<proto>_<port>     e.g. ..._inbound_tcp_4444
#     AgentalSec_device_<ip>_<in or out>                e.g. ..._203.0.113.7_in
#
# The prefix is how list_agental_rules_status() finds OUR rules among the
# user's own, and how the unblocks find the rule to remove. A rule that
# cannot be found by name cannot be removed, which is half of why the old
# file was dangerous: it could block and could not unblock.
#
# IPv6: characters a comment may not carry are replaced with '-', so a v6
# address in a marker reads 2001-db8--1. The marker is built by the same
# function on the way in and on the way out, so the two can never disagree.

import ipaddress
import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

RULE_PREFIX = "AgentalSec_"

UFW = "ufw"
NFT = "nft"
NFT_TABLE = "agental_sec"
NFT_FAMILY = "inet"

# One command may not run forever. nft on a large ruleset is fast; ufw
# reloads are the slow case and 30s covers them with room.
_DEFAULT_TIMEOUT = 30
_LIST_TIMEOUT = 15


# RUNNING A COMMAND, AND THE ONE DETAIL THAT MATTERS

def _run(argv: list, timeout: int = _DEFAULT_TIMEOUT):
    """
    Run one command. Returns (returncode, stdout, stderr, error_or_None).

    stdin is DEVNULL on every call, deliberately. ufw has interactive
    prompts ("Proceed with operation (y|n)?") and this code is called from a
    sensor thread inside a daemon whose stdin may be a terminal or may be
    nothing at all. A prompt inherited from a terminal would HANG the calling
    thread for as long as it takes a person to notice; with stdin closed the
    same prompt reads EOF and aborts immediately, which this function then
    reports as the failure it is. A hang and a refusal are different
    sentences, and only one of them is true here.
    """
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or "", None
    except FileNotFoundError:
        return 127, "", "", f"{argv[0]} is not installed on this host"
    except subprocess.TimeoutExpired:
        return 124, "", "", (f"{argv[0]} did not finish within {timeout}s. "
                             f"Nothing can be said about whether it took "
                             f"effect; treat this as unverified.")
    except Exception as e:
        return 1, "", "", f"{type(e).__name__}: {e}"


def _euid() -> int:
    try:
        return os.geteuid()
    except AttributeError:              # not Linux; the caller decides
        return -1


def needs_root() -> bool:
    """True when this process cannot change the firewall. Say so, never fail silent."""
    return _euid() != 0


def _refuse_needs_root(action: str) -> dict:
    """
    The refusal for 'this needs root'. Honest, specific, and actionable.

    NOT {"success": False, "error": "permission denied"}. The reader of this
    dict is either the model or the operator, and both are owed the reason
    and the way out.
    """
    return {
        "success": False,
        "refused": True,
        "needs_root": True,
        "error": (
            f"{action} needs root: ufw, nft and iptables all refuse to change "
            f"the ruleset unelevated, and so does this app. Nothing was "
            f"changed and nothing was left half-done. Run the app elevated, "
            f"or make this one change yourself with sudo."
        ),
    }


# WHICH BACKEND IS REALLY IN CHARGE

def _ufw_installed() -> bool:
    rc, _out, _err, _e = _run([UFW, "--version"], timeout=_LIST_TIMEOUT)
    return rc == 0


def _ufw_configured_enabled() -> tuple:
    """
    (enabled, note) read from ufw's own config file.

    /etc/ufw/ufw.conf is world readable, which matters: this decides the
    backend on an UNELEVATED run too, where `ufw status` cannot be asked.
    The answer is about configuration, not about the running state, and the
    note says exactly that so nobody reads more into it than it is.
    """
    path = "/etc/ufw/ufw.conf"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.upper().startswith("ENABLED="):
                    value = line.split("=", 1)[1].strip().strip('"').lower()
                    if value == "yes":
                        return True, (f"ufw is installed and configured "
                                      f"ENABLED in {path}.")
                    return False, (f"ufw is installed but {path} says "
                                   f"ENABLED={value}.")
    except OSError as e:
        return False, f"could not read {path} ({e})."
    return False, f"ufw is installed but {path} has no ENABLED line."


def detect_backend() -> str:
    """'ufw' | 'nftables' | 'iptables' | 'none'. See the header for the order."""
    return detect_backend_detail()["backend"]


def detect_backend_detail() -> dict:
    """
    The backend AND the sentence that explains the choice.

    The old detect_backend returned a bare string and threw the reasoning
    away, so when it picked nftables on a ufw-managed box there was nothing
    anywhere that said why. A status panel that cannot explain itself is
    how that went unnoticed.
    """
    if _ufw_installed():
        enabled, note = _ufw_configured_enabled()
        if enabled:
            return {"backend": "ufw", "reason": note}

    rc, _out, _err, _e = _run([NFT, "--version"], timeout=_LIST_TIMEOUT)
    if rc == 0:
        readable = _run([NFT, "list", "ruleset"], timeout=_LIST_TIMEOUT)[0] == 0
        reason = ("nftables is the engine on this host"
                  + (", and its ruleset reads fine here."
                     if readable else
                     ". The ruleset itself cannot be READ unelevated; "
                     "blocking still works with root, and every action "
                     "reads back what it wrote."))
        return {"backend": "nftables", "reason": reason}

    rc, _out, _err, e = _run(["iptables", "-L", "-n"], timeout=_LIST_TIMEOUT)
    if rc == 0 or e is None:
        return {"backend": "iptables",
                "reason": ("Nothing else is installed, so iptables is the "
                           "engine. On modern Debian/Ubuntu this is the "
                           "nf_tables shim, and comments work.")}

    return {"backend": "none",
            "reason": ("No ufw, no nft and no iptables could be run on this "
                       "host, so this app cannot block anything here. That "
                       "is a fact about the host, not about the network.")}


# RULE NAMES

def _marker(text: str) -> str:
    """A comment token every backend will accept, built identically both ways."""
    return re.sub(r"[^A-Za-z0-9_.-]", "-", text)


def _port_rule_name(port: int, direction: str, protocol: str = "tcp") -> str:
    return _marker(f"{RULE_PREFIX}port_{direction}_{protocol}_{port}")


def _ip_rule_name(ip: str, leg: str) -> str:
    """leg is 'in' or 'out' — a device block is one rule per direction."""
    return _marker(f"{RULE_PREFIX}device_{ip}_{leg}")


def _rule_name(port: int, direction: str, protocol: str = "tcp") -> str:
    """Kept under its old name: callers outside this file used it."""
    return _port_rule_name(port, direction, protocol)


def _is_v6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


# UFW BACKEND

def _ufw_out(argv: list, timeout: int = _DEFAULT_TIMEOUT):
    return _run([UFW, *argv], timeout=timeout)


def _ufw_listing_text() -> tuple:
    """
    (readable, text, reason) — everything ufw will say about its rules.

    Two sources on purpose. `status numbered` is what the owner reads and
    carries the rule NUMBER; `show added` echoes the add commands back, so a
    comment is visible even on a ufw build that does not render comments in
    status. Verification searches BOTH, because a rule that is in one and
    not the other is still there, and telling a user their block is missing
    when it is present is its own kind of falsehood.
    """
    rc, out, err, e = _ufw_out(["status", "numbered"])
    if e:
        return False, "", e
    if rc != 0:
        return False, "", (err.strip() or
                           "ufw status failed (it needs root to read the "
                           "ruleset)")

    rc2, out2, _err2, _e2 = _ufw_out(["show", "added"])
    return True, (out or "") + "\n" + (out2 or ""), ""


def _ufw_rule_present(marker: str) -> tuple:
    """(present, position_or_None, snippet) — searched across both listings."""
    readable, text, _reason = _ufw_listing_text()
    if not readable:
        return False, None, ""
    for line in text.splitlines():
        if marker in line:
            num = re.match(r"\s*\[\s*(\d+)\]\s*(.*)", line)
            if num:
                return True, int(num.group(1)), line.strip()
            return True, None, line.strip()
    return False, None, ""


def _ufw_ordering_note(port: int) -> str:
    """
    Is there an ALLOW rule for this port, and does ours beat it.

    ufw evaluates rules top-down and the FIRST MATCH wins, so a deny at
    position 1 beats an allow at position 20 — and that is worth saying out
    loud in the result, because the owner's own allow rule for that port
    still shows in `ufw status` and looks like it should win.
    """
    readable, text, _reason = _ufw_listing_text()
    if not readable:
        return ""
    needle = f"{port}/"
    allows = []
    for line in text.splitlines():
        m = re.match(r"\s*\[\s*(\d+)\]\s*(.*)", line)
        if m and "ALLOW" in m.group(2).upper() and needle in m.group(2):
            allows.append(int(m.group(1)))
    if not allows:
        return ""
    return (f"Note: an ALLOW rule for port {port} exists at position(s) "
            f"{allows}. ufw checks rules top-down and the first match wins, "
            f"and this app inserts at position 1, so this block takes "
            f"precedence over {'them' if len(allows) > 1 else 'it'}.")


def _ufw_add(spec: list, marker: str, label: str) -> dict:
    """
    Insert one ufw rule at the top and READ IT BACK.

    insert 1 is deliberate: at the top of the list this rule outranks
    everything already there, which is what a response to an incident needs.
    Appending would leave a pre-existing allow rule winning — a block that
    reports success and blocks nothing.
    """
    argv = ["insert", "1", *spec, "comment", marker]
    rc, out, err, e = _ufw_out(argv)
    if e:
        return {"success": False, "backend": "ufw", "error": e,
                "command": "ufw " + " ".join(argv)}
    if rc != 0:
        return {"success": False, "backend": "ufw",
                "error": (err or out).strip() or "ufw refused the rule",
                "command": "ufw " + " ".join(argv)}

    # ufw says "Skipping adding existing rule" when it already has it. That
    # is not a failure and it is not a NEW block either; both facts travel.
    already = "skipping" in (out or "").lower()

    present, position, snippet = _ufw_rule_present(marker)
    if not present:
        return {
            "success": False, "backend": "ufw", "rule_name": marker,
            "error": (f"ufw accepted this rule but it does not appear in "
                      f"ufw's own listings, so this app will not report it "
                      f"as blocked. command: ufw {' '.join(argv)}"),
            "command": "ufw " + " ".join(argv),
        }

    return {
        "success": True, "backend": "ufw", "rule_name": marker,
        "verified": True, "already_present": already,
        "position": position, "rule_text": snippet,
        "command": "ufw " + " ".join(argv),
    }


def block_port_ufw(port: int, direction: str, protocol: str = "tcp") -> dict:
    """Deny one port through ufw, at the top of the list, and verify it."""
    if needs_root():
        return _refuse_needs_root(f"Blocking port {port} ({direction})")

    verb = "in" if direction == "inbound" else "out"
    marker = _port_rule_name(port, direction, protocol)
    result = _ufw_add(["deny", verb, "proto", protocol, "to", "any",
                       "port", str(port)], marker,
                      f"port {port} {direction}")
    if result.get("success"):
        note = _ufw_ordering_note(port)
        if note:
            result["ordering_note"] = note
    return result


def block_ip_ufw(ip: str, direction: str = "both") -> dict:
    """Deny a device through ufw: one rule per direction, each verified."""
    if needs_root():
        return _refuse_needs_root(f"Blocking {ip}")

    results, rules = {}, []
    if direction in ("inbound", "both"):
        name = _ip_rule_name(ip, "in")
        res = _ufw_add(["deny", "in", "from", ip], name, f"{ip} inbound")
        results["inbound"] = res
        rules.append(res.get("rule_name") or name)
    if direction in ("outbound", "both"):
        name = _ip_rule_name(ip, "out")
        res = _ufw_add(["deny", "out", "to", ip], name, f"{ip} outbound")
        results["outbound"] = res
        rules.append(res.get("rule_name") or name)

    failed = [k for k, r in results.items() if not r.get("success")]
    if failed:
        return {
            "success": False, "backend": "ufw",
            "error": (f"the {', '.join(failed)} rule(s) for {ip} did not "
                      f"verify. A partial block is reported as a failure on "
                      f"purpose: half a ban reads exactly like a whole one "
                      f"from the outside."),
            "partial": results,
        }
    return {
        "success": True, "backend": "ufw", "ip": ip, "direction": direction,
        "verified": True, "rules": rules,
        "already_present": all(r.get("already_present")
                               for r in results.values()),
    }


def _ufw_delete(argv: list, marker: str, label: str) -> dict:
    """Delete by exact spec, then verify absence. Absence is the proof."""
    argv = ["--force", "delete", *argv, "comment", marker]
    rc, out, err, e = _ufw_out(argv)
    if e:
        return {"success": False, "backend": "ufw", "error": e}

    present, _pos, _snip = _ufw_rule_present(marker)
    if present:
        return {
            "success": False, "backend": "ufw", "rule_name": marker,
            "error": (f"ufw said {((err or out).strip() or 'done')!r} but "
                      f"{marker} is STILL in its listings. The rule is still "
                      f"in force."),
        }
    if rc != 0:
        # Not present and the delete complained: nothing of ours was there.
        return {"success": False, "backend": "ufw", "rule_name": marker,
                "not_found": True,
                "error": (f"no ufw rule named {marker} exists, so nothing "
                          f"needed removing and nothing was removed.")}
    return {"success": True, "backend": "ufw", "rule_name": marker,
            "verified": True, "removed": True}


def unblock_port_ufw(port: int, direction: str, protocol: str = "tcp") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Unblocking port {port} ({direction})")
    verb = "in" if direction == "inbound" else "out"
    marker = _port_rule_name(port, direction, protocol)
    return _ufw_delete(["deny", verb, "proto", protocol, "to", "any",
                        "port", str(port)], marker, f"port {port}")


def unblock_ip_ufw(ip: str, direction: str = "both") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Unblocking {ip}")
    results, any_removed = {}, False
    if direction in ("inbound", "both"):
        results["inbound"] = _ufw_delete(["deny", "in", "from", ip],
                                         _ip_rule_name(ip, "in"), ip)
        any_removed = any_removed or results["inbound"].get("success", False)
    if direction in ("outbound", "both"):
        results["outbound"] = _ufw_delete(["deny", "out", "to", ip],
                                          _ip_rule_name(ip, "out"), ip)
        any_removed = any_removed or results["outbound"].get("success", False)

    # REM-8, 2026-09-24. THE ASYMMETRY, MEASURED AND REMOVED.
    #
    # What this did: returned success when ANY leg's delete succeeded, while
    # block_ip_ufw one screen up returns FAILURE when any leg's add did not
    # verify, with its own comment giving the reason ("A partial block is
    # reported as a failure on purpose: half a ban reads exactly like a whole
    # one from the outside"). The same argument holds in reverse and it is the
    # direction that leaves the operator less protected than the owner believes:
    # lifting the INBOUND rule of a two-direction ban and failing on the
    # OUTBOUND one means the device is still cut off from this host, this app
    # has just said the block is gone, and the operator's next move is to stop
    # looking at it. Measured by driving the shipped path with one leg
    # succeeding and one refusing.
    #
    # Note what "removal" makes easier to miss than "creation": a half-block is
    # visible (the device still gets through), and a half-lift is not (the
    # device is still blocked, which looks exactly like the ban working).
    failed = [k for k, r in results.items() if not r.get("success")]
    if failed and any_removed:
        return {
            "success": False, "backend": "ufw", "ip": ip,
            "partial": results, "removed_some": True,
            "error": (f"ONLY PART OF THE BLOCK WAS LIFTED for {ip}: the "
                      f"{', '.join(failed)} rule(s) are STILL IN FORCE. A "
                      f"half-lifted ban reads exactly like a whole one from "
                      f"the outside, so this is reported as a failure. "
                      f"Anything already lifted stays lifted; run this again "
                      f"once the refusal is understood."),
        }

    if not any_removed:
        return {"success": False, "backend": "ufw", "ip": ip,
                "not_found": all(r.get("not_found")
                                 for r in results.values()),
                "error": (f"none of this app's rules for {ip} were found, so "
                          f"nothing was lifted."),
                "partial": results}
    return {"success": True, "backend": "ufw", "ip": ip, "removed": True,
            "partial": results}


# NFTABLES BACKEND
#
# The fix for the oldest bug in this file. A table needs BASE CHAINS —
# chains that carry `type filter hook input` — or nothing in it is ever
# traversed. The old code created bare chains with no type and no hook,
# added rules into them, and returned success. Rules in a hookless chain
# are stored, listable, and completely inert: the exact shape of a block
# that reports itself as working.

_NFT_CHAINS = (("input", "input"), ("output", "output"))


def _nft_out(argv: list, timeout: int = _DEFAULT_TIMEOUT):
    return _run([NFT, *argv], timeout=timeout)


def _nft_table_exists() -> bool:
    return _nft_out(["list", "table", NFT_FAMILY, NFT_TABLE],
                    timeout=_LIST_TIMEOUT)[0] == 0


def _nft_ensure() -> dict:
    """Table and base chains exist, WITH their hooks. Verified, not assumed."""
    if not _nft_table_exists():
        rc, out, err, e = _nft_out(["add", "table", NFT_FAMILY, NFT_TABLE])
        if e or rc != 0:
            return {"ok": False, "error": e or (err or out).strip()}

    for chain, hook in _NFT_CHAINS:
        listing = _nft_out(["list", "chain", NFT_FAMILY, NFT_TABLE, chain],
                           timeout=_LIST_TIMEOUT)
        exists = listing[0] == 0
        if exists and f"hook {hook}" in listing[1]:
            continue
        if exists:
            # A chain that exists WITHOUT its hook is exactly the old bug's
            # debris. Do not add rules to it — say what is wrong.
            return {"ok": False,
                    "error": (f"chain {NFT_TABLE}/{chain} exists but has no "
                              f"hook, so anything added to it would never be "
                              f"traversed. Delete it by hand and re-run.")}
        spec = (f"add chain {NFT_FAMILY} {NFT_TABLE} {chain} "
                f"{{ type filter hook {hook} priority 0 ; policy accept ; }}")
        rc, out, err, e = _nft_out([spec])
        if e or rc != 0:
            return {"ok": False, "error": e or (err or out).strip()}

    # Read the whole table back once. This is the check the old code never
    # made: both chains present, both hooked.
    rc, out, err, _e = _nft_out(["list", "table", NFT_FAMILY, NFT_TABLE],
                                timeout=_LIST_TIMEOUT)
    if rc != 0:
        return {"ok": False, "error": (err or out).strip()}
    missing = [h for _c, h in _NFT_CHAINS if f"hook {h}" not in out]
    if missing:
        return {"ok": False,
                "error": (f"base chain(s) for hook(s) {', '.join(missing)} "
                          f"are not attached after creation. Not writing "
                          f"rules into a table that cannot see traffic.")}
    return {"ok": True}


def _nft_find_rule(chain: str, marker: str) -> tuple:
    """(present, handle) — handles come from `nft -a`, which shows comments too."""
    # -a makes nft print "# handle N"; without it no rule could be deleted.
    rc, out, _err, _e = _nft_out(["-a", "list", "chain", NFT_FAMILY, NFT_TABLE,
                                  chain], timeout=_LIST_TIMEOUT)
    if rc != 0:
        return False, None
    for line in (out or "").splitlines():
        if marker in line:
            m = re.search(r"#\s*handle\s+(\d+)", line)
            return True, (int(m.group(1)) if m else None)
    return False, None


def _nft_add_rule(chain: str, match: list, marker: str) -> dict:
    argv = ["add", "rule", NFT_FAMILY, NFT_TABLE, chain, *match,
            "drop", "comment", f'"{marker}"']
    rc, out, err, e = _nft_out(argv)
    if e:
        return {"success": False, "backend": "nftables", "error": e}
    if rc != 0:
        return {"success": False, "backend": "nftables",
                "error": (err or out).strip(),
                "command": "nft " + " ".join(argv)}

    present, handle = _nft_find_rule(chain, marker)
    if not present:
        return {"success": False, "backend": "nftables", "rule_name": marker,
                "error": ("nft accepted the rule but it is not in the chain "
                          "listing, so it is not reported as placed.")}
    return {"success": True, "backend": "nftables", "rule_name": marker,
            "verified": True, "handle": handle, "chain": chain}


def block_port_nftables(port: int, direction: str, protocol: str = "tcp") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Blocking port {port} ({direction})")
    chain = "input" if direction == "inbound" else "output"
    key = "dport" if direction == "inbound" else "sport"
    marker = _port_rule_name(port, direction, protocol)

    ensured = _nft_ensure()
    if not ensured["ok"]:
        return {"success": False, "backend": "nftables", "error": ensured["error"]}

    present, _h = _nft_find_rule(chain, marker)
    if present:
        return {"success": True, "backend": "nftables", "rule_name": marker,
                "verified": True, "already_present": True}

    return _nft_add_rule(chain, [protocol, key, str(port)], marker)


def block_ip_nftables(ip: str, direction: str = "both") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Blocking {ip}")
    ensured = _nft_ensure()
    if not ensured["ok"]:
        return {"success": False, "backend": "nftables", "error": ensured["error"]}

    fam = "ip6" if _is_v6(ip) else "ip"
    results = {}
    if direction in ("inbound", "both"):
        results["inbound"] = _nft_add_rule("input", [fam, "saddr", ip],
                                           _ip_rule_name(ip, "in"))
    if direction in ("outbound", "both"):
        results["outbound"] = _nft_add_rule("output", [fam, "daddr", ip],
                                            _ip_rule_name(ip, "out"))
    failed = [k for k, r in results.items() if not r.get("success")]
    if failed:
        return {"success": False, "backend": "nftables", "ip": ip,
                "error": f"rule(s) for {', '.join(failed)} did not verify",
                "partial": results}
    return {"success": True, "backend": "nftables", "ip": ip,
            "direction": direction, "verified": True}


def _nft_delete_rule(chain: str, marker: str) -> dict:
    present, handle = _nft_find_rule(chain, marker)
    if not present:
        return {"success": False, "backend": "nftables", "rule_name": marker,
                "not_found": True,
                "error": f"no rule named {marker} in {chain}"}
    if handle is None:
        return {"success": False, "backend": "nftables", "rule_name": marker,
                "error": (f"{marker} is present but nft did not print a "
                          f"handle, so it cannot be deleted by name here.")}

    rc, out, err, e = _nft_out(["delete", "rule", NFT_FAMILY, NFT_TABLE,
                                chain, "handle", str(handle)])
    if e or rc != 0:
        return {"success": False, "backend": "nftables",
                "error": e or (err or out).strip()}

    still, _h = _nft_find_rule(chain, marker)
    if still:
        return {"success": False, "backend": "nftables", "rule_name": marker,
                "error": (f"nft deleted handle {handle} but {marker} is still "
                          f"listed. The rule is still in force.")}
    return {"success": True, "backend": "nftables", "rule_name": marker,
            "verified": True, "removed": True}


def unblock_port_nftables(port: int, direction: str, protocol: str = "tcp") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Unblocking port {port} ({direction})")
    chain = "input" if direction == "inbound" else "output"
    return _nft_delete_rule(chain, _port_rule_name(port, direction, protocol))


def unblock_ip_nftables(ip: str, direction: str = "both") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Unblocking {ip}")
    results, any_removed = {}, False
    if direction in ("inbound", "both"):
        results["inbound"] = _nft_delete_rule("input", _ip_rule_name(ip, "in"))
        any_removed = any_removed or results["inbound"].get("success", False)
    if direction in ("outbound", "both"):
        results["outbound"] = _nft_delete_rule("output", _ip_rule_name(ip, "out"))
        any_removed = any_removed or results["outbound"].get("success", False)
    # REM-8: the same asymmetry as the ufw path, and the same answer. See
    # unblock_ip_ufw for the measurement and the argument.
    failed = [k for k, r in results.items() if not r.get("success")]
    if failed and any_removed:
        return {"success": False, "backend": "nftables", "ip": ip,
                "partial": results, "removed_some": True,
                "error": (f"ONLY PART OF THE BLOCK WAS LIFTED for {ip}: the "
                          f"{', '.join(failed)} rule(s) are STILL IN FORCE. A "
                          f"half-lifted ban reads exactly like a whole one "
                          f"from the outside, so this is reported as a "
                          f"failure rather than as a lift.")}
    if not any_removed:
        return {"success": False, "backend": "nftables", "ip": ip,
                "not_found": True,
                "error": f"none of this app's rules for {ip} were found.",
                "partial": results}
    return {"success": True, "backend": "nftables", "ip": ip, "removed": True,
            "partial": results}


# IPTABLES BACKEND
#
# Last choice, and only for hosts with neither ufw nor nft. On modern
# Debian/Ubuntu `iptables --version` prints "(nf_tables)", which is the shim
# over the same engine as everything above — comments work, so the naming
# scheme does too. IPv6 goes through ip6tables when the address needs it.

def _iptables_bin(v6: bool) -> str:
    return "ip6tables" if v6 else "iptables"


def _iptables_delete_by_marker(chain: str, marker: str, v6: bool = False) -> dict:
    """
    Remove by exact rule text. -S prints rules as the commands that made
    them, which makes this a spec delete rather than a line-number guess;
    a number shifts under anything else editing the chain.
    """
    binary = _iptables_bin(v6)
    rc, out, err, e = _run([binary, "-S", chain], timeout=_LIST_TIMEOUT)
    if e or rc != 0:
        return {"success": False, "backend": "iptables",
                "error": e or (err or out).strip(),
                "rule_name": marker}

    target = None
    prefix = f"-A {chain} "
    for line in (out or "").splitlines():
        if marker in line and line.startswith(prefix):
            target = line[len(prefix):].split()
            break
    if target is None:
        return {"success": False, "backend": "iptables", "rule_name": marker,
                "not_found": True,
                "error": f"no rule named {marker} exists in {chain}"}

    rc, out, err, e = _run([binary, "-D", chain, *target])
    if e or rc != 0:
        return {"success": False, "backend": "iptables",
                "error": e or (err or out).strip()}

    rc, out, _err, _e = _run([binary, "-S", chain], timeout=_LIST_TIMEOUT)
    if rc == 0 and marker in (out or ""):
        return {"success": False, "backend": "iptables", "rule_name": marker,
                "error": f"deleted but {marker} is still listed. Still in force."}
    return {"success": True, "backend": "iptables", "rule_name": marker,
            "verified": True, "removed": True}


def _iptables_add_rule(chain: str, match: list, marker: str,
                       v6: bool = False) -> dict:
    binary = _iptables_bin(v6)
    argv = [binary, "-A", chain, *match, "-j", "DROP",
            "-m", "comment", "--comment", marker]
    rc, out, err, e = _run(argv)
    if e or rc != 0:
        return {"success": False, "backend": "iptables",
                "error": e or (err or out).strip(),
                "command": " ".join(argv)}

    # -C asks the kernel to confirm the rule is in the chain. This is a
    # stronger check than re-reading -S, and it is one call.
    check = [binary, "-C", chain, *match, "-j", "DROP",
             "-m", "comment", "--comment", marker]
    rc2, _out2, _err2, _e2 = _run(check, timeout=_LIST_TIMEOUT)
    if rc2 != 0:
        return {"success": False, "backend": "iptables", "rule_name": marker,
                "error": ("iptables accepted the rule but the kernel will "
                          "not confirm it with -C, so it is not reported as "
                          "placed.")}
    return {"success": True, "backend": "iptables", "rule_name": marker,
            "verified": True, "chain": chain,
            "command": " ".join(argv)}


def block_port_iptables(port: int, direction: str, protocol: str = "tcp") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Blocking port {port} ({direction})")
    chain = "INPUT" if direction == "inbound" else "OUTPUT"
    key = "--dport" if direction == "inbound" else "--sport"
    marker = _port_rule_name(port, direction, protocol)

    rc, out, _err, _e = _run(["iptables", "-S", chain], timeout=_LIST_TIMEOUT)
    if rc == 0 and marker in (out or ""):
        return {"success": True, "backend": "iptables", "rule_name": marker,
                "verified": True, "already_present": True}

    return _iptables_add_rule(chain, ["-p", protocol, key, str(port)], marker)


def block_ip_iptables(ip: str, direction: str = "both") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Blocking {ip}")
    v6 = _is_v6(ip)
    results = {}
    if direction in ("inbound", "both"):
        results["inbound"] = _iptables_add_rule(
            "INPUT", ["-s", ip], _ip_rule_name(ip, "in"), v6=v6)
    if direction in ("outbound", "both"):
        results["outbound"] = _iptables_add_rule(
            "OUTPUT", ["-d", ip], _ip_rule_name(ip, "out"), v6=v6)
    failed = [k for k, r in results.items() if not r.get("success")]
    if failed:
        return {"success": False, "backend": "iptables", "ip": ip,
                "error": f"rule(s) for {', '.join(failed)} did not verify",
                "partial": results}
    return {"success": True, "backend": "iptables", "ip": ip,
            "direction": direction, "verified": True}


def unblock_port_iptables(port: int, direction: str, protocol: str = "tcp") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Unblocking port {port} ({direction})")
    chain = "INPUT" if direction == "inbound" else "OUTPUT"
    return _iptables_delete_by_marker(
        chain, _port_rule_name(port, direction, protocol))


def unblock_ip_iptables(ip: str, direction: str = "both") -> dict:
    if needs_root():
        return _refuse_needs_root(f"Unblocking {ip}")
    v6 = _is_v6(ip)
    results, any_removed = {}, False
    if direction in ("inbound", "both"):
        results["inbound"] = _iptables_delete_by_marker(
            "INPUT", _ip_rule_name(ip, "in"), v6=v6)
        any_removed = any_removed or results["inbound"].get("success", False)
    if direction in ("outbound", "both"):
        results["outbound"] = _iptables_delete_by_marker(
            "OUTPUT", _ip_rule_name(ip, "out"), v6=v6)
        any_removed = any_removed or results["outbound"].get("success", False)
    # REM-8: third backend, same asymmetry, same answer. See unblock_ip_ufw.
    failed = [k for k, r in results.items() if not r.get("success")]
    if failed and any_removed:
        return {"success": False, "backend": "iptables", "ip": ip,
                "partial": results, "removed_some": True,
                "error": (f"ONLY PART OF THE BLOCK WAS LIFTED for {ip}: the "
                          f"{', '.join(failed)} rule(s) are STILL IN FORCE. A "
                          f"half-lifted ban reads exactly like a whole one "
                          f"from the outside, so this is reported as a "
                          f"failure rather than as a lift.")}
    if not any_removed:
        return {"success": False, "backend": "iptables", "ip": ip,
                "not_found": True,
                "error": f"none of this app's rules for {ip} were found.",
                "partial": results}
    return {"success": True, "backend": "iptables", "ip": ip, "removed": True,
            "partial": results}


# DISPATCHERS — what the tool registry and remediation call.

_BACKENDS = {
    "ufw": {
        "block_port": block_port_ufw,
        "unblock_port": unblock_port_ufw,
        "block_ip": block_ip_ufw,
        "unblock_ip": unblock_ip_ufw,
    },
    "nftables": {
        "block_port": block_port_nftables,
        "unblock_port": unblock_port_nftables,
        "block_ip": block_ip_nftables,
        "unblock_ip": unblock_ip_nftables,
    },
    "iptables": {
        "block_port": block_port_iptables,
        "unblock_port": unblock_port_iptables,
        "block_ip": block_ip_iptables,
        "unblock_ip": unblock_ip_iptables,
    },
}


def _dispatch(verb: str, *args, backend: str = None, **kwargs) -> dict:
    """
    Route to the backend, or refuse with the reason there is none.

    `backend` is an override, used by the verification script to exercise one
    implementation on a host where another is in charge. Nothing in the app
    passes it.
    """
    backend = backend or detect_backend()
    if backend == "none":
        return {
            "success": False, "refused": True, "backend": "none",
            "error": (detect_backend_detail()["reason"] + " Nothing was "
                      "changed."),
        }
    return _BACKENDS[backend][verb](*args, **kwargs)


def block_port(port: int, direction: str, protocol: str = "tcp",
               backend: str = None) -> dict:
    """Block one TCP port through whichever firewall is really in charge."""
    if direction not in ("inbound", "outbound"):
        return {"success": False,
                "error": f"direction must be inbound or outbound, got {direction!r}"}
    return _dispatch("block_port", port, direction, protocol, backend=backend)


def unblock_port(port: int, direction: str, protocol: str = "tcp",
                 backend: str = None) -> dict:
    if direction not in ("inbound", "outbound"):
        return {"success": False,
                "error": f"direction must be inbound or outbound, got {direction!r}"}
    return _dispatch("unblock_port", port, direction, protocol, backend=backend)


def block_ip_address(ip: str, direction: str = "both",
                     backend: str = None) -> dict:
    """Block a device. One rule per direction; both must verify or this fails."""
    if direction not in ("inbound", "outbound", "both"):
        return {"success": False,
                "error": f"direction must be inbound, outbound or both, got {direction!r}"}
    return _dispatch("block_ip", ip, direction, backend=backend)


def unblock_ip_address(ip: str, direction: str = "both",
                       backend: str = None) -> dict:
    if direction not in ("inbound", "outbound", "both"):
        return {"success": False,
                "error": f"direction must be inbound, outbound or both, got {direction!r}"}
    return _dispatch("unblock_ip", ip, direction, backend=backend)


# READING WHAT IS THERE — and, when it cannot be read, SAYING SO

def _list_ufw() -> dict:
    readable, text, reason = _ufw_listing_text()
    if not readable:
        return {"readable": False, "reason": reason, "rules": []}
    rules = []
    for line in text.splitlines():
        if RULE_PREFIX in line:
            m = re.match(r"\s*\[\s*(\d+)\]\s*(.*)", line)
            if m:
                rules.append({"number": int(m.group(1)),
                              "rule": m.group(2).strip(),
                              "backend": "ufw"})
            else:
                rules.append({"number": None, "rule": line.strip(),
                              "backend": "ufw"})
    return {"readable": True, "reason": "", "rules": rules}


def _list_nft() -> dict:
    rc, out, err, _e = _nft_out(["list", "table", NFT_FAMILY, NFT_TABLE],
                                timeout=_LIST_TIMEOUT)
    if rc != 0:
        if "No such file or directory" in (err or "") or \
                "does not exist" in (err or ""):
            # The table not existing is a REAL, readable empty answer: this
            # app has never written a rule here.
            return {"readable": True, "reason": "", "rules": []}
        return {"readable": False,
                "reason": (err.strip() or
                           "nft could not read the ruleset (it needs root)"),
                "rules": []}
    rules = []
    for line in (out or "").splitlines():
        if RULE_PREFIX in line:
            rules.append({"rule": line.strip(), "backend": "nftables"})
    return {"readable": True, "reason": "", "rules": rules}


def _list_iptables() -> dict:
    rules = []
    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        rc, out, err, e = _run(["iptables", "-S", chain], timeout=_LIST_TIMEOUT)
        if e or rc != 0:
            return {"readable": False,
                    "reason": e or (err or out).strip(),
                    "rules": []}
        for line in (out or "").splitlines():
            if RULE_PREFIX in line:
                rules.append({"chain": chain, "rule": line.strip(),
                              "backend": "iptables"})
    return {"readable": True, "reason": "", "rules": rules}


def list_agental_rules_status() -> dict:
    """
    Every rule this app wrote, plus whether the reading worked at all.

    THE SEPARATION IS THE POINT. An empty list unelevated used to mean
    "could not read the ruleset", and every reader of it — the adapter, the
    model, the operator — treated it as "nothing is blocked". Those are
    different sentences; this function keeps them apart and every caller is
    required to say which one it is reporting.
    """
    detail = detect_backend_detail()
    backend = detail["backend"]
    if backend == "none":
        return {"readable": False, "reason": detail["reason"], "rules": [],
                "backend": "none"}
    if backend == "ufw":
        result = _list_ufw()
    elif backend == "nftables":
        result = _list_nft()
    else:
        result = _list_iptables()
    result["backend"] = backend
    return result


def list_agental_rules() -> list:
    """Compatibility shape: the rules only. Use the _status form to also say
    whether the read succeeded — this one cannot."""
    return list_agental_rules_status()["rules"]


def get_status() -> dict:
    """What the dashboard and the adapter ask about this subsystem."""
    detail = detect_backend_detail()
    listing = list_agental_rules_status()
    return {
        "backend": detail["backend"],
        "backend_reason": detail["reason"],
        "available": detail["backend"] != "none",
        "needs_root": needs_root(),
        "readable": listing["readable"],
        "read_unavailable_reason": listing["reason"],
        # None, never 0, when the read failed. A count of zero is a claim.
        "rules_count": len(listing["rules"]) if listing["readable"] else None,
        "can_block": detail["backend"] != "none" and not needs_root(),
        "note": (
            "Every rule this app writes carries the AgentalSec_ marker, so "
            "it can be listed and removed by name rather than by position."
            if detail["backend"] != "none" else
            "No firewall backend could be found on this host, so this app "
            "cannot block anything here."
        ),
    }


if __name__ == "__main__":          # a human asking, from a shell
    import json as _json
    print(_json.dumps(get_status(), indent=2))
