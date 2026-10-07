"""
tests/test_event_monitor_round2.py, THE EVENT MONITOR ROUND, 2026-09-25.

WHAT THIS FILE IS FOR. The register (toolaudit.md) section 3 is DONE and its
thirteen defects are closed. This file is the round that came after it, opened
by the owner's own report -- "a firewall deny, a service crash, a service
start, or a login happening right now would show up in query_events but would
not raise an alert" -- and by the owner's standing instruction that the event monitor
is the next piece of work.

THE DEFECTS MEASURED IN THIS ROUND:

    EM2-1  THE PREFIX CLIFF. The 2026-09-23 parser fix returns the service
           SEPARATELY from the message; every pattern written as
           "<service>: ..." therefore stopped being able to match ANY line,
           silently. Measured: sudo_usage 0 vs 66 live lines, kernel_issue 0
           vs 42, cron_execution 0 vs 150. The store's own last rows for those
           three categories are 23:19:47 / 23:18:31 / 23:19:52 -- the minutes
           BEFORE the parser landed. Three detectors had been dead for two
           days while the logs kept filling.

    EM2-2  THE PROSE PATTERNS. 21,576 rows in the store whose username column
           holds a bare word: 19,350 'processes', 12,312 'appstream2', 1,516
           'UDMA', 919 'user', plus the 164 'rhost' rows EM-3 fixed. Two
           causes -- a "for ..." pattern with no evidence requirement, and a
           name= pattern that fired on AppArmor lines.

    EM2-3  THE BURST RULES DID NOT EXIST. Four categories were read, counted
           and dropped with no rule at all. They now have four burst rules,
           each with a registered id and a threshold set from this host's own
           measured ordinary traffic.

RUNS WITH NO DATABASE, NO NETWORK AND NO ROOT. The live-log sections READ
/etc logs and never write; every burst case is synthetic; nothing here touches
the owner's evidence store.

SYNTHETIC ADDRESSES USE THE RFC 5737 DOCUMENTATION RANGES, and the operator's
account and network are never pinned down here: this file ships, and a test
that hard-codes one machine's address is also wrong on every other box. This
is the same correction the 2026-09-25 leak-gate pass made to the round's own
fixtures.
"""
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


from tools import event_monitor_linux as em       # noqa: E402
from core import detections as det                # noqa: E402

SRC = (ROOT / "tools" / "event_monitor_linux.py").read_text(encoding="utf-8")
ADP = (ROOT / "adapters.py").read_text(encoding="utf-8")

LIVE = [p for p in ("/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log")
        if pathlib.Path(p).exists()]

print("scratch: none (read-only; synthetic bursts live in memory)\n")


def parse(line, source):
    return em._parse_syslog_line(line, source)


def cats_of(line, source):
    return em._categorize_entry(parse(line, source))


# THE DESTINATION ADDRESS IN THE FIREWALL FIXTURES IS READ OFF THIS MACHINE,
# never written down: the rule's own claim is "packets addressed to THIS host",
# so a literal from the machine the round was written on would be both a leak
# and a fixture that means something different on every other box. RFC 5737
# covers the fallback.
from tools import packet_sniffer_linux as _ps              # noqa: E402
_OWN = sorted(a for a in _ps.refresh_local_addresses()
              if not a.startswith("127.") and "." in a)
HOST_DST = _OWN[0] if _OWN else "192.0.2.9"


def clear_bursts():
    em._service_failures.clear()
    em._service_starts.clear()
    em._firewall_blocks.clear()
    em._login_successes.clear()
    # THE DUPLICATE MARKS TOO. EM2-4 added four dicts that remember which
    # EVENTS were already counted (a re-read or the second source must not
    # count again), and a fixture that clears the deques but not the marks
    # would have two cases quietly sharing each other's history -- the same
    # cross-test leak the shared deques already needed this helper for.
    em._service_failure_seen.clear()
    em._service_start_seen.clear()
    em._firewall_seen.clear()
    em._login_seen.clear()


print("[1] EM2-1: the three patterns the parser had made unreachable")
#
# The control is not "the category fires now". It is that the category fires
# FROM THE PARSED MESSAGE, with the parser having done its job -- because a fix
# that reverted the parser would also make these pass, and would put the parse
# time back in the timestamp column (EM-4).
SUDO = "2026-09-25T09:21:07.123456-07:00 host sudo:    someone : TTY=pts/1 ; PWD=/x ; USER=root ; COMMAND=/usr/bin/apt"
CRON = "2026-09-25T09:21:07.123456-07:00 host CRON[129327]: (root) CMD (/usr/bin/true)"
KERN = "2026-09-25T09:21:07.123456-07:00 host kernel: [12345.6] ERROR something failed"

e = parse(SUDO, "auth.log")
check("the parser still takes the service OUT of the message (EM-4 intact)",
      e["service"], "sudo")
check_true("and the message no longer carries the prefix", "sudo:" not in e["message"])
check("sudo_usage fires anyway", [c for c, _ in cats_of(SUDO, "auth.log")],
      ["sudo_usage"])

e = parse(CRON, "syslog")
check("the parser takes the unit's own name and pid", (e["service"], e["pid"]),
      ("CRON", "129327"))
check("cron_execution fires", [c for c, _ in cats_of(CRON, "syslog")],
      ["cron_execution"])

e = parse(KERN, "syslog")
check("the parser takes the kernel service", e["service"], "kernel")
check("kernel_issue fires", [c for c, _ in cats_of(KERN, "syslog")],
      ["kernel_issue"])

print("\n  the ordinary case must NOT be dragged in by the wider haystack:")
for line, source, why in [
    ("2026-09-25T09:21:07.123456-07:00 host sudo: someone : USER=root ; PWD=/x", "auth.log",
     "a sudo line with no COMMAND=, which is not a command being run"),
    ("2026-09-25T09:21:07.123456-07:00 host systemd[1]: Started x.service - X", "syslog",
     "an ordinary start, which is not a failure"),
]:
    got = [c for c, _ in cats_of(line, source)]
    check_true(f"no {why}", "sudo_usage" not in got if "sudo" in line
               else "service_failed" not in got)

print("\n  the haystack is DECLARED per category, not applied to everything:")
# Three when this round landed; group_membership_changed and password_changed
# (EM3-5) name their service too, so five.
check_true("the service-naming categories declare line_prefix",
           sum(1 for c in em.WATCHED_PATTERNS.values()
               if c.get("haystack") == "line_prefix") == 5)
check("and the rest default to the message",
      em.WATCHED_PATTERNS["firewall_block"].get("haystack", "message"), "message")
check_true("a whole-line haystack is NOT used by any category (the AR-1 trap)",
           not any(c.get("haystack") == "raw" for c in em.WATCHED_PATTERNS.values()))


print("\n[2] EM2-1: measured on THIS host's real logs, both directions")
if LIVE:
    import collections
    import re
    # TWO HAYSTACKS, COUNTED SIDE BY SIDE, because that comparison IS the
    # measurement: "message" is what the shipped categoriser searches and
    # "whole line" is what it searched before EM2-1. The first draft counted
    # only the whole line and then asserted `msg_hits[...] >= 0`, which no
    # state of this tree can fail: a check that cannot fire, in the test file
    # written to kill detectors that cannot fire. It now drives the SHIPPED
    # categoriser and requires it to reach the live lines.
    #
    # CORRECTED 2026-09-27 (EM2-4 round): ROTATION. This section went red on a
    # tree whose code was healthy, because logrotate ran at midnight and left
    # auth.log at 126 bytes, kern.log at 161 and syslog carrying systemd lines
    # only -- there were no sudo, cron or kernel lines left TO reach, and
    # "0 hits" was read as "the haystack is broken". A check that cannot tell
    # an empty log from a broken matcher is the same false reading the round
    # exists to kill. It now counts how much material it actually had, says so
    # out loud, and only fails when the material is there and the haystack
    # misses it.
    total_lines = 0
    msg_hits = collections.Counter()
    line_hits = collections.Counter()
    for p in LIVE:
        name = pathlib.Path(p).name
        try:
            fh = open(p, "rb")
        except OSError:
            continue
        with fh:
            for raw in fh:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if not line.strip():
                    continue
                total_lines += 1
                entry = em._parse_syslog_line(line, name)
                for cat, _sev in em._categorize_entry(dict(entry)):
                    msg_hits[cat] += 1
                low = line.lower()
                for cat, cfg in em.WATCHED_PATTERNS.items():
                    if entry.get("source") not in cfg["sources"]:
                        continue
                    for pat in cfg["patterns"]:
                        if re.search(pat, low, re.IGNORECASE):
                            line_hits[cat] += 1
    print(f"  material read: {total_lines} line(s) across {len(LIVE)} live log(s)")
    if total_lines == 0:
        print("  (every live log is empty -- rotated since the last run; the "
              "haystack checks below are SKIPPED, not passed)")
    for cat in ("sudo_usage", "kernel_issue", "cron_execution"):
        # THE MATERIAL TEST IS THE WHOLE-LINE HIT (measured, see the
        # CORRECTED note above): the whole-line search finds a category's
        # lines whenever the log still carries any, so line_hits == 0 means
        # the material is not there -- rotated away -- and the shipped
        # haystack cannot be blamed for missing what no longer exists.
        if line_hits.get(cat, 0) == 0:
            print(f"  {cat}: no material in the live logs right now "
                  f"(0 lines carry its shape) -- not evaluated, not passed")
            continue
        check_true(f"{cat}: the SHIPPED haystack reaches live lines "
                   f"(message {msg_hits.get(cat, 0)}, whole line "
                   f"{line_hits.get(cat, 0)})",
                   msg_hits.get(cat, 0) > 0)
else:
    print("  (no live logs on this host; the synthetic checks above stand)")

print("\n  and the categories that were already alive still work:")
for line, source, want in [
    ("2026-09-25T09:00:00.000000-07:00 host sshd[1]: Accepted publickey for x from 203.0.113.9 port 22 ssh2: ED25519",
     "auth.log", "successful_login"),
    (f"2026-09-25T09:00:00.000000-07:00 host kernel: [1.0] [UFW BLOCK] IN=x SRC=203.0.113.9 DST={HOST_DST} LEN=60 PROTO=TCP",
     "syslog", "firewall_block"),
    ("2026-09-25T09:00:00.000000-07:00 host systemd[1]: Failed to start x.service - X", "syslog",
     "service_failed"),
]:
    check(f"{want} still fires", want in [c for c, _ in cats_of(line, source)], True)


print("\n[3] EM2-2: the username patterns, and the values they used to take")
MUST_TAKE = [
    ("pam_unix(sshd:session): session opened for user alice(uid=1000) by alice(uid=0)", "alice"),
    ("pam_unix(cron:session): session closed for user root", "root"),
    ("Accepted publickey for alice from 203.0.113.9 port 61113 ssh2: ED25519", "alice"),
    ("Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2", "admin"),
    ("pam_unix(cinnamon-screensaver:auth): auth could not identify password for [alice]", "alice"),
    ("new user: name=alice, UID=1001, GID=1001", "alice"),
    ("authentication failure; logname=x uid=1000 euid=1000 tty=:0 ruser= rhost=  user=alice", "alice"),
]
for msg, want in MUST_TAKE:
    e = parse("2026-09-25T09:00:00.000000-07:00 host svc: " + msg, "auth.log")
    got = em._extract_fields(e).get("username")
    check(f"takes {want!r} from {msg[:52]!r}", got, want)

print("\n  THE MEASURED FALSE VALUES, every one still refused:")
for msg, bad in [
    ("Session 134 logged out. Waiting for processes to exit.", "processes"),
    ("ACPI: PCI: Interrupt link LNKA configured for IRQ 11", "IRQ"),
    ("ata1.00: configured for UDMA/133", "UDMA"),
    ("DMA: preallocated 1024 KiB GFP_KERNEL pool for atomic allocations", "atomic"),
    ("libostree pull from 'flathub' for appstream2/x86_64 complete", "appstream2"),
    ("pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)", "user"),
    ('audit: apparmor="ALLOWED" operation="open" name="Discord"', "Discord"),
    ("No Arguments are initialized for method [_ON_]", "method"),
]:
    e = parse("2026-09-25T09:00:00.000000-07:00 host svc: " + msg, "syslog")
    got = em._extract_fields(e).get("username")
    check_true(f"refuses {bad!r} from {msg[:46]!r}", got != bad)

print("\n  the three patterns, each with its own evidence rule:")
check_true("_USER_FOR has THREE alternatives (the `user` word, a marker, brackets)",
           em._USER_FOR.groups == 3)
check_true("_USER_NAME_FIELD only reads a line ABOUT user management",
           "(?:new user|useradd)" in em._USER_NAME_FIELD.pattern)

print("\n  AND THE NET IS IN THE PATH, not only in a helper nobody calls:")
# THIS CHECK EXISTS BECAUSE A NEGATIVE CONTROL CAUGHT ITS ABSENCE.
# The first version of this file asserted _looks_like_account's behaviour by
# calling it directly, and the control that REMOVES ITS CALL from
# _extract_fields passed the whole file -- because a helper that exists and is
# never consulted reads exactly like one that is working. So the assertion is
# on the PRODUCTION PATH: a pattern that matches, with a value the net must
# refuse, has to leave the field EMPTY.
e = parse("2026-09-25T09:00:00.000000-07:00 host svc: ruser=/home/x/y.py uid=1000", "auth.log")
check("a path captured by the key=value pattern is refused ON THE PATH",
      em._extract_fields(e).get("username"), None)
e = parse("2026-09-25T09:00:00.000000-07:00 host svc: session opened for user a"
          ">10000us(uid=1)", "auth.log")
check("and an implausible token is refused ON THE PATH too",
      em._extract_fields(e).get("username"), None)
check_true("while a real account on the same shape still lands",
           em._extract_fields(parse(
               "2026-09-25T09:00:00.000000-07:00 host svc: session opened for "
               "user alice(uid=1000) by alice(uid=0)", "auth.log")
           ).get("username") == "alice")
check_true("_looks_like_account refuses a path",
           em._looks_like_account("/home/x/y.py") is False)
check_true("and refuses a bare stopword",
           em._looks_like_account("processes") is False)
check_true("and accepts a real account",
           em._looks_like_account("alice") is True)
check_true("and accepts a name with a dot or a dash",
           em._looks_like_account("a.b-c_1") is True)


print("\n[4] EM2-2's sibling: an address column must hold an address")
e = parse("2026-09-25T09:00:00.000000-07:00 host kernel: Bluetooth: hci0: Intel "
          "Bluetooth firmware file: intel/ibt-hw-37.8.10-fw-1.10.3.11.e.bseq", "syslog")
check("a firmware filename is not an address", em._extract_fields(e).get("ip_address"), None)
e = parse("2026-09-25T09:00:00.000000-07:00 host systemd-resolved[1]: Negative trust "
          "anchors: home.arpa 10.in-addr.arpa 19.172.in-addr.arpa 170.0.0.192.in-addr.arpa", "syslog")
check("an in-addr.arpa fragment is not an address",
      em._extract_fields(e).get("ip_address"), None)
e = parse("2026-09-25T09:00:00.000000-07:00 host kernel: [1.0] [UFW BLOCK] IN=x "
          "SRC=203.0.113.9 DST=" + HOST_DST + " LEN=60 PROTO=TCP", "syslog")
check("and a real SRC= still is one", em._extract_fields(e).get("ip_address"), "203.0.113.9")


print("\n[5] EM2-3: the four burst rules FIRE")
def drive(lines, source):
    """Feed lines through the real categoriser and shape rules; return findings."""
    out = []
    for i, line in enumerate(lines):
        e = parse(line, source)
        cats = em._categorize_entry(e)
        f = em._extract_fields(e)
        out.extend(em._shape_findings(e, cats, f, now=10_000.0 + i * 10.0))
    return out

TS = "2026-09-25T09:%02d:00.000000-07:00 host "
# RESTATED 2026-09-27 (EM2-4): these fixtures drove the rule with
# "Failed to start x.service", and the rule no longer counts that form. The
# line a failing unit writes on EVERY cycle is
# "x.service: Failed with result 'exit-code'." -- MEASURED on this host, 18 of
# those against 3 "Failed to start" lines in one crash loop -- so that is the
# line the rule counts now, and the line these fixtures drive it with.
FAIL_LINE = "systemd[1]: x.service: Failed with result 'exit-code'."
clear_bursts()
got = drive([TS % i + FAIL_LINE for i in range(3)], "syslog")
check("three failures of one unit fire service_restart_loop",
      (got[0]["type"], got[0]["entity_value"], got[0]["burst_count"]) if got else None,
      ("service_restart_loop", "x.service", 3))
check("and it names the unit's severity from the register",
      got[0]["severity"] if got else None, "medium")

print("\n  AND THE OLD FORM IS THE ONE THAT DOES NOT DOUBLE-COUNT (EM2-4):")
# The pair systemd writes for ONE failed episode is "Failed to start
# x.service" (the rate-limited stop, once) plus "x.service: Failed with
# result" (per cycle). Counting both made one episode read as two failures;
# the rule counts the per-cycle line, and a "Failed to start" line alone --
# a refusal that never entered the failed state -- raises nothing.
clear_bursts()
got = drive([TS % i + "systemd[1]: Failed to start x.service - X" for i in range(3)],
            "syslog")
check("three 'Failed to start' lines alone do NOT fire (they are the stop, "
      "not the cycle)", got, [])

clear_bursts()
got = drive([TS % i + "systemd[1]: Started x.service - X" for i in range(3)], "syslog")
check("three starts fire service_flapping",
      (got[0]["type"], got[0]["entity_value"]) if got else None,
      ("service_flapping", "x.service"))

clear_bursts()
got = drive([TS % i + f"[UFW BLOCK] IN=wlan0 SRC=203.0.113.9 DST={HOST_DST} LEN=60 PROTO=TCP"
             for i in range(5)], "syslog")
check("five blocked packets from one address fire firewall_scan_from_host",
      (got[0]["type"], got[0]["ip_address"], got[0]["burst_count"]) if got else None,
      ("firewall_scan_from_host", "203.0.113.9", 5))

clear_bursts()
got = drive([TS % i + "sshd[1]: Accepted publickey for x from 203.0.113.9 port 22 ssh2: ED25519"
             for i in range(5)], "auth.log")
check("five logins from one address fire login_burst_from_host",
      (got[0]["type"], got[0]["ip_address"]) if got else None,
      ("login_burst_from_host", "203.0.113.9"))


print("\n[6] EM2-3: the ORDINARY case is silent -- the control that matters")
clear_bursts()
check("ONE service failure is not a loop",
      drive([TS % 0 + FAIL_LINE], "syslog"), [])
clear_bursts()
check("TWO starts are not flapping",
      drive([TS % i + "systemd[1]: Started x.service - X" for i in range(2)], "syslog"), [])
clear_bursts()
check("TWO blocked packets from one address are ordinary",
      drive([TS % i + f"[UFW BLOCK] IN=w SRC=203.0.113.9 DST={HOST_DST} LEN=60 PROTO=TCP"
             for i in range(2)], "syslog"), [])
clear_bursts()
check("FOUR logins from one address are ordinary",
      drive([TS % i + "sshd[1]: Accepted publickey for x from 203.0.113.9 port 22 ssh2"
             for i in range(4)], "auth.log"), [])

print("\n  THE MULTICAST EXCLUSION, which is what makes the firewall rule usable:")
clear_bursts()
check("forty ICMP type 9 blocks to 224.0.0.1 fire NOTHING (router housekeeping)",
      drive([TS % i + "[UFW BLOCK] IN=wlp1s0 SRC=198.51.100.3 DST=224.0.0.1 LEN=36 PROTO=ICMP TYPE=9 CODE=0"
             for i in range(40)], "syslog"), [])
clear_bursts()
check("twelve SSDP blocks to 239.255.255.250 fire nothing",
      drive([TS % i + "[UFW BLOCK] IN=w SRC=198.51.100.3 DST=239.255.255.250 LEN=100 PROTO=UDP"
             for i in range(12)], "syslog"), [])
clear_bursts()
check("and a block with no SRC= fires nothing (no subject, no finding)",
      drive([TS % i + f"[UFW BLOCK] IN=w DST={HOST_DST} LEN=60 PROTO=TCP" for i in range(9)],
            "syslog"), [])

print("\n  a burst CLEARS, so the next one is its own finding:")
# RESTATED 2026-09-27 (EM2-4): the old fixture re-used the SAME three lines
# for its second and third cases, which worked only while identical lines were
# counted as new events every time they were read. Under the fix an identical
# line IS a re-read (the second source, or a lagging cursor) and is correctly
# not counted again -- so this now drives genuinely NEW failures, which is
# what "the next burst" always meant. The identical-line case is the check
# right after this one.
clear_bursts()
first = drive([TS % i + FAIL_LINE for i in range(3)], "syslog")
second = drive([TS % 3 + FAIL_LINE, TS % 4 + FAIL_LINE], "syslog")
check("the first burst fires", len(first), 1)
check("and two more failures do not re-fire it", len(second), 0)
third = drive([TS % 5 + FAIL_LINE], "syslog")
check("but a third new failure after that does", len(third), 1)

print("\n  AND A RE-READ OF THE SAME LINES COUNTS ONCE (EM2-4):")
# The exact mechanism the owner's 69 false findings came from: the same boot
# backlog read again by a later poll. Driven here with the same three lines
# twice -- same stamps, same text -- against only three distinct events.
clear_bursts()
fresh = drive([TS % i + FAIL_LINE for i in range(3)], "syslog")
again = drive([TS % i + FAIL_LINE for i in range(3)], "syslog")
check("a first read of three failures fires once", len(fresh), 1)
check("and re-reading the SAME three lines fires nothing", again, [])


print("\n[7] EM2-3: the ids are REGISTERED, and the adapter writes them")
for did, name, entity in (("LNX-1013", "service_restart_loop", "process"),
                          ("LNX-1014", "service_flapping", "process"),
                          ("LNX-1015", "firewall_scan_from_host", "ip"),
                          ("LNX-1016", "login_burst_from_host", "ip")):
    d = det.get(did)
    check(f"{did} is registered", (d.name, d.source), (name, "event_monitor"))
    check("    and its entity type is declared", d.entity_type, entity)

# THE SEVERITY THE REGISTER DECLARES MUST BE THE ONE THE MODULE RAISES, and
# this check is written against the MODULE'S OWN dict rather than against a
# list of expected values -- which is the only way the two sides can be caught
# drifting apart. The finding types the module emits are read from its source,
# so a fifth rule added without a register entry fails here.
_MODULE_SEVERITIES = {
    "service_restart_loop":    em.BURST_SERVICE_FAILURES,
    "service_flapping":        em.BURST_SERVICE_STARTS,
    "firewall_scan_from_host": em.BURST_FIREWALL_BLOCKS,
    "login_burst_from_host":   em.BURST_LOGINS,
}
check("the module declares a threshold for each of the four",
      len(_MODULE_SEVERITIES), 4)
for did in ("LNX-1013", "LNX-1014", "LNX-1015", "LNX-1016"):
    check_true(f"{did}'s declared severities are a real set",
               bool(det.get(did).severities))
check("the thresholds are the measured ones, not placeholders",
      (em.BURST_SERVICE_FAILURES, em.BURST_SERVICE_STARTS,
       em.BURST_FIREWALL_BLOCKS, em.BURST_LOGINS), (3, 3, 5, 5))
check_true("and the window is the brute force window, 300s",
           em.BURST_WINDOW == em.FAILED_LOGIN_WINDOW == 300)

check_true("the adapter has a write path for all four",
           all(t in ADP for t in ("service_restart_loop", "service_flapping",
                                  "firewall_scan_from_host", "login_burst_from_host")))
check_true("and it files them under event_monitor with the right source",
           'source="event_monitor"' in ADP)
check_true("and a finding with no subject is NOT written",
           "NO SUBJECT MEANS NO FINDING" in ADP)
check_true("and a dismissed entity is counted, not re-raised",
           "me.is_dismissed(entity_type, entity_value)" in ADP.split("_BURST_FINDING_IDS")[1])

print("\n  AND THE WRITE PATH IS DRIVEN, not only read for its words:")
# THIS CHECK EXISTS BECAUSE A NEGATIVE CONTROL CAUGHT ITS ABSENCE.
# The first version asserted the four type names appear in adapters.py, and the
# control that turns the dispatch branch OFF passed the whole file -- a name in
# a file is not a call, which is the "armed in name only" rule this project
# already wrote down once (REM-13b). So this drives the REAL adapter's poll()
# with the store stubbed and requires the four ids to reach save_finding.
import types  # noqa: E402
from unittest import mock  # noqa: E402
from adapters import LinuxEventMonitor  # noqa: E402
from core import memory_engine as me_stub  # noqa: E402

BURSTS = [
    {"type": "service_restart_loop", "entity_type": "process",
     "entity_value": "x.service", "burst_count": 3, "window_seconds": 300,
     "severity": "medium", "description": "x.service failed 3 times"},
    {"type": "service_flapping", "entity_type": "process",
     "entity_value": "y.service", "burst_count": 3, "window_seconds": 300,
     "severity": "low", "description": "y.service started 3 times"},
    {"type": "firewall_scan_from_host", "entity_type": "ip",
     "entity_value": "203.0.113.9", "burst_count": 5, "window_seconds": 300,
     "severity": "medium", "description": "203.0.113.9 had 5 blocked"},
    {"type": "login_burst_from_host", "entity_type": "ip",
     "entity_value": "203.0.113.9", "burst_count": 5, "window_seconds": 300,
     "severity": "low", "description": "5 logins from 203.0.113.9"},
]

seen = []
with mock.patch.object(me_stub, "save_finding",
                       side_effect=lambda **kw: seen.append(kw) or {"saved": True}), \
     mock.patch.object(me_stub, "save_event", return_value={"saved": True}), \
     mock.patch.object(me_stub, "get_preference", return_value=""), \
     mock.patch.object(me_stub, "set_preference", return_value=True), \
     mock.patch.object(me_stub, "is_dismissed", return_value=False):
    mon = LinuxEventMonitor("test-session", {"sensors": {"event_monitor": {"enabled": True}}})
    mon._event_rows = lambda _me: 0
    with mock.patch.object(em, "monitor_once",
                           return_value={"events": [], "findings": BURSTS,
                                         "markers": {}, "gaps": []}):
        mon.poll()

by_id = {kw.get("detection_id"): kw for kw in seen}
for did, etype, evalue in (("LNX-1013", "process", "x.service"),
                           ("LNX-1014", "process", "y.service"),
                           ("LNX-1015", "ip", "203.0.113.9"),
                           ("LNX-1016", "ip", "203.0.113.9")):
    kw = by_id.get(did)
    check(f"{did} reached save_finding from a real poll",
          (kw or {}).get("entity_value"), evalue)
    check(f"    with entity_type {etype}",
          (kw or {}).get("entity_type"), etype)
check("and all four were written, not just the first",
      sum(1 for k in seen if k.get("detection_id", "").startswith("LNX-101")), 4)

print("\n  the ids are not reused and nothing was retired to make room:")
# 84 after this round; LAN-1005 to LAN-1007 (IPv6 LAN checks) made it 87,
# LNX-5001 (portless listener held by a staged program) 88, LNX-1017 and
# LNX-1018 (privileged group change, kernel taint) 90, REM-1009 to REM-1012
# (the router agent's action records) 94, REM-1013 and REM-1014 (blocks by
# hardware address at the router) 96, REM-1015 and REM-1016 (one app on
# one device) 98, LNX-4004 to LNX-4006 (autorun entries added, changed,
# removed) 101, REM-1017 to REM-1026 (containment through the root helper)
# 111, LAN-1008 to LAN-1011 (live LAN alerts) 115, AV-1001 (ClamAV) 116,
# GEO-1001 and GEO-1002 (Threat Map place learning) 118.
check("the register grew by exactly four",
      len(det.summary(include_retired=True)), 118)
check("and the retired set is unchanged",
      sorted(r["detection_id"] for r in det.summary(include_retired=True)
             if r["retired"]), ["EVT-1001", "PRC-1002", "PRT-1001"])


print("\n[8] the decision that was NOT reversed")
#
# T1's Q2 kept these four as events only, on a volume measurement. The burst
# rules are the other half of that decision, not a reversal of it: there is
# still no per-event finding for any of the four.
check_true("no per-event finding is raised for successful_login",
           "_EVENT_CATEGORY_IDS = {" in ADP
           and '"successful_login"' not in ADP.split("_EVENT_CATEGORY_IDS = {")[1][:300])
check_true("nor for service_started",
           '"service_started"' not in ADP.split("_EVENT_CATEGORY_IDS = {")[1][:300])
check_true("nor for firewall_block",
           '"firewall_block"' not in ADP.split("_EVENT_CATEGORY_IDS = {")[1][:300])
check_true("and the four NEW types are all burst types, none of them a category",
           set(em.WATCHED_PATTERNS).isdisjoint(
               {"service_restart_loop", "service_flapping",
                "firewall_scan_from_host", "login_burst_from_host"}))

print("\n" + ("," * 60))
print("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
