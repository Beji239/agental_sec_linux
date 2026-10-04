# tools/runbook.py
# AgentalSec V2, CISA KEV feed sync and runbook management

import json
import logging
import threading

import requests

logger = logging.getLogger(__name__)

from core import memory_engine as me

CISA_KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_SIZE_LIMIT  = 10 * 1024 * 1024
KEV_MIN_ENTRIES = 100

# WHAT A KEV ROW IS ALLOWED TO CLAIM

# 2026-09-16. The five STATIC entries below got applies_to and verify_hint
# after the EternalBlue-on-Windows-11 mess. The ~1500 rows the feed brings in
# never got them, because the INSERT below simply did not write those columns,
# so they landed NULL. Same for entry_kind.
#
# That left every imported row reading like a bare assertion. Somebody asked
# about a Cisco ISE entry on a network with no Cisco hardware, and the row
# itself had nothing on it that said "I do not know whether this applies to
# you". The qualifier framework existed and the mirror walked straight past it.
#
# So the two facts a KEV row has to keep separate:
#
#   THE FEED SAYS NOTHING ABOUT VERSIONS. cveID, vendorProject, product,
#       vulnerabilityName, shortDescription, requiredAction, dateAdded,
#       dueDate, knownRansomwareCampaignUse. That is the whole entry. There is
#       no affected-version range and no port. So the scope of a KEV row is
#       UNKNOWN, which is a different sentence from "applies to everything"
#       and a different sentence again from "does not apply here".
#
#   THE FEED SAYS NOTHING ABOUT SEVERITY EITHER. No CVSS, no rating, nothing.
#       See _kev_severity for what we do instead of making one up.

KEV_VERIFY_HINT = (
    "This came from the CISA KEV mirror, which means it is known to have been "
    "exploited somewhere, not that it is present here. The feed gives no "
    "version range and no port, so nothing in this row can tell you whether "
    "this host is affected. Establish that yourself: query_software_inventory "
    "for what is installed, query_port_scan for what is listening, web_search "
    "for the affected version range. If you could not establish it, say you "
    "could not check. Do not report 'not affected' on the strength of a row "
    "that never knew."
)


def _kev_applies_to(vendor: str, product: str) -> str:
    """
    The applies_to text for an imported KEV row.

    Says what the feed actually gave us and stops there. Named as a function
    rather than inlined so the migration that repairs the rows already in the
    database writes the identical sentence, instead of a second copy that
    drifts.
    """
    named = " / ".join(p for p in (vendor or "", product or "") if p) or "not named"
    return (
        f"SCOPE UNKNOWN. The CISA KEV feed names the vendor and product only "
        f"({named}) and carries no affected-version range. That is not the "
        f"same as 'all versions', and it is not the same as 'applies here'. "
        f"Find the version range before you apply this to a host."
    )


def _kev_ransomware(entry: dict) -> str:
    """
    The feed's knownRansomwareCampaignUse, kept as itself.

    2026-09-17. It was read once by _kev_severity and then thrown away, so a
    row could show its rating and not the reason for it, and the Runbook tab
    had nothing to display except a severity word that is blank on most rows.
    Lower-cased because the feed writes 'Known' and 'Unknown' and a column
    people will filter on should not depend on that.
    """
    return str(entry.get("knownRansomwareCampaignUse", "")).strip().lower()


def _kev_severity(entry: dict) -> str:
    """
    Severity for an imported KEV row.

    The old code wrote 'high' for all ~1500 of them, hardcoded. Nothing was
    ever read from the feed, so the field carried no information at all: a
    2004 IOS telnet bug and a fresh pre-auth bypass got the same word, and
    anything sorting or filtering on it was sorting on a constant.

    The feed has exactly one severity-ish signal in it, knownRansomwareCampaignUse,
    and it is a real one, so that is the only case that earns a rating here.
    Everything else says 'unknown', which is honest: we did not look it up,
    and pretending otherwise is how a runbook row starts getting believed.
    """
    if _kev_ransomware(entry) == "known":
        return "high"
    return "unknown"


# STATIC ENTRIES

# These are hand-written priors, not findings. Two distinct kinds live here
# and conflating them is what produced a false critical:
#
#   entry_kind 'vulnerability', a real CVE. Only applies to the versions in
#       applies_to. A port match alone proves nothing; the host has to be
#       running affected software.
#
#   entry_kind 'exposure', a port worth noticing. Not a defect, not a CVE.
#       Severity here means "worth a look", never "you are compromised".
#
# History: STATIC-001 originally read `severity: critical` with no version
# scope, so an open 445 on a Windows 11 machine, the default state of every
# Windows box on a home LAN, surfaced as a critical EternalBlue finding with
# 2017 remediation attached. The model quoted the row accurately. The row was
# wrong. Severities below are scoped so that stops happening, and verify_hint
# tells the model what to establish before it alerts on any of them.

STATIC_ENTRIES = [
    {
        "cve_id": "STATIC-001", "vendor": "Microsoft", "product": "SMB",
        "vulnerability": "EternalBlue / MS17-010 SMBv1 remote code execution",
        "severity": "low",
        "entry_kind": "vulnerability",
        "known_ports": json.dumps([445, 139]),
        "applies_to": (
            "SMBv1 only, on Windows versions patched before March 2017: "
            "XP, Vista, 7, 8.1, Server 2003-2016, and Windows 10 builds "
            "earlier than 1703. NOT Windows 10 1709+ or Windows 11, which "
            "do not install SMBv1 by default. An open 445 on a modern "
            "Windows host is normal file and printer sharing."
        ),
        "verify_hint": (
            "Establish the OS version and whether SMBv1 is enabled before "
            "raising this above low. On Windows: "
            "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. "
            "Also confirm the port is reachable from another host, a scan "
            "run on the machine itself sees services bound, not exposed."
        ),
        "remediation": (
            "Modern Windows: no action, SMBv1 is absent. Legacy hosts: disable "
            "SMBv1 and apply MS17-010. Restrict 445/139 at the perimeter in "
            "all cases, they should never be reachable from the internet."
        ),
        "source": "static",
    },
    {
        "cve_id": "STATIC-002", "vendor": "Microsoft", "product": "RDP",
        "vulnerability": "BlueKeep (CVE-2019-0708) RDP pre-auth RCE",
        "severity": "low",
        "entry_kind": "vulnerability",
        "known_ports": json.dumps([3389]),
        "applies_to": (
            "Windows XP, 7, Server 2003/2008/2008 R2, patched May 2019. "
            "NOT Windows 8, 10, 11 or Server 2012+. An open 3389 on a "
            "current OS is RDP enabled, not BlueKeep."
        ),
        "verify_hint": (
            "Establish the OS version. On anything current, the finding is "
            "'RDP is reachable', which is worth reviewing on its own terms, "
            "especially if exposed beyond the LAN, not BlueKeep."
        ),
        "remediation": (
            "Legacy hosts: patch CVE-2019-0708 and enable Network Level "
            "Authentication. Current hosts: confirm RDP exposure is intended "
            "and never reachable from the internet without a VPN."
        ),
        "source": "static",
    },
    {
        "cve_id": "STATIC-003", "vendor": "Multiple", "product": "Telnet",
        "vulnerability": "Telnet transmits credentials in plaintext",
        "severity": "medium",
        "entry_kind": "exposure",
        "known_ports": json.dumps([23]),
        "applies_to": (
            "Any host with a listening Telnet service. Protocol-level, not "
            "version-specific, Telnet has no transport encryption by design."
        ),
        "verify_hint": (
            "Confirm something is actually listening rather than the port "
            "merely appearing in a scan. Common on IoT, printers, switches "
            "and routers, where it is often on by default."
        ),
        "remediation": "Disable Telnet and use SSH. If the device offers no SSH, isolate it.",
        "source": "static",
    },
    {
        "cve_id": "STATIC-004", "vendor": "Multiple", "product": "Port 4444",
        "vulnerability": "Port 4444 is the Metasploit default listener",
        "severity": "medium",
        "entry_kind": "exposure",
        "known_ports": json.dumps([4444]),
        "applies_to": (
            "A convention, not a vulnerability. 4444 is Metasploit's default "
            "reverse-shell port, but it is an ordinary high port and is also "
            "used by legitimate software, including some Java and Node "
            "development servers."
        ),
        "verify_hint": (
            "Identify the process bound to the port before drawing any "
            "conclusion. Direction matters more than the number: an OUTBOUND "
            "connection to 4444 on a remote host is far more interesting than "
            "a local listener, and a beaconing interval is stronger evidence "
            "than the port itself."
        ),
        "remediation": (
            "Identify the owning process. If unrecognised, capture it before "
            "killing it. Do not treat the port number alone as compromise."
        ),
        "source": "static",
    },
    {
        "cve_id": "STATIC-005", "vendor": "Multiple", "product": "VNC",
        "vulnerability": "VNC often exposed with weak or absent authentication",
        "severity": "medium",
        "entry_kind": "exposure",
        "known_ports": json.dumps([5900, 5901]),
        "applies_to": (
            "Any listening VNC server. Severity depends entirely on whether "
            "authentication is configured, which a port scan cannot determine."
        ),
        "verify_hint": (
            "A listening VNC port says nothing about whether it requires a "
            "password. Raise severity only with evidence of unauthenticated "
            "access or exposure beyond the LAN."
        ),
        "remediation": (
            "Require strong authentication, bind to localhost, or tunnel over "
            "SSH. Never expose VNC directly to the internet."
        ),
        "source": "static",
    },
]


class Runbook:

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._synced    = False

    def start(self):
        logger.info("Runbook ready.")

    def status(self) -> dict:
        """
        Ready still means loaded and callable. The note is the useful part.

        cisa_kev_synced was already in here and nothing read it, so the
        readiness row printed 'running.' whether the mirror held 1700 rows
        or none at all. An empty mirror is not a crash, which is exactly why
        it needs saying out loud rather than a colour.

        THE NOTE USED TO ASSERT AN EMPTY TABLE IT HAD NOT LOOKED AT.
        "the Runbook tab is showing the static entries only" is about the
        TABLE, and _synced is about THIS RUN: MEASURED 2026-09-27 against the
        operator's own store, _synced False -- a boot that could not sync, or a
        status() answered before any sync -- printed that sentence over 1,726
        cisa_kev rows and 5 static ones. Nothing in this module deletes a KEV
        row (`grep -c DELETE tools/runbook.py` is 0), so a failed sync never
        empties the mirror; it leaves the PREVIOUS one in place, which is
        useful and is not the same thing. The count is now read from the table
        and the sentence says which of the two states it is.
        """
        kept = self._kev_rows_in_table()
        if self._synced:
            note = ("The CISA KEV mirror synced this run."
                    + (f" The table holds {kept:,} KEV entries."
                       if kept is not None else ""))
        elif kept:
            note = (f"The CISA KEV mirror has NOT synced this run. That does "
                    f"not empty it: the table still holds the {kept:,} "
                    f"entries the last successful sync wrote, and Sync CISA KEV "
                    f"on that tab refreshes them.")
        else:
            note = ("The CISA KEV mirror has NOT synced this run and the table "
                    "holds no KEV entries, so the Runbook tab is showing the "
                    "static entries only. Sync CISA KEV on that tab fills it.")
        return {"ready": True, "cisa_kev_synced": self._synced,
                "kev_rows": kept, "note": note}

    def _kev_rows_in_table(self):
        """
        How many cisa_kev rows are stored, or None when that cannot be read.

        None rather than 0 on a failed read, because a zero here would be a
        claim about the operator's table made out of an exception.
        """
        try:
            with me._get_conn() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM runbook WHERE source = 'cisa_kev'"
                ).fetchone()
            return int(row[0]) if row else 0
        except Exception as e:
            logger.debug(f"runbook: could not count the KEV rows: {e}")
            return None

    # CISA KEV SYNC

    def sync_cisa_kev(self) -> dict:
        self._load_static_entries()

        try:
            # S26, 2026-08-28. STREAMED, SO THE SIZE LIMIT IS CHECKED BEFORE
            # THE BODY IS IN MEMORY RATHER THAN AFTER IT.
            #
            # Without stream=True, requests reads the entire response body
            # before get() returns. KEV_SIZE_LIMIT was therefore checked
            # against data already allocated: the limit could report the
            # problem, never prevent it. timeout=15 does not cover it either,
            # being a per-read timeout rather than a budget for the whole
            # transfer, so a slow drip that never pauses fifteen seconds runs
            # indefinitely.
            #
            # This is the one module that fetches from a third party over the
            # network, which makes it the one that has to assume the answer
            # might be hostile. router_monitor's own config findings name a
            # compromised gateway handing out its own resolver as a scenario
            # this tool exists to catch, and that is precisely the position
            # from which something else answers for this hostname.
            resp = requests.get(CISA_KEV_URL, timeout=15, stream=True)
            resp.raise_for_status()

            chunks, total = [], 0
            for chunk in resp.iter_content(64 * 1024):
                total += len(chunk)
                if total > KEV_SIZE_LIMIT:
                    resp.close()
                    return {"success": False, "error": "KEV feed too large"}
                chunks.append(chunk)

            data       = json.loads(b"".join(chunks))
            vulns      = data.get("vulnerabilities", [])

            if len(vulns) < KEV_MIN_ENTRIES:
                return {"success": False, "error": f"KEV feed too small: {len(vulns)} entries"}

            return self._write_kev_rows(vulns)

        except requests.RequestException as e:
            logger.warning(f"CISA KEV fetch failed: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"CISA KEV sync error: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    # KEV WRITE

    def _write_kev_rows(self, vulns: list) -> dict:
        """
        Write the feed into the runbook.

        Three things changed here on 2026-09-16, and they are all the same
        shape of bug, a row saying something nobody checked.

        UPSERT, NOT INSERT OR IGNORE. The old write ignored any cve_id already
        present, so a re-sync could never carry a CISA correction. A
        description they fixed upstream stayed wrong here forever, and the
        whole point of re-running a sync is that the source changed. The
        static loader already worked this out for itself and uses REPLACE,
        with a comment saying the uncorrected STATIC-001 would otherwise have
        survived its own fix. Same reasoning, opposite setting, so it is the
        same fix.

        The DO UPDATE is scoped to source = 'cisa_kev'. A conflict against a
        hand-written row resolves to nothing at all, no error, no overwrite,
        which is the one part of the old IGNORE behaviour worth keeping. The
        five static entries are code and this is a mirror, so the mirror does
        not get to touch them.

        ONE CONNECTION, ONE TRANSACTION. The old loop opened a fresh
        connection per row, so ~1500 connections and ~1500 commits against a
        multi-gigabyte database for one sync. Nothing needed that.

        THE COUNTS ARE NOW TRUE. 'inserted' used to be incremented once per
        row the loop reached, including rows the IGNORE threw away, so on
        every sync after the first it reported around fifteen hundred inserts
        and did zero. The existing ids get read up front so inserted, updated
        and skipped mean what they say.
        """
        from core.memory_engine import _get_conn

        inserted = updated = skipped = rejected = 0

        with _get_conn() as conn:
            # Same tolerance the static loader has: migrations add these, but
            # the writer should not hard-fail on a database that somehow has
            # not been migrated yet. It writes fewer columns, it does not
            # crash, and the migration fills them in later.
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(runbook)")}
            qualifier_cols = [c for c in ("entry_kind", "applies_to", "verify_hint")
                              if c in cols]
            # Same tolerance, one migration later. ransomware_use is not a
            # qualifier, it is a fact the feed states, so it is kept separate
            # from the three columns that exist to say what a row does NOT
            # know.
            feed_fact_cols = [c for c in ("ransomware_use",) if c in cols]
            if len(qualifier_cols) < 3:
                logger.warning(
                    "runbook is missing qualifier columns %s, KEV rows will be "
                    "written without them until migrations run.",
                    sorted({"entry_kind", "applies_to", "verify_hint"} - set(qualifier_cols)),
                )

            # Who is already here, and who owns them. Read once.
            owners = {r["cve_id"]: r["source"]
                      for r in conn.execute("SELECT cve_id, source FROM runbook")}

            feed_cols = ["cve_id", "vendor", "product", "vulnerability",
                         "description", "remediation", "date_added", "due_date",
                         "severity", "source"] + qualifier_cols + feed_fact_cols
            # source and cve_id are not in the SET: cve_id is the key, and a
            # row's source is not the feed's to change.
            set_clause = ", ".join(
                f"{c} = excluded.{c}" for c in feed_cols
                if c not in ("cve_id", "source")
            )
            sql = (
                f"INSERT INTO runbook ({', '.join(feed_cols)}) "
                f"VALUES ({', '.join('?' * len(feed_cols))}) "
                f"ON CONFLICT(cve_id) DO UPDATE SET {set_clause} "
                f"WHERE runbook.source = 'cisa_kev'"
            )

            for v in vulns:
                try:
                    cve_id = str(v.get("cveID", "")).strip()
                    if not cve_id:
                        rejected += 1
                        continue

                    owner  = owners.get(cve_id)
                    vendor  = v.get("vendorProject", "")
                    product = v.get("product", "")

                    values = [
                        cve_id,
                        vendor,
                        product,
                        v.get("vulnerabilityName", ""),
                        v.get("shortDescription", ""),
                        v.get("requiredAction", ""),
                        v.get("dateAdded", ""),
                        v.get("dueDate", ""),
                        _kev_severity(v),
                        "cisa_kev",
                    ]
                    for c in qualifier_cols:
                        if c == "entry_kind":
                            # Every KEV entry is a real CVE, so 'vulnerability'
                            # is right. Written rather than left to the column
                            # default, because a default is a thing nobody
                            # decided.
                            values.append("vulnerability")
                        elif c == "applies_to":
                            values.append(_kev_applies_to(vendor, product))
                        else:
                            values.append(KEV_VERIFY_HINT)
                    for c in feed_fact_cols:
                        values.append(_kev_ransomware(v))

                    conn.execute(sql, values)

                    # Counted AFTER the write, so a row that threw is counted
                    # once, as rejected, and not also as a success.
                    if owner is None:
                        inserted += 1
                        # The feed can carry the same id twice. Without this
                        # the second copy would be counted as another insert,
                        # which is the same "report what you did not check"
                        # bug this whole change is about, just smaller.
                        owners[cve_id] = "cisa_kev"
                    elif owner == "cisa_kev":
                        updated += 1
                    else:
                        # A hand-written row wearing this id. The WHERE on the
                        # upsert made the statement a no-op. Counted out loud
                        # rather than folded into a success number.
                        skipped += 1
                except Exception:
                    rejected += 1

        self._synced = True
        logger.info(
            f"CISA KEV sync: {inserted} inserted, {updated} updated, "
            f"{skipped} skipped (hand-written row owns the id), {rejected} rejected"
        )
        return {"success": True, "inserted": inserted, "updated": updated,
                "skipped": skipped, "rejected": rejected}

    def _load_static_entries(self):
        """
        Upsert the static priors.

        REPLACE, not IGNORE. These rows are code, so the copy in the database
        must track the copy in this file, under the old INSERT OR IGNORE an
        existing install kept whatever it was first seeded with, which meant
        the uncorrected STATIC-001 would have survived this fix forever and
        gone on producing critical EternalBlue findings against Windows 11.

        Scoped to source='static' so a REPLACE can never touch a CISA KEV row.
        """
        from core.memory_engine import _get_conn

        updated = 0
        for entry in STATIC_ENTRIES:
            try:
                with _get_conn() as conn:
                    cols = {r["name"] for r in conn.execute("PRAGMA table_info(runbook)")}

                    # Tolerate a database that predates the qualifier columns:
                    # migrations add them, but the loader must not hard-fail if
                    # it somehow runs first.
                    extra_cols, extra_vals = [], []
                    for col in ("entry_kind", "applies_to", "verify_hint"):
                        if col in cols:
                            extra_cols.append(col)
                            extra_vals.append(entry.get(col))

                    existing = conn.execute(
                        "SELECT source FROM runbook WHERE cve_id = ?", (entry["cve_id"],)
                    ).fetchone()
                    if existing and existing["source"] != "static":
                        logger.warning(
                            f"{entry['cve_id']} exists with source="
                            f"{existing['source']!r}; not overwriting."
                        )
                        continue

                    names = ["cve_id", "vendor", "product", "vulnerability",
                             "known_ports", "remediation", "severity", "source"] + extra_cols
                    values = [entry["cve_id"], entry["vendor"], entry["product"],
                              entry["vulnerability"], entry["known_ports"],
                              entry["remediation"], entry["severity"],
                              entry["source"]] + extra_vals

                    conn.execute(
                        f"INSERT OR REPLACE INTO runbook ({', '.join(names)}) "
                        f"VALUES ({', '.join('?' * len(names))})",
                        values,
                    )
                    updated += 1
            except Exception as e:
                logger.warning(f"Static entry {entry.get('cve_id')} load error: {e}")

        logger.info(f"Runbook static priors loaded/refreshed: {updated}")
        return updated