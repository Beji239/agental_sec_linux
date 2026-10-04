"""
core/oui.py, who made this hardware address.

WHY THIS EXISTS, and it is a real story rather than a nice-to-have.

On 2026-09-01 the model found an always-on device on the LAN that was not in
the inventory, dug hard, and concluded it was a LIFX smart bulb. It was not.
The first three bytes of its address are registered to a company that is not
LIFX, and one lookup would have said so in a single call. The model could not
do that lookup, so it reasoned from broadcast ports instead, got a plausible
answer, and then went further and invented a supporting fact to back it up.
See TODO 36 and 37.

The lesson is not that the model was careless. It is that the CHEAPEST piece
of identifying evidence on a local network was not available to it, so it
spent its effort somewhere weaker. This module makes that evidence free.

WHAT IT IS: an offline lookup against the IEEE registry file, no network at
call time. `scripts/update_oui.py` fetches the file. Nothing here reaches the
internet, so it cannot hang, cannot leak an address off the machine, and works
the same whether or not this host has egress.

WHAT IT REFUSES TO DO. There are four different ways to not have a vendor and
they are NOT the same claim:

    resolved         the prefix is registered, here is the name
    randomized       locally administered address, so NO vendor exists at all
    unknown_prefix   the file is loaded and this prefix is genuinely not in it
    no_data          there is no file, so nothing is known either way

Collapsing those into "unknown" is exactly the failure this project keeps
writing rules about. `no_data` means ASK, `unknown_prefix` means the registry
really has no entry, and `randomized` is a positive finding about the device
rather than a gap in ours.
"""

import csv
import logging
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

# IEEE publishes three blocks at three prefix lengths. MA-L is the classic
# 24 bit OUI; MA-M and MA-S are longer prefixes carved out of it, so a hit on
# a longer one is MORE specific and has to win. Ordered longest first, which
# is how _match walks them.
REGISTRY_FILES = (
    ("mas.csv", 9),     # MA-S, 36 bit
    ("mam.csv", 7),     # MA-M, 28 bit
    ("oui.csv", 6),     # MA-L, 24 bit
)

# Wireshark's `manuf` file, added 2026-09-02 as a second accepted format.
# IEEE started answering the update script with HTTP 418, which is what a
# bot filter returns when it does not like the user agent, so having one
# source and one format turned out to be a single point of failure for
# something that is supposed to work offline forever. This file carries all
# three prefix lengths in one place and is a plain tab separated list.
MANUF_FILE = "manuf"

# The IEEE's own placeholder organisation, and the one string in this file that
# is matched by VALUE rather than by a flag. MEASURED 2026-09-27 on the shipped
# registry: 436 of 40,208 /24 rows carry it, and those are the rows whose blocks
# were subdivided into MA-M and MA-S assignments. See lookup().
_AUTHORITY_NAME = "ieee registration authority"


def _names_authority(org: str) -> bool:
    """Is this row the IEEE's delegating placeholder rather than a maker."""
    return (org or "").strip().lower() == _AUTHORITY_NAME

_tables: dict | None = None
_lock = threading.Lock()


def _normalise(mac) -> str | None:
    """Strip separators and upper-case. None if it is not a MAC at all."""
    if not mac:
        return None
    hexonly = "".join(c for c in str(mac).upper()
                      if c in "0123456789ABCDEF")
    # 12 hex characters is a 48 bit address. Anything shorter is not one, and
    # guessing at a truncated address is how you attribute the wrong vendor.
    return hexonly if len(hexonly) == 12 else None


def _load() -> dict:
    """
    Read the registry files once, keyed by prefix length.

    Returns {} when there is no data directory at all, which the caller must
    treat as no_data rather than as an empty registry. A missing file and an
    empty file mean different things here too: an empty file is a broken
    download and says so in the log.
    """
    global _tables
    if _tables is not None:
        return _tables

    with _lock:
        if _tables is not None:
            return _tables

        tables: dict = {}

        for filename, length in REGISTRY_FILES:
            path = DATA_DIR / filename
            if not path.exists():
                continue
            table = {}
            try:
                with path.open(newline="", encoding="utf-8") as fh:
                    for row in csv.DictReader(fh):
                        assignment = (row.get("Assignment") or "").strip().upper()
                        org = (row.get("Organization Name") or "").strip()
                        if assignment and org:
                            table[assignment] = (org, filename)
            except Exception as e:
                # Never raise into a caller. A broken registry file must not
                # be able to stop a device listing from rendering.
                logger.warning(f"oui: could not read {filename}: {e}")
                continue

            if table:
                tables[length] = table
                logger.info(f"oui: {filename} loaded, {len(table):,} prefixes")
            else:
                logger.warning(f"oui: {filename} is present but empty")

        _load_manuf(DATA_DIR / MANUF_FILE, tables)

        _tables = tables
        return _tables


def _load_manuf(path: Path, tables: dict):
    """
    Merge Wireshark's `manuf` file into the tables, if it is there.

    Format is tab separated, one prefix per line, comments start with #:

        5C:41:5A          Short          Longer Company Name
        00:55:DA:80:00:00/28    Short    Longer Company Name

    A bare prefix is 24 bit. The /28 and /36 forms are the same longer blocks
    the separate IEEE files carry, so they land in the same length buckets and
    the longest-prefix walk in lookup() keeps working unchanged.

    IEEE's own CSVs win where both are present. They are the primary source
    and this is the fallback, so it fills in rather than overwrites.
    """
    if not path.exists():
        return

    added = 0
    skipped_because_ieee = 0
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = [p for p in line.split("\t") if p.strip()]
                if len(parts) < 2:
                    continue

                prefix, *names = parts
                bits = 24
                if "/" in prefix:
                    prefix, _, raw_bits = prefix.partition("/")
                    try:
                        bits = int(raw_bits)
                    except ValueError:
                        continue

                hexonly = "".join(c for c in prefix.upper()
                                  if c in "0123456789ABCDEF")
                length = bits // 4
                if length not in (6, 7, 9) or len(hexonly) < length:
                    continue

                # The long name is the useful one. Wireshark's short name is
                # an abbreviation meant for a packet list column.
                org = (names[-1] if names else "").strip()
                if not org:
                    continue

                key = hexonly[:length]
                # IEEE's own CSVs are the primary source, so a manuf row does
                # not overwrite one. WHAT THE OVERLAP MEANS, MEASURED
                # 2026-09-27 on the real files: this function used to be silent
                # about it, and silence here is the difference between "the
                # fallback filled a gap" and "the fallback DISAGREES with the
                # file that won". A disagreement is worth a line because the
                # lookup's own answer carries `source`, so a reader can be told
                # which file the vendor came from.
                bucket = tables.setdefault(length, {})
                if key in bucket:
                    skipped_because_ieee += 1
                    if bucket[key][0].strip().lower() != org.lower():
                        logger.info(
                            f"oui: {path.name} calls {key} {org!r}, while "
                            f"{bucket[key][1]} calls it {bucket[key][0]!r}. "
                            f"The IEEE file wins, by this function's own rule.")
                    continue
                bucket[key] = (org, path.name)
                added += 1
    except Exception as e:
        logger.warning(f"oui: could not read {path.name}: {e}")
        return

    if added:
        logger.info(f"oui: {path.name} loaded, {added:,} prefixes"
                    + (f" ({skipped_because_ieee:,} already covered by an "
                       f"IEEE file)" if skipped_because_ieee else ""))
    elif skipped_because_ieee:
        logger.info(f"oui: {path.name} is present and adds nothing: all "
                    f"{skipped_because_ieee:,} of its prefixes are already "
                    f"covered by the IEEE files.")
    else:
        logger.warning(f"oui: {path.name} is present but nothing parsed out "
                       f"of it")


def reload():
    """Drop the cache. For tests, and for after running the update script."""
    global _tables
    with _lock:
        _tables = None


def is_locally_administered(mac) -> bool:
    """
    Bit 1 of the first octet. Set means software assigned the address.

    Same bit test as memory_engine.is_randomized_mac, kept here so this module
    stands alone and does not drag the database layer into a string lookup.
    """
    clean = _normalise(mac)
    if not clean:
        return False
    try:
        return bool(int(clean[0:2], 16) & 0b10)
    except ValueError:
        return False


def lookup(mac) -> dict:
    """
    Vendor for a hardware address. Always returns a dict, never raises.

        {"vendor": str|None, "status": str, "note": str}

    Read `status` before `vendor`. A None vendor means four different things
    and the status is the only thing that says which.
    """
    clean = _normalise(mac)
    if not clean:
        return {
            "vendor": None,
            "status": "unparseable",
            "note": "not a 48 bit hardware address, so there is nothing to "
                    "look up",
        }

    if is_locally_administered(clean):
        return {
            "vendor": None,
            "status": "randomized",
            "note": "locally administered address, assigned by software. NO "
                    "vendor is registered for it and none can be. This is a "
                    "fact about the device, usually MAC randomization on a "
                    "phone or laptop, not a gap in the lookup.",
        }

    tables = _load()
    if not tables:
        return {
            "vendor": None,
            "status": "no_data",
            "note": "no IEEE registry file on this machine, so the vendor is "
                    "UNKNOWN rather than absent. Run "
                    "scripts/update_oui.py. Do not infer a vendor from "
                    "behaviour while this says no_data.",
        }

    # WHICH TIERS ARE MISSING, AND WHY THAT MATTERS TO THIS ANSWER.
    #
    # Found and measured 2026-09-21 on a real partial fetch. IEEE answered
    # oui.csv and mam.csv and dropped the connection on mas.csv, and the old
    # code then walked from the 36 bit prefix down to the 24 bit parent and
    # returned `resolved -> 'IEEE Registration Authority'` for a device whose
    # maker is in the missing file. That is worse than no_data: it is a
    # confident answer about the wrong entity, and the entity it names is the
    # authority that DELEGATED the block rather than the one that built the
    # device.
    #
    # Measured on the shipped registry: 7,196 of the 7,196 MA-S blocks and
    # 6,468 of the 6,596 MA-M blocks have a 24 bit parent that names the
    # authority placeholder, so a missing tier does not degrade quietly here,
    # it changes the answer for essentially every 28 and 36 bit address.
    #
    # The answer is still RETURNED, because the /24 registration is a true
    # fact about the block, and refusing it outright would throw away a real
    # reading for hardware whose parent is a genuine registrant. What changes
    # is that the answer says it is short, so a reader is not told a
    # delegating authority is the manufacturer.
    loaded = set(tables)
    missing_lengths = sorted({length for _, length in REGISTRY_FILES} - loaded)
    short_of = [n for n in missing_lengths if n > 0]

    for length in sorted(tables, reverse=True):
        hit = tables[length].get(clean[:length])
        if hit:
            org, source = hit
            note = (f"registered {length * 4} bit prefix, from {source}. "
                    f"This is who registered the address block, which is "
                    f"the manufacturer of the network part. It is not "
                    f"necessarily the brand on the box.")
            shorter = [n for n in short_of if n > length]
            if shorter:
                note += (f" THIS ANSWER IS SHORT: the "
                         + " and ".join(f"{n * 4} bit" for n in shorter)
                         + f" registry is not on disk, so it was read from "
                         f"the next shorter prefix up. On the shipped data "
                         f"those parent rows name the registering authority "
                         f"rather than the maker, so treat the vendor above "
                         f"as the holder of the block and not as this "
                         f"device's manufacturer. Run "
                         f"scripts/update_oui.py to fill the gap.")
            # THE OTHER WAY AN ANSWER IS SHORT, and the warning above never
            # covered it. That check looks for a whole TIER missing from disk.
            # MEASURED 2026-09-27 on the shipped registry: of the 436 /24 rows
            # whose own organisation is 'IEEE Registration Authority', 508 of
            # their /28 slots are NOT in mam.csv. For one of those, every tier
            # is present and the walk STILL lands on the authority row, so
            # `short_of` is empty and nothing is said.
            #
            # The example that was driven through the shipped lookup:
            #     B8:4C:87:F0:00:00 -> resolved, 'IEEE Registration Authority'
            # while the SAME parent's sibling slots answer with real makers
            # (B8:4C:87:00 -> 'Annapurna labs', B8:4C:87:10 -> 'em-trak').
            # The module's own header calls this shape worse than no_data: it
            # is a confident answer naming a delegating body as the maker, and
            # the model's lesson (TODO 36) is that it is exactly this lookup
            # that must not mislead.
            #
            # The answer still stands -- the /24 registration is a true fact --
            # and the note now says the block was subdivided.
            if _names_authority(org) and not shorter:
                longer_loaded = [n for n in sorted(loaded, reverse=True)
                                 if n > length]
                if longer_loaded:
                    note += (f" THE BLOCK IS SUBDIVIDED: this prefix is "
                             f"registered to the IEEE's own registering "
                             f"authority, which means it was carved into "
                             f"longer blocks assigned to real registrants, and "
                             f"this address is not in any of those in the "
                             f"registry on disk. So the name above is the "
                             f"body that DELEGATED the block, not the maker "
                             f"of this device, and no vendor can be named for "
                             f"it. Do not read it as the manufacturer.")
            return {
                "vendor": org,
                "status": "resolved",
                # The file it came from is part of the answer. This whole
                # module exists because a claim got made without a source
                # behind it, so it would be a poor joke to return one.
                "source": source,
                "note": note,
            }

    return {
        "vendor": None,
        "status": "unknown_prefix",
        "note": "the registry is loaded and this prefix is genuinely not in "
                "it. Either the file is out of date or the address is not a "
                "registered one.",
    }


# vendor_of() was here, a one-line wrapper round lookup()["vendor"]. Deleted
# 2026-09-03: only the test suite ever called it, and a convenience with no
# real caller is a second way of asking the same question that somebody has
# to keep in step with the first.


def status() -> dict:
    """
    What this module can currently do. For a boot line or a health panel.

    READINESS IS MEASURED PER PREFIX LENGTH, NOT PER FILE, and that is the
    whole design of this function. Narrowed 2026-09-21 off a real partial
    fetch: with mas.csv absent the old code said `ready: True` and main.py
    printed a healthy boot line, while every 36 bit address in the room was
    answered from its 24 bit parent, which on the shipped data names IEEE
    rather than the maker.

    Counting lengths rather than filenames is what lets the Wireshark `manuf`
    fallback count as covering a missing IEEE tier: it carries all three
    lengths in one file (measured: 39,960 /24 rows, 6,593 /28, 11,768 /36), so
    a tree with no mas.csv but a good manuf is genuinely complete and must not
    be reported as short.

    `missing` names the tiers that are absent, by the IEEE file that would
    have carried them. A tier already filled in by the Wireshark `manuf`
    fallback is NOT listed, because it is not missing: the answer is complete
    and saying otherwise would send the operator to fetch a file they already
    have the content of.
    """
    tables = _load()
    loaded = set(tables)
    expected = {length for _, length in REGISTRY_FILES}
    missing_lengths = sorted(expected - loaded)

    missing = [f for f, length in REGISTRY_FILES if length in missing_lengths]

    # HOW OLD THE FILES ARE, since 2026-09-27. This is the one fact status()
    # did not carry, and it is the one an operator needs: `ready: True` says
    # every prefix length is answerable and says nothing about whether the
    # assignments in it are current. IEEE reassigns blocks, so a registry that
    # is years old will name the previous holder of a block with the same
    # confidence as the current one. The file's own mtime is the only age this
    # module has -- scripts/update_oui.py re-fetches on a 90 day clock -- so it
    # is reported here for a boot line or a health panel to use.
    ages = {}
    for filename, _length in REGISTRY_FILES:
        path = DATA_DIR / filename
        try:
            if path.exists():
                ages[filename] = round(
                    (time.time() - path.stat().st_mtime) / 86400, 1)
        except OSError:
            pass
    oldest = max(ages.values()) if ages else None

    return {
        "ready": not missing_lengths,
        "prefixes": sum(len(t) for t in tables.values()),
        "files": sorted([f for f, n in REGISTRY_FILES
                         if (DATA_DIR / f).exists()]
                        + ([MANUF_FILE] if (DATA_DIR / MANUF_FILE).exists()
                           else [])),
        # Empty on a complete registry, and empty on a machine with no
        # registry at all, since `ready` already says that and naming three
        # missing files would make "nothing fetched yet" read as "the
        # download went wrong".
        "missing": missing if tables else [],
        # Nothing loaded at all is its own state, and it is NOT the same as a
        # partial one: no_data means ask, a short answer means the name you
        # were given holds the block rather than built the device.
        "loaded_lengths": sorted(loaded, reverse=True),
        # Days old, per file, and the oldest of them. None when nothing is on
        # disk. See the note above: a complete registry is not a current one.
        "file_age_days": ages,
        "oldest_days": oldest,
        "data_dir": str(DATA_DIR),
    }
