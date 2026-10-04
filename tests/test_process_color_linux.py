"""
tests/test_process_color_linux.py, the Processes page on LINUX.

2026-09-23, found by looking at the running dashboard rather than at the code:
every row on the Processes tab was GREY, which is the colour this app uses for
"could not be read". 214 of 214 on the machine this was written on.

THE CAUSE, measured before anything was changed. `process_table` colours each
row with `trust_of`, which colours from what `signatures_for` said. That
function is an Authenticode check written for Windows: it runs PowerShell, and
on anything that is not Windows it returns, for every path it is handed, a note
saying exactly that. So on Linux EVERY row arrives at `trust_of` with an
unknown status, `trust_of` does the only thing it can with an unknown status,
and the page says "could not be read" about a machine where most of the
processes are packaged system binaries.

    python3 -c "from tools import process_monitor as pm; \
                print(pm.process_table(limit=400)['counts'])"
    -> {'bad': 0, 'watch': 0, 'ok': 0, 'unknown': 214}      BEFORE
    -> the same call now                                     AFTER

WHAT THE COLOUR RESTS ON HERE INSTEAD. Linux has no Authenticode. What it has
is the package manager, and it is a better answer than a signature for the
question this page is actually asking:

    ownership   dpkg-query -S says which package a file belongs to
    contents    that package's own md5sums record versus the file on disk
    kernel      a kernel thread has no file at all, and saying so is a fact,
                not a failure to read something

Everything below runs against THIS MACHINE, for real: the real process table,
the real dpkg database. The two paths that cannot be produced on a live host
without damaging it (a tampered package file, a file no package claims) are
driven by patching the one function that reads the package records, so the
comparison logic is still what is under test.

Runs anywhere Linux does. No network, no writes to the real database.
"""
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db                              # noqa: E402
_isolate_db.isolate()

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


from tools import process_monitor as pm         # noqa: E402

print("\n[0] this file is about Linux, and this host is Linux")
check("the module sees the same platform this test does", os.name, "posix")
check("no PowerShell anywhere in the path being tested",
      pm._dpkg_query_path() is not None, True)


print("\n[1] THE DEFECT: the page must not paint packaged binaries grey")
table = pm.process_table(limit=400)
check("the table came back", table["available"], True)
total = table["total"]
counts = table["counts"]
unknown = counts.get("unknown", 0)
print(f"    {total} processes: {counts}")
check_true("there are processes to colour", total > 20)

# THE NUMBER THAT WAS 100 PERCENT. A machine where MOST rows could not be read
# is not a machine with a reading problem, it is a page with a broken basis,
# and this is the assertion that says so.
check_true("most rows are NOT 'could not be read'",
           unknown <= total * 0.15)
check_true("and the packaged system binaries are recognised as such",
           counts.get("ok", 0) > 20)

check("every row still has a colour from the fixed set",
      all(r.get("trust") in pm.TRUST_LEVELS for r in table["processes"]), True)
check("the counts still add up to the total",
      sum(table["counts"].values()), total)
check_true("every row can say why it is that colour",
           all((r.get("trust_reason") or "").strip() for r in table["processes"]))

# THE WORDS, because a colour whose reason is about the wrong operating system
# is how this went unnoticed for a fortnight.
check("no row explains itself in terms of Windows",
      [r["pid"] for r in table["processes"] if "windows" in
       (r.get("trust_reason") or "").lower()], [])
check("and the page's own summary does not either",
      "windows" in (table.get("signature_check") or "").lower(), False)
check_true("the summary says what the colours actually rest on",
           "package" in (table.get("signature_check") or "").lower())


print("\n[2] a packaged binary is recognised, and the package is named")
sig = pm.signatures_for(["/usr/bin/bash"], {})
bash = sig.get("/usr/bin/bash") or {}
check("its file matches what the bash package shipped", bash.get("status"), "Valid")
check("and the row names the package", bash.get("signer"), "bash")
check("and says what was compared, not 'signed'",
      "bash" in (bash.get("label") or ""), True)
level, why = pm.trust_of({"exe": "/usr/bin/bash", "signature": bash})
check("so the row is green", level, "ok")
check("and the reason names the package too", "bash" in why, True)

# A SYMLINKED ONE: /sbin/init is what the process table reports for PID 1 and
# dpkg has never heard of /sbin/init, only of /usr/lib/systemd/systemd. This is
# the same class of bug as the Windows tree's drive-letter work: two places
# doing their own string handling on a path.
init = pm.signatures_for(["/sbin/init"], {}).get("/sbin/init") or {}
check("a symlinked system binary resolves to its package", init.get("status"), "Valid")
check("and names it", init.get("signer"), "systemd")

check("a path that does not exist is never called clean",
      (pm.signatures_for(["/no/such/file/at/all"], {}).get("/no/such/file/at/all")
       or {}).get("status") != "Valid", True)


print("\n[3] a kernel thread is a fact, not a failure to read")
threads = [r for r in table["processes"] if r.get("trust") == "kernel"]
check_true("the kernel threads are identified as such", len(threads) > 5)
one = threads[0] if threads else {}
print(f"    e.g. pid {one.get('pid')} {one.get('name')}: {one.get('trust_reason')}")
check("none of them is claimed to be a checked file",
      any("file" in (r.get("trust_reason") or "") and
          "not" not in (r.get("trust_reason") or "") for r in threads), False)
check("and each says what it is",
      all("kernel" in (r.get("trust_reason") or "").lower() for r in threads), True)
# THE CONTROL. A kernel thread is exactly: no executable, no command line, and
# either it is kthreadd or kthreadd is its parent. Anything else with no path
# is a process we could not read, and that must stay grey rather than be
# quietly promoted to "kernel" to make the page look better.
check("a process with a command line is never called a kernel thread",
      pm._is_kernel_thread({"pid": 4242, "exe": None, "cmdline": "x",
                            "parent_pid": 2}), False)
check("nor is one whose parent is not kthreadd",
      pm._is_kernel_thread({"pid": 4242, "exe": None, "cmdline": None,
                            "parent_pid": 1}), False)
check("a row we could not read stays grey",
      pm.trust_of({"exe": None, "signature": {"status": "unknown",
                                              "note": "its executable could "
                                                      "not be read"}})[0],
      "unknown")


print("\n[4] a file no package claims is amber, and says which folder it is in")
# NOT PRODUCIBLE ON THIS HOST WITHOUT TOUCHING IT, so the reader is patched.
# What is under test is what the page does with an unowned file, not whether
# this particular machine happens to have one.
_real_owner_map = pm._package_owner_map
_python = os.path.realpath(sys.executable)
try:
    pm._package_owner_map = lambda paths: {}
    # THE ANSWER IS CACHED ON (path, size, mtime), so a patched reader is not
    # consulted for a file that was already checked a few lines ago. That is
    # correct behaviour and it is what the first run of this test tripped
    # over: section [2] had put /usr/bin/python3.12 in the cache as Valid.
    pm._SIG_CACHE.clear()
    unowned = pm.signatures_for([_python], {}).get(_python) or {}
finally:
    pm._package_owner_map = _real_owner_map
    pm._SIG_CACHE.clear()

check("an unowned file is not called valid", unowned.get("status"), "NotSigned")
check("and the label says the package database was asked",
      "no installed package" in (unowned.get("label") or ""), True)
level, why = pm.trust_of({"exe": _python, "signature": unowned})
check("so it is a look, not a verdict", level, "watch")
# AND THE CONTROL: with the real reader it is green, or the check above would
# pass on a function that calls everything unowned.
again = pm.signatures_for([_python], {}).get(_python) or {}
check("the same file, unpatched, is owned and valid", again.get("status"), "Valid")


print("\n[5] a packaged file that has been CHANGED is not called valid")
# THE ONE CASE THIS PAGE EXISTS FOR. Driven the same way: the record the
# package keeps is patched to a digest that cannot match.
_real_md5 = pm._md5sums_for


def _tampered(package):
    out = dict(_real_md5(package))
    for path in list(out):
        out[path] = "0" * 32
    return out


try:
    pm._md5sums_for = _tampered
    pm._SIG_CACHE.clear()
    bad = pm.signatures_for(["/usr/bin/bash"], {}).get("/usr/bin/bash") or {}
finally:
    pm._md5sums_for = _real_md5
    pm._SIG_CACHE.clear()

check("a changed file is not valid", bad.get("status"), "HashMismatch")
check("and the row says it does not match what the package shipped",
      "does NOT match" in (bad.get("label") or ""), True)
check("and the row is amber rather than silent",
      pm.trust_of({"exe": "/usr/bin/bash", "signature": bad})[0], "watch")


print("\n[6] the sweep still counts what happened rather than shrugging")
# The four keys are what the Windows sweep has always published and what the
# page's summary line is built from. A new basis must not quietly change the
# shape of the stats dict, because test_process_inspection asserts this key set.
stats = {}
pm.signatures_for(["/no/such/file/at/all"], stats)
check("the stats dict still has exactly the four documented keys",
      sorted(stats), ["cached", "checked", "failed", "not_reached"])


print("\n[7] the deep look on one row uses the same basis")
out = pm.inspect_process(os.getpid())
check("it found this process", out["found"], True)
p = out["process"]
check_true("the executable was hashed", len(p["sha256"] or "") == 64)
check("the signature answer comes from the package records",
      (p["signature"] or {}).get("signer") is not None, True)
check("and the ceiling sentence describes what was actually compared",
      "package" in p["how_to_read_this"].lower(), True)
check("and does not talk about Authenticode on Linux",
      "authenticode" in p["how_to_read_this"].lower()
      or "signed by its publisher" in p["how_to_read_this"].lower(), False)


print("\n[8] the page has a colour for it, wired all the way through")
ui = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
check("the fifth colour is in the fixed set",
      "kernel" in pm.TRUST_LEVELS, True)
check("the page has a label for it", "kernel:" in ui, True)
check("a dot for it", ".p-kernel" in ui, True)
check("and a segment in the bar", ".t-kernel" in ui, True)
check("the bar draws every level the backend can send",
      all(f"'{lvl}'" in ui.split("const order")[1][:200] for lvl in pm.TRUST_LEVELS
          if lvl != "unknown"), True)
# The page must not claim a Windows basis in its own prose either.
check("the tab no longer says Task Manager",
      "the same place Task Manager reads it" in ui, False)
check("and does not promise a signature check it cannot do",
      "checking signatures. The first load takes a moment" in ui, False)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
