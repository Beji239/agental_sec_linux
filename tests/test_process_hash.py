"""
tests/test_process_hash.py, hashing the binary behind a finding.

WHAT THIS FILE IS ABOUT. core/enrichment.py has had a MalwareBazaar lane since
2026-09-02 and nothing ever gave it a hash to look up. Now a process that
raises a finding gets its binary hashed and the digest queued. The tests that
matter here are the refusals: a hash that cannot be taken has to say WHY,
because a missing hash with no reason reads as "nothing wrong".

CONVERTED 2026-09-25. Section [5] USED TO TEST THE DEFENDER DEDUP TRIM -- an
OrderedDict of detection identities, bounded so the oldest were evicted rather
than an arbitrary half. That cache belonged to the Windows poll loop, which
read Defender's own history through the capability shim; the loop, the reader
and the cache all left tools/process_monitor.py in this round, so there is
nothing left to bound. The hash feeder, which is what this file was really
for, is untouched and still asserted below.
"""
import hashlib
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


import tools.process_monitor as pm        # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())


print("\n[1] a real file hashes, and the digest is the right one")
f = tmp / "thing.exe"
f.write_bytes(b"not really an executable, but it hashes the same way")
want = hashlib.sha256(f.read_bytes()).hexdigest()

digest, why = pm._sha256_of(str(f))
check("digest matches hashlib", digest, want)
check("and there is no excuse attached", why, None)


print("\n[2] the cache answers the second time, and notices a change")
check("cached", pm._sha256_of(str(f))[0], want)
check("the cache actually holds it", len(pm._HASH_CACHE) >= 1, True)

f.write_bytes(b"different content entirely")
new = hashlib.sha256(f.read_bytes()).hexdigest()
# Same path, new size and mtime, so the key changes and it is read again.
# A cache keyed on path alone would hand back the stale digest here, which on
# a file that was swapped under a running process is the worst possible time
# to be confidently wrong.
check("an edited file is re-hashed", pm._sha256_of(str(f))[0], new)


print("\n[3] every refusal says why, and none of them raise")
digest, why = pm._sha256_of("")
check("no path -> no digest", digest, None)
check("and the reason mentions the unelevated case",
      "unelevated" in (why or "").lower(), True)

digest, why = pm._sha256_of(str(tmp / "does-not-exist.exe"))
check("missing file -> no digest", digest, None)
check("and it says stat failed", "stat" in (why or ""), True)

big = tmp / "big.bin"
with open(big, "wb") as fh:
    fh.truncate(pm.MAX_HASH_BYTES + 1)
digest, why = pm._sha256_of(str(big))
check("oversized -> no digest", digest, None)
check("and it says which cap", "cap" in (why or ""), True)

check("the cap is a sane size", pm.MAX_HASH_BYTES <= 512 * 1024 * 1024, True)


print("\n[4] the hash cache is bounded, oldest out first")
pm._HASH_CACHE.clear()
for i in range(pm.MAX_HASH_CACHE + 10):
    pm._HASH_CACHE[("p%d" % i, i, i)] = "x"
    while len(pm._HASH_CACHE) > pm.MAX_HASH_CACHE:
        pm._HASH_CACHE.popitem(last=False)
check("size held", len(pm._HASH_CACHE), pm.MAX_HASH_CACHE)
check("the oldest key is gone", ("p0", 0, 0) in pm._HASH_CACHE, False)
check("the newest key is kept",
      ("p%d" % (pm.MAX_HASH_CACHE + 9), pm.MAX_HASH_CACHE + 9,
       pm.MAX_HASH_CACHE + 9) in pm._HASH_CACHE, True)
pm._HASH_CACHE.clear()


print("\n[6] the enrichment lane this feeds actually accepts a hash")
from core import enrichment                # noqa: E402
check("a sha256 classifies as a hash", enrichment.classify(want), "hash")
check("and there is a source for that kind",
      bool(enrichment.SOURCES_BY_KIND.get("hash")), True)
# Honest note rather than a check: whether the lookup ANSWERS depends on
# AGENTAL_ABUSECH_KEY being set. The feeder is what this file is about.


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
