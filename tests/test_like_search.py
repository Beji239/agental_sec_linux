"""
tests/test_like_search.py, a typed %, _ or backslash in a search box matches
itself, not any text (SEC-1).

On a scratch database, through the real query functions: a search for
"a_b" finds a_b and not axb, "100%" finds 100% and not 1000, and an
ordinary search still finds what it always found.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
db = _isolate_db.isolate()

from core import memory_engine as me  # noqa: E402
from core import migrations  # noqa: E402

migrations.run_migrations(db)
failures = []


def check(label, got, want):
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: {got!r}")
    if not ok:
        failures.append(label)
        print(f"        want {want!r}")


print("The pattern")
check("special characters are escaped", me.like_contains("a_b%c\\d"),
      "%a\\_b\\%c\\\\d%")
check("plain text is only wrapped", me.like_contains("example"), "%example%")

with me._get_conn() as conn:
    for i, name in enumerate(("a_b.example", "axb.example", "100%.example",
                              "1000.example", "back\\slash.example")):
        conn.execute(
            "INSERT INTO dns_queries (queried_at, client_ip, domain, source, "
            "source_row_id) VALUES ('2026-10-13 10:00:00', '192.0.2.5', ?, "
            "'test', ?)", (name, f"r{i}"))
        conn.execute(
            "INSERT INTO tls_hello (first_seen, last_seen, src_ip, dst_ip, "
            "dst_port, sni, sni_state) VALUES ('2026-10-13 10:00:00', "
            "'2026-10-13 10:00:00', '192.0.2.5', '198.51.100.9', 443, ?, "
            "'present')", (name,))
    conn.commit()


def dns(term):
    r = me.query_dns(domain=term)
    rows = r["rows"] if isinstance(r, dict) else r
    return sorted(x["domain"] for x in rows)


def tls(term):
    r = me.query_tls(sni=term)
    rows = r["rows"] if isinstance(r, dict) else r
    return sorted(x["sni"] for x in rows)


print("\nDNS lookups")
check("an underscore is an underscore", dns("a_b"), ["a_b.example"])
check("a percent sign is a percent sign", dns("100%"), ["100%.example"])
check("a backslash is a backslash", dns("back\\slash"), ["back\\slash.example"])
check("a bare percent finds only names holding one", dns("%"), ["100%.example"])
check("an ordinary search still finds", dns("example"),
      sorted(["1000.example", "100%.example", "a_b.example", "axb.example",
              "back\\slash.example"]))

print("\nTLS names")
check("an underscore is an underscore", tls("a_b"), ["a_b.example"])
check("a percent sign is a percent sign", tls("100%"), ["100%.example"])

print(f"\n{'FAILED' if failures else 'ALL PASSED'}")
sys.exit(1 if failures else 0)
