"""
tests/test_sql_injection.py, SQL built from pieces must not take outside data.

Part 1 reads every execute() in the app and traces where each piece spliced
into the SQL text comes from. Literal text and UPPER_CASE constants pass; any
other origin must be in REVIEWED with the reason it is safe, so a new
string-built query fails here until someone has looked at it.

Part 2 pushes hostile strings through every query function's text arguments
on a scratch database. A syntax error, a changed schema or changed row counts
means the input reached the SQL text.
"""
import ast
import importlib
import inspect
import pathlib
import re
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _isolate_db  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

failures = []


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)
        if detail:
            print(f"        {detail}")


# Part 1, the static trace

EXEC = {"execute", "executemany", "executescript"}
SAFE_CALLS = {"len", "int", "range", "max", "min"}

# (file, function): why the non-literal pieces there cannot carry outside data.
REVIEWED = {
    ("core/duty.py", "_emergency_measure"):
        "clause names fixed columns, addresses go in as ? parameters",
    ("core/integrity.py", "seal_row"):
        "table_name must be a key of SEALED_TABLES, refused otherwise",
    ("core/integrity.py", "_trim_consistent"):
        "only called with table == 'session_log'",
    ("core/memory_engine.py", "_completeness"):
        "table is a literal at every caller, where is built from fixed text",
    ("core/memory_engine.py", "_with_total"):
        "table is a literal at every caller, where is built from fixed text",
    ("core/memory_engine.py", "query_packets"):
        "_packet_conditions emits fixed text, values go in as parameters",
    ("core/memory_engine.py", "packet_search_scope"):
        "_packet_conditions emits fixed text, values go in as parameters",
    ("core/memory_engine.py", "unmerge_device"):
        "column names kept only when a real column or in _MERGE_MOVED_FLAGS",
    ("core/memory_engine.py", "suppress_detection"):
        "_suppression_scope emits fixed text, values go in as parameters",
    ("core/memory_engine.py", "unsuppress_detection"):
        "_suppression_scope emits fixed text, values go in as parameters",
    ("core/migrations.py", "_columns"):
        "table is a literal at every caller",
    ("core/migrations.py", "create_fresh_database"):
        "runs the project's own Schema.SQL",
    ("core/retention.py", "_payload_expr"):
        "table comes from PRUNABLE, columns from PRAGMA table_info",
    ("core/retention.py", "session_inventory"):
        "table comes from PRUNABLE, columns from PRAGMA table_info",
    ("core/timeline.py", "timeline_rows"):
        "one fixed SELECT per record kind",
    ("tools/background_actions_linux.py", "_journal_update"):
        "column names are keyword names written in that file",
    ("tools/place_watch.py", "_cursor"):
        "table and time column are literals at both callers",
}


def _pieces(node):
    """Spliced sub-expressions of a string-building expression, else None."""
    if isinstance(node, ast.Constant):
        return []
    if isinstance(node, ast.JoinedStr):
        return [v.value for v in node.values
                if isinstance(v, ast.FormattedValue)]
    if isinstance(node, ast.BinOp):
        out = []
        for side in (node.left, node.right):
            p = _pieces(side)
            out += p if p is not None else [side]
        return out
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"):
        return list(node.args) + [k.value for k in node.keywords]
    if isinstance(node, ast.IfExp):
        return [node.body, node.orelse]
    return None


def _is_const(name):
    return name.lstrip("_").isupper()


class _Fn:
    """Where each local name in one function gets its value."""

    def __init__(self, fn):
        a = fn.args
        self.params = {x.arg for x in a.args + a.kwonlyargs}
        self.params |= {x.arg for x in (a.vararg, a.kwarg) if x}
        self.defs = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    self._bind(t, n.value)
            elif isinstance(n, (ast.AugAssign, ast.AnnAssign)) and n.value:
                self._bind(n.target, n.value)
            elif isinstance(n, (ast.For, ast.comprehension)):
                self._bind(n.target, n.iter)
            elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr in ("append", "extend", "insert")
                  and isinstance(n.func.value, ast.Name) and n.args):
                self.defs.setdefault(n.func.value.id, []).append(n.args[-1])

    def _bind(self, target, value):
        names = (target.elts if isinstance(target, ast.Tuple) else [target])
        for t in names:
            if isinstance(t, ast.Name):
                self.defs.setdefault(t.id, []).append(value)

    def origins(self, e, seen=frozenset()):
        """Leaf origins other than literal text, as short strings."""
        if isinstance(e, ast.Constant):
            return set()
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            return set().union(*[self.origins(x, seen) for x in e.elts])
        if isinstance(e, ast.Dict):
            return set().union(*[self.origins(k, seen) for k in e.keys if k])
        sub = _pieces(e)
        if sub is not None:
            return set().union(*[self.origins(x, seen) for x in sub])
        if isinstance(e, ast.Name):
            if e.id in seen:
                return set()
            if e.id in self.defs:
                r = set().union(*[self.origins(d, seen | {e.id})
                                  for d in self.defs[e.id]])
                return r | ({"param:" + e.id} if e.id in self.params else set())
            if e.id in self.params:
                return {"param:" + e.id}
            return set() if _is_const(e.id) else {"name:" + e.id}
        if isinstance(e, ast.Attribute) and _is_const(e.attr):
            return set()
        if isinstance(e, ast.Call):
            f = e.func
            if isinstance(f, ast.Name) and f.id in SAFE_CALLS:
                return set()
            if isinstance(f, ast.Name) and f.id in ("str", "sorted", "list",
                                                    "enumerate", "zip"):
                return set().union(*[self.origins(a, seen) for a in e.args])
            if isinstance(f, ast.Attribute) and f.attr in (
                    "join", "keys", "items", "values", "replace", "strip",
                    "upper", "lower", "get"):
                r = self.origins(f.value, seen)
                if f.attr in ("join", "replace", "get"):
                    r |= set().union(*[self.origins(a, seen) for a in e.args])
                return r
        if isinstance(e, (ast.GeneratorExp, ast.ListComp)):
            return self.origins(e.elt, seen)
        if isinstance(e, ast.Subscript):
            return self.origins(e.value, seen)
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Mult):
            return self.origins(e.left, seen)
        return {"expr:" + ast.unparse(e)[:60]}


def scan():
    """{(file, function): [(line, origins)]} for every non-literal SQL text."""
    files = [p for d in ("core", "tools", "api", "ebpf")
             for p in sorted((ROOT / d).rglob("*.py"))]
    files += [ROOT / "main.py", ROOT / "adapters.py"]
    found, calls = {}, 0
    for f in files:
        rel = str(f.relative_to(ROOT))
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            tracer = None
            for n in ast.walk(fn):
                if not (isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute)
                        and n.func.attr in EXEC and n.args):
                    continue
                calls += 1
                tracer = tracer or _Fn(fn)
                o = tracer.origins(n.args[0])
                if o:
                    found.setdefault((rel, fn.name), []).append(
                        (n.lineno, sorted(o)))
    return found, calls


print("Part 1, every execute() traced")
found, calls = scan()
check(f"the trace read the app's queries ({calls} execute calls)", calls > 500)
for key in sorted(found):
    if key not in REVIEWED:
        for line, o in found[key]:
            check(f"{key[0]}:{line} {key[1]} splices {', '.join(o)} "
                  "into SQL and is not reviewed", False,
                  "Use ? parameters, or check it and add it to REVIEWED.")
stale = sorted(set(REVIEWED) - set(found))
check("every REVIEWED entry still exists", not stale,
      f"remove: {stale}")
print(f"  {len(found)} reviewed functions splice non-literal pieces")

# Part 2, hostile strings through the real query functions

# Each calls canary() once spliced into SQL text, in a different quoting.
PAYLOADS = [
    "x' OR canary() OR '",
    "x' OR canary() --",
    "x\" OR canary() OR \"",
    "x') OR canary() OR ('",
    "x')) OR canary() --",
    "1 OR canary()",
    "canary()",
    "ASC, canary()",
    "%' OR canary() --",
    "x'; DROP TABLE findings; --",
]
BENIGN = "zz-no-such-value"
INJECTED = ("syntax error", "unrecognized token", "incomplete input",
            "no such column", "no such function")

QUERY_MODULES = ["core.memory_engine", "core.actions", "core.duty",
                 "core.incident", "core.predictions", "core.questions",
                 "core.timeline", "core.place_map", "core.case_memory"]
PREFIXES = ("query_", "list_", "count_", "timeline_rows", "process_pairs",
            "packet_search_scope", "similar_incidents", "worst_finding")
REQUIRED = {"entity_type": "ip", "entity_value": "203.0.113.5",
            "behavior_key": "k", "ips": ["203.0.113.5"]}


def _snapshot(path):
    c = sqlite3.connect(path)
    try:
        schema = c.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY name").fetchall()
        counts = {t: c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                  for (kind, t, _) in schema if kind == "table"}
    finally:
        c.close()
    return schema, counts


# Every connection the app opens gets canary(), which counts its calls.
CANARY = []
_connect = sqlite3.connect


def _connect_with_canary(*a, **kw):
    conn = _connect(*a, **kw)
    conn.create_function("canary", 0, lambda: CANARY.append(1) or 0)
    return conn


sqlite3.connect = _connect_with_canary


def _error(f, kwargs):
    try:
        f(**kwargs)
    except sqlite3.Error as e:
        return str(e)
    except Exception:                                     # noqa: BLE001
        return None
    return None


print("\nPart 2, hostile strings through the query functions")
def _seed(path):
    """One row in every table, so a WHERE or ORDER BY has a row to run on."""
    c = _connect(path)
    seeded = 0
    try:
        tables = [r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'")]
        for t in tables:
            cols = c.execute(f'PRAGMA table_info("{t}")').fetchall()
            if not cols or "fts" in t:
                continue
            vals = []
            for _, name, ctype, _, _, pk in cols:
                ctype = (ctype or "").upper()
                vals.append(None if pk and "INT" in ctype
                            else 1 if "INT" in ctype or "REAL" in ctype
                            else "2026-01-01 00:00:00" if name.endswith(("_at", "since"))
                            else "203.0.113.5" if "ip" in name
                            else "seed")
            names = [col[1] for col in cols]
            # A refused value is replaced by the first one the CHECK allows.
            for _ in range(len(cols) + 1):
                try:
                    c.execute(f'INSERT INTO "{t}" VALUES '
                              f'({", ".join("?" * len(vals))})', vals)
                    seeded += 1
                    break
                except sqlite3.Error as e:
                    m = re.search(r"failed: (?:\w+ IS NULL OR )?(\w+) IN "
                                  r"\('([^']*)'", str(e))
                    if m and m.group(1) in names:
                        vals[names.index(m.group(1))] = m.group(2)
                        continue
                    m = re.search(r"NOT NULL constraint failed: \w+\.(\w+)",
                                  str(e))
                    if m and m.group(1) in names:
                        vals[names.index(m.group(1))] = 1
                        continue
                    break
        c.commit()
    finally:
        c.close()
    return seeded, len(tables)


db = _isolate_db.isolate()
seeded, ntables = _seed(db)
print(f"  seeded {seeded} of {ntables} tables with one row")
before = _snapshot(db)
tried = hits = 0
for modname in QUERY_MODULES:
    mod = importlib.import_module(modname)
    for name, f in inspect.getmembers(mod, inspect.isfunction):
        if f.__module__ != modname or not name.startswith(PREFIXES):
            continue
        sig = inspect.signature(f)
        base, text_args, runnable = {}, [], True
        for p in sig.parameters.values():
            if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                continue
            if p.default is p.empty:
                if p.name not in REQUIRED:
                    runnable = False
                    break
                base[p.name] = REQUIRED[p.name]
            if p.default is None or isinstance(p.default, str):
                text_args.append(p.name)
        if not runnable:
            continue
        text_args += [a for a in REQUIRED if a in base
                      and isinstance(base[a], str)]
        for arg in text_args:
            benign_err = _error(f, {**base, arg: BENIGN})
            for payload in PAYLOADS:
                tried += 1
                called = len(CANARY)
                err = _error(f, {**base, arg: payload})
                hit = len(CANARY) > called or (
                    err and err != benign_err
                    and any(s in err.lower() for s in INJECTED))
                if hit:
                    hits += 1
                    check(f"{modname}.{name}({arg}={payload!r})", False,
                          f"reached the SQL text: {err or 'canary() ran'}")

check(f"no hostile string reached the SQL text ({tried} calls)",
      hits == 0 and tried > 300)
after = _snapshot(db)
check("the schema is unchanged", before[0] == after[0])
check("no table gained or lost rows", before[1] == after[1],
      str({t: (before[1].get(t), n) for t, n in after[1].items()
           if before[1].get(t) != n}))

print(f"\n{'FAILED' if failures else 'ALL PASSED'}"
      f"{f': {len(failures)} check(s)' if failures else ''}")
sys.exit(1 if failures else 0)
