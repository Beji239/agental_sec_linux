#!/usr/bin/env python3
"""
Which Windows-derived code is still in the Linux tree, and is each one
NECESSARY for functionality on this host?

The owner's rule, 2026-09-21: "no windows related code comes to the linux
version of the App unless its necessary for the functionality of the code, so
is the folder, unless its necessary not even in the folder."

The test is therefore never "does it mention Windows". It is:

    if this file were deleted right now, would anything on this host stop
    working?

Which is answered from the tree, not by judgement:
  reachable    imported by another module, or loaded by main.py's role table,
               or in a package __init__
  live_linux   has a real branch that runs on this host (a _linux path, or a
               non-Windows implementation it dispatches to)
  win_module   imports a Windows-only module at module level WITHOUT a guard
  win_only     the whole file is a Windows implementation

A file that is win_only AND unreachable is the case the rule is about.
"""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WIN = ROOT.parent / "agental_sec"

# WHERE THE WINDOWS-ONLY MATERIAL LIVES NOW.
#
# The owner's rule, 2026-09-21: no Windows-only code in the Linux tree, and
# not the folder either, unless it is necessary. So the reference material was
# moved OUT of the tree entirely and now sits beside the two source folders,
# where neither platform ships it. This script looks for it there, and its job
# is to prove nothing LIVE reaches it.
REFERENCE_DIR = ROOT.parent / "agental_sec_win32_reference"

WIN_MODULES = {"winreg", "win32api", "win32con", "win32evtlog", "win32security",
               "win32file", "win32service", "win32event", "win32process",
               "wintypes", "pythoncom", "pywintypes", "wmi"}


def all_py():
    out = [p for p in ROOT.glob("*.py") if p.is_file()]
    for d in ("core", "tools", "api", "scripts", "tests"):
        out += sorted((ROOT / d).rglob("*.py"))
    return out


def module_name(path):
    rel = path.relative_to(ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def parse_all():
    trees = {}
    for p in all_py():
        try:
            trees[p] = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, UnicodeDecodeError):
            pass
    return trees


def resolve_imports(tree, this_mod):
    """Every module path this file imports, in dotted form.

    Handles `import a.b`, `from a import b` (which may mean a.b, a module, or
    a NAME from a - all three are recorded and filtered by existence later),
    and relative imports.
    """
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                found.add(n.name)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:                       # from . import x
                pkg = ".".join(this_mod.split(".")[:-(node.level)] or [])
                base = f"{pkg}.{base}".strip(".") if base else pkg
            for n in node.names:
                found.add(n.name if not base else f"{base}.{n.name}")
                if base:
                    found.add(base)
    return found


def windows_imports(tree):
    hard, guarded = [], []
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Import):
            targets = [(n.name, node) for n in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            targets = [(node.module, node)]
        for name, _ in targets:
            root = name.split(".")[0]
            if root in WIN_MODULES:
                hard.append(name)
        if isinstance(node, ast.Try):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Import):
                    for n in sub.names:
                        if n.name.split(".")[0] in WIN_MODULES:
                            guarded.append(n.name)
                elif isinstance(sub, ast.ImportFrom) and sub.module:
                    if sub.module.split(".")[0] in WIN_MODULES:
                        guarded.append(sub.module)
    return hard, guarded


def linux_signs(path, tree):
    """Real evidence this file does something HERE. Each one named."""
    text = path.read_text(encoding="utf-8", errors="replace")
    signs = []
    if re.search(r"\bdef _linux\b|\bdef _host_linux\b", text):
        signs.append("has a _linux() implementation")
    for prog in ("dpkg-query", "/proc/net", "/proc/meminfo", "systemctl",
                 "journalctl", "ufw status", "nft list", "iptables -S",
                 "AF_PACKET", "os.uname()", "/etc/os-release", "psutil"):
        if prog in text:
            signs.append(f"reads {prog!r}")
    if re.search(r"^\s*def is_protected|^\s*def is_elevated", text, re.M):
        signs.append("exposes a predicate the live code calls")
    return signs


def main():
    trees = parse_all()
    mods = {module_name(p): p for p in trees}

    # Who imports whom, resolved to real modules in this tree.
    imported_by = {}
    for p, tree in trees.items():
        me = module_name(p)
        for name in resolve_imports(tree, me):
            if name in mods and mods[name] != p:
                imported_by.setdefault(name, set()).add(me)

    main_src = (ROOT / "main.py").read_text(encoding="utf-8")
    # Modules main.py names as a string (role tables, loaders).
    named = set(re.findall(r'"([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_.]*)"', main_src))

    # Tests count as reaching a module: they are run by the runner.
    test_names = {module_name(p) for p in trees
                  if module_name(p).startswith("tests.")}

    rows = []
    for mod, p in sorted(mods.items()):
        if mod.startswith("win32.") or mod.startswith("tests."):
            continue
        tree = trees[p]
        hard, guarded = windows_imports(tree)
        signs = linux_signs(p, tree)
        by = sorted(imported_by.get(mod, ()))
        by_main = (mod in named) or (f"from {mod} import" in main_src) \
            or (f"import {mod}" in main_src)
        by_test = any(m.startswith("tests.") for m in by)
        reachable = bool(by) or by_main
        if not (hard or guarded or re.search(r"Windows|\.exe\b|winreg", 
                                             p.read_text(encoding="utf-8",
                                                         errors="replace"))):
            continue
        rows.append({
            "mod": mod, "path": p.relative_to(ROOT), "reachable": reachable,
            "by": by, "by_main": by_main, "by_test": by_test,
            "signs": signs, "hard": hard, "guarded": guarded,
        })

    print("=" * 78)
    print("WINDOWS-FLAVOURED MODULES IN THE LINUX TREE, AND WHETHER THEY RUN HERE")
    print("=" * 78)
    print(f"\n{'module':<34} {'reaches it':<26} {'runs here':<28} win imports")
    print("-" * 110)
    for r in rows:
        reached = []
        if r["by_main"]:
            reached.append("main.py")
        if r["by"]:
            reached.append("+" + str(len(r["by"])) + " importer(s)")
        runs = "; ".join(r["signs"][:2]) or "-"
        imp = ",".join(r["hard"] + r["guarded"]) or "-"
        flag = "  <-- NOTHING" if not r["reachable"] else ""
        print(f"{r['mod']:<34} {','.join(reached) or 'nothing':<26} "
              f"{runs[:26]:<28} {imp}{flag}")

    print("\n" + "=" * 78)
    print("UNREACHABLE (the case the owner's rule is about)")
    print("=" * 78)
    dead = [r for r in rows if not r["reachable"]]
    if not dead:
        print("  none")
    for r in dead:
        print(f"  {str(r['path']):<40} {len(r['hard'])} unguarded win import(s)")

    print("\n" + "=" * 78)
    print("IS THE WINDOWS-ONLY MATERIAL OUT OF THE TREE, AND IS IT UNREACHED?")
    print("=" * 78)
    if not REFERENCE_DIR.exists():
        print(f"  REFERENCE DIR MISSING: {REFERENCE_DIR}")
        print("  The Windows-only files have to live SOMEWHERE. If this says")
        print("  missing, they were deleted rather than moved, and the")
        print("  history the rule preserves is gone.")
        return 1
    ref = sorted(REFERENCE_DIR.rglob("*.py"))
    print(f"  reference: {REFERENCE_DIR.name}/  {len(ref)} .py files")
    for sub in sorted({p.parent.relative_to(REFERENCE_DIR) for p in ref}):
        n = sum(1 for p in ref if p.parent == REFERENCE_DIR / sub)
        print(f"      {str(sub):<12} {n} file(s)")

    in_tree = list(ROOT.rglob("win32"))
    print(f"  a win32/ folder inside the tree: "
          f"{'STILL PRESENT at ' + str(in_tree) if in_tree else 'none'}")

    # THE REAL TEST: does anything live import or name it?
    importers, namers = [], []
    for p in all_py():
        if any(part in ("win32", "tests") for part in p.relative_to(ROOT).parts):
            continue
        try:
            t = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(t):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            if any(m.startswith("win32") for m in mods):
                importers.append(f"{p.relative_to(ROOT)}:{node.lineno}")
        text = p.read_text(encoding="utf-8", errors="replace")
        if REFERENCE_DIR.name in text or "win32/" in text:
            namers.append(str(p.relative_to(ROOT)))
    print(f"  LIVE modules that IMPORT from it: {len(importers)}"
          + ("" if not importers else "  <-- VIOLATION"))
    for i in importers:
        print(f"      {i}")
    print(f"  LIVE modules that NAME it in prose: {len(namers)}")
    for n in namers:
        print(f"      {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
