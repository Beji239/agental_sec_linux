#!/usr/bin/env python3
"""
tests/test_module_manifest.py: add-on manifests of the wrong shape are skipped
without stopping the others, a manifest cannot ask for the app's own keys, and
config files are replaced without writing through a link left at a fixed name.
"""
import json
import os
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import module_host  # noqa: E402
from core.private_file import replace_private  # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp(prefix="modmanifest-"))
module_host.MODULES_DIR = tmp / "modules"


def module(name, manifest):
    folder = module_host.MODULES_DIR / name
    folder.mkdir(parents=True)
    (folder / "service.py").write_text("")
    (folder / "manifest.json").write_text(manifest if isinstance(manifest, str) else json.dumps(manifest))


print("manifests of the wrong shape")
module("good", {"name": "good", "secrets": ["AGENTAL_GOOD_TOKEN"]})
module("as_list", [1, 2, 3])
module("bad_entry", {"name": "bad_entry", "entry": 5})
module("bad_ui", {"name": "bad_ui", "ui": ["x"]})
module("bad_lists", {"name": "bad_lists", "secrets": "AGENTAL_BAD_LISTS_X",
                     "decides": 7, "needs": {"a": 1}, "ram_mb": "lots"})
module("not_json", "{")
found = module_host.discover()
check("the healthy module is still found", "good" in found, True)
check("a manifest that is not an object is skipped", "as_list" in found, False)
check("an entry that is not text is skipped", "bad_entry" in found, False)
check("a ui that is not text is ignored", found.get("bad_ui", {}).get("ui"), None)
check("lists of the wrong type become empty",
      [found["bad_lists"][k] for k in ("secrets", "decides", "needs", "ram_mb")], [[], [], [], None])
check("the module list still answers", sorted(m["name"] for m in module_host.list_modules()),
      ["bad_lists", "bad_ui", "good"])

print("keys a module may have")
module("dashboard", {"name": "dashboard", "secrets": ["AGENTAL_DASHBOARD_KEY", "AGENTAL_DASHBOARD_OWN"]})
module("thief", {"name": "thief", "secrets": ["AGENTAL_API_KEY", "AGENTAL_ABUSECH_KEY",
                                              "AGENTAL_MODULE_TOKEN", "AGENTAL_THIEF_OWN"]})
found = module_host.discover()
check("its own keys are kept", found["good"]["secrets"], ["AGENTAL_GOOD_TOKEN"])
check("the app's keys are refused", found["thief"]["secrets"], ["AGENTAL_THIEF_OWN"])
check("even under a module named like one", found["dashboard"]["secrets"], ["AGENTAL_DASHBOARD_OWN"])
os.environ["AGENTAL_API_KEY"] = "real-app-key-1234"
check("the app's key is never shown as the module's",
      [s["env"] for s in module_host.secret_status("thief")], ["AGENTAL_THIEF_OWN"])
check("and cannot be overwritten from the module's tab",
      module_host.set_secret("thief", "AGENTAL_API_KEY", "x")["ok"], False)
check("and is not passed to it", "AGENTAL_API_KEY" in module_host._child_env(found["thief"], "t"), False)
os.environ.pop("AGENTAL_API_KEY")
check("the remote module keeps its bot token",
      module_host._read_manifest(ROOT / "modules" / "remote")["secrets"], ["AGENTAL_REMOTE_BOT_TOKEN"])

print("config files are replaced, never written through a link")
target = tmp / "config.json"
target.write_text("old")
victim = tmp / "victim"
victim.write_text("keep")
os.symlink(victim, tmp / "config.json.tmp")
replace_private(target, "new")
check("the file is replaced", target.read_text(), "new")
check("owner-only", oct(target.stat().st_mode & 0o777), "0o600")
check("a link at the old temp name is not followed", victim.read_text(), "keep")
check("no temp file is left", sorted(p.name for p in tmp.iterdir() if p.name.endswith(".tmp")),
      ["config.json.tmp"])

shutil.rmtree(tmp, ignore_errors=True)
print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
