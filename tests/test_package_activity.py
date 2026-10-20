"""
tests/test_package_activity.py, file changes a package install explains.

A path is explained only when a package owns it (or it links to one that
does), that package was installed close to the change, and the file still
matches dpkg's checksum. dpkg itself is faked; the files are real temp files.
"""
import hashlib
import pathlib
import sys
import tempfile
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import package_activity as pa              # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp(prefix="pkgact."))
unit = tmp / "lib" / "example.service"
unit.parent.mkdir()
unit.write_text("[Service]\nExecStart=/usr/sbin/example\n")
wants = tmp / "wants"
wants.mkdir()
(wants / "example.service").symlink_to(unit)
stray = tmp / "lib" / "stray.service"
stray.write_text("[Service]\nExecStart=/tmp/x\n")

NOW = datetime.now(timezone.utc)
OWNED = {str(unit): "example-tools"}
MD5 = {str(unit): hashlib.md5(unit.read_bytes()).hexdigest()}
ACTIONS = [(NOW - timedelta(minutes=2), "install", "example-tools")]
pa.owner = lambda p: OWNED.get(p)
pa._actions = lambda: ACTIONS
pa._recorded_md5 = lambda pkg, p: MD5.get(p)

print("\n[1] Explained")
hit = pa.explains(str(unit), NOW)
check("a package file installed just now", (hit or {}).get("package"),
      "example-tools")
link = pa.explains(str(wants / "example.service"), NOW)
check("the enable link points at it", (link or {}).get("package"),
      "example-tools")
check("the link is described", "a link to" in (link or {}).get("how", ""),
      True)
folder = pa.explains(str(wants) + "/", NOW)
check("the directory that holds the link", (folder or {}).get("package"),
      "example-tools")

print("\n[2] Not explained")
check("a file no package owns", pa.explains(str(stray), NOW), None)
ACTIONS[:] = [(NOW - timedelta(days=3), "install", "example-tools")]
check("an install long before the change", pa.explains(str(unit), NOW), None)
ACTIONS[:] = [(NOW - timedelta(minutes=2), "install", "example-tools")]
MD5[str(unit)] = "0" * 32
check("a file edited after the install", pa.explains(str(unit), NOW), None)
MD5[str(unit)] = hashlib.md5(unit.read_bytes()).hexdigest()
ACTIONS[:] = [(NOW - timedelta(minutes=2), "install", "other-tools")]
check("an install of a different package", pa.explains(str(unit), NOW), None)
check("a path that does not exist", pa.explains(str(tmp / "nope"), NOW), None)

print("\n[3] dpkg's temporary names")
new = tmp / "lib" / "example.service.dpkg-new"
new.write_text("[Service]\nExecStart=/usr/sbin/example --new\n")
ACTIONS[:] = [(NOW - timedelta(minutes=2), "upgrade", "example-tools")]
hit = pa.explains(str(new), NOW)
check("a .dpkg-new beside a file just upgraded", (hit or {}).get("package"),
      "example-tools")
check("it is described as dpkg's copy",
      "temporary copy" in (hit or {}).get("how", ""), True)
gone = str(tmp / "lib" / "example.service.dpkg-tmp")
check("one already renamed away",
      (pa.explains(gone, NOW) or {}).get("package"), "example-tools")
check("one beside a file no package owns",
      pa.explains(str(stray) + ".dpkg-new", NOW), None)
ACTIONS[:] = [(NOW - timedelta(days=3), "upgrade", "example-tools")]
check("one long after the upgrade", pa.explains(str(new), NOW), None)
ACTIONS[:] = [(NOW - timedelta(minutes=2), "install", "example-tools")]
check("the base of a temporary name", pa.dpkg_temp_base("/etc/a.dpkg-old"),
      "/etc/a")
check("an ordinary name has none", pa.dpkg_temp_base("/etc/a.conf"), None)
check("a bare suffix has none", pa.dpkg_temp_base("/etc/.dpkg-new"), None)

print("\n[4] Removals in the integrity pass")
from tools import local_integrity as li              # noqa: E402


def finding(title, path):
    return {"entity_type": "file", "entity_value": path, "title": title,
            "detection_id": "LNX-2001"}


out = {}
kept = li.drop_package_changes(
    [finding(f"File removed from a watched directory: {gone}", gone),
     finding(f"File removed from a watched directory: {unit}", str(unit))],
    out)
check("a removed temporary name is left out",
      [f["entity_value"] for f in kept], [str(unit)])
check("and listed as explained",
      [b["path"] for b in out.get("by_packages", [])], [gone])

print("\n[5] Merged /usr spellings")
check("both spellings tried", pa._spellings("/usr/lib/systemd/x.service"),
      ["/usr/lib/systemd/x.service", "/lib/systemd/x.service"])

print("\nALL PASS" if not fails else f"\n{len(fails)} FAILED: {fails}")
sys.exit(1 if fails else 0)
