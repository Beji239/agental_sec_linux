# tests/test_user_units.py
# disable_service and enable_service on a unit in the user's own manager
# (systemctl --user), against a stand-in systemctl. A unit whose file lives in
# the user's unit folder cannot be masked, so its file is moved aside and put
# back by the undo; one elsewhere is masked. Desktop units are refused.

import os
import pathlib
import sys
import tempfile
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import systemd_units as sd                 # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}" + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


tmp = pathlib.Path(tempfile.mkdtemp())
home = tmp / "home"
unit_dir = home / ".config" / "systemd" / "user"
unit_dir.mkdir(parents=True)
state = tmp / "state"
state.mkdir()
fakebin = tmp / "bin"
fakebin.mkdir()
# State per unit: <unit>.active (present = running), <unit>.mask, <unit>.enabled.
(fakebin / "systemctl").write_text(f"""#!/bin/sh
S={state}; U={unit_dir}
all="$*"
verb=""; for a in "$@"; do case "$a" in -*) ;; *) verb=$a; break ;; esac; done
for a in "$@"; do u=$a; done
now=""; case " $all " in *" --now "*) now=1 ;; esac
frag=""
[ -f "$U/$u" ] && frag="$U/$u"
[ -f "$S/$u.elsewhere" ] && frag="$S/$u.file"
case $verb in
  show)
    case "$all" in *FragmentPath*) echo "$frag"; exit 0 ;; esac
    load=not-found; [ -n "$frag" ] && load=loaded; [ -f "$S/$u.mask" ] && load=masked
    act=inactive; [ -f "$S/$u.active" ] && act=active
    ufs=disabled; [ -f "$S/$u.enabled" ] && ufs=enabled; [ -f "$S/$u.mask" ] && ufs=masked
    [ "$load" = not-found ] && ufs=""
    echo "LoadState=$load"; echo "ActiveState=$act"; echo "UnitFileState=$ufs" ;;
  disable) rm -f "$S/$u.enabled"; [ -n "$now" ] && rm -f "$S/$u.active" ;;
  mask) [ -f "$U/$u" ] && {{ echo "Failed to mask unit: File $U/$u already exists." >&2; exit 1; }}; touch "$S/$u.mask" ;;
  unmask) rm -f "$S/$u.mask" ;;
  enable) touch "$S/$u.enabled" ;;
esac
exit 0
""")
(fakebin / "systemctl").chmod(0o755)
os.environ["PATH"] = f"{fakebin}:{os.environ['PATH']}"
held = tmp / "held"
fake_pw = types.SimpleNamespace(pw_dir=str(home), pw_uid=os.getuid(), pw_gid=os.getgid())
sd._held_dir = lambda owner: (str(held), fake_pw)
sd._user_target = lambda: (["systemctl", "--user"], dict(os.environ), "tester")

print("[1] a unit file in the user's own unit folder")
(unit_dir / "evil-sync.service").write_text("[Service]\nExecStart=/bin/true\n")
for f in ("evil-sync.service.active", "evil-sync.service.enabled"):
    (state / f).write_text("")
check("the user manager knows it", sd.user_unit_known("evil-sync.service"), True)
r = sd.disable_user_unit("evil-sync.service")
check("disabled, stopped and moved aside",
      (r["success"], r["after"].get("LoadState"), (held / "evil-sync.service").exists()),
      (True, "not-found", True))
check("no longer in the unit folder", (unit_dir / "evil-sync.service").exists(), False)
r = sd.enable_user_unit("evil-sync.service")
check("the undo puts it back and enables it",
      (r["success"], (unit_dir / "evil-sync.service").exists(), r["after"].get("UnitFileState")),
      (True, True, "enabled"))
check("and the held copy is gone", (held / "evil-sync.service").exists(), False)

print("[2] a unit whose file lives elsewhere is masked")
(state / "other.service.elsewhere").write_text("")
(state / "other.service.active").write_text("")
r = sd.disable_user_unit("other.service")
check("masked and stopped", (r["success"], r["after"].get("UnitFileState"), r["after"].get("ActiveState")),
      (True, "masked", "inactive"))
r = sd.enable_user_unit("other.service")
check("unmasked by the undo", (r["success"], r["after"].get("UnitFileState")), (True, "enabled"))

print("[3] refusals")
for unit in ("pipewire.service", "dbus.service", "agentalsec-gw.service", "gnome-shell.service"):
    check(f"{unit} is refused", sd.disable_user_unit(unit).get("refused"), True)
check("a name with a dash first is refused", sd.disable_user_unit("-x.service").get("refused"), True)
check("an unknown unit is refused", sd.disable_user_unit("nope.service").get("refused"), True)
sd._user_target = lambda: (None, None, None)
check("no desktop user to act for is refused",
      sd.disable_user_unit("evil-sync.service").get("refused"), True)

print()
print("ALL CHECKS PASSED" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
