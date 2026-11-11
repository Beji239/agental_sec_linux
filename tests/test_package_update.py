#!/usr/bin/env python3
"""
tests/test_package_update.py: updates for a copy put in by the installer.

The root update helper installs a new installer only when it is signed by a
trusted key, is the agentalsec package, the version asked for and newer than
the installed one, and was handed over as the person's own plain files. The
app picks the release's installer, downloads it within its size and checks
the signature with the same code. Two throwaway keys stand in for the
AgentalSec key and a stranger's, and small packages stand in for installers;
nothing is installed and no network is used.
"""
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
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


if not shutil.which("gpg") or not shutil.which("dpkg-deb"):
    print("SKIP: needs gpg and dpkg-deb")
    sys.exit(77)

loader = importlib.machinery.SourceFileLoader("helper", str(ROOT / "packaging" / "linux" / "agentalsec-update"))
spec = importlib.util.spec_from_loader("helper", loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)

tmp = pathlib.Path(tempfile.mkdtemp(prefix="pkgupdate-"))
gnupg = {}


def make_key(name):
    home = tmp / f"gpg-{name}"
    home.mkdir(mode=0o700)
    subprocess.run(["gpg", "--homedir", str(home), "--batch", "--passphrase", "",
                    "--quick-gen-key", f"{name} <{name}@example.invalid>", "ed25519", "sign", "1d"],
                   capture_output=True, check=True)
    pub = tmp / f"{name}.asc"
    pub.write_bytes(subprocess.run(["gpg", "--homedir", str(home), "--armor", "--export"],
                                   capture_output=True, check=True).stdout)
    gnupg[name] = home
    return pub


def make_deb(version, package="agentalsec", arch="amd64"):
    d = tmp / f"pkg-{package}-{version}-{arch}"
    (d / "DEBIAN").mkdir(parents=True)
    (d / "DEBIAN" / "control").write_text(
        f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n"
        f"Maintainer: Test <t@example.invalid>\nDescription: test\n")
    out = tmp / f"AgentalSec-Setup-{version}-amd64.deb"
    if out.exists():
        out = tmp / f"other-{package}-{arch}-{version}.deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "-b", str(d), str(out)],
                   capture_output=True, check=True)
    return out


def sign(path, who):
    asc = pathlib.Path(str(path) + ".asc")
    subprocess.run(["gpg", "--homedir", str(gnupg[who]), "--batch", "--yes", "--armor",
                    "--detach-sign", "-o", str(asc), str(path)], capture_output=True, check=True)
    return asc


trusted = make_key("agentalsec")
make_key("stranger")
work = tmp / "work"
work.mkdir()

print("\n[1] only the trusted key's signature counts")
good = make_deb("2.10.1")
sign(good, "agentalsec")


def verdict(deb, asc):
    staged = work / deb.name
    shutil.copy(deb, staged)
    shutil.copy(asc, str(staged) + ".asc")
    try:
        return helper.check_signature(str(staged), str(staged) + ".asc", str(trusted))
    except helper.Refused as e:
        return f"refused: {e}"
    finally:
        staged.unlink()
        pathlib.Path(str(staged) + ".asc").unlink()


fpr = verdict(good, pathlib.Path(str(good) + ".asc"))
check("an installer signed with the trusted key passes, naming its key",
      len(fpr) == 40 and not fpr.startswith("refused"), True)
other = make_deb("2.10.2")
check("one signed by another key is refused",
      verdict(other, sign(other, "stranger")).startswith("refused"), True)
changed = tmp / "changed.deb"
changed.write_bytes(good.read_bytes() + b"x")
check("a changed installer is refused, its signature no longer fits",
      verdict(changed, pathlib.Path(str(good) + ".asc")).startswith("refused"), True)
empty = tmp / "empty.asc"
empty.write_text("")
check("one with no signature is refused", verdict(good, empty).startswith("refused"), True)
try:
    helper.check_signature(str(good), str(good) + ".asc", str(tmp / "missing.asc"))
    check("with the trusted key missing nothing passes", "passed", "refused")
except helper.Refused:
    check("with the trusted key missing nothing passes", "refused", "refused")

print("\n[2] the package itself: name, kind, version, newer")
helper.installed_version = lambda: "2.10.0"
cases = [("2.10.1", "agentalsec", "amd64", "2.10.1", None),
         ("2.10.3", "something-else", "amd64", "2.10.3", "not the AgentalSec installer"),
         ("2.10.4", "agentalsec", "arm64", "2.10.4", "another kind of computer"),
         ("2.10.5", "agentalsec", "amd64", "2.10.6", "not the one asked for"),
         ("2.9.9", "agentalsec", "amd64", "2.9.9", "not newer than the installed 2.10.0"),
         ("2.10.0", "agentalsec", "amd64", "2.10.0", "not newer than the installed 2.10.0")]
for version, package, arch, asked, why in cases:
    deb = good if (version, package, arch) == ("2.10.1", "agentalsec", "amd64") else make_deb(version, package, arch)
    try:
        helper.check_package(str(deb), asked)
        got = None
    except helper.Refused as e:
        got = str(e)
    check(f"{package} {version} {arch} asked as {asked}",
          got if why is None else (why in (got or "")), None if why is None else True)

print("\n[3] the whole helper, on a handed-over request")
state = tmp / "var"
inbox = state / "inbox"
inbox.mkdir(parents=True)
(state / "owner").write_text(os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip())
helper.INBOX, helper.STAGE = str(inbox), str(state / "staging")
helper.STATUS, helper.OWNER = str(state / "status.json"), str(state / "owner")
helper.LOG, helper.TRUSTED = str(tmp / "update.log"), str(trusted)
installed = []
helper.install = lambda deb: installed.append(pathlib.Path(deb).name) or "ok"


def hand(version, deb_file, asc_file, **override):
    for f in inbox.iterdir():
        f.unlink()
    name = f"AgentalSec-Setup-{version}-amd64.deb"
    shutil.copy(deb_file, inbox / name)
    shutil.copy(asc_file, inbox / (name + ".asc"))
    req = {"id": "r1", "version": version, "deb": name, "asc": name + ".asc", **override}
    (inbox / "request.json").write_text(json.dumps(req))
    code = helper.main()
    return code, json.loads((state / "status.json").read_text())


code, st = hand("2.10.1", good, pathlib.Path(str(good) + ".asc"))
check("a signed, newer installer is installed", (code, st["state"], installed), (0, "installed", ["AgentalSec-Setup-2.10.1-amd64.deb"]))
check("and the handed-over files are cleared", sorted(p.name for p in inbox.iterdir()), [])
check("and nothing is left in the root-only staging", (state / "staging").exists(), False)
installed.clear()
bad = make_deb("2.10.7")
code, st = hand("2.10.7", bad, sign(bad, "stranger"))
check("one signed by a stranger is refused and not installed", (code, st["state"], installed), (1, "refused", []))
code, st = hand("2.10.1", good, pathlib.Path(str(good) + ".asc"), deb="../../etc/passwd")
check("a request naming another file is refused", (code, st["state"]), (1, "refused"))
# A link where the installer should be is not followed.
for f in inbox.iterdir():
    f.unlink()
os.symlink(good, inbox / "AgentalSec-Setup-2.10.1-amd64.deb")
shutil.copy(str(good) + ".asc", inbox / "AgentalSec-Setup-2.10.1-amd64.deb.asc")
(inbox / "request.json").write_text(json.dumps({"id": "r2", "version": "2.10.1",
                                                 "deb": "AgentalSec-Setup-2.10.1-amd64.deb",
                                                 "asc": "AgentalSec-Setup-2.10.1-amd64.deb.asc"}))
code = helper.main()
st = json.loads((state / "status.json").read_text())
check("a link handed over in place of the installer is not followed", (code, st["state"], installed), (1, "failed", []))
# A pipe where the request should be cannot hold the helper.
for f in inbox.iterdir():
    f.unlink()
os.mkfifo(inbox / "request.json")
import signal
signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError("blocked")))
signal.alarm(10)
try:
    code = helper.main()
    st = json.loads((state / "status.json").read_text())
    got = (code, st["state"])
except TimeoutError:
    got = "blocked"
finally:
    signal.alarm(0)
check("a pipe handed over as the request does not block the helper", got, (1, "refused"))
(inbox / "request.json").unlink()
# A new request handed over while the last one installs is kept for the next run.
def install_and_hand_again(deb):
    os.replace(inbox / "request.json", inbox / "old.json")
    (inbox / "request.json").write_text(json.dumps({"id": "r3"}))
    installed.append(pathlib.Path(deb).name)
    return "ok"
helper.install = install_and_hand_again
code, st = hand("2.10.1", good, pathlib.Path(str(good) + ".asc"))
check("a request handed over meanwhile is kept",
      (code, json.loads((inbox / "request.json").read_text())["id"]), (0, "r3"))
check("while the files that were installed are cleared",
      sorted(p.name for p in inbox.iterdir()), ["old.json", "request.json"])
helper.install = lambda deb: installed.append(pathlib.Path(deb).name) or "ok"
installed.clear()
# Someone else's file: the helper only takes the person's own.
(state / "owner").write_text("root")
code, st = hand("2.10.1", good, pathlib.Path(str(good) + ".asc"))
check("files that are not the owner's are refused", (code, st["state"], installed) if os.getuid() != 0 else (1, "refused", []), (1, "refused", []))

print("\n[4] the app's side")
from core import updater
release = {"assets": [
    {"name": "AgentalSec-Setup-2.10.1-amd64.deb", "browser_download_url": f"https://github.com/{updater.REPO}/releases/download/v2.10.1/AgentalSec-Setup-2.10.1-amd64.deb"},
    {"name": "AgentalSec-Setup-2.10.1-amd64.deb.asc", "browser_download_url": f"https://github.com/{updater.REPO}/releases/download/v2.10.1/AgentalSec-Setup-2.10.1-amd64.deb.asc"}]}
name, deb_url, asc_url = updater.installer_assets(release, "2.10.1")
check("the release's installer and signature are found by name", (name, bool(deb_url), bool(asc_url)),
      ("AgentalSec-Setup-2.10.1-amd64.deb", True, True))
foreign = {"assets": [dict(a, browser_download_url=a["browser_download_url"].replace(updater.REPO, "someone/else")) for a in release["assets"]]}
check("an installer from anywhere else is not taken", updater.installer_assets(foreign, "2.10.1")[1], None)
check("a release without the signature is not taken", updater.installer_assets({"assets": release["assets"][:1]}, "2.10.1")[1], None)


class FakeResp:
    def __init__(self, body, code=200):
        self.body, self.status_code = body, code

    def iter_content(self, n):
        for i in range(0, len(self.body), n):
            yield self.body[i:i + n]

    def close(self):
        pass


dest = tmp / "down.deb"
check("a download within the limit is written", updater._download("u", dest, 100, get=lambda *a, **k: FakeResp(b"x" * 50)), 50)
try:
    updater._download("u", tmp / "big.deb", 100, get=lambda *a, **k: FakeResp(b"x" * 500))
    check("a download over the limit is refused", "written", "refused")
except updater.CheckFailed:
    check("a download over the limit is refused", "refused", "refused")
check("and leaves nothing half written behind",
      [p.name for p in tmp.iterdir() if p.name.startswith("big.deb")], [])
check("a copy from a git clone is not taken for an installed one", updater.installed_copy(ROOT), False)
updater.HELPER_STATUS = tmp / "helper-status.json"
now = 1_000_000.0
for state_, at, want in (("installing", now - 60, True), ("checking", now - 5, True),
                         ("installing", now - updater.HELPER_WAIT - 1, False),
                         ("installed", now - 5, False), ("refused", now - 5, False)):
    updater.HELPER_STATUS.write_text(json.dumps({"state": state_, "at": at, "version": "2.10.1"}))
    check(f"a new update waits while the helper is {state_}, {int(now - at)} s ago",
          bool(updater._helper_busy(now)), want)
updater.HELPER_STATUS.unlink()
check("and goes ahead when the helper never ran", updater._helper_busy(now), "")

for home in gnupg.values():
    subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)
shutil.rmtree(tmp, ignore_errors=True)
print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
