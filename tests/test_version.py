"""
tests/test_version.py, the version the console shows.

VERSION is the only place the number is written and is a plain x.y.z. A
folder with git history adds the commits since that release's tag, and only
for its own tag. Before a release: a tag on HEAD must equal VERSION, and no
tag may be newer than VERSION, so a tag cannot go out with an old number.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import version                              # noqa: E402

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def key(v):
    return tuple(int(x) for x in v.split("."))


print("the file")
number = version.read_file()
check("VERSION holds a plain x.y.z", bool(number), True)

tmp = pathlib.Path(tempfile.mkdtemp(prefix="version."))
(tmp / "VERSION").write_text("2.6.0\n")
check("it is read without the newline", version.read_file(tmp), "2.6.0")
(tmp / "VERSION").write_text("v2.6\n")
check("a malformed number is refused", version.read_file(tmp), None)
check("and the label says unknown", version.info(tmp)["label"], "unknown")
(tmp / "VERSION").write_text("2.6.0\n")
check("without git history the plain number shows", version.info(tmp),
      {"version": "2.6.0", "commits": 0, "label": "2.6.0"})

print("git describe")
check("commits after the tag are read",
      version.parse_describe("v2.6.0-11-g32cca04"), ("2.6.0", 11))
check("on the tag itself there are none",
      version.parse_describe("v2.6.0-0-g32cca04"), ("2.6.0", 0))
check("anything else is not a version", version.parse_describe("32cca04"), None)

git = shutil.which("git")
if git:
    repo = tmp / "repo"
    repo.mkdir()

    def g(*a):
        subprocess.run([git, "-C", str(repo), *a], check=True,
                       capture_output=True)
    g("init", "-q")
    g("config", "user.email", "t@example.invalid")
    g("config", "user.name", "t")
    (repo / "VERSION").write_text("1.2.3\n")
    g("add", "VERSION")
    g("commit", "-qm", "one")
    g("tag", "v1.2.3")
    (repo / "x").write_text("x")
    g("add", "x")
    g("commit", "-qm", "two")
    check("a clone one commit past its tag shows +1",
          version.info(repo)["label"], "1.2.3 +1")
    (repo / "VERSION").write_text("1.3.0\n")
    check("a tag of another version adds nothing",
          version.info(repo)["label"], "1.3.0")

print("this folder's tags agree with VERSION")
if git and (ROOT / ".git").exists() and number:
    tags = subprocess.run([git, "-C", str(ROOT), "tag", "--list", "v*"],
                          capture_output=True, text=True).stdout.split()
    tags = [t[1:] for t in tags if re.fullmatch(r"v\d+\.\d+\.\d+", t)]
    newer = [t for t in tags if key(t) > key(number)]
    check("no release tag is newer than VERSION", newer, [])
    on_head = subprocess.run(
        [git, "-C", str(ROOT), "tag", "--points-at", "HEAD", "--list", "v*"],
        capture_output=True, text=True).stdout.split()
    check("a tag on this commit is VERSION's own",
          [t for t in on_head if t != f"v{number}"], [])
else:
    print("  SKIP  no git history here, so there are no tags to compare")

print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
