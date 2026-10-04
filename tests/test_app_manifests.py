"""
tests/test_app_manifests.py, the manifest reader tells installed from declared.

WHERE THIS CAME FROM, 2026-09-08. On a Magento KEV row the model reported that
dpkg on the Linux box shows no Magento, and then flagged its own answer as
weak, because Composer deploys into a web root and dpkg cannot see anything
that arrives that way. It was right. "dpkg cannot see there" is not "no".

The gap was never PHP. Software inventory only ever asked the package manager,
so every KEV row about an APPLICATION rather than a package could only produce
a shrug. Reading the manifests those apps leave behind answers four ecosystems
for the cost of one hourly command.

WHAT THIS TEST IS REALLY GUARDING. The feature is only worth having if it
keeps two facts apart:

    installed   a lock file, a pinned requirement, an app's own version file.
    declared    "^2.4" in a config, which is a RANGE somebody asked for.

Collapse those two and the tool starts reporting versions that are not on the
box, confidently, on security questions. That is worse than the shrug it
replaces, so most of what follows is checking that the line holds.

No SSH here. The parsing and the find semantics are the parts that are easy to
get wrong, and both can be checked on their own.
"""
import ast
import io
import json
import logging
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


# The module imports paramiko and the memory engine. Neither is needed to test
# the parser, so the method is lifted out of the source rather than imported.
# Same trick as reading the SUID command straight off the class: test the part
# that has the logic in it, not the plumbing around it.
SRC = io.open(ROOT / "tools" / "linux_monitor.py", encoding="utf-8").read()

# The notes below are written as adjacent f-string literals across several
# source lines, so a phrase that reads as one sentence is not one contiguous
# run of characters in the file. Join adjacent literals before matching,
# rather than reformatting real code to suit a test.
JOINED = re.sub(r'"\s*\n\s*f?"', "", SRC)
_tree = ast.parse(SRC)
_cls = next(n for n in _tree.body
            if isinstance(n, ast.ClassDef) and n.name == "LinuxMonitor")
_fn = next(n for n in _cls.body
           if isinstance(n, ast.FunctionDef) and n.name == "_parse_manifest")
_ns = {"json": json, "logger": logging.getLogger(__name__)}
exec(textwrap.dedent(ast.get_source_segment(SRC, _fn))
     .replace("def _parse_manifest(self,", "def parse("), _ns)
parse = _ns["parse"]


def one(rows, name):
    hit = [r for r in rows if r["name"] == name]
    return hit[0] if hit else None


print("\n[1] composer.lock is installed, composer.json is only declared")
# This is the Magento case that started it. The lock file is the answer to
# "what is actually on this box".
lock = parse("/var/www/shop/composer.lock",
             '{"packages":[{"name":"magento/product-community-edition",'
             '"version":"2.4.6-p3"}]}')
mag = one(lock, "magento/product-community-edition")
check("magento is found at all", mag is not None, True)
check("with the real version", mag["version"], "2.4.6-p3")
check("and it counts as installed", mag["evidence"], "installed")

decl = parse("/var/www/shop/composer.json",
             '{"name":"acme/shop","require":{"magento/product-community-edition":"^2.4"}}')
mag2 = one(decl, "magento/product-community-edition")
check("the same package from composer.json is DECLARED, not installed",
      mag2["evidence"], "declared")
check("and keeps the range verbatim rather than resolving it",
      mag2["version"], "^2.4")


print("\n[2] the noise in composer.json stays out")
# php itself and the ext-* entries are platform requirements, not software
# anyone asks a KEV question about.
noisy = parse("/x/composer.json",
              '{"require":{"php":"^8.1","ext-gd":"*","monolog/monolog":"^3.0"}}')
check("php is not reported as an application", one(noisy, "php"), None)
check("ext-gd either", one(noisy, "ext-gd"), None)
check("a real dependency still is", one(noisy, "monolog/monolog") is not None, True)


print("\n[3] npm, both lockfile shapes")
v3 = parse("/srv/api/package-lock.json",
           '{"packages":{"":{"version":"1.2.0"},'
           '"node_modules/express":{"version":"4.18.2"}}}')
exp = one(v3, "express")
check("v2/v3 lock gives an installed version", exp["evidence"], "installed")
check("with the path prefix stripped off the name", exp["version"], "4.18.2")
check("the root entry with a blank name is dropped", one(v3, ""), None)

v1 = parse("/srv/api/package-lock.json",
           '{"dependencies":{"lodash":{"version":"4.17.21"}}}')
check("v1 lock is read too", one(v1, "lodash")["version"], "4.17.21")

pj = parse("/srv/api/package.json",
           '{"name":"api","version":"1.2.0","dependencies":{"express":"^4.18.2"}}')
check("package.json dependencies are declared only",
      one(pj, "express")["evidence"], "declared")
check("but the app's own version in its own file is real enough to keep",
      one(pj, "api")["version"], "1.2.0")


print("\n[4] requirements.txt, pinned is installed and a range is not")
# This is the LiteLLM case from TODO 8.6: a pip install into a venv that dpkg
# will never see.
req = parse("/srv/api/requirements.txt",
            "litellm==1.34.0\n"
            "requests>=2.28\n"
            "flask\n"
            "# a comment\n"
            "-r other.txt\n"
            "\n")
check("a pinned version counts as installed",
      one(req, "litellm")["evidence"], "installed")
check("and the version is clean", one(req, "litellm")["version"], "1.34.0")
check("a range does not", one(req, "requests")["evidence"], "declared")
check("and keeps its operator so nobody reads it as a version",
      one(req, "requests")["version"], ">=2.28")
check("an unpinned name is still reported, with no version",
      one(req, "flask")["version"], "")
check("comments are not packages", one(req, "# a comment"), None)
check("nor are -r includes", len([r for r in req if r["name"].startswith("-")]), 0)


print("\n[5] wordpress is presence, not a made up version")
wp = parse("/opt/blog/wp-config.php", "<?php define('DB_NAME','wp');")
check("wordpress is reported", one(wp, "wordpress") is not None, True)
check("with an EMPTY version, because wp-config.php does not contain one",
      one(wp, "wordpress")["version"], "")
# If this ever starts returning a version, somebody has taught it to guess.
check("and it is still marked installed, since the file being there is a fact",
      one(wp, "wordpress")["evidence"], "installed")


print("\n[6] every row says where it came from")
# Without the source path the model can report a version with no way for
# anyone to go and check it, which is the failure this codebase keeps writing
# comments about.
for row in lock + decl + v3 + req + wp:
    if not row.get("source"):
        fails.append("a row with no source path")
        break
else:
    check("all rows carry their file path", True, True)
check("evidence is only ever one of the two words",
      sorted({r["evidence"] for r in lock + decl + v3 + req + wp}),
      ["declared", "installed"])


print("\n[7] a malformed file does not take the scan down")
# The caller catches per file and moves on, so one broken manifest must not
# cost the other thirty-nine.
try:
    parse("/x/composer.json", "{not json at all")
    check("malformed json raises for the caller to catch", False, True)
except Exception:
    check("malformed json raises for the caller to catch", True, True)
check("an unknown filename is simply empty, not an error",
      parse("/x/some-other-file.txt", "hello"), [])


print("\n[8] the find semantics, run for real")
# -prune -o -print is easy to write and easy to get subtly wrong, and getting
# it wrong here means walking every installed dependency of every app on the
# box. Same reasoning as test_suid_prune [2].
if os.name == "nt":
    print("  SKIP  needs a POSIX find, the command runs on the remote host")
else:
    with tempfile.TemporaryDirectory() as d:
        base = pathlib.Path(d)
        (base / "www" / "shop" / "vendor" / "magento" / "deep").mkdir(parents=True)
        (base / "www" / "api" / "node_modules" / "lodash").mkdir(parents=True)
        (base / "www" / "shop").joinpath("composer.lock").write_text("{}")
        (base / "www" / "shop" / "vendor" / "magento" / "deep"
         ).joinpath("composer.json").write_text("{}")
        (base / "www" / "api").joinpath("package.json").write_text("{}")
        (base / "www" / "api" / "node_modules" / "lodash"
         ).joinpath("package.json").write_text("{}")

        cmd = (r"find . -maxdepth 6 "
               r"\( -name node_modules -o -name vendor \) -prune -o "
               r"-type f \( -name composer.lock -o -name composer.json "
               r"-o -name package.json \) -print 2>/dev/null")
        out = subprocess.run(cmd, shell=True, cwd=str(base),
                             capture_output=True, text=True).stdout.split()

        check("the application's own lock file is found",
              any(p.endswith("shop/composer.lock") for p in out), True)
        check("the application's package.json too",
              any(p.endswith("api/package.json") for p in out), True)
        check("nothing inside vendor/",
              any("vendor" in p for p in out), False)
        check("nothing inside node_modules/",
              any("node_modules" in p for p in out), False)


print("\n[9] the built command and the honesty of the note")
check("the roots include the usual web roots",
      all(r in SRC for r in ("/var/www", "/srv", "/usr/share/nginx")), True)
check("vendor and node_modules are pruned in the find itself",
      '"node_modules", "vendor"' in SRC, True)
check("remote paths are filtered before they reach a shell command",
      "_APP_SAFE_PATH" in SRC, True)
# The note is the only thing standing between "not in the list" and
# "not installed", so it is treated as part of the feature.
check("the note tells the model to read the evidence field",
      "Check the evidence field on every row" in JOINED, True)
check("both notes still say a miss is not evidence",
      JOINED.count("A hit is evidence. A miss is not.") >= 2, True)
check("and it still admits it cannot see into containers",
      "inside a container" in JOINED, True)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
