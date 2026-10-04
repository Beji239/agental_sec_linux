"""
tests/test_read_helper.py, L3 tier D. The read-only helper's rules.

FAILURE CASES FIRST, and for this file that ordering is not a style choice:
EVERY OTHER THING THIS HELPER DOES IS A REFUSAL. It reads four things, and
the code that decides what it may NOT read is the part that matters. A test
suite that proved the four reads work and left the refusals untested would be
testing the half of the file that can only cost a finding.

There is a second reason the refusals come first. This helper is invoked
through `sudo -n` and it is the only thing on this machine that a sudoers
rule grants root to. Every property that makes that grant small is a property
somebody could delete later; each one below is asserted so that deleting it
fails a named test rather than being noticed by an audit.

WHAT IS TESTED HERE, AND WHAT CANNOT BE:
  * the verb table and its refusals          -- here, by running the helper
  * the self-check (root-owned path)         -- here, against real paths
  * the elevation refusal                    -- here, by running unelevated
  * that no caller string reaches a command  -- asserted against the source
  * that /etc/shadow is not in the table     -- asserted against the source
  * the ACTUAL ELEVATED READ                 -- NOT HERE. That needs the
    sudoers drop-in installed, and installing it is an operational change the
    owner must run. scripts/install_read_helper.sh --verify does that half,
    and T5_LOCAL_INTEGRITY.md says which half is which.

Run it directly: python tests/test_read_helper.py
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

HELPER = ROOT / "tools" / "read_helper.py"
SRC = HELPER.read_text(encoding="utf-8")

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


def check_true(label, got):
    check(label, bool(got), True)


def run(*args):
    """Run the helper and return (exit code, parsed stdout, stderr)."""
    p = subprocess.run([sys.executable, str(HELPER)] + list(args),
                       capture_output=True, text=True, timeout=60)
    try:
        out = json.loads(p.stdout)
    except (ValueError, TypeError):
        out = None
    return p.returncode, out, p.stderr


print("\n[1] THE VERB TABLE IS A TABLE, AND NOTHING TAKES A PATH")
# THE CENTRAL PROPERTY. A helper that accepts a path from its caller is
# `sudo cat`, and no amount of care in the rest of the file changes that.
import importlib.util                                   # noqa: E402

_spec = importlib.util.spec_from_file_location("read_helper", HELPER)
rh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rh)

check("the verbs are exactly the five this design approved",
      sorted(rh.VERBS), ["dpkg_verify", "proc_exe", "root_ssh", "sudoers", "sudoers_d"])
check("every verb's paths are absolute literals",
      all(p.startswith("/") for v in rh.VERBS.values() for p in v["paths"]), True)
check("exactly one verb has no paths, and it is the one that runs dpkg",
      sorted(v for v, d in rh.VERBS.items() if not d["paths"]), ["dpkg_verify"])

# the source-level assertions. These read the file, because the property
# is about what the CODE can do rather than about what one call returns.
check("no verb is a function of a caller-supplied path",
      "def verb_(" in SRC, False)
check("there is no read of sys.argv[1] as a path anywhere",
      bool(re.search(r"open\(\s*sys\.argv", SRC)), False)
check("sys.argv is only ever consumed by main()",
      len(re.findall(r"\bsys\.argv\b", SRC)), 1)
_handlers = re.search(r"HANDLERS\s*=\s*\{(.*?)\}", SRC, re.S).group(1)
check("the handler table maps verb names to zero-argument functions",
      sorted(re.findall(r'"(\w+)":\s*verb_', _handlers)),
      ["dpkg_verify", "proc_exe", "root_ssh", "sudoers", "sudoers_d"])
check("no handler takes a parameter",
      len(re.findall(r"def verb_\w+\(([^)]*)\)", SRC)
          ) == len([m for m in re.findall(r"def verb_\w+\(([^)]*)\)", SRC) if not m]),
      True)

# and /etc/shadow is not reachable.
check("/etc/shadow is NOT in the verb table",
      "/etc/shadow" in json.dumps(rh.VERBS), False)
check("/etc/gshadow is NOT in the verb table",
      "/etc/gshadow" in json.dumps(rh.VERBS), False)
check_true("and the file says so in words, so nobody adds it 'for completeness'",
           "MUST NOT BE ADDED" in SRC)
check_true("naming the reason -- password hashes",
           "password hashes" in SRC)


print("\n[2] AN UNRECOGNISED VERB IS REFUSED, NOT GUESSED AT")
code, out, err = run("cat_the_whole_disk")
check("it exits 1", code, 1)
check("and says ok: false", out.get("ok") if out else None, False)
check_true("with the real table named, so the caller can fix the call",
           "dpkg_verify" in (out or {}).get("refused", ""))
check_true("and 'Nothing was read'",
           "Nothing was read" in (out or {}).get("refused", ""))

code, out, err = run("/etc/shadow")
check("a PATH where a verb belongs is refused the same way", code, 1)
check_true("and the refusal explains that a path is not a verb",
           "not in" in (out or {}).get("refused", ""))

code, out, err = run()
check("no verb at all exits 2 with usage, not a traceback", code, 2)
check_true("and the usage says there is no verb that takes a path",
           "sudo cat" in err)


print("\n[3] AN EXTRA ARGUMENT IS REFUSED. THIS IS THE SUDOERS '*' HOLE.")
# A sudoers rule ending in '*' would let the caller pass anything. The helper
# refuses arguments anyway, so the grant is bounded by the script as well as
# by the rule -- two independent refusals rather than one.
code, out, err = run("sudoers", "/etc/shadow")
check("`sudoers /etc/shadow` exits 1", code, 1)
check("and reads NOTHING", out.get("ok") if out else None, False)
check_true("naming the argument count",
           "2 were supplied" in (out or {}).get("refused", ""))
check_true("and saying no verb takes a parameter",
           "NO VERB TAKES A PARAMETER" in (out or {}).get("refused", ""))

code, out, err = run("sudoers", "--all", "-x")
check("two extra arguments are refused too", code, 1)
check_true("and it counts them", "3 were supplied" in (out or {}).get("refused", ""))

code, out, err = run("--verbs", "extra")
check("even --verbs refuses an argument", code, 1)


print("\n[4] --verbs LISTS THE TABLE AND READS NOTHING")
code, out, err = run("--verbs")
check("it exits 0 unelevated, because listing the table needs no privilege",
      code, 0)
check("and reports the five verbs",
      sorted((out or {}).get("verbs", {})),
      ["dpkg_verify", "proc_exe", "root_ssh", "sudoers", "sudoers_d"])
check_true("and publishes what it REFUSES, so the refusal is auditable",
           "/etc/shadow" in (out or {}).get("refuses", {}))
# THE ASSERTION IS ABOUT THE STRUCTURE, NOT THE PROSE.
# The first version searched the whole serialized JSON for the word "content"
# and failed, because the `why` strings legitimately SAY "a content edit that
# leaves those identical". A test that fires on a word rather than the thing
# is noise, and this project has three recorded examples of exactly that. So:
# no ENTRY may carry a `content` key, and no file payload may be present.
check("no entry in the listing carries a content field",
      any("content" in entry for entry in (out or {}).get("verbs", {}).values()),
      False)
check("and the whole payload has no 'content' KEY, only prose mentioning it",
      sorted(out.keys()) if out else None,
      ["at", "ok", "refuses", "schema", "verbs"])


print("\n[5] THE SELF-CHECK COMES FIRST, AND IT MAKES THE TREE COPY UNUSABLE")
# THIS IS THE MOST IMPORTANT PROPERTY IN THE FILE.
#
# The helper lives in the project tree, which the operator's account owns and
# which is mode 775. So running it FROM THE TREE refuses -- correctly, and
# before it even looks at privilege -- because a sudoers rule naming that path
# would be a rule granting root to anything anybody with write access to this
# tree decides to put there.
#
# THAT MEANS THE UNELEVATED ELEVATION-REFUSAL TEST CANNOT BE RUN FROM THE
# TREE COPY, and the first version of this test tried to run it there and
# failed on a correct refusal while claiming to test something else. What is
# tested instead is the thing that is actually true: this copy refuses, for
# the right reason, and it refuses BEFORE the elevation check.
code, out, err = run("sudoers")
_msg = (out or {}).get("refused", "")
if os.geteuid() != 0:
    check("running the helper from the project tree is REFUSED", code, 1)
    check_true("because this tree is unprivileged-owned and mode 775",
               "owned by uid" in _msg or "group- or world-writable" in _msg)
    check_true("and the refusal names the real path, not a generic message",
               "read_helper.py" in _msg)
    check_true("and names the fix: install it under /usr/local/lib",
               "install_read_helper.sh" in _msg)
    check_true("and says nothing was read",
               "Nothing was read" in _msg)
    check_true("and the PATH check runs BEFORE the privilege check, so the "
               "message is about the install and not about uid 1000",
               "running as uid" not in _msg)
    # AND THE SUBSTRING THAT MADE THIS AMBIGUOUS.
    # The first version asserted `"not root" not in _msg` and it failed --
    # correctly -- because the OWNERSHIP message ends "... is owned by uid
    # 1000, not root." So a substring test on "not root" cannot tell the two
    # refusals apart. The assertion above uses the elevation refusal's own
    # opening words instead, and this one records why.
    check_true("(and 'not root' appears in the ownership text too, which is "
               "why the assertion above names the privilege message exactly)",
               "not root" in _msg)
else:
    print("  (running as root, so the ownership refusal cannot be tested "
          "from here)")

# THE ORDER, ASSERTED STRUCTURALLY RATHER THAN BY ABSENCE.
# The check above looks for the ABSENCE of the privilege message in the path
# refusal. That is the right assertion for this copy, but it would still pass
# if main() called assert_elevated() first and assert_elevated simply did not
# fire -- so the call order in main() is asserted directly as well.
_main = SRC.split("def main(")[1]
check("main() calls the path check before the privilege check",
      _main.index("assert_self_is_safe()") < _main.index("assert_elevated()"),
      True)

# the elevation refusal itself, driven directly.
# assert_elevated() is called by main() after the path check. To test its
# message without a root-owned install, it is exercised in a subprocess with
# the path check monkeypatched out -- which is the only honest way to reach
# the second refusal on a machine where the first one always fires.
_elev_probe = (
    "import importlib.util, sys, json\n"
    "spec = importlib.util.spec_from_file_location('rh', %r)\n"
    "rh = importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(rh)\n"
    "rh.assert_self_is_safe = lambda: None\n"      # only the path check
    "try:\n"
    "    rh.assert_elevated()\n"
    "except SystemExit:\n"
    "    pass\n" % str(HELPER))
p = subprocess.run([sys.executable, "-c", _elev_probe],
                   capture_output=True, text=True, timeout=60)
try:
    _elev = json.loads(p.stdout)
except (ValueError, TypeError):
    _elev = {}
if os.geteuid() != 0:
    check("unelevated, assert_elevated refuses rather than returning",
          _elev.get("ok"), False)
    check_true("it says it is not root",
               "not root" in _elev.get("refused", ""))
    check_true("and names BOTH reasons that could be, so the reader is not "
               "left guessing",
               "drop-in" in _elev.get("refused", "")
               and "password" in _elev.get("refused", ""))
    check_true("and states the consequence: it can read no more than the "
               "sensor already could",
               "no more than the sensor" in _elev.get("refused", ""))


print("\n[6] THE SELF-CHECK REFUSES A HELPER THAT NON-ROOT COULD REPLACE")
# A sudoers rule grants root to a PATH. If the path can be written by a
# non-root account, the allowlist is decorative. This is tested by running a
# COPY of the helper from a directory that is NOT root-owned -- which is what
# this test tree is -- and reading the refusal.
_tmp = tempfile.mkdtemp(prefix="rh_test_")
_copy = os.path.join(_tmp, "read_helper.py")
with open(HELPER, "rb") as fh:
    data = fh.read()
with open(_copy, "wb") as fh:
    fh.write(data)

# [6a] the check itself, called directly against paths we control.
# The tree copy in section [5] IS this case; the assertions here are the ones
# about WHAT the refusal says rather than that it happened.
_own = os.stat(_copy)
if _own.st_uid != 0:
    print("  (this test tree is owned by uid %d, so the copy is a real "
          "non-root case)" % _own.st_uid)
    p = subprocess.run([sys.executable, _copy, "sudoers"],
                       capture_output=True, text=True, timeout=60)
    check("a helper in an unprivileged directory refuses to run, exit 1",
          p.returncode, 1)
    try:
        body = json.loads(p.stdout)
    except (ValueError, TypeError):
        body = {}
    check_true("naming the ownership rather than a generic error",
               "owned by uid" in body.get("refused", ""))
    check_true("and explaining that a sudoers rule would then be arbitrary "
               "root execution",
               "arbitrary root execution" in body.get("refused", ""))
    check_true("and naming the fix",
               "install_read_helper.sh" in body.get("refused", ""))
    check_true("and stating that nothing was read",
               "Nothing was read" in body.get("refused", ""))
    # AND IT NAMES EVERY BAD LINK IN THE CHAIN, NOT JUST THE FIRST.
    # Refusing on the first problem and stopping would leave the reader to fix
    # one directory, re-run, and discover the next one. The copy lives in a
    # temp dir under /tmp, so the chain it reports is at least its own
    # directory and the file.
    check_true("and it reports EVERY problem in the path, not just the first",
               body.get("refused", "").count("owned by uid") >= 2)
    # AND THE ORDER: the path check runs before the elevation check.
    check_true("and the self-check runs FIRST, before the elevation check",
               "running as uid" not in body.get("refused", ""))

# [6b] the world-writable case, asserted against the source.
check_true("the check looks for the group-write bit",
           "S_IWGRP" in SRC)
check_true("and the world-write bit", "S_IWOTH" in SRC)
check_true("and it walks all the way up to /",
           'if path == "/":' in SRC)
check_true("and it uses the REAL path, so a symlink cannot dodge it",
           "os.path.realpath" in SRC)

# [6c] and it is stricter than 'not me'. A third account is a way in.
check_true("ownership by ANY non-root account is refused, not just the caller's",
           "st.st_uid != 0" in SRC)


print("\n[7] THE OUTPUT CONTRACT: A REFUSAL LOOKS LIKE A SUCCESS")
# The caller is a sensor. It must be able to tell a refusal from an empty
# read WITHOUT inspecting the exit code, because a subprocess that dies and a
# subprocess that reports nothing look the same to a careless caller.
code, refused, _e = run("nonsense_verb")
check("a refusal carries 'ok': false", refused.get("ok"), False)
check_true("a reason in words", bool(refused.get("refused")))
check_true("a timestamp, so a stale answer is visible",
           bool(refused.get("at")))
check_true("and a schema number, so a future format change is detectable",
           (out or {}).get("schema") == 1)

code, listed, _e = run("--verbs")
check("a success carries 'ok': true", listed.get("ok"), True)
check("with the same schema", listed.get("schema"), 1)
check_true("and the same timestamp field", bool(listed.get("at")))
check_true("so a caller can treat both shapes with one parser",
           set(refused) == set(listed)
           or set(listed).issuperset({"ok", "schema", "at"}))


print("\n[8] THE dpkg VERB CANNOT BE HANDED ANYTHING")
# It runs a subprocess, which is the only place an argument could become a
# command line. The package list comes from dpkg-query run BY THE HELPER.
check_true("the verb builds its own package list from dpkg-query",
           "dpkg-query" in SRC)
check("it passes NO caller data into the command",
      bool(re.search(r"subprocess\.run\(\s*\[\s*\"dpkg\",\s*\"-V\"\s*\]\s*\+",
                     SRC)), True)
check("and the only thing appended is the list it computed itself",
      len(re.findall(r"\[\s*\"dpkg\",\s*\"-V\"\s*\]", SRC)), 1)
check_true("and the man page's own warning is carried, because dpkg -V is not "
           "a security tool", "NOT a security verification" in SRC)
check_true("it also says it cannot detect an attacker who edited the control "
           "file too, which is the honest limit of an md5sum check",
           "edited the control file as well" in SRC)
check_true("and the caveat travels with the verb's OUTPUT, not only in a "
           "comment, so a reader of the JSON sees it",
           '"caveat": DPKG_CAVEAT' in SRC)


print("\n[9] THE HELPER AND THE SENSOR AGREE ABOUT THE PATH")
# The sensor invokes HELPER_PATH. If those two drift, the sensor reports the
# helper as not installed forever and nobody knows why.
from tools import local_integrity as li                 # noqa: E402
check("the sensor's HELPER_PATH is the path the installer uses",
      li.HELPER_PATH, "/usr/local/lib/agentalsec/read_helper.py")
_installer = (ROOT / "scripts" / "install_read_helper.sh").read_text(
    encoding="utf-8")
check_true("and the installer installs to that same path",
           li.HELPER_PATH in _installer)


print("\n[10] THE SENSOR TREATS A BROKEN HELPER AS UNREAD, NOT AS UNCHANGED")
# THE THIRD STATE, and the one that silently degrades. A helper that is
# installed but failing must not look like a machine where nothing moved.
# Simulated, so this section tests the not-installed state on a machine
# where the helper IS installed.
_real_helper_path = li.HELPER_PATH
li.HELPER_PATH = "/nonexistent/agentalsec/read_helper.py"
li.helper_forget()
_absent_state = li.helper_status(force=True)
check_true("with the helper not installed, the state carries a reason",
           bool(_absent_state.get("reason")))
check_true("and the reason names the three file sets that stay metadata-only",
           "sudoers" in _absent_state["reason"]
           and "authorized_keys" in _absent_state["reason"])
check("and it does NOT claim the helper is available",
      _absent_state.get("available"), False)

_note = li.helper_coverage_note()
li.HELPER_PATH = _real_helper_path
check("the coverage note lists what is NOT read in this state",
      sorted(_note["uncovered"]),
      sorted(["/etc/sudoers CONTENTS", "/etc/sudoers.d CONTENTS",
              "root's authorized_keys",
              "/etc/shadow and /etc/gshadow CONTENTS, refused by design "
              "(they hold password hashes)"]))
check("and nothing is claimed as covered",
      _note["covered"], [])
check_true("and says a file nobody read is not a file that did not change",
           "A file nobody read is not a file that did not change"
           in _note["note"])

# and the shadow refusal is in the list in EVERY state, including a
# working one. It is a decision, not a gap, and it must not disappear when
# the helper starts working.
_verbs_state = dict(_absent_state, available=True, reason=None,
                    verbs=["root_ssh", "sudoers", "sudoers_d", "dpkg_verify"])
li._remember_helper(_verbs_state)
_working = li.helper_coverage_note()
check_true("with a working helper, shadow is STILL listed as not read",
           any("shadow" in u for u in _working["uncovered"]))
check("and the three sets moved to covered",
      sorted(_working["covered"]),
      ["/etc/sudoers CONTENTS", "/etc/sudoers.d CONTENTS",
       "root's authorized_keys"])
check_true("with the consequence spelled out in the note",
           "A file nobody read is not a file that did not change"
           in _working["note"])
li.helper_forget()


print("\n[11] AND THE THING THIS HELPER DOES NOT FIX IS STATED, NOT IMPLIED")
# The owner's question was whether to run the app as root so that dpkg -V
# works. The measured answer is that dpkg -V already works unelevated, and
# the helper's dpkg verb buys 27 /boot files. That is a fact a future reader
# needs, so it lives in the source.
check_true("the helper says dpkg -V does NOT need root",
           "does NOT need root to run" in SRC)
check_true("and names the measured cost of believing otherwise",
           "27" in SRC and "/boot" in SRC)
check_true("and states it plainly enough that the sentence survives the line "
           "wrap, which is what broke the first version of this assertion",
           "NOT need root" in SRC)


print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
