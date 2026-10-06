#!/usr/bin/env python3
"""
Enforce design rule 1: universal, not local.

AgentalSec is meant to run on networks it has never seen. Anything specific to
the machine it was developed on belongs in config.json (gitignored) or .env
(gitignored), never in a .py or .html file, which are the files that get
published.

HOW THIS PROJECT PUBLISHES, AND THEREFORE WHAT THIS CHECK IS FOR.

Nothing is gitignored into safety here. Publishing means building a SEPARATE,
SANITISED COPY of the folder and committing that. The working folder is
expected to be full of local detail: config.json holds the real network on
purpose, and the audit, spec and working notes are internal by design. None of
that is a leak.

So the tree whose cleanliness is a security property is the copy, and that is
what this check is aimed at:

    python scripts/check_no_local_details.py --release ../agental_sec_release

In release mode NOTHING is exempt. A working document that reached the copy is
a finding, not an exception, exempting it by name would hide the one bug
this check exists to catch.

Identifiers are still discovered from the WORKING folder, because the copy has
no config.json or .env to read. What to look FOR comes from here; what to look
IN is wherever you point it. Getting that backwards makes the check discover
nothing and pass everything.

Run without arguments for an informational pass over the working folder:

    python scripts/check_no_local_details.py

Exit code 0 = clean, 1 = something local leaked into source. Also importable
as a pytest test (test_no_local_details) if pytest is ever added; it needs
nothing installed to run on its own.


WHY THIS FILE CONTAINS NO NAMES OR ADDRESSES

The obvious way to write this is a list of strings to grep for, the
developer's username, hostname, LAN addresses. That version leaks the exact
thing it exists to prevent, and it lands in the repo, and it goes stale the
moment anything changes.

So it discovers what to look for at runtime instead: from the environment
(home directory name, login, hostname) and from the two gitignored config
files. Nothing personal is written down here, and the check keeps working for
the next person on a completely different machine, which is the same rule
it is enforcing, applied to itself.
"""

from __future__ import annotations

import io
import subprocess
import ipaddress
import json
import os
import re
import socket
import sys
import tokenize
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parent.parent

# The tree being checked. Defaults to this project, but the point of this
# script is to be aimed at the SANITISED COPY before it is published. See
# RELEASE MODE below.
PROJECT_ROOT = SOURCE_ROOT

# Release mode: no file is exempt from anything. Set by --release.
RELEASE_MODE = False

# Only files that would actually be published: if it ships, it is scanned.
SCAN_SUFFIXES = {".py", ".html", ".sql", ".json", ".md", ".txt", ".sh"}

SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "env",
             "_backup_pre_fixes", "node_modules", ".vscode", "geoip",
             # real captured traffic and log output, never tracked
             "logs", "captures",
             # downloaded third-party text (IEEE registry, LOLBAS cache), gitignored
             "data"}

# Gitignored, and holding the operator's real network is their purpose.
NEVER_SCANNED = {"config.json", ".env", "wg0.conf"}

# Files the app writes about this install. They must not ship (an anchor
# from here would trip a tamper alarm on a clean install); checked only
# in release mode.
MACHINE_STATE = {
    "integrity_anchor.json",
    "integrity_anchor_history.jsonl",
}


# Documents that carry internal history and do not ship. The list is only
# a fallback: git is asked below, and a claimed file git would publish is
# scanned anyway.
WORKING_FILES = {
    "TODO.md", "NEXT_SESSION.md", "RELEASE_PREP.md",
    "AGENTALSEC_AUDIT.txt", "AGENTALSEC_SPEC.txt", "AGENTALSEC_OVERVIEW.txt",
    "AgentalSec.md",
}


def git_will_ship(paths: list[Path]) -> tuple[set[Path], bool]:
    """
    Which of these paths git WOULD publish. Returns (shipping, asked_ok).

    Two questions, because either one alone gives the wrong answer:

    * `git check-ignore` reports what .gitignore covers, but it deliberately
      says nothing about files ALREADY TRACKED. A tracked file ships whatever
      .gitignore says about it, so ignoring alone is not safety.
    * `git ls-files` reports what is tracked, but says nothing about a new
      untracked file that `git add -A` would sweep in.

    So a file is safe only when it is BOTH untracked AND ignored. Anything
    else ships. asked_ok is False when there is no repository or no git, and
    the caller must not read that as "nothing ships".
    """
    if not (PROJECT_ROOT / ".git").exists():
        return set(), False

    def run(args, stdin=None):
        try:
            return subprocess.run(args, input=stdin, capture_output=True,
                                  text=True, cwd=PROJECT_ROOT, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None

    tracked_out = run(["git", "ls-files"])
    if tracked_out is None:
        return set(), False
    tracked = {(PROJECT_ROOT / line.strip()).resolve()
               for line in tracked_out.stdout.splitlines() if line.strip()}

    ignored: set[Path] = set()
    ignore_out = run(["git", "check-ignore", "--stdin"],
                     stdin="\n".join(str(p) for p in paths))
    if ignore_out is not None:
        for line in ignore_out.stdout.splitlines():
            line = line.strip()
            if line:
                ignored.add((PROJECT_ROOT / line).resolve()
                            if not Path(line).is_absolute()
                            else Path(line).resolve())

    shipping = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in tracked or resolved not in ignored:
            shipping.add(resolved)
    return shipping, True


# Wider than SCAN_SUFFIXES: the house-style rules below apply to anything
# with prose in it, including Markdown and the ignore file.
PROSE_SUFFIXES = {".py", ".html", ".md", ".txt"}
PROSE_NAMES = {".gitignore"}

# This file names the categories it hunts for, so its own text trips several
# patterns. It is excluded by name rather than by weakening the patterns.
SELF = Path(__file__).name

# HOUSE STYLE
#
# Two characters are banned from comments and prose across the project.
#
# A run of three or more dashes is a separator, and the codebase already has
# one: the comma run above. Two conventions for the same job means every file
# picks one at random and section headers stop being scannable.
#
# A vertical bar reads as a table column or a shell pipe. In a comment it is
# neither, and in a Markdown file a stray one silently starts a table. Prose
# that needs to separate alternatives can use a semicolon.
#
# Checked here rather than left to memory, because a style rule nothing
# enforces is a style rule that lasts one session. Code is exempt: SQLite
# string concatenation and Python type unions both use the bar legitimately,
# so only comments, docstrings and Markdown are examined.

BANNED_IN_PROSE = [
    ("|",   "a vertical bar; use a semicolon, or a list"),
    ("---", "a dash-run separator; use the comma-run style"),
]

# THE DASH RULE, ENFORCED RATHER THAN REMEMBERED
#
# Added 2026-09-14. The owner's rule is no em dashes and no double hyphens
# anywhere, including code comments, docstrings, UI text and docs. The owner has had
# to repeat it many times, which is the tell: it was living in a preference
# and nowhere in the tree. The tree was swept by hand on 2026-09-13 and four
# double hyphens were still sitting in config.example.json the next day, plus
# a handful in comments and two in strings the model and the user actually
# read. A hand sweep finds what you look at.
#
# "---" is already above and stays there so its message keeps naming the
# separator case. These two are the rest of it.
#
# EXEMPTIONS, and they are the reason this is not just another entry in the
# list. A double hyphen is real syntax in three places that legitimately
# appear inside prose:
#   a command line flag, --strict, --release, mentioned in a comment or a doc
#   a SQL comment marker, which is how Schema.SQL annotates every column
#   an HTML comment marker, and an ASCII diagram elbow like +--
# So the check skips a line when the double hyphen is followed by a letter
# (that is a flag), and prose_files already keeps it away from .sql. What is
# left is the case the rule is actually about: a dash used as a pause in a
# sentence.
DASH_CHARS = "—–"      # em dash, en dash


def _dash_problems(line: str) -> list[str]:
    """The dash rule on one prose line, flags and markers left alone."""
    out = []
    if any(c in line for c in DASH_CHARS):
        out.append("an em or en dash; use a comma, or the comma-run style")
    if "--" in line and "---" not in line:
        # Strip the legitimate shapes, then see whether any pair survives.
        rest = re.sub(r"(?:<!--|-->)", "", line)
        rest = re.sub(r"(^|[\s\"'`(\[=/])--[A-Za-z]", r"\1", rest)
        rest = re.sub(r"^[\s+|\\/`]*\+?--", "", rest)
        if "--" in rest:
            out.append("a double hyphen; use a comma, or the comma-run style")
    return out

# Identifiers too short or too common to match on without drowning in noise.
# "pc", "dev", "user" as a username would flag every third line.
MIN_IDENTIFIER_LEN = 4

GENERIC_STOPWORDS = {
    "user", "users", "test", "admin", "guest", "home", "root", "local",
    "localhost", "default", "public", "desktop", "documents", "windows",
    "program files", "youruser", "yourname", "example", "sample",
}


# WHAT COUNTS AS LOCAL

def discover_identifiers() -> dict[str, str]:
    """
    Strings that identify THIS machine or THIS operator, found at runtime.

    Returns {identifier: where it came from}. The source string is carried
    along so a failure can say "this is your Windows username" rather than
    just printing the offending line.
    """
    found: dict[str, str] = {}

    def add(value, origin: str):
        if value is None:
            return
        text = str(value).strip()
        if (len(text) >= MIN_IDENTIFIER_LEN
                and text.lower() not in GENERIC_STOPWORDS):
            found.setdefault(text, origin)

    # The machine and the person at it.
    try:
        add(Path.home().name, "your home directory name")
    except (OSError, RuntimeError):
        pass

    for var in ("USERNAME", "USER", "LOGNAME", "COMPUTERNAME"):
        add(os.environ.get(var), f"environment variable {var}")

    try:
        hostname = socket.gethostname()
        add(hostname, "this machine's hostname")
        # host.local -> also check the bare label
        add(hostname.split(".")[0], "this machine's hostname")
    except OSError:
        pass

    # The machine-specific fields of config.json.
    #
    # NOT every value in the file. The first version of this check walked all
    # of them and produced 83 failures, of which zero were real: config.json
    # holds "127.0.0.1", "5000", "ollama" and "model-chat" too, and those
    # are universal defaults that belong in source. A check that cries wolf 83
    # times gets switched off within a day, and then it is worth less than no
    # check at all.
    #
    # So only the fields that are inherently about THIS deployment. Everything
    # else is caught by the generic patterns below, which need no config at
    # all, a private host address is a leak whether or not it is in anyone's
    # config file.
    # SOURCE_ROOT, not PROJECT_ROOT, and this is not a detail.
    #
    # In release mode PROJECT_ROOT is the sanitised copy, which by design
    # contains no config.json and no .env. Reading identifiers from there
    # would discover NOTHING, and a check with nothing to look for passes
    # everything, silently, and exactly when it is being trusted most.
    #
    # What to look for comes from the working folder. What to look IN comes
    # from wherever the check was pointed.
    config_path = SOURCE_ROOT / "config.json"
    if config_path.exists():
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}

        lm = data.get("linux_monitor") or {}
        add(lm.get("user"), "the SSH user from config.json")
        add(lm.get("key_path"), "the SSH key path from config.json")
        for host in (lm.get("hosts") or []):
            if isinstance(host, dict):
                add(host.get("label"), "a host label from config.json")
                add(host.get("user"), "an SSH user from config.json")
                add(host.get("key_path"), "an SSH key path from config.json")

        geo = data.get("geoip") or {}
        add(geo.get("home_label"), "your geoip home_label from config.json")

    env_path = SOURCE_ROOT / ".env"   # See config_path above.
    if env_path.exists():
        try:
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    _, _, value = line.partition("=")
                    value = value.strip().strip("'\"")
                    if len(value) >= 8:          # a real secret, not a flag
                        add(value, "a secret from .env")
        except OSError:
            pass

    return found


# Addresses that look local but are correct in source.
#
# Loopback is not a disclosure, it is the same address on every machine,
# which is exactly what makes it universal.
#
# The documentation ranges are the intended way to write an example address:
# RFC 5737 reserved them so nobody's real network gets used as a placeholder,
# and RFC 2606 does the same for domain names. config.linux.example.json uses them.
ALLOWED_ADDRESSES = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1"}

DOCUMENTATION_NETS = [
    ipaddress.IPv4Network("192.0.2.0/24"),     # RFC 5737 TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # RFC 5737 TEST-NET-3
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECRET_RES = [
    # OpenSSH's security key types (sk-ecdsa-sha2-..., sk-ssh-...) are not keys.
    (re.compile(r"\bsk-(?!ecdsa-sha2-|ssh-)[A-Za-z0-9_-]{16,}\b"), "an API key"),
    (re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])"), "a 64-hex key"),
]
WIN_USER_RE = re.compile(r"[A-Za-z]:\\+Users\\+([^\\\"'\s,]+)", re.I)


def check_line(line: str, identifiers: dict[str, str]) -> list[str]:
    """Every problem on one line, as human-readable strings."""
    problems = []

    # 1. Private IPv4 addresses. A subnet literal (10.0.0.0/8) is a universal
    #    constant and legitimate in network code; a specific host on it is not.
    for match in IPV4_RE.finditer(line):
        text = match.group()
        if text in ALLOWED_ADDRESSES:
            continue
        try:
            addr = ipaddress.IPv4Address(text)
        except ValueError:
            continue
        if not addr.is_private or addr.is_loopback:
            continue
        if any(addr in net for net in DOCUMENTATION_NETS):
            continue                       # an intentional example address
        rest = line[match.end():]
        if rest.startswith("/"):           # CIDR: a range, not a host
            continue
        if int(text.split(".")[-1]) == 0:  # network address, not a host
            continue
        problems.append(
            f"private address {text}, use a documentation address "
            f"(192.0.2.x) or read it from config.json"
        )

    # 2. Secrets.
    for pattern, label in SECRET_RES:
        for match in pattern.finditer(line):
            problems.append(f"{label} ({match.group()[:8]}...), belongs in .env")

    # 3. Someone's actual Windows profile path.
    for match in WIN_USER_RE.finditer(line):
        name = match.group(1)
        if name.lower() not in GENERIC_STOPWORDS and not name.startswith("<"):
            problems.append(
                f"a real Windows profile path (C:\\Users\\{name}), "
                f"use a placeholder or read it from config"
            )

    # 4. The discovered identifiers.
    lowered = line.lower()
    for identifier, origin in identifiers.items():
        if identifier.lower() in lowered:
            problems.append(f"{origin} appears verbatim ({identifier!r})")

    return problems


# RUNNER

def _candidates() -> list[Path]:
    files = []
    for path in sorted(PROJECT_ROOT.rglob("*")):
        if path.suffix.lower() not in SCAN_SUFFIXES or not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name == SELF:
            continue
        files.append(path)
    return files


def partition() -> tuple[list[Path], list[Path], list[Path]]:
    """
    Split every candidate into (scanned, exempt, claimed_but_tracked).

    The third list is the one that matters and it is why this function exists.

    A name in NEVER_SCANNED or WORKING_FILES is a CLAIM that the file does not
    ship. Git is then asked whether that is true. Anything claimed as exempt
    that git would nonetheless publish goes into the third list and is scanned
    anyway, loudly, because a file nobody meant to ship is exactly the file
    nobody has proofread.

    When git cannot be asked, no repository yet, or no git on PATH, every
    claim is unverified, so all claimed files are scanned. Failing towards
    scanning is the safe direction: the cost is noise, and the cost of the
    other direction is a published SSH port.
    """
    candidates = _candidates()

    # RELEASE MODE: NOTHING IS EXEMPT.
    #
    # The working folder is expected to be full of local detail, config.json
    # holds the real network on purpose, and the audit and spec documents are
    # internal by design. That is not a leak, it is the working copy working.
    #
    # Publishing here does not mean pushing this folder. It means building a
    # separate sanitised copy and publishing THAT. So the only tree whose
    # cleanliness is a security property is the copy, and in the copy there is
    # no such thing as a file that is allowed to contain local detail. If a
    # working document reached the release folder, that is precisely the bug
    # this check exists to catch, and exempting it by name would hide it.
    if RELEASE_MODE:
        return candidates, [], []

    claimed = [p for p in candidates
               if p.name in NEVER_SCANNED or p.name in WORKING_FILES]

    shipping, asked_ok = git_will_ship(candidates)

    exempt, tracked = [], []
    for path in claimed:
        if not asked_ok:
            # No repository, or git unavailable. Nothing can ship yet, so the
            # claim is untestable rather than false. Reported as unverified.
            exempt.append(path)
        elif path.resolve() in shipping:
            tracked.append(path)
        else:
            exempt.append(path)

    scanned = [p for p in candidates if p not in exempt]
    return scanned, exempt, tracked


def machine_state_present() -> list[Path]:
    """
    Any machine-state file sitting in the tree being checked.

    Matched by name across the whole tree rather than by suffix, because
    .jsonl is not in SCAN_SUFFIXES and adding it there would pull in every
    other .jsonl for a leak scan it does not need.
    """
    found = []
    for path in PROJECT_ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.name in MACHINE_STATE:
            found.append(path)
    return sorted(found)


def source_files() -> list[Path]:
    return partition()[0]


def prose_files() -> list[Path]:
    """
    Files whose comments and text are subject to the house style.

    Wider than source_files: Markdown counts, because that is where a stray
    vertical bar does the most damage. It silently starts a table and the
    paragraph stops rendering as a paragraph.
    """
    files = []
    for path in sorted(PROJECT_ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name == SELF:
            continue
        if path.suffix.lower() in PROSE_SUFFIXES or path.name in PROSE_NAMES:
            files.append(path)
    return files


def prose_lines(path: Path):
    """
    Yield (line number, text) for the parts of a file that are prose.

    Code is skipped deliberately. SQLite string concatenation and Python type
    unions both use a vertical bar and are correct; banning the character
    outright would mean banning valid code to tidy comments.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    suffix = path.suffix.lower()

    if suffix in {".md", ".txt"} or path.name in PROSE_NAMES:
        for number, line in enumerate(source.splitlines(), 1):
            if path.name in PROSE_NAMES and not line.lstrip().startswith("#"):
                continue
            yield number, line
        return

    if suffix == ".py":
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
        except (tokenize.TokenError, IndentationError):
            return
        for token in tokens:
            if token.type == tokenize.COMMENT:
                yield token.start[0], token.string
            elif (token.type == tokenize.STRING
                  and token.line.strip().startswith(('"""', "'''", 'r"""'))):
                for offset, line in enumerate(token.string.splitlines()):
                    yield token.start[0] + offset, line
        return

    if suffix == ".html":
        inside = False
        for number, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if "<!--" in line:
                inside = True
            if inside or stripped.startswith("//"):
                yield number, line
            if "-->" in line:
                inside = False


def check_style(line: str) -> list[str]:
    """House-style violations on one prose line."""
    problems = []
    for banned, explanation in BANNED_IN_PROSE:
        if banned in line:
            problems.append(f"house style: contains {explanation}")
    for explanation in _dash_problems(line):
        problems.append(f"house style: contains {explanation}")
    return problems


def run() -> list[str]:
    """All failures found, empty if clean."""
    identifiers = discover_identifiers()
    failures = []

    def record(path: Path, number: int, problem: str, line: str):
        rel = path.relative_to(PROJECT_ROOT)
        failures.append(f"{rel}:{number}: {problem}\n    {line.strip()[:120]}")

    for path in source_files():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as e:
            failures.append(f"{path}: could not read ({e})")
            continue
        for number, line in enumerate(lines, 1):
            for problem in check_line(line, identifiers):
                record(path, number, problem, line)

    for path in prose_files():
        for number, line in prose_lines(path):
            for problem in check_style(line):
                record(path, number, "house style: " + problem, line)

    return failures


def split_failures(failures: list[str]) -> tuple[list[str], list[str]]:
    """
    Local-detail leaks first, house style second, and never mixed.

    1.6c, 2026-08-28. The first full run produced 122 problems, of which about
    100 were dash-run separators in working documents and about 20 were this
    machine's home path, LAN addresses, SSH username and SSH port. They were
    interleaved in one list, so the leak was buried under the cosmetics.

    That is the same failure this project has already fixed twice elsewhere:
    linux_monitor flooding the findings table, and the review queue filling
    with the same phone. Volume buries signal, and a report nobody reads to
    the bottom of is a report that has failed regardless of how correct it is.
    """
    leaks = [f for f in failures if "house style:" not in f]
    style = [f for f in failures if "house style:" in f]
    return leaks, style


def test_no_local_details():
    """
    Pytest entry point, if pytest is ever added.

    Asserts on LEAKS only, not on house style. A dash-run in a comment is not
    a reason to fail a build, and a suite that fails for cosmetic reasons gets
    marked skip and then stops catching the real thing.
    """
    leaks, _ = split_failures(run())
    assert not leaks, "\n".join(leaks)


def main(argv: list[str] | None = None) -> int:
    global PROJECT_ROOT, RELEASE_MODE

    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"-h", "--help"}:
        print(__doc__)
        return 0
    if argv and argv[0] == "--release":
        if len(argv) < 2:
            print("usage: check_no_local_details.py --release <folder>")
            return 2
        PROJECT_ROOT = Path(argv[1]).resolve()
        RELEASE_MODE = True
        if not PROJECT_ROOT.is_dir():
            print(f"Not a directory: {PROJECT_ROOT}")
            return 2

    if RELEASE_MODE:
        print(f"RELEASE MODE. Checking the sanitised copy at {PROJECT_ROOT}")
        print("Nothing is exempt here. A working document that reached this "
              "folder is a finding, not an exception.")
        if PROJECT_ROOT == SOURCE_ROOT:
            print("\nREFUSING: --release was pointed at the working folder "
                  "itself. The whole point is that the copy is a DIFFERENT "
                  "folder. Point it at the sanitised one.")
            return 2
    else:
        print("Working-folder mode. This tree is EXPECTED to contain local "
              "detail; config.json holds your real network on purpose.")
        print("This run is informational. The one that gates a push is:")
        print("    python scripts/check_no_local_details.py --release <copy>")
        print()

    identifiers = discover_identifiers()
    files = source_files()
    print(f"Scanning {len(files)} shipped files "
          f"({', '.join(sorted(SCAN_SUFFIXES))}) "
          f"against {len(identifiers)} discovered identifiers.")

    _, exempt, tracked = partition()
    if exempt:
        if (PROJECT_ROOT / ".git").exists():
            print(f"Not scanned, git confirms they do not ship ({len(exempt)}): "
                  + ", ".join(p.name for p in exempt))
        else:
            print(f"Not scanned, claim UNVERIFIED ({len(exempt)}): "
                  + ", ".join(p.name for p in exempt))
            print("  There is no git repository here yet, so nothing could be "
                  "asked whether these actually ship. Re-run after `git init` "
                  "and before the first push.")

    if tracked:
        print()
        print("*** THESE FILES ARE CLAIMED AS 'DOES NOT SHIP' AND GIT SAYS "
              "OTHERWISE ***")
        for path in tracked:
            print(f"    {path.relative_to(PROJECT_ROOT)}")
        print("    They are NOT in .gitignore, so `git add -A` publishes "
              "them. They are being scanned below rather than exempted.")
        print("    Fix by adding them to .gitignore, or by scrubbing them "
              "and removing them from WORKING_FILES.")

    # A zero here means the check is not doing its job, and it is silent
    # otherwise. It discovers what to look for from the machine it runs on, so
    # in a sandbox or a CI container it finds nothing and then passes
    # everything, which reads exactly like a clean result.
    if not identifiers:
        print("\nWARNING: ZERO identifiers were discovered, so the "
              "local-detail half of this check found nothing to look FOR and "
              "proves nothing. That happens when it runs somewhere other than "
              "the machine this project was developed on, with no config.json "
              "and no .env. Re-run it on the real machine before trusting a "
              "clean result. The house-style half below is still meaningful.")

    # Machine state is checked before the scan, and only in the copy. It is
    # not a leak, so nothing below would ever mention it, and a quiet pass is
    # the failure mode this catches.
    state = machine_state_present() if RELEASE_MODE else []
    if state:
        print(f"\n*** MACHINE STATE IN THE RELEASE COPY, {len(state)} "
              f"file(s) ***")
        for path in state:
            print(f"    {path.relative_to(PROJECT_ROOT)}")
        print("    These describe THIS install, not the project. Delete them "
              "from the copy.")
        print("    They carry no network detail, which is why the scan below "
              "will not mention them.")

    failures = run()
    leaks, style = split_failures(failures)

    if state and not failures:
        print(f"\nNo local detail found, but the machine-state file(s) above "
              f"must be removed before this copy is published.")
        return 1

    if not failures:
        print(f"\nCLEAN, no local detail found in any of the "
              f"{len(files)} shipped files.")
        return 0

    # Leaks first, always, and never interleaved with cosmetics.
    if leaks:
        print(f"\nLOCAL DETAIL, {len(leaks)} leak(s). THIS IS THE PART "
              f"THAT MATTERS:\n")
        for failure in leaks:
            print(f"  {failure}")

    if style:
        print(f"\nHOUSE STYLE, {len(style)} cosmetic issue(s), listed "
              f"after the leaks on purpose.")
        by_file: dict[str, int] = {}
        for failure in style:
            by_file[failure.split(":")[0]] = by_file.get(failure.split(":")[0], 0) + 1
        for name, count in sorted(by_file.items(), key=lambda kv: -kv[1]):
            print(f"  {count:4}  {name}")
        print("  Summarised by file rather than listed line by line. A "
              "hundred separator lines scrolling past is how the leaks above "
              "get missed.")
    print("\nDesign rule 1: network specifics live in config.json, secrets in "
          ".env. Code holds neither.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
