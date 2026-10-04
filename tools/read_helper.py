#!/usr/bin/env python3
# tools/read_helper.py
# A read-only helper, run by the sensors with `sudo -n`, that reads a fixed
# set of things and nothing else. It exists so the code that parses hostile
# input never runs as root.
#
# Verbs (none takes an argument, and there is no "read this path" verb):
#   sudoers      the content of /etc/sudoers
#   sudoers_d    every file in /etc/sudoers.d, with mode and owner
#   root_ssh     root's authorized_keys, per key
#   dpkg_verify  dpkg -V with the package list computed here. dpkg -V
#                does NOT need root to run; root only adds 27 files in /boot.
#   proc_exe     the running file of every process, with its start time
#
# /etc/shadow and /etc/gshadow MUST NOT BE ADDED: they hold password hashes.
#
# The helper refuses to run unless its own path and every directory above
# it are root-owned and not group- or world-writable.
#
# Output is JSON with an "ok" key; exit 0 for a read, 1 for a refusal.

import json
import os
import stat
import subprocess
import sys
import time

SCHEMA = 1

# Every verb, with the paths it may touch. Written out so that reading this
# dict is enough to audit what this file can reach -- there is no path
# concatenation anywhere below.
VERBS = {
    "sudoers": {
        "paths": ["/etc/sudoers"],
        "why": "sudoers is root-only (mode 440), so the sensor watches its "
               "name, mode, owner, size and mtime and cannot see a content "
               "edit that leaves those identical.",
    },
    "sudoers_d": {
        "paths": ["/etc/sudoers.d"],
        "why": "the drop-in directory is listable but every file in it is "
               "root-only, so the CONTENTS are unwatched. A drop-in is how a "
               "line is added to sudoers without touching sudoers.",
    },
    "root_ssh": {
        "paths": ["/root/.ssh/authorized_keys"],
        "why": "root's authorized_keys grants standing root access from "
               "anywhere, and /root is mode 700 so the sensor cannot even "
               "list the directory it lives in.",
    },
    "proc_exe": {
        "paths": ["/proc"],
        "why": "/proc/<pid>/exe of another account's process is refused to "
               "the sensor, so those rows had no path to compare against a "
               "package. Every process is listed, with its start time so the "
               "caller can tell a reused pid from the one it asked about.",
    },
    "dpkg_verify": {
        "paths": [],
        "why": "runs dpkg -V with the package list computed inside this "
               "process, so no caller-supplied string reaches a command "
               "line. Elevation here only changes what dpkg can READ.",
    },
}

# A read cap, for the same reason every other reader in this tree has one:
# an attacker who can write a file can make it enormous.
MAX_BYTES = 4 * 1024 * 1024
MAX_KEYS = 500
MAX_PIDS = 65536

# dpkg -V is an integrity cross-check, not a security tool: md5sums, no
# signatures. The verb reports what it said rather than endorsing it.
DPKG_CAVEAT = (
    "dpkg -V is an integrity check and NOT a security verification: its own "
    "man page says so in those words. It compares contents against recorded "
    "md5sums, does not check signatures, and cannot detect a change made by "
    "somebody who edited the control file as well. Treat its output as "
    "evidence, not as a verdict."
)


class Refusal(Exception):
    """A verb that will not run. Always carries a sentence for the operator."""


def _refuse(msg: str):
    """Print a refusal in the same shape as a success, and exit 1."""
    json.dump({"ok": False, "schema": SCHEMA, "refused": msg,
               "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(1)


def _ok(payload: dict):
    payload["ok"] = True
    payload["schema"] = SCHEMA
    payload["at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.exit(0)


# THE SELF-CHECK. Nothing runs before this passes.

def assert_self_is_safe():
    """
    Refuse to run if this file, or any directory above it, is replaceable by
    a non-root user.

    A sudoers rule grants root to a PATH, so the path has to be one only root
    can write. The check walks from the file up to / and refuses on:
      * a real path owned by anybody but root (uid 0)
      * any group- or world-writable bit anywhere in that chain

    IT IS DELIBERATELY STRICTER THAN "NOT MY USER". Ownership by a THIRD
    unprivileged account is just as good a way in, and a rule that only looked
    for the caller's own account would pass a helper sitting in a colleague's
    home directory.
    """
    path = os.path.realpath(__file__)
    problems = []
    while True:
        try:
            st = os.stat(path)
        except OSError as e:
            problems.append(f"{path}: cannot be stat'ed ({e})")
            break
        if st.st_uid != 0:
            problems.append(
                f"{path} is owned by uid {st.st_uid}, not root. A sudoers "
                f"rule naming this path would grant root to whatever that "
                f"account chooses to put there.")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            problems.append(
                f"{path} is group- or world-writable (mode "
                f"{format(stat.S_IMODE(st.st_mode), '03o')}). Anybody who "
                f"can write it can run code as root through this verb table.")
        if path == "/":
            break
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    if problems:
        _refuse(
            "This helper refused to run because the path it is installed at "
            "could be replaced by a non-root account, which would turn the "
            "sudoers rule that names it into arbitrary root execution: "
            + " ".join(problems)
            + " Install it under /usr/local/lib/agentalsec/ (root-owned, mode "
              "755) with scripts/install_read_helper.sh. Nothing was read.")


def assert_elevated():
    """The helper is useless unelevated and must say so rather than guess."""
    if not hasattr(os, "geteuid"):
        _refuse("This platform reports no effective uid, so this helper "
                "cannot tell whether it has the privilege it needs.")
    if os.geteuid() != 0:
        _refuse(
            "This helper is running as uid %d, not root, so it can read no "
            "more than the sensor already could. That is not an error in the "
            "sensor: it means `sudo -n` did not elevate, which happens when "
            "the sudoers drop-in has not been installed, or when a password "
            "would be required and there is nobody to type it."
            % os.geteuid())


def _read(path, limit=MAX_BYTES):
    """(bytes, None) or (None, reason). Never returns empty on a failure."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except FileNotFoundError:
        return None, "gone"
    except PermissionError:
        return None, "permission denied"
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    if len(data) > limit:
        return None, f"larger than {limit} bytes, not read"
    return data, None


def _meta(path) -> dict:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"exists": False}
    except PermissionError:
        return {"exists": None, "reason": "permission denied"}
    except OSError as e:
        return {"exists": None, "reason": f"{type(e).__name__}: {e}"}
    return {"exists": True,
            "mode": format(stat.S_IMODE(st.st_mode), "03o"),
            "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size,
            "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns,
            "ino": st.st_ino,
            "type": ("dir" if stat.S_ISDIR(st.st_mode) else
                     "link" if stat.S_ISLNK(st.st_mode) else
                     "file" if stat.S_ISREG(st.st_mode) else "other")}


# THE VERBS

def verb_sudoers():
    path = "/etc/sudoers"
    meta = _meta(path)
    data, reason = _read(path)
    return {"verb": "sudoers",
            "note": VERBS["sudoers"]["why"],
            "entries": {path: {"meta": meta,
                               "readable": data is not None,
                               "unreadable_reason": reason,
                               "sha256": (_sha(data) if data is not None
                                          else None)},
                        # The content is returned so the caller decides what to do with it.
                        "content": (data.decode("utf-8", errors="replace")
                                    if data is not None else None)}}


def verb_sudoers_d():
    path = "/etc/sudoers.d"
    out = {"verb": "sudoers_d", "note": VERBS["sudoers_d"]["why"],
           "entries": {}, "unreadable": [], "total": 0, "mode": None}
    try:
        names = sorted(os.listdir(path))
    except FileNotFoundError:
        out["unreadable"].append(f"{path}: does not exist")
        return out
    except PermissionError:
        out["unreadable"].append(f"{path}: permission denied")
        return out
    except OSError as e:
        out["unreadable"].append(f"{path}: {type(e).__name__}: {e}")
        return out

    out["mode"] = _meta(path)
    files = [n for n in names if os.path.isfile(os.path.join(path, n))]
    out["total"] = len(files)
    for name in files:
        full = os.path.join(path, name)
        meta = _meta(full)
        data, reason = _read(full)
        entry = {"meta": meta, "readable": data is not None,
                 "unreadable_reason": reason,
                 "sha256": _sha(data) if data is not None else None}
        if data is not None:
            entry["content"] = data.decode("utf-8", errors="replace")
        out["entries"][name] = entry
    return out


def verb_root_ssh():
    path = "/root/.ssh/authorized_keys"
    meta = _meta(path)
    data, reason = _read(path)
    out = {"verb": "root_ssh", "note": VERBS["root_ssh"]["why"],
           "path": path, "meta": meta, "readable": data is not None,
           "unreadable_reason": reason,
           "sha256": _sha(data) if data is not None else None,
           "keys": {}}
    if data is None:
        return out
    # Per-key lines, so an added key can be named rather than counted.
    for line in data.decode("utf-8", errors="replace").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if len(out["keys"]) >= MAX_KEYS:
            out["keys_capped"] = True
            break
        parts = text.split()
        out["keys"][_sha(text.encode())] = {
            "type": parts[0] if parts else "",
            "comment": " ".join(parts[2:])[:80] if len(parts) > 2 else "",
        }
    return out


def verb_dpkg_verify():
    """
    Run dpkg -V with the package list computed HERE.

    NO CALLER-SUPPLIED ARGUMENT REACHES A COMMAND LINE. The caller cannot pass
    a package name, a flag or a path: the verb takes no arguments at all and
    the list comes from dpkg-query run by this process. That is the difference
    between a verb table and a shell.

    This exists for one measured reason: unelevated, dpkg -V reports 27 files
    as ones it could not read, and every one of them is in /boot, which is
    mode 600 root. Running it elevated moves those from "unreadable" to
    "compared". It does not make dpkg -V possible -- dpkg -V already works
    unelevated -- and the sensor does not need this verb to do tier C.
    """
    try:
        res = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Abbrev}\n"],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        raise Refusal(f"dpkg-query could not be run: {type(e).__name__}: {e}")

    names = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].strip().startswith("ii"):
            names.append(parts[0].strip())

    if not names:
        return {"verb": "dpkg_verify", "note": VERBS["dpkg_verify"]["why"],
                "ran": False,
                "reason": "dpkg-query returned no installed packages, so "
                          "there is nothing to verify.",
                "packages": 0, "stdout": "", "stderr": "", "exit": None,
                "seconds": None}

    info = "/var/lib/dpkg/info"
    loadable = []
    refused = {}
    for name in names:
        md5sums = os.path.join(info, name + ".md5sums")
        if not os.path.exists(md5sums):
            continue
        try:
            with open(md5sums, "r", encoding="utf-8", errors="replace") as fh:
                bad = None
                for n, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    parts = line.split("  ", 1)
                    if len(parts) != 2 or len(parts[0]) != 32:
                        bad = f"line {n}"
                        break
            if bad:
                refused[name] = bad
            else:
                loadable.append(name)
        except OSError as e:
            refused[name] = f"unreadable ({type(e).__name__})"

    started = time.monotonic()
    try:
        res = subprocess.run(["dpkg", "-V"] + loadable,
                             capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        raise Refusal("dpkg -V did not finish within 1800s.")
    except (OSError, subprocess.SubprocessError) as e:
        raise Refusal(f"dpkg could not be run: {type(e).__name__}: {e}")
    took = round(time.monotonic() - started, 1)

    return {"verb": "dpkg_verify", "note": VERBS["dpkg_verify"]["why"],
            "caveat": DPKG_CAVEAT,
            "ran": True, "seconds": took,
            "euid": os.geteuid(),
            "packages": len(loadable),
            "packages_installed": len(names),
            "refused": refused,
            "exit": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr.strip()[:2000]}


def _start_ticks(pid: str):
    """Field 22 of /proc/<pid>/stat: start time in clock ticks since boot."""
    data, _ = _read(f"/proc/{pid}/stat", 4096)
    if data is None:
        return None
    # The name field can hold spaces and parentheses, so split after the
    # last ")".
    rest = data.decode("utf-8", errors="replace").rsplit(")", 1)[-1].split()
    try:
        return int(rest[19])
    except (IndexError, ValueError):
        return None


def verb_proc_exe():
    """
    The running file of every process. Takes no argument: the caller cannot
    name a pid, so nothing it supplies reaches a path. The " (deleted)"
    suffix the kernel adds is kept, because it is a fact about the process.
    """
    out = {"verb": "proc_exe", "note": VERBS["proc_exe"]["why"],
           "processes": {}, "no_exe": 0, "capped": False}
    try:
        names = [n for n in os.listdir("/proc") if n.isdigit()]
    except OSError as e:
        raise Refusal(f"/proc could not be listed: {type(e).__name__}: {e}")
    for pid in sorted(names, key=int):
        if len(out["processes"]) >= MAX_PIDS:
            out["capped"] = True
            break
        entry = {"exe": None, "start_ticks": _start_ticks(pid), "reason": None}
        try:
            entry["exe"] = os.readlink(f"/proc/{pid}/exe")
        except FileNotFoundError:
            # Kernel threads have no executable, and a process can exit
            # between the listing and the read.
            entry["reason"] = "no executable (kernel thread, or exited)"
            out["no_exe"] += 1
        except OSError as e:
            entry["reason"] = f"{type(e).__name__}: {e}"
            out["no_exe"] += 1
        out["processes"][pid] = entry
    out["total"] = len(out["processes"])
    return out


def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()[:16]


HANDLERS = {
    "sudoers": verb_sudoers,
    "sudoers_d": verb_sudoers_d,
    "root_ssh": verb_root_ssh,
    "dpkg_verify": verb_dpkg_verify,
    "proc_exe": verb_proc_exe,
}


def main(argv):
    args = [a for a in argv[1:] if a]

    if not args or args[0] in ("-h", "--help"):
        sys.stderr.write(
            "AgentalSec read-only helper. Verbs, and nothing else:\n"
            + "".join(f"    {v}\n" for v in sorted(VERBS))
            + "\nUsage: read_helper.py <verb>\n"
              "       read_helper.py --verbs      # print the table, read nothing\n"
              "\nThere is no verb that takes a path. A helper that did would "
              "be sudo cat, which is not an allowlist.\n")
        return 2

    # Extra arguments are refused for every form, --verbs included.
    if len(args) > 1:
        _refuse(
            f"This helper takes exactly one argument and {len(args)} were "
            f"supplied. NO VERB TAKES A PARAMETER: every verb names one fixed "
            f"file or directory chosen in this source, so an argument here "
            f"would be a value chosen by the caller, which is the thing this "
            f"design exists to prevent. A sudoers rule ending in '*' would "
            f"allow exactly this call. NOTHING WAS READ.")

    if args[0] == "--verbs":
        # Carries 'at' and 'schema' like every other reply.
        print(json.dumps({"ok": True, "schema": SCHEMA,
                          "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                          "verbs": {v: {"paths": d["paths"], "why": d["why"]}
                                    for v, d in sorted(VERBS.items())},
                          "refuses": {
                              "/etc/shadow": (
                                  "NOT IN THE VERB TABLE AND MUST NOT BE ADDED. "
                                  "It holds password hashes and has no business "
                                  "in AgentalSec's database. Its size, mode and "
                                  "mtime are watched unelevated, which is what "
                                  "catches an account being added."),
                              "/etc/gshadow": "same rule as /etc/shadow",
                              "<any caller-supplied path>": (
                                  "there is no verb that takes a path"),
                          }},
                         indent=2))
        return 0

    verb = args[0]
    if verb not in VERBS:
        _refuse(
            f"No verb named {verb!r}. The table is fixed and this is not in "
            f"it: {sorted(VERBS)}. An unrecognised verb is refused rather than "
            f"guessed at, because a helper that accepts a near-miss is a helper "
            f"somebody will talk into reading something else. Nothing was read.")

    # The argument count is checked once, above.

    # THE ORDER MATTERS: the self-check first, before privilege is even
    # considered, because a helper installed in a writable place is unsafe
    # whether or not it is running as root.
    assert_self_is_safe()
    assert_elevated()

    try:
        payload = HANDLERS[verb]()
    except Refusal as e:
        _refuse(str(e))
    except Exception as e:                          # noqa: BLE001
        _refuse(f"The verb {verb!r} failed: {type(e).__name__}: {e}. Nothing "
                f"here says the file is fine; it says this helper could not "
                f"read it.")
    _ok(payload)


if __name__ == "__main__":
    # sys.exit so the usage exit code (2) reaches the caller.
    sys.exit(main(sys.argv))
