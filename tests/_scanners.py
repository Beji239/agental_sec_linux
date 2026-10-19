# tests/_scanners.py
# Runs each security scanner and returns its findings in one shape:
# {"tool", "rule", "path", "text", "line", "message"}. Used by the
# tests/test_scan_*.py files and by scripts/security_review.py.

import glob
import importlib.metadata
import json
import os
import pathlib
import re
import site
import subprocess
import tempfile

import _tools

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY_TARGETS = ["core", "tools", "api", "ebpf", "main.py", "adapters.py"]
SKIP_DIRS = ("ebpf/.toolchain", "coverage", "__pycache__", ".git", "logs")
SEMGREP_EXCLUDE = (".toolchain", "coverage", "__pycache__", "logs")


class Unavailable(Exception):
    """The scanner could not run here; the test reports a skip."""


def _line(path: str, n: int) -> str:
    try:
        with open(ROOT / path, encoding="utf-8", errors="replace") as fh:
            for i, text in enumerate(fh, 1):
                if i == n:
                    return text.strip()
    except OSError:
        pass
    return ""


def _rel(path: str) -> str:
    p = pathlib.Path(path)
    p = p if p.is_absolute() else ROOT / p
    return str(p.resolve().relative_to(ROOT))


def _run(cmd, timeout=900, ok=(0, 1)):
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True,
                       timeout=timeout)
    if p.returncode not in ok:
        raise Unavailable(f"{cmd[0]} exited {p.returncode}: "
                          f"{(p.stderr or p.stdout)[-300:]}")
    return p


def bandit() -> list:
    exe = _tools.need("bandit")
    targets = [t for t in PY_TARGETS if (ROOT / t).exists()]
    p = _run([exe, "-r", *targets, "-x", ",".join(SKIP_DIRS), "-f", "json",
              "-q"])
    out = []
    for r in json.loads(p.stdout)["results"]:
        path = _rel(r["filename"])
        out.append({"tool": "bandit", "rule": r["test_id"], "path": path,
                    "line": r["line_number"],
                    "text": _line(path, r["line_number"]),
                    "message": r["issue_text"]})
    return out


def shellcheck() -> list:
    exe = _tools.need("shellcheck")
    files = sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*.sh")
                   if not any(str(p.relative_to(ROOT)).startswith(d)
                              for d in SKIP_DIRS))
    if not files:
        return []
    p = _run([exe, "-f", "json", "-S", "warning", *files])
    return [{"tool": "shellcheck", "rule": f"SC{r['code']}", "path": r["file"],
             "line": r["line"], "text": _line(r["file"], r["line"]),
             "message": r["message"]} for r in json.loads(p.stdout or "[]")]


def semgrep() -> list:
    exe = _tools.need("semgrep")
    rules = sorted(glob.glob(str(_tools.TOOLS_HOME / "semgrep-rules" / "*.yml")))
    rules = [r for r in rules if not r.endswith("javascript.yml")]
    if not rules:
        raise Unavailable("needs the Semgrep rule packs, run "
                          "./scripts/install_test_tools.sh")
    targets = [t for t in PY_TARGETS if (ROOT / t).exists()]
    cmd = [exe, "scan", "--metrics=off", "--disable-version-check", "--quiet",
           # tool_registry.py alone took 228 s on a loaded laptop; a timeout
           # makes the whole scan a skip, so each file gets ten minutes.
           "--json", "--timeout", "600", "--timeout-threshold", "0"]
    for r in rules:
        cmd += ["--config", r]
    for d in SEMGREP_EXCLUDE:
        cmd += ["--exclude", d]
    p = _run(cmd + targets, timeout=1800, ok=(0, 1))
    data = json.loads(p.stdout)
    timeouts = [e for e in data.get("errors", [])
                if "Timeout" in str(e.get("type"))]
    if timeouts:
        raise Unavailable(f"Semgrep timed out on {len(timeouts)} file(s), "
                          "so the scan is incomplete")
    out = []
    for r in data["results"]:
        path = _rel(r["path"])
        line = r["start"]["line"]
        out.append({"tool": "semgrep", "rule": r["check_id"].split(".")[-1],
                    "path": path, "line": line, "text": _line(path, line),
                    "message": r["extra"].get("message", "")[:200]})
    return out


def _requirement_names() -> list:
    names = []
    for raw in (ROOT / "requirements.txt").read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.-]+)", line)
        if m:
            names.append(m.group(1).lower())
    return names


def _closure(names: list) -> set:
    """The installed requirements and everything they pull in."""
    seen, todo = set(), list(names)
    while todo:
        n = re.sub(r"[-_.]+", "-", todo.pop().lower())
        if n in seen:
            continue
        try:
            dist = importlib.metadata.distribution(n)
        except importlib.metadata.PackageNotFoundError:
            continue
        seen.add(n)
        for req in dist.requires or []:
            if "extra ==" in req:
                continue
            m = re.match(r"^([A-Za-z0-9_.-]+)", req)
            if m:
                todo.append(m.group(1))
    return seen


def _install_paths() -> list:
    """Every site directory holding one of the app's packages. The user site
    alone missed the copies the distribution installs under /usr/lib."""
    paths = set()
    for n in _closure(_requirement_names()):
        try:
            paths.add(str(importlib.metadata.distribution(n).locate_file("")))
        except importlib.metadata.PackageNotFoundError:
            pass
    return sorted(paths) or [site.getusersitepackages()]


def _loaded_version(name: str):
    try:
        return importlib.metadata.distribution(name).version
    except importlib.metadata.PackageNotFoundError:
        return None


def pip_audit(installed: bool = False) -> list:
    """requirements.txt as pip would install it today, or with installed=True
    the versions on this machine, limited to what the app needs."""
    exe = _tools.need("pip-audit")
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "a.json")
        if installed:
            cmd = [exe]
            for path in _install_paths():
                cmd += ["--path", path]
        else:
            cmd = [exe, "-r", "requirements.txt"]
        p = _run(cmd + ["-f", "json", "-o", out, "--progress-spinner", "off"],
                 timeout=900)
        if not os.path.exists(out):
            raise Unavailable(f"pip-audit wrote nothing: {p.stderr[-300:]}")
        data = json.loads(open(out).read())
    keep = _closure(_requirement_names()) if installed else None
    found = []
    for dep in data.get("dependencies", []):
        name = re.sub(r"[-_.]+", "-", dep["name"].lower())
        if keep is not None and name not in keep:
            continue
        # A second, shadowed copy in another site directory is never
        # imported, so only the version Python loads counts.
        if keep is not None and dep.get("version") != _loaded_version(name):
            continue
        for v in dep.get("vulns", []):
            found.append({"tool": "pip-audit", "rule": v["id"], "path": name,
                          "line": 0, "text": dep.get("version", ""),
                          "message": f"fixed in {', '.join(v.get('fix_versions') or []) or 'no release yet'}"})
    return found


GITLEAKS_ALLOW = """[extend]
useDefault = true
[allowlist]
paths = ['''(^|/)\\.env$''', '''(^|/)config\\.json$''', '''\\.db(-wal|-shm)?$''',
         '''(^|/)logs/''', '''(^|/)coverage/''', '''(^|/)__pycache__/''',
         '''(^|/)ebpf/\\.toolchain/''', '''\\.empty_backup$''']
"""


def gitleaks() -> list:
    """The files, without the ones meant to hold secrets, and the git
    history when there is one."""
    exe = _tools.need("gitleaks")
    found = []
    with tempfile.TemporaryDirectory() as tmp:
        conf = os.path.join(tmp, "gitleaks.toml")
        open(conf, "w").write(GITLEAKS_ALLOW)
        runs = [("dir", ["dir", str(ROOT)])]
        if (ROOT / ".git").exists():
            runs.append(("git", ["git", str(ROOT)]))
        for name, args in runs:
            rep = os.path.join(tmp, f"{name}.json")
            _run([exe, *args, "--no-banner", "--redact", "-c", conf, "-f",
                  "json", "-r", rep, "--exit-code", "0"], timeout=900, ok=(0,))
            for r in json.loads(open(rep).read() or "[]"):
                found.append({"tool": "gitleaks", "rule": r["RuleID"],
                              "path": r["File"], "line": r.get("StartLine", 0),
                              "text": f"{name} {r.get('Commit', '')[:12]}",
                              "message": r.get("Description", "")})
    return found


def trivy() -> list:
    """The Docker image, built here and deleted after, scanned for known
    flaws with a fix available and for secrets. Flaws the distribution has
    not fixed yet are counted, not failed: nothing here can act on them."""
    if not (ROOT / "Dockerfile").exists():
        raise Unavailable("no Dockerfile in this folder")
    exe = _tools.need("trivy")
    if not _tools.find("docker"):
        raise Unavailable("needs docker")
    tag = "agentalsec-trivy-scan:test"
    _run(["docker", "build", "-q", "-t", tag, "."], timeout=1800, ok=(0,))
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rep = os.path.join(tmp, "trivy.json")
            _run([exe, "image", "--quiet", "--scanners", "vuln,secret",
                  "--cache-dir", str(_tools.TOOLS_HOME / "trivy-cache"),
                  "--format", "json", "--output", rep, tag],
                 timeout=1800, ok=(0,))
            data = json.loads(open(rep).read())
    finally:
        subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)
    out, trivy.unfixed = [], 0
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            if not v.get("FixedVersion"):
                trivy.unfixed += 1
                continue
            out.append({"tool": "trivy", "rule": v["VulnerabilityID"],
                        "path": r["Target"], "line": 0,
                        "text": f"{v['PkgName']} {v['InstalledVersion']} "
                                f"fixed in {v['FixedVersion']}",
                        "message": v.get("Title") or v["Severity"]})
        for x in r.get("Secrets") or []:
            out.append({"tool": "trivy", "rule": x.get("RuleID", "secret"),
                        "path": r["Target"], "line": x.get("StartLine", 0),
                        "text": "secret", "message": x.get("Title", "")})
    return out


trivy.unfixed = 0


SCANNERS = {"bandit": bandit, "shellcheck": shellcheck, "semgrep": semgrep,
            "gitleaks": gitleaks, "pip-audit": pip_audit}
