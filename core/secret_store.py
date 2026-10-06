# core/secret_store.py
# AgentalSec V2, Secret resolution.
#
# Secrets live in .env (gitignored). config.json holds only non-secret shape:
# hosts, ports, paths, model names. That split is what makes config.json
# safe to commit, which in turn is what lets a GitHub user see a working
# example configuration instead of guessing at the schema.
#
# Resolution order for every secret, highest priority first:
#   1. A real environment variable (shell, systemd, Docker, CI)
#   2. .env in the project root
#   3. config.json, LEGACY, warned about loudly, removed on next write
#
# Step 3 exists only so an existing install does not break on upgrade. It
# is a migration path, not a supported location.

import logging
import os
import secrets as _secrets
from pathlib import Path

from core import secret_crypto as crypto

logger = logging.getLogger(__name__)

# Values in .env that are DPAPI encrypted and could not be opened by this
# account, as (variable name, reason). Collected rather than raised, because
# one unreadable key should not stop the app booting: everything else still
# works and the panel can say which one is the problem. See TODO 2.2.
_DECRYPT_FAILURES: list[tuple[str, str]] = []


def decrypt_failures() -> list[tuple[str, str]]:
    """What .env held that this Windows account could not read."""
    return list(_DECRYPT_FAILURES)

ENV_API_KEY      = "AGENTAL_API_KEY"
ENV_APP_KEY      = "AGENTAL_APP_API_KEY"

# The router's SNMP read community string.
#
# It is not resolved by resolve() alongside the other two, and that is
# deliberate. Those two are needed at boot by everything; this one is needed
# by exactly one collector, which is off by default. Reading it on demand
# means the value is never held in a dict that gets logged, returned to a
# route, or passed to a constructor that did not ask for it.
#
# A community string is a password sent in clear text by SNMP v1 and v2c. It
# should be a read community, and on most consumer firmware a read community
# is all there is. That is the ceiling on what leaking it costs, and it is
# why tools/router_monitor.py implements no write operation: the credential
# is weak by design, so the containment has to be on our side of it.
ENV_ROUTER_COMMUNITY = "AGENTAL_ROUTER_COMMUNITY"


def load_dotenv(path: Path) -> int:
    """
    Read KEY=VALUE lines from .env into os.environ. Returns the count loaded.

    Deliberately not python-dotenv. This is ~25 lines of parsing and keeps
    the clean-install path at exactly the dependencies already in
    requirements.txt, which matters more for a security tool that people
    are asked to run as Administrator.

    A variable already present in the environment is never overwritten, so
    a real env var always beats the file.

    A value written as fernet:v1:... is decrypted on the way in, see
    core/secret_crypto. One that cannot be decrypted is SKIPPED and recorded
    in decrypt_failures(), not guessed at and not passed on as a key, because
    a blob handed to an API as a credential produces a 401 that blames the
    wrong thing.
    """
    if not path.exists():
        return 0

    loaded = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        logger.warning(f"Could not read {path.name}: {e}")
        return 0

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Strip one matched pair of surrounding quotes.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]

        if not key or key in os.environ:
            continue

        # An encrypted value goes back to plain here, once, at boot. Nothing
        # downstream knows or cares that .env was encrypted, which is the
        # point: adding 2.2 changed one function, not forty call sites.
        if crypto.is_protected(value):
            try:
                value = crypto.unprotect(value)
            except crypto.SecretCryptoError as e:
                _DECRYPT_FAILURES.append((key, str(e)))
                logger.warning(f"{key}: {e}")
                continue

        os.environ[key] = value
        loaded += 1

    return loaded


def resolve(config: dict, project_root: Path) -> dict:
    """
    Return {"api_key": str, "app_api_key": str, "legacy": [names]}.

    `legacy` lists any secret that had to be read out of config.json, so the
    caller can warn once at startup instead of on every use.

    A MINTED APP KEY IS WRITTEN TO .env BEFORE IT IS RETURNED, and that write
    is the point of this function rather than a nicety. Before this, the key
    was generated fresh in memory and lived only in the process dict: the
    dashboard still worked, because GET / injects whatever the app holds into
    the page, but every RESTART rotated the key. A bookmark, a script, a
    second browser tab, or any tool holding the old key was silently locked
    out with a 401 and nothing on disk explained why. The log line said "add
    it to .env", which is advice, and advice is not persistence.
    """
    load_dotenv(project_root / ".env")

    legacy = []

    model_key = os.environ.get(ENV_API_KEY, "").strip()
    if not model_key:
        model_key = ((config.get("provider") or {}).get("api_key")
                     or "").strip()
        if model_key:
            legacy.append("model provider API key")

    app_key = os.environ.get(ENV_APP_KEY, "").strip()
    if not app_key:
        app_key = (config.get("api_key") or "").strip()
        if app_key:
            legacy.append("app API key")

    # No app key anywhere, mint one. This is the app's own auth token for
    # its localhost REST API, not a third-party credential, so generating it
    # is always safe.
    if not app_key:
        app_key = _secrets.token_hex(32)
        if persist_env_value(project_root / ".env", ENV_APP_KEY, app_key):
            logger.info("Generated a new app API key and saved it to .env, "
                        "so it survives a restart.")
        else:
            logger.warning(
                "Generated a new app API key but could NOT save it to .env. "
                "The dashboard will work for this run and the key will change "
                "on the next start, which breaks anything holding the old one. "
                "Set %s in .env, or mint one on the Settings tab.", ENV_APP_KEY)

    return {
        "api_key":          model_key,
        "app_api_key":      app_key,
        "legacy":           legacy,
    }


def persist_env_value(path: Path, name: str, value: str) -> bool:
    """
    Write NAME=value into .env, creating the file if it is not there yet.

    Used for the app's own API key and nothing else. A third-party credential
    is the operator's to type: this function exists because a key this app
    GENERATES has no other home, and a generated secret that only lives in
    process memory is not a key, it is a per-run coincidence.

    An existing line for the same name is REPLACED rather than appended, so a
    run cannot leave the file holding two values for one variable where the
    parser's answer depends on line order. Every other line is preserved
    verbatim, including comments and the operator's own keys, so this never
    rewrites a file it did not have to touch.
    """
    try:
        existing = ""
        if path.exists():
            existing = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning(f"Could not read {path.name}: {e}")
        return False

    line = f"{name}={value}"
    lines = existing.splitlines()
    replaced = False
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        if stripped.split("=", 1)[0].strip() == name:
            lines[i] = line
            replaced = True
            break
    if not replaced:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"# Written automatically by AgentalSec on "
                     f"{__import__('datetime').datetime.now().isoformat(timespec='seconds')}."
                     f" Generated, not typed: safe to replace.")
        lines.append(line)

    body = "\n".join(lines) + "\n"
    try:
        path.write_text(body, encoding="utf-8")
        # .env holds the provider key too. 0600 regardless of the process
        # umask, because a world-readable secret file is the whole problem
        # that putting secrets in a file was supposed to avoid.
        os.chmod(path, 0o600)
        return True
    except OSError as e:
        logger.warning(f"Could not write {path.name}: {e}")
        return False


def router_community() -> str:
    """
    The router read community, or an empty string.

    Read from the environment on every call rather than cached, so that
    clearing it out of .env and restarting is enough to revoke it. Callers
    treat empty as "not configured" and say so; none of them substitutes a
    default. 'public' as a fallback would be a tool that starts probing a
    router the operator never pointed it at.
    """
    return os.environ.get(ENV_ROUTER_COMMUNITY, "").strip()


def secrets_in_config(config: dict) -> list[tuple[str, str]]:
    """
    Every secret PHYSICALLY present in config.json, as (label, env var name).

    Distinct from resolve()'s `legacy` list, which reports only the secrets it
    had to *fall back* to config.json for. Once .env supplies a value, `legacy`
    goes empty while the duplicate in config.json stays on disk, unread,
    unmentioned, and one `git add` from being published. This function is what
    "is config.json safe to commit?" should be asked of.
    """
    found = []
    if ((config.get("provider") or {}).get("api_key") or "").strip():
        found.append(("model provider API key", ENV_API_KEY))
    if (config.get("api_key") or "").strip():
        found.append(("app API key", ENV_APP_KEY))
    return found


def write_env_template(path: Path, app_key: str = "") -> bool:
    """Write .env.example. Never contains a real secret."""
    body = (
        "# AgentalSec secrets. Copy to .env and fill in.\n"
        "# .env is gitignored; this template is not.\n"
        "#\n"
        "# A real environment variable overrides anything set here.\n"
        "#\n"
        "# On Windows the settings panel writes these encrypted, as\n"
        "#   NAME=fernet:v1:...\n"
        "# A plain value typed in by hand keeps working, always. See TODO 2.2.\n"
        "# The converter for keys already in your file is Windows only (it\n"
        "# needs DPAPI) and is kept outside this tree, beside the two source\n"
        "# folders. On this platform plain text protected by file\n"
        "# permissions is the answer.\n"
        "\n"
        "# Model API key, for whichever provider you point AgentalSec at.\n"
        "#\n"
        "# Required. The analyst cannot answer without it.\n"
        "#\n"
        "# The endpoint is provider.api_url in config.json and the model name\n"
        "# is provider.model. They can point at an OpenAI-style chat API\n"
        "# (DeepSeek, OpenAI, OpenRouter, a server on this machine) or at the\n"
        "# Anthropic Messages API, and this is whatever that service expects.\n"
        f"{ENV_API_KEY}=\n"
        "\n"
        "# AgentalSec's own REST API key. Any 64-char hex string.\n"
        "# Generate: python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        f"{ENV_APP_KEY}=\n"
        "\n"
        "# Router SNMP READ community string. Only needed if you turn on\n"
        "# router_monitor in config.json. Leave blank and that collector\n"
        "# stays off and says so.\n"
        "#\n"
        "# Use a read-only community. AgentalSec implements no SNMP write\n"
        "# operation, but SNMP v2c sends this in clear text on the wire, so\n"
        "# a community that can also write is a credential worth stealing.\n"
        f"{ENV_ROUTER_COMMUNITY}=\n"
    )

    # The enrichment keys are DERIVED, not typed out again. This template used
    # to stop at the three above, so every keyed intel source added after it
    # was written was missing from the file a new user is told to copy: the
    # key existed, the code read it, and nothing anywhere said so. The
    # settings panel now reports that gap out loud as drift, which is how it
    # was noticed. Generating the blocks from KEYED_SOURCES means the gap
    # cannot open again.
    try:
        import textwrap
        from core.enrichment import KEYED_SOURCES
        for name, meta in KEYED_SOURCES.items():
            lines = textwrap.wrap(f"{name}: {meta['gives']}. {meta['note']}",
                                  width=74)
            body += "\n" + "".join(f"# {ln}\n" for ln in lines)
            body += f"{meta['env']}=\n"
    except Exception as e:                       # pragma: no cover
        logger.warning(f"Could not add the enrichment keys to the template: {e}")

    # The keyed search backends, TODO 53.1. Derived for the same reason: a
    # template that has to be edited by hand every time a key is added is a
    # template that goes stale, which is the drift 47 already found once.
    try:
        import textwrap
        from core.web_search import KEYED_BACKENDS
        for name, meta in KEYED_BACKENDS.items():
            lines = textwrap.wrap(
                f"{name} search backend: {meta['gives']}. Free tier: "
                f"{meta['free_tier']}. Sign up: {meta['signup']}", width=74)
            body += "\n" + "".join(f"# {ln}\n" for ln in lines)
            body += f"{meta['env']}=\n"
            if meta.get("also_env"):
                body += f"{meta['also_env']}=\n"
    except Exception as e:                       # pragma: no cover
        logger.warning(f"Could not add the search keys to the template: {e}")

    try:
        path.write_text(body, encoding="utf-8")
        return True
    except OSError as e:
        logger.warning(f"Could not write {path.name}: {e}")
        return False


def strip_from_config(config: dict) -> tuple[dict, bool]:
    """
    Remove secret fields from a config dict so it can be written back to disk
    safely. Returns (cleaned_copy, changed).
    """
    cleaned = {k: v for k, v in config.items() if k != "api_key"}
    changed = "api_key" in config

    ds = dict(cleaned.get("provider") or {})
    if ds.pop("api_key", None) is not None:
        changed = True
    if ds or "provider" in cleaned:
        cleaned["provider"] = ds

    return cleaned, changed
