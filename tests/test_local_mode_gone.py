"""
tests/test_local_mode_gone.py, local mode stays gone. TODO 105, 2026-09-14.

This file replaces tests/test_local_mode_readonly.py, which guarded a property
that no longer exists: local mode was the one configuration this app could
honestly call read only, and local mode was removed.

WHY REPLACE IT RATHER THAN JUST DELETE IT. A removal like this one is easy to
half undo. Somebody adds an Ollama branch back for a good reason, or a config
loader starts filling in a local_model block again, and the second code path
returns one function at a time with nothing failing. These checks are cheap
and they fail the moment that starts.

Runs anywhere. Reads source, imports nothing that needs a network or a device.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []


def check(label, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {got!r}"
          + ("" if ok else f"  (want {want!r})"))
    if not ok:
        fails.append(label)


from core import agent_loop as al               # noqa: E402
from core import tool_registry as tr            # noqa: E402


print("\n[1] the second backend is gone from agent_loop")
for name in ("_mode", "_local_cfg", "_local_ready", "_local_error",
             "set_mode", "mode_status", "check_ollama", "_stream_ollama",
             "_to_ollama_messages", "_ollama_url", "_strip_think",
             "LOCAL_MODE_ADDENDUM", "MIN_LOCAL_NUM_CTX", "RESPONSE_RESERVE"):
    check(f"{name} is gone", hasattr(al, name), False)

check("and model_status replaced it", hasattr(al, "model_status"), True)


print("\n[2] there is ONE manifest")
for name in ("LOCAL_TOOL_NAMES", "LOCAL_TOOL_MANIFEST", "manifest_for_mode",
             "write_tools_in_mode"):
    check(f"{name} is gone", hasattr(tr, name), False)

check("TOOL_MANIFEST is still there", len(tr.TOOL_MANIFEST) > 50, True)
check("tool_exists takes a name and nothing else",
      tr.tool_exists("query_findings"), True)
check("and says no to something that is not a tool",
      tr.tool_exists("not_a_tool"), False)


print("\n[3] nothing still branches on a mode that does not exist")
# A leftover branch on a removed mode is dead code that still decides things,
# which is worse than a leftover constant.
agent = (ROOT / "core" / "agent_loop.py").read_text(encoding="utf-8")


def code_only(text):
    out = []
    for line in text.splitlines():
        cut = line.find("#")
        out.append(line if cut < 0 else line[:cut])
    return "\n".join(out)


# Self-tested, so this section cannot pass because the stripper ate everything.
check("(the comment stripper works)",
      code_only('x = 1  # _mode == "local"').strip(), "x = 1")

agent_code = code_only(agent)
check("no mode comparison survives in agent_loop",
      '_mode ==' in agent_code, False)
check("and no ollama call does either",
      "ollama" in agent_code.lower(), False)

for path in ("core/tool_registry.py", "api/routes.py", "core/settings.py",
             "main.py"):
    src = code_only((ROOT / path).read_text(encoding="utf-8"))
    check(f"{path} has no local_model block left",
          "local_model" in src, False)


print("\n[4] the config files stopped shipping one")
import json                                      # noqa: E402
for name in ("config.linux.example.json",):
    cfg = json.loads((ROOT / name).read_text(encoding="utf-8"))
    check(f"{name} has no local_model key", "local_model" in cfg, False)
    check(f"{name} still has a provider block", "provider" in cfg, True)
    check(f"{name} keeps the endpoint that replaced it",
          "api_url" in cfg["provider"], True)


print("\n[5] the replacement is documented where somebody will look")
# CONVERTED 2026-09-21. The Windows tree documented pointing the model at a
# local server under a heading this tree does not use; the Linux setup guide
# aims the operator at .env and the Settings tab instead. The RULE is unchanged and
# is what the check is for: whatever replaces local mode has to be written down
# somewhere a reader will actually look, with the settings named.
readme = (ROOT / "SETUP.md").read_text(encoding="utf-8")
check("the setup guide says where the key goes",
      "AGENTAL_API_KEY" in readme, True)
check("and names the two settings that aim it",
      ".env" in readme and "Settings" in readme, True)


print("\n" + ("ALL CHECKS PASSED" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
