"""
tests/test_vpn_tool.py, TODO 48.2. The VPN reading is back in the manifest,
and the two controls are still gone.

THE DECISION, 2026-09-06. 8.3 removed vpn_connect and vpn_disconnect because
connecting a tunnel is the single most effective way to blind every sensor on
this host, and blinding is the threat model. That reasoning is about CHANGING
the tunnel and it survives untouched. Reading it is a different act, and not
being able to read it produced its own failure: an answer asserted a browser
was running over a VPN with nothing behind the claim.

So the test has two halves and the second one matters more:
  the reading works, and carries its own blind spot on every answer
  the controls are still absent, from the manifest and from the dispatcher
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


from core import tool_registry as tr            # noqa: E402

names = {t["name"] for t in tr.TOOL_MANIFEST}


print("\n[1] the reading is in the manifest")
check("query_vpn_state is offered", "query_vpn_state" in names, True)
entry = next(t for t in tr.TOOL_MANIFEST if t["name"] == "query_vpn_state")
check("it takes no arguments, so there is nothing to point it at",
      entry["input_schema"].get("properties"), {})

desc = entry["description"]
# The description IS the safety property here. The failure being fixed was an
# answer that read "no tunnel" as "no VPN", so the tool has to say the
# difference where the model will actually read it.
check("it says disconnected is not the same as no VPN",
      "not the same claim" in desc.lower() or "never means" in desc.lower(),
      True)
check("it names the proxy blind spot", "proxy" in desc.lower(), True)
check("and says unknown is not a no", "not a no" in desc.lower(), True)


print("\n[2] the controls are still gone, which is the point")
check("no vpn_connect", "vpn_connect" in names, False)
check("no vpn_disconnect", "vpn_disconnect" in names, False)
# Nothing in the manifest may write to the VPN at all. A name check is cheap
# and it is the thing somebody would break by copying an old branch back in.
writers = [n for n in names if n.startswith("vpn_") or n in
           ("connect_vpn", "disconnect_vpn")]
check("nothing else can touch the tunnel either", writers, [])


print("\n[3] the reader answers, and says what it cannot see")
from tools.vpn_state import VPNState             # noqa: E402
st = VPNState().status()
check("state is one of the three", st["state"] in
      ("connected", "disconnected", "unknown"), True)
check("blind_to rides on every answer", bool(st.get("blind_to")), True)
check("and names the proxy case", "proxy" in st["blind_to"].lower(), True)
check("measured is a real flag", isinstance(st["measured"], bool), True)
if st["state"] == "disconnected":
    check("the wording is about interfaces, not about VPNs existing",
          "no tunnel interface is up" in st["note"].lower(), True)


print("\n[4] the dispatcher refuses honestly when the module is missing")
# An unloaded module must not read as 'no tunnel'. That is the same mistake
# in a different place, and it is the one 8.3 was written about.
saved = dict(tr._modules)
try:
    tr._modules.pop("vpn_state", None)
    # It comes back as the 1.8 error envelope rather than an exception, which
    # is what every other unavailable tool does. What matters is that the
    # answer is an error and not a state.
    envelope = tr.execute_tool("query_vpn_state", {})
    check("no state is returned", envelope.get("result"), None)
    check("an error is", bool(envelope.get("error")), True)
    check("and it says an unread state is not a no",
          "not the same as no tunnel" in (envelope.get("error") or "").lower(),
          True)
finally:
    tr._modules.clear()
    tr._modules.update(saved)


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
