"""
tests/test_refusal_messages.py, a refusal has to say what it WOULD accept.

WHERE THIS CAME FROM. Watching a real session on 2026-09-06, the model wrote
a behavioural observation, got refused, said "let me correct the observation
type", got refused again, said "let me use valid keys", and only then got it
right. The refusals were correct both times. The guessing was the problem,
and the guessing is ours: the list was in the message as a printed python
set, unordered, which is not something anybody reads while they are busy.

So this checks the shape of the NO, not the yes:
  the allowed values are listed, sorted and quoted
  a near miss gets named
  a key that is real for another entity type says so
  and none of it accepts the wrong value, ever
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


from core import memory_engine as me            # noqa: E402


def refusal(fn, *args, **kwargs) -> str:
    """The message from a refusal, or '' if it did not refuse."""
    try:
        fn(*args, **kwargs)
        return ""
    except Exception as e:
        return str(e)


print("\n[1] a wrong entity_type lists the four that exist")
msg = refusal(me._validate_entity, "proces", "192.0.2.1")
check("it refused", bool(msg), True)
for t in sorted(me.VALID_ENTITY_TYPES):
    check(f"{t} is named", repr(t) in msg, True)
check("and the near miss is offered", "Did you mean 'process'?" in msg, True)


print("\n[2] a wrong behavior_key lists the keys for THAT type")
msg = refusal(me._validate_entity, "ip", "192.0.2.1", "proces_names")
check("it refused", bool(msg), True)
check("the entity type is named in the refusal", "'ip'" in msg, True)
check("and the keys are listed", "'beacon_interval'" in msg, True)
# Sorted, because the failure this is written against is somebody not reading
# the list. An unordered set is the same as no list on a long line.
keys = [k for k in sorted(me.VALID_BEHAVIOR_KEYS["ip"]) if repr(k) in msg]
positions = [msg.index(repr(k)) for k in keys]
check("in order", positions, sorted(positions))


print("\n[3] a key that belongs to another type says which one")
# The normal way this goes wrong: a real key used against the wrong entity.
# "not valid" is true and useless; naming where it IS valid is the fix.
borrowed = None
for key in me.VALID_BEHAVIOR_KEYS.get("process", set()):
    if key not in me.VALID_BEHAVIOR_KEYS.get("ip", set()):
        borrowed = key
        break
if borrowed:
    msg = refusal(me._validate_entity, "ip", "192.0.2.1", borrowed)
    check("it refused", bool(msg), True)
    check("and points at the type it would have been right for",
          "'process'" in msg, True)
else:
    print("  SKIP  no key is unique to 'process' in this schema")


print("\n[4] the refusal is still a refusal")
# Naming the right answer must never turn into accepting the wrong one. A key
# written by a guess is a row nobody can trust six weeks later.
check("a wrong type is not corrected into a right one",
      bool(refusal(me._validate_entity, "proces", "192.0.2.1")), True)
check("a wrong key is not corrected into a right one",
      bool(refusal(me._validate_entity, "ip", "192.0.2.1", "proces_names")),
      True)
check("a good pair still passes",
      refusal(me._validate_entity, "ip", "192.0.2.1", "beacon_interval"), "")


print("\n[5] the helpers themselves")
check("the list is sorted and quoted",
      me._listed({"b", "a"}), "'a', 'b'")
check("a near miss is named", me._near("beacon_intervl",
                                       ["beacon_interval", "first_seen"]),
      " Did you mean 'beacon_interval'?")
check("something unrelated gets no guess",
      me._near("zzzzzz", ["beacon_interval", "first_seen"]), "")


print("\n" + ("ALL PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(1 if fails else 0)
