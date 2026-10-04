# core/voice.py
# AgentalSec, TODO 113.1. One place that decides who a sentence is for.
#
# Ported to Linux 2026-09-21 from the Windows V2 tree, which added it on
# 2026-09-18. Nothing in it is platform specific: it is a marker string, one
# helper, and a guard against a prompt that denies a capability the app has.

"""
WHY THIS EXISTS, 2026-09-18.

The owner's complaint, in the owner's words: the model keeps explaining its
deficiencies in the MIDDLE of a conversation, what it cannot do and what it
does not have, and it reads as "why are we using this tool to begin with".

The owner is right and it was my fault, twice over.

FAULT ONE. The caveats are mine. They are written into SYSTEM_PROMPT and into
nearly every tool description, and they arrive in results as fields called
how_to_read_this, blind_to and reading notes. All of it was written as
instructions to the model. None of it said so. So the model read prose,
decided prose was for the user, and passed it on. Every time.

FAULT TWO, and it is the worse one. A lot of it was simply STALE. The prompt
told the model there was no hashing and no reputation lookup long after
inspect_process started returning a sha256, a code signature and the
reputation known for that hash. A hardcoded list of what an app cannot do rots
the moment somebody builds the thing, and then the app is lying about itself
in the pessimistic direction, which nobody ever checks because it sounds
modest.

THE RULE THIS MODULE HOLDS

  A limit is said to the operator ONLY when it changes what they should do or
  believe right now. Otherwise it is noise about ourselves.

  When one does need saying it is ONE short line, attached to the claim it
  qualifies, and it states the SCOPE rather than the failure:

      "From the host sensor: X"        not   "I am blind to everything else"
      "No tunnel interface on this     not   "I cannot see proxy VPNs,
       host"                                  browser extensions, ..."

  And what the app CAN do gets answered from the live tool list, never from a
  list typed into a prompt.

WHAT THIS DOES NOT CHANGE. The rule that matters stands exactly as it was: a
function must never assert a fact it could not check, and "no match" and "I
could not look" stay different sentences. That is a rule about what the CODE
writes into a field. It was never a rule about the model's speaking voice, and
pushing it into the voice is how a limit that belongs in a field became a
paragraph in every answer.

So the fix here is RELOCATION, not removal. Every caveat still travels with
the result. It just says out loud who it is addressed to.
"""

# The marker. Prefixed onto any string in a tool result that is guidance for
# the model rather than an answer for the person reading the screen.
#
# Deliberately shouty and deliberately first. The model skims long results,
# and a marker in the middle of a paragraph is a marker nobody reads.
NOT_FOR_RECITAL = "FOR YOU, NOT FOR THE OPERATOR. DO NOT READ THIS OUT. "


def for_you(text: str) -> str:
    """
    Mark a guidance string as addressed to the model.

    Idempotent, so a note that passes through two layers does not end up
    wearing the marker twice. Empty stays empty, because marking nothing as
    not-for-recital is just noise in a payload.
    """
    if not text:
        return text
    if text.startswith(NOT_FOR_RECITAL):
        return text
    return NOT_FOR_RECITAL + text


def is_marked(text: str) -> bool:
    """True when this string already says it is not for the operator."""
    return bool(text) and text.startswith(NOT_FOR_RECITAL)


# THE STALE DENIAL GUARD
#
# Fault two, caught in code rather than written down and forgotten. Each entry
# is a phrase that DENIES a capability, paired with the tools that would make
# that denial false. If the phrase is in the prompt and any of those tools is
# registered, the prompt is lying about its own app and this goes red.
#
# It is deliberately narrow. It catches the exact denials this prompt has
# actually carried, because a clever general matcher would fire on every
# careful sentence in a file that is mostly careful sentences.
#
# Adding a tool that covers one of these? Delete the denial, do not soften it.
DENIAL_CLAIMS: list[tuple[str, tuple[str, ...]]] = [
    ("no antivirus, hashing",        ("inspect_process",)),
    ("hashing, reputation lookup",   ("inspect_process", "lookup_ip")),
    ("reputation lookup or YARA",    ("inspect_process", "lookup_ip")),
    ("no file integrity",            ("quarantine_file", "restore_file")),
    ("only scans TCP",               ("run_port_scan",)),
    ("TCP only, there is no UDP",    ("run_port_scan",)),
]


def stale_denials(prompt: str, tool_names) -> list[str]:
    """
    Every denial in `prompt` that the live tool list contradicts.

    Returns a list of plain sentences, empty when the prompt is honest. The
    caller decides what to do about it: a check fails, and a boot check could
    log it.

    Note what this does NOT do: it never says the prompt is fine. An empty
    list means none of the KNOWN stale denials are present, which is a
    narrower claim, and this docstring says so because the same rule applies
    to this function as to any other.
    """
    have = set(tool_names or ())
    low = (prompt or "").lower()
    out = []
    for phrase, tools in DENIAL_CLAIMS:
        if phrase.lower() not in low:
            continue
        live = [t for t in tools if t in have]
        if live:
            out.append(
                f"the prompt says {phrase!r} but these tools are registered: "
                + ", ".join(sorted(live))
            )
    return out
