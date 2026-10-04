# core/questions.py
# AgentalSec V2, the model asks the owner something.
#
# PREREQUISITES: standard library plus core.memory_engine and core.enrichment.
# Look at the queue from the command line with:
#   python scripts/show_questions.py
#
#
# THE ONLY PLACE THIS TOOL STARTS THE CONVERSATION
#
# Everything else here waits to be asked. This is the one path where the model
# raises its hand, because there are things it genuinely cannot work out and a
# person standing next to the network can answer in five seconds. An address
# on the threat map that no registry can place. A process nobody recognises. A
# router setting that changed on a Sunday.
#
#
# THE RULES, and most of them are about not being annoying
#
# 1. ASK ONLY AFTER THE AUTOMATED PATH FAILED. Asking the owner what RDAP
#    could have answered is the fastest way to make the owner stop reading these,
#    and once the owner stops, every other rule here is worthless. file_question
#    refuses when the enrichment row resolved the thing.
#
# 2. NEVER ASK THE SAME THING TWICE. Answered, refused or ignored, it is
#    asked once. That is a UNIQUE index on (topic, entity_type, entity_value)
#    rather than a rule the model is asked to follow, because free text can be
#    rephrased around a rule without anyone meaning to.
#
# 3. THE QUESTION CARRIES WHAT WE ALREADY TRIED. Derived from the enrichment
#    row, not written by hand. "RDAP says HERN Labs, AbuseIPDB scored it 4 off
#    one report, URLhaus has nothing, none of them say whether it is yours" is
#    a five second answer. A bare "what is this address" is homework.
#
# 4. THE HINTS SAY WHERE TO LOOK, NEVER WHAT THE OWNER WILL FIND. Derived from the
#    source catalog, from which keyed sources have no key, and from the
#    entity's KIND -- which is never guessed. A hint that says "this is
#    probably a VPN exit, search for that" is the model's guess smuggled in
#    wearing a helpful hat, and the owner would then go find confirmation for
#    something nobody established. A hint built from a guessed KIND is the
#    same guess with a URL on it.
#
# 5. THREE OUTCOMES, NEVER SUMMED. answered, do_not_know, expired.
#    "I do not know either" is INFORMATION and not a failure: it means nobody
#    knows, stop asking, and this is a real unknown rather than a gap waiting
#    to be filled.
#
# 6. THE EXPIRY CLOCK STARTS WHEN THE OWNER WAS SHOWN IT. Ten days from
#    first_shown_at, not from asked_at. A question sitting behind the popup
#    budget for nine days would otherwise expire the day after the owner first sees
#    it. Not being asked and choosing not to answer are different things.
#
#
# THE INTERRUPTION BUDGET
#
# Questions are unlimited. POPUPS are not. One popup can carry several
# questions, the budget counts popups, and there is deliberately NO urgency
# bypass. The model decides what is urgent, and the week after a bypass is
# added every question arrives marked important, which is the same as having
# no budget at all. If a genuinely urgent case is ever delayed by this, that
# is a real example to design against, which is better than a guess.

import json
import logging
from datetime import datetime, timedelta, timezone

from core import memory_engine as me

logger = logging.getLogger(__name__)

# WHEN A QUESTION STOPS BEING ASKED FOR, measured 2026-09-26.
#
# The expiry clock (expire_stale) runs from first_shown_at and only ever
# moves a question the owner was SHOWN. That is right and it stays. What it cannot
# cover is the case this host actually produced: a question the owner ANSWERED --
# in chat, where the answer was recorded as an observation -- whose row was
# never closed, because nothing connects "the model filed an operator_stated
# observation about this entity" to "the question about it is answered". The
# row sat open, was counted in the waiting badge, and stayed the reply the
# model got when it tried to ask again.
#
# So the READING path names that state instead of letting it hide. It is
# deliberately NOT a fifth `state` value: the four states are the answer
# vocabulary (answered / do_not_know / expired / open) and adding a fifth
# would break every reader that sums them, the popup query included. This is
# a flag ON TOP of 'open' -- "open, and there is an operator_stated
# observation for this entity" -- which is exactly what it is.
UNHEARD_ANSWER_NOTE = (
    "An operator_stated observation exists for this entity while the question "
    "is still open. That is not proof the owner answered THIS question, the model "
    "can file an operator_stated row after asking the owner in chat, but it is "
    "the sign that the question and the owner's answer have not been joined up. "
    "Closing it is a person's decision: POST answer on the question id.")

TOPICS = {
    "identify_device": (
        "Is this device yours, and what is it? Use when the inventory has an "
        "address with no name and the hardware vendor is not enough to place "
        "it."),
    "identify_destination": (
        "Do you recognise this destination? Use for an outbound address or "
        "domain that no lookup could place, especially one on the threat map."),
    "identify_process": (
        "Do you recognise this program? Use when a binary is unsigned or "
        "unknown and no reputation source has anything on it."),
    "expected_behaviour": (
        "Is this normal for you? Use when something is unusual against the "
        "baseline but could easily be ordinary and only the owner knows."),
    "confirm_change": (
        "Did you change this? Use when a setting, a device or a pattern "
        "changed in a way that looks deliberate."),
}

DEFAULT_POPUP_DAILY_CAP = 3
DEFAULT_POPUP_MIN_GAP_MIN = 120
DEFAULT_EXPIRY_DAYS = 10

# Human-visitable lookup pages, by indicator kind. These are places the OWNER
# can go, not endpoints this app calls, and nothing here is ever fetched.
#
# Kept separate from enrichment.SOURCE_CATALOG on purpose. That catalog
# describes the API hosts the research worker talks to and why; these are web
# pages a person reads. Some overlap, most do not, and conflating them would
# mean either sending the owner to a JSON endpoint or implying the app checks
# a site it has never contacted.
HUMAN_LOOKUPS = {
    "ip": [
        ("Shodan", "https://www.shodan.io/host/{v}",
         "what services that address exposes to the internet"),
        ("Censys", "https://search.censys.io/hosts/{v}",
         "the same question from a second scanner, with certificate detail"),
        ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{v}",
         "aggregated reputation across a lot of vendors at once"),
    ],
    "domain": [
        ("VirusTotal", "https://www.virustotal.com/gui/domain/{v}",
         "aggregated reputation and who else has looked at it"),
        ("urlscan.io", "https://urlscan.io/search/#{v}",
         "what the page actually does when somebody loads it"),
    ],
    "hash": [
        ("VirusTotal", "https://www.virustotal.com/gui/file/{v}",
         "which engines flag this exact file"),
        ("MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search=sha256%3A{v}",
         "whether a sample of it has been uploaded and what family it is"),
    ],
    "process": [
        ("A literal web search", "https://duckduckgo.com/?q=%22{v}%22",
         "the name in quotes. Most unknown binaries are somebody's installer"),
    ],
}


def _pref_int(key: str, default: int) -> int:
    try:
        return int(float(me.get_preference(key, str(default))))
    except (TypeError, ValueError):
        return default


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sql_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_ts(value):
    if not value:
        return None
    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    try:
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


# WHAT WE ALREADY TRIED

def _what_was_tried(entity_value: str) -> tuple[list, bool]:
    """
    Read the enrichment row and say, per source, what it answered.

    Returns (lines, resolved). `resolved` true means the automated path
    ANSWERED this and there is nothing to ask a person about.

    Derived rather than written by the model, for the same reason the
    enrichment sources panel is derived: a hand-written account of what was
    tried drifts from what was actually tried, and drifts in the flattering
    direction.
    """
    try:
        from core import enrichment
        row = enrichment.read(entity_value)
    except Exception as e:
        logger.debug(f"enrichment unavailable while building a question: {e}")
        return ([{"source": "enrichment",
                  "said": "the research worker could not be reached, so "
                          "nothing was tried automatically"}], False)

    if not row:
        # AN EMPTY LOOKUP ROW IS TWO DIFFERENT SILENCES AND THIS USED TO PUBLISH
        # ONE. MEASURED 2026-09-26: enrichment.enqueue REFUSES an indicator
        # whose kind cannot be established ("Not a recognisable indicator.
        # This takes an IP, a domain, a CVE id, a MAC address or a file
        # hash."), so for a package name there is no lookup to run and never
        # will be -- while the sentence printed here said only "nothing has
        # been looked up for this yet", which reads as "a lookup is pending
        # or possible". The owner was being shown a gap that cannot be filled
        # as though somebody had not got round to filling it.
        try:
            from core import enrichment
            if not enrichment.classify(entity_value):
                return ([{"source": "enrichment",
                          "said": ("the research worker REFUSED this one: "
                                   "nothing here recognises its shape as an "
                                   "address, a domain, a CVE, a MAC or a "
                                   "file hash, so no lookup applies. This is "
                                   "not a lookup waiting to happen.")}], False)
        except Exception as e:
            logger.debug(f"could not ask enrichment whether it would refuse: {e}")
        return ([{"source": "enrichment",
                  "said": "nothing has been looked up for this yet"}], False)

    # SHAPE NOTE, checked against enrichment.py rather than assumed. `tried`
    # is a list of source NAMES and `sources` is a list of URL STRINGS. They
    # are not parallel and they do not pair up: a source can answer without
    # contributing a citable url. So the names carry the account of what was
    # asked, and the urls are listed separately as the receipts.
    lines = []
    fields = row.get("fields") or {}
    tried_names = [str(n) for n in (row.get("tried") or [])]
    if tried_names:
        lines.append({"source": "asked", "said": ", ".join(tried_names)})
    else:
        lines.append({"source": "asked", "said": "nothing was asked"})

    for url in row.get("sources") or []:
        lines.append({"source": "receipt", "said": str(url), "url": str(url)})

    if row.get("gap"):
        lines.append({"source": "the gap this leaves", "said": row["gap"]})
    if row.get("stale"):
        lines.append({"source": "note",
                      "said": "that lookup has expired, so it is also out of "
                              "date"})

    # A resolved row means the automated path DID answer. The owner should not
    # be asked. The one exception is ownership: no registry on earth knows
    # whether a device is the owner's, so identify_device is never blocked by this.
    resolved = row.get("status") == "resolved" and not row.get("stale")
    if fields:
        summary = ", ".join(f"{k}={v}" for k, v in list(fields.items())[:4])
        lines.insert(0, {"source": "what came back", "said": summary})
    return lines, resolved


def _research_hints(entity_value: str, kind: str = None) -> list:
    """
    Where THE OWNER can look, that this app could not.

    Two halves, both DERIVED:
      1. keyed sources with no key, straight out of enrichment.KEYED_SOURCES,
         carrying that source's own note about how to get one.
      2. human-readable lookup pages for this kind of indicator.

    NEVER a hint about what the owner will find. See rule 4 in the header.

    A KIND THAT CANNOT BE ESTABLISHED PRODUCES NO KIND-SPECIFIC HINTS --
    measured, 2026-09-26. This function used to fall back to "ip" whenever
    classify() answered None, so the ONE question on this host's own queue, a
    PACKAGE name (example-app), was handed Shodan, Censys and VirusTotal links
    with the package name pasted into an IP address URL, plus three IP
    sources named as "not asked". A hint whose whole purpose is to say where
    to look was sending the owner to the wrong kind of place entirely, and it
    was doing it on the strength of a default nobody chose.

    The fallback looked harmless because classify() usually knows: an address,
    a domain, a CVE, a MAC, a hash and a process name are all recognised by
    shape. What it was really doing was dressing up "this app does not know
    what this thing is" as "here are some IP lookups for it". The keyed-source
    half of the hints was worse than useless for the same reason: it named
    abuseipdb, abuse.ch and greynoise as not asked about a FILE, which tells
    the owner the app tried to run IP reputation on a package.

    So: the kind is either established or there are no KIND-SPECIFIC hints,
    and the caller is TOLD that rather than left to read the empty list as
    "there is nowhere to look". The generic half (a quoted web search, below)
    does not depend on the kind and still goes out.
    """
    hints = []
    kind_known = False

    try:
        from core import enrichment
        kind = kind or enrichment.classify(entity_value)
        kind_known = bool(kind)
        if kind_known:
            for name, spec in enrichment.KEYED_SOURCES.items():
                if kind not in spec.get("kinds", ()):
                    continue
                if enrichment._keyed_available(name):
                    continue
                hints.append({
                    "label": f"{name} was not asked",
                    "url": None,
                    "why": f"no key is set. {spec.get('note', '')}".strip(),
                })
    except Exception as e:
        logger.debug(f"could not derive keyed-source hints: {e}")

    if kind_known:
        for label, template, why in HUMAN_LOOKUPS.get(kind, []):
            hints.append({"label": label,
                          "url": template.format(v=entity_value),
                          "why": why})

    if not hints:
        # NO HINT IS BETTER THAN A WRONG HINT, and the sentence has to say
        # which of the two silences this is. The alternative -- the IP links
        # this used to publish for anything it could not classify -- is rule 4
        # broken with a default.
        hints.append({
            "label": "no kind was established for this",
            "url": None,
            "why": ("nothing here recognised the shape of this as an address, "
                    "a domain, a file hash, a MAC or a program, so no "
                    "lookup service applies. That is the app failing to "
                    "classify it, NOT evidence about the thing itself."),
        })

    # THE GENERIC HALF rides last when it is the only usable one, and last is
    # where it belongs in every case: it is the weakest hint there is.
    if not kind_known:
        for label, template, why in HUMAN_LOOKUPS.get("process", []):
            hints.append({"label": label,
                          "url": template.format(v=entity_value),
                          "why": why})
    return hints


# ASKING

def file_question(session_id: str, topic: str, entity_type: str,
                  entity_value: str, question: str,
                  why_stuck: str = None) -> dict:
    """
    Put a question to the owner. Refuses anything the owner should not be bothered with.
    """
    topic = (topic or "").strip().lower()
    if topic not in TOPICS:
        return {"success": False,
                "error": (f"topic must be one of {', '.join(TOPICS)}. Got "
                          f"{topic!r}. The list is fixed so the same question "
                          f"cannot be asked twice in different words.")}

    entity_type = (entity_type or "").strip().lower()
    if entity_type not in ("ip", "process", "port", "user"):
        return {"success": False,
                "error": "entity_type must be one of ip, process, port, user."}

    entity_value = (entity_value or "").strip()
    question = (question or "").strip()
    if not entity_value or not question:
        return {"success": False,
                "error": "entity_value and question are both required."}

    tried, resolved = _what_was_tried(entity_value)

    # RULE 1. An answered lookup means there is nothing to ask. Ownership is
    # the exception and it is not a loophole: no registry anywhere knows
    # whether a device belongs to the owner, so a resolved row says nothing about
    # that question.
    if resolved and topic != "identify_device":
        return {
            "success": False,
            "error": ("The research worker already resolved this, so do not "
                      "spend the owner's attention on it. Read query_enrichment for "
                      f"{entity_value} and answer from that. If the lookup "
                      "answered a DIFFERENT question from the one you are "
                      "stuck on, say which, and ask under a topic that fits."),
            "refused": True,
            "already_known": tried,
        }

    hints = _research_hints(entity_value)
    now = _sql_ts(_now())

    with me._get_conn() as conn:
        existing = conn.execute(
            "SELECT id, state, answer_text, asked_at, first_shown_at, "
            "       topic, entity_type, entity_value, question "
            "FROM operator_question "
            "WHERE topic=? AND entity_type=? AND entity_value=?",
            (topic, entity_type, entity_value)).fetchone()
        if existing:
            # RULE 2. Asked once, ever. Answered rows hand back the answer so
            # the model is not stuck repeating itself; open ones just say wait.
            #
            # WAITING IS NOT NOTHING, and this branch used to say nothing
            # else. MEASURED 2026-09-26 on this host's own queue: one question,
            # open since 2026-09-23, shown to the owner that same night, and STILL
            # the thing the model is handed when it tries to ask. Two costs
            # came out of that, and both are fixed here rather than left for
            # the next reader:
            #
            #   * the caller was told "wait" and not HOW LONG, so it could not
            #     tell a question filed a minute ago from one a machine has
            #     been carrying for days;
            #   * the QUESTION ITSELF was not handed back, so the caller could
            #     not tell what was actually put to the owner -- which is the one
            #     thing it needs to decide whether its new question is the
            #     same question or a different one wearing the same topic.
            #     (A topic is not a question. The unique index is on
            #     (topic, entity_type, entity_value) and the prose is free.)
            #
            # THIS DOES NOT RE-ASK AND DOES NOT REOPEN. The refusal stands,
            # exactly as rule 2 says; the reply just carries the state of the
            # thing being refused.
            waited = ""
            filed = _parse_ts(existing["asked_at"])
            if filed:
                secs = (_now() - filed).total_seconds()
                waited = (f"{int(secs // 86400)} day(s), "
                          f"{int((secs % 86400) // 3600)} hour(s)")
            return {
                "success": False,
                "error": ("You have already asked this. A question is put to "
                          "the owner once, whatever came back."),
                "already_asked": True,
                "state": existing["state"],
                "his_answer": existing["answer_text"],
                "question_id": existing["id"],
                "asked_at": existing["asked_at"],
                "waiting_for": waited or None,
                "first_shown_at": existing["first_shown_at"],
                "already_asked_text": existing["question"],
                "note": (
                    "This is the question that is already filed, with its "
                    "state. It has NOT been re-asked and it is NOT reopened. "
                    + ("The owner has not been shown it yet."
                       if not existing["first_shown_at"] else
                       "The owner has been shown it; it leaves the queue on its own "
                       "after the expiry window if the owner does not answer.")
                    + " If what you want to ask is genuinely a DIFFERENT "
                      "question, it needs a topic that fits it, not this one."),
            }

        cursor = conn.execute("""
            INSERT INTO operator_question
                (session_id, asked_at, topic, entity_type, entity_value,
                 question, why_stuck, tried_json, hints_json)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (session_id, now, topic, entity_type, entity_value, question,
              why_stuck, json.dumps(tried), json.dumps(hints)))
        new_id = cursor.lastrowid

        # WHAT THE APP SAID TO THE OWNER IS WITNESSED, in the same transaction as
        # the row, added 2026-09-26. The argument is in core/integrity's
        # SEALED_TABLES block: every other witness in that journal is the
        # app's account of the network or of its own decisions, and this is
        # the app's account of its ADVICE -- the prose and the why_stuck a
        # person reads when deciding whether to spend the owner's attention on it.
        # Measured before this was written: the one question on this host's
        # queue carried a sentence about a file that was not true, and there
        # was nothing attesting to what the app had told the owner.
        try:
            from core import integrity
            integrity.seal_row("operator_question", new_id, conn=conn)
        except Exception as e:                      # noqa: BLE001
            # Never fatal. The question is filed and that is the important
            # half; a seal that can lose the question is a seal that gets
            # removed. Same call core/actions.py makes about its own row.
            logger.error(f"Filed question {new_id} but could not seal it: {e}")

    logger.info("Question filed for the operator: %s on %s", topic, entity_value)
    return {
        "success": True,
        "question_id": new_id,
        "tried": tried,
        "hints": hints,
        "note": ("Filed. The owner is not interrupted immediately: questions gather "
                 "and one popup carries several, under a daily budget. The owner may "
                 "also never answer, and after "
                 f"{_pref_int('question_expiry_days', DEFAULT_EXPIRY_DAYS)} "
                 "days from when the owner is actually shown it, it retires. Do not "
                 "wait on this and do not ask again."),
    }


# THE INTERRUPTION BUDGET

def popup_due(in_chat: bool = False, actions_waiting: int = 0) -> dict:
    """
    Should a popup go on the owner's screen right now, and what would it carry?

    READ ONLY. Deciding is separate from doing, so the dashboard can poll this
    on a timer without every poll burning a slot. claim_popup is what actually
    spends the budget.

    in_chat true means the owner is looking at the chat tab. No popup then: the
    question can simply be said to the owner where the owner already is. The popup is a
    doorbell, and ringing it at somebody standing in the doorway is the exact
    behaviour this whole design is trying to avoid.
    """
    now = _now()
    cap = _pref_int("question_popup_daily_cap", DEFAULT_POPUP_DAILY_CAP)
    gap = _pref_int("question_popup_min_gap_min", DEFAULT_POPUP_MIN_GAP_MIN)

    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "operator_question"):
            return {"due": False, "reason": "the question queue does not exist yet"}

        waiting = me._rows_to_dicts(conn.execute("""
            SELECT id, topic, entity_value, question
            FROM operator_question
            WHERE state = 'open' AND first_shown_at IS NULL
            ORDER BY id ASC
        """).fetchall())

        # ACTIONS RIDE THE SAME BUDGET.
        #
        # A parked action is a card that waits on the owner, which is an
        # interruption of exactly the kind this budget governs, so it goes
        # through here rather than getting a doorbell of its own. Two
        # interrupt systems with two budgets is how a tool becomes something
        # people mute.
        #
        # WITHOUT THIS, a queued approval could sit unseen indefinitely: the
        # action queue notifies once, at filing time, and a notification that
        # arrived while the owner was asleep had nothing behind it that ever tried
        # again. The popup is the second attempt.
        #
        # actions_waiting comes from the caller (the route reads
        # actions.pending_count) rather than from an import here, so this
        # module keeps knowing nothing about the action queue.
        actions_waiting = int(actions_waiting or 0)

        if not waiting and not actions_waiting:
            return {"due": False, "waiting": 0, "actions_waiting": 0,
                    "reason": "nothing is waiting to be shown"}

        spent = conn.execute(
            "SELECT COUNT(*) FROM operator_popup WHERE shown_at >= ?",
            (_sql_ts(now - timedelta(hours=24)),)).fetchone()[0]
        last = conn.execute(
            "SELECT shown_at FROM operator_popup ORDER BY id DESC LIMIT 1"
        ).fetchone()

    if in_chat:
        return {"due": False, "waiting": len(waiting),
                "actions_waiting": actions_waiting,
                "reason": ("the owner is in the chat tab, so ask the owner there instead "
                           "of interrupting the owner"),
                "ask_in_chat": True, "questions": waiting}

    if spent >= cap:
        return {"due": False, "waiting": len(waiting),
                "actions_waiting": actions_waiting,
                "reason": f"the interruption budget is spent, {spent} of {cap} "
                          f"in the last 24 hours"}

    if last:
        since = _parse_ts(last["shown_at"])
        if since and (now - since) < timedelta(minutes=gap):
            mins = int((now - since).total_seconds() // 60)
            return {"due": False, "waiting": len(waiting),
                    "actions_waiting": actions_waiting,
                    "reason": f"the owner was interrupted {mins} minutes ago and the "
                              f"minimum gap is {gap}"}

    return {"due": True, "waiting": len(waiting), "questions": waiting,
            "actions_waiting": actions_waiting,
            "budget_left": cap - spent - 1}


def claim_popup(question_ids: list = None, actions_waiting: int = 0) -> dict:
    """
    Record that a popup went on the owner's screen, and start the expiry clocks.

    SEPARATE FROM popup_due ON PURPOSE. A read that spent budget would mean a
    dashboard polling every eight seconds burned the day's interruptions
    without showing the owner anything. This is called once, by the thing that
    actually painted the popup.
    """
    decision = popup_due(actions_waiting=actions_waiting)
    if not decision.get("due"):
        return {"shown": False, **decision}

    ids = question_ids or [q["id"] for q in decision.get("questions") or []]
    now = _sql_ts(_now())

    with me._get_conn() as conn:
        # A popup carrying only an approval card has no question ids, so the
        # UPDATE is skipped rather than run with an empty IN () list, which is
        # a syntax error in SQLite. The popup row is still written, because
        # the interruption happened and the budget has to know about it.
        if ids:
            placeholders = ",".join("?" for _ in ids)
            conn.execute(f"""
                UPDATE operator_question
                   SET first_shown_at = ?
                 WHERE id IN ({placeholders}) AND first_shown_at IS NULL
            """, (now, *ids))
        conn.execute("""
            INSERT INTO operator_popup (shown_at, question_ids, carried)
            VALUES (?,?,?)
        """, (now, json.dumps(ids), len(ids)))

    logger.info("Operator popup shown, carrying %d question(s) and %d action "
                "card(s).", len(ids), int(actions_waiting or 0))
    return {"shown": True, "carried": len(ids), "question_ids": ids,
            "actions_waiting": int(actions_waiting or 0)}


def mark_shown_in_chat(question_ids: list) -> dict:
    """
    The owner is in the chat and the question was said to the owner there.

    THIS DOES NOT SPEND THE POPUP BUDGET, because no popup happened. It does
    start the expiry clock, which is the honest call: the owner was shown it.

    It is worth naming the case this cannot tell apart. The chat tab being
    open does not prove the owner is at the desk. If the tab is open and the owner is out,
    the question is marked shown and the ten days start running while nobody
    reads it. The alternative, waiting for proof the owner read it, needs a signal
    the app does not have, and would leave questions unshown forever. The
    state stays 'open' either way, so an unanswered question is never mistaken
    for a refusal.
    """
    ids = [int(i) for i in (question_ids or [])]
    if not ids:
        return {"shown": 0}
    now = _sql_ts(_now())
    with me._get_conn() as conn:
        placeholders = ",".join("?" for _ in ids)
        cur = conn.execute(f"""
            UPDATE operator_question SET first_shown_at = ?
             WHERE id IN ({placeholders}) AND first_shown_at IS NULL
        """, (now, *ids))
        return {"shown": cur.rowcount or 0, "via": "chat"}


# ANSWERING

def answer(question_id: int, answer_text: str = None,
           do_not_know: bool = False) -> dict:
    """
    The owner answers, or says the owner does not know either.

    'I do not know' IS AN ANSWER AND IS STORED AS ONE. It closes the question
    so the owner is never asked again, and it says something the app could not
    otherwise learn: that this is a real unknown rather than a gap waiting to
    be filled. Throwing it away, or filing it as no answer, would leave the
    question looking ignored when the owner actually engaged with it.
    """
    now = _sql_ts(_now())
    with me._get_conn() as conn:
        row = conn.execute("SELECT * FROM operator_question WHERE id = ?",
                           (question_id,)).fetchone()
        if not row:
            return {"success": False, "error": f"no question with id {question_id}"}
        if row["state"] != "open":
            return {"success": False,
                    "error": f"that question is already {row['state']}."}

        if do_not_know:
            conn.execute("""
                UPDATE operator_question
                   SET state='do_not_know', answered_at=?, answer_text=?
                 WHERE id=?
            """, (now, answer_text or "I do not know either", question_id))
            return {"success": True, "state": "do_not_know",
                    "note": ("Recorded. Nobody knows, so this stops being a "
                             "question and becomes a known unknown.")}

        answer_text = (answer_text or "").strip()
        if not answer_text:
            return {"success": False,
                    "error": ("Say something, or pass do_not_know. An empty "
                              "answer and 'I do not know' are different "
                              "things and only one of them is useful.")}

        conn.execute("""
            UPDATE operator_question
               SET state='answered', answered_at=?, answer_text=?
             WHERE id=?
        """, (now, answer_text, question_id))
        topic = row["topic"]
        entity_type = row["entity_type"]
        entity_value = row["entity_value"]

    # FILE IT WHERE THE FACT BELONGS, not only in this table. Two places
    # holding the same fact is how they drift, which is the argument the
    # promoted-findings design already settled by refusing to keep a copy.
    #
    # THE VALUE IS CAPPED AND THE CONTEXT IS NOT. behavior_value is limited to
    # 300 characters on purpose, it is meant to be the value and not the
    # explanation, so the owner's full sentence goes in context where nothing is lost
    # and a trimmed version goes in the value.
    filed_as, file_error = None, None
    try:
        obs = me.write_behavioral_observation(
            entity_type=entity_type,
            entity_value=entity_value,
            behavior_key="operator_answer",
            behavior_value=answer_text[:280],
            session_id=f"operator-answer-{question_id}",
            context=(f"The owner was asked ({topic}): {row['question']}\n"
                     f"The owner said: {answer_text}"),
            basis="operator_stated",
        )
        if obs.get("success"):
            filed_as = f"behavioral_session:{obs['id']}"
        else:
            file_error = obs.get("error") or "the write was refused"
    except Exception as e:
        # The owner's answer is already committed in the row above. This is the
        # derived copy, so a failure here must never lose what the owner said.
        file_error = str(e)

    if file_error:
        logger.error("Operator answer %s was NOT filed as an observation: %s",
                     question_id, file_error)

    if filed_as:
        with me._get_conn() as conn:
            conn.execute("UPDATE operator_question SET answer_filed_as=? "
                         "WHERE id=?", (filed_as, question_id))

    # SAY WHICH OF THE TWO THINGS ACTUALLY HAPPENED. The first version of this
    # returned success with a note reading "Recorded as operator_stated"
    # whether or not the filing worked, and on the first run it did not work:
    # operator_answer was not in VALID_BEHAVIOR_KEYS, the write was refused,
    # the error went to the log and the caller was told it was recorded.
    #
    # That is rule two inside the feature built to honour rule two. The owner's answer
    # was safe either way, it is in operator_question, but a reader would
    # believe it had reached the baseline when it had not.
    if filed_as:
        note = ("Recorded as operator_stated, which is the strongest thing "
                "this app has for a question like this and is still not a "
                "measurement.")
    else:
        note = ("Your answer is saved on the question. It could NOT be filed "
                "as an observation, so the model will not see it in the "
                f"baseline: {file_error}. This is a defect in the app, not "
                f"something you did.")

    return {"success": True, "state": "answered", "filed_as": filed_as,
            "filing_failed": file_error, "note": note}


# EXPIRY

def expire_stale(now: datetime = None) -> dict:
    """
    Retire questions the owner was shown and did not answer.

    THE CLOCK RUNS FROM first_shown_at. A question that has never been shown
    is never expired, however old it is, because not being asked is not the
    same as not caring. That is the whole reason the column exists.

    NOTHING IS DELETED. The row keeps its question, what was tried and what
    was suggested, and gains a state. Same rule as every other withdrawal in
    this codebase.
    """
    now = now or _now()
    days = _pref_int("question_expiry_days", DEFAULT_EXPIRY_DAYS)
    cutoff = _sql_ts(now - timedelta(days=days))

    with me._get_conn() as conn:
        if not me._table_exists_ro(conn, "operator_question"):
            return {"expired": 0}
        cur = conn.execute("""
            UPDATE operator_question
               SET state = 'expired'
             WHERE state = 'open'
               AND first_shown_at IS NOT NULL
               AND first_shown_at <= ?
        """, (cutoff,))
        count = cur.rowcount or 0

    if count:
        logger.info("%d question(s) retired after %d days unanswered.",
                    count, days)
    return {"expired": count, "after_days": days}


# READING

def _unheard_answers(rows: list) -> list:
    """
    Mark the open questions that have an operator_stated observation for their
    entity -- the sign that the owner's answer and the question never got joined up.

    MEASURED 2026-09-26, on this host's own queue, and it is why this exists.
    The one question on this machine: asked 2026-09-23 03:26, shown to the owner at
    03:45, and at 03:37 -- BETWEEN those two -- the owner answered it in chat ("ok
    then do it example-app") and the model filed the answer as
    `operator_stated`: "user confirmed intentional install of example-app
    26.1.5". The question row was never closed, because nothing joins the two
    up, so eleven days later the page still shows it waiting on the owner and the
    model still gets "wait" when it tries to ask anything about that package.
    The owner had answered. The queue did not know.

    WHY THIS ONLY MARKS AND NEVER CLOSES. Closing it would be the app
    deciding that an observation is an answer to a question, and that is a
    claim the app cannot make: `operator_stated` is a basis, not a receipt,
    and the model files these from chat as well as from ask_operator. Under
    the register's rule 6 that is a behaviour change over rows already
    written, so it is named for a person to close rather than taken.

    Reads by entity_value rather than by (entity_type, entity_value), and
    says so in the output. The successful observation for this host's
    question is keyed 'process' while a refused attempt was keyed 'file' --
    the same thing, filed under two vocabularies, and a join on both columns
    would have missed one of them.
    """
    if not rows:
        return rows
    try:
        values = sorted({str(r.get("entity_value") or "") for r in rows
                         if r.get("entity_value")})
        if not values:
            return rows
        seen = {}
        with me._get_readonly_conn() as conn:
            if not me._table_exists_ro(conn, "behavioral_session"):
                return rows
            for chunk_start in range(0, len(values), 200):
                chunk = values[chunk_start:chunk_start + 200]
                ph = ",".join("?" for _ in chunk)
                got = me._rows_to_dicts(conn.execute(
                    f"SELECT entity_value, entity_type, behavior_key, "
                    f"       observed_at, substr(context, 1, 240) AS ctx, "
                    f"       substr(behavior_value, 1, 240) AS val "
                    f"  FROM behavioral_session "
                    f" WHERE entity_value IN ({ph}) "
                    f"   AND basis = 'operator_stated' "
                    f"   AND superseded_by IS NULL "
                    f" ORDER BY observed_at DESC", chunk).fetchall())
                for row in got:
                    seen.setdefault(row["entity_value"], row)
        for r in rows:
            hit = seen.get(str(r.get("entity_value") or ""))
            # `state` IS OPTIONAL IN THE CALLER'S ROW, and requiring it is how
            # this flag would silently never fire: MEASURED while writing it,
            # summary() selected the open rows WITHOUT the state column and
            # every row came back unheard_answer False against a row that had
            # one -- a feature that cannot fire, which is the defect class this
            # tree has the most entries for. A row with no state column is
            # treated as open, because every caller of this function either
            # filtered on state='open' or passed the whole table, and a
            # non-open row is only ever a row somebody else's answer closed.
            state = r.get("state", "open")
            r["unheard_answer"] = bool(hit) and state == "open"
            if r["unheard_answer"]:
                r["unheard_answer_detail"] = {
                    "observed_at": hit.get("observed_at"),
                    "entity_type_as_filed": hit.get("entity_type"),
                    "behavior_value": hit.get("val"),
                    "context_excerpt": hit.get("ctx"),
                    "note": UNHEARD_ANSWER_NOTE,
                }
    except Exception as e:
        # A read that fails must not empty the queue. Absent the flag, the
        # page renders what it always did, which is the honest fallback.
        logger.debug(f"could not check for unheard answers: {e}")
    return rows


def query_questions(state: str = None, limit: int = 100) -> list[dict]:
    where, params = [], []
    if state:
        where.append("state = ?")
        params.append(state)
    sql = "SELECT * FROM operator_question"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit or 100), 500)))

    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "operator_question"):
            return []
        rows = me._rows_to_dicts(conn.execute(sql, params).fetchall())

    for row in rows:
        for field, key in (("tried_json", "tried"), ("hints_json", "hints")):
            try:
                row[key] = json.loads(row.pop(field) or "[]")
            except (TypeError, ValueError):
                row[key] = []
    return _unheard_answers(rows)


def summary() -> dict:
    """
    The counts, kept apart, plus the owner's answers so the model can read them.

    THE COUNTS ARE LEFT ALONE, deliberately. `unheard_answer` is a flag on
    individual rows (see _unheard_answers), not a fifth state, so the four
    numbers here still add up to the number of rows and every reader that
    sums them keeps working. What the summary adds is the SENTENCE -- an
    open question with a filed operator_stated answer is named, with its id,
    so the model reading this stops treating it as a question still waiting
    on the owner. MEASURED: without it, the one row this host has is counted as
    open forever while the owner's answer sits in behavioral_session.
    """
    with me._get_readonly_conn() as conn:
        if not me._table_exists_ro(conn, "operator_question"):
            return {"available": False,
                    "note": "the question queue does not exist yet"}
        counts = {"open": 0, "answered": 0, "do_not_know": 0, "expired": 0}
        for row in conn.execute(
                "SELECT state, COUNT(*) n FROM operator_question GROUP BY state"):
            counts[row["state"]] = row["n"]

        answers = me._rows_to_dicts(conn.execute("""
            SELECT id, topic, entity_value, question, answer_text, state,
                   answered_at
            FROM operator_question
            WHERE state IN ('answered','do_not_know')
            ORDER BY answered_at DESC LIMIT 25
        """).fetchall())

        open_rows = me._rows_to_dicts(conn.execute("""
            SELECT id, state, topic, entity_type, entity_value, question,
                   asked_at, first_shown_at
            FROM operator_question
            WHERE state = 'open'
            ORDER BY id ASC LIMIT 200
        """).fetchall())

    unheard = [r for r in _unheard_answers(open_rows)
               if r.get("unheard_answer")]

    out = {
        "available": True,
        **counts,
        "answers": answers,
        "how_to_read_this": (
            "answered means the owner told you. do_not_know means the owner does not know "
            "either, which is a real answer and means nobody knows, so treat "
            "it as a standing unknown and never ask again. expired means the owner "
            "was shown it and let it go, which usually means it did not "
            "matter. open means the owner has not been shown it yet or has not "
            "replied. These four are never added together."),
    }
    if unheard:
        out["open_with_a_filed_answer"] = [
            {"question_id": r["id"], "topic": r["topic"],
             "entity_value": r["entity_value"],
             "asked_at": r["asked_at"],
             "observed_at": (r.get("unheard_answer_detail") or {}).get(
                 "observed_at"),
             "what_was_filed": (r.get("unheard_answer_detail") or {}).get(
                 "behavior_value")}
            for r in unheard]
        out["unheard_answer_note"] = UNHEARD_ANSWER_NOTE
    return out
