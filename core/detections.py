# core/detections.py
# AgentalSec V2, the register of every detection this app can raise.
#
# TODO 112, 2026-09-15. Borrowed from Snort, which has done this since 1998.
# Every Snort rule carries a sid, a number that names that exact detection
# forever, and a rev that goes up when the rule is edited. Everything else in
# that ecosystem hangs off the sid: tuning, suppression, documentation, the
# ticket somebody filed about it. The rule text can be rewritten completely
# and the sid stays, which is the entire point.
#
# WHAT THIS FIXES, WITH THE RECEIPTS
#
# Before this file, a finding had no identity of its own. The only things
# that said WHAT a row was were `source` (which sensor) and `title` (a prose
# sentence with the subject baked into it). Three consequences, all of them
# already paid for:
#
#   1. memory_engine.clear_port_findings matches the substring "192.0.2.124
#      :8888" against the title, because that string is the only surviving
#      record of which device an old port finding was about. Its own docstring
#      calls this ugly and honest. It is ugly because there was no id.
#
#   2. finding_already_open dedupes on (source, entity_type, entity_value,
#      title). Reword a title and every already-raised finding re-raises,
#      because the row now says something the database has never seen.
#
#   3. dismiss_entity is keyed on the ENTITY, so silencing one noisy
#      detection about 192.0.2.124 silences every detection about 192.0.2.124.
#      That is not tuning, that is turning a device off.
#
# packet_sniffer already felt this and invented half a solution locally: its
# dedup_key strings ("volume:192.0.2.5", "beacon:a:b") are detection ids that
# live in memory, die at restart and nothing else can read. This file is that
# idea finished and made durable.
#
# THE RULES OF THIS REGISTER
#
# A NUMBER IS NEVER REUSED. Not after a detection is deleted, not after it is
# rewritten into something else. A retired entry stays here with retired set,
# because rows in the findings table still carry that id and a reader has to
# be able to look it up. Reusing a number silently relabels history.
#
# THE ID IS NOT THE NAME. `name` is a slug for humans and can be reworded.
# `did` is the key and cannot. That split is the whole reason to use a number
# rather than a descriptive string: the description is the part that changes.
#
# REV GOES UP WHEN THE MEANING CHANGES. A threshold move, a new condition, a
# narrowed scope. Not for a typo in the summary. Findings are stamped with
# the rev that was live when they were raised, so "why did this fire in
# August but not now" has an answer that does not depend on git.
#
# AN UNREGISTERED ID IS FATAL. Same call as core/finding_policy.policy_for,
# and for the same reason: a default would let a new detection inherit
# somebody else's identity quietly. This register is only worth anything if
# nothing can raise a finding without being in it.
#
# SEVERITIES ARE DECLARED AND ENFORCED. Each entry lists every severity it is
# allowed to raise at. A detection that starts raising critical where it used
# to raise low has changed its meaning, and that should be a decision in this
# file rather than a diff in a sensor nobody re-read.
#
# THE CIA AXIS (Q3, approved 2026-09-17). Schema v35, T2.
#
# Every detection now declares WHAT KIND OF LOSS it points at. This is not a
# severity and it does not replace one: severity says how loud, the axis says
# what is at stake, and the incident ledger carries both so a reader can see
# "a quiet thing about the router's configuration" and "a loud thing about a
# process" as different shapes rather than as one number.
#
# HOW TO ASSIGN ONE. Ask what is lost IF THE THING THIS RULE POINTS AT IS
# REAL, and answer with the triad:
#
#   confidentiality  something is being TAKEN, or a channel exists through
#                    which it could be: exfiltration, intercepted traffic,
#                    access gained, credentials guessed or obtained
#   integrity        something on this host CHANGED, or a channel exists
#                    through which it could be changed: a file, a schedule,
#                    an account, a set of rules, a binary that lies about
#                    what it is
#   availability     something is NOT THERE, or the monitoring itself could
#                    not look: absence, overflow, blindness
#
# A rule can carry more than one axis, and that is a statement rather than
# hedging: a remote-code-execution attempt can both take and alter, so it says
# both. An axis on an "attempt" rule names the loss if the attempt SUCCEEDS;
# the register has no other place to say that.
#
# AN EMPTY AXIS IS A DECISION AND IT IS A REAL ONE. Empty means this rule
# reports a measurement or a discovery that carries no loss by itself: a
# volume, a new device, an inventory change. The watcher reads empty exactly
# that way, which is why assigning it by default would be the wrong kind of
# quiet. Two entries carry an empty axis for a different reason and say so in
# their own comments (PKT-1099 is not-yet-classified, the REM block is not a
# detection at all).
#
# IT IS REQUIRED, NOT DEFAULTED. Detection() takes it with no default, so a
# new entry cannot inherit "no loss" by being written in a hurry, and the
# vocabulary is checked at import so a typo cannot become an empty axis.

import logging

logger = logging.getLogger(__name__)


class UnknownDetection(Exception):
    """
    A finding named a detection id that is not registered here.

    Fatal on purpose. The alternative is a findings table where some rows can
    be traced to a rule and some cannot, which is worse than none of them
    being traceable, because it looks like it works.
    """


class MissingDetectionId(Exception):
    """A writer called save_finding without saying which detection fired."""


class BadSeverity(Exception):
    """A detection raised at a severity it does not declare."""


# The suppression wildcard. See core/memory_engine.suppress_detection for why
# this is a literal string and not NULL: in SQLite two NULLs are not equal to
# each other, so a UNIQUE index containing NULL columns does not actually stop
# duplicates, and a "silence this everywhere" rule could be inserted a hundred
# times over.
ALL_ENTITIES = "*"

# Worst first, for display. Not a validation list: memory_engine.
# VALID_SEVERITY is still the authority on what a severity may be.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# The axis vocabulary, and the order axes are displayed in. Sorted
# alphabetically they would read "confidentiality, availability, integrity",
# which buries the middle one.
AXES = ("confidentiality", "integrity", "availability")
_AXIS_ORDER = list(AXES)


class Detection:
    """One detection, with its reasoning attached."""

    def __init__(self, did, rev, name, source, entity_type, severities,
                 summary, cia, retired=False, retired_reason=None,
                 threat_label_prefix=None, kind="detection",
                 entity_is_not_a_host=False):
        self.did = did
        self.rev = rev
        self.name = name
        self.source = source
        self.entity_type = entity_type
        self.severities = frozenset(severities)
        self.summary = summary            # ONE line. What makes this fire.
        # See THE CIA AXIS above. Empty is a claim: no loss attached.
        self.cia = frozenset(cia)
        self.retired = retired
        self.retired_reason = retired_reason
        # Only for packet_sniffer threat labels, see detection_for_threat().
        self.threat_label_prefix = threat_label_prefix
        # "detection" fires because something was OBSERVED. "action_record"
        # fires because this app DID something. Both end up in the findings
        # table, both need an id, and calling the second one a detection would
        # make the register lie about what this tool can catch. See the REM
        # block below.
        self.kind = kind
        # TRUE WHEN entity_value IS NOT AN ADDRESS ANY HOST CAN HAVE, 2026-09-23.
        #
        # PKT-1017's entity is an address the SENDER'S OWN STACK wrote wrong --
        # an ICMP router advertisement whose source is the octet-reverse of the
        # address in its own body. It is a real string in a real header and it is
        # routable, so every reader that treats entity_value as "a host on the
        # internet" will place it somewhere: measured on this host, 1.0.0.10
        # resolved to South Brisbane, 11.22.37.169 to Seongnam-si, and
        # 11.22.33.44 to Santa Barbara. The finding's own text says "do not chase
        # where it geolocates to", and the threat map plotted all three on the
        # globe as foreign endpoints, one of them drawing an arc to Queensland.
        #
        # The flag is here rather than in the map because it is a fact about the
        # RULE, and both copies of the map (the dashboard route and the model's
        # tool) have to read the same one. A reader that finds this set cannot
        # honestly plot the address, and must report it separately instead --
        # reported, never dropped.
        self.entity_is_not_a_host = entity_is_not_a_host

    def as_dict(self) -> dict:
        return {
            "detection_id": self.did,
            "rev": self.rev,
            "name": self.name,
            "source": self.source,
            "entity_type": self.entity_type,
            # Worst first. sorted() gave alphabetical, so PKT-1002 rendered
            # as "high, low, medium" on the page, which reads as a list
            # nobody ordered. Anything not on the ladder sorts last rather
            # than being dropped, because a severity this does not recognise
            # is still one the register declared.
            "severities": sorted(
                self.severities,
                key=lambda x: _SEVERITY_ORDER.index(x)
                if x in _SEVERITY_ORDER else len(_SEVERITY_ORDER)),
            "cia": sorted(self.cia,
                          key=lambda x: _AXIS_ORDER.index(x)
                          if x in _AXIS_ORDER else len(_AXIS_ORDER)),
            "summary": self.summary,
            "retired": self.retired,
            "retired_reason": self.retired_reason,
            "kind": self.kind,
            # Carried through as_dict so a reader of the catalogue -- the
            # Detections page, the model's detection tool, the threat map --
            # gets the fact without importing this module and reaching into
            # the object. See __init__ for what it means.
            "entity_is_not_a_host": self.entity_is_not_a_host,
        }


def _d(*args, **kwargs) -> Detection:
    return Detection(*args, **kwargs)


# THE REGISTER
#
# Prefix says which sensor owns the number, so a reader can tell at a glance
# where a finding came from without a lookup. Numbers start at 1001 in each
# prefix and only ever go up.
#
# THE LNX BLOCK SPANS THE LOCAL LINUX SENSORS TOO, as of T2 (2026-09-17).
# It began as "linux_monitor, over SSH". Two things now raise findings about
# THE HOST THIS APP RUNS ON and they needed rules: the local event monitor
# (accounts, keys, read out of auth.log and journald) and the local process
# monitor (the three LNX-11xx entries below). They are raised under LNX
# numbers because that is the prefix the owner approved for them, and their
# `source` column names the exact sensor that raises them, so the mapping
# from a number to a sensor is still readable without a lookup. The row's own
# source column names the raiser too, and for the same rule those two are the
# same string: a finding raised by the local event monitor says
# source='event_monitor' and carries LNX-1009.

_REGISTER: list[Detection] = [

    # packet_sniffer, position host
    _d("PKT-1001", 1, "volume_sustained", "packet_sniffer", "ip",
       {"low"},
       "One source sustained a packet rate above the volume threshold for a "
       "whole window. A measurement, not a classification, backups look the "
       "same.",
       ()),

    _d("PKT-1002", 1, "beacon_interval", "packet_sniffer", "ip",
       {"low", "medium", "high"},
       "Repeated connection attempts to one destination at a near-constant "
       "interval, which is the timing signature of automated check-in.",
       ("confidentiality",)),

    _d("PKT-1003", 1, "capture_overflow", "packet_sniffer", "ip",
       {"medium"},
       "The capture buffer hit its ceiling and packets were counted but not "
       "stored, so this window is incomplete and cannot be called quiet.",
       ("availability",)),

    # The threat-label family. These come out of the sniffer's own classifier
    # as colon-delimited strings with the subject baked in
    # ("dangerous_port_inbound:445:SMB"), so the label is different on every
    # occurrence and could never have been an identity. The PREFIX is the
    # detection, the rest is the parameter. See detection_for_threat().
    _d("PKT-1010", 1, "metasploit_signature", "packet_sniffer", "ip",
       {"critical"},
       "A known Metasploit payload byte sequence appeared in the live packet "
       "bytes, on any port and in either direction.",
       ("confidentiality", "integrity"),
       threat_label_prefix="metasploit_signature"),

    _d("PKT-1011", 1, "sqli_payload", "packet_sniffer", "ip",
       {"medium"},
       "A SQL injection string appeared in cleartext on a plaintext service "
       "port, inbound or internal only.",
       ("confidentiality", "integrity"),
       threat_label_prefix="sqli_payload"),

    _d("PKT-1012", 1, "xss_payload", "packet_sniffer", "ip",
       {"medium"},
       "A cross-site scripting string appeared in cleartext on a plaintext "
       "service port, inbound or internal only.",
       ("confidentiality",),
       threat_label_prefix="xss_payload"),

    _d("PKT-1013", 1, "dangerous_port_inbound", "packet_sniffer", "ip",
       {"low"},
       "Something outside reached for a port on this host that should not be "
       "exposed.",
       ("confidentiality",),
       threat_label_prefix="dangerous_port_inbound"),

    _d("PKT-1014", 1, "dangerous_port_outbound", "packet_sniffer", "ip",
       {"high"},
       "This host reached OUT to a dangerous port on a public address, which "
       "is the direction that matters for command and control.",
       ("confidentiality",),
       threat_label_prefix="dangerous_port_outbound"),

    _d("PKT-1015", 1, "suspicious_outbound", "packet_sniffer", "ip",
       {"high"},
       "This host talked outbound on a port that is neither on the safe list "
       "nor obviously dangerous, so it is worth a look rather than an alarm.",
       ("confidentiality",),
       threat_label_prefix="suspicious_outbound"),

    _d("PKT-1016", 1, "icmp_routing_from_offlink", "packet_sniffer", "ip",
       {"low"},
       "An ICMP message that changes routing arrived from an address that is "
       "not on this network, which is never ordinary.",
       ("confidentiality", "integrity"),
       threat_label_prefix="icmp_routing_from_offlink"),

    _d("PKT-1017", 1, "icmp_routing_source_mismatch", "packet_sniffer", "ip",
       {"low"},
       "A routing ICMP whose source contradicts the address in its own body, "
       "usually a byte-order bug in the sender rather than a hijack.",
       ("confidentiality", "integrity"),
       threat_label_prefix="icmp_routing_source_mismatch",
       # THE ENTITY IS NOT A HOST. See Detection.__init__. Every surface that
       # treats an ip entity as "somewhere on the internet" has to read this
       # flag: the address is the sender's own mangled header, so geolocating
       # it answers a question nobody asked about a machine that never existed.
       entity_is_not_a_host=True),

    # THE HONEST FALLBACK, and the reason detection_for_threat may return None
    # without killing a capture thread. If the sniffer's classifier grows a new
    # label before anybody registers it, the finding still gets raised, under
    # this id, saying plainly that the rule it came from is not in the register
    # yet. The alternative designs are both worse: refusing to raise means an
    # unregistered label silences a real detection, and inventing an id at the
    # call site means the register stops being the list of what exists.
    #
    # A row carrying PKT-1099 is a BUG REPORT ABOUT THIS FILE. Its presence
    # means somebody added a classifier branch and did not come back here.
    # scripts/detection_report.py lists the unmapped prefixes by name.
    #
    # EMPTY AXIS, AND HERE IT MEANS NOT-YET-CLASSIFIED RATHER THAN NO LOSS.
    # The one entry where those differ, because the subject of this rule IS
    # the fact that nobody has classified it. Writing an axis here would be
    # inventing one on behalf of a rule that has not been written.
    _d("PKT-1099", 1, "unmapped_threat_label", "packet_sniffer", "ip",
       {"low", "medium", "high", "critical"},
       "The sniffer classified this packet with a threat label that has no "
       "detection registered, so the finding is real and its rule is not "
       "written down yet.",
       ()),

    # retired, kept so the numbers cannot be reused.
    #
    # THE TWO WINDOWS RULES LEFT THIS REGISTER 2026-09-25, and they are retired
    # rather than deleted because retiring is what this list already does with
    # an id that must never be handed out again:
    #
    #   EVT-1001  windows_brute_force. Its summary named Windows event 4625,
    #             which nothing on this platform can read. The Linux brute
    #             force is a DIFFERENT rule reading a different log and has
    #             been since the EM round: LNX-1002 ssh_brute_force, driven by
    #             adapters.LinuxEventMonitor. Zero rows ever carried EVT-1001
    #             in the owner's store, measured.
    #   PRC-1002  defender_detection. Microsoft Defender's own history, read
    #             by Get-MpThreatDetection through the capability shim. Both
    #             halves are gone. Zero rows ever, measured.
    #
    # WHAT RETIRING BUYS, kept from the PRT-1001 note below: the id stays in
    # this list so anything that once carried it still has something to resolve
    # to, and so nobody hands the number to a new detection by accident.
    _d("EVT-1001", 1, "windows_brute_force", "event_monitor", "ip",
       {"critical"},
       "Enough failed Windows logons (event 4625) from one source inside the "
       "window to clear the brute force threshold.",
       ("confidentiality",),
       retired=True,
       retired_reason=(
           "A Windows event channel rule. This platform reads journald and the "
           "log files, and the equivalent detection here is LNX-1002 "
           "ssh_brute_force, raised by adapters.LinuxEventMonitor off the same "
           "sensor. Measured before retiring: zero rows in the owner's store "
           "ever carried EVT-1001. Kept so the id is never reused."
       )),

    _d("PRC-1002", 1, "defender_detection", "process_monitor", "process",
       {"low", "medium", "high", "critical"},
       "Microsoft Defender reported a detection, read out of its own history "
       "rather than inferred here.",
       ("confidentiality", "integrity"),
       retired=True,
       retired_reason=(
           "Microsoft Defender does not exist on this platform, and the "
           "PowerShell reader that produced these rows is gone with it. "
           "Measured before retiring: zero rows in the owner's store ever "
           "carried PRC-1002. Kept so the id is never reused."
       )),

    # process_monitor. The rule that is left after PRC-1002 retired.
    _d("PRC-1001", 1, "suspicious_process_name", "process_monitor", "process",
       {"low", "medium", "high"},
       "A running process matched the suspicious-name list. Weak evidence by "
       "design: a filename is the easiest thing in the world to change.",
       ("confidentiality", "integrity")),

    # linux_monitor over SSH, and the LOCAL Linux sensors, see the note
    # above the register for why the block spans both
    _d("LNX-1001", 1, "fail2ban_ban", "linux_monitor", "ip",
       {"medium"},
       "fail2ban on the remote host banned an address. The HOST'S own "
       "decision read from its log, not our inference from a rate.",
       ("confidentiality",)),

    _d("LNX-1002", 1, "ssh_brute_force", "linux_monitor", "ip",
       {"medium", "high"},
       "Failed SSH logins from one source cleared the configured threshold "
       "inside the window, read from real auth logs.",
       ("confidentiality",)),

    _d("LNX-1003", 1, "ssh_failed_then_success", "linux_monitor", "ip",
       {"high"},
       "A login succeeded straight after a run of failures from the same "
       "source, which is the shape of a brute force that got in.",
       ("confidentiality", "integrity")),

    _d("LNX-1004", 1, "log_intake_blind", "linux_monitor", "ip",
       {"high"},
       "The host answered but every SSH log source came back empty, so this "
       "monitor is blind rather than reassuring. A statement about itself.",
       ("availability",)),

    _d("LNX-1005", 1, "suspicious_linux_process", "linux_monitor", "process",
       {"medium", "high"},
       "A process on the remote host matched the suspicious-name list, at the "
       "higher severity when its arguments matched too.",
       ("confidentiality", "integrity")),

    _d("LNX-1006", 1, "crontab_changed", "linux_monitor", "ip",
       {"high"},
       "Scheduled task configuration on the remote host no longer matches the "
       "stored baseline.",
       ("integrity",)),

    _d("LNX-1007", 1, "sensitive_file_changed", "linux_monitor", "ip",
       {"critical"},
       "A watched file on the remote host no longer matches its stored "
       "baseline hash.",
       ("integrity",)),

    _d("LNX-1008", 1, "new_suid_binary", "linux_monitor", "ip",
       {"high"},
       "A SUID binary exists on the remote host that was not in the recorded "
       "baseline.",
       ("integrity",)),

    # T2, 2026-09-17, Q2. The account and key events the local event monitor
    # reads. They were counted and dropped until now for want of a rule; the
    # owner's answer was that these three become FINDINGS and the other eight
    # categories stay events only. Reason, recorded in T1_FIREWALL_TRUTH.md:
    # these are §53.3 violated-declaration cases with threshold 1, and the
    # eight that stay events include 2,782 successful logins and 232 sudo rows
    # in one evening, which is how an operator is trained to ignore the owner's own
    # tool.
    #
    # THE SEVERITIES ARE THE MODULE'S OWN, read out of
    # tools/event_monitor_linux.py WATCHED_PATTERNS rather than decided here.
    # All three are 'high' there. T1_FIREWALL_TRUTH.md records this set as
    # "high/high/info" and that is WRONG for ssh_key_added, which the source
    # declares high at line 123. Corrected from the source, per the standing
    # rule that documentation is written from the code.
    _d("LNX-1009", 1, "account_created", "event_monitor", "user",
       {"high"},
       "An account was created on THIS host, read from auth.log or journald. "
       "A new identity is a new way in, and one occurrence is enough.",
       ("confidentiality", "integrity")),

    _d("LNX-1010", 1, "account_deleted", "event_monitor", "user",
       {"high"},
       "An account was deleted on THIS host. Ordinary housekeeping and a "
       "cover-up look identical here, which is why the finding exists rather "
       "than a filter.",
       ("confidentiality", "integrity")),

    _d("LNX-1011", 1, "ssh_key_added", "event_monitor", "user",
       {"high"},
       "An SSH authorized key was added on THIS host. It grants standing "
       "access that survives a password change.",
       ("confidentiality", "integrity")),

    # LNX-1012, ADDED 2026-09-23 WITH THE EVENT MONITOR FIX ROUND.
    #
    # WHY IT NEEDED ITS OWN NUMBER RATHER THAN REUSING LNX-1002. LNX-1002 is
    # ssh_brute_force and its registered source is "linux_monitor": the REMOTE
    # sensor that reads another box over SSH. The LOCAL event monitor was
    # raising that same id with source="event_monitor", which breaks the
    # invariant written at the top of this register: "for the same rule those
    # two are the same string". Nothing refused the write, because save_finding
    # checks that the id exists and that the severity fits and nothing else, so
    # the mismatch was invisible. It also made the two disagree about severity:
    # LNX-1002 declares {medium, high} and the retired Windows rule for the
    # same behaviour declared {critical}.
    #
    # THE SEVERITIES HERE ARE THE MODULE'S OWN, read out of
    # tools/event_monitor_linux.py's _check_brute_force, which builds its dict
    # with severity "high". LNX-1002 keeps {medium, high} unchanged and is
    # still the remote rule; this one is the local rule and only the local
    # event monitor raises it.
    #
    # THE ENTITY IS AN ADDRESS OR AN ACCOUNT, and that is the measured half of
    # the same entry. All 662 failed logins in this host's store came from
    # pam_unix and NOT ONE carried a source address, so a rule keyed on an
    # address alone could never fire here; the module now keys on `src_ip or
    # username`, which is what the Windows twin already did.
    _d("LNX-1012", 1, "local_brute_force", "event_monitor", "user",
       {"high"},
       "Enough failed logins for one account, or from one address, on THIS "
       "host inside the window, read from auth.log or journald. A console or "
       "screensaver prompt being hammered is the same fact as an SSH password "
       "being guessed, and neither needs an address to be worth knowing.",
       ("confidentiality",)),

    # LNX-1013 TO LNX-1016, ADDED 2026-09-25. THE FOUR CATEGORIES THAT
    # WERE READ AND RAISED NOTHING.
    #
    # WHY THEY ARE BURST RULES AND NOT PER-EVENT RULES. T1's Q2 decision
    # (2026-09-17) kept firewall_block, service_failed, service_started and
    # successful_login as EVENTS ONLY, on a measurement: 2,782 successful
    # logins and 232 sudo rows in one evening, and raising a finding per login
    # is how an operator is trained to ignore the owner's own tool. That decision
    # STANDS and is not reversed here. What the owner's report of 2026-09-24
    # named -- "a firewall deny, a service crash, a service start, or a login
    # happening right now would show up in query_events but would not raise an
    # alert" -- is the half that was missing: the SHAPE.
    #
    # Each of the four fires on a burst from ONE subject inside a 5-minute
    # window, and each threshold is set from this host's own measured ordinary
    # traffic rather than from taste (see BURST_* in
    # tools/event_monitor_linux.py, where the histograms are written down).
    # The ordinary case cannot reach them: 447 of the 690 measured
    # service-start windows hold one line, and the ordinary firewall case is
    # multicast housekeeping that the rule refuses to count at all.
    #
    # THE SEVERITIES ARE THE MODULE'S OWN, so the two sides cannot drift.
    _d("LNX-1013", 1, "service_restart_loop", "event_monitor", "process",
       {"medium"},
       "One systemd unit failed repeatedly inside a short window. A single "
       "failure is ordinary; a loop means the unit cannot stay up, and systemd "
       "will keep restarting it. Read from journald or syslog.",
       ("availability", "integrity")),

    _d("LNX-1014", 1, "service_flapping", "event_monitor", "process",
       {"low"},
       "One systemd unit started repeatedly inside a short window. It is "
       "either failing and being restarted, or something is cycling it. Read "
       "from journald or syslog.",
       ("availability",)),

    _d("LNX-1015", 1, "firewall_scan_from_host", "event_monitor", "ip",
       {"medium"},
       "One address had several packets blocked that were addressed to THIS "
       "host, inside a short window. One block is the firewall doing its job; "
       "a run of them from one address is that address probing. The multicast "
       "housekeeping Linux drops by design is excluded from this rule, which "
       "is why it can fire at all on a desktop.",
       ("confidentiality",)),

    _d("LNX-1016", 1, "login_burst_from_host", "event_monitor", "ip",
       {"low"},
       "Several successful logins from one address inside a short window. Not "
       "an accusation: an automated login loop, a misconfigured client and a "
       "stolen key all look like this, and the shape is worth knowing. Read "
       "from auth.log or journald.",
       ("confidentiality",)),

    # T2, 2026-09-17, Q1. The three process finding types that
    # tools/process_monitor_linux.py has always raised and the adapter has
    # always counted and dropped, because they had no id and folding them
    # under PRC-1001 would have made one rule claim four different things.
    # The owner approved registering them, as LNX-11xx.
    #
    # SEVERITIES ARE THE MODULE'S OWN (tools/process_monitor_linux.py, the
    # _analyze_process checks): location low, masquerading high, lolbin
    # medium. One severity each, because the module emits exactly one each,
    # and _fit_severity in adapters.py maps anything unexpected onto the
    # declared value and logs the substitution.
    _d("LNX-1017", 1, "privileged_group_added", "event_monitor", "user",
       {"high"},
       "An account was added to a group that can become root or read what "
       "root reads (sudo, wheel, adm, docker, lxd, libvirt, disk, shadow). "
       "Routine when an administrator did it; if nobody did, it is how an "
       "intruder keeps access.", ("integrity", "confidentiality")),


    _d("LNX-1018", 1, "kernel_tainted", "event_monitor", "file",
       {"medium"},
       "A kernel module tainted the kernel: out-of-tree, unsigned or from "
       "staging. Such a module runs with full kernel rights, which is how "
       "rootkits load; locally built driver modules (DKMS) do it "
       "legitimately and can be dismissed by name.", ("integrity",)),


    _d("LNX-1101", 1, "suspicious_process_location", "process_monitor",
       "process", {"low"},
       "A process is running out of a directory programs do not normally run "
       "from: /tmp, /dev/shm or a user's cache. Common for installers, which "
       "is why it is low, and where a dropped implant usually lives.",
       ("integrity",)),

    _d("LNX-1102", 1, "masquerading_system_binary", "process_monitor",
       "process", {"high"},
       "A process carries the name of a system binary but is not running the "
       "system's copy of it, so the name on the process list is a claim "
       "rather than a fact.",
       ("integrity",)),

    _d("LNX-1103", 1, "lolbin_abuse", "process_monitor", "process",
       {"medium"},
       "A legitimate system tool is being used as the payload: a shell with a "
       "reverse connection, a downloader piped into an interpreter.",
       ("confidentiality", "integrity")),

    # local_integrity, L3, 2026-09-22. THE INTEGRITY OF THIS HOST
    #
    # WHY THESE ARE A SEPARATE FAMILY FROM LNX-1006 TO LNX-1008. Those three
    # are the REMOTE host checks in tools/linux_monitor.py: crontab_changed,
    # sensitive_file_changed, new_suid_binary, all read over SSH from another
    # machine. Reusing them here would put a number on the dashboard that means
    # "some host over there" for a finding about the machine the app is running
    # on, and the two answer different questions. LNX-2007 is deliberately
    # CLOSE IN MEANING to LNX-1008 and deliberately not the same number: the
    # local one keeps the file's hash, so it can tell a new setuid binary from
    # the system's own binary being swapped underneath its name, and that is a
    # different claim from "a file appeared that was not in the baseline".
    #
    # ONE ID PER CLAIM, not one id per file watched. A key being added to
    # authorized_keys (LNX-2002) and a key file becoming world-writable
    # (LNX-2003) are different facts about the machine, they have different
    # remedies, and folding them into one "ssh stuff changed" entry would make
    # the Detections page describe one rule that catches two things.
    #
    # EVERY SEVERITY DECLARED HERE IS ONE THIS CODE ACTUALLY RAISES, and the
    # spread inside an entry is a statement rather than hedging. LNX-2004
    # carries critical for the file APPEARING and high for it changing, because
    # a file that makes every program on the machine load attacker code is the
    # loudest fact this module can report, and one that was already there and
    # moved is a change to something already flagged. Read the description the
    # finding carries: it names which of the two happened.
    #
    # THE ELEVATION LIMIT IS PART OF THE CLAIM, not a footnote elsewhere. On an
    # unelevated run /etc/sudoers and /etc/sudoers.d cannot be read, so those
    # files are watched for name, mode, owner, size and mtime only, and a
    # content edit that leaves all of those identical is NOT DETECTED. The
    # status block says which files that applies to, and the finding's own
    # raw_data carries `content_read`.
    _d("LNX-2001", 1, "local_sensitive_file_changed", "local_integrity",
       "file", {"medium", "high"},
       "A file on THIS host no longer matches its recorded baseline, or an "
       "entry appeared in or vanished from a watched directory such as "
       "/etc/sudoers.d, /etc/pam.d or a systemd unit directory.",
       ("integrity",)),

    _d("LNX-2002", 1, "local_ssh_key_changed", "local_integrity",
       "file", {"high"},
       "A key was added to a home's authorized_keys on THIS host, or one was "
       "removed. A key there grants standing access that survives a password "
       "change, and it works from anywhere.",
       ("confidentiality", "integrity")),

    _d("LNX-2003", 1, "local_ssh_key_permissions", "local_integrity",
       "file", {"medium", "high"},
       "A file that decides who may log in, or a key file itself, changed its "
       "mode or owner on THIS host. World-writable raises this on the first "
       "pass rather than being seeded, because any account could then add a "
       "key.",
       ("confidentiality", "integrity")),

    _d("LNX-2004", 1, "local_ld_preload", "local_integrity",
       "file", {"medium", "high", "critical"},
       "The file that makes every dynamically linked program on this machine "
       "load other code FIRST, before anything else. Its expected state is "
       "absent, and critical is the file APPEARING.",
       ("integrity", "confidentiality")),

    # TIER C, 2026-09-22, AND THE RESERVATION IS NOW SPENT. 2005 and 2006 were
    # held back by name while tier C was unbuilt, on the rule that registering
    # a rule nothing can raise puts a number on the Detections page that
    # catches nothing. They are registered here because the code that raises
    # them now exists and is exercised by tests/test_local_integrity.py.
    #
    # THE TWO IDS ARE TWO DIFFERENT CLAIMS ABOUT THE SAME OUTPUT, which is why
    # dpkg's 55 measured lines are not one rule:
    #
    #   LNX-2005  "dpkg could not read something, so NOTHING can be said about
    #              it." That covers a file dpkg could not open (on this host,
    #              every /boot kernel image, because they are mode 600 root), a
    #              file that is genuinely gone, a package whose own control
    #              file dpkg refuses to load at all, output lines this parser
    #              does not recognise, and a run that aborted before it
    #              finished. All of those are statements about COVERAGE.
    #
    #   LNX-2006  "dpkg read the file, compared it against the digest it
    #              recorded at unpack time, and they disagree." That is an
    #              integrity claim about a specific file that was actually
    #              examined, and it is the only rule here that says something
    #              is WRONG rather than UNKNOWN.
    #
    # Folding them together would put "I could not look" and "this file is not
    # what it was" on one row, and the operator's action differs completely:
    # the first is fixed by privilege, or by the control-file separator that
    # makes a package unloadable (CORRECTED 2026-09-26: this sentence used to
    # read "privilege or a reinstall", and a reinstall cannot repair the
    # separator class -- the installed control file is byte-identical to the
    # copy inside the vendor's own package, measured on this host, so
    # reinstalling writes the same bytes back); the second by reading the file.
    #
    # SEVERITY IS DECLARED, AND THE MEDIUM IS THE HONEST ONE. On this host a
    # stock install produces 22 content differences in icons, .desktop files
    # and two conffiles that ship modified -- so a `high` for the class would
    # be high on a machine nobody has touched. The code raises high ONLY for a
    # non-conffile content difference, which is the shape of a binary replaced
    # under its name, and medium for a conffile, which the package manager
    # expects a person to edit.
    _d("LNX-2005", 1, "package_file_unverifiable", "local_integrity",
       "file", {"medium"},
       "On THIS host: a file dpkg could not read or compare, a file a package "
       "shipped that is no longer on disk, a package whose md5sums control "
       "file dpkg refuses to load at all, dpkg output this sensor did not "
       "understand, or a verification run that aborted. Every one of these "
       "means the file was NOT checked, which is not the same as a file that "
       "is intact.",
       ("availability", "integrity")),

    _d("LNX-2006", 1, "package_file_content_changed", "local_integrity",
       "file", {"medium", "high"},
       "dpkg compared a file a package shipped against the digest it recorded "
       "at unpack time and they disagree, on THIS host. High when the file is "
       "not a conffile, the shape of a binary or library replaced in place. "
       "Medium for a conffile, which is the class of file an administrator is "
       "expected to edit.",
       ("integrity",)),
    #
    # THE TWO ABOVE ARE THE LAST LOCAL INTEGRITY IDS AND THEY COMPLETE THE
    # LNX-20xx BLOCK: 2001 through 2012 are now all registered and all
    # reachable. Nothing in this range is reserved any more.
    _d("LNX-2007", 1, "local_suid_changed", "local_integrity",
       "file", {"medium", "high"},
       "On THIS host: a setuid file that was not in the sweep's baseline "
       "(high), the file at a known setuid path whose CONTENTS changed "
       "(high, which is the shape of a binary being swapped underneath its "
       "name), or a setuid bit that was cleared (medium).",
       ("integrity",)),

    _d("LNX-2008", 1, "local_sgid_changed", "local_integrity",
       "file", {"low", "medium", "high"},
       "On THIS host: a setgid file that was not in the baseline (medium), a "
       "known setgid file whose contents changed (high), or a setgid bit that "
       "was cleared (low). Setgid runs with the group's authority, which is "
       "quieter than setuid and still a capability.",
       ("integrity",)),

    _d("LNX-2009", 1, "local_file_capability_changed", "local_integrity",
       "file", {"medium", "high"},
       "A file on THIS host carries a different set of capabilities than the "
       "one recorded: one appeared (high), one changed (high) or one was "
       "removed (medium). Capabilities are quieter than setuid and are how "
       "modern packages hand out privilege.",
       ("integrity",)),

    _d("LNX-2010", 1, "integrity_sweep_incomplete", "local_integrity",
       "file", {"medium"},
       "The setuid, setgid and capability sweep could not read part of this "
       "filesystem, or could not hash part of what it found. A statement "
       "about this sensor rather than about the machine: an empty diff over a "
       "tree it could not walk is not an all-clear.",
       ("availability",)),

    _d("LNX-2011", 1, "mac_posture_changed", "local_integrity",
       "file", {"high"},
       "A mandatory access control system on THIS host stopped enforcing, or "
       "stopped being enabled in the kernel. A permissive MAC logs and does "
       "not stop, which is the difference between a control and a note in "
       "the log.",
       ("integrity",)),

    # THE ANSWER TO THE UNELEVATED HOLE, and it is a real one rather than a
    # hedge. MEASURED ON THIS HOST 2026-09-22, on a file shaped exactly like
    # /etc/sudoers: write the same NUMBER of bytes with different content, then
    # call utime() with the recorded mtime, and size, mtime, mode and owner all
    # match the baseline EXACTLY. Every field the metadata-only watch had would
    # agree, so a line added to sudoers by an unprivileged process was
    # invisible. The kernel's inode change time moved and cannot be put back
    # from userspace.
    #
    # IT IS A SEPARATE ID FROM LNX-2001 BECAUSE IT IS A SEPARATE CLAIM, and the
    # difference is the whole point of the rule. LNX-2001 says "this file is
    # not what it was". This says "this file was changed AND SOMEBODY PUT ITS
    # TIMESTAMPS BACK", which is a statement about intent that no other rule
    # here can make. The owner's rule is one finding per claim; folding these
    # would put a sentence about deliberate timestamp preservation on a row
    # that mostly means an apt upgrade.
    #
    # HIGH, NOT CRITICAL, and the reason is the innocent population. A restored
    # backup, a post-install script that touches timestamps, and rsync with
    # -t all trip this legitimately. High is "worth looking at", and the
    # description names all three innocent causes before it names the guilty
    # one, because a reader who cannot tell them apart cannot weigh the row.
    _d("LNX-2012", 1, "local_timestamps_rolled_back", "local_integrity",
       "file", {"high"},
       "A file on THIS host was modified and its mtime was then put back to "
       "the recorded value, so only the inode change time gives it away. The "
       "shape of a change made to look old.",
       ("integrity",)),

    # THE FIRST IDS IN THIS REGISTER WHOSE ENTITY IS A FILE, and that is why
    # the entries above it are worth reading together. 'file' joined the
    # vocabulary on 2026-09-22 with L3, and the vocabulary is enforced in
    # exactly three places, all of which had to move in the same sitting or
    # these eight rules would have been rules that could not raise:
    #
    #   memory_engine.VALID_ENTITY_TYPES   gates dismiss_entity and the two
    #                                      behavioral write paths
    #   incident.write_incident            REFUSES an entity_type it does not
    #                                      know, and its refusal is caught and
    #                                      counted by the watcher's own
    #                                      try/except, so an unextended
    #                                      vocabulary means every finding these
    #                                      rules raise reaches the findings
    #                                      table and opens NO incident: the
    #                                      detector runs, the hit is
    #                                      computed, and nothing arrives.
    #                                      (The comparison ledger that named
    #                                      this shape was deleted 2026-09-23
    #                                      on the owner's instruction; the
    #                                      shape outlived the record of it.)
    #
    # The value is the PATH, because that is what a person acts on and what a
    # dismissal should cover. Two findings about two different files are two
    # entities, which is the entire point of watching files individually.

    # network_scanner
    _d("NET-1001", 1, "new_device", "network_scanner", "ip",
       {"medium"},
       "An address answered that has no row in the device inventory yet.",
       ()),

    _d("NET-1002", 1, "always_on_absent", "network_scanner", "ip",
       {"medium"},
       "A device the USER declared should always answer has missed enough "
       "consecutive presence sweeps to clear the register's threshold.",
       ("availability",)),

    # router_monitor, position gateway
    _d("RTR-1001", 1, "new_router_client", "router_monitor", "ip",
       {"medium"},
       "The router's own client list gained an entry this app had not seen "
       "from its host vantage.",
       ()),

    _d("RTR-1002", 1, "router_setting_changed", "router_monitor", "ip",
       {"medium"},
       "A recorded gateway setting now reads differently. A measurement "
       "against an earlier value, not an opinion about what it means.",
       ("integrity",)),

    # probe, the three-week enrollment pass
    _d("PRB-1001", 1, "enrolled_device_drift", "probe", "ip",
       {"medium"},
       "An enrolled device's fingerprint no longer matches what was recorded "
       "when the user vouched for it.",
       ("integrity",)),

    _d("PRB-1002", 1, "permanent_device_retired", "probe", "ip",
       {"medium"},
       "A device marked permanently present missed enough sweeps that it was "
       "retired from the inventory automatically.",
       ("availability",)),

    # remediation, and these are NOT detections
    #
    # Found by the call-site test on 2026-09-15, which is the only reason they
    # are here: tools/remediation_linux.py writes seven rows into the findings
    # table
    # and none of them is a detection. They are RECORDS OF WHAT THIS APP DID,
    # all at severity info, written so that a killed process or a blocked port
    # appears in the same timeline as the finding that prompted it.
    #
    # They still need ids, because save_finding now requires one, and giving
    # them ids is better than the alternative of a second table. But calling
    # them detections would make the Detections page overstate what this tool
    # can catch by seven rules, so kind says what they are and the page keeps
    # them apart.
    #
    # NOT SUPPRESSIBLE IN PRACTICE, and nothing stops it in code. Suppressing
    # one would mean the app quietly stops recording that it killed things,
    # which is a different and worse idea than muting a noisy sensor. Left as
    # a note rather than a lock: the page does not offer the button.
    #
    # EMPTY AXIS, AND FOR ROWS THAT ARE RECORDS RATHER THAN DETECTIONS. The
    # axis answers "what is lost if this is real". These rows are not claims
    # about the world at all, they are receipts for something this app did at
    # somebody's instruction, so there is no loss to name. The incident
    # watcher skips kind='action_record' outright and does not consult this
    # field, deliberately: an incident already exists for the finding that
    # prompted the action.
    _d("REM-1001", 1, "process_killed", "remediation", "process", {"info"},
       "This app killed a process, at a human's instruction.",
       (),
       kind="action_record"),
    _d("REM-1002", 1, "port_blocked", "remediation", "port", {"info"},
       "This app added a firewall rule blocking a port.",
       (),
       kind="action_record"),
    _d("REM-1003", 1, "port_unblocked", "remediation", "port", {"info"},
       "This app removed a firewall rule it had added for a port.",
       (),
       kind="action_record"),
    _d("REM-1004", 1, "device_blocked", "remediation", "ip", {"info"},
       "This app blocked an address at this host only, not at the gateway.",
       (),
       kind="action_record"),
    _d("REM-1005", 1, "device_unblocked", "remediation", "ip", {"info"},
       "This app lifted a host-level block on an address.",
       (),
       kind="action_record"),
    _d("REM-1006", 1, "file_quarantined", "remediation", "ip", {"info"},
       "This app moved a file into quarantine.",
       (),
       kind="action_record"),
    _d("REM-1007", 1, "file_restored", "remediation", "ip", {"info"},
       "This app restored a file out of quarantine.",
       (),
       kind="action_record"),

    _d("REM-1008", 1, "service_stopped", "remediation", "process", {"info"},
       "This app stopped a systemd unit, and verified afterwards that it was "
       "inactive rather than trusting the exit code. An action record, not a "
       "detection: it says what was DONE, and the kill_process path refuses "
       "the supervised case it exists for.",
       (),
       kind="action_record"),

    # The router's own enforcement, T9, 2026-09-29. Separate ids from
    # REM-1004/1005 because those say "at this host only", and a block at the
    # router is a different act with a different reach.
    _d("REM-1009", 2, "gateway_device_blocked", "remediation", "ip", {"info"},
       "This app blocked an address at the router, through the gateway agent, "
       "so the device cannot reach the internet or other subnets. Devices on "
       "the same switch or radio can still reach it. Kept across a router "
       "reboot when the agent reports persist, otherwise lasts until then.",
       (),
       kind="action_record"),
    _d("REM-1010", 1, "gateway_device_unblocked", "remediation", "ip", {"info"},
       "This app lifted a block it made at the router.",
       (),
       kind="action_record"),
    # By hardware address, so a new IP does not get the device back online.
    # The entity is the device's address at the time, the MAC is in the title.
    _d("REM-1013", 1, "gateway_device_mac_blocked", "remediation", "ip", {"info"},
       "This app blocked a device at the router by its hardware address. It "
       "keeps DNS and DHCP to the router and loses everything else through "
       "it, whatever IP address it takes. Devices on the same switch or radio "
       "can still reach it. A device that changes its hardware address is a "
       "new device to this block. Kept across a router reboot.",
       (),
       kind="action_record"),
    _d("REM-1014", 1, "gateway_device_mac_unblocked", "remediation", "ip", {"info"},
       "This app lifted a hardware address block it made at the router.",
       (),
       kind="action_record"),
    # One app on one device, by hardware address. The app is in the title.
    _d("REM-1015", 1, "gateway_app_blocked", "remediation", "ip", {"info"},
       "This app blocked one app on one device at the router. The device "
       "loses the addresses the router's resolver gives for that app's "
       "domains, and DNS over TLS, and keeps everything else. An app that "
       "shares servers with another (Meta's apps, Google's) can take the "
       "other with it. Kept across a router reboot.",
       (),
       kind="action_record"),
    _d("REM-1016", 1, "gateway_app_unblocked", "remediation", "ip", {"info"},
       "This app lifted an app block it made at the router.",
       (),
       kind="action_record"),
    # The entity is the ROUTER whose resolver changed, not the domain:
    # 'domain' is not in the entity vocabulary, and adding one moves three
    # gates at once (see the note above the LNX-20xx entries). The domain is
    # in the title and the raw data.
    _d("REM-1011", 1, "domain_sinkholed", "remediation", "ip", {"info"},
       "This app made the router's resolver answer a domain with nothing, for "
       "every device that uses that resolver. A device with its own DNS "
       "server, or DNS over HTTPS, is not covered. Lasts until the router "
       "reboots.",
       (),
       kind="action_record"),
    _d("REM-1012", 1, "domain_unsinkholed", "remediation", "ip", {"info"},
       "This app lifted a sinkhole it made at the router's resolver.",
       (),
       kind="action_record"),

    # Containment through the root helper. Each removal keeps an undo record,
    # and its undo is a separate record because it lowers protection again.
    _d("REM-1017", 1, "ssh_key_removed", "remediation", "user", {"info"},
       "This app took one key, named by its fingerprint, out of an account's "
       "authorized_keys. Sessions already open with it are not closed.",
       (), kind="action_record"),
    _d("REM-1018", 1, "ssh_key_restored", "remediation", "user", {"info"},
       "This app put back an SSH key it had removed.",
       (), kind="action_record"),
    _d("REM-1019", 1, "account_locked", "remediation", "user", {"info"},
       "This app locked an account's password and expired it, so new logins "
       "by password or key are refused. Running sessions are not ended.",
       (), kind="action_record"),
    _d("REM-1020", 1, "account_unlocked", "remediation", "user", {"info"},
       "This app put an account it had locked back as it was.",
       (), kind="action_record"),
    _d("REM-1021", 1, "privileged_group_removed", "remediation", "user",
       {"info"},
       "This app took an account out of a group that can become root or read "
       "what root reads. Logged-in sessions keep the group until they end.",
       (), kind="action_record"),
    _d("REM-1022", 1, "privileged_group_restored", "remediation", "user",
       {"info"},
       "This app put back a group membership it had removed.",
       (), kind="action_record"),
    _d("REM-1023", 1, "cron_line_disabled", "remediation", "file", {"info"},
       "This app commented out one cron line, keeping the text. A job already "
       "running from it is not stopped.",
       (), kind="action_record"),
    _d("REM-1024", 1, "cron_line_restored", "remediation", "file", {"info"},
       "This app made a cron line it had disabled active again.",
       (), kind="action_record"),
    _d("REM-1025", 1, "service_disabled", "remediation", "process", {"info"},
       "This app stopped, disabled and masked a systemd unit, read back as "
       "masked, so it does not start again at boot or on demand.",
       (), kind="action_record"),
    _d("REM-1026", 1, "service_enabled", "remediation", "process", {"info"},
       "This app unmasked and enabled a unit it had disabled. It was not "
       "started.",
       (), kind="action_record"),

    # ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
    # PORTED FROM THE WINDOWS REGISTER 2026-09-21. These nine are raised by
    # tools/lan_watch.py, tools/dns_inspector.py and tools/feed_matcher.py,
    # which arrived with the tools port. THEY WERE NOT IN THIS REGISTER, and
    # that is not a cosmetic gap: memory_engine.save_finding calls det.get()
    # and raises UnknownDetection for an id nobody wrote down, so EVERY
    # finding those three modules produced was refused, and the refusal was
    # swallowed by the callback's own try/except. The detectors ran, the
    # hits were computed, and nothing reached the findings table.
    #
    # MEASURED BEFORE THE FIX: a real ARP impostor claiming the default
    # gateway produced a correct LAN-1002 hit from lan_watch and zero rows
    # in findings, with one warning in the log naming LAN-1002 as
    # unregistered. The comparison pass that found this was closed by
    # registering the ids, and NOT by porting the detectors alone.
    #
    # The entries below are the Windows text, unchanged. Nothing was
    # reworded: these descriptions are what the model reads, and the two
    # trees describing one rule differently is how a reconciliation turns
    # into a fork.


    # dns_inspector, TODO 113.3
    #
    # DNS raises no findings on novelty alone (see the big comment in
    # tools/dns_monitor.py). These two fire on COMBINED signals: entropy is
    # not enough on its own, cadence is not enough on its own. Both are.
    _d("DNS-1001", 1, "dga_suspected", "dns_inspector", "ip",
       {"medium", "high"},
       "A device queried a domain whose second-level label has the statistical "
       "profile of algorithmically generated names: high Shannon entropy and "
       "long enough that it is unlikely to be a human-chosen word. Combined "
       "signal only: novelty alone is not enough. Malware uses DGA to rotate "
       "C2 hostnames faster than block lists can follow.\n\n"
       "TWO SEVERITIES, 2026-09-20. ONE odd-looking name is medium, because "
       "the commonest cause is a CDN with a hash in it. A device reaching for "
       "MANY of them in one window is high: rotation is the pattern DGA "
       "exists to produce, and no CDN makes a client ask for a dozen "
       "different random-looking second-level domains. The high row is the "
       "summary one, raised past the per-client cap.", ("confidentiality",)),


    _d("DNS-1002", 1, "dns_beacon", "dns_inspector", "ip",
       {"medium"},
       "A device queried the same domain on a near-constant cadence, the "
       "timing signature of automated check-in through DNS. The interval is "
       "regular enough that it is unlikely to be human-driven browsing. "
       "Normal backup and update tools produce this; so does C2 polling.", ("confidentiality",)),


    # dns_inspector, the checks that were listed as NOT BUILT until
    # 2026-09-22.
    #
    # WHY THESE FOUR ARRIVED TOGETHER, AND WHY THE NOTE THAT SAID THEY DID NOT
    # EXIST MATTERED MORE THAN THE MISSING CODE.
    #
    # query_dns_inspection carried a `not_implemented` list saying NXDOMAIN
    # rate and TXT volume "were never computed" because "the resolver import
    # does not carry the response code" and "does not carry the query type".
    # Measured against the tree on 2026-09-22 and BOTH CLAUSES WERE FALSE:
    # tools/dns_monitor.read_pihole decodes reply_type and query_type, the
    # columns are in dns_queries, and core/perf.py already aggregated NXDOMAIN
    # per client-hour out of them. So the list described a limit that no
    # longer existed, and it was the text the model reads: a model told the
    # data is not there does not go looking for it, and a model told a check
    # does not exist cannot say it was skipped. Both sentences shape the
    # answer more than the code does.
    #
    # The four below are that work, and each one is a claim the other rules in
    # this family cannot make:
    #
    #   DNS-1001 scores the REGISTERED (second-level) label, which is where a
    #   DGA lands. It never measures the labels to its left, so it cannot see
    #   data smuggled there at ANY threshold. DNS-1003 measures those labels,
    #   and that is a scope difference rather than a tuning difference.
    #
    #   DNS-1002 measures CADENCE on one name. DNS-1004 measures VOLUME for
    #   one client across every name, DNS-1005 measures the FAILURE SHARE (a
    #   device asking for names that do not exist, over and over), and
    #   DNS-1006 measures one RECORD TYPE, because TXT is both an ordinary
    #   lookup and the record type a resolver will carry arbitrary text in.
    #
    # ONE ID PER CLAIM: each of the four is a different fact with a different
    # remedy and they do not share a number.
    _d("DNS-1003", 1, "dns_tunnel_suspected", "dns_inspector", "ip",
       {"medium", "high"},
       "A device asked the resolver for several DISTINCT names whose "
       "encoded-looking part sits in the labels LEFT of the registered "
       "domain, which is where a DNS tunnel carries its payload. A scope "
       "claim rather than a threshold one: the DGA rule scores the registered "
       "label and never reads these, so a tunnel writing its data to the left "
       "of that label is invisible to it at any entropy setting. Named as a "
       "suspicion: base32-looking CDN and analytics names exist, which is why "
       "it takes several distinct payloads from one device rather than one "
       "long name.", ("confidentiality",)),

    _d("DNS-1004", 1, "dns_query_volume", "dns_inspector", "ip",
       {"low", "medium"},
       "One device made an unusually large number of DNS queries in the "
       "window, counted across every name it asked for. A measurement, not a "
       "classification: a browser cache flushing, a fresh install, a sync "
       "client and a resolver loop all look like this, and the address is "
       "worth a look rather than an accusation.", ()),

    _d("DNS-1005", 1, "dns_nxdomain_burst", "dns_inspector", "ip",
       {"medium"},
       "A device asked for a large number of names that DO NOT EXIST, and "
       "they were most of what it asked for in the window. Malware hunting "
       "for a live controller domain and a device with a broken search suffix "
       "both produce this shape, which is why the SHARE of its queries "
       "matters as much as the count. Only readable from a resolver that "
       "records the reply code: on this host that is Pi-hole, and the tool "
       "says so rather than implying AdGuard rows were checked.",
       ("confidentiality",)),

    _d("DNS-1006", 1, "dns_txt_volume", "dns_inspector", "ip",
       {"medium"},
       "A device asked this resolver for an unusual number of TXT records. "
       "TXT is a real record type that ordinary software uses, and it is also "
       "the record type a resolver will carry arbitrary text in, which makes "
       "it the cheapest outbound channel on a network where DNS is the only "
       "thing that always gets out. Volume rather than content: this tool "
       "does not read what the records SAID.", ("confidentiality",)),


    # L4, 2026-09-22. THE KERNEL AUDIT SUBSYSTEM, read by tools/
    # auditd_monitor.py when it is installed. AUD-1xxx because it is a
    # different FEED from anything above, not a different sensor of the same
    # kind: auditd is the kernel's own record of syscalls, watches and
    # reconfiguration, with the identity of whoever did it.
    #
    # BOTH OF THESE CAN BE STRUCTURALLY ABSENT ON A HOST, and that is the state
    # the owner's machine is in: auditd is not installed, so neither id can
    # fire however many passes run. What the app must never do is let that read
    # as a quiet machine -- query_audit_events says NOT INSTALLED in words and
    # prints the one command, which is the owner's Q7 wording for this task.
    #
    # ONE ID PER CLAIM, as always: "the monitoring was RECONFIGURED" and "a
    # watched file was TOUCHED" are different facts about different things, and
    # the first is about the watch itself rather than about the machine.
    _d("AUD-1001", 1, "audit_config_changed", "auditd", "file",
       {"medium"},
       "The kernel audit subsystem reported that its own configuration "
       "changed: a rule added, a rule removed, or the enabled flag flipped. "
       "The rules are what decide which syscalls and file watches are recorded "
       "at all, so a rule REMOVED reduces what this host writes down, and the "
       "absence of records afterwards is invisible by construction. This is "
       "the one rule in the register that reports a change to the monitoring "
       "itself, and nothing else in this tree can see it.",
       ("availability", "integrity")),

    _d("AUD-1002", 1, "audit_watch_touched", "auditd", "file",
       {"low"},
       "A path under a kernel audit watch was touched, recorded by the KERNEL "
       "with the identity of whoever did it. Unlike a polling check this does "
       "not depend on the process still existing: an execution or write that "
       "lasted milliseconds is still in the record. LOW because a watch firing "
       "is usually the answer its owner wanted, not a surprise, and because "
       "this app has the path and the identity and not the content: the local "
       "integrity sensor is what compares files against what they were.",
       ("integrity",)),

    # AND THE TWO THAT SAY THE RECORDING STOPPED.
    #
    # Same family as AUD-1001 -- a change to the monitoring itself -- and
    # deliberately NOT the same id, because the remedies differ and a reader
    # who is told "the rules changed" when the switch was turned OFF goes
    # looking for the wrong thing. Both are the shape this app exists to
    # refuse: a quiet feed that is quiet because the recorder was switched off
    # rather than because the machine was quiet.
    _d("AUD-1003", 1, "audit_kernel_disabled", "auditd", "file",
       {"high"},
       "The KERNEL's audit switch is OFF (audit_enabled=0 in a KERNEL record), "
       "or the kernel has DROPPED records because its backlog overflowed "
       "(audit_lost > 0). With the switch off, the kernel records NOTHING at "
       "all: no syscalls, no file watches, no rule changes, and the evidence "
       "of everything that happens from that moment is simply never written. "
       "HIGH because this is the one state that makes every later quiet "
       "answer wrong in the reassuring direction. The command that turns it "
       "back on is printed on the finding.",
       ("availability", "integrity")),

    _d("AV-1001", 1, "malware_signature_found", "av_scanner", "file",
       {"high"},
       "ClamAV matched one of its malware signatures in a file: a running "
       "program, or a new file in /tmp, /var/tmp, /dev/shm or a Downloads "
       "folder. A match names a known family or a test file; malware ClamAV "
       "has no signature for is not found this way.",
       ("integrity", "confidentiality")),

    _d("AUD-1004", 1, "audit_daemon_stopped", "auditd", "file",
       {"medium"},
       "The audit daemon wrote DAEMON_END: the process that writes the "
       "kernel's audit records to the log has exited, by a deliberate stop, a "
       "package upgrade or a crash. The kernel may still be collecting into "
       "its own buffers, but nothing is being written down, so from that "
       "moment the log is silent for a reason that has nothing to do with "
       "this machine being quiet. A DAEMON_START after it means it came back.",
       ("availability",)),


    # lan_watch, TODO 113.5
    #
    # SOURCE IS packet_sniffer, NOT lan_watch, and that is deliberate.
    # tools/lan_watch.py holds the logic but opens nothing and writes nothing.
    # packet_sniffer owns the capture, the cooldown and the write, so it is
    # the source in the sense this register means: the thing that raised it.
    # Same arrangement as tls_hello.
    #
    # ALL FOUR ARE HIGH. Unusual for this app, and the reason is that none of
    # them has a large innocent population. A gateway MAC does not change on
    # its own, a second DHCP server is wrong even when it is not an attack,
    # and a host answering name queries for four different names cannot be
    # doing anything else. The descriptions all carry the innocent
    # explanations, because "high" is about how much it is worth looking at,
    # not a verdict that something bad happened.
    _d("LAN-1001", 1, "arp_binding_flap", "packet_sniffer", "ip",
       {"high"},
       "One address had its hardware address change repeatedly in a short "
       "window. A single change is an ordinary DHCP lease moving; changing "
       "back and forth is two machines both claiming the address, which is "
       "what ARP spoofing looks like from outside.", ("integrity", "confidentiality")),


    _d("LAN-1002", 1, "gateway_mac_changed", "packet_sniffer", "ip",
       {"high"},
       "The default gateway is answering from a different hardware address "
       "than the one recorded for it. That is the position an attacker takes "
       "to sit between this network and everything outside it. A replaced or "
       "rebooted router produces the same observation.", ("confidentiality", "integrity")),


    _d("LAN-1003", 1, "rogue_dhcp_server", "packet_sniffer", "ip",
       {"high"},
       "A second device is answering DHCP. A rogue server can hand a client "
       "its own address as both gateway and DNS, which puts it in the middle "
       "of everything that client does. A misconfigured second router does "
       "the same thing by accident.", ("confidentiality",)),


    _d("LAN-1004", 1, "name_service_poisoning", "packet_sniffer", "ip",
       {"high"},
       "One host answered LLMNR or NBT-NS queries for several different "
       "names. A normal machine answers for its own name only. Answering for "
       "whatever was asked is the signature of a credential-capture tool, "
       "because these protocols have no authentication and the first reply "
       "wins.", ("confidentiality",)),


    # The IPv6 forms of the same attacks.
    _d("LAN-1005", 1, "ndp_binding_flap", "packet_sniffer", "ip",
       {"high"},
       "One IPv6 address had its hardware address change repeatedly in "
       "neighbour advertisements. Neighbour discovery is IPv6's ARP, and "
       "changing back and forth is two machines both claiming the address.",
       ("integrity", "confidentiality")),


    _d("LAN-1006", 1, "rogue_ipv6_router", "packet_sniffer", "ip",
       {"high"},
       "A new device is sending IPv6 router advertisements, which makes it "
       "the default IPv6 router for every host that hears them. A rogue one "
       "sits in the middle of IPv6 traffic; a second router or a phone "
       "sharing its connection does the same by accident.",
       ("confidentiality", "integrity")),


    _d("LAN-1007", 1, "rogue_dhcpv6_server", "packet_sniffer", "ip",
       {"high"},
       "A new device is answering DHCPv6. It can hand hosts its own address "
       "as their DNS server, which is how the mitm6 tool takes over name "
       "resolution, even on a network that uses only IPv4.",
       ("confidentiality",)),

    # The live LAN monitor, through the router. High ones wake the duty loop.
    _d("LAN-1008", 1, "new_device_live", "lan_live", "ip", {"high"},
       "The router lists a hardware address the device inventory has never "
       "held. Raised once per address, within a minute of it joining.",
       ("confidentiality", "integrity")),
    _d("LAN-1009", 1, "unusual_upload", "lan_live", "ip", {"high"},
       "A device sent far more out through the router in ten minutes than "
       "its own last week says is normal, or past a fixed limit while it has "
       "under a day of history.",
       ("confidentiality",)),
    _d("LAN-1010", 1, "threat_feed_contact_lan", "lan_live", "ip",
       {"high", "medium"},
       "A device on the network has a connection through the router to an "
       "address, or a name it looked up, on a threat feed. Medium when the "
       "feed's own list is old.",
       ("confidentiality", "integrity")),
    _d("LAN-1011", 1, "blocked_device_returned", "lan_live", "ip",
       {"high", "medium"},
       "A blocked device came back under a new address. High when only its "
       "old address was blocked, so it is online again; medium when the "
       "router still blocks its hardware address.",
       ("integrity",)),

    # feed_matcher, TODO 113.4
    #
    # THESE ARE THE ONLY DETECTIONS IN THIS REGISTER THAT ARE NOT THIS APP'S
    # OWN OPINION. Everything else here fires because a threshold we chose was
    # crossed. These fire because somebody else, with far more visibility than
    # one home network, published the address as known bad. That is why they
    # are allowed at high where almost nothing else is.
    #
    # MEDIUM IS THE STALE CASE, not a weaker variant of the same thing. A feed
    # that has not refreshed in two days may be listing infrastructure that was
    # taken down since, so the confidence really is lower and the severity says
    # so rather than burying it in the description.
    _d("FED-1001", 1, "c2_address_contacted", "feed_matcher", "ip",
       {"high", "medium"},
       "A device on this network opened an outbound connection to an address "
       "that a live known-bad feed lists as botnet command and control. Not a "
       "threshold this app chose: an external list said so.", ("confidentiality",)),


    _d("FED-1002", 1, "malicious_domain_resolved", "feed_matcher", "ip",
       {"high", "medium"},
       "A device asked the resolver for a domain that a known-bad feed lists "
       "as serving malware. A query is not proof the connection followed, but "
       "nothing asks for a name by accident.", ("confidentiality",)),


    _d("FED-1003", 1, "malicious_sni_handshake", "feed_matcher", "ip",
       {"high", "medium"},
       "A TLS handshake carried a server name that a known-bad feed lists. "
       "Stronger than the DNS version, because the handshake was actually "
       "attempted, and it still works when the device uses encrypted DNS.", ("confidentiality",)),

    # T6, 2026-09-22. THE KERNEL CAMERA. ebpf/ebpf_monitor.py runs as root,
    # attaches sched_process_exec and sys_enter_connect, and writes a sidecar
    # file; tools/ebpf_events.py reads it and raises these three.
    #
    # WHY THIS FAMILY IS WORTH A NEW NUMBER RANGE. Every rule above fires on
    # something a POLLING sensor asked the kernel about, which means every one
    # of them has the same structural hole: a program that starts, acts and
    # exits between two asks leaves no trace anywhere, and the app cannot even
    # report that it might have missed it. These three fire on events the
    # KERNEL reported rather than events we asked about, so they are the only
    # rules in this register that can see the five-second process. That is a
    # different kind of knowledge and it gets its own range: LNX-3xxx is the
    # camera, LNX-1xxx is the remote host over SSH, LNX-2xxx is this host's
    # files.
    #
    # THE CAMERA IS OPTIONAL AND THIS WHOLE FAMILY CAN BE ABSENT. It needs root
    # to load, so on a host where the operator has not run the installer there
    # is no camera, no event, and no finding from these ids -- and that absence
    # is reported in words by query_ebpf_events rather than left to be read as
    # a quiet machine. See ebpf/ebpf_monitor.py's header for why the privilege
    # is confined to that one file.
    #
    # ONE ID PER CLAIM, the rule this register is built on. LNX-3001 and
    # LNX-3002 are both "something ran from a staging directory" and they are
    # deliberately two numbers, because they are two facts with two remedies:
    # a program whose bytes are in /tmp is a file to go and look at, and a
    # SHELL running on such a file is a program that runs other programs, so
    # the remedy is to ask what it ran. An earlier draft had one id whose
    # severity moved between low and high, which is exactly the shape this file
    # exists to forbid: two different things sharing one history on the
    # Detections page.
    #
    # ALL THREE ARE STAGED-LOCATION AND PORT CLAIMS, NOT MALWARE CLAIMS. /tmp
    # is where installers, package builds, browser downloads and every mktemp
    # script on the machine legitimately run; 4444 is a port that appears in
    # the default configuration of remote-control tooling and is also a port
    # somebody's test server uses. The severities say how much it is worth
    # looking at, and each description carries the innocent reading, because a
    # rule whose reader assumes malice is a rule they stop reading.

    _d("LNX-3001", 1, "execution_from_staging_directory", "ebpf_events",
       "process", {"low"},
       "A program executed out of a staging directory (/tmp, /var/tmp, "
       "/dev/shm, a per-user runtime dir, or a user's cache or Downloads), "
       "seen by the kernel at the moment of the execve rather than by a poll "
       "that might have arrived after it exited. This is also where "
       "installers, package builds and everything that uses mktemp "
       "legitimately run, which is why it is low. The camera's default "
       "allowlist covers systemd's own private-tmp executors, which fire on "
       "every boot and are not worth a finding.",
       ("integrity",)),

    _d("LNX-3002", 1, "shell_on_staged_file", "ebpf_events",
       "process", {"high"},
       "A shell (sh, bash, dash, zsh and their relatives) executed a file "
       "that lives in a staging directory. A shell is a program whose whole "
       "purpose is running other programs, so a shell started on /tmp/x.sh "
       "means /tmp/x.sh is a script something chose to run, and the next "
       "question is what it ran. HIGH rather than medium because a shell in a "
       "staging directory has no large innocent population the way its parent "
       "rule does, and separate from LNX-3001 because the remedy is different: "
       "there you look at a file, here you ask what it started.",
       ("integrity", "confidentiality")),

    _d("LNX-3003", 1, "process_connect_dangerous_port", "ebpf_events",
       "ip", {"medium"},
       "A local process called connect() to an address and port that the "
       "sensor recognises as a remote-control or post-exploitation port "
       "(4444, 5555, 6666, 31337, 12345, 54321). THIS IS NOT A THREAT-FEED "
       "MATCH: it is a port nobody usually listens on by accident, which is a "
       "weaker claim, and the honest test is what is answering at the other "
       "end. The value over the packet capture is attribution: the capture "
       "sees the connection from the wire side and cannot say which process "
       "made it, and this says which program, under which pid, as which "
       "account. Loopback and link-local destinations are never raised.",
       ("confidentiality",)),

    # persistence / autoruns.
    #
    # THESE THREE ARE NEW ON 2026-09-24 AND THEY CAME OUT OF AN AUDIT, NOT OUT
    # OF A FEATURE REQUEST. Measured before this round: the autorun sensor
    # raised THREE finding types (suspicious_systemd_service, suspicious_cron_job,
    # suspicious_shell_startup), NONE of them had a registered detection id, and
    # no source named this sensor, so every one of its findings was dropped on
    # the floor with nothing saying so -- EM-2's shape exactly, one sensor over
    # ("the sensor has stored ZERO findings, ever, against 119 polls that logged
    # 0 finding(s)").
    #
    # WHY THREE RULES AND NOT ONE. The three places an autorun can hide have
    # three different remedies and three different owners: a systemd unit runs
    # as root for the machine, a cron entry runs as whoever owns the tab, and a
    # shell startup line runs as one human the moment they open a terminal. A
    # single "suspicious autorun" id would put those three on one line of the
    # Detections page and tell a reader nothing about which they are looking at.
    #
    # ALL THREE ARE MEDIUM AND THAT IS DELIBERATE. The pattern list is a weak
    # claim: measured on this host after the matcher was repaired, the two
    # surviving hits are `nft flush ruleset` in nftables' own ExecStop and
    # `systemctl stop` in systemd's own ask-password unit. Both are correct
    # matches and neither is an attack, which is the whole reason this is not
    # high and not critical. The strong claim lives elsewhere and is a different
    # rule: LNX-2006 and the local_integrity tier A comparison watch the FILE.
    # This watches the CONTENT OF A COMMAND and says what it matched.
    _d("LNX-5001", 1, "portless_listener_staged", "port_owner", "process",
       {"high"},
       "A program running from a staging directory (/tmp, /dev/shm and the "
       "like) or from a deleted binary holds a raw or packet socket. Those "
       "receive traffic with no open port, so no scan can see them; it is how "
       "BPFDoor-style backdoors wait for a trigger packet.",
       ("integrity", "confidentiality")),


    _d("LNX-4001", 1, "suspicious_persistence_unit", "registry_monitor",
       "file", {"medium"},
       "A systemd unit's executive line (ExecStart and its siblings) matches a "
       "pattern associated with remote fetch, a reverse shell, inline script "
       "execution, payload assembly, detaching, or disabling a defence. The "
       "finding quotes the line and says whether it is live code or a comment. "
       "MEDIUM AND NOT HIGH: a pattern cannot tell a legitimate shutdown script "
       "from a hostile one, and the units that matched on this host were "
       "nftables' own ExecStop and systemd's own ask-password teardown.",
       ("integrity", "confidentiality")),

    _d("LNX-4002", 1, "suspicious_persistence_cron", "registry_monitor",
       "file", {"medium"},
       "A cron job's command matches a pattern associated with remote fetch, a "
       "reverse shell, inline script execution, payload assembly, detaching, or "
       "disabling a defence. It runs unattended and, for a system tab, as root. "
       "The finding quotes the schedule and the command.",
       ("integrity", "confidentiality")),

    _d("LNX-4003", 1, "suspicious_shell_startup", "registry_monitor",
       "file", {"low", "medium"},
       "A shell startup file (.bashrc, .profile, .zshrc and friends) contains a "
       "line matching a pattern associated with remote fetch, a reverse shell, "
       "inline script execution or payload assembly. It runs for ONE ACCOUNT "
       "the moment that account opens a shell, which is why it matters: this is "
       "how a session gets a backdoor. MEDIUM for live code, LOW when the line "
       "is commented out, a commented-out pipe-to-shell line is a fact worth "
       "reporting and is not a backdoor.",
       ("integrity", "confidentiality")),

    _d("LNX-4004", 1, "autorun_entry_added", "registry_monitor",
       "file", {"medium"},
       "A systemd unit, user unit, cron entry, init script or shell startup "
       "file appeared since the autorun monitor's last reading. The change is "
       "the signal: a new way for something to start on its own.",
       ("integrity",)),

    _d("LNX-4005", 1, "autorun_entry_changed", "registry_monitor",
       "file", {"medium"},
       "An autorun entry that was already there now runs something different, "
       "or its unit changed state, since the last reading. A package update "
       "does this too; the finding quotes what it was and what it is.",
       ("integrity",)),

    _d("LNX-4006", 1, "autorun_entry_removed", "registry_monitor",
       "file", {"low"},
       "An autorun entry present at the last reading is gone. Usually an "
       "uninstall; worth a look when nobody removed anything.",
       ("integrity",)),

    # retired, kept so the numbers cannot be reused
    _d("PRT-1001", 1, "port_listening", "port_scanner", "port",
       {"low", "medium", "high", "critical"},
       "An open port was reported by a scan.",
       ("confidentiality",),
       retired=True,
       retired_reason=(
           "No code raises this any more; the port scanner writes to "
           "port_scan_results instead. Rows from before that change are still "
           "in the findings table with entity_type 'port', and "
           "memory_engine.clear_port_findings still has to find them by "
           "matching 'ip:port' inside the title, because they were written "
           "before anything had an id. Kept here so those rows have something "
           "to resolve to and so PRT-1001 is never handed to a new detection."
       )),
]


DETECTIONS: dict[str, Detection] = {d.did: d for d in _REGISTER}

# Guard against the one mistake this file exists to prevent. A duplicate id in
# the list above would silently collapse two detections into one in the dict
# and nobody would notice until two different things shared a history.
if len(DETECTIONS) != len(_REGISTER):
    _seen, _dupes = set(), []
    for _d_ in _REGISTER:
        if _d_.did in _seen:
            _dupes.append(_d_.did)
        _seen.add(_d_.did)
    raise RuntimeError(
        f"Duplicate detection ids in core/detections.py: {_dupes}. A number "
        f"is never reused, not even by accident."
    )

# Same guard for the threat-label prefixes, which are a second key into the
# same table. Two detections claiming one prefix means the sniffer's classifier
# output resolves to whichever happened to be later in the list.
_PREFIX_MAP: dict[str, Detection] = {}
for _d_ in _REGISTER:
    if _d_.threat_label_prefix:
        if _d_.threat_label_prefix in _PREFIX_MAP:
            raise RuntimeError(
                f"Two detections claim threat label prefix "
                f"'{_d_.threat_label_prefix}'."
            )
        _PREFIX_MAP[_d_.threat_label_prefix] = _d_

# THE THIRD KEY: WHICH RULE A BURST OF AN EVENT TYPE RAISES. TN-4, 2026-09-25.
#
# WHY IT IS HERE AND NOT IN THE PAGE. The Timeline has to say, on a
# service_started row, what would turn that row into a finding. That fact is a
# property of the REGISTER, and until this table existed it lived in
# adapters.py's LinuxEventMonitor as two local dicts (_EVENT_CATEGORY_IDS and
# _BURST_FINDING_IDS) that no reader outside that method could see. A page
# that typed the mapping again would be a second copy of a rule, and the
# second copy is the one that goes stale: rename a rule in the register and
# the page goes on naming the old id, which reads exactly like a working page.
#
# WHAT IS NOT HERE: the categories that are EVENTS ONLY and raise nothing.
# log_entry, sudo_usage, successful_login, failed_login's non-burst half and
# the rest are deliberately absent, because the honest sentence for those is
# "this is a record, not an alert", and a table with an entry for them would
# say a rule exists where the whole point is that none does. A reader that
# finds nothing here is reading the truth.
#
# The values are checked against DETECTIONS below rather than trusted, for the
# same reason the prefix map above is: a typo here would make the Timeline
# name a rule that does not exist while the register stayed correct.
EVENT_TYPE_RULES: dict[str, str] = {
    # Per-event categories that ARE findings, threshold 1. See adapters.py's
    # _EVENT_CATEGORY_IDS, which now reads its ids from here.
    "account_created":  "LNX-1009",
    "account_deleted":  "LNX-1010",
    "ssh_key_added":    "LNX-1011",
    "brute_force_detected": "LNX-1012",
    # The four burst rules added 2026-09-25. The event itself is a record; the
    # BURST is the finding, which is why the sentence the Timeline prints for
    # one of these rows names the threshold rather than this line.
    "service_restart_loop":    "LNX-1013",
    "service_flapping":        "LNX-1014",
    "firewall_scan_from_host": "LNX-1015",
    "login_burst_from_host":   "LNX-1016",
    "privileged_group_added":  "LNX-1017",
    "kernel_tainted":          "LNX-1018",
}

for _etype_, _did_ in EVENT_TYPE_RULES.items():
    if _did_ not in DETECTIONS:
        raise RuntimeError(
            f"EVENT_TYPE_RULES maps the event type '{_etype_}' to {_did_}, "
            f"which is not a registered detection. A pointer to a rule that "
            f"does not exist is worse than no pointer: it reads like one."
        )
    if DETECTIONS[_did_].source not in ("event_monitor", "linux_monitor"):
        raise RuntimeError(
            f"EVENT_TYPE_RULES maps '{_etype_}' to {_did_}, whose registered "
            f"source is {DETECTIONS[_did_].source!r}. A burst event type is "
            f"raised by a log reader; pointing it at another sensor's rule "
            f"would name the wrong raiser on every row that reads it."
        )


# And the same guard for the axis vocabulary. A typo -- "confidentialty" --
# would otherwise sit in the register looking like an axis while the watcher
# read the rule as carrying no loss at all. The two failures look identical
# from the outside, which is the reason to catch it here rather than in a
# review nobody runs.
for _d_ in _REGISTER:
    _unknown_axes = sorted(set(_d_.cia) - set(AXES))
    if _unknown_axes:
        raise RuntimeError(
            f"{_d_.did} declares axes that are not in the vocabulary: "
            f"{_unknown_axes}. Valid: {list(AXES)}. An axis nobody can read "
            f"is worse than none, because it looks classified."
        )


def get(did: str) -> Detection:
    """
    The registered detection, or raise.

    Deliberately fatal. See the module header: a findings table where only
    some rows resolve to a rule is worse than one where none do.
    """
    d = DETECTIONS.get(did)
    if d is None:
        raise UnknownDetection(
            f"No detection registered as '{did}'. Add an entry to "
            f"core/detections._REGISTER before raising it. Every finding has "
            f"to be traceable to a rule somebody wrote down, and a new id is "
            f"a decision, not a string literal at a call site."
        )
    return d


def exists(did: str) -> bool:
    """Non-raising membership test, for readers rather than writers."""
    return did in DETECTIONS


def check_severity(did: str, severity: str) -> None:
    """
    Refuse a severity this detection does not declare.

    Raises rather than correcting. Quietly clamping a severity would mean the
    screen and the register disagree about how bad this detection is, and the
    register is supposed to be the place that answer lives.
    """
    d = get(did)
    if severity not in d.severities:
        raise BadSeverity(
            f"{did} ({d.name}) is registered for severities "
            f"{sorted(d.severities)} and was raised at '{severity}'. If the "
            f"detection genuinely changed, change the register and bump its "
            f"rev, so the change is a decision rather than a drift."
        )


def axes(did: str) -> list[str]:
    """
    The axis of one detection, for a reader that only has the id.

    Same order as as_dict, and the same empty-list answer for a rule that
    carries no loss. Raises on an unregistered id like everything else here.
    """
    d = get(did)
    return sorted(d.cia,
                  key=lambda x: _AXIS_ORDER.index(x)
                  if x in _AXIS_ORDER else len(_AXIS_ORDER))


def by_axis() -> dict[str, list[dict]]:
    """The register grouped by axis, for a reviewer. Empty is a group."""
    out: dict[str, list[dict]] = {}
    for d in _REGISTER:
        if not d.cia:
            out.setdefault("no_axis", []).append(d.as_dict())
            continue
        for axis in d.cia:
            out.setdefault(axis, []).append(d.as_dict())
    return out


def detection_for_threat(threat_label: str) -> str | None:
    """
    Map a packet_sniffer threat label to its detection id.

    The labels are colon-delimited and carry their own parameters, so
    "dangerous_port_inbound:445:SMB" and "dangerous_port_inbound:3389:RDP" are
    the same detection seen twice. Everything before the first colon is the
    detection, everything after is the subject.

    RETURNS None RATHER THAN RAISING, and that is the one deliberate exception
    to this module being fatal. The classifier can grow a label before the
    register catches up, and the right answer in that moment is a finding that
    honestly says its detection is unmapped, not a sniffer thread that dies
    mid-capture and takes the whole sensor down with it. The caller decides
    what to do; core/memory_engine logs it loudly.
    """
    if not threat_label:
        return None
    prefix = threat_label.split(":", 1)[0]
    d = _PREFIX_MAP.get(prefix)
    return d.did if d else None


def unmapped_threat_prefixes(seen: list[str]) -> list[str]:
    """
    Which of these observed threat labels have no detection registered.

    For the report script and the test. Answers "has the classifier grown a
    label nobody registered", which is the failure detection_for_threat is
    allowed to survive and therefore the failure that could go unnoticed.
    """
    out = []
    for label in seen or []:
        if not label:
            continue
        prefix = label.split(":", 1)[0]
        if prefix not in _PREFIX_MAP and prefix not in out:
            out.append(prefix)
    return sorted(out)


def summary(include_retired: bool = True) -> list[dict]:
    """The whole register, for a page, a reviewer or the model."""
    return [
        d.as_dict() for d in _REGISTER
        if include_retired or not d.retired
    ]


def real_detections() -> list[dict]:
    """
    Only the entries that are actually detections, live ones.

    What to show when answering "what can this tool catch". Action records and
    retired numbers are real rows in the register and would inflate that
    answer, so they are counted elsewhere rather than here.
    """
    return [d.as_dict() for d in _REGISTER
            if d.kind == "detection" and not d.retired]


def by_source() -> dict[str, list[dict]]:
    """The register grouped by the sensor that owns each number."""
    out: dict[str, list[dict]] = {}
    for d in _REGISTER:
        out.setdefault(d.source, []).append(d.as_dict())
    return out
