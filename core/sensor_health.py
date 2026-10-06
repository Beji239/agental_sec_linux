# core/sensor_health.py
# AgentalSec V2, which sensor every tool's answer rests on.
#
# TODO 61.
#
# WHY THIS EXISTS
#
# On 2026-09-07 the dashboard was fixed three times in one afternoon for the
# same fault: a sensor that could not see, reported as fine. Every fix was on
# a screen. Then the obvious question, which the owner asked: the model does not
# look at screens.
#
# On a run where capture is blind, query_packets returns []. Nothing in that
# answer says the sensor was never able to look. The model reads [] as a quiet
# network, and unlike a wrong tile that conclusion gets WRITTEN DOWN, as a
# behavioral observation, a baseline, or the absence of a finding.
#
# That is the worst version of this bug in the whole codebase, and it was the
# last one anybody looked at.
#
# THE RULE
#
# EVERY tool declares what its answer rests on. depends_on() raises on a tool
# that has not declared, exactly as finding_policy raises on an unregistered
# sensor and core/privilege raises on an unregistered module. A tool that
# never declared would be a tool whose empty answer nobody has thought about,
# and it would look identical to one that genuinely depends on nothing.
#
# "Depends on nothing" is a claim. It gets written down like any other.
#
# WHEN IT SAYS SOMETHING
#
# Only when a dependency is actually degraded. A healthy run adds nothing to
# any tool result, which is why the lists below can be generous: listing every
# sensor that feeds the findings table costs nothing on a good day and is the
# whole point on a bad one.

import logging

from core.voice import for_you

logger = logging.getLogger(__name__)

# A capability from core/capabilities, rather than a loaded module. These are
# the things the MACHINE can refuse even when the module is running fine.
CAP = "cap:"

# HOW MANY POLLS IN A ROW MAKE A FAILURE WORTH SAYING OUT LOUD. 2026-09-25.
#
# One failed poll is a blip and says nothing; three in a row is a sensor that
# has measured nothing since the first of them. THE SAME FIGURE THIS TREE
# ALREADY USES for a monitor that is loaded, callable and getting nowhere
# (core/settings' consecutive_unresolved branch and the dashboard tile both
# floor at three), so there is one house answer rather than a second one for
# the same question. Declared HERE and imported by the card, so the two
# surfaces cannot drift apart.
CONSECUTIVE_FAILURE_FLOOR = 3


# COLLECTORS THAT ARE OFF BY DEFAULT AND ARE NOT OBJECTS.
#
# dns_monitor and router_monitor never enter main.py's modules dict. They are
# module level status(config) functions and both ship switched off. Without
# this, they came out of the check below as "NOT LOADED", which is true and
# reads as broken, and on 2026-09-07 the model duly reported a deliberately
# disabled collector as a degradation.
#
# OFF and BROKEN have to be different sentences. Both explain an empty answer,
# and only one of them is something to go and fix. Getting this wrong is how a
# warning list turns into noise somebody learns to skip, which would undo the
# whole point of the file.
CONFIG_COLLECTORS = {
    "dns_monitor":    "tools.dns_monitor",
    "router_monitor": "tools.router_monitor",
}

_config_cache = None


def _config() -> dict:
    global _config_cache
    if _config_cache is None:
        try:
            import json
            from core import settings
            _config_cache = json.loads(
                settings.CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug(f"config unreadable for the health check: {e}")
            _config_cache = {}
    return _config_cache


def _config_collector_trouble(name: str) -> str | None:
    """One of the off-by-default collectors, in its own words, or None."""
    try:
        import importlib
        mod = importlib.import_module(CONFIG_COLLECTORS[name])
        st = mod.status(_config() or {})
    except Exception as e:
        return (f"{name} could not report its own health "
                f"({type(e).__name__}: {e})")
    if st.get("available"):
        return None
    return (f"{name} is OFF, not broken: "
            f"{st.get('reason') or 'not configured'}. So this answer is empty "
            f"because nothing is collecting, which is a configuration choice "
            f"rather than a failure and rather than a quiet network")


class UnregisteredTool(Exception):
    """A tool asked what it depends on and no entry exists for it."""


# tool name -> what its answer rests on.
#
# Module names match the keys main.py registers. linux_monitor is registered
# per host as "linux_monitor:<address>", so it is matched by prefix.
DEPENDS: dict[str, tuple] = {

    # live sensor reads. The empty-means-quiet cases.
    "query_packets":              ("packet_sniffer", CAP + "capture"),
    # QUERY_EVENTS RESTS ON THE SENSOR, NOT ON A WINDOWS CAPABILITY.
    # 2026-09-25.
    #
    # This entry used to be ("event_monitor", CAP + "security_log"). On Linux
    # `security_log` was the WINDOWS Security channel, absent by construction at
    # any elevation, so every one of these results carried "the machine refuses
    # 'security_log'" into the model's context about a sensor that reads all
    # four of its sources fine. Twelve such lines are in the app's own log; one
    # of them sat on a real query_events result.
    #
    # The capability is gone from core/capabilities.py this round, so the
    # sentence cannot come back. What remains is the declaration that was
    # always the true one: the answer rests on event_monitor, whose own health
    # (blind, backlog, stalled, failing polls) is what the model needs.
    "query_events":               ("event_monitor",),
    # search_logs, ADDED 2026-09-23 WITH THE TOOL ITSELF.
    #
    # Same dependency as query_events and for the same reason: an empty answer
    # from this tool means "no line matched" ONLY IF the reader could read the
    # logs. On a run where journald is refused and no log file is readable,
    # "no matches" is a statement about access, and the model must not read it
    # as a quiet host. Nothing else here: the tool reads the logs directly
    # rather than a table, so there is no other module whose health it rests
    # on.
    "search_logs":                ("event_monitor",),
    "query_port_scan":            ("port_scanner",),
    "query_dns_clients":          ("dns_monitor",),
    "query_dns":                  ("dns_monitor",),
    # systemd units. L2, 2026-09-22.
    #
    # BOTH DECLARE NOTHING, AND THAT IS THE DECISION RATHER THAN AN OMISSION.
    # The systemd module is not a SENSOR: it has no thread, contributes no
    # findings on its own, and answers a question about the machine that is
    # true or false independently of whether anything here is watching. A
    # warning bolted onto it would be a caveat about something the answer never
    # claimed. Its OWN partial failures -- systemctl missing, a manager that
    # will not answer -- are carried in its payload as words, which is where a
    # reader can act on them.
    "query_services":             (),
    "stop_service":               (),
    # Background apps read systemd and the desktop directly; no sensor needed.
    "query_background_apps":      (),
    "block_background_app":       (),
    "disable_background_app":     (),
    "undo_background_change":     (),
    # The router agent, T9. Every answer rests on reaching it, so a router
    # that cannot be asked travels with the answer as a warning.
    "query_gateway":              ("gateway",),
    "gateway_block_device":       ("gateway",),
    "gateway_unblock_device":     ("gateway",),
    "gateway_sinkhole_domain":    ("gateway",),
    "gateway_unsinkhole_domain":  ("gateway",),
    "query_router_clients":       ("router_monitor",),
    "query_router_config":        ("router_monitor",),
    "adopt_router_hostname":      ("router_monitor",),
    "query_host_info":            ("host_info",),
    "query_installed_software":   ("software_inventory",),
    "query_autoruns":             ("registry_monitor",),
    "query_local_integrity":      ("local_integrity",),
    "query_ebpf_events":          ("ebpf_events",),
    # the kernel audit feed. L4, 2026-09-22.
    #
    # IT DECLARES THE ROLE AND NOT A CAPABILITY, and it is the only entry here
    # whose module is LOADED ON A HOST WHERE ITS SOURCE CANNOT EXIST. The
    # module always loads -- see main.py -- so "auditd is NOT LOADED" never
    # appears for the absence; the absence travels in the payload as
    # `installed: false` and `auditd_state: "NOT INSTALLED"`, which is where a
    # reader can act on it (it names the one command).
    #
    # That is deliberately NOT the blind flag, and the module says so at
    # length: a machine that has not installed auditd is a stated limit of the
    # machine, not a fault in this app, and reporting blind for it would
    # attach a permanent caveat to every answer for the life of the
    # installation. The one case here that IS blind is the log existing and
    # this account being unable to read it, which is the DEFAULT on every
    # install, and that one does raise the envelope through the module's own
    # status().
    "query_audit_events":         ("auditd",),
    "list_monitored_hosts":       ("linux_monitor",),
    "query_vpn_state":            ("vpn_state",),
    # TODO 113.2. The TLS rows come from the sniffer and nowhere else, so a
    # blind capture means an empty name list, not a quiet machine. This entry
    # is also what stops execute_tool raising UnregisteredTool, which is the
    # guardrail that caught the three prediction tools in 109.
    #
    # PORTED 2026-09-21. The Linux sniffer is a different module
    # (tools.packet_sniffer_linux behind the "packet_sniffer" role) and the
    # dependency is declared by ROLE, not by module path, so this entry is
    # correct on this platform unchanged.
    "query_tls":                  ("packet_sniffer", CAP + "capture"),
    "query_dns_answers":          ("packet_sniffer", CAP + "capture"),

    # TODO 120, 2026-09-20, PORTED 2026-09-21. The 113.3 to 113.6
    # detectors.
    #
    # ALL FOUR OF THESE CAN RETURN AN HONEST EMPTY ANSWER FOR TWO COMPLETELY
    # DIFFERENT REASONS, which is exactly what this map exists for. The
    # modules themselves carry their own coverage blocks, and the entries
    # here are the second line: they say which sensor going quiet makes the
    # emptiness meaningless.
    #
    # query_payload, arm and disarm all rest on the CAPTURE, because the ring
    # lives inside the sniffer and is filled from the capture callback. No
    # capture means the ring is not just empty, it does not exist, and
    # "nothing was kept" would then read as "nothing was sent".
    "query_payload":              ("packet_sniffer", CAP + "capture"),
    "arm_payload_capture":        ("packet_sniffer", CAP + "capture"),
    "disarm_payload_capture":     ("packet_sniffer", CAP + "capture"),

    # The LAN checks are decoded out of frames the same capture delivers, and
    # ARP in particular needs the widened BPF filter. A blind capture means
    # not one ARP frame was examined.
    "query_lan_watch":            ("packet_sniffer", CAP + "capture"),

    # DNS inspection reads the resolver import, not the capture. So its quiet
    # case is dns_monitor going quiet, and that is a different sensor with a
    # different failure: the resolver log unreadable, rather than the adapter
    # unopened.
    "query_dns_inspection":       ("dns_monitor",),

    # The feed matcher rests on NO SENSOR AT ALL, and that is the honest
    # answer rather than an omission. Its coverage question is whether the
    # DOWNLOAD succeeded, which is nothing to do with whether this machine
    # can see traffic, and the tool answers that itself with feed_loaded and
    # stale. Declaring a sensor here would attach the wrong explanation to an
    # empty result.
    "query_threat_feed":          (),

    # Findings come from every sensor that writes one. An absent finding is
    # the quietest evidence in the app, so this list is deliberately long.
    #
    # THE TWO WINDOWS CAPABILITIES CAME OFF IT 2026-09-25. `cap:security_log`
    # and `cap:defender` were declared here and on query_important below, and
    # on this platform neither could ever be anything but unavailable, so they
    # were a permanent degradation line on the two tools the owner reads most.
    # The sensors that raise the findings these tools return are all named
    # above them, which is the declaration that carries information.
    "query_findings": (
        "packet_sniffer", "event_monitor", "process_monitor",
        "linux_monitor", "port_scanner", "network_scanner",
        "registry_monitor", "remediation",
        CAP + "capture",
    ),

    # Device knowledge rests on the sweeps and on capture seeing the device
    # talk. A device missing here on a blind run is not a device that is gone.
    "query_known_devices":        ("network_scanner", "probe", "packet_sniffer",
                                   CAP + "capture"),
    "query_device_drift":         ("network_scanner", "probe"),
    "query_presence":             ("network_scanner", "probe", "packet_sniffer",
                                   CAP + "capture"),
    "identify_device":            ("network_scanner", "probe", "packet_sniffer",
                                   CAP + "capture"),

    # behavioural. The model WRITES here, which is why a blind run
    # matters more, not less: a baseline built while the sensor could not see
    # is a lie that outlives the session.
    "query_behavioral_baseline":  ("packet_sniffer", CAP + "capture"),
    "query_behavioral_session":   ("packet_sniffer", CAP + "capture"),
    "query_behavioral_deviation": ("packet_sniffer", CAP + "capture"),
    "write_behavioral_observation": ("packet_sniffer", "event_monitor",
                                     CAP + "capture"),
    "update_behavioral_baseline": ("packet_sniffer", CAP + "capture"),
    "write_deviation":            ("packet_sniffer", CAP + "capture"),
    "resolve_deviation":          ("packet_sniffer", CAP + "capture"),
    "supersede_observation":      (),
    "query_suppressed_baselines": (),
    "trigger_rollup":             ("packet_sniffer", CAP + "capture"),

    # the prediction ledger, v31.
    #
    # write_prediction DECLARES THE SENSORS ITS CLAIM WILL BE CHECKED
    # AGAINST, and that is the useful moment to say so. The checker already
    # refuses to score a window the capture could not see, so a prediction
    # filed on a blind run is not dangerous, it is just wasted: it comes back
    # unverifiable hours later and the model never finds out why. Warning at
    # the moment of filing turns that into a decision.
    #
    # This is the opposite reasoning from write_behavioral_observation next to
    # it. There, a blind run means the row is a LIE that outlives the session.
    # Here it means the row is a WASTE. Same declaration, different cost, and
    # worth writing down because someone will otherwise read this entry as
    # copied from the one above.
    "write_prediction":           ("packet_sniffer", "network_scanner",
                                   CAP + "capture"),

    # The two reads rest on the prediction table alone. The score is our own
    # bookkeeping about our own guesses, so a blind sensor does not make it
    # less true, and warning about capture here would attach a caveat to a
    # number that has nothing to do with capture. An empty ledger means
    # nothing has been filed, which is never ambiguous.
    "query_prediction_score":     (),
    "query_predictions":          (),

    # v33, TODO 112. DECLARES NOTHING, and the reasoning is the opposite of
    # every other entry on this list.
    #
    # This tool answers "what rules exist and which are silenced", which is a
    # fact about this codebase and its own configuration. A blind sensor does
    # not make that answer less true, and a capture warning bolted onto it
    # would be a caveat about something the answer never claimed.
    #
    # The caveat this tool DOES need is different in kind and it is carried in
    # the payload rather than here: findings raised before detection ids
    # existed have no id, so a rule can read zero while having fired for
    # weeks. detection_overview reports that count separately and says so in
    # words, because "0" and "0 that I can attribute" are different sentences.
    "query_detections":           (),

    # the case memory, v43.
    #
    # THE READS DECLARE NOTHING, the same argument query_incidents and
    # query_action_requests make: these answer "what has this app remembered
    # about its own incidents", which is a fact about our own bookkeeping. A
    # blind sensor does not make that less true, and a capture warning here
    # would be a caveat about something the answer never claimed.
    #
    # Its OWN partial blindness is different in kind and is carried in the
    # payload rather than here: `index.lag` says how far the search index is
    # behind the ledger, and the note distinguishes "nothing similar ever
    # happened" from "the index could not answer". Those are the two sentences
    # this tool exists to keep apart, and they belong on the answer, not on a
    # sensor map.
    "query_case_memory":          (),

    # the incident ledger, v35, T2.
    #
    # THE READS DECLARE NOTHING, and that is the same argument query_detections
    # makes: these answer "what has this app raised and how has it been
    # triaged", which is a fact about our own bookkeeping. A blind sensor does
    # not make that less true, and a capture warning here would be a caveat
    # about something the answer never claimed.
    #
    # THE WATCHER'S OWN HEALTH, though, is the one place in this block where
    # blindness is the whole subject, and the incident_watcher module reports
    # it itself through status(). It is deliberately NOT in DEPENDS: the tool
    # that reports whether things are being watched must not itself be gated
    # on the watching working, or a stopped watcher would silence the report
    # that says it stopped.
    "query_incidents":            (),
    "query_incident_summary":     (),

    # the action queue, v36, T3.
    #
    # THE READS DECLARE NOTHING, the same argument again: these answer "what
    # has this app asked the operator to approve and what did the owner say", which
    # is a fact about our own bookkeeping and not about the network.
    #
    # THE EXECUTOR'S OWN HEALTH is the one thing here that can be blind, and
    # like the watcher it reports itself through status(). Also deliberately
    # NOT in DEPENDS, for the watcher's reason: the tool that reports whether
    # an approval has anything behind it must not be silenced by the thing it
    # is reporting on.
    #
    # file_action_request declares nothing, and the tempting reading is the
    # opposite one. A request filed on a blind run looks like it needs a
    # capture warning. It does not: what was FILED is a proposal, its
    # blindness belongs on the incident and on the coverage snapshot the
    # incident already carries, and a caveat here would attach the sensor's
    # state to a filing receipt that makes no claim about the network.
    "file_action_request":        (),
    "query_action_requests":      (),

    # the duty loop, v37, T4.
    #
    # THE REPORT READ DECLARES NOTHING, the same argument query_incidents and
    # query_action_requests make: these answer "what has this app's agent woken
    # up and written", which is a fact about our own bookkeeping. A blind
    # sensor does not make that less true.
    #
    # THE LOOP'S OWN HEALTH is the one thing here that can be blind, and like
    # the watcher and the executor it reports itself through status(). Also
    # deliberately NOT in DEPENDS, for the same reason as those two: the tool
    # that reports whether anything is awake must not be silenced by the thing
    # it is reporting on.
    "query_agent_reports":        (),

    # asking the owner, v32.
    #
    # ask_operator DECLARES NOTHING, and that is the interesting entry on this
    # list. Every other declaration here exists because a blind sensor makes
    # an empty answer misleading. This tool's answer is "filed" or "refused",
    # which is about the queue and not about the network, so a capture warning
    # attached to it would be a caveat about something the answer does not
    # claim.
    #
    # Worth saying out loud because the tempting read is the opposite one: a
    # question asked on a blind run looks like it needs a warning. It does
    # not. The blindness is exactly WHY the owner is being asked.
    "ask_operator":               (),
    "query_operator_answers":     (),

    # the performance axis, v32. It is built entirely out of stored
    # packets, so a run where capture is down produces thin hours, and thin
    # hours are the case the whole coverage column exists to mark. The
    # declaration is here anyway: the tool's own answer marks its blind hours
    # per bucket, and this marks the whole answer when the sensor behind it is
    # down right now. Belt and braces, in the direction of saying too much
    # about what we could not see.
    "query_performance":          ("packet_sniffer", CAP + "capture"),

    # pcap. A file on disk, so nothing live, but the analyser has to
    # have loaded.
    "run_pcap_analysis":          ("pcap_analyzer",),
    "query_pcap_results":         ("pcap_analyzer",),
    "write_pcap_assessment":      (),

    # outside the machine.
    "lookup_ip":                  ("enrichment",),
    "enqueue_enrichment":         ("enrichment",),
    "query_enrichment":           ("enrichment",),
    "web_search":                 ("web_search",),
    "geolocate_ip":               ("geoip",),
    "query_threat_map":           ("geoip", "packet_sniffer", CAP + "capture"),
    "query_runbook":              ("runbook",),

    # actions. These declare the capability the machine can refuse, so
    # the model is told BEFORE it asks a human to approve something that
    # cannot work.
    "kill_process":               ("remediation", CAP + "process_kill"),

    # Reading the process table needs no rights and no module, so this
    # declares only the capability that widens it. Unelevated, process_details
    # is LIMITED rather than unavailable: your own processes read fine and
    # another account's come back with an empty command line. That is a
    # narrower answer, not a missing one, and the limited wording says so.
    "query_processes":            (CAP + "process_details",),

    # Port ownership, added 2026-09-25 with the tool. It depends on NO MODULE:
    # it reads /proc itself, on its own thread, so it answers even on a run
    # where every sensor in the module table failed to load. The privilege
    # limit it DOES have (other accounts' fd tables are unreadable unelevated)
    # is not a sensor dependency and is carried in the payload's own coverage
    # sentence, which is where a reader can act on it -- see the argument on
    # query_services just above.
    "query_port_owner":           (),
    "query_host_listeners":       (),

    # Hashing and the signature check need no rights and no module either.
    # The reputation half rests on enrichment, and enrichment being off is
    # worth saying, because "no reputation" would otherwise read as "nothing
    # known against it" when nobody asked anybody.
    "inspect_process":            ("enrichment", CAP + "process_details"),
    "block_port":                 ("remediation", CAP + "firewall_write"),
    "unblock_port":               ("remediation", CAP + "firewall_write"),
    "block_device":               ("remediation", CAP + "firewall_write"),
    "unblock_device":             ("remediation", CAP + "firewall_write"),
    "query_blocked_ports":        ("remediation", CAP + "firewall_read"),
    "query_device_blocks":        ("remediation", CAP + "firewall_read"),
    "quarantine_file":            ("remediation",),
    "restore_file":               ("remediation",),
    "scan_with_antivirus":        ("av_scanner",),
    "remove_ssh_key":             ("remediation",),
    "restore_ssh_key":            ("remediation",),
    "lock_account":               ("remediation",),
    "unlock_account":             ("remediation",),
    "remove_group_member":        ("remediation",),
    "restore_group_member":       ("remediation",),
    "disable_cron_line":          ("remediation",),
    "restore_cron_line":          ("remediation",),
    "disable_service":            ("remediation",),
    "enable_service":             ("remediation",),
    "query_quarantine":           ("remediation",),
    "run_port_scan":              ("port_scanner",),
    # query_inventory_gaps rests on the SWEEPS, not on the scanner having been
    # asked: it is the every-fifteen-minute presence record it reads, and the
    # scanner going blind is what makes the gap grow without anyone noticing.
    "query_inventory_gaps":       ("network_scanner",),
    "scan_network":              ("network_scanner",),

    # reads of our own bookkeeping. These rest on nothing outside the
    # database, and that is a claim, written down rather than assumed.
    "query_sensors":              (),
    # The tool that REPORTS health cannot itself depend on health, or a blind
    # sensor would make the one tool that explains blindness look unreliable.
    "query_sensor_health":        (),
    "query_database_size":        (),
    # TODO 84. The important list is a VIEW over findings, not a copy, so it
    # inherits their whole dependency list. It gets it for a sharper reason
    # than query_findings does: this is the list the owner trusts most, so a
    # quiet one on a blind run is the most dangerous quiet in the app. If
    # capture is down, nothing new is being raised, nothing new can be
    # promoted, and a settled-looking important list is exactly the wrong
    # thing to take comfort from.
    "query_important": (
        "packet_sniffer", "event_monitor", "process_monitor",
        "linux_monitor", "port_scanner", "network_scanner",
        "registry_monitor", "remediation",
        CAP + "capture",
    ),
    # Nominating acts on ONE finding that already exists, by id. Its answer
    # does not rest on any sensor being alive right now, the same as
    # dismiss_entity below. Declaring nothing here is a claim, and this is it.
    "nominate_finding":           (),

    "query_dismissed":            (),
    "dismiss_entity":             (),
    "undismiss_entity":           (),
    "query_review_queue":         (),
    "revert_suppression":         (),
    "list_code_files":            (),
    "read_code_file":             (),
}


def depends_on(tool: str) -> tuple:
    """
    What this tool's answer rests on. Raises if the tool never declared.

    Fatal on purpose. See THE RULE at the top of this file.
    """
    deps = DEPENDS.get(tool)
    if deps is None:
        raise UnregisteredTool(
            f"No sensor dependency entry for tool '{tool}'. Add one to "
            f"core/sensor_health.DEPENDS, including if the answer is an empty "
            f"tuple. A tool that never declared is a tool whose empty answer "
            f"nobody has thought about, and on a run where its sensor is "
            f"blind the model will read that emptiness as a quiet network."
        )
    return deps


def _module_trouble(name: str, mod) -> str | None:
    """
    One module, in one sentence, or None when it is fine.

    Order matters. Blind is checked before running for the same reason the
    readiness card checks it first: a module that is running and cannot see is
    a worse answer than one that is simply off, and it is the one that looks
    healthy. Failing polls are checked the same way and for the same reason:
    the module is up, its own counter says the last several passes threw, and
    nothing has been measured since the first of them.
    """
    if mod is None:
        return f"{name} is NOT LOADED, so it contributed nothing this run"

    status = getattr(mod, "status", None)
    if not callable(status):
        return None
    try:
        st = mod.status()
    except Exception as e:
        return f"{name} could not report its own health ({type(e).__name__})"
    if not isinstance(st, dict):
        return None

    if st.get("blind"):
        return (f"{name} is BLIND: "
                f"{st.get('blind_reason') or 'reason not recorded'}")

    if st.get("reachable") is False:
        fails = st.get("consecutive_failures")
        tail = f", {fails} polls in a row have failed" if fails else ""
        return (f"{name} is NOT ANSWERING{tail}: "
                f"{st.get('last_error') or 'no reason recorded'}")

    # ALIVE AND THROWING ON EVERY POLL. 2026-09-25.
    #
    # adapters._BaseAdapter counts consecutive failures and keeps the last
    # error, and its status() publishes both, and until this line NOTHING in
    # this file read either one unless the module also published `reachable`,
    # which most of the Linux modules do not. MEASURED with a module reporting
    # 7 consecutive failures: identical to a healthy control, None here and
    # "running." on the card. The app's own log already holds one real
    # instance (local_integrity, 2026-09-22). A module that is up and measuring
    # nothing must not read as a quiet machine to the model, which is the whole
    # argument this file opens with.
    #
    # GATED ON THE MODULE NOT SAYING IT IS STOPPED, so a sensor that was shut
    # down after a bad run still gets the more precise sentence below: it is
    # NOT RUNNING, and that is the fact to lead with.
    fails = st.get("consecutive_failures")
    alive = st.get("running", st.get("ready", st.get("available")))
    if (isinstance(fails, int) and not isinstance(fails, bool)
            and fails >= CONSECUTIVE_FAILURE_FLOOR and alive is not False):
        return (f"{name} is FAILING POLLS: the last {fails} in a row failed "
                f"({st.get('last_error') or 'no reason recorded'}), so it has "
                f"measured nothing since the first of them")

    if alive is False:
        return f"{name} is NOT RUNNING: {st.get('reason') or 'no reason recorded'}"

    return None


def _capability_trouble(cap_name: str) -> str | None:
    """One privileged capability, or None when the machine allows it."""
    try:
        from core import capabilities
        row = capabilities.get().availability().get(cap_name)
    except Exception as e:                              # pragma: no cover
        logger.debug(f"capability {cap_name} unreadable: {e}")
        return None
    if row is None:
        return None
    # A CAPABILITY THAT IS NOT THERE IS REPORTED, AND NOTHING HERE EXCUSES ONE.
    # 2026-09-25.
    #
    # This function used to carry a branch that returned None for a capability
    # whose `kind` was "not_on_this_platform": `security_log` and `defender`
    # were Windows capabilities, permanently unavailable here, and every
    # query_events and search_logs result carried "the machine refuses
    # 'security_log'" into the model's context about a sensor that reads all
    # four of its sources fine.
    #
    # THE FIX WAS THE PRODUCER RATHER THAN THIS BRANCH. Those capabilities are
    # gone from core/capabilities.py this round, with their verbs and their
    # cards, so no dependency can name one and this function only ever meets a
    # capability this platform HAS. If one is unavailable, that is a fact about
    # this RUN -- a missing right or a missing library -- and the model is told
    # it. Keeping a branch here for a capability that no longer exists would be
    # code waiting for a state that cannot arrive.
    if not row.get("available"):
        return (f"the machine refuses '{cap_name}': "
                f"{row.get('why_not') or 'no reason recorded'}")
    if row.get("limited"):
        return f"'{cap_name}' is narrower than usual: {row['limited']}"
    return None


def warnings_for(tool: str, modules: dict) -> list[str]:
    """
    What is wrong with the things this tool's answer rests on, right now.

    Empty list on a healthy run, which is most runs, so nothing is added to a
    tool result unless there is something real to say.
    """
    out = []
    for dep in depends_on(tool):
        if dep.startswith(CAP):
            trouble = _capability_trouble(dep[len(CAP):])
            if trouble:
                out.append(trouble)
            continue

        # linux_monitor is registered per host as "linux_monitor:<address>",
        # so one declared dependency can match several loaded modules.
        if dep in CONFIG_COLLECTORS:
            trouble = _config_collector_trouble(dep)
            if trouble:
                out.append(trouble)
            continue

        matched = {k: v for k, v in (modules or {}).items()
                   if k == dep or k.startswith(dep + ":")}
        if not matched:
            # Same wording the readiness card uses, and for the same reason:
            # this cannot tell the two apart, so it says so rather than
            # picking one and sounding certain.
            out.append(f"{dep} is NOT LOADED, either switched off in "
                       f"config.json or it failed to import at boot, and the "
                       f"log says which. Either way it contributed nothing")
            continue
        for key, mod in sorted(matched.items()):
            trouble = _module_trouble(key, mod)
            if trouble:
                out.append(trouble)
    return out


def measurement_is_possible(tool: str, modules: dict) -> tuple[bool, str]:
    """
    Could ANY live sensor behind this tool have measured something right now.

    (True, "") when at least one of them can see. (False, why) when every one
    of them is degraded, which is the only case where a claim of measurement
    is certainly false.

    Deliberately not "any sensor is degraded". If capture is blind but the log
    reader is fine, a measured claim about a logon is still true, and refusing
    it would teach somebody that the guard is wrong. One healthy sensor is
    enough to allow the claim; nought is enough to refuse it.
    """
    live = [d for d in depends_on(tool)
            if not d.startswith(CAP) and d not in CONFIG_COLLECTORS]
    if not live:
        return True, ""

    problems = []
    for dep in live:
        matched = {k: v for k, v in (modules or {}).items()
                   if k == dep or k.startswith(dep + ":")}
        if not matched:
            problems.append(f"{dep} is not loaded")
            continue
        for key, mod in sorted(matched.items()):
            trouble = _module_trouble(key, mod)
            if trouble is None:
                return True, ""          # one healthy sensor is enough
            problems.append(trouble)
    return False, "; ".join(problems)


# The sentence that does the actual work. Written for a reader who is about to
# draw a conclusion from a short answer.
#
# MARKED NOT-FOR-RECITAL, ported 2026-09-21 with core/voice.py. The marker
# exists because this sentence is an instruction TO THE MODEL, and the model
# used to read it as prose meant for the operator and repeat it mid-answer.
# The dashboard strips the marker back off on the way out (see
# sanitize.for_display), so the operator still reads the whole caveat.
READING_NOTE = for_you(
    "Something this answer rests on is degraded right now, so a small or "
    "empty result may mean THE SENSOR COULD NOT LOOK. It is not evidence "
    "that nothing happened, and silence here is not evidence of a quiet "
    "network. Do not write an observation or a baseline that treats the gap "
    "as quiet. In the ANSWER: if the thin result is what they actually asked "
    "about, say it in ONE short line naming the gap. If it is not, stay quiet "
    "about it and answer the question they asked."
)


def envelope_for(tool: str, modules: dict) -> dict | None:
    """
    The block execute_tool adds to a result, or None when all is well.

    Kept as data rather than prose glued onto the payload, so the model gets
    the reason and the instruction as separate things, and so the dashboard
    could show the same list later without re-parsing a sentence.
    """
    problems = warnings_for(tool, modules)
    if not problems:
        return None
    return {"degraded": problems, "how_to_read_this": READING_NOTE}
