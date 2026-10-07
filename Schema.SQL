-- AgentalSec V2 -- Complete Database Schema
-- agental_sec.db
-- Model owns: behavioral_session, behavioral_baseline, behavioral_deviation
-- Python owns (read-only for model): everything else

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- PYTHON-OWNED TABLES (model has READ access only)

-- Vantage points. Where an observation was made from.
--
-- Every collector sees a subset of the network decided by where it sits, not
-- by how well it is written. A capture on this host sees this host, plus
-- broadcast and multicast; a switch forwards unicast only to the port it
-- learned the destination MAC on, so traffic between two other devices never
-- reaches this card. That was documented in prose, which meant the model had
-- to take it on trust every time it read a silence.
--
-- can_see and cannot_see are written by Python from core/sensors.py, because
-- they are facts about topology and not judgements about this network. They
-- are stored on the row rather than looked up at read time, so that moving a
-- sensor does not silently rewrite the scope of observations it already made.
CREATE TABLE IF NOT EXISTS sensors (
    sensor_id       TEXT PRIMARY KEY,
    label           TEXT,
    position        TEXT NOT NULL,      -- host, gateway, mirror, inline, resolver, offline
    summary         TEXT,
    can_see         TEXT NOT NULL,
    cannot_see      TEXT NOT NULL,
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes           TEXT
);

-- DNS queries, imported from the network's resolver by tools/dns_monitor.py
--
-- WHY THIS TABLE EXISTS. A destination address identifies almost nothing on
-- the modern internet. Shared hosting and content delivery networks put
-- thousands of unrelated services behind one address on purpose, which is the
-- reason RFC 6066 introduced Server Name Indication, and it is also why
-- command and control is routinely run over Drive, Telegram and GitHub. The
-- name a client asked for is the identity the address is not.
--
-- It is also the only sensor that covers devices nothing can be installed on
-- and that no capture on this host can see, because a device that cannot
-- resolve cannot connect.
--
-- WHAT IT DOES NOT COVER is recorded on the sensor row at position
-- 'resolver': devices using DNS over HTTPS or TLS, devices with a hardcoded
-- public resolver, answers served from the client's own cache, and
-- connections made to a literal address. A missing name here does not mean a
-- missing connection.
--
-- UNTRUSTED. Every domain in this table was chosen by whoever controls the
-- device that asked for it. It is attacker-influenced text, and the query
-- tools are fenced in core/sanitize.py for that reason.
CREATE TABLE IF NOT EXISTS dns_queries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    queried_at      TIMESTAMP NOT NULL,
    client_ip       TEXT,
    domain          TEXT NOT NULL,
    query_type      TEXT,                   -- 'A','AAAA','HTTPS','PTR' etc
    status          TEXT,                   -- the resolver's own verdict
    blocked         INTEGER DEFAULT 0,
    upstream        TEXT,                   -- which resolver answered, when known
    reply_type      TEXT,                   -- 'IP','NXDOMAIN','NODATA','CNAME' etc
    source          TEXT NOT NULL,          -- 'pihole','adguard'
    -- Identity of the row in the source, so a re-import is a no-op rather
    -- than a duplicate. Pi-hole supplies a rowid; AdGuard has none, so a
    -- hash of time, client and name stands in.
    source_row_id   TEXT NOT NULL,
    imported_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sensor_id       TEXT REFERENCES sensors(sensor_id),
    UNIQUE(source, source_row_id)
);

CREATE INDEX IF NOT EXISTS idx_dns_client     ON dns_queries(client_ip, queried_at);
CREATE INDEX IF NOT EXISTS idx_dns_domain     ON dns_queries(domain);
CREATE INDEX IF NOT EXISTS idx_dns_time       ON dns_queries(queried_at);
CREATE INDEX IF NOT EXISTS idx_dns_client_dom ON dns_queries(client_ip, domain);


-- What the first packet of a TLS handshake said, read by tools/tls_hello.py
-- and written from the sniffer. TODO 113.2, v38.
--
-- WHY IT IS AGGREGATED AND NOT ONE ROW PER CONNECTION. A browser opens
-- hundreds of TLS connections an hour, and the packets table already carries
-- one row each. What anybody actually asks is "which domains does this
-- machine talk to" and "has this process ever used a different client
-- fingerprint", both of which are questions about DISTINCT combinations. So
-- the key is the combination and times_seen counts the rest. On the owner's
-- database, one row per connection would have been another table the size of
-- packets; this stays in the low thousands.
--
-- FAILED PARSES ARE STORED TOO, on purpose. A ClientHello that spans two TCP
-- segments cannot be read from one packet, and the count of those is the only
-- honest answer to "is this all of them". Without it the SNI list looks
-- complete and is not. sni_state says which kind of row this is and the
-- model's tool reports the unreadable count separately, never folded in.
CREATE TABLE IF NOT EXISTS tls_hello (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen      TIMESTAMP NOT NULL,
    last_seen       TIMESTAMP NOT NULL,
    times_seen      INTEGER NOT NULL DEFAULT 1,
    src_ip          TEXT NOT NULL,
    dst_ip          TEXT NOT NULL,
    dst_port        INTEGER NOT NULL DEFAULT 0,
    -- '' is not NULL here, deliberately. SQLite lets duplicate NULLs through
    -- a UNIQUE index, so a nullable key column is not a key at all. Same
    -- decision as the '*' wildcard in detection_suppression, v33.
    sni             TEXT NOT NULL DEFAULT '',
    sni_state       TEXT NOT NULL
                    CHECK(sni_state IN ('present','absent','unreadable')),
    ja3             TEXT NOT NULL DEFAULT '',
    ja3_md5         TEXT NOT NULL DEFAULT '',
    alpn            TEXT NOT NULL DEFAULT '',
    legacy_version  TEXT NOT NULL DEFAULT '',
    cipher_count    INTEGER,
    ext_count       INTEGER,
    process_name    TEXT NOT NULL DEFAULT '',
    process_pid     INTEGER,
    -- Only ever set on an unreadable row. It says HOW the read failed, and
    -- it is what stops "we saw no name" and "we could not look" merging.
    parse_reason    TEXT NOT NULL DEFAULT '',
    session_id      TEXT,
    sensor_id       TEXT REFERENCES sensors(sensor_id),
    -- 'quic' when the hello was read out of a QUIC Initial packet (v56).
    transport       TEXT NOT NULL DEFAULT 'tcp',
    UNIQUE(src_ip, dst_ip, dst_port, sni, ja3_md5, process_name, parse_reason)
);

CREATE INDEX IF NOT EXISTS idx_tls_sni     ON tls_hello(sni);
CREATE INDEX IF NOT EXISTS idx_tls_ja3     ON tls_hello(ja3_md5);
CREATE INDEX IF NOT EXISTS idx_tls_dst     ON tls_hello(dst_ip);
CREATE INDEX IF NOT EXISTS idx_tls_seen    ON tls_hello(last_seen);
CREATE INDEX IF NOT EXISTS idx_tls_process ON tls_hello(process_name);


-- What captured DNS replies said each name resolves to (v56). Aggregated like
-- tls_hello: one row per distinct answer, times_seen counts the repeats. It
-- is how a packet's destination address is turned back into the name the
-- host asked for. rrtype 'NXDOMAIN' rows carry no value: the name does not
-- exist, and a burst of those is what generated domain names look like.
CREATE TABLE IF NOT EXISTS dns_answer (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    times_seen  INTEGER NOT NULL DEFAULT 1,
    name        TEXT NOT NULL,
    rrtype      TEXT NOT NULL,
    value       TEXT NOT NULL DEFAULT '',
    ttl         INTEGER,
    client_ip   TEXT NOT NULL DEFAULT '',
    resolver    TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL DEFAULT 'dns',
    sensor_id   TEXT,
    UNIQUE(name, rrtype, value, client_ip, resolver)
);

CREATE INDEX IF NOT EXISTS idx_dns_answer_value ON dns_answer(value);
CREATE INDEX IF NOT EXISTS idx_dns_answer_name  ON dns_answer(name);
CREATE INDEX IF NOT EXISTS idx_dns_answer_seen  ON dns_answer(last_seen);


-- The known-bad indicator lists, pulled by tools/feed_matcher.py. TODO 113.4,
-- v40. Added to this file 2026-09-20: it was in core/migrations only, so a
-- live database had it and a fresh one built from this file did not.
--
-- THE TABLE DOES NOT GROW. A refresh DELETEs that feed's rows and writes the
-- new ones, so the size tracks the live feed rather than the history of
-- everything abuse.ch has ever published. first_added is carried across a
-- refresh in feed_matcher, so "how long has this been listed" survives the
-- row being rewritten; without that, every refresh would reset it to now and
-- the column would quietly mean nothing.
--
-- AN EMPTY TABLE MEANS NO REFRESH HAS SUCCEEDED, NOT THAT NOTHING IS LISTED.
-- That difference is the whole of rule two for this feature: a matcher whose
-- download failed checks every packet against an empty set and reports a
-- beautifully clean network. feed_matcher.status reads the count and refuses
-- to make a claim on zero.
CREATE TABLE IF NOT EXISTS threat_feed (
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL
                    CHECK(indicator_type IN ('ip','domain')),
    feed            TEXT NOT NULL,
    malware_family  TEXT NOT NULL DEFAULT '',
    first_added     TIMESTAMP NOT NULL,
    last_refreshed  TIMESTAMP NOT NULL,
    -- The feed is part of the key. Two feeds listing the same address are two
    -- facts, and collapsing them would make a refresh of one delete the
    -- other's rows.
    PRIMARY KEY (indicator, indicator_type, feed)
);

-- The one index that matters. Every packet, DNS row and TLS row becomes a
-- point query against it, so it is on the hot path rather than for reporting.
CREATE INDEX IF NOT EXISTS idx_threat_feed_lookup
    ON threat_feed(indicator_type, indicator);
CREATE INDEX IF NOT EXISTS idx_threat_feed_feed ON threat_feed(feed);


-- Flushed packet payload, written by tools/payload_ring.py. TODO 113.6, v41.
-- Added to this file 2026-09-20 for the same reason as threat_feed above.
--
-- WHY THIS TABLE IS DIFFERENT FROM EVERY OTHER ONE HERE. The rest hold
-- observations ABOUT traffic: addresses, ports, sizes, times. This one holds
-- the traffic. It is the only place in this database that can contain the
-- user's own plaintext, and it is the ONLY TABLE WITH A RETENTION DEFAULT
-- MEASURED IN DAYS rather than never. Seven, in user_preferences under
-- payload_retention_days, pruned by payload_ring.prune at boot and at
-- shutdown.
--
-- ROWS ARRIVE ONLY TWO WAYS and neither is "always on": a detector fired and
-- flushed the flow that caused it, or the user armed that destination by
-- name. The always-on half of 113.6 is a MEMORY ring that never touches
-- disk. If this table is large, something armed was left armed.
--
-- was_armed IS PER ROW because the armed list changes and a row has to keep
-- the reason it exists.
--
-- AN EMPTY TABLE MEANS NOTHING WAS FLUSHED, NOT THAT NOTHING WAS SEEN. The
-- coverage dict in payload_ring is what tells those apart, and anything
-- reading this table has to carry it.
CREATE TABLE IF NOT EXISTS payload_capture (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    -- When the ring was emptied into here.
    flushed_at      TIMESTAMP NOT NULL,
    -- When the frame was actually on the wire. These differ, and the gap
    -- between them IS the feature: the bytes predate the decision to keep
    -- them, which is the timing hole the ring exists to close.
    captured_at     TIMESTAMP NOT NULL,
    src_ip          TEXT NOT NULL,
    dst_ip          TEXT NOT NULL,
    dst_port        INTEGER NOT NULL DEFAULT 0,
    protocol        TEXT NOT NULL DEFAULT '',
    direction       TEXT NOT NULL DEFAULT '',
    -- Order within one flush, so the conversation can be replayed.
    seq             INTEGER NOT NULL DEFAULT 0,
    data_hex        TEXT NOT NULL,
    was_armed       INTEGER NOT NULL DEFAULT 0,
    trigger_detection_id TEXT NOT NULL DEFAULT '',
    trigger_entity  TEXT NOT NULL DEFAULT ''
);

-- flushed_at first: the prune query runs most often and it is the only query
-- here that has to stay fast on a table nobody is reading.
CREATE INDEX IF NOT EXISTS idx_payload_flushed
    ON payload_capture(flushed_at);
CREATE INDEX IF NOT EXISTS idx_payload_flow
    ON payload_capture(src_ip, dst_ip, dst_port);
CREATE INDEX IF NOT EXISTS idx_payload_trigger
    ON payload_capture(trigger_detection_id);


-- What the router says is on the network, read by tools/router_monitor.py
--
-- WHY THIS TABLE EXISTS. Every other inventory here is built from what this
-- host could reach or overhear. A ping sweep records whoever answered ICMP in
-- the last fraction of a second, which is a different set from whoever is on
-- the network: a device that ignores ICMP, or that was asleep for that
-- fraction of a second, is written down as absent. The router does not have
-- that problem, because it exchanged the traffic itself.
--
-- IT IS NOT A LEASE TABLE, and the difference matters. What is read here is
-- the router's neighbour table, so a device with a static address that is
-- talking appears, and a device holding a lease that is not talking does not.
-- Entries age out. Presence means recent contact; absence means nothing. The
-- sensor row at position 'gateway_api' carries this, so the model reads it as
-- data rather than being told it in prose.
--
-- CURRENT STATE, NOT A LOG. One row per (router, address, hardware address),
-- upserted. A collection that finds nothing new writes no rows, only a
-- last_seen touch. Change is carried by a finding raised at the moment it is
-- detected, because a collector on a timer that grows the database every tick
-- is a collector that gets switched off.
--
-- UNTRUSTED. A hostname here was chosen by whoever controls the device that
-- presented it, exactly like a domain in dns_queries, and is fenced the same
-- way. It is a self-report and never on its own an identification.
CREATE TABLE IF NOT EXISTS router_clients (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    router_host  TEXT NOT NULL,          -- which router reported this
    ip           TEXT NOT NULL,
    mac          TEXT,
    hostname     TEXT,                   -- self-reported by the device, if any
    vendor       TEXT,                   -- from the MAC prefix; a prior, not an identity
    interface    TEXT,                   -- the router interface it was seen on
    entry_type   TEXT,                   -- 'dynamic','static','other','invalid'
    source       TEXT NOT NULL,          -- e.g. 'snmp:ipNetToMediaTable'
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sensor_id    TEXT REFERENCES sensors(sensor_id)
);

-- An expression index rather than a table constraint, because SQLite treats
-- two NULLs as distinct inside UNIQUE. A neighbour table row essentially
-- always carries a hardware address, but "essentially always" is how a table
-- quietly gains one duplicate per collection on the one router that omits it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_router_clients_key
    ON router_clients(router_host, ip, COALESCE(mac,''));

CREATE INDEX IF NOT EXISTS idx_router_clients_ip   ON router_clients(ip);
CREATE INDEX IF NOT EXISTS idx_router_clients_mac  ON router_clients(mac);
CREATE INDEX IF NOT EXISTS idx_router_clients_seen ON router_clients(last_seen);

-- The router's own settings, as the router reports them
--
-- The gateway is the one device on the network whose compromise defeats this
-- tool rather than merely evading it. Change the addresses handed out by DHCP
-- and the resolver sensor is reading a resolver nothing uses; open a port
-- inward and no sensor at position 'host' can see it. So the router is worth
-- watching as an entity, not only querying as a source.
--
-- NO SEVERITY IS ASSIGNED HERE, and that is deliberate. "A listener bound to
-- every interface is critical" is a judgement written once into Python that
-- no evidence can revise, which is the failure PORT_PROFILES and STATIC-001
-- are the standing reminders of. What Python records is that a value CHANGED
-- from the one previously recorded, which is a measurement against a stored
-- prior rather than an opinion about what the value means.
--
-- `present` is why a setting that DISAPPEARS is still visible. A listener
-- that stops listening is drift in the same way a new one is, and a row that
-- simply stopped being written would read as though nothing had happened.
CREATE TABLE IF NOT EXISTS router_config (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    router_host    TEXT NOT NULL,
    setting        TEXT NOT NULL,        -- e.g. 'sysDescr', 'listener:tcp:80'
    value          TEXT,
    detail         TEXT,                 -- JSON extras for this setting
    previous_value TEXT,                 -- what it held before it last changed
    present        INTEGER DEFAULT 1,    -- 0 once the router stops reporting it
    source         TEXT NOT NULL,
    first_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    changed_at     TIMESTAMP,
    sensor_id      TEXT REFERENCES sensors(sensor_id),
    UNIQUE(router_host, setting)
);

CREATE INDEX IF NOT EXISTS idx_router_config_changed ON router_config(changed_at);

-- Raw captured packets from packet_sniffer.py
CREATE TABLE IF NOT EXISTS packets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    captured_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    direction       TEXT CHECK(direction IN ('inbound','outbound','internal')),
    -- Precise address classification, added v10. direction is the coarse
    -- three-value answer the CHECK above allows; scope is what the packet
    -- actually is. The two are separate because direction's 'internal' used
    -- to double as the fallthrough for anything unclassifiable, so a public
    -- source sending to a multicast group was filed under the same name as
    -- ordinary LAN chatter and was read that way.
    --
    -- Values: private_to_private, outbound, inbound, local_multicast,
    -- foreign_multicast, broadcast, loopback, public_to_public, unclassified.
    -- Assigned in tools/packet_sniffer.py:classify_scope.
    --
    -- Deliberately UNCONSTRAINED. A new scope name must not require rebuilding
    -- this table, which is most of the database. The lesson of the column
    -- above is that a CHECK on a vocabulary that turns out to be incomplete
    -- pushes the incompleteness into a fallthrough value instead.
    scope           TEXT,
    packet_size     INTEGER,
    flags           TEXT,                   -- TCP flags JSON, plus ICMP type/code
    -- First 256 bytes, as hex, and ONLY when threat_label is set. NULL here
    -- means nothing was flagged on this row, NOT that a payload was
    -- unavailable. Written that way since 2026-09-01: it was 566.7 MB across
    -- 1.3 million rows of which 242 were flagged. See TODO 34.
    payload_snippet TEXT,
    threat_label    TEXT,                   -- 'dangerous_port','beaconing','volume','signature' etc
    vpn_state       TEXT DEFAULT 'unknown' CHECK(vpn_state IN ('connected','disconnected','unknown')),
    -- raw_summary was here and was RETIRED 2026-09-01. It held scapy's
    -- summary() line, which is rebuilt from src_ip, dst_ip, protocol and
    -- flags, all of them columns above. 124.0 MB on the real database and no
    -- reader anywhere. A database created before that date still HAS the
    -- column, holding old values, until scripts/reclaim_packet_space.py drops
    -- it. Nothing reads it in either case, so the two shapes behave the same.
    -- Which LOCAL process owns the socket this packet belongs to. Attributed
    -- at capture time from the OS connection table, see the ConnCache in
    -- tools/packet_sniffer.py. NULL means NOT ATTRIBUTED, never "no process":
    -- the packet had no local endpoint (traffic between other devices seen on
    -- a mirror), the owning socket opened and closed between two poll ticks,
    -- or psutil was unavailable. Same NULL-is-unknown rule as scope.
    process_name    TEXT,
    process_pid     INTEGER,
    sensor_id       TEXT REFERENCES sensors(sensor_id)   -- vantage point; see sensors table
);

CREATE INDEX IF NOT EXISTS idx_packets_session    ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_packets_src        ON packets(src_ip, captured_at);
CREATE INDEX IF NOT EXISTS idx_packets_dst        ON packets(dst_ip, captured_at);
CREATE INDEX IF NOT EXISTS idx_packets_port       ON packets(dst_port);
CREATE INDEX IF NOT EXISTS idx_packets_time       ON packets(captured_at);
-- ADDED TO THIS FILE 2026-09-21, WITH THE SCHEMA PORT. Both of these were
-- created by core/migrations._migrate_sensor_vantage and listed nowhere in
-- Schema.SQL, so every database that had ever been MIGRATED carried them and
-- every database built FRESH from this file did not. Measured before the fix:
-- the migrated copy of the live database reported 91 indexes, a fresh build
-- from this file reported 89, and these two were the whole difference.
--
-- The Windows tree hit this exact shape on 2026-09-20 with threat_feed and
-- wrote the lesson into that table's comment: a table that is in migrations
-- only is a table a live database has and a fresh install does not. It is the
-- same class of bug as a feature that works on the developer's machine.
--
-- These are the sensor attribution indexes. Without them every "what did this
-- sensor see" query full-scans the two largest tables in the database.
CREATE INDEX IF NOT EXISTS idx_packets_sensor     ON packets(sensor_id);

-- Security findings from all monitors
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    found_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source          TEXT,                   -- 'packet_sniffer','event_monitor','process_monitor' etc
    severity        TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    entity_type     TEXT,                   -- 'ip','process','port','user'
    entity_value    TEXT,                   -- the IP, process name, etc
    title           TEXT NOT NULL,
    description     TEXT,
    raw_data        TEXT,                   -- JSON blob of supporting evidence
    vpn_state       TEXT DEFAULT 'unknown',
    dismissed       INTEGER DEFAULT 0,
    dismissed_at    TIMESTAMP,
    dismissed_reason TEXT,
    sensor_id       TEXT REFERENCES sensors(sensor_id),  -- vantage point; see sensors table
    -- TODO 81/84, 2026-09-09. Findings that matter, kept HERE rather than in
    -- a table of their own, and that is the whole design.
    --
    -- A separate table would be a COPY, and a copy goes stale the moment the
    -- rule that raised the original gets fixed. Seventeen false masquerading
    -- findings on 2026-09-08 are the proof: fixing the rule did nothing for
    -- rows already written. Promotion living on the finding means a finding
    -- that is dismissed, cleared or resolved takes its promotion with it,
    -- with no second thing to remember to clean.
    --
    -- nominated_* is the MODEL raising its hand. promoted is the USER
    -- agreeing. The model can never write promoted, which is why they are
    -- two sets of columns and not one.
    nominated_at     TIMESTAMP,
    nominated_by     TEXT,                   -- 'model' or 'user'
    nominated_reason TEXT,
    promoted         INTEGER DEFAULT 0,
    promoted_at      TIMESTAMP,
    promoted_reason  TEXT,
    -- TODO 112, 2026-09-15. WHICH RULE FIRED, borrowed from Snort's sid/rev.
    --
    -- Before this, the only things saying what a row WAS were `source` and
    -- `title`, and title is prose with the subject baked into it. That is why
    -- clear_port_findings has to match "192.0.2.124:8888" as a substring, and
    -- why rewording a title re-raises every finding it had already dedup'd.
    --
    -- detection_id resolves against core/detections.DETECTIONS and is stable
    -- for the life of the detection. detection_rev is the register's rev AT
    -- THE MOMENT THIS ROW WAS RAISED, copied rather than looked up later, so
    -- "why did this fire in August and not now" survives the rule changing.
    --
    -- NULL means RAISED BEFORE THIS EXISTED, not "unknown rule". Nothing
    -- backfills it: the old rows record their detection only as a sentence,
    -- and guessing which rule wrote a sentence is inference, not a lookup.
    -- scripts/detection_report.py shows what a backfill WOULD match, read
    -- only, so the choice stays with a human.
    detection_id     TEXT,
    detection_rev    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_findings_detection
    ON findings(detection_id);

-- TODO 112. Silence ONE detection, optionally on ONE entity.
--
-- The thing dismissed_findings could never do. That table is keyed on the
-- entity, so quieting one noisy rule about 192.0.2.124 silences every rule
-- about 192.0.2.124, which is not tuning, it is turning a device off. Both
-- mechanisms stay: this one is the scalpel, dismiss_entity is still the
-- blunt instrument, and they are checked separately so a reader can always
-- tell which one silenced something.
--
-- entity_value '*' MEANS EVERY ENTITY, AND IT IS A LITERAL STRING ON PURPOSE.
-- NULL would read better and would not work: in SQLite two NULLs are not
-- equal to each other, so a UNIQUE index over columns containing NULL does
-- not stop duplicates at all, and "silence PKT-1001 everywhere" could be
-- inserted a hundred times over with nothing complaining.
--
-- expires_at NULL means no expiry. A suppression is a standing decision, so
-- unlike an operator question it does not retire itself by default.
CREATE TABLE IF NOT EXISTS detection_suppression (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id  TEXT NOT NULL,
    entity_type   TEXT NOT NULL DEFAULT '*',
    entity_value  TEXT NOT NULL DEFAULT '*',
    reason        TEXT NOT NULL,
    created_by    TEXT NOT NULL DEFAULT 'user'
                  CHECK(created_by IS NULL OR created_by IN ('user','model')),
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP,
    UNIQUE(detection_id, entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_suppression_detection
    ON detection_suppression(detection_id);

CREATE INDEX IF NOT EXISTS idx_findings_session   ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_entity    ON findings(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity, found_at);
CREATE INDEX IF NOT EXISTS idx_findings_dismissed ON findings(dismissed);
CREATE INDEX IF NOT EXISTS idx_findings_promoted  ON findings(promoted, dismissed);
CREATE INDEX IF NOT EXISTS idx_findings_nominated ON findings(nominated_at);
-- See the note on idx_packets_sensor. Created by migrations, absent from this
-- file until 2026-09-21, so migrated databases had it and fresh ones did not.
CREATE INDEX IF NOT EXISTS idx_findings_sensor    ON findings(sensor_id);

-- Windows/Linux security events
-- source_record_id, v21, 2026-08-31. The id the SOURCE gave a record, so the
-- same record cannot become two rows.
--
-- EventMonitor reads the Windows log newest first and only advances its
-- high-water mark when the walk reaches known ground. When a burst caps a pass
-- the mark deliberately does not move, because a skipped 4720 is gone for good
-- and a re-read one is not. The price is that the newest records are read
-- again on the next poll, and they were being stored again as well. Nobody
-- notices duplicate rows directly, they notice a baseline built on counts that
-- are too high.
--
-- NULL for any source with no id of its own. NULLs are distinct in a SQLite
-- unique index, so old rows and other sources are untouched by the index
-- below.
--
-- Kept out here rather than inside the CREATE TABLE on purpose: a comment
-- block containing a bare double-dash line inside a table definition stops
-- SQLite re-parsing the stored DDL, and ALTER TABLE DROP COLUMN on that table
-- then fails. Learned the hard way on this very column.
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    occurred_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source          TEXT,                   -- 'windows_event_log','linux_auth','process_monitor'
    event_id        TEXT,                   -- '4625','4624','4720' etc
    event_type      TEXT,                   -- 'failed_login','account_created','process_launch' etc
    username        TEXT,
    src_ip          TEXT,
    process_name    TEXT,
    description     TEXT,
    raw_data        TEXT,                   -- JSON
    severity        TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    vpn_state       TEXT DEFAULT 'unknown',
    sensor_id       TEXT REFERENCES sensors(sensor_id),  -- vantage point; see sensors table
    source_record_id INTEGER          -- id the source gave it, see above
);

CREATE INDEX IF NOT EXISTS idx_events_session     ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type        ON events(event_type, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_user        ON events(username);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_record
    ON events(source, source_record_id);
-- ADDED TO THIS FILE 2026-09-25, WITH THE TIMELINE ROUND (TN-1). Every other
-- index on this table leads with a column the reader filters BY, and the
-- Timeline does not filter by anything: it asks for the newest rows inside a
-- time window, which is a range scan on occurred_at alone. Without this index
-- that one read was a full scan of a 725,000 row table on every page load.
--
-- MEASURED ON A COPY OF THE LIVE STORE, and the copy matters: a plain `cp` of
-- a database with a live writer is an inconsistent image, and reading one
-- answers "database disk image is malformed", which is what happened first.
-- sqlite3's own backup API takes a correct copy.
--
--     200 newest events in a 2h window, no index   1.765 s
--     the same read WITH this index                0.002 s
--     count of the same window, no index            0.333 s
--     count WITH this index                         0.001 s
--
-- The build cost 3.3 s on the 1.1 GB copy, so on the owner's real store it is
-- a few seconds once, during a migration, and never again.
CREATE INDEX IF NOT EXISTS idx_events_time
    ON events(occurred_at);

-- Port scan results
CREATE TABLE IF NOT EXISTS port_scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    scanned_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    target_host     TEXT NOT NULL,
    port            INTEGER NOT NULL,
    state           TEXT CHECK(state IN ('open','closed','filtered')),
    service_guess   TEXT,
    -- NOT A BANNER. Nothing here is ever read off the wire.
    --
    -- _check_port does a bare connect and closes. It never receives a byte,
    -- so no service on this network has ever told this tool what it is. This
    -- column held the PROFILE NOTE, which is prose a human wrote about that
    -- port number in general, stored under a name that asserts observation.
    --
    -- The model read it as one. Port 8888 open on a smart speaker became "a
    -- Jupyter-style banner a stock Echo should not serve", and the Jupyter
    -- came from the profile table, not from the device. A false finding on a
    -- real network, produced by a column name.
    --
    -- banner stays for old rows and is never written again. service_note is
    -- where the annotation goes, named for what it is.
    banner          TEXT,
    service_note    TEXT,
    risk_level      TEXT CHECK(risk_level IN ('critical','high','medium','low','none')),

    -- WHICH PROTOCOL. v34, 2026-09-15.
    --
    -- Every row in this table before v34 came from a TCP connect, because
    -- _check_port is the only thing that has ever written here and it calls
    -- socket.create_connection. The scanner knew that at scan time and did not
    -- write it down, so a row said "port 500 open" and a reader had to assume
    -- which protocol that meant. "port 8888" and "8888/tcp" are not the same
    -- claim, and the second one is the one we can actually support.
    --
    -- The v34 migration defaults old rows to 'tcp'. That is not a guess: TCP
    -- is the only thing this codebase has ever probed.
    protocol        TEXT NOT NULL DEFAULT 'tcp' CHECK(protocol IN ('tcp','udp')),

    -- 'self'   = the scanner ran on the target, so this proves the service is
    --            BOUND, not that anything else can reach it. Windows does not
    --            filter traffic that never leaves the host.
    -- 'remote' = scanned across the network, so it does measure reachability.
    -- Without this column both look identical in the Ports tab, which is how
    -- an open 445 on the tool's own machine read as critical exposure.
    scan_origin     TEXT DEFAULT 'remote' CHECK(scan_origin IN ('self','remote')),
    sensor_id       TEXT REFERENCES sensors(sensor_id)   -- vantage point; see sensors table
);

-- One row per port scan RUN, as opposed to one row per open port found.
--
-- WHY THIS EXISTS, 2026-09-02. The model scanned a device, then queried the
-- packet table, saw the scan's own return traffic, and reported to the owner
-- that the device was "actively probing THIS host's ports 27017 and 32400".
-- Source port 27017 to an ephemeral port is the scanned device answering with
-- RST because the port is closed. It read the reply leg of its own scan as
-- unsolicited hostile activity and escalated on it.
--
-- port_scan_results could not answer "was there a scan running then", because
-- it only holds ports that were OPEN. A scan that found nothing leaves no
-- trace at all, and those are exactly the scans that generate the most
-- refused-connection traffic. So the RUN gets recorded, separately from what
-- it found.
--
-- query_packets joins this to stamp self_induced on rows this tool caused.
-- See TODO 37.2.
CREATE TABLE IF NOT EXISTS port_scan_run (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    target_host     TEXT NOT NULL,
    started_at      TIMESTAMP NOT NULL,
    -- NULL means the scan is still running, or died without finishing. Not
    -- the same as finishing instantly, and a reader must not treat it as a
    -- zero length window. The join below uses a fallback for exactly this.
    finished_at     TIMESTAMP,
    port_count      INTEGER,
    port_set        TEXT,
    -- Which protocols this RUN actually probed, comma separated. 'tcp' today.
    -- A run that only spoke TCP must not be quotable as evidence about UDP,
    -- and without this column the run row could not tell the difference.
    protocols       TEXT DEFAULT 'tcp',
    scan_origin     TEXT DEFAULT 'remote' CHECK(scan_origin IN ('self','remote')),
    sensor_id       TEXT REFERENCES sensors(sensor_id)
);

CREATE INDEX IF NOT EXISTS idx_scan_run_target ON port_scan_run(target_host, started_at);
CREATE INDEX IF NOT EXISTS idx_scan_run_time   ON port_scan_run(started_at);

CREATE INDEX IF NOT EXISTS idx_ports_session      ON port_scan_results(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_host         ON port_scan_results(target_host, port);

-- Network device inventory
-- expected_always_on, v22, 2026-09-01. MEMBERSHIP AND AVAILABILITY ARE TWO
-- DIFFERENT DECLARATIONS AND THEY WERE SHARING ONE COLUMN.
--
-- is_permanent meant "this device belongs on this network". The absence check
-- read it as "this device should always be answering", and raised a medium
-- finding whenever a permanent device went quiet.
--
-- The owner corrected that: permanent means it is part of the inventory, not
-- that it is powered on. A TV, a console or a VM sits dark for days because
-- nobody is using it, and that is the ordinary case rather than an event.
--
-- So availability gets its own column. is_permanent keeps meaning membership,
-- and only expected_always_on licenses the absence finding. Splitting them is
-- the honest fix, because merging two declarations into one flag meant every
-- device the user vouched for silently also promised to stay awake.
CREATE TABLE IF NOT EXISTS known_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT NOT NULL,
    mac             TEXT,
    vendor          TEXT,
    hostname        TEXT,
    known_as        TEXT,                   -- assigned label, e.g. 'living room TV'
    device_type     TEXT,                   -- 'router','laptop','phone','tv','iot' etc
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes           TEXT,

    -- expected_always_on, v22, 2026-09-01. See the block above this table.
    expected_always_on INTEGER DEFAULT 0,

    -- WHO SAID SO, AND ON WHAT BASIS
    --
    -- An identification with no source is a guess promoted to a fact by being
    -- written down. The agent once decided a device was a games console
    -- because the user mentioned owning one, then backed it with a service
    -- record belonging to an entirely different vendor. Nothing in the row
    -- said which part was evidence and which was suggestion.
    --
    -- identified_by is 'user' or 'model'. evidence is the observation the
    -- label rests on, in the identifier's own words, and is required.
    identified_by   TEXT,
    evidence        TEXT,
    identified_at   TIMESTAMP,
    sensor_id       TEXT REFERENCES sensors(sensor_id),  -- vantage point; see sensors table

    -- PERMANENCE AND DRIFT (schema v13)
    --
    -- is_permanent means the USER has said this device is supposed to be on
    -- the network at all times. It is the flag that turns absence into a
    -- question, because absence only means something for a device that is
    -- meant to be there. A phone leaving is a phone leaving.
    --
    -- WRITABLE BY THE USER ONLY. There is no tool that sets it, at any
    -- privilege, and identify_device deliberately does not touch it. Naming a
    -- device and vouching for it are different acts, and the model is allowed
    -- to do the first. A model that could mark a device permanent could
    -- quieten the absence signal for the one device an attacker cares about,
    -- and it could do so through a description it read in a packet.
    is_permanent    INTEGER DEFAULT 0,
    permanence_set_by   TEXT,        -- 'user'. Nothing else is ever written.
    permanence_set_at   TIMESTAMP,

    -- What this device LOOKED LIKE when it was enrolled, as JSON.
    --
    -- known_as records what a device IS. This records what it looked like,
    -- which is the only thing a later observation can be compared against.
    -- Without it, "known does not mean safe" is an instruction with no
    -- evidence behind it: the model can be perfectly suspicious of a trusted
    -- device and have nothing to be suspicious WITH, because there is no
    -- recorded starting point for it to have drifted from.
    --
    -- Contents are only what this tool actually observes. See
    -- memory_engine.build_device_fingerprint for the exact shape and for why
    -- there is no OS field: nothing here fingerprints a remote operating
    -- system, and a column that is always null is a claim the tool cannot
    -- support.
    enrollment_fingerprint      TEXT,
    enrollment_fingerprint_at   TIMESTAMP,

    -- IDENTITY MERGE (schema v14)
    --
    -- This table is keyed on IP, so one physical device collects a new row
    -- every time it takes a different lease. A phone that randomizes its
    -- hardware address looks like a new client to the DHCP server each time
    -- it rotates, so it takes a new lease routinely, and the review queue
    -- fills with the same handset wearing different addresses.
    --
    -- merged_into points at the canonical row for the same physical device.
    -- The canonical row has merged_into NULL. Chains are impossible by
    -- construction: merge_devices resolves the target to its root first, so
    -- every merged row points directly at a root.
    --
    -- WRITABLE BY THE USER ONLY, for the same reason as is_permanent above
    -- and one more. Merging is a claim that two observations are one device,
    -- and a model that could merge could fold an intruder's row into the
    -- printer's identity and take it out of the review queue entirely. That
    -- is the blinding attack with a filing cabinet.
    --
    -- Rows are never deleted by a merge. A merge is a claim and claims get
    -- revised, so the row and its history survive and unmerge_device puts it
    -- back.
    merged_into     INTEGER REFERENCES known_devices(id),
    merged_at       TIMESTAMP,
    merged_by       TEXT,        -- 'user'. Nothing else is ever written.
    -- What the merge moved to the target (JSON), so unmerge can give it back.
    merge_carried   TEXT,

    -- RETIREMENT (schema v15)
    --
    -- A permanent device that has genuinely gone -- the printer was thrown
    -- out -- would otherwise report missing on every sweep, forever. After a
    -- few days of that the user stops reading absence alerts, and the whole
    -- mechanism is dead: not broken, ignored, which is worse because it still
    -- looks like it is working.
    --
    -- So after N consecutive misses the probe clears is_permanent and stamps
    -- these. The transition is shown ONCE.
    --
    -- retired_at is what distinguishes this from the user un-vouching by
    -- hand: both leave is_permanent at 0, and permanence_set_by still records
    -- who last vouched, which is worth keeping.
    --
    -- The row is never deleted and the fingerprint is never cleared. If the
    -- printer comes back, everything needed to recognise it is still here.
    retired_at      TIMESTAMP,
    retired_reason  TEXT,

    -- v50, 2026-09-24. AND SOMETHING HAS TO RECOGNISE IT. "Everything needed
    -- to recognise it is still here" was true of the DATA and not of the
    -- CODE: retired_at was written by retire_device and cleared by nothing,
    -- and three readers filter on it (permanent_devices, always_on_devices,
    -- and the scanner's own is_new test). So a device that came back was in
    -- the inventory, watched by nothing, on a row saying it is gone.
    --
    -- These are where the retirement GOES when it is lifted. Clearing
    -- retired_at alone would delete the evidence that the device ever left,
    -- and that evidence is the thing a reader wants after it comes back
    -- twice. Written by memory_engine.reacknowledge_device, which restores
    -- NEITHER is_permanent NOR expected_always_on: a device answering a probe
    -- is not the operator declaring it should always be there.
    unretired_at     TIMESTAMP,
    unretired_reason TEXT,

    -- PORTS THE OWNER HAS SAID ARE NORMAL FOR THIS DEVICE (schema v24).
    --
    -- JSON, keyed by port number:
    --   {"8888": {"declared_at": "...", "declared_by": "user",
    --             "reason": "Echo devices listen here"}}
    --
    -- WHY THIS EXISTS. The owner identified a device, told the tool it was
    -- his, and the open-port finding stayed high anyway, because naming a
    -- device says nothing about which of its ports are normal. So the tool
    -- asked about the same port three times in a row. A tool that keeps
    -- asking a question you already answered is one you stop reading, which
    -- is the same failure as the unread review queue in 4A.
    --
    -- dismiss_entity could not do this job. It is keyed on
    -- (entity_type, entity_value), so dismissing port 8888 silences 8888 on
    -- EVERY device on the network. This is one port on one device.
    --
    -- IT SILENCES THE FINDING, NOT THE OBSERVATION. The port still appears in
    -- port_scan_results and in this row. A different port on the same device
    -- still raises. The port closing is still visible. Same rule the owner
    -- set for the safe list on 2026-08-31: it silences one specific alert and
    -- everything else about the device still applies.
    --
    -- THE MODEL CANNOT WRITE THIS. There is no tool for it, deliberately.
    -- A model that can mark its own findings expected has a silencing path,
    -- which is 8.1F one layer over. Written by scripts/expect_port.py only.
    expected_ports  TEXT,

    UNIQUE(ip)
);

-- ,,,,,,,,,,,,,,,,,,,,
-- PROBE RUNS (schema v15)
-- ,,,,,,,,,,,,,,,,,,,,
--
-- One row per pass of the fingerprint probe. Same shape and same reasoning as
-- presence_sweep: a pass that could not run is recorded as FAILED, never
-- silently absent, because a stretch where the probe was broken must not be
-- indistinguishable from a stretch where nothing changed.
--
-- Separate from presence_sweep because they are separate cadences doing
-- separate jobs. Presence is cheap and frequent and answers "is it there".
-- This is expensive and rare and answers "is it still the same thing".
-- Collapsing them was the first design error caught in review; keeping the
-- records apart is what stops them being collapsed again by accident.
CREATE TABLE IF NOT EXISTS probe_run (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT NOT NULL,
    started_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at      TIMESTAMP,

    outcome          TEXT NOT NULL CHECK(outcome IN ('ok','failed','skipped')),
    -- 'skipped' is not a failure and not a success. It is the ordinary case:
    -- the cadence has not elapsed. Recorded so that "the probe has not run in
    -- five weeks" is answerable.
    detail           TEXT,

    eligible         INTEGER DEFAULT 0,  -- permanent devices in scope
    probed           INTEGER DEFAULT 0,  -- actually fingerprinted this pass
    excluded         INTEGER DEFAULT 0,  -- refused by the exclusion list
    deferred         INTEGER DEFAULT 0,  -- left for next pass by the rate limit
    drift_found      INTEGER DEFAULT 0,
    retired          INTEGER DEFAULT 0,

    sensor_id        TEXT REFERENCES sensors(sensor_id)
);

CREATE INDEX IF NOT EXISTS idx_probe_run_time
    ON probe_run(started_at);
CREATE INDEX IF NOT EXISTS idx_probe_run_outcome
    ON probe_run(outcome, started_at);

CREATE INDEX IF NOT EXISTS idx_known_devices_merged
    ON known_devices(merged_into);

-- CISA KEV + static runbook entries
CREATE TABLE IF NOT EXISTS runbook (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT,
    vendor          TEXT,
    product         TEXT,
    vulnerability   TEXT,
    description     TEXT,
    remediation     TEXT,
    date_added      TEXT,
    due_date        TEXT,
    known_ports     TEXT,                   -- JSON: [445, 3389] etc
    severity        TEXT,
    source          TEXT DEFAULT 'static',  -- 'static' or 'cisa_kev'

    -- A port match is not a vulnerability match. Without these three
    -- columns the STATIC-001 row read as "SMB on 445 = critical
    -- EternalBlue", and the model reported exactly that against a Windows
    -- 11 host, where MS17-010 was patched in 2017 and SMBv1 is not even
    -- installed. The model was right to trust the table; the table was wrong.
    entry_kind      TEXT DEFAULT 'vulnerability',
                    -- 'vulnerability' = a real CVE, only on affected versions
                    -- 'exposure'      = a port worth noticing, not a defect
    applies_to      TEXT,                   -- which versions are actually affected
    verify_hint     TEXT,                   -- what to establish before alerting

    -- The CISA feed publishes no CVSS, so `severity` above is only ever what
    -- the feed itself states, which is 'unknown' unless it flags ransomware
    -- use. A rating fetched from a source that does publish one is a
    -- different claim from a different place, so it lives in its own columns
    -- and never overwrites the first.
    --
    -- cvss_state is the important one:
    --   NULL        nobody has looked yet
    --   'ok'        a source answered with a score
    --   'no_score'  the record exists upstream and carries no base score
    --   'not_found' the sources answered and have no record of this CVE
    --   'error'     we could not ask, or no answer arrived
    -- Four outcomes, four names. "Nothing found" and "could not look" are
    -- different sentences and the column must keep them apart.
    cvss_score      REAL,
    cvss_severity   TEXT,                   -- critical / high / medium / low, as published
    cvss_vector     TEXT,                   -- so the score can be argued with
    cvss_source     TEXT,                   -- who answered
    cvss_state      TEXT,
    cvss_note       TEXT,                   -- why, whenever the state is not 'ok'
    cvss_checked_at TEXT,                   -- stamped on EVERY attempt, empty ones included

    -- knownRansomwareCampaignUse, the one severity-ish signal the feed does
    -- carry. Kept as itself so a row can show why it was rated.
    ransomware_use  TEXT,
    UNIQUE(cve_id)
);

CREATE INDEX IF NOT EXISTS idx_runbook_cve        ON runbook(cve_id);

-- Dismissed entities (IPs/ports/processes user has explicitly cleared)
CREATE TABLE IF NOT EXISTS dismissed_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dismissed_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    entity_type     TEXT,
    entity_value    TEXT,
    reason          TEXT,
    dismissed_by    TEXT DEFAULT 'user',    -- 'user' or 'model'
    UNIQUE(entity_type, entity_value)
);

-- User preferences
CREATE TABLE IF NOT EXISTS user_preferences (
    key             TEXT PRIMARY KEY,
    value           TEXT,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Session log (rolling cap via trigger)
CREATE TABLE IF NOT EXISTS session_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    logged_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    role            TEXT CHECK(role IN ('user','assistant','system')),
    content         TEXT,
    token_count     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_session_log_sid    ON session_log(session_id, logged_at);

-- Rolling cap: keep last 500 entries per session
CREATE TRIGGER IF NOT EXISTS trim_session_log
AFTER INSERT ON session_log
BEGIN
    DELETE FROM session_log
    WHERE id IN (
        SELECT id FROM session_log
        WHERE session_id = NEW.session_id
        ORDER BY id DESC
        LIMIT -1 OFFSET 500
    );
END;

-- PCAP analysis results cache
CREATE TABLE IF NOT EXISTS pcap_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    analyzed_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_path       TEXT NOT NULL,
    packet_count    INTEGER,
    duration_seconds REAL,
    result_json     TEXT,                   -- full structured result from pcap_analyzer
    model_assessment TEXT,  -- model writes its narrative here after reading result_json
    sensor_id       TEXT REFERENCES sensors(sensor_id)   -- vantage point; see sensors table
);

-- MODEL-OWNED TABLES (model has READ + WRITE access)
-- Python has read access for rollup coordination only

-- SESSION TIER: raw behavioral observations for the current session
CREATE TABLE IF NOT EXISTS behavioral_session (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    observed_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    entity_type     TEXT NOT NULL CHECK(entity_type IN ('ip','process','port','user')),
    entity_value    TEXT NOT NULL,
    behavior_key    TEXT NOT NULL,
    -- Valid keys for 'ip':      beacon_interval, beacon_destinations, connection_count,
    --                           avg_packet_size, active_hours, open_ports_inbound,
    --                           open_ports_outbound, typical_dest_ports, typical_dest_ips,
    --                           volume_per_session, first_seen, user_action_history
    -- Valid keys for 'process': typical_parent, typical_network_ports, typical_paths,
    --                           spawn_frequency, user_action_history
    -- Valid keys for 'port':    typical_process, open_frequency, typical_direction,
    --                           last_seen_open
    -- Valid keys for 'user':    login_hours, login_sources, typical_processes,
    --                           failed_login_count, user_action_history
    behavior_value  TEXT NOT NULL,          -- scalar or JSON blob
    context         TEXT,                   -- model's own reasoning about why it noted this
    written_by      TEXT DEFAULT 'model' CHECK(written_by IN ('model','system')),

    -- WITHDRAWN OBSERVATIONS
    --
    -- This log is append-only, and that is right: it records what the agent
    -- believed and when, and deleting from it destroys the evidence that a
    -- mistake happened. But append-only with no linkage means a wrong
    -- observation and its correction sit as equal rows, and whether the
    -- correction wins depends on the next reader noticing both.
    --
    -- superseded_by points at the observation that replaced this one, or -1
    -- when it was withdrawn without a replacement. A withdrawn row is
    -- excluded from query_behavioral_session by default, and the COUNT of
    -- what was hidden is always reported, so this can never be silent.
    superseded_by     INTEGER,
    superseded_reason TEXT,
    sensor_id       TEXT REFERENCES sensors(sensor_id),  -- vantage point; see sensors table

    -- PROVENANCE OF THE EVIDENCE (v17)
    --
    -- The slow-poisoning attack: crafted text is fed to a sensor over weeks,
    -- the model reads it and writes observations establishing that something
    -- is normal, those observations become a baseline, and the baseline
    -- justifies suppression. Every step is individually reasonable. What was
    -- missing is that by the last step nothing recorded that the FIRST step
    -- was attacker-controlled -- the provenance was destroyed in the middle.
    --
    -- Gating the write does not help: this tool is meant to be called
    -- constantly and a permission card on it gets clicked through. Capping
    -- does not help either: three observations a week for two months sits
    -- under any tolerable cap. The control has to be provenance, not volume.
    --
    -- agent_loop already knows which tool results came back untrusted; it
    -- fences them and used to discard the fact. These two columns keep it.
    evidence_untrusted INTEGER DEFAULT 0,  -- 1 = written while reading fenced content
    evidence_sources   TEXT,               -- which tool results were in context

    -- BASIS. v26, 2026-09-02. WHAT KIND OF THING IS THIS ROW.
    --
    -- Three very different claims used to land in this table looking
    -- identical, and telling them apart is the whole point:
    --
    --   measured          this tool watched it happen on this network
    --   external_intel    somebody else's database said so. Dated, expires.
    --   model_conclusion  a model reasoned to it. Nothing else backs it.
    --
    -- The argument that produced it, both halves. The owner is right that
    -- enrichment facts BELONG here: a model that re-looks-up the same address
    -- every session is the waste the enrichment engine exists to stop, and not
    -- logging is worse than logging. What survives from the other side is only
    -- about which column: an enrichment fact written bare loses the TTL, the
    -- source URLs and the status that made it checkable, and six months on it
    -- is a permanent measured fact that nothing re-checks.
    --
    -- model_conclusion came from a different row the same afternoon. The model
    -- concluded the packet recorder had a byte-order bug and wrote it here. It
    -- is wrong; src comes straight out of scapy. Unmarked, the next session
    -- reads that as something this tool MEASURED.
    --
    -- NULL means the row predates v26 and the question was never asked. That
    -- is 'unrecorded', and it is never counted as measured.
    --
    -- operator_stated, v32, 2026-09-14. The FOURTH kind, and it is none of the
    -- other three. The owner answered a question the tool could not answer
    -- itself: "that address is my work laptop", "yes I changed the router
    -- setting". Nothing measured it, no registry stated it, and the model did
    -- not reason to it. A person who was there said so.
    --
    -- It is the STRONGEST value here for one narrow class of question, is
    -- this yours, is this expected, did you do this, and that is the same
    -- authority the probe enrollment already rests on because there is no
    -- Intune on this network. It is not a measurement and must never be
    -- filed as one: people misremember, and a person's answer about last
    -- Tuesday is not a packet.
    --
    -- TWO NOTES ON THIS CONSTRAINT, and the second one was a live defect.
    --
    -- FIRST. v26 added basis with ALTER TABLE ADD COLUMN, and SQLite cannot
    -- attach a CHECK that way, so an EXISTING database has no constraint on
    -- this column at all. This line only ever applied to databases created
    -- fresh from this file.
    --
    -- SECOND, found 2026-09-14 while adding the fourth value. This CHECK was
    -- written as `basis IN ('a','b','c',NULL)` and THAT ENFORCED NOTHING, on
    -- any database, ever. In SQL, `x IN (a, b, NULL)` evaluates to NULL
    -- rather than false for any x not in the list, and a CHECK constraint
    -- passes when its expression is NULL: only an explicit false rejects.
    -- So a fresh database happily accepted any string at all in this column
    -- while the comment above it described a constraint. Proved with a real
    -- SQLite handle, not reasoned about.
    --
    -- Written as `IS NULL OR IN (...)` now, which refuses a bad value and
    -- still allows the NULL that pre-v26 rows carry. The real gate for both
    -- database shapes is still memory_engine.VALID_OBSERVATION_BASIS, which
    -- every writer passes through; this is the second line of defence that
    -- was pretending to be there.
    basis           TEXT CHECK(basis IS NULL OR basis IN
                        ('measured','external_intel','model_conclusion',
                         'operator_stated')),
    -- Where an external fact came from, normally 'enrichment:<indicator>'.
    -- Required for external_intel, because an external claim with no source is
    -- exactly what this column exists to prevent. It is also what lets the
    -- read path mark the row STALE once that lookup expires.
    basis_ref       TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_basis ON behavioral_session(basis);


CREATE INDEX IF NOT EXISTS idx_bsession_session   ON behavioral_session(session_id);
CREATE INDEX IF NOT EXISTS idx_bsession_entity    ON behavioral_session(session_id, entity_type, entity_value);

-- HISTORICAL TIER: rolled-up baselines per entity
-- Updated hourly and on clean shutdown
-- This is the model's long-term conscience about this specific network
CREATE TABLE IF NOT EXISTS behavioral_baseline (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type     TEXT NOT NULL CHECK(entity_type IN ('ip','process','port','user')),
    entity_value    TEXT NOT NULL,
    behavior_key    TEXT NOT NULL,

    -- Statistical summary built from session observations
    sample_count    INTEGER DEFAULT 0,
    value_mean      REAL,                   -- avg value across all sessions
    value_stddev    REAL,                   -- standard deviation -- defines "normal range"
    value_min       REAL,
    value_max       REAL,

    -- Rich behavioral context (JSON arrays)
    typical_hours       TEXT,              -- [8,9,10,17,18,19,20,21,22]
    typical_dest_ports  TEXT,              -- [80, 443, 8080]
    typical_dest_ips    TEXT,              -- ["142.250.80.46", "1.1.1.1"]

    -- Confidence and status
    confidence      TEXT DEFAULT 'low' CHECK(confidence IN ('low','medium','high')),
    -- Counted in DISTINCT SESSIONS via baseline_session_seen, never in raw
    -- observations. A 120s poll loop produces dozens of observations per
    -- session; treating those as evidence let one sitting manufacture 'high'.
    -- The tier boundaries are NOT fixed here. They come from the
    -- 'confidence_session_thresholds' preference seeded at the bottom of this
    -- file, and are validated on read by rollup_engine._confidence_thresholds.
    -- Defaults:
    -- low    = 2+ sessions of data
    -- medium = 4+ sessions, consistent behavior
    -- high   = 6+ sessions, model has declared this normal
    -- These three lines said 5 until 2026-08-29 while the code used 6. To
    -- change the number, change the PREFERENCE, not this comment.
    flagged_as_normal   INTEGER DEFAULT 0, -- 1 = explicitly classified as expected
    alert_suppressed    INTEGER DEFAULT 0, -- 1 = stop alerting entirely
    -- alert_suppressed can only be set by an affirmative signal: an explicit
    -- user decision, or a model call that passed the permission gate. The
    -- silence timer must never set it. See core/rollup_engine.py.

    -- MEASURED CONTACT REGULARITY (v20, 2026-08-29)
    -- JSON, written by core/intervals.py. Holds the spacing between contacts
    -- for this entity's steadiest destination, plus the per-destination
    -- breakdown. It exists because `packets` has to be pruned and the spacing
    -- lives nowhere else: value_mean/stddev above carry the numbers, this
    -- carries WHICH destination they belong to.
    -- Structured, not prose, on purpose. A sentence would go stale the way
    -- model_notes did.
    beacon_detail   TEXT,

    -- Model's own narrative -- builds up over time
    model_notes     TEXT,                  -- "198.51.100.7 consistently beacons to a CDN..."

    -- Timestamps
    first_seen      TIMESTAMP,
    last_updated    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- v29, 2026-09-13. WITHDRAWING A BASELINE.
    --
    -- supersede_observation could withdraw a session observation, but rollup
    -- reads current observations only, so a withdrawal kept the row out of
    -- future merges and did nothing about the baseline that had already eaten
    -- it. You could retract the sentence and not the belief it produced.
    --
    -- Nothing is deleted. The row keeps its identity and gains a reason, the
    -- same shape as superseded_reason on behavioral_session, so a later
    -- reader can see what was believed and why that changed.
    retracted_at     TIMESTAMP,
    retracted_reason TEXT,

    UNIQUE(entity_type, entity_value, behavior_key)
);

CREATE INDEX IF NOT EXISTS idx_baseline_entity    ON behavioral_baseline(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_baseline_confidence ON behavioral_baseline(confidence, flagged_as_normal);

-- DEVIATION LOG: when model detects something outside baseline
-- This is where real threat intelligence lives
CREATE TABLE IF NOT EXISTS behavioral_deviation (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    detected_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    entity_type     TEXT NOT NULL,
    entity_value    TEXT NOT NULL,
    behavior_key    TEXT NOT NULL,

    -- What was expected vs what happened
    expected_value  TEXT,                  -- from behavioral_baseline
    observed_value  TEXT,                  -- what actually occurred
    deviation_score REAL,                  -- stddevs from mean (>2.0 = notable, >3.0 = alert)

    -- Severity drives the silence-timer floor. 'critical' and 'high' are
    -- NEVER auto-resolved or baselined by silence -- they stay in the
    -- review queue until a human actually answers.
    severity        TEXT DEFAULT 'low' CHECK(severity IN ('critical','high','medium','low','info')),

    -- Model's assessment
    model_assessment TEXT,                 -- model writes its full reasoning here
    action_taken    TEXT CHECK(action_taken IN ('alerted','logged','blocked','ignored','quarantined')),

    -- User response tracking.
    -- NOTE: silence is NOT approval. An unanswered alert resolves to
    -- 'unreviewed', which means nobody looked -- not that it is normal.
    alerted_at      TIMESTAMP,
    user_responded  INTEGER DEFAULT 0,     -- 0 = silence, 1 = user replied
    user_response   TEXT,                  -- verbatim if they responded
    silence_timeout_seconds INTEGER DEFAULT 150,  -- 2.5 min default, configurable

    -- Resolution
    resolved_as     TEXT CHECK(resolved_as IN ('normal','threat','investigating','ignored','false_positive','unreviewed')),
    resolved_at     TIMESTAMP,

    -- WHO resolved it. v30, 2026-09-14, TODO 98.
    --
    -- user_responded and user_response are the operator's, and the model tool
    -- could write both of them with nothing recording that a model had. This
    -- column is the difference between "a person answered" and "the model
    -- thinks". A model resolution stays in the review queue until a person
    -- answers it, see query_review_queue.
    --
    -- The shape here was `IN (..., NULL)`, which enforced nothing. See the
    -- long note on behavioral_session.basis: `x IN (a, NULL)` is NULL rather
    -- than false for a value not in the list, and a CHECK passes on NULL. So
    -- this column, added by TODO 98 precisely to stop a model resolution
    -- looking like a human one, would have accepted any string at all on a
    -- fresh database. memory_engine.resolve_deviation validates it against
    -- VALID_RESOLVED_BY and always did, which is why nothing bad reached the
    -- column, but the second line of defence was decorative. Corrected
    -- 2026-09-14.
    resolved_by     TEXT CHECK(resolved_by IS NULL OR
                               resolved_by IN ('user','model','silence_timer')),

    -- Learning signal: user feedback trains future confidence
    -- 'false_positive' -> bump baseline confidence, suppress future alerts
    -- 'threat'         -> keep alerting, lower deviation threshold for this entity
    --
    -- NOTHING WRITES THIS COLUMN. Checked 2026-09-14: the only references
    -- anywhere are this line and the copy list in the migration that rebuilds
    -- the table. It is not wired to anything, and the two lines above
    -- describe behaviour that does not exist. Left in place rather than
    -- dropped, because dropping a column needs a table rebuild and this one
    -- is harmless, but it should not be read as a live control. Its CHECK is
    -- corrected for the same inert-NULL reason as the two above.
    user_feedback   TEXT CHECK(user_feedback IS NULL OR
                               user_feedback IN ('false_positive','correct',
                                                 'investigating'))
);

CREATE INDEX IF NOT EXISTS idx_deviation_entity   ON behavioral_deviation(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_deviation_session  ON behavioral_deviation(session_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_deviation_unresolved ON behavioral_deviation(user_responded, alerted_at)
    WHERE resolved_as IS NULL;
CREATE INDEX IF NOT EXISTS idx_deviation_review   ON behavioral_deviation(resolved_as, severity, detected_at);

-- SESSION ACCOUNTING FOR BASELINE CONFIDENCE
-- One row per (entity, behavior_key, session) the behavior was seen in.
-- behavioral_baseline.sample_count is derived from COUNT(*) here, which is
-- what a session-counted confidence tier was always supposed to mean. The
-- actual boundary is the 'confidence_session_thresholds' preference (high
-- defaults to 6), not a number written into a comment.
CREATE TABLE IF NOT EXISTS baseline_session_seen (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type   TEXT NOT NULL,
    entity_value  TEXT NOT NULL,
    behavior_key  TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- v29. Stamped when the baseline this session fed was withdrawn. The row
    -- is KEPT so the audit of which sessions saw what survives, it just stops
    -- counting toward a belief that was pulled. Without this, retracting a
    -- baseline would leave the session count intact and the next observation
    -- would come straight back at the old confidence.
    retracted_at  TIMESTAMP,
    UNIQUE(entity_type, entity_value, behavior_key, session_id)
);

CREATE INDEX IF NOT EXISTS idx_bss_entity ON baseline_session_seen(entity_type, entity_value, behavior_key);

-- ROLLUP AUDIT LOG
-- Tracks every time session tier was merged into historical tier
CREATE TABLE IF NOT EXISTS rollup_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rolled_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_id      TEXT NOT NULL,
    trigger_reason  TEXT CHECK(trigger_reason IN ('hourly','shutdown','manual')),
    entities_processed INTEGER DEFAULT 0,
    baselines_updated  INTEGER DEFAULT 0,
    baselines_created  INTEGER DEFAULT 0,
    duration_ms        INTEGER,
    notes           TEXT
);

-- ,,,,,,,,,,,,,,,,,,,,
-- PRESENCE SWEEPS (schema v12)
-- ,,,,,,,,,,,,,,,,,,,,
--
-- WHY THIS EXISTS.
--
-- `known_devices.last_seen` is one value that gets overwritten. It answers
-- "when was this last seen" and cannot answer "how many of the last forty
-- sweeps did it answer", because sweeps one through thirty-nine left no
-- trace. Absence was therefore never countable, and a device that is
-- SUPPOSED to be permanently present could stop answering without anything
-- in the database being able to show it.
--
-- These two tables make absence a measurement instead of an impression.
--
-- Only POSITIVES are stored. A device is absent from a sweep when it has no
-- row for that sweep, which is derived by joining against presence_sweep
-- rather than written down. Two reasons: storage is bounded by how many
-- devices actually answered rather than by the size of the address space,
-- and, more importantly, nothing can read presence without also reading the
-- denominator it was measured against. Thirty-eight present out of forty and
-- one present out of one cannot be made to look alike.
--
-- THE OUTCOME COLUMN IS THE POINT OF THE FIRST TABLE. A sweep that could not
-- run is not a sweep in which everything was absent. Only outcome='ok' rows
-- are ever counted as a denominator. This is the distinction the project
-- already enforces between `searched: false` and "found nothing", applied to
-- the network sweep.

CREATE TABLE IF NOT EXISTS presence_sweep (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    swept_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    subnet          TEXT,
    method          TEXT NOT NULL,          -- 'icmp+arp'

    -- 'ok'     = the sweep ran and is usable as a denominator.
    -- 'failed' = it could not run. NEVER counted. detail says why.
    outcome         TEXT NOT NULL CHECK(outcome IN ('ok','failed')),
    detail          TEXT,

    targets         INTEGER DEFAULT 0,      -- addresses probed
    responded       INTEGER DEFAULT 0,      -- addresses that answered
    duration_ms     INTEGER,

    sensor_id       TEXT REFERENCES sensors(sensor_id)
);

CREATE INDEX IF NOT EXISTS idx_presence_sweep_time
    ON presence_sweep(swept_at);
CREATE INDEX IF NOT EXISTS idx_presence_sweep_outcome
    ON presence_sweep(outcome, swept_at);

-- One row per address that ANSWERED a given sweep. No absence rows.
--
-- `via` matters and is not decoration. An ICMP reply is the device answering
-- now. An ARP cache entry is the operating system's recollection, which
-- outlives the device for as long as the entry lives, so arp-only presence
-- is a weaker claim than icmp presence and a reader has to be able to tell
-- them apart. Recording which it was is the only way to keep that
-- distinction available later.
CREATE TABLE IF NOT EXISTS presence_observation (
    sweep_id        INTEGER NOT NULL REFERENCES presence_sweep(id) ON DELETE CASCADE,
    ip              TEXT NOT NULL,
    mac             TEXT,
    via             TEXT NOT NULL CHECK(via IN ('icmp','arp','both')),
    PRIMARY KEY (sweep_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_presence_obs_ip
    ON presence_observation(ip);

-- INTEGRITY JOURNAL (v16)
--
-- An append-only, hash-chained record of the writes that change what this
-- tool will TELL you later: findings saved and dismissed, deviations
-- resolved, baselines suppressed, devices vouched for and retired, and the
-- POLICY those decisions are judged by (see config_observed below).
--
-- Anything running with administrator rights on this machine can edit a
-- finding or rewrite a baseline, and without this nothing would ever know.
-- That is not preventable on a box the attacker controls. It is DETECTABLE,
-- and detectable is the thing worth buying, because the entire value of this
-- tool is that its record can be believed afterwards.
--
-- Each entry carries the hash of the entry before it, so altering or
-- removing anything in the middle breaks every hash after it.
--
-- READ THE HONEST LIMITS IN core/integrity.py BEFORE TRUSTING THIS. In
-- short: an attacker who reads that source can recompute the whole chain, so
-- the chain alone catches careless tampering, not deliberate tampering. What
-- makes it real is an ANCHOR -- the head hash kept somewhere the attacker
-- cannot edit. A phone photo of the hash is a better anchor than a file in
-- this folder, and that is not a joke.
--
-- 'config_observed' entries are the operation added 2026-08-29. They digest
-- the whole user_preferences table and are written ONLY when it differs from
-- the last snapshot, so a config_observed entry ALWAYS means the rules
-- changed. It is never routine noise and never needs to be ignored.
CREATE TABLE IF NOT EXISTS integrity_journal (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    operation      TEXT NOT NULL,
    table_name     TEXT,
    row_ref        TEXT,
    payload_digest TEXT NOT NULL,   -- digest of the payload, never the payload
    prev_hash      TEXT NOT NULL,
    entry_hash     TEXT NOT NULL
);

-- entry_hash is looked up on every append to find the head, and on every
-- verification pass. row_ref is how an investigator asks "what happened to
-- this finding".
CREATE INDEX IF NOT EXISTS idx_journal_hash ON integrity_journal(entry_hash);
CREATE INDEX IF NOT EXISTS idx_journal_ref  ON integrity_journal(table_name, row_ref);


-- ENRICHMENT. v25, 2026-09-02. Tier 1 of the research worker, TODO 35 and 40.
--
-- SECOND-HAND BY CONSTRUCTION. Everything in packets, events, presence_
-- observation and known_devices was measured on this network by this tool.
-- Everything here is what somebody else's registry said when we asked. Those
-- are different kinds of claim and they get different tables, so that the
-- model can always tell which one it is holding. TODO 37 is what happens when
-- it cannot: invented evidence read exactly like observed evidence, because
-- nothing about the shape of the data said otherwise.
--
-- Reads come back with record_type='external_intel' stamped on them, and both
-- model tools are in sanitize.UNTRUSTED_TOOLS, so this content reaches the
-- model fenced like a packet payload.
--
-- status IS THE CONTRACT, from TODO 35.3. Three values, and a job ALWAYS
-- writes one of them:
--     resolved     two independent sources answered and agree
--     partial      something was learned and the gap is named
--     unresolved   nothing found, and `tried_json` says what was asked
-- Silence is not an answer. A CHECK constraint keeps a fourth value from
-- quietly appearing and changing what the model has been told these mean.
--
-- fields_json rather than columns, because an IP answers with an ASN and a
-- CVE answers with a CVSS vector. core/enrichment._fields_only caps every
-- string at 200 characters and drops anything that is not a scalar, which is
-- how "fields only, no free prose" is enforced structurally rather than
-- remembered.
--
-- expires_at is a per-kind lifetime. Ownership lasts a month, a vendor prefix
-- a year, and anything UNRESOLVED expires in hours on purpose: that is how a
-- failed lookup gets retried later without a scheduler existing.
CREATE TABLE IF NOT EXISTS enrichment (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator    TEXT NOT NULL,
    kind         TEXT NOT NULL
                 CHECK(kind IN ('ip','domain','cve','mac','hash','process')),
    status       TEXT NOT NULL
                 CHECK(status IN ('resolved','partial','unresolved')),
    confidence   TEXT,
    fields_json  TEXT NOT NULL DEFAULT '{}',
    sources_json TEXT NOT NULL DEFAULT '[]',
    tried_json   TEXT NOT NULL DEFAULT '[]',
    gap          TEXT,
    session_id   TEXT,
    fetched_at   TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL,
    UNIQUE(indicator, kind)
);

CREATE INDEX IF NOT EXISTS idx_enrichment_kind   ON enrichment(kind, status);
CREATE INDEX IF NOT EXISTS idx_enrichment_expiry ON enrichment(expires_at);

-- The queue. enqueue_enrichment writes here and returns immediately; a single
-- background thread drains it one job at a time, which is the cap TODO 35.6
-- asks for and also what keeps this inside published rate limits that are
-- measured in single-digit requests per ten seconds.
CREATE TABLE IF NOT EXISTS enrichment_queue (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator    TEXT NOT NULL,
    kind         TEXT NOT NULL,
    requested_by TEXT,
    reason       TEXT,
    session_id   TEXT,
    requested_at TIMESTAMP NOT NULL,
    started_at   TIMESTAMP,
    finished_at  TIMESTAMP,
    state        TEXT NOT NULL DEFAULT 'queued'
                 CHECK(state IN ('queued','running','done','failed')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    note         TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrichment_queue_state
    ON enrichment_queue(state, id);


-- PREDICTION LEDGER (v31, 2026-09-14)
--
-- The model says what it expects to happen. The app checks it later and
-- writes down whether it was right. Nothing else in this project ever told
-- the model it was wrong, and a model that is never scored has no way to get
-- better at this network specifically.
--
-- THE CHECK IS DONE BY PYTHON, NEVER BY THE MODEL. A model grading its own
-- prediction is the same shape as a model declaring its own expected port,
-- and that argument was already settled: it cannot.
--
-- THREE OUTCOMES, AND THEY ARE NEVER SUMMED.
--   hit          the claim held, and we could see well enough to say so
--   miss         the claim did not hold
--   unverifiable we could not look. The capture was down for most of the
--                window, or this sensor has never once seen that device.
--
-- The third one is the whole reason this table is shaped this way. "No
-- traffic from the TV" is trivially true when the sniffer was off, and
-- counting that as a hit would build a hit rate out of our own blind spots.
-- A hit rate that flatters the model is worse than no hit rate.
--
-- NOTHING HERE FEEDS A BASELINE, A FINDING OR A SUPPRESSION. A prediction is
-- a guess with a deadline. It gets to be wrong without costing anything, and
-- that freedom is only safe while it stays walled off from the tables that
-- decide what gets alerted on.
CREATE TABLE IF NOT EXISTS prediction (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    made_at         TIMESTAMP NOT NULL,
    -- When the claim can first be judged. Predictions are not checked before
    -- this and are not checked twice after.
    horizon_ends_at TIMESTAMP NOT NULL,

    -- WHAT KIND OF CLAIM. Constrained, because a free-text prediction cannot
    -- be checked by anything and would quietly never be scored. The model has
    -- to say something falsifiable or it does not get to file it at all.
    claim_kind      TEXT NOT NULL
                    CHECK(claim_kind IN ('no_traffic','traffic_above',
                                         'traffic_below','no_finding',
                                         'finding_expected','device_present',
                                         'device_absent')),
    entity_type     TEXT NOT NULL CHECK(entity_type IN ('ip','process','port','user')),
    entity_value    TEXT NOT NULL,
    threshold       REAL,                   -- traffic_above / traffic_below only
    detail          TEXT,                   -- minimum severity for the finding kinds

    -- The model's own sentence, for a person to read, plus why it thinks so.
    -- The claim above is what gets checked; these two are what make the row
    -- worth reading afterwards.
    statement       TEXT NOT NULL,
    reasoning       TEXT,

    -- NULL until checked. Then one of the three, and never changed again.
    outcome         TEXT CHECK(outcome IN ('hit','miss','unverifiable')),
    outcome_reason  TEXT,
    observed_value  REAL,                   -- what was actually counted
    coverage_note   TEXT,                   -- how much of the window we could see
    checked_at      TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_prediction_due
    ON prediction(outcome, horizon_ends_at);
CREATE INDEX IF NOT EXISTS idx_prediction_entity
    ON prediction(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_prediction_made
    ON prediction(made_at);


-- THE QUESTION QUEUE (v32, 2026-09-14)
--
-- The model asks the owner something it cannot work out on its own. This is
-- the only path in the app where the tool starts the conversation.
--
-- WHEN IT IS ALLOWED TO ASK. Only after the automated path has run and come
-- back short. Asking the owner what RDAP could have told us is the fastest
-- way to make him stop reading these, and once he stops, the mechanism is
-- worth nothing no matter how well it is built.
--
-- TOPICS ARE A FIXED LIST, same reasoning as the prediction claim kinds. A
-- free-text question cannot be checked for having been asked before, so the
-- model could rephrase its way around the no-repeat rule without ever meaning
-- to. One question per topic per entity, ever, enforced by the unique index.
--
-- THREE OUTCOMES, NEVER SUMMED, the same discipline as everything else here:
--   answered       he told us
--   do_not_know    he does not know either. This is INFORMATION, not a
--                  failure. It means nobody knows, stop asking, and this is a
--                  genuine unknown rather than a gap waiting to be filled.
--   expired        ten days passed from when he was actually SHOWN it
--
-- THE EXPIRY CLOCK STARTS AT first_shown_at, NOT asked_at. A question sitting
-- behind the popup budget for nine days would otherwise expire the day after
-- he first sees it. Not being asked and choosing not to answer are different
-- things and only the second one means it did not matter.
CREATE TABLE IF NOT EXISTS operator_question (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    asked_at      TIMESTAMP NOT NULL,

    topic         TEXT NOT NULL
                  CHECK(topic IN ('identify_device','identify_destination',
                                  'identify_process','expected_behaviour',
                                  'confirm_change')),
    entity_type   TEXT NOT NULL CHECK(entity_type IN ('ip','process','port','user')),
    entity_value  TEXT NOT NULL,

    question      TEXT NOT NULL,    -- the model's own sentence
    why_stuck     TEXT,             -- why it cannot answer this itself
    -- What the automated path already did, and what each source said.
    -- DERIVED from the enrichment row at asking time, not written by hand, so
    -- the owner is never asked something the app could have answered.
    tried_json    TEXT NOT NULL DEFAULT '[]',
    -- Where HE can look, that the app could not. Derived from the source
    -- catalog plus the keyed sources with no key. Says where to look and what
    -- to type, NEVER what he will find: a hint carrying the model's guess is
    -- that guess smuggled in wearing a helpful hat, and he would then go and
    -- find confirmation for something nobody established.
    hints_json    TEXT NOT NULL DEFAULT '[]',

    -- NULL until he has actually been shown it. Starts the expiry clock.
    first_shown_at TIMESTAMP,
    state         TEXT NOT NULL DEFAULT 'open'
                  CHECK(state IN ('open','answered','do_not_know','expired')),
    answered_at   TIMESTAMP,
    answer_text   TEXT,
    -- Where the answer landed, so the same fact does not live in two places.
    -- 'known_devices:192.0.2.5', 'behavioral_session:1841', or NULL when it
    -- only ever needed to be a sentence.
    answer_filed_as TEXT,

    UNIQUE(topic, entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_question_state ON operator_question(state, asked_at);
CREATE INDEX IF NOT EXISTS idx_question_shown ON operator_question(first_shown_at);

-- One row per popup actually put on his screen. Not per question: a popup can
-- carry several. This is what the budget is counted from, and it is a table
-- rather than a counter so "when was I last interrupted" has an answer that
-- survives a restart.
CREATE TABLE IF NOT EXISTS operator_popup (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    shown_at     TIMESTAMP NOT NULL,
    question_ids TEXT NOT NULL DEFAULT '[]',
    carried      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_popup_shown ON operator_popup(shown_at);


-- THE PERFORMANCE AXIS (v32, 2026-09-14)
--
-- One row per device per hour. How much it talked, to how many peers, how its
-- DNS went, and whether it answered when something knocked.
--
-- WHY IT IS STORED AND NOT COMPUTED ON DEMAND. The same argument core/
-- intervals.py makes: retention prunes packets, and when they go, so does the
-- only place any of this was ever recorded. Measure it while the packets are
-- still here, keep the summary, then prune. Never the other way round.
--
-- COVERAGE_SECONDS IS THE MOST IMPORTANT COLUMN AND IT IS NOT DECORATION. An
-- hour with 4,000,000 bytes and an hour with zero look like a busy device and
-- a quiet one, right up until you notice the second hour had 40 seconds of
-- capture in it. Every reader of this table has to divide by what we could
-- see, and the page paints a thin-coverage bucket GREY rather than green. A
-- quiet network and a blind sensor are different things and this column is
-- what keeps them different.
--
-- WHAT IS DELIBERATELY NOT HERE. Gateway round trip time and TCP
-- retransmissions. Both are real performance signals and neither is
-- derivable from what is stored: retransmits need sequence numbers the
-- sniffer does not keep, and RTT needs an active probe nothing runs. They are
-- named as gaps on the page instead of appearing as zeroes, because a zero
-- would read as a perfect network.
CREATE TABLE IF NOT EXISTS perf_hourly (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_value     TEXT NOT NULL,          -- the device address
    hour_start       TIMESTAMP NOT NULL,     -- UTC, top of the hour
    bytes_in         INTEGER NOT NULL DEFAULT 0,
    bytes_out        INTEGER NOT NULL DEFAULT 0,
    packets_in       INTEGER NOT NULL DEFAULT 0,
    packets_out      INTEGER NOT NULL DEFAULT 0,
    distinct_peers   INTEGER NOT NULL DEFAULT 0,
    -- NULL, not 0, when no DNS source is importing. Zero failures and no
    -- resolver to ask are not the same sentence.
    dns_queries      INTEGER,
    dns_failures     INTEGER,
    -- How many successful sweeps ran in that hour and how many this device
    -- answered. Both NULL when no sweep ran at all.
    sweeps_total     INTEGER,
    sweeps_answered  INTEGER,
    coverage_seconds INTEGER NOT NULL DEFAULT 0,
    computed_at      TIMESTAMP NOT NULL,
    UNIQUE(entity_value, hour_start)
);

CREATE INDEX IF NOT EXISTS idx_perf_hour   ON perf_hourly(hour_start);
CREATE INDEX IF NOT EXISTS idx_perf_entity ON perf_hourly(entity_value, hour_start);


-- THE AGENT DRIVER (v37, 2026-09-17, TODO 116)
-- PORTED TO LINUX 2026-09-21, AND DORMANT ON THIS TREE. The owner asked for
-- everything in this file that is possible to port, so these three are here.
-- NOTHING IN THIS TREE WRITES TO THEM: this tree's agentic record is T2/T3/T4,
-- which is `incident`, `watcher_run`, `action_request`, `duty_run` and
-- `duty_report`, and that is the design wired into main.py, the routes, the UI
-- and the verification scripts. An empty agent_run here means the Windows
-- driver is not running, NOT that nothing has ever run. See
-- core/migrations._migrate_agent_runs for the full reasoning, including why
-- this tree's `action_request` and Windows's `agent_action_request` are two
-- different tables rather than one under two names.

--
-- Until this, nothing in this app ever took a turn unless the owner typed.
-- The model lived inside a chat request, which made him the trigger for
-- everything. His words, and they are fair: why do we call it an agent then.
--
-- These three tables are the record of the app acting on its own. One row per
-- wake up, one row per step inside it, and one row per action that stopped
-- and asked him first.
--
-- WHERE THE HUMAN SITS, and this is his rule from the beginning that the
-- earlier design got wrong: the human is consulted at the LAST step, before
-- something indefinite or destructive. He is not the trigger for the reading,
-- the querying, the correlating or the writing of an observation. Those run
-- on the agent's own initiative. Killing a process or changing the firewall
-- stops and shows him a card with the reasoning on it.
--
-- WHY A RUN IS A ROW EVEN WHEN IT ACHIEVED NOTHING. A wake up that picked no
-- job, or ran out of rounds, or errored, is still a wake up that spent money.
-- A log that only records successes cannot answer "why is it doing nothing",
-- which is the question somebody actually asks.
CREATE TABLE IF NOT EXISTS agent_run (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    started_at    TIMESTAMP NOT NULL,
    finished_at   TIMESTAMP,

    -- WHAT WOKE IT. scheduled is the ordinary daily budget. critical_finding
    -- is the override: a brute force in progress or a beaconing listener does
    -- not wait for tomorrow's quota. manual is the button on the page.
    trigger       TEXT NOT NULL
                  CHECK(trigger IN ('scheduled','critical_finding','manual')),
    -- For a critical wake, which detection on which entity. This is also the
    -- DEDUPE KEY: a noisy rule firing two hundred times in an hour must not
    -- buy two hundred wake ups, so the same detection on the same entity
    -- wakes it once per day and is folded into the next scheduled run after
    -- that. Without this the override is a way to spend a month of budget in
    -- an evening.
    trigger_detail TEXT,

    -- NULL until the model picks. A run that never picked one is a real run
    -- and has to be visible, so this is not NOT NULL.
    job_id        TEXT,
    pillar        TEXT CHECK(pillar IS NULL OR pillar IN ('C','I','A')),
    entity_type   TEXT,
    entity_value  TEXT,
    -- The model's own sentence for why this job and this target, out of the
    -- menu it was given. The pick is the one decision nothing else records.
    pick_reason   TEXT,

    rounds_used   INTEGER NOT NULL DEFAULT 0,

    -- HOW IT ENDED. Seven values, and none of them is a synonym for another:
    --   concluded          it worked the job and wrote its answer down
    --   asked_operator     it filed a question rather than guessing
    --   parked_action      it wants to do something destructive, card is up
    --   nothing_due        no job had a candidate. Not a failure.
    --   no_pick            the model was given a menu and picked nothing
    --   rounds_exhausted   it used its whole round budget and stopped
    --   error              something threw
    outcome       TEXT CHECK(outcome IS NULL OR outcome IN
                  ('concluded','asked_operator','parked_action','nothing_due',
                   'no_pick','rounds_exhausted','error')),
    summary       TEXT,           -- the model's closing text, for a person
    error         TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_run_time    ON agent_run(started_at);
CREATE INDEX IF NOT EXISTS idx_agent_run_trigger ON agent_run(trigger, started_at);
CREATE INDEX IF NOT EXISTS idx_agent_run_job     ON agent_run(job_id, started_at);

-- One row per step inside a run. This is what makes a run readable after the
-- fact instead of being one paragraph of the model's own account of itself.
CREATE TABLE IF NOT EXISTS agent_step (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES agent_run(id),
    step_no       INTEGER NOT NULL,
    happened_at   TIMESTAMP NOT NULL,

    -- model    a paid round: the model thought and either spoke or called tools
    -- tool     a tool actually executed
    -- gate     a call that was stopped and turned into an approval card
    -- refusal  a call this app refused outright, with the reason
    kind          TEXT NOT NULL CHECK(kind IN ('model','tool','gate','refusal')),
    tool_name     TEXT,
    params_json   TEXT,
    -- A SHORT result, never the whole payload. The full answer went to the
    -- model; this column is for a person scanning what happened, and storing
    -- megabytes of tool output per run would make the log the biggest table
    -- in the database within a week.
    result_brief  TEXT,
    error         TEXT,
    action_request_id INTEGER REFERENCES agent_action_request(id)
);

CREATE INDEX IF NOT EXISTS idx_agent_step_run ON agent_step(run_id, step_no);

-- THE APPROVAL CARD. The one place the human is still required.
--
-- REASONING IS NOT NULL, and that is the owner's requirement in his own
-- words: after good explanation as to why it thinks those things have to go.
-- A card that arrives saying only "kill pid 4120" asks him to rubber stamp
-- something he has no way to judge, and he will either approve everything or
-- stop reading them. Both outcomes are worse than no card.
--
-- THE DECISION REASON IS KEPT ON A REJECTION TOO. That record is the only
-- material the agent has for learning what he says no to, and it is read back
-- into later runs. Rejections that vanish teach nothing and the same card
-- comes back next week.
--
-- NOTHING EXECUTES FROM THIS TABLE EXCEPT core/agent_actions.execute_approved,
-- and state must be 'approved' when it does. A route cannot execute, a tool
-- cannot execute, and the model cannot set a state.
CREATE TABLE IF NOT EXISTS agent_action_request (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER REFERENCES agent_run(id),
    session_id    TEXT NOT NULL,
    requested_at  TIMESTAMP NOT NULL,

    tool_name     TEXT NOT NULL,
    params_json   TEXT NOT NULL,
    -- What the agent is trying to achieve, what it saw, and what it expects
    -- to happen. Written by the model, required, and shown verbatim.
    reasoning     TEXT NOT NULL,
    -- What this changes on the machine, written by US from the tool name, not
    -- by the model. The model describes its intent; the app describes the
    -- effect. Those are different claims and the card shows both.
    effect_note   TEXT,

    state         TEXT NOT NULL DEFAULT 'pending'
                  CHECK(state IN ('pending','approved','rejected','executed',
                                  'failed','expired')),
    decided_at    TIMESTAMP,
    decided_by    TEXT,          -- 'user' only. Hardcoded at the route.
    decision_reason TEXT,
    executed_at   TIMESTAMP,
    result_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_action_state
    ON agent_action_request(state, requested_at);
CREATE INDEX IF NOT EXISTS idx_agent_action_run
    ON agent_action_request(run_id);




-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- THE INCIDENT LEDGER (v35, T2, 2026-09-17)
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- The layer between "a finding happened" and "somebody should look". A
-- finding is one thing one sensor saw, once; an incident is many findings
-- about one subject collapsed into one thing a person should look at, kept
-- and updated over time.
--
-- incident_key is UNIQUE: one incident per (rule, subject). That makes
-- coalescing a property of the database rather than something the watcher
-- has to remember across a restart.
--
-- COVERAGE IS THE HONESTY COLUMN. coverage_json records which sensors were
-- BLIND when the incident was raised. An incident assessed while capture was
-- down is a statement about this app's eyes, not about the network, and
-- without this column the two are indistinguishable afterwards.
--
-- THE STATE MACHINE IS ENFORCED HERE. action_pending exists in the schema
-- from the start because T3's action queue writes it.
--
-- Kept in sync with core/migrations._migrate_incident_ledger by hand; there
-- is no code that reads one and writes the other. Change both.
CREATE TABLE IF NOT EXISTS incident (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_key    TEXT NOT NULL UNIQUE,
    detection_id    TEXT NOT NULL,
    detection_rev   INTEGER,
    entity_type     TEXT NOT NULL,
    entity_value    TEXT NOT NULL,
    source          TEXT,
    severity        TEXT NOT NULL,
    severity_rank   INTEGER NOT NULL DEFAULT 0,
    cia_json        TEXT NOT NULL DEFAULT '[]',
    title           TEXT NOT NULL,
    first_seen_at   TIMESTAMP NOT NULL,
    last_seen_at    TIMESTAMP NOT NULL,
    finding_count   INTEGER NOT NULL DEFAULT 1,
    finding_ids_json TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'new'
                    CHECK(status IN ('new','triaged','action_pending',
                                     'resolved','dismissed')),
    status_at       TIMESTAMP NOT NULL,
    status_by       TEXT NOT NULL DEFAULT 'watcher'
                    CHECK(status_by IN ('watcher','model','user',
                                        'silence_timer')),
    assessment      TEXT,
    assessed_at     TIMESTAMP,
    assessment_tokens INTEGER,
    actions_json    TEXT NOT NULL DEFAULT '[]',
    coverage_json   TEXT,
    coverage_note   TEXT,
    suppressed      INTEGER NOT NULL DEFAULT 0,
    suppressed_reason TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incident_status    ON incident(status, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_incident_detection ON incident(detection_id);
CREATE INDEX IF NOT EXISTS idx_incident_entity    ON incident(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_incident_seen      ON incident(last_seen_at);

-- One row per watcher tick, so "was anything reading findings at 3am" has an
-- answer after the fact rather than being inferred from an absence.
CREATE TABLE IF NOT EXISTS watcher_run (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    ran_at        TIMESTAMP NOT NULL,
    outcome       TEXT NOT NULL
                  CHECK(outcome IN ('ok','refused','error')),
    findings_read INTEGER NOT NULL DEFAULT 0,
    new_incidents INTEGER NOT NULL DEFAULT 0,
    coalesced     INTEGER NOT NULL DEFAULT 0,
    refused       INTEGER NOT NULL DEFAULT 0,
    capped        INTEGER NOT NULL DEFAULT 0,
    backlog       INTEGER NOT NULL DEFAULT 0,
    detail        TEXT,
    duration_ms   INTEGER,
    -- THE WATCHER'S CURSOR: the highest finding id this tick accounted for.
    -- It lives here rather than in user_preferences because core/integrity
    -- snapshots that table as "the policy" and journals a config_observed
    -- entry whenever it moves, on the stated contract that such an entry
    -- ALWAYS means the rules changed and is never routine noise. A cursor
    -- written every 60 seconds would turn the tamper journal into a log of
    -- the watcher's own bookkeeping. NULL means no row has ever carried a
    -- cursor, which is a first run; a tick that read nothing carries the
    -- previous value forward.
    last_processed_finding_id INTEGER
);

CREATE INDEX IF NOT EXISTS idx_watcher_run_at ON watcher_run(ran_at);


-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- THE ACTION QUEUE (v36, T3, 2026-09-18)
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- A gated action the agent wanted to take, filed as a REQUEST instead of run.
-- This is the piece that makes "the agent decides at 3am to block an IP and
-- asks permission" possible at all: a chat-card approval lives inside the SSE
-- stream that produced it, so the decision and the thing that would act on it
-- die together when the tab closes. A row here outlives every one of those.
--
-- UNANSWERED NEVER BECOMES EXECUTED. There is no clock in this table that
-- turns silence into an approval. `expired` is the clock and it means one
-- thing: NOT APPROVED AND NOT DENIED, and it did not run. 'denied' and
-- 'expired' are never summed — a person saying no and nobody saying anything
-- are different facts and only one of them is about the request.
--
-- APPROVED IS NOT EXECUTED. It is a decision with a person's timestamp on it,
-- waiting on core/actions.py's worker. A row can sit in 'approved' for as long
-- as it takes, and the executor is reported as BLIND by status() when it is
-- not running, because an approval with nothing behind it is exactly the
-- "decided and nothing happened" shape this whole programme exists to remove.
--
-- THE CLAIM COLUMNS make "exactly once" true: the worker takes a row with an
-- UPDATE that carries `state='approved'` in its WHERE clause, so a second
-- worker updates zero rows. A claim older than core/actions.CLAIM_STALE_SECONDS
-- is treated as abandoned rather than as in-flight forever.
--
-- Kept in sync with core/migrations._migrate_action_queue by hand; there is no
-- code that reads one and writes the other. Change both.
CREATE TABLE IF NOT EXISTS action_request (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- The tool call this would make, and only the parameters that tool
    -- declares. params_json is NARROWED at filing time so the thing that runs
    -- hours later is the thing that was validated, not a superset of it.
    verb            TEXT NOT NULL,
    target          TEXT NOT NULL,      -- the subject; what a denial is
                                        -- remembered against
    params_json     TEXT NOT NULL,
    reason          TEXT,               -- required by write_request, kept
                                        -- nullable so a hand-edited row is
                                        -- visible rather than rejected

    -- WHAT IT RESTS ON. evidence_json is shown on the card. The fingerprint is
    -- what a re-proposal is compared against after a denial (§53.3): a denial
    -- stands until the evidence changes, and this is how "materially new" is
    -- decided without this table guessing what evidence means per verb.
    evidence_json   TEXT,
    evidence_fingerprint TEXT,

    proposed_by     TEXT NOT NULL DEFAULT 'model'
                    CHECK(proposed_by IN ('model','watcher','user')),
    incident_id     INTEGER,            -- the incident this came from, when
                                        -- there is one. Not a FK: an incident
                                        -- being pruned must not delete the
                                        -- record of an action somebody
                                        -- approved.

    state           TEXT NOT NULL DEFAULT 'pending'
                    CHECK(state IN ('pending','approved','denied','executed',
                                    'failed','expired')),
    decided_at      TIMESTAMP,
    decided_by      TEXT
                    CHECK(decided_by IS NULL OR decided_by IN ('user')),
    decision_note   TEXT,

    -- EXECUTION. outcome is separate from state on purpose: 'failed' with
    -- outcome 'refused' is the tool declining with its own reason, and
    -- 'failed' with outcome 'error' is something breaking. They send a reader
    -- to different places and a single 'failed' would lose that.
    claim_at        TIMESTAMP,
    claimed_by      TEXT,
    executed_at     TIMESTAMP,
    outcome         TEXT
                    CHECK(outcome IS NULL OR outcome IN ('success','refused',
                                                         'error',
                                                         'not_attempted')),
    result_json     TEXT,               -- the whole tool envelope, kept
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_action_state   ON action_request(state, id);
CREATE INDEX IF NOT EXISTS idx_action_target  ON action_request(verb, target, state);
CREATE INDEX IF NOT EXISTS idx_action_incident ON action_request(incident_id);


-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- THE DUTY LOOP (v37, T4, 2026-09-18)
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- The agentic half. The watcher (v35) is deterministic and has no model; this
-- is the part that spends tokens: it wakes on two triggers, investigates what
-- the ledger raised, and leaves a readable report. See core/duty.py.
--
-- TWO TRIGGERS, NOT ONE, on the owner's instruction (AGENTIC_PROGRAMME §T4):
--   * emergency  an incident of a kind that cannot wait: a UDP flood, a high
--                volume of packets inbound AND outbound. Runs as soon as the
--                conditions are seen, not at the next scheduled moment.
--   * regular    four moments a day. Each wake-up picks up to two findings
--                from DIFFERENT tools, writes about them, and goes back to
--                sleep.
--
-- WHY A RUN TABLE RATHER THAN LOG LINES. This component is supposed to do
-- nothing most of the time. "It woke and found nothing eligible" and "it was
-- not running" are the same silence on the Agents page and only one of them is
-- a statement about the network. Every tick writes a row either way.
--
-- THE DAILY CEILING IS COMPUTED BY SUMMING THIS TABLE, not from a counter.
-- A counter and a log drift apart, and the one that drifts quietly is the one
-- that lets a runaway spend happen. tokens_estimated says whether the numbers
-- on a row were reported by the provider or derived from character counts.
CREATE TABLE IF NOT EXISTS duty_run (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    ran_at          TIMESTAMP NOT NULL,
    ended_at        TIMESTAMP,

    trigger         TEXT NOT NULL
                    CHECK(trigger IN ('regular','emergency','manual','verify')),

    -- investigated  looked at an incident and wrote a report
    -- reported      gathered a regular report and wrote one
    -- budget        a cap refused it; NOTHING WAS EXAMINED
    -- idle          it woke, looked, and nothing was eligible
    -- error         something broke, and detail says what
    outcome         TEXT NOT NULL
                    CHECK(outcome IN ('investigated','reported','budget',
                                      'idle','error')),

    incident_id     INTEGER,
    report_id       INTEGER,

    tokens_prompt     INTEGER NOT NULL DEFAULT 0,
    tokens_completion INTEGER NOT NULL DEFAULT 0,
    tokens_spent      INTEGER NOT NULL DEFAULT 0,
    tokens_estimated  INTEGER NOT NULL DEFAULT 0,
    model_calls       INTEGER NOT NULL DEFAULT 0,

    coverage_json   TEXT,
    coverage_note   TEXT,

    detail          TEXT,
    duration_ms     INTEGER,

    -- WHAT IT ACTUALLY CALLED. v47, 2026-09-23. The names of the tools the
    -- unattended turn invoked, in order, as a JSON array.
    --
    -- NULL AND '[]' ARE DIFFERENT AND BOTH ARE KEPT. NULL means no unattended
    -- turn ran on this tick (a budget refusal, an idle tick, a row a script
    -- wrote); '[]' means a turn ran and called nothing, which is the ordinary
    -- shape of a report answered from the prompt alone. Collapsing them would
    -- make "it never got that far" and "it looked and needed no tools" the
    -- same value, which this project does not do anywhere else.
    --
    -- THE DEFECT THIS CLOSES: agent_loop.run_unattended collects these names
    -- and hands them back; duty._usage_dict then read the result for tokens
    -- and answers and dropped `tool_calls` entirely. The app could say what
    -- the agent concluded and never what it ran. Nothing is backfilled --
    -- those names were discarded at the time, so there is nothing on disk to
    -- rebuild them from, and every existing row keeps NULL because nobody
    -- recorded it. That is exactly what NULL means here.
    tools_json      TEXT
);

CREATE INDEX IF NOT EXISTS idx_duty_run_at      ON duty_run(ran_at);
CREATE INDEX IF NOT EXISTS idx_duty_run_outcome ON duty_run(outcome, ran_at);


-- What the Agents tab renders. One row per report, carrying the three parts
-- the owner asked to be able to read (hypothesis, evidence, verdict) plus, for
-- a "no action" conclusion, WHAT IT SAW -- because "no action" with nothing
-- behind it is an absence and "I looked at these four things and here is why
-- none of them needed doing" is a claim a person can disagree with.
--
-- kind: 'incident' is the duty loop working an incident from the ledger.
--       'regular' is one of the four scheduled moments, about up to two
--       findings from different tools.
--
-- Nothing backfills this and nothing consumes read_at yet. A report nobody has
-- read and a report somebody read and agreed with are different things, and an
-- NULL read_at is the honest state for the former.
CREATE TABLE IF NOT EXISTS duty_report (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL,

    kind            TEXT NOT NULL CHECK(kind IN ('incident','regular')),
    trigger         TEXT NOT NULL,

    incident_id     INTEGER,
    finding_id      INTEGER,
    second_finding_id INTEGER,

    hypothesis      TEXT,
    evidence        TEXT,
    verdict         TEXT,
    saw             TEXT,
    action_taken    TEXT
                    CHECK(action_taken IS NULL OR action_taken IN
                          ('none','proposed','notified')),

    body            TEXT NOT NULL,

    tokens_spent    INTEGER NOT NULL DEFAULT 0,
    model_calls     INTEGER NOT NULL DEFAULT 0,

    coverage_json   TEXT,
    coverage_note   TEXT,

    read_at         TIMESTAMP,
    read_by         TEXT,

    -- ,,,, v51, 2026-09-25. THE DISMISSAL FLAG, WHICH IS NOT A DELETE.
    --
    -- The owner's instruction: a dismiss button and a checkbox on the agent
    -- reports, plus a dismiss-all, and "those however won't delete the agent
    -- entries from the database". That is the correct instinct and this is how
    -- it is implemented: the report stays, the row stays, the verdict and the
    -- evidence and the coverage note stay, and the page simply stops showing
    -- it. A report written while something was blind is the coverage record of
    -- that moment as well as the agent's conclusion, and deleting either half
    -- would remove the only account of what it saw and what it could not.
    --
    -- NULL means NOBODY HAS DISMISSED THIS, which is not the same as "somebody
    -- read it and agreed" -- that is read_at, and the two are kept apart on
    -- purpose. Nothing is backfilled: every row that predates this column was
    -- never dismissed, which is exactly what NULL says.
    --
    -- The transition is journalled (integrity.record("report_dismissed")), so
    -- "who shortened my Reports list" always has an answer that does not
    -- depend on these columns surviving.
    dismissed_at    TIMESTAMP,
    dismissed_by    TEXT,
    dismissal_note  TEXT
);

CREATE INDEX IF NOT EXISTS idx_duty_report_at   ON duty_report(created_at);
CREATE INDEX IF NOT EXISTS idx_duty_report_kind ON duty_report(kind, created_at);


-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- PORT OWNERSHIP, v51, 2026-09-25. WHICH PROCESS OWNS WHICH PORT.
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
--
-- The owner's instruction: the agent has to be able to say which port relates
-- to which process on this machine, Python has to sweep it on a set interval,
-- and the agent has to be able to drive a pass itself when it wakes to write a
-- report. tools/port_owner.py carries the full design; the schema half is here.
--
-- THE THREE TABLES, AND WHY THE SPLIT IS NOT OVER-ENGINEERING:
--
--   port_owner_sweep   ONE ROW PER PASS. The heartbeat and the coverage.
--                      "Is the sweep running" and "what is listening" are
--                      different questions: an empty listener list with sweep
--                      rows is a machine with nothing open, and an empty
--                      listener list with NO sweep rows is a feature that has
--                      never run. Only the sweep row can tell them apart.
--   port_owner_socket  ONE ROW PER LISTENER IDENTITY (proto, scope, address,
--                      port, pid, exe), carrying first_seen_at, last_seen_at,
--                      seen_count and active. Bounded by construction: an
--                      ordinary desktop has a few dozen, and a row is only
--                      INSERTED when a new listener appears. THIS is what stops
--                      a five-minute sweep writing 8,640 rows a day.
--   port_owner_change  ONE ROW PER TRANSITION. A quiet machine writes nothing
--                      here, and a report reads this table rather than
--                      scanning the socket table for something to say.
--
-- ONLY LISTENERS ARE TRACKED, NOT ESTABLISHED CONNECTIONS. Established sockets
-- churn by the second -- opening one browser tab moves several -- and tracking
-- them would recreate the packets-table growth problem in a second table. The
-- sweep row counts them anyway, because "400 connections, 29 listeners" is a
-- different machine from "29 and 29".
--
-- WHY THESE ARE NOT KEYS IN user_preferences, for the fourth time in this tree:
-- core/integrity hashes that whole table as "the policy" and journals a
-- config_observed entry on ANY difference, on the contract that such an entry
-- always means the rules changed. A sweep that writes its state on a timer
-- would journal that false warning every five minutes, in the one record whose
-- entire value is that it never cries wolf. See references/new-sensor-wiring.md
-- in the skill tree, where this lesson has now been paid for four times.
--
-- NOTHING IS BACKFILLED AND NOTHING CAN BE: the kernel's socket table is live,
-- and a socket that has closed leaves nothing to reconstruct an owner from.
CREATE TABLE IF NOT EXISTS port_owner_sweep (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id              TEXT NOT NULL,
    taken_at                TIMESTAMP NOT NULL,

    sockets                 INTEGER NOT NULL DEFAULT 0,
    listeners               INTEGER NOT NULL DEFAULT 0,
    established             INTEGER NOT NULL DEFAULT 0,

    -- THE FOUR NUMBERS THAT MAKE AN EMPTY LIST READABLE. Measured on this
    -- host, unelevated: 9 of 29 listening sockets could be matched to a
    -- process, because the rest belong to root. A reader who sees only
    -- `listeners` cannot tell "nothing is open" from "I could not read half of
    -- them", so the split travels on every sweep row.
    listeners_with_owner    INTEGER NOT NULL DEFAULT 0,
    listeners_unreadable    INTEGER NOT NULL DEFAULT 0,
    listeners_no_holder     INTEGER NOT NULL DEFAULT 0,
    all_interface_listeners INTEGER NOT NULL DEFAULT 0,

    processes_denied        INTEGER NOT NULL DEFAULT 0,
    duration_ms             INTEGER,

    -- The coverage sentence, rendered once by port_owner.coverage_sentence so
    -- the boot log, the tool payload and the report block cannot describe one
    -- run three different ways.
    note                    TEXT
);

CREATE INDEX IF NOT EXISTS idx_port_owner_sweep_at
    ON port_owner_sweep(taken_at);

CREATE TABLE IF NOT EXISTS port_owner_socket (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- The identity of a listener, deliberately NOT the socket inode: the inode
    -- changes every time the socket is recreated, while pid+exe+bind is what a
    -- person means by "the same listener". The inode is carried anyway so a
    -- socket recreated under an unchanged process is visible to a reader.
    proto           TEXT NOT NULL,
    scope           TEXT NOT NULL CHECK(scope IN ('listen','established')),
    local_address   TEXT NOT NULL,
    local_port      INTEGER NOT NULL,
    remote_address  TEXT,
    remote_port     INTEGER,

    pid             INTEGER,
    -- comm is 15 bytes the PROCESS chose for itself (prctl(PR_SET_NAME));
    -- exe is the kernel's own answer. Both are stored and the payload says
    -- which is which, because this tree already carries a register entry whose
    -- whole paragraph is about reading a self-chosen name as a fact.
    comm            TEXT,
    exe             TEXT,

    -- identified | unreadable_as_user | no_holder_found. THREE facts, never
    -- two: "nothing owns this port" and "the owner is root and this run is not"
    -- are different sentences and only one of them is ever true.
    owner_status    TEXT NOT NULL,
    inode           TEXT,

    first_seen_at   TIMESTAMP NOT NULL,
    last_seen_at    TIMESTAMP NOT NULL,
    seen_count      INTEGER NOT NULL DEFAULT 1,
    active          INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_port_owner_identity
    ON port_owner_socket(proto, scope, local_address, local_port, pid);
CREATE INDEX IF NOT EXISTS idx_port_owner_active
    ON port_owner_socket(active, scope, local_port);
CREATE UNIQUE INDEX IF NOT EXISTS idx_port_owner_unique
    ON port_owner_socket(proto, scope, local_address, local_port,
                         COALESCE(pid, -1), COALESCE(exe, ''),
                         COALESCE(remote_address, ''),
                         COALESCE(remote_port, 0));

CREATE TABLE IF NOT EXISTS port_owner_change (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sweep_id        INTEGER REFERENCES port_owner_sweep(id),
    detected_at     TIMESTAMP NOT NULL,

    -- appeared | disappeared | owner_changed | bind_changed.
    -- owner_changed and bind_changed are computed on the PORT and not on the
    -- row identity, because identity IS pid+exe: a service restart would
    -- otherwise be reported as an arrival plus a departure every single time,
    -- which is the loudest possible way to describe `systemctl restart`.
    kind            TEXT NOT NULL
                    CHECK(kind IN ('appeared','disappeared',
                                   'owner_changed','bind_changed')),

    proto           TEXT,
    scope           TEXT,
    local_address   TEXT,
    local_port      INTEGER,
    pid             INTEGER,
    comm            TEXT,
    exe             TEXT,

    -- The row as it stood BEFORE, for the two kinds where "before" is the
    -- interesting half. NULL on an appearance, which is honest: there was
    -- nothing there.
    previous_json   TEXT,
    note            TEXT
);

CREATE INDEX IF NOT EXISTS idx_port_owner_change_at
    ON port_owner_change(detected_at);
CREATE INDEX IF NOT EXISTS idx_port_owner_change_kind
    ON port_owner_change(kind, detected_at);


-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- LOCAL INTEGRITY BASELINES, v42, 2026-09-22. L3.
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
--
-- The baselines tools/local_integrity.py compares against: what the watched
-- files, the watched directory sets, every home's SSH artifacts, the
-- setuid/setgid/capability sweep and the MAC posture looked like at the last
-- pass that recorded them.
--
-- WHY THIS IS NOT IN user_preferences, WHERE IT STARTED. core/integrity
-- hashes that whole table as "the policy" and journals a config_observed
-- entry on any difference, on the contract that such an entry ALWAYS means
-- the rules changed. A sensor that rewrites a baseline every time a watched
-- file moves would have journalled that false warning on every such pass.
-- MEASURED in the boot log before this table existed: a "the policy in
-- user_preferences has CHANGED" warning carrying six JSON blobs of sudoers,
-- pam and systemd hashes. Same defect as the T2 watcher cursor, whose cleanup
-- core/migrations still carries.
--
-- ONE ROW PER SET, the whole set as JSON. There are six (files, dirs,
-- user_dirs, ssh, sweep, mac) and they are read and written as a unit, so a
-- column-per-field design would be a schema that changes every time a check
-- is added. value_json is OPAQUE to this schema on purpose.
--
-- NOTHING IS BACKFILLED and nothing can be: a baseline is a record of what a
-- file looked like at a moment, and that moment has passed.
CREATE TABLE IF NOT EXISTS local_integrity_baseline (
    name        TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- LAN WATCH BASELINES, v53, 2026-09-26 (register section 13).
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
--
-- The gateway MAC a capture has LEARNED, and the DHCP server set it has
-- LEARNED. Both are baselines that must survive a restart, and both used to
-- live in `user_preferences` -- the table core/integrity.snapshot_config
-- DIGESTS as THE POLICY, journaling a config_observed entry on ANY difference
-- on the contract that such an entry always means the rules changed.
--
-- MEASURED on a scratch database before this table existed, driving the
-- shipped code: the FIRST gateway MAC a capture learns, from a packet and
-- nothing else, moved the policy digest and journalled a false "the policy in
-- user_preferences has CHANGED" warning carrying the MAC. A learned DHCP
-- server did the same; a person's accept moved it again.
--
-- The FIFTH table in this file to carry this argument: ebpf_camera_cursor,
-- local_integrity_baseline, auditd_cursor, feed_cursor, and this one. A table
-- that is not user_preferences cannot be mistaken for policy by anything, and
-- nothing has to remember a key prefix to exclude. The v53 migration MOVES
-- the two old keys into this table and then deletes them; see its docstring
-- for why moved rather than dropped (a learned gateway MAC is real state, and
-- a spoof in progress at the upgrade must not be relearned as trusted).
--
-- ONE ROW PER SET, JSON, OPAQUE to this schema on purpose: the set of
-- baselines is the module's business and a column-per-field design would
-- change the schema every time a check is added. `name` is "gateway_mac" or
-- "dhcp_servers".
CREATE TABLE IF NOT EXISTS lan_baseline (
    name        TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- CASE MEMORY, v43, 2026-09-22.
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
--
-- The patient file. The owner's words: "the agent writes an assessment for
-- every incident and never reads the old ones. Every alert is investigated
-- from a blank page." This is the store that makes a past incident readable
-- while a new one is being worked.
--
-- TWO OBJECTS. case_index is the AUTHORITY: one row per indexed incident,
-- carrying the content hash it was built from, the disposition at the time of
-- indexing, and mirror columns so a ranked result reads without a join per
-- field. case_fts is a STANDALONE FTS5 table, rowid = incident id, holding
-- the searchable text.
--
-- WHY STANDALONE AND NOT content= WITH TRIGGERS. MEASURED: FTS5's own
-- `integrity-check` PASSES on a desynchronised external-content index. A row
-- deleted from incident without the delete trigger firing leaves the index
-- serving a phantom that no check reports, so the index would look verified
-- and be wrong. That is the failure shape this project treats as fatal. The
-- index is written by core/case_memory alone, and the distance between it and
-- the ledger is computed and reported on every read (index_lag), so lag is a
-- visible number rather than a silent gap.
--
-- NOTHING IS BACKFILLED BY THE MIGRATION. The rows are written by
-- case_memory.index_pending on the watcher's tick.
--
-- WHETHER FTS5 EXISTS IS A PROPERTY OF THE SQLITE BUILD, NOT OF THIS SCHEMA,
-- so on a build without it the case_fts CREATE fails and is REPORTED rather
-- than fatal: entity history runs on plain SQL and must keep working.
CREATE TABLE IF NOT EXISTS case_index (
    incident_id   INTEGER PRIMARY KEY,
    indexed_at    TIMESTAMP NOT NULL,
    content_hash  TEXT NOT NULL,
    detection_id  TEXT NOT NULL DEFAULT '',
    entity_type   TEXT NOT NULL DEFAULT '',
    entity_value  TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT '',
    severity_rank INTEGER NOT NULL DEFAULT 0,
    cia_json      TEXT NOT NULL DEFAULT '[]',
    source        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT '',
    status_by     TEXT NOT NULL DEFAULT '',
    assessed      INTEGER NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMP,
    last_seen_at  TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_case_index_rule
    ON case_index(detection_id);

CREATE INDEX IF NOT EXISTS idx_case_index_entity
    ON case_index(entity_type, entity_value);

CREATE VIRTUAL TABLE IF NOT EXISTS case_fts USING fts5(
    subject, title, assessment, detection_id, verdict,
    tokenize='porter unicode61'
);


-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- THE KERNEL CAMERA'S CURSOR, v44, 2026-09-22.
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
--
-- The camera is ebpf/ebpf_monitor.py: a root-confined process that attaches
-- sched_process_exec and sys_enter_connect and writes a SIDECAR file of its
-- own, so that nothing running as root ever opens this database. THIS ROW is
-- the other end of that one-way street: it is how the app running as the
-- operator remembers what it has already analysed.
--
-- WHY IT IS HERE AND NOT IN THE CAMERA'S FILE. The camera's file belongs to a
-- root process and this app must not write to it at all. A cursor written by
-- the reader into the writer's file would be the reader reaching into the
-- privileged side, which is the exact coupling the sidecar design exists to
-- prevent.
--
-- WHY THREE VALUES AND NOT ONE TIMESTAMP. `last_event_id` is the only strictly
-- increasing thing in the camera's table and is what the exec read pages by;
-- `last_event_at` is what survives the camera's file being deleted and rebuilt,
-- where the id sequence starts again; `last_connect_ns` is the kernel
-- monotonic clock the connect window is bounded by, which is NOT comparable to
-- any userspace clock. One number cannot serve all three.
--
-- `seeded_at` NULL MEANS THIS FILE HAS NEVER BEEN ANALYSED, which is the state
-- that produces no findings from a file holding a week of history. It is
-- deliberately distinct from a cursor that has moved: "we have never looked"
-- and "we looked and there was nothing" are different sentences, and this is
-- the column that keeps them apart.
CREATE TABLE IF NOT EXISTS ebpf_camera_cursor (
    name            TEXT PRIMARY KEY,
    last_event_id   INTEGER NOT NULL DEFAULT 0,
    last_event_at   TIMESTAMP,
    last_connect_ns INTEGER NOT NULL DEFAULT 0,
    last_connect_id INTEGER NOT NULL DEFAULT 0,
    seeded_at       TIMESTAMP,
    passes          INTEGER NOT NULL DEFAULT 0
);

-- `last_connect_id` IS NOT a duplicate of `last_connect_ns` and both are
-- needed. v49, 2026-09-23, E-4 in bugfinder.md: the timestamp is the KERNEL'S
-- monotonic clock (bpf_ktime_get_ns, counting from boot) while the id is the
-- camera table's own primary key, and a row can be newer by id and a
-- nanosecond older by timestamp -- which is the ordinary case for anything
-- written while this app is mid-pass. Bounded by the timestamp alone, such a
-- row is skipped FOREVER. The id is the mark this app can actually keep.


-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
-- THE AUDIT LOG'S CURSOR, v45, 2026-09-22.
-- ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
--
-- L4. tools/auditd_monitor.py reads the Linux kernel's own audit log
-- (/var/log/audit/audit.log by default, or wherever auditd.conf says) and
-- this row is its bookmark: a BYTE OFFSET into that file, so a pass reads
-- only what has arrived since the last one.
--
-- IT IS HERE WHETHER OR NOT AUDITD IS INSTALLED, and that is a decision
-- rather than a side effect of the migration chain. This table is part of the
-- shape a fresh install gets, so a machine that later installs auditd --
-- with the one command the sensor prints, `sudo apt install auditd` -- does
-- not ALSO need a schema migration before the reader works. The alternative
-- is a sensor that reports itself broken on the day its source appears, which
-- is the worst possible day for it.
--
-- WHY A TABLE OF ITS OWN AND NOT user_preferences, the same reason
-- ebpf_camera_cursor above has one: `user_preferences` IS the policy,
-- core/integrity.snapshot_config digests it, and it journals a
-- `config_observed` entry on ANY difference on the contract that such an
-- entry always means the rules changed. A bookmark that moves every fifteen
-- seconds would write a false "the policy has CHANGED" warning into the
-- tamper journal forever, in the one record whose whole value is that it
-- never cries wolf.
--
-- `last_offset` IS A BYTE COUNT, not a row id and not a timestamp. auditd
-- only ever APPENDS and it only rotates under its own logrotate rules, and a
-- rotation makes the file shorter than the stored offset -- which the reader
-- DETECTS rather than reading from the wrong place. See read_new()'s rotation
-- branch in the module.
--
-- `seeded_at` NULL MEANS THIS LOG HAS NEVER BEEN READ, which is the state in
-- which nothing may be raised from a file already holding a week of
-- somebody else's history. An offset of zero is a different state from a
-- cursor that has never been written, and this is the column that keeps them
-- apart. Same discipline as ebpf_camera_cursor above and
-- local_integrity_baseline before it.
CREATE TABLE IF NOT EXISTS auditd_cursor (
    name            TEXT PRIMARY KEY,
    last_offset     INTEGER NOT NULL DEFAULT 0,
    last_inode      INTEGER,
    last_record_at  TIMESTAMP,
    seeded_at       TIMESTAMP,
    passes          INTEGER NOT NULL DEFAULT 0,
    records_seen    INTEGER NOT NULL DEFAULT 0
);


-- The feed matcher's bookkeeping. v46, 2026-09-23 (MISP and OTX).
--
-- WHY THIS EXISTS AS ITS OWN TABLE, and it is the FOURTH time this argument has
-- been made in this schema. The feed cursor keys used to live in
-- `user_preferences`, which core/integrity.snapshot_config DIGESTS as the
-- policy and journals a `config_observed` entry on ANY difference on the
-- contract that such an entry always means the rules changed. tools/
-- feed_matcher.match_once advances three cursors on every pass -- every five
-- minutes by default -- so a running matcher wrote a false "the policy has
-- CHANGED" warning into the tamper journal carrying a JSON blob of cursor
-- numbers, in the one record whose whole value is that it does not cry wolf.
-- MEASURED on a copy of the live database before the move (see the module
-- header); the same defect the T2 watcher cursor and the L3 baselines each
-- paid for.
--
-- `value` IS TEXT, not INTEGER, deliberately. Three of the four keys are row
-- counts and one of them (feed_last_result) is a JSON blob recording what the
-- last refresh did per feed, so a reader can answer "why is OTX absent from my
-- table" days later. A column typed INTEGER would force that report through a
-- coercion that silently makes a malformed report look like a valid bookmark.
--
-- NO ROW MEANS THE BOOKMARK HAS NEVER BEEN WRITTEN, which is a different state
-- from a bookmark at zero: the second says the pass has run and reached the
-- start of the table, the first says it has never run at all. That distinction
-- is what stops a first-ever pass scanning every row the app has ever written.
CREATE TABLE IF NOT EXISTS feed_cursor (
    name        TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- The DNS importer's and the DNS inspector's bookkeeping. v54, 2026-09-26.
--
-- WHY THIS EXISTS AS ITS OWN TABLE, and it is the SIXTH time this argument has
-- been made in this schema. Both cursors used to be rows in `user_preferences`,
-- which core/integrity.snapshot_config DIGESTS as the policy and journals a
-- `config_observed` entry on ANY difference, on the contract that such an
-- entry ALWAYS means the rules changed. The importer advances its cursor on
-- every pass -- every fifteen minutes by default -- so a working resolver
-- sensor wrote a false "the policy in user_preferences has CHANGED" warning
-- into the tamper journal carrying nothing but a row number.
--
-- MEASURED on a scratch database, driving the shipped code: one call to
-- dns_monitor._set_cursor("pihole", 1234) moved the digest and produced a
-- config_observed row whose payload was {'dns_import_cursor_pihole': '1234'},
-- and dns_inspector's cursor did the same. The shapes this repeats: the T2
-- watcher cursor, the L3 baselines (v42), the feeds' refresh time (v46), the
-- port-owner tables (v51) and the lan_watch baselines (v53).
--
-- A table rather than a prefix excluded from the digest, for the reason
-- local_integrity's migration gives at length: excluding a key PATTERN would
-- make "the policy" mean "user_preferences except the ones starting with dns_",
-- a rule living in a string comparison that the next person has to know about.
-- A table that is not user_preferences cannot be confused for policy by
-- anything.
--
-- `identity` CARRIES THE SOURCE FILE'S INODE for the AdGuard reader, and it is
-- not decoration. A byte offset cannot tell a grown file from a DIFFERENT one:
-- AdGuard rotates by renaming its log away and starting a new one, and when
-- the new file is already bigger than the stored offset -- the ordinary case
-- on a busy resolver -- the next pass skips its first rows in silence.
-- MEASURED: 3 of 12 rows skipped with no note anywhere. The auditd round
-- carries its source's inode for exactly this reason.
--
-- NO ROW MEANS THE BOOKMARK HAS NEVER BEEN WRITTEN, which is a different state
-- from a bookmark at zero: the second says a pass has run and reached the
-- start of the file, the first says no pass has ever run.
CREATE TABLE IF NOT EXISTS dns_cursor (
    name        TEXT PRIMARY KEY,
    value       TEXT,
    identity    TEXT,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- Background apps: every block or disable is written here before it runs,
-- with the step that undoes each one.
CREATE TABLE IF NOT EXISTS background_change (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    requested_by  TEXT NOT NULL,
    action        TEXT NOT NULL,
    owner_kind    TEXT NOT NULL,
    owner_name    TEXT NOT NULL,
    display_name  TEXT,
    tier          TEXT,
    reason        TEXT,
    steps_json    TEXT,
    state         TEXT NOT NULL,
    error         TEXT,
    finished_at   TEXT,
    undone_at     TEXT,
    undo_reason   TEXT,
    undo_error    TEXT
);

-- BOOTSTRAP: default user preferences
INSERT OR IGNORE INTO user_preferences(key, value) VALUES
    ('silence_timeout_seconds',  '150'),
    ('deviation_alert_threshold', '2.0'),
    ('rollup_interval_minutes',  '60'),
    ('confidence_session_thresholds', '{"low":2,"medium":4,"high":6}'),
    ('alert_suppression_at',     'high'),
    ('max_query_limit',          '500'),
    ('pcap_max_packets',         '10000'),
    ('vpn_required',             '0'),
    ('web_search_enabled',       '1'),
    -- Silence-timer safety rails (added v2, 2026-08)
    ('silence_confidence_cap',    'medium'),  -- ceiling on confidence from silence alone
    ('silence_severity_floor',    'high'),    -- this severity and above is never auto-resolved
    -- REMOVED 2026-08-29: ('suppression_requires_user', '1')
    -- It was seeded here and in migrations.py and read by NOTHING. Setting it
    -- to 0 loosened nothing; reading it as 1 meant trusting a row that had no
    -- effect. Suppression really is gated -- by tool_registry.
    -- suppression_is_requested and the permission card -- so the guarantee
    -- was true and the knob that appeared to provide it was a decoration.
    -- A config key that looks like a control and is not one is the same
    -- defect as the S3(a) port-scan gate, pointed the other way.
    ('log_process_launch_events', '0'),       -- event 4688 is very high volume
    -- Prediction ledger (v31). The cap is per DAY and not per hour on
    -- purpose: this app runs when somebody starts it, so an hourly quota
    -- would give a short session a quota of one and an overnight run a quota
    -- of twelve, which rewards leaving the laptop on rather than thinking
    -- well. min_coverage is how much of a prediction's window the capture has
    -- to have covered before a quiet answer is allowed to count as a hit.
    ('prediction_daily_cap',      '12'),
    ('prediction_min_coverage',   '0.5'),
    -- The question queue (v32). The popup budget is the interruption budget,
    -- not the question budget: questions are unlimited and one popup can
    -- carry several. There is deliberately NO urgency bypass around this. The
    -- model decides what is urgent, and the moment a bypass exists every
    -- question arrives marked important, which is the same as having no
    -- budget at all. If a genuinely urgent case is ever delayed we will have
    -- a real example to design against instead of a guess.
    ('question_popup_daily_cap',   '3'),
    ('question_popup_min_gap_min', '120'),
    ('question_expiry_days',       '10'),
    -- The performance axis (v32). An hour with less capture than this is
    -- painted grey rather than counted, because a thin hour reads as a quiet
    -- device and it is a blind one.
    ('perf_min_coverage_seconds',  '600'),
    -- How many hours of a device's own history are needed before "unusual"
    -- means anything. Under this, the page says it does not know yet.
    ('perf_min_history_hours',     '12'),

    -- SCHEMA VERSION IS SEEDED DELIBERATELY LOW. Read this before "fixing" it.
    --
    -- This file creates the CURRENT shape (v18). Seeding 18 here would make
    -- run_migrations see an up-to-date database and skip every step, which
    -- means a fresh install would depend entirely on this file being perfect
    -- and would get no second chance if it is not. It was not: until
    -- 2026-08-29 this file was missing integrity_journal (v16) and the two
    -- provenance columns (v17), so a database created from it and never
    -- migrated had NO tamper journal at all -- silently, because record()
    -- logs and returns None rather than raising.
    --
    -- Seeding 1 makes migrations run once as a VERIFICATION PASS over a fresh
    -- database. Every step is state-checked and idempotent, so the cost is a
    -- few PRAGMA reads, and the guarantee is that a fresh database and a
    -- migrated one converge on the same schema. That trade is worth taking
    -- every time.
    --
    -- (It said '2' before, which was not a decision -- just a number nobody
    -- revisited after v2.)
    ('schema_version',            '1');

-- v57, the live LAN monitor. See core/migrations._migrate_lan_traffic.
CREATE TABLE IF NOT EXISTS lan_traffic_minute (
    minute        TEXT NOT NULL,
    ip            TEXT NOT NULL,
    mac           TEXT,
    up_bytes      INTEGER NOT NULL DEFAULT 0,
    down_bytes    INTEGER NOT NULL DEFAULT 0,
    up_packets    INTEGER NOT NULL DEFAULT 0,
    down_packets  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (minute, ip)
);
CREATE TABLE IF NOT EXISTS lan_flow (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_ip     TEXT NOT NULL,
    device_mac    TEXT,
    proto         TEXT NOT NULL,
    dst           TEXT NOT NULL,
    dport         INTEGER,
    dst_name      TEXT,
    bytes_out     INTEGER NOT NULL DEFAULT 0,
    bytes_in      INTEGER NOT NULL DEFAULT 0,
    packets_out   INTEGER NOT NULL DEFAULT 0,
    packets_in    INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    sensor_id     TEXT
);
CREATE INDEX IF NOT EXISTS idx_lan_flow_device ON lan_flow(device_ip, last_seen);
CREATE INDEX IF NOT EXISTS idx_lan_flow_dst    ON lan_flow(dst);
CREATE INDEX IF NOT EXISTS idx_lan_flow_seen   ON lan_flow(last_seen);
CREATE INDEX IF NOT EXISTS idx_lan_minute_ip   ON lan_traffic_minute(ip, minute);


-- AUTORUN BASELINE, v58. The autorun monitor's last reading, one row per
-- entry, so an entry that appears, changes or disappears is reported.
CREATE TABLE IF NOT EXISTS autorun_baseline (
    entry_key    TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    name         TEXT,
    path         TEXT,
    fingerprint  TEXT NOT NULL,
    detail       TEXT,
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
