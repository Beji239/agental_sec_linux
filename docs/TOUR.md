# A tour of the dashboard

Start AgentalSec from its launcher in your app menu or on your desktop. If
you have no launcher yet, run `./scripts/install_launchers.sh` once from the
project folder (step 9 of [SETUP.md](../SETUP.md)). The dashboard opens at
http://127.0.0.1:5000. It has 21 tabs. This page goes
through each one: what it shows, how to read it, and what you would do there.

Two habits run through every tab:

- **Quiet and unwatched look different.** An empty table always says why it
  is empty, so you can tell "nothing happened" from "that sensor is off" at a
  glance.
- **Three kinds of knowledge.** Green is measured by a sensor here, blue is
  looked up in a public source, amber is worked out by the model. A finding
  built on a measurement and one built on a guess never look the same.

[Back to the README](../README.md)

## Chat

Talk to the analyst. The buttons above the input are starting points: check
my connections, any intrusions, scan my network, what is on my threat map, run
a full check. Enter sends, Shift+Enter starts a new line.

When the analyst wants to do something that changes your system, an approval
card appears in the conversation. Nothing happens until you press approve. See
[ANALYST.md](ANALYST.md).

## Dashboard

<p align="center">
  <img src="../assets/screenshots/dashboard.png" alt="Dashboard" width="800">
</p>

- **System overview.** Findings this session, packets captured, events
  logged, known devices.
- **Module status.** Every sensor and worker. A green dot is running or
  loaded, red is supposed to work and does not, with the reason underneath.
  In the picture the event monitor reads "blind, seeing nothing" because the
  journal was not readable, and it says so instead of showing zero events.
  A tile with a setting links to its entry on the Settings tab, and says when
  a value saved there waits for a restart.
- **What the tool knows, and how it knows it.** The key to the three colours,
  and which public sources are switched on (blue boxes) or off (grey).
- **Which hosts get contacted, and why each one.** Every address the app
  talks to, grouped by purpose: lookups, the malware and vulnerability lists,
  the model provider, web search, the threat map, your router and network,
  and downloads you start yourself. Each row says what is sent, what comes
  back and why. A row that needs a key links straight to its field in
  Settings.

## Alerts

<p align="center">
  <img src="../assets/screenshots/alerts.png" alt="Alerts" width="800">
</p>

Active findings this session, newest first. Each has a severity, a one line
title and the measurement behind it, written so you can check it. Dismiss
hides a finding from this list, and Dismiss All does that for every finding
shown.

## Timeline

Everything the app recorded, in time order: findings, events, port scans,
device sightings and packets. Its purpose is the question "what else was
happening at the same time". Choose a window of 2 hours up to 7 days. Packets
far outnumber everything else, so the window is cut into equal slices and
each slice keeps its share of rows. The line above the list says how much was
not shown. Tick "findings and events only" to hide packets.

Each row says who recorded it, which sensor and session, and why it is there.

## Network

- **Network devices.** Everything this machine can see on the local network:
  address, your label, type, identity, the **basis** for that identity,
  hardware address, vendor, hostname, last seen. Read the basis before
  trusting a label, most identities are inferred from vendor prefixes and
  announcements, not proven. Scan Network runs a presence sweep. After a scan,
  rows flash green if you have named them and red if unrecognised. NEW marks a
  device that was not there at the previous scan.
- **Router view.** With the router agent: what the router says is on the
  network. A device that ignores ping still shows here because the router
  exchanged its traffic. NOT SEEN HERE marks a device the router talks to that
  no sensor on this machine has ever seen, a gap in coverage.
- **Router settings.** The router's DNS, DHCP and gateway settings as last
  read. CHANGED marks a value that differs from the one recorded before.

## Inventory

Your enrolment list. You are the authority on what belongs on your network,
and this is where you say so.

- **Name** a device and the analyst stops guessing what it is.
- **Mark it permanent** if it should always be present. Its absence then
  becomes a question instead of being ignored.
- **Merge** two rows that are one device with several addresses.

Only devices with a stable hardware address are listed. Phones and newer
laptops that invent a new private address per network are counted in the
"transient" tile instead, since marking one permanent would not stick. To
list your own phone, turn off "private Wi-Fi address" for this network on the
phone and scan again.

## Live LAN

With the router agent enrolled: every device on the network with its upload
and download right now, totals, open connections and a two minute graph.
Select a device to see where it is talking to now, its recent DNS lookups and
its finished connections. From here you can block an app for one device, or
block a destination for the whole network. Both ask for approval. See
[ROUTER.md](ROUTER.md).

## Threat Map

<p align="center">
  <img src="../assets/screenshots/threat_map.png" alt="Threat map" width="800">
</p>

*The map with the panel open for one address: where it is, the network that
owns it, the names seen for it, the device that reached it and whether that
country is usual for it, its alerts, and the actions. Sample data.*

Where your home's connections go. Each circle is an external address, and
its colour comes from the alerts recorded about it, never from the country.
The white pin is home, placed from your public address or, when that is off
or contradicts your timezone, from the timezone. The map and its database are
local, the page loads nothing from the internet. Locations are approximate,
see the limitations in the README.

**Whole home or this machine.** The map covers the last 24 hours, and a
restart does not empty it. This machine's own traffic is always on it, with
the program behind each connection. With the router agent, the other devices
in your home are added too, each line named by device. Without a router agent the map still shows every
destination this machine reached, and says the rest of the home is not
covered. The menu above the map shows the whole home, this machine only, the
other devices only, or only the places with an alert.

**Click a point** to open its panel: where it is, the network company that
owns it (with the optional ASN database, `scripts/fetch_geoip.py --asn`), the
names seen for it, which programs and devices reached it, whether that is a
place each of them usually goes, and every alert about it. The panel offers:

- **Block** the address: at the router for every device when the router
  agent is there, otherwise on this machine only.
- **Cut off** a device that reached it, at the router.
- **Block a domain** seen for it, at the router's resolver.
- **Chat about this**, which opens a small chat window you can drag anywhere
  on the screen and resize from its corner. The analyst is given what the app
  recorded about that address, and each address keeps its own conversation,
  separate from the Chat tab. Approval cards work there as in the Chat tab.

Router actions are greyed out without the router agent, and hovering says
why. Every action asks for a reason and is recorded.

<p align="center">
  <img src="../assets/screenshots/threat_map_chat.png" alt="Threat map chat window beside the panel for one address" width="800">
</p>

*Chat about this, dragged next to the panel. The panel shows a GEO-1001
alert: a program reached a country it does not usually reach. The analyst
starts from what the app recorded about this address. Sample data.*

## Ports

TCP and UDP port scan results. Enter a host, pick a set (common, extended or
all 65,535 ports) and press Scan Host. Scans of hosts outside your own network
ask for approval first.

- **UDP has three answers.** A row means the port replied. An ICMP
  unreachable means nothing listens. Silence means neither, and is never
  shown as closed.
- **Scope.** A self-scan proves a service is listening on this machine, not
  that anyone can reach it. A remote scan across the network does measure
  reachability.
- **Repeats** of the same open port are collapsed into one row with a count.
  Tick "every scan" to see each observation.

## Processes

- **Background apps you can switch off.** Services, timers and login apps
  worth acting on, each with a tier and a reason. "Safe to block" means
  nothing leans on it. "Block, do not disable" means other things talk to it,
  so only its network is cut. Disable stops it and keeps it from starting
  again. Every change is recorded with an Undo.
- **Running processes.** Everything running, from the kernel's process table.
  Green means the executable still matches the digest its package recorded at
  install. Amber means no package owns it, ordinary for things you built
  yourself, worth a look in a temporary folder. Faint grey is a kernel thread.
  Press inspect on a row for the full hash, the owning package and whether
  that exact file is known to public malware databases.

## PCAP

Import a capture file taken somewhere else and analyse it. You are asked where
it came from, in your own words, and that note is stored as your claim about
the file so it is not read with the same weight as this machine's own
traffic.

## Behavioral

The baselines the tool has learned: for every address, process, port and
user, what it usually does and how confident the tool is (low after 2
sessions, medium after 4, high after 6). Below them, recent deviations: about
two steps from usual is a note, three or more is an alert.

## Performance

Traffic per device per hour, for the last day, two days or week, coloured
against that device's own normal: usual, well above, well below, not enough
history, or not measured because nothing was watching that hour. Performance
signals this tool does not collect are listed by name rather than shown as
zero.

## Predictions

The analyst's own record. It makes guesses with deadlines and the app grades
them afterwards: right, wrong, or could not check when the app was closed for
most of the window. The hit rate counts only right and wrong.

## Detections

<p align="center">
  <img src="../assets/screenshots/detections.png" alt="Detections" width="800">
</p>

*The guide at the top, then each rule in plain words, with the exact
condition opened under Technical detail on the first row and a Mute button
on every rule. Sample data.*

Everything the app knows how to spot. Each row is a rule, not an alert: when
what the rule watches for happens, it raises an alert on the Alerts tab and its
count here goes up.

How to read a row:

- **Rule** is its permanent name. The letters say which part of the app raises
  it (PKT network traffic, LAN devices on your network, DNS name lookups, FED
  public threat lists, GEO new countries and networks, LNX this machine, AUD
  the audit log, AV the virus scanner, NET and PRB device checks, RTR the
  router, PRC running programs, REM records of what the app did). Names are
  never reused, so an old alert always points at the rule that raised it.
- **Version** goes up when the rule's logic changes. Each alert remembers the
  version that raised it.
- **What it watches for** says it in plain words. **Technical detail** opens
  the exact condition.
- **Watched by**, **Severity** and **Times fired** say which part of the app
  runs it, how serious its alerts can be, and how many it has raised (open
  ones in brackets).
- **Muted** says whether you switched it off. **Mute** stops one rule for one
  address or for every address, with a reason you write; **Unmute** brings it
  back. Nothing is deleted.

When the Alerts tab is quiet, it means one of three things: nothing happened,
no rule here covers it, or the rule that covers it is muted. This tab tells
them apart. The analyst reads the same list and can see what you muted, but
only you can mute. Rows marked Record are a trail of what the app did, such as
blocking a device, and cannot be muted. Hover any column heading for its
meaning.

## Questions

What the analyst wants to ask you, such as whether a device is yours. Answer
here and the answer is used from then on. Questions nobody answers retire
after a while and are listed as such, never quietly treated as yes.

## Actions

Approval cards waiting on you, and the record of everything already decided:
ran, did not run, you denied, nobody answered. An approved action is carried
out once by the executor, outside any chat. The executor's own state is shown
here, because if it is not running an approved card would never run.

## Agents

What the duty loop did while nobody was asking. Its reports, newest first,
each with a verdict, the evidence and a note of what it could see at the time.
Below them, every wake-up, including the ones that found nothing to do, and
the reason: idle, or stopped by a budget. "Wake it now" starts a round by
hand. Dismissing a report only hides it here, it deletes nothing.

## Review

Everything silenced, in one place.

- **Blinding budget.** How many things the analyst has dismissed today
  against its daily limit. Your own dismissals are shown, never limited.
- **Dismissed entities.** Addresses, processes and devices that are dropped
  before a finding is ever raised, with who dismissed them and why. At most
  100 stand; the oldest expires when a new one is added.
- **Suppressed baselines.** Behaviour that is still recorded but no longer
  alerts.

If the chat and this tab disagree about what is silenced, this tab is right.

## Runbook

The CISA catalogue of known exploited vulnerabilities, with a CVSS severity
for each, searchable and filterable. Sync CISA KEV fetches the latest list,
Fetch CVSS fills in scores. A row here is a vulnerability that exists in the
world, not a finding about your machines.

## Settings

- **Model provider.** Endpoint, model and key, with a check that the
  provider answers and knows the model.
- **What is on, what is off, and why.** Every collector: green running, amber
  switched off or not configured, red supposed to work and not working, each
  with its reason.
- **Stop AgentalSec.** The same clean stop as Ctrl+C in the terminal, for
  when the terminal is out of reach.
