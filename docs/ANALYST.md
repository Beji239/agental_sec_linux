# The AI analyst

The analyst is a language model with tools for reading everything AgentalSec
has recorded. You talk to it on the Chat tab. It also works on its own, on a
schedule, while you are away. This page covers connecting a model, what the
analyst can and cannot do, how approval works, and how to get good answers
from it.

[Back to the README](../README.md)

## Connecting a model

Everything except the analyst runs without a model. To turn it on, set three
things, on the Settings tab or by hand:

- `provider.api_url` in `config.json`: the provider's chat endpoint. Either an
  OpenAI-style endpoint (`.../v1/chat/completions`) or an Anthropic-style one
  (`.../v1/messages`). `provider.api_style` is `auto` by default and reads the
  style from the address; set it to `openai` or `anthropic` to force one.
- `provider.model` in `config.json`: the model's id at that provider.
- `AGENTAL_API_KEY` in `.env`: the provider's key.

Any hosted provider works, as does a gateway that fronts many providers.

**A local model.** Point `provider.api_url` at a local OpenAI-compatible
server, such as Ollama, LM Studio, vLLM or SGLang, and put whatever key that
server expects in `AGENTAL_API_KEY`, or any placeholder if it checks none.
Nothing the analyst reads then leaves your network.

The Settings tab checks the connection: whether the provider answers, and
whether it knows the model you named.

## How much is sent per question

Every question sends the analyst's instructions and its tool list, then the
conversation, then whatever its tools return. The tool list alone is roughly
49,000 tokens, and 16,384 are held back for the answer
(`provider.max_output_tokens`).

- `provider.context_budget` caps how much is sent per question. The template
  sets 128,000. Remove it and the budget follows the model's own context
  window, as reported by the provider. The app never sends more than the
  model's real window.
- A budget too small for the tool list cannot work. The app refuses the
  question before sending anything and names the minimum, currently about
  81,000 tokens. With a local model, this means a context length of at least
  that much.
- Wide questions such as "run a full network analysis" need more room than
  narrow ones. If a turn stops at the context ceiling, ask about one part at a
  time or raise the budget.

Each turn also has a limit of 25 tool rounds and ten minutes, not counting
time spent at an approval card. When a limit stops a turn, the reply says
which one.

## What it can read

About a hundred tools, in these groups:

- **Findings, incidents and alerts**, with the evidence behind each.
- **Network:** packets, conversations, DNS lookups and answers, TLS server
  names, the threat map, threat feed matches, port scans, LAN protocol
  checks, payload captures, imported pcap results.
- **Devices:** known devices, presence over time, identity and its basis,
  drift, inventory gaps, the router's clients and settings.
- **This machine:** processes, listeners and their owners, services, startup
  entries, installed software, file integrity, audit and eBPF records, logs,
  VPN state, host details.
- **Behaviour:** baselines, deviations and sessions.
- **Lookups:** enrichment of an address, domain, CVE, hardware prefix or file
  hash, the CISA KEV runbook, and web search when a key is set.
- **Its own record:** past reports, case memory, its predictions and their
  score, your answers to its questions.
- **The app itself:** sensor health, database size, and its own source code,
  so it can explain how a finding was produced.

Every tool does one narrow, clearly defined thing. By design there is no
shell and no way to run arbitrary commands, so you always know exactly what
the analyst can do.

## What needs your approval

These tools never run without you:

- `kill_process`, `stop_service`
- `block_port`, `unblock_port`, `block_device`, `unblock_device` (firewall,
  through nftables)
- `quarantine_file`, `restore_file`
- `disable_background_app`, `block_background_app`, `undo_background_change`
- `gateway_block_device`, `gateway_unblock_device`,
  `gateway_sinkhole_domain`, `gateway_unsinkhole_domain`,
  `adopt_router_hostname` (on the router)
- `arm_payload_capture` (saving payloads for a target)
- `dismiss_entity` (silencing an address, process or device)

Changes to baselines that would suppress alerts also need approval. Port scans
of hosts outside your own network need approval; scans of your own network do
not.

**How approval works.** The analyst files a request. It appears as a card in
the chat and on the Actions tab, and as a desktop notification
(`action_queue.notify`). You approve or deny. An approved request is carried
out once by the executor, a worker outside any chat, so an approval still
holds if you close the tab. A card nobody answers expires after ten days
(`action_queue.expiry_days`). The Actions tab keeps the full record.

Firewall changes and ending processes need root. Run the privileged launcher,
or install the root action helper (see [SETUP.md](../SETUP.md)) so the app
stays unprivileged and only approved actions run as root.

## Working while you are away

**Incident watcher.** A plain rule engine, with no model and no cost. Every
minute it groups new findings at or above medium severity into incidents, up
to 40 a day. Config: `incident_watcher`.

**Duty loop.** The analyst wakes on its own:

- at once when an emergency condition, such as a flood, is seen;
- at four regular times a day (`duty_loop.wake_hours`, by default 9, 13, 17
  and 21 local time), when it investigates up to two open findings from
  different tools and writes a report.

It is capped at three investigations an hour and a daily token ceiling
(`duty_loop.daily_token_ceiling`); when a cap is reached it examines nothing,
records why once, and waits until the budget allows work again instead of
retrying every minute. In an investigation, long tool results are capped and
results from earlier rounds are shortened, because every call resends the
whole conversation. It works with a smaller set of mostly read-only tools, and
anything that would change your system becomes a request on the Actions tab,
exactly as in the chat. Every change still goes through you. Its reports,
and every wake-up including the ones that found nothing to do, are on the
Agents tab. Set `duty_loop.enabled` to `false` to turn it off.

## How it keeps itself honest

- **It says what it could not see.** Every answer names the sensors that were
  blind at the time, and tells "zero rows because nothing happened" apart
  from "zero rows because of a limit".
- **Three kinds of knowledge.** Measured, looked up and worked out are kept
  apart in answers and in the dashboard's colours.
- **It asks you.** When it needs something only you know, it files a question
  on the Questions tab instead of guessing. Unanswered questions retire, they
  are never treated as yes.
- **It is graded.** It makes predictions with deadlines, and the app checks
  them. The hit rate is on the Predictions tab.
- **Case memory.** Before working on an incident it reads what the app
  already knows about the subject and what happened the last times something
  looked like it.
- **Blinding budget.** The analyst may dismiss at most 10 things in any 24
  hours, and at most 100 dismissals stand at once. Every dismissal goes into
  the tamper journal, and the Review tab shows them all with who made them.

## Asking good questions

- **Ask neutrally.** "What is 192.0.2.10?" gets a better answer than "that is
  my printer, right?". The analyst tends to agree with what you assert.
- **Name devices you own** on the Inventory tab instead of telling the chat.
  A label there is the strongest evidence the app holds, and it stops the
  analyst re-guessing every session.
- **Ask about one thing at a time** when a wide question hits the context
  ceiling.
- **Ask how it knows.** It can show the measurement, the lookup or the code
  behind any finding.
