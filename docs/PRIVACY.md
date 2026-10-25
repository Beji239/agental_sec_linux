# Privacy and security

AgentalSec runs on your own computer and answers only on it. I never took that
as a reason to relax. Every other program on this machine, every other account
on it, and every web page your browser opens is treated as a possible
stranger. This page lists what is in place against each of them.

[Back to the README](../README.md)

## Your data stays on this machine

- The database, `config.json`, `.env` and the logs live in the project folder.
  The database and `config.json` are readable by your account only, and the
  app narrows them again at every start in case something widened them.
- `.env` is created owner only before the first byte is written, so there is
  no moment when another account could read it.
- The logs are readable by you only, in a folder only you can open.
- Each module keeps its data in a folder only you can open. The phones paired
  with Remote manager are stored owner only, like the main database.
- The kernel camera and the names helper write to `/var/lib/agental_sec`.
  Root writes there, your account can read it, and no other account can even
  list it. New files there get your group and stay closed to everyone else.
  The services start with a umask that keeps every file they create private.
- Nothing is sent anywhere unless it is listed under
  [What leaves the machine](#what-leaves-the-machine). There is no telemetry.

## Secrets

- Keys live in `.env`, never in `config.json`, so `config.json` is safe to
  share when you ask for help.
- Stored secrets are encrypted. The key is a SHA-256 of this machine's ID,
  your account and a salt, so a copied `.env` does not open on another
  computer or under another account.

## The dashboard answers this machine only

- The dashboard listens on 127.0.0.1, the loopback address. Nothing on your
  network can reach it.
- If you ever bind it wider, it warns you unless you also name the hosts it
  may answer to.
- Every request is checked for the host it names. A request aimed at any
  other name is refused, so a web page cannot use a trick like DNS rebinding
  to reach the dashboard through your browser. Cross origin requests are
  allowed from the dashboard's own address only.
- Modules reach the app on 127.0.0.1, even when the dashboard listens on
  every address.
- To use the dashboard from another computer, use an SSH tunnel (see
  [SETUP.md](../SETUP.md)). That keeps it on loopback and encrypts the way in.

## Signing in

- Every API call needs the app key. The key is compared in constant time, so
  timing tells a guesser nothing.
- Ten wrong keys inside a minute lock that caller out for a minute. A correct
  key is never counted, so the dashboard can never lock you out.
- The page itself holds no key. When the app opens your browser it uses a
  one time link that works once, for two minutes. The link goes through a
  private page in your own runtime folder, deleted after two minutes, so it
  never shows up in the process list where other accounts could read it.
- Your browser then keeps a session for 30 days. Links and sessions are
  signed with HMAC SHA-256 from the app key; a forged or spent one just lands
  on the sign in box.

## The page in your browser

- The page runs no script but its own. A strict Content Security Policy with
  a fresh nonce on every load blocks anything injected, and the page cannot
  be framed by another site, post a form anywhere, or load plugins.
- Isolation headers keep other sites' pages away from it, and camera,
  microphone, location, USB and screen capture are switched off for it.
- API answers are never cached and send no referrer.

## Hashes that make tampering visible

- Every high value write, such as a finding, a baseline or a rule change, is
  added to a hash chained journal. Change one row and every hash after it
  breaks. Copy the newest hash somewhere else (a file on another device, or a
  photo of it), and even a rebuilt chain gives itself away.
- The local integrity sensor hashes the files that decide who gets in, such
  as sudoers, SSH keys and startup files, and tells you when one changes.
- Remote manager stores pairing codes as SHA-256 hashes only, and a code
  expires after 15 minutes. PINs and panic words are kept only as scrypt
  hashes, and the authenticator keys are encrypted with a key bound to this
  machine and your account.

## Every part has only the rights it needs

The app runs as you, not as root. Each right sits with one small part. The
three services are fenced in by systemd: no new privileges, a read only view
of the system and a private temporary folder.

- **Capture service.** Runs as your account with only the two network
  capabilities packet capture needs.
- **Names helper.** No network at all, and two capabilities.
- **Kernel camera.** Root with only the capabilities eBPF needs, no network,
  and a read only view of the system.
- **Read helper.** Runs through `sudo` for a fixed list of reads. None of
  them takes an argument, and there is no "read this file" at all. The code
  that parses what it reads never runs as root.
- **Action helper.** Runs through `pkexec` for actions you approved, and only
  those. It imports nothing from the project folder and runs Python isolated,
  so no file your account can write is ever run as root.

## Hostile text stays text

A process name, a host name, a DNS name or a packet can be chosen by an
attacker.

- Before anything reaches the logs, control characters and terminal escape
  codes are stripped, so outside text cannot forge a log line or drive your
  terminal.
- Before anything reaches the model, it passes a trust boundary and arrives
  fenced. The model is told it is evidence to look at, never an instruction.
- Anything that changes your system, such as a kill, a block or a
  quarantine, waits for your approval. No exceptions.

## Your router and other machines

The router and your other Linux machines are reached over SSH, with a list of
known keys that belongs to AgentalSec alone.

- The router login refuses any key it does not already know, so a machine
  pretending to be your router is not trusted.
- Other Linux machines trust the first key they see and refuse a changed one
  after that. Once all your machines are known, set `strict_host_key` to
  `true` and an unknown one is refused too (see [ROUTER.md](ROUTER.md)).

## Remote manager

Off by default. Switched on, it runs as its own small process and opens no
port.

- It talks to Telegram outward, over HTTPS with the certificate checked, by
  asking for new messages. Telegram never connects in.
- It reads the app over 127.0.0.1 with a token that is new on every run.
- The Remote tab talks to it over a private socket file that only your
  account can open.
- Only people you pair can use it. Anyone else gets no answer.
- Nothing secret is ever sent in plain, because Telegram can read bot chats.
  The alerts it does send pass through Telegram's servers.
- With private messages set up for a person, what goes to them is sealed
  with AES-256-GCM and a key only this computer and their phone hold. The
  key goes from the screen to the phone by QR code, never through Telegram,
  and is kept in the phone's secure storage (Keychain or Keystore) and here
  encrypted like the authenticator keys. Telegram sees scrambled text and
  how urgent the message is. The reader page that opens it loads nothing
  from anywhere and cannot send anything out. What the person types to the
  bot is not sealed.
- Deciding from the phone needs a PIN and an authenticator code. The
  authenticator key is shown once, at the computer, and never goes through
  Telegram. The bot deletes a PIN, a code or the panic word from the chat as
  soon as it has read it.
- Chat from the phone is off until you turn it on. A question goes to the
  model like one typed at the computer, and the answer comes back through
  Telegram, so the agent is told never to put a key, a password or the
  contents of a file in it. From the phone it can only read and file
  requests. The conversation is kept in memory only and forgotten when
  control ends. Numbers alone, typed when nothing asked for a PIN, are
  deleted and never reach the model.

## What leaves the machine

- **Your questions to the analyst**, together with the data its tools read,
  go to the model you configure. With a local model server, nothing the
  analyst reads leaves your network.
- **Threat feeds and lookup services**, to check addresses and names.
- **A public address lookup** that places the threat map's home pin. Turn it
  off with `geoip.locate_online` in `config.json`.
- **The update check**, once a day to GitHub's release page. You can switch
  it off on the Settings tab.
- **Telegram**, only with Remote manager switched on.
- **The reader page**, fetched only when you press **Check the page** in
  the Remote tab, to compare it with the copy that came with the module.

## What no local tool can promise

A program already running as root on this machine can read anything here,
this app included. These measures make sure nothing else can, and the hash
chain makes sure that changes to the record show, even when they cannot be
prevented.
