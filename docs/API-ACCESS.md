# API access and dashboard approvals

## Two separate credentials

`AGENTAL_APP_API_KEY` permits authenticated GET and HEAD requests. It is the
credential to give a read-only integration. It cannot change settings, approve
or deny an action, start an update, manage a module, sign a dashboard session,
or exchange itself for one.

`AGENTAL_DASHBOARD_KEY` signs dashboard sessions and one-time opening links.
It is generated and saved privately at startup when absent. Keep it private,
including from integrations. The app opens the dashboard with a one-time link;
the browser keeps its session, not the key.

For example, an imaginary monitoring script could read findings like this:

```bash
curl -H 'X-API-Key: replace-with-your-read-only-key' \
  http://127.0.0.1:5000/api/findings
```

This is an example only. No real credential belongs in source code, logs,
screenshots, or a shared command history. Each credential still relies on
private filesystem access. Programs running as the same account may be able
to read that account's files.

## Updating from 2.8.1 or earlier

The old application key becomes read-only. Scripts using it for POST requests
will receive 403. Existing dashboard sessions end once when the new private
signing key is created. If automatic browser opening is enabled, the first
update restart opens a new signed-in tab. Otherwise, sign in with `AGENTAL_DASHBOARD_KEY` from the private
`.env` file, or let the app open a new dashboard link on its next normal start.
The sign-in box names the key it needs. Do not paste a provider key or the
read-only integration key there.

The updater still discovers published GitHub releases and installs only after
you press Update. This release changes the privileged action helper, so allow
the helper refresh when the updater requests a password. A refused refresh
is reported as unfinished, with the command to complete it. The helper must
match the new project code for the SSH and cron file protections to apply.
Configuration, credentials, and the database remain local and are not replaced
by the published source.

## Decision records

Queued action decisions record their source, dashboard or paired phone, in
the stored decision note and integrity journal. Phone decisions also retain
the enrolled person's name. Live dashboard approval decisions are journalled.
An integration cannot label itself as the user through a read key.

## Verification scope

The stored-text tests build migrated disposable databases and enumerate their
tables. Every application table must have a valid fixture. SQLite internals
and full text shadow storage are identified explicitly. Remote module tables
are inventoried in their own database. Reader tests use fake module adapters
and block outbound connections; this tests the data boundary, not native
sensor behavior or whether a model can resist every instruction in text.

Browser tests run selected original renderers in Chromium without relying on
CSP to stop injected markup. They cover approval cards, queued requests,
reports, run rows, and update information. They do not claim every dashboard
interaction has been tested.

The SSH and cron helper opens parent directories without following symlinks,
uses pinned directory handles for replacement, refuses intervening edits and
multiple hard links, and bounds text reads and writes. A deliberately
symlinked parent directory is refused. These checks do not make concurrent
edits by the file's owner impossible, and the helper does not claim it can
control changes made by other programs after the operation finishes.

Quarantine and restore also use pinned parent directories. Restored file
ownership and permissions are applied to the open file descriptor, so a
changed pathname cannot redirect those changes to another file.

Tool errors and attached sensor-failure details are scrubbed and returned as
untrusted data too. Host information and stored map summaries receive the
same protection as other observation-derived results.
