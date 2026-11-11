# mailhub-mirror

`ghcr.io/worph/mailhub-mirror`: the mail side of the Yundera store's **MailHub** app. Every provider mailbox
as a local copy in MailHub's Dovecot, the provider staying the source of truth.

The app itself (compose, Dovecot config with the Lua hook that records IMAP actions, setup scripts) lives in
the store: `Yundera/AppStore` → `Apps/MailHub`. The webmail, whose *Settings → Mail accounts* page writes
the account files this reads, is [worph/mailhub-roundcube](https://github.com/worph/mailhub-roundcube); the test
kit (`dev/accounts-test.py` covers the mirror end to end) is in [worph/mailhub](https://github.com/worph/mailhub),
where this image was built up to 0.4.1 (history kept here).

## What it does

One mailbox per MailHub user: the owner, `admin`, plus every user in the registry the webmail keeps
(`/users/<name>.json`, one per signed-in identity; mailhub-roundcube's `mailhub_sso`). For each account
file a user's page writes (`/accounts/<user>/<slug>.json`):

- **pull**: mbsync, pull only, into `Live/<address>/` (Maildir). Never writes to the provider; folders are
  never removed. One worker per account, every `MAILHUB_SYNC_INTERVAL` seconds (120), or at once when the
  accounts change or the page touches `/accounts/.sync-now`.
- **replay**: the IMAP actions done on `Live/` folders (recorded by the store's Dovecot Lua hook in
  `live-queue/events.jsonl`) become the same command at that provider: flags, append, expunge of that one UID,
  create / rename, delete only if empty there. Nothing is inferred. A move between two folders of one account
  (Dovecot records the message added there, with its Message-ID, then expunged here) is one `UID MOVE` at the
  provider (`COPY` + expunge without MOVE), so the provider keeps its own message: on Gmail, where a folder
  is a label, archiving changes the label and a move to `[Gmail]/Trash` is a real delete, where `APPEND` +
  `EXPUNGE` made a second copy and left the first in All Mail. A message added to a `Live/` folder waits a few
  seconds for that expunge, then is appended as before. Folders the replay touched are pulled once per batch.
  Before 0.7.0 a pull ran after each appended message and renamed the other messages of the same move, so a
  move of several messages into an account folder appended only the first and expunged them all at the
  provider: the others stayed only in this server's copy, as files `.mbsyncstate` does not pair.
  Dovecot copies by hard link and keeps the file name, the source folder's `,U=<n>` included, so a copied
  message is never taken for a mirrored one by its name (0.8.0 did when that number was paired in the
  destination too: the copy was skipped and the source still expunged). A provider connection dropped while
  idle is reopened once before a replayed action counts as failed.
- **views**: `Merged/All inboxes`, `Unread`, `Flagged`, `Trash`, `Junk` and `Archive` (Dovecot virtual folders) rewritten from the
  accounts and folders that exist, minus accounts with `"in_views": false`; new `Live/` and `Merged/` folders
  subscribed. (Named `Virtual/` before 0.4.1: those subscriptions are dropped.) `All inboxes`, `Trash` and `Junk` also cover the local
  `INBOX`, `Trash` and `Junk`, and save there what is moved into the view (the `!` line), so the webmail can
  use `Merged/Trash` and `Merged/Junk` as its Trash and Junk. `Archive` covers each account's `Archive` (or `Archives`)
  folder and its subfolders, plus the local `Archive` (created if missing); archived mail is left out of `Unread`.
  A folder created through Dovecot (the webmail archiving into an account that had no Archive) is added to the views
  as soon as its CREATE is replayed.
- **status**: `/state/<user>/status/<slug>.json` for the Mail accounts page, with the download progress.
- **idle**: IMAP IDLE on each account's INBOX at the provider (one more connection per account): new mail wakes
  that account's worker for an INBOX-only pull at once, instead of at the next interval. `MAILHUB_IDLE=0` turns
  it off; a server without IDLE just keeps the polling.
- **push**: Web Push (VAPID, RFC 8291 encryption, `webpush.py`) to the devices each user turned on in the
  webmail's *Settings → Notifications* (`/accounts/<user>/.push.json`, written by mailhub-roundcube's
  `mailhub_push`). After each pull, the account's INBOX messages above its high-water mark
  (`/state/<user>/push-hwm.json`) still unread become a notification: sender and subject (or a count only, with
  *show sender and subject* off), one summary for more than 3; muted accounts are skipped. The first download
  and the first sync without a mark (an upgrade) only set the mark, so nothing old is announced. A test request
  (`.push-test.json`) is answered in `/state/<user>/push-status.json`, which also holds each device's last
  delivery or failure, `gone` after a 404/410. The server key is made once in `/state/.push/` (`vapid.json`,
  0600; `vapid-public.txt` for the webmail). The payload is encrypted for the device: the push service (FCM,
  Mozilla, Apple) only relays it.
- **users**: the device logins (IMAPS, CalDAV/CardDAV). `/srv/vmail/.mailhub-passwd`, the passwd-file the
  store's Dovecot config checks, is rendered from the registry's `{SSHA512}` hashes plus the owner's
  `MAILHUB_PASSWORD`; each registry user gets a Baïkal account (user, principal, one calendar, one address
  book) with its digest, in Baïkal's SQLite (`/baikal/db/db.sqlite`); `/state/<user>/device-applied` says
  which digest is in effect. The owner's Baïkal account is the store's `baikal-init` step's.

Dovecot is reached as each user through its master login (SASL PLAIN, authzid = the user,
`MAILHUB_MASTER_PASSWORD`). Before 0.5.0 there was one user and the files were `/accounts/<slug>.json` and
`/state/{status,run}/`: moved under `admin/` at start. A user removed from the registry stops syncing; their
mail stays on disk.

An account file removed stops its worker and deletes this server's copy (never the provider's).

Settings: `MAILHUB_MASTER_PASSWORD` (Dovecot's master login), `MAILHUB_PASSWORD` (the owner's device
login), `MAILHUB_IMAP_HOST` / `_PORT` (`mailhub-imap:31143`), `MAILHUB_SYNC_INTERVAL`, `MAILHUB_IDLE` (1),
`MAILHUB_PUSH_SUBJECT` (the VAPID contact: the app's `https://` URL or a `mailto:`), `MAILHUB_VMAIL_UID`
(1000), `MAILHUB_WEB_UID` (33, the webmail's user, for the moved account folder), `MAILHUB_BAIKAL_DB`.
The device logins are also written to `/state/.submit/passwd` for mailhub-submit (below).
Mounts: `/srv/vmail`, `/accounts` (read-write for the one-time move), `/state`, `/users` (ro), `/baikal`. Runs as root to read the webmail's
private account files; mbsync runs as the mailbox owner. Details in `mirror.py`'s docstring.

## mailhub-submit (`submit.py`)

The same image, run as a second service (`entrypoint: [/sbin/tini, --, python3, -u, /usr/local/bin/submit.py]`):
one SMTP login for mail apps. A phone or desktop client sets up MailHub as one account, IMAPS 993 and SMTP
465 (or 587) on the same host with the same device login, and every address the user connected in *Mail
accounts* sends from it, each through its own provider with that account's login.

- **Ports**: 31465 implicit TLS, 31587 STARTTLS (required before AUTH); the IMAPS certificate in `/tls`.
  AUTH PLAIN / LOGIN only.
- **Login**: the device login, checked against `/submit/passwd`, the copy of Dovecot's passwd-file this mirror
  writes in `/state/.submit/`. Dovecot is never asked, so its master login cannot be reached from this port.
  A PLAIN authorization id other than the user is refused, and so is a name that isn't a local user. Failed
  logins back off per client IP (5 in 10 min, then 1, 2, 4… up to 15 min).
- **Sender**: `MAIL FROM` must be one of the user's account addresses, and the `From:` header that same single
  address, else `550 5.7.1`. The provider is chosen from that address only. An account file without
  `smtp_host` (written before mailhub-roundcube 0.8.0) is refused with "open Mail accounts and save it again".
- **Relay**: synchronous, nothing queued. The provider is connected at `MAIL FROM`, each `RCPT` gets its
  answer, and its reply to `DATA` is the client's (2xx / 5xx kept, anything else 4xx), the account named in
  the text. The provider transaction has 90 s at most. Nothing is saved: clients keep their sent copy in
  the local Sent, as the webmail does.
- **Limits**: `MAILHUB_SUBMIT_DAILY_RCPT` recipients per user per 24 h (500), `MAILHUB_SUBMIT_MAX_SIZE` (25 MB).
- **Log**: one line per message (user, account, recipients, size, provider code); never a subject, body or
  password.
- Settings: `APP_TLS_HOST` (the name in the greeting), `MAILHUB_SUBMIT_BUDGET` (90),
  `MAILHUB_SUBMIT_CONNECT_TIMEOUT` (20). Mounts, read-only: `/accounts`, `/submit`, `/tls`.

Tests: `tests/test_submit.py` against an in-process fake provider, run in the image (CI does):

```sh
docker build -t mailhub-mirror . && \
docker run --rm -v "$PWD/tests:/tests:ro" --entrypoint python3 mailhub-mirror -m unittest discover -s /tests -v
```

## Building and releasing

```sh
docker build -t mailhub-mirror .
```

CI (`.github/workflows/build.yml`) builds amd64 + arm64 on every push and PR. Pushing a tag `vX.Y.Z`
publishes `ghcr.io/worph/mailhub-mirror:X.Y.Z` (and `X.Y`); then bump its tag in the store's
`Apps/MailHub/docker-compose.yml`. Versions continue from worph/mailhub: 0.4.1 was the last one built there.
