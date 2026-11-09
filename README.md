# mailhub-mirror

`ghcr.io/worph/mailhub-mirror`: the mail side of the Yundera store's **MailHub** app. Every provider mailbox
as a local copy in MailHub's Dovecot, the provider staying the source of truth.

The app itself (compose, Dovecot config with the Lua hook that records IMAP actions, setup scripts) lives in
the store: `Yundera/AppStore` → `Apps/MailHub`. The webmail, whose *Settings → Mail accounts* page writes
the account files this reads, is [worph/mailhub-roundcube](https://github.com/worph/mailhub-roundcube); the test
kit (`dev/accounts-test.py` covers the mirror end to end) is in [worph/mailhub](https://github.com/worph/mailhub),
where this image was built up to 0.4.1 (history kept here).

## What it does

For each account file (`/accounts/<slug>.json`):

- **pull**: mbsync, pull only, into `Live/<address>/` (Maildir). Never writes to the provider; folders are
  never removed. One worker per account, every `MAILHUB_SYNC_INTERVAL` seconds (120), or at once when the
  accounts change or the page touches `/accounts/.sync-now`.
- **replay**: the IMAP actions done on `Live/` folders (recorded by the store's Dovecot Lua hook in
  `live-queue/events.jsonl`) become the same command at that provider: flags, append, expunge of that one UID,
  create / rename, delete only if empty there. Nothing is inferred.
- **views**: `Merged/All inboxes`, `Unread`, `Flagged`, `Trash`, `Junk` and `Archive` (Dovecot virtual folders) rewritten from the
  accounts and folders that exist, minus accounts with `"in_views": false`; new `Live/` and `Merged/` folders
  subscribed. (Named `Virtual/` before 0.4.1: those subscriptions are dropped.) `All inboxes`, `Trash` and `Junk` also cover the local
  `INBOX`, `Trash` and `Junk`, and save there what is moved into the view (the `!` line), so the webmail can
  use `Merged/Trash` and `Merged/Junk` as its Trash and Junk. `Archive` covers each account's `Archive` (or `Archives`)
  folder and its subfolders, plus the local `Archive` (created if missing); archived mail is left out of `Unread`.
  A folder created through Dovecot (the webmail archiving into an account that had no Archive) is added to the views
  as soon as its CREATE is replayed.
- **status**: `/state/status/<slug>.json` for the Mail accounts page, with the download progress.

An account file removed stops its worker and deletes this server's copy (never the provider's).

Settings: `MAILHUB_USER` (`admin`), `MAILHUB_PASSWORD` (to subscribe folders), `MAILHUB_IMAP_HOST` / `_PORT`
(`mailhub-imap:31143`), `MAILHUB_SYNC_INTERVAL`, `MAILHUB_VMAIL_UID` (1000). Runs as root to read the webmail's
private account files; mbsync runs as the mailbox owner. Details in `mirror.py`'s docstring.

## Building and releasing

```sh
docker build -t mailhub-mirror .
```

CI (`.github/workflows/build.yml`) builds amd64 + arm64 on every push and PR. Pushing a tag `vX.Y.Z`
publishes `ghcr.io/worph/mailhub-mirror:X.Y.Z` (and `X.Y`); then bump its tag in the store's
`Apps/MailHub/docker-compose.yml`. Versions continue from worph/mailhub: 0.4.1 was the last one built there.
