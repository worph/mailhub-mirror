"""MailHub mirror: every provider mailbox as a local copy, the provider staying the truth.

One local mailbox per MailHub user: the owner, `admin`, plus every user in the
registry the webmail keeps (/users/<name>.json, one per signed-in identity). For each
account file a user's Mail accounts page writes (/accounts/<user>/<slug>.json):

  pull     mbsync, Sync Pull only, into ~/live/<address>/ (Maildir). Never writes to
           the provider; folders are never removed (Remove None). A worker per account,
           every MAILHUB_SYNC_INTERVAL seconds, or at once when the accounts change.
  replay   Dovecot's Lua push notification (mailhub-replay.lua) appends every IMAP
           action to ~/live-queue/events.jsonl. Actions on Live/<address>/ folders
           become the same command at that provider: flags -> UID STORE, message added
           -> APPEND, message removed -> UID EXPUNGE of that one UID, folder created /
           renamed -> CREATE / RENAME, folder deleted -> DELETE only if empty there.
           Nothing is inferred: no recorded action, no change at the provider. A local
           message is tied to its provider UID by mbsync's own pairing (",U=<n>" in the
           file name + the folder's .mbsyncstate); an action on a message mbsync has
           not paired yet waits in pending.jsonl, in order per folder.
           A move between two folders of one account (Dovecot: added there, with its
           Message-ID, then expunged here) is one UID MOVE at the provider, not APPEND
           + EXPUNGE: the provider keeps its own message, and on Gmail, where a folder is
           a label, a move to [Gmail]/Trash is a real delete instead of a second copy
           while the first stays in All Mail. A message added to a Live/ folder waits up
           to PAIR_WAIT s for that expunge, then is APPENDed as before. Folders touched
           by the replay are pulled once the batch is done: a pull in the middle renamed
           the messages of the same move still to be replayed (mbsync numbers what it
           finds), so before 0.7.0 a move of several messages APPENDed only the first
           and expunged them all at the provider.
  views    Merged/All inboxes, Unread, Flagged, Trash, Junk and Archive (Dovecot virtual
           folders) are rewritten from the accounts and folders that exist, leaving out the
           accounts set to stay out of them ("in_views": false in the account file),
           and new Live/ and Merged/ folders are subscribed (the webmail lists
           subscribed folders). Before 0.4.1 the views were under Virtual/: those
           subscriptions are dropped. All inboxes, Trash, Junk and Archive include the
           local INBOX, Trash, Junk and Archive and save into them (what is moved to the
           view). Archive covers each account's Archive (or Archives) folder and its
           subfolders, which are left out of Unread (archived = out of the way).
  status   /state/<user>/status/<slug>.json for the Mail accounts page, with the
           download progress while a sync runs.
  idle     IMAP IDLE on each account's INBOX at the provider (MAILHUB_IDLE, on by
           default): new mail there wakes the account's worker for an INBOX-only pull
           at once. A server without IDLE keeps the polling.
  push     Web Push to the devices a user turned on in the webmail (Settings →
           Notifications, /accounts/<user>/.push.json): after each pull, the INBOX
           messages above the account's high-water mark (/state/<user>/push-hwm.json,
           the highest UID seen) still unread become a notification (sender + subject,
           or only a count with show_content off; more than 3 at once: one summary).
           The first download and the first sync with no mark only set the mark.
           A test request (.push-test.json, {nonce, device}) is answered in
           /state/<user>/push-status.json, with each device's last delivery or failure
           (`gone` once the push service answers 404/410). The VAPID key is made once
           in /state/.push/ (vapid.json private, vapid-public.txt for the webmail);
           MAILHUB_PUSH_SUBJECT is its contact (the app's https URL).

  users    The device logins (IMAPS, CalDAV/CardDAV): /srv/vmail/.mailhub-passwd, the
           passwd-file Dovecot checks, rendered from the registry's hashes plus the
           owner's MAILHUB_PASSWORD (also copied to /state/.submit/passwd for mailhub-submit,
           submit.py, which checks the SMTP logins against it); and each registry user's Baïkal account (user,
           principal, one calendar, one address book) with its digest. The owner's
           Baïkal account is the store's baikal-init step's. /state/<user>/device-applied
           holds the digest in effect, for the webmail's own calendar connection.

An account removed from the page stops syncing and its local copy is deleted (only
this server's copy; nothing is deleted at the provider). A user removed from the
registry stops syncing; their mail stays on disk.

Dovecot is reached as each user through its master login (SASL PLAIN, authzid = the
user, MAILHUB_MASTER_PASSWORD), the user's own password being nowhere here.

Before 0.5.0 there was one user and the files were /accounts/<slug>.json and
/state/{status,run}/: moved under admin/ at start.

Runs as root to read the webmail's private account files; mbsync runs as the
mailbox's owner (MAILHUB_VMAIL_UID) and every file it creates belongs to it.
"""
import base64, email.parser, email.policy, hashlib, imaplib, json, os, re, select, shutil, sqlite3, ssl, subprocess, threading, time

import webpush

OWNER = "admin"
OWNER_PASSWORD = os.environ.get("MAILHUB_PASSWORD", "")
MASTER_PASSWORD = os.environ.get("MAILHUB_MASTER_PASSWORD", "")
MASTER_NAME = "mailhub-mirror"
IMAP_HOST = os.environ.get("MAILHUB_IMAP_HOST", "mailhub-imap")
IMAP_PORT = int(os.environ.get("MAILHUB_IMAP_PORT", "31143"))
INTERVAL = int(os.environ.get("MAILHUB_SYNC_INTERVAL", "120"))
VMAIL = int(os.environ.get("MAILHUB_VMAIL_UID", "1000"))
# Web Push: the VAPID subject (the app's https URL, or a mailto:) and IMAP IDLE on each INBOX
PUSH_SUBJECT = os.environ.get("MAILHUB_PUSH_SUBJECT", "")
IDLE_ON = os.environ.get("MAILHUB_IDLE", "1") != "0"
IDLE_RENEW = 25 * 60  # RFC 2177: re-issue IDLE before the server's 29-minute cut
WEB_UID = int(os.environ.get("MAILHUB_WEB_UID", "33"))  # the webmail's www-data
ACCOUNTS = "/accounts"
STATE = "/state"
USERS = "/users"
VMAIL_ROOT = "/srv/vmail"
PASSWD = f"{VMAIL_ROOT}/.mailhub-passwd"
# the same device logins for mailhub-submit (submit.py), which mounts only this folder
SUBMIT_DIR = f"{STATE}/.submit"
SUBMIT_PASSWD = f"{SUBMIT_DIR}/passwd"
BAIKAL_DB = os.environ.get("MAILHUB_BAIKAL_DB", "/baikal/db/db.sqlite")
BAIKAL_REALM = "BaikalDAV"
PUSH_DIR = f"{STATE}/.push"  # vapid.json (private, 0600) + vapid-public.txt (the webmail reads it)
VAPID = None  # webpush.Vapid, set in main()
# a local user name: also a Dovecot home (/srv/vmail/<name>) and a Baïkal principal
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")

# a move inside one account: its expunge is paired with the added message when written within
# PAIR_WINDOW s of it; a message added to a Live/ folder waits up to PAIR_WAIT s for that expunge
PAIR_WINDOW, PAIR_WAIT = 60, 4
SYSTEM_FLAGS = {"\\Seen", "\\Flagged", "\\Answered", "\\Draft", "\\Deleted"}
MAILDIR_FLAG = {"D": "\\Draft", "F": "\\Flagged", "R": "\\Answered", "S": "\\Seen", "T": "\\Deleted"}
# left out of the Unread and Flagged views (compared case-insensitively, last path part)
NOT_IN_VIEWS = {"trash", "deleted items", "deleted messages", "bin", "junk", "spam", "bulk mail",
                "drafts", "sent", "sent items", "sent messages", "sent mail", "all mail", "important", "starred"}
# an account's Trash and Junk, by the folder's last path part (Gmail: [Gmail]/Trash, [Gmail]/Spam)
TRASH_NAMES = {"trash", "deleted items", "deleted messages", "bin"}
JUNK_NAMES = {"junk", "spam", "bulk mail"}
# an account's archive, by the folder's first path part (Archive/2024 included)
ARCHIVE_NAMES = {"archive", "archives"}
# Gmail's label views would download every message again
GMAIL_SKIP = ["[Gmail]/All Mail", "[Gmail]/Important", "[Gmail]/Starred", "[Google Mail]/All Mail",
              "[Google Mail]/Important", "[Google Mail]/Starred"]


def log(*a):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), *a, flush=True)


def own(path, uid=VMAIL):
    os.chown(path, uid, uid)


def makedirs(path, mode=0o700, uid=VMAIL):
    os.makedirs(path, mode=mode, exist_ok=True)
    own(path, uid)


def q(name):
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def imap_as(user):
    """An IMAP session on the local Dovecot as `user`: its master login (SASL PLAIN with
    authzid), or, without a master password (an older compose), the owner's own."""
    m = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
    if MASTER_PASSWORD:
        m.authenticate("PLAIN", lambda _: f"{user}\0{MASTER_NAME}\0{MASTER_PASSWORD}".encode())
    elif user == OWNER and OWNER_PASSWORD:
        m.login(user, OWNER_PASSWORD)
    else:
        m.shutdown()
        raise RuntimeError("no MAILHUB_MASTER_PASSWORD to log in as " + user)
    return m


def atomic_write(path, text, mode, uid):
    tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    own(tmp, uid)
    os.replace(tmp, path)


# ------------------------------------------------------------------ users ---

def load_users():
    """The registry the webmail writes: {name: entry}. The owner is always there."""
    users = {OWNER: {"local": OWNER}}
    for fn in sorted(os.listdir(USERS)) if os.path.isdir(USERS) else []:
        if not fn.endswith(".json") or fn.startswith("."):
            continue
        name = fn[:-5]
        try:
            u = json.load(open(os.path.join(USERS, fn)))
            if not NAME_RE.fullmatch(name) or u.get("local") != name:
                raise ValueError("bad user name")
            users[name] = u
        except Exception as e:
            log("skipping user file", fn, repr(e))
    return users


def ssha512(password):
    salt = os.urandom(8)
    return "{SSHA512}" + base64.b64encode(hashlib.sha512(password.encode() + salt).digest() + salt).decode()


class Provisioner:
    """Dovecot's passwd-file and the registry users' Baïkal accounts, redone when the
    registry (or the owner's password) changes."""

    def __init__(self):
        self.seen_passwd, self.seen_dav, self.owner_hash = None, None, None

    def run(self, users):
        try:
            self.passwd(users)
            self.baikal(users)
            self.applied(users)
        except Exception as e:
            log("device logins / calendar & contacts accounts failed:", repr(e))

    @staticmethod
    def applied(users):
        """/state/<user>/device-applied: the Baïkal digest now in effect, so the webmail
        connects its calendar only once the new password works there (a few seconds
        after the user is created or their password replaced)."""
        for n, u in users.items():
            digest = u.get("dav_digest", "")
            if n == OWNER or not digest:
                continue
            path = f"{STATE}/{n}/device-applied"
            try:
                if open(path).read() == digest:
                    continue
            except OSError:
                pass
            os.makedirs(f"{STATE}/{n}", exist_ok=True)
            os.chmod(f"{STATE}/{n}", 0o755)
            atomic_write(path, digest, 0o644, 0)

    def passwd(self, users):
        sig = (OWNER_PASSWORD, tuple(sorted((n, u.get("device_hash", "")) for n, u in users.items() if n != OWNER)))
        if sig == self.seen_passwd and os.path.exists(PASSWD) and os.path.exists(SUBMIT_PASSWD):
            return
        if self.owner_hash is None and OWNER_PASSWORD:
            self.owner_hash = ssha512(OWNER_PASSWORD)
        lines = [f"{OWNER}:{self.owner_hash}"] if self.owner_hash else []
        for n, u in sorted(users.items()):
            h = u.get("device_hash", "")
            if n != OWNER and re.fullmatch(r"\{SSHA512\}[A-Za-z0-9+/=]+", h):
                lines.append(f"{n}:{h}")
        text = "".join(l + "\n" for l in lines)
        atomic_write(PASSWD, text, 0o600, VMAIL)
        os.makedirs(SUBMIT_DIR, mode=0o700, exist_ok=True)
        os.chmod(SUBMIT_DIR, 0o700)
        atomic_write(SUBMIT_PASSWD, text, 0o600, 0)
        self.seen_passwd = sig
        log("device logins:", ", ".join(l.split(":", 1)[0] for l in lines) or "none")

    def baikal(self, users):
        want = {n: u for n, u in users.items() if n != OWNER and re.fullmatch(r"[0-9a-f]{32}", u.get("dav_digest", ""))}
        sig = tuple(sorted((n, u["dav_digest"], u.get("name", ""), u.get("email", "")) for n, u in want.items()))
        if sig == self.seen_dav or not want:
            self.seen_dav = sig
            return
        if not os.path.exists(BAIKAL_DB):
            # not created yet (the store's baikal-init step does it): next round
            raise RuntimeError(f"{BAIKAL_DB} not there yet")
        db = sqlite3.connect(BAIKAL_DB, timeout=30)
        try:
            with db:
                for n, u in want.items():
                    if db.execute("SELECT COUNT(*) FROM users WHERE username = ?", (n,)).fetchone()[0]:
                        db.execute("UPDATE users SET digesta1 = ? WHERE username = ? AND digesta1 != ?",
                                   (u["dav_digest"], n, u["dav_digest"]))
                        continue
                    p = f"principals/{n}"
                    db.execute("INSERT INTO users (username, digesta1) VALUES (?, ?)", (n, u["dav_digest"]))
                    db.execute("INSERT INTO principals (uri, email, displayname) VALUES (?, ?, ?)",
                               (p, u.get("email") or None, u.get("name") or n))
                    db.execute("INSERT INTO principals (uri, email, displayname) VALUES (?, NULL, NULL)", (f"{p}/calendar-proxy-read",))
                    db.execute("INSERT INTO principals (uri, email, displayname) VALUES (?, NULL, NULL)", (f"{p}/calendar-proxy-write",))
                    cid = db.execute("INSERT INTO calendars (synctoken, components) VALUES (1, 'VEVENT,VTODO')").lastrowid
                    db.execute("INSERT INTO calendarinstances (calendarid, principaluri, access, displayname, uri, description, "
                               "calendarorder, calendarcolor, timezone, transparent) VALUES (?, ?, 1, 'Calendar', 'default', "
                               "'Default calendar', 0, '#3a87ad', NULL, 0)", (cid, p))
                    db.execute("INSERT INTO addressbooks (principaluri, displayname, uri, description, synctoken) "
                               "VALUES (?, 'Contacts', 'default', 'Default address book', 1)", (p,))
                    log("calendar & contacts account created for", n)
        finally:
            db.close()
        self.seen_dav = sig


# --------------------------------------------------------------- mailbox ---

class Mailbox:
    """One local user's mirror: their accounts, workers, replay queue and views."""

    def __init__(self, user):
        self.user = user
        self.home = f"{VMAIL_ROOT}/{user}"
        self.live, self.live_index, self.live_control = f"{self.home}/live", f"{self.home}/live-index", f"{self.home}/live-control"
        self.qdir = f"{self.home}/live-queue"
        self.queue, self.offset, self.pending_file, self.failed = (
            f"{self.qdir}/events.jsonl", f"{self.qdir}/offset", f"{self.qdir}/pending.jsonl", f"{self.qdir}/failed.jsonl")
        self.virtual = f"{self.home}/virtual"
        self.accounts = f"{ACCOUNTS}/{user}"
        self.state = f"{STATE}/{user}"
        self.run_dir = f"{self.state}/run"  # generated mbsync configs and password files, owned by VMAIL, 0700
        self.views_lock = threading.Lock()
        # (email, box, dovecot uid) -> mbsync near uid, so an expunge can be resolved
        self.snap = {}
        # uidlist path -> (inode, mtime_ns, size) when last read. The replay loop calls
        # snapshot() every 2 s; re-parsing every folder's uidlist each time (tens of
        # thousands of lines on a few big accounts) kept a core a quarter busy, while
        # a uidlist only changes when mail arrives, moves or is expunged.
        self.snap_seen = {}
        # (slug, box, provider uid) -> Message-ID, to pair a move's two halves (provider_move)
        self.mid_cache = {}
        # (slug, folder) -> account: folders to pull after the current replay batch
        self.repull = {}
        self.workers = {}
        self.seen, self.seen_views, self.nudge = None, None, 0
        self.push = Push(self)
        self.stopped = False

    def log(self, *a):
        log(f"[{self.user}]", *a)

    def setup(self):
        for d in (self.home, self.live, self.live_index, self.live_control, self.qdir, self.virtual):
            makedirs(d)
        if not os.path.exists(self.queue):
            open(self.queue, "a").close()
        own(self.queue)
        os.chmod(self.queue, 0o600)
        os.makedirs(f"{self.state}/status", exist_ok=True)
        os.chmod(self.state, 0o755)
        os.chmod(f"{self.state}/status", 0o755)
        threading.Thread(target=self.replay_loop, daemon=True).start()
        self.refresh_views()

    # ----------------------------------------------------------- accounts ---

    def load_accounts(self):
        accs = {}
        for fn in sorted(os.listdir(self.accounts)) if os.path.isdir(self.accounts) else []:
            if not fn.endswith(".json") or fn.startswith("."):
                continue
            try:
                a = json.load(open(os.path.join(self.accounts, fn)))
                a["slug"] = fn[:-5]
                if not re.fullmatch(r"[a-z0-9._-]+", a["slug"]) or "@" not in a.get("email", "") or "/" in a["email"]:
                    raise ValueError("bad slug or address")
                accs[a["slug"]] = a
            except Exception as e:
                self.log("skipping account file", fn, repr(e))
        return accs

    def write_status(self, slug, **s):
        s.setdefault("at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        d = f"{self.state}/status"
        os.makedirs(d, exist_ok=True)
        tmp = f"{d}/.{slug}.tmp"
        with open(tmp, "w") as f:
            json.dump(dict(account=slug, **s), f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, f"{d}/{slug}.json")

    def mbsync_config(self, a):
        """Write the account's mbsync config (pull only) and password file; return the config path."""
        makedirs(self.run_dir)
        passfile, conf = f"{self.run_dir}/{a['slug']}.pass", f"{self.run_dir}/{a['slug']}.mbsyncrc"
        with open(passfile, "w") as f:
            f.write(a["pass"])
        os.chmod(passfile, 0o600)
        own(passfile)
        root = f"{self.live}/{a['email']}"
        patterns = "*" + "".join(f' !"{p}"' for p in GMAIL_SKIP)
        tls = "IMAPS" if a.get("imap_security", "ssl") == "ssl" else ("STARTTLS" if a.get("imap_security") == "tls" else "None")
        lines = [
            "# Generated by mailhub-mirror from the Mail accounts page. Pull only:",
            "# nothing here writes to the provider.",
            f"IMAPAccount {a['slug']}",
            f"Host {a['imap_host']}",
            f"Port {int(a['imap_port'])}",
            f"TLSType {tls}",
            # an unencrypted server (set so on purpose on the page): mbsync wants it said
            *(["AuthMechs LOGIN"] if tls == "None" else []),
            f"User {a['user']}",
            f"PassCmd \"cat {passfile}\"",
            "CertificateFile /etc/ssl/certs/ca-certificates.crt",
            "PipelineDepth 10",
            "",
            f"IMAPStore {a['slug']}-far",
            f"Account {a['slug']}",
            "",
            f"MaildirStore {a['slug']}-near",
            f"Path {root}/",
            f"Inbox {root}/INBOX",
            "SubFolders Verbatim",
            "",
            f"Channel {a['slug']}",
            f"Far :{a['slug']}-far:",
            f"Near :{a['slug']}-near:",
            f"Patterns {patterns}",
            "Create Near",
            "Remove None",
            "Expunge Near",
            "Sync Pull",
            "SyncState *",
            "CopyArrivalDate yes",
            "",
        ]
        with open(conf, "w") as f:
            f.write("\n".join(lines))
        os.chmod(conf, 0o600)
        own(conf)
        makedirs(root)
        return conf

    def count_local(self, email):
        n = 0
        for dirpath, dirnames, filenames in os.walk(f"{self.live}/{email}"):
            if os.path.basename(dirpath) in ("cur", "new"):
                n += len(filenames)
        return n

    def run_mbsync(self, a, box=None, worker=None):
        conf = self.mbsync_config(a)
        target = a["slug"] + (f":{box}" if box else "")
        p = subprocess.Popen(["mbsync", "-c", conf, target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             user=VMAIL, group=VMAIL, env={"HOME": self.run_dir, "PATH": "/usr/bin:/bin"})
        if worker is not None:
            worker.proc = p
        out, err = p.communicate()
        return subprocess.CompletedProcess(p.args, p.returncode, out, err)

    def warm_index(self, a):
        """Have Dovecot full-text index the account's new mail now. mbsync writes Maildir
        files directly, so nothing is indexed on arrival; without this the first search
        in a big new mailbox would index it all while the user waits (and other searches
        answer INUSE meanwhile). A search triggers the indexing (fts_search_add_missing)
        and the indexer goes on with it after the search gives up."""
        try:
            m = imap_as(self.user)
            for f in self.live_folders(a["email"]):
                if m.select(q(prefix_of(a) + f), readonly=True)[0] == "OK":
                    m.search(None, "BODY", '"mailhub-index-warm-up"')  # NO [INUSE] is fine
            m.logout()
            self.log(a["slug"], "full-text indexing started")
        except Exception as e:
            self.log(a["slug"], "full-text warm-up:", repr(e))

    # -------------------------------------------------------------- views ---

    def live_folders(self, email):
        """Folder names (relative to the account) of the local copy: dirs holding cur/."""
        root, out = f"{self.live}/{email}", []
        for dirpath, dirnames, filenames in os.walk(root):
            if "cur" in dirnames and dirpath != root:
                out.append(os.path.relpath(dirpath, root))
            for skip in ("cur", "new", "tmp"):
                if skip in dirnames:
                    dirnames.remove(skip)
        return sorted(out)

    def refresh_views(self):
        with self.views_lock:
            accs = self.load_accounts()
            # "!" marks where a message moved into the view is saved (the local folder):
            # Roundcube's Trash and Junk are Merged/Trash and Merged/Junk.
            inboxes, rest, with_sent = ["!INBOX"], ["INBOX"], ["INBOX"]
            trash, junk, archive = ["!Trash"], ["!Junk"], ["!Archive"]
            for a in accs.values():
                if a.get("in_views") is False:
                    continue
                folders = self.live_folders(a["email"])
                for f in folders:
                    name = prefix_of(a) + f
                    base = f.split("/")[-1].lower()
                    if f == "INBOX":
                        inboxes.append(name)
                    if base in TRASH_NAMES:
                        trash.append(name)
                    if base in JUNK_NAMES:
                        junk.append(name)
                    archived = f.split("/")[0].lower() in ARCHIVE_NAMES
                    if archived:
                        archive.append(name)
                    if base not in NOT_IN_VIEWS and not archived:
                        rest.append(name)
                    if base not in NOT_IN_VIEWS or base in ("sent", "sent items", "sent messages", "sent mail"):
                        with_sent.append(name)
            views = {"All inboxes": (inboxes, "all"), "Unread": (rest, "unseen"), "Flagged": (with_sent, "flagged"),
                     "Trash": (trash, "all"), "Junk": (junk, "all"), "Archive": (archive, "all")}
            makedirs(self.virtual, 0o700)
            for view, (boxes, rule) in views.items():
                d = f"{self.virtual}/{view}"
                makedirs(d)
                text = "\n".join(boxes) + f"\n  {rule}\n"
                path = f"{d}/dovecot-virtual"
                if not os.path.exists(path) or open(path).read() != text:
                    with open(path, "w") as f:
                        f.write(text)
                    own(path)
                    self.log("view", view, "now covers", len(boxes), "folders")
            self.subscribe_all()

    def subscribe_all(self):
        try:
            m = imap_as(self.user)
            # Merged/Archive saves what is moved into it in the local Archive, which the
            # stock config does not create (it does Trash and Junk)
            if not (m.list('""', "Archive")[1] or [None])[0]:
                self.log("create local Archive:", m.create("Archive")[0])
            names = set()
            for pat in ("Live/*", "Merged/*"):
                for line in m.list('""', pat)[1] or []:
                    if line and b"\\Noselect" not in line:
                        names.add(line.decode().rsplit(' "/" ', 1)[-1].strip('"'))
            subscribed = set(l.decode().rsplit(' "/" ', 1)[-1].strip('"') for l in (m.lsub('""', "*")[1] or []) if l)
            for n in sorted(names - subscribed):
                m.subscribe(q(n))
                self.log("subscribed", n)
            for n in sorted(n for n in subscribed if n.startswith("Virtual/")):  # the views' name before 0.4.1
                m.unsubscribe(q(n))
                self.log("unsubscribed", n)
            m.logout()
        except Exception as e:
            self.log("subscribe failed:", repr(e))

    def forget(self, slug, email):
        self.push.forget(slug)
        """An account removed from the page: delete this server's copy (never the provider's)."""
        for d in (f"{self.live}/{email}", f"{self.live_index}/{email}", f"{self.live_control}/{email}"):
            if email and os.path.isdir(d) and os.path.realpath(d).startswith(self.home + "/live"):
                shutil.rmtree(d)
        for f in (f"{self.run_dir}/{slug}.pass", f"{self.run_dir}/{slug}.mbsyncrc", f"{self.state}/status/{slug}.json"):
            if os.path.exists(f):
                os.remove(f)
        self.log("removed", email, "(local copy deleted; nothing changed at the provider)")

    # ------------------------------------------------------------- replay ---

    def far_of_near(self, a, box, near):
        try:
            with open(f"{self.live}/{a['email']}/{box}/.mbsyncstate") as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 2 and p[0].isdigit() and p[1] == str(near):
                        return int(p[0])
        except FileNotFoundError:
            raise Wait(box)
        raise Wait(f"{box} near {near}")

    def local_file(self, a, box, uid):
        ul = f"{self.live_control}/{a['email']}/{box}/dovecot-uidlist"
        base = None
        with open(ul) as f:
            for line in f:
                p = line.rstrip("\n").split(" ", 1)
                if p[0] == str(uid) and len(p) > 1 and ":" in p[1]:
                    base = p[1][p[1].index(":") + 1:]
                    break
        if base is None:
            return None
        for sub in ("cur", "new"):
            d = f"{self.live}/{a['email']}/{box}/{sub}"
            for fn in os.listdir(d):
                # or renamed by mbsync, which gives a near UID to a message it finds in its
                # folder (base + ",U=<n>"): a pull of this folder ran since Dovecot wrote it
                if fn == base or fn.startswith(base + ":") or fn.startswith(base + ",U="):
                    return os.path.join(d, fn)
        return None

    def pull_later(self, a, box):
        """Pull this folder once the current batch of replayed actions is done: a pull in
        the middle of one renames the messages of the same move still to be replayed."""
        self.repull[(a["slug"], box)] = a

    def pull_now(self):
        for (slug, box), a in list(self.repull.items()):
            self.run_mbsync(a, box)
        self.repull.clear()

    def snapshot(self, accs):
        for a in accs.values():
            root = f"{self.live_control}/{a['email']}"
            for dirpath, dirnames, filenames in os.walk(root):
                if "dovecot-uidlist" not in filenames:
                    continue
                box = os.path.relpath(dirpath, root)
                path = os.path.join(dirpath, "dovecot-uidlist")
                try:
                    with open(path) as f:
                        st = os.fstat(f.fileno())
                        sig = (st.st_ino, st.st_mtime_ns, st.st_size)
                        if self.snap_seen.get(path) == sig:
                            continue  # unchanged: its pairs are already in snap
                        for line in f:
                            p = line.rstrip("\n").split(" ", 1)
                            if len(p) > 1 and p[0].isdigit():
                                m = NEAR_UID.search(p[1])
                                if m:
                                    self.snap[(a["email"], box, int(p[0]))] = int(m.group(1))
                        self.snap_seen[path] = sig
                except FileNotFoundError:
                    self.snap_seen.pop(path, None)

    def apply(self, ev, accs, remotes):
        box_full = ev.get("mailbox", "")
        a = next((x for x in accs.values() if box_full.startswith(prefix_of(x))), None)
        if a is None:
            return None  # not a Live folder: a local-only action
        box, kind, uid = box_full[len(prefix_of(a)):], ev.get("event"), int(ev.get("uid", 0) or 0)
        r = remotes.setdefault(a["slug"], Remote(a))
        r.a = a

        if kind in ("FlagsSet", "FlagsClear"):
            flags = [f for f in (ev.get("flags") or []) if f in SYSTEM_FLAGS]
            if not flags:
                return "skip (no system flag)"
            try:
                path = self.local_file(a, box, uid)
            except FileNotFoundError:
                path = None
            n = near_uid(path) if path else self.snap.get((a["email"], box, uid))
            if n is None:
                return "skip (local-only message)"
            fu = self.far_of_near(a, box, n)
            m = r.get()
            m.select(q(box))
            typ, d = m.uid("STORE", str(fu), "+FLAGS.SILENT" if kind == "FlagsSet" else "-FLAGS.SILENT", "(" + " ".join(flags) + ")")
            return f"{kind} {flags} on provider UID {fu}: {typ}"

        if kind in ("MessageAppend", "MessageNew"):
            path = self.local_file(a, box, uid)
            if path is None:
                return "skip (file not found)"
            # No "already mirrored" test on the file name: Dovecot copies by hard link and keeps
            # the name, ",U=<n>" of the source folder included, which in this folder can be
            # another message's pair. An event is an IMAP action; mbsync's writes make none.
            info = os.path.basename(path).split(":2,", 1)
            flags = [MAILDIR_FLAG[c] for c in (info[1] if len(info) > 1 else "") if c in MAILDIR_FLAG]
            data = open(path, "rb").read()
            typ, d = r.get().append(q(box), "(" + " ".join(flags) + ")", imaplib.Time2Internaldate(os.path.getmtime(path)), data)
            if typ != "OK":
                raise RuntimeError(f"APPEND {typ} {d}")
            os.remove(path)  # the provider's copy comes back with the next pull, paired by mbsync
            self.pull_later(a, box)
            return f"APPEND to {box} ({len(data)} bytes): {typ}"

        if kind == "MessageExpunge":
            n = self.snap.get((a["email"], box, uid))
            if n is None:
                return "skip (local-only or unknown message)"
            fu = self.far_of_near(a, box, n)
            m = r.get()
            m.select(q(box))
            m.uid("STORE", str(fu), "+FLAGS.SILENT", "(\\Deleted)")
            typ, d = m.uid("EXPUNGE", str(fu))  # UIDPLUS: this message only
            self.snap.pop((a["email"], box, uid), None)
            return f"EXPUNGE provider UID {fu} in {box}: {typ}"

        if kind == "MailboxCreate":
            typ, d = r.get().create(q(box))
            self.refresh_views()  # a new Archive belongs in Merged/Archive now, not at the next pull
            return f"CREATE {box}: {typ}"
        if kind == "MailboxRename":
            old = ev.get("mailbox_old", "")
            if not old.startswith(prefix_of(a)):
                return "skip (rename from outside this account)"
            typ, d = r.get().rename(q(old[len(prefix_of(a)):]), q(box))
            return f"RENAME {old[len(prefix_of(a)):]} -> {box}: {typ}"
        if kind == "MailboxDelete":
            m = r.get()
            typ, d = m.status(q(box), "(MESSAGES)")
            if typ == "OK" and b"MESSAGES 0" in d[0]:
                typ, d = m.delete(q(box))
                return f"DELETE {box} (was empty): {typ}"
            return f"skip DELETE {box}: not empty at the provider"
        return f"skip ({kind})"

    def upload_candidate(self, ev, accs):
        """(account, folder, local file) when ev is a message added to a Live/ folder that
        the replay would APPEND at the provider (not a mirrored message); else None."""
        if ev.get("event") not in ("MessageAppend", "MessageNew") or not (ev.get("message_id") or "").strip():
            return None
        box_full = ev.get("mailbox", "")
        a = next((x for x in accs.values() if box_full.startswith(prefix_of(x))), None)
        if a is None:
            return None
        box = box_full[len(prefix_of(a)):]
        try:
            path = self.local_file(a, box, int(ev.get("uid", 0) or 0))
        except FileNotFoundError:
            return None
        if path is None:
            return None
        return a, box, path

    def message_ids(self, m, a, box, fus):
        """provider UID -> Message-ID for these UIDs of box (cached: a move of n messages
        asks for each one once)."""
        want = [fu for fu in fus if (a["slug"], box, fu) not in self.mid_cache]
        if want:
            if len(self.mid_cache) > 20000:
                self.mid_cache.clear()
            typ, _ = m.select(q(box))
            if typ != "OK":
                return {}
            typ, d = m.uid("FETCH", ",".join(map(str, want)), "(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
            if typ == "OK":
                for part in d:
                    if not isinstance(part, tuple):
                        continue
                    u = re.search(rb"UID (\d+)", part[0])
                    h = re.sub(rb"\r?\n[ \t]+", b" ", part[1] or b"")
                    v = re.search(rb"(?im)^message-id:\s*(.*?)\s*$", h)
                    if u:
                        self.mid_cache[(a["slug"], box, int(u.group(1)))] = v.group(1).decode("utf-8", "replace") if v else ""
        return {fu: self.mid_cache.get((a["slug"], box, fu)) for fu in fus}

    def provider_move(self, ev, later, accs, remotes):
        """A move between two folders of one account, as Dovecot records it: the message
        added to the destination (with its Message-ID), then expunged from the source, in
        a later line. Replayed as one UID MOVE at the provider instead of APPEND + EXPUNGE,
        so the provider keeps its own message: on Gmail a folder is a label, and APPEND
        made a second message while the EXPUNGE only took the label off the first one (it
        stayed in All Mail); a move to [Gmail]/Trash is now a real delete.
        later: [(index, event)] of the lines after this one. Returns (result, index of the
        paired expunge), or None: no pair found (or the provider refused), replayed as before."""
        c = self.upload_candidate(ev, accs)
        if c is None:
            return None
        a, dest, path = c
        pre, mid = prefix_of(a), ev["message_id"].strip()
        cands = []
        for j, e in later:
            src_full = e.get("mailbox", "")
            if (e.get("event") != "MessageExpunge" or not src_full.startswith(pre) or src_full == ev.get("mailbox")
                    or abs((e.get("at") or 0) - (ev.get("at") or 0)) > PAIR_WINDOW):
                continue
            src = src_full[len(pre):]
            n = self.snap.get((a["email"], src, int(e.get("uid", 0) or 0)))
            if n is None:
                # moved before the snapshot saw it (within a replay round of Dovecot numbering
                # it): a hard-linked copy kept the source's file name and its ",U=<n>"; else
                # the source message is looked up at the provider by Message-ID (_provider_move)
                n = near_uid(path)
            fu = None
            if n is not None:
                try:
                    fu = self.far_of_near(a, src, n)
                except Wait:
                    pass
            cands.append((j, src, fu, e))
        if not cands:
            return None
        r = remotes.setdefault(a["slug"], Remote(a))
        r.a = a
        for attempt in (1, 2):  # a kept connection the provider has dropped: once more, anew
            try:
                return self._provider_move(r, a, cands, mid, dest, path)
            except Exception as e:
                r.close()
                if attempt == 2:
                    self.log("replay: provider MOVE failed, replayed as APPEND + EXPUNGE:", repr(e))
        return None

    def _provider_move(self, r, a, cands, mid, dest, path):
        """provider_move's work on one connection: (result, index) or None."""
        m = r.get()
        for j, src, fu, e in cands:
            if fu is None:
                if m.select(q(src))[0] != "OK":
                    continue
                found = m.uid("SEARCH", "HEADER", "Message-ID", mid)[1][0].split()
                if len(found) != 1:
                    continue  # not there, or ambiguous: replayed as before
                fu = int(found[0])
            elif self.message_ids(m, a, src, [x[2] for x in cands if x[1] == src and x[2]]).get(fu) != mid:
                continue
            m.select(q(src))
            if "MOVE" in m.capabilities:
                typ, d = m.uid("MOVE", str(fu), q(dest))
            else:  # UIDPLUS, as the plain expunge assumes
                typ, d = m.uid("COPY", str(fu), q(dest))
                if typ == "OK":
                    m.uid("STORE", str(fu), "+FLAGS.SILENT", "(\\Deleted)")
                    m.uid("EXPUNGE", str(fu))
            if typ != "OK":
                self.log("replay: provider MOVE refused, replayed as APPEND + EXPUNGE:", typ, d)
                return None
            self.snap.pop((a["email"], src, int(e.get("uid", 0) or 0)), None)
            self.mid_cache.pop((a["slug"], src, fu), None)
            os.remove(path)  # the provider's copy comes back with the next pull, paired by mbsync
            self.pull_later(a, dest)
            return f"MOVE provider UID {fu} {src} -> {dest}: {typ}", j
        return None

    def replay_loop(self):
        remotes, pending, last_retry = {}, [], 0
        if os.path.exists(self.pending_file):
            pending = open(self.pending_file).read().splitlines(True)

        def try_one(line, accs):
            ev = json.loads(line)
            try:
                res = self.apply(ev, accs, remotes)
            except (imaplib.IMAP4.abort, OSError) as e:
                # a kept connection the provider has dropped (idle timeout): once more, anew
                for x in remotes.values():
                    x.close()
                self.log("replay: provider connection lost, retrying:", repr(e))
                res = self.apply(ev, accs, remotes)
            if res is not None:
                self.log("replay", ev.get("event"), ev.get("mailbox"), ev.get("uid"), "->", res)

        while not self.stopped:
            try:
                accs = self.load_accounts()
                self.snapshot(accs)
                try:
                    off = int(open(self.offset).read())
                except (FileNotFoundError, ValueError):
                    # first start: replay from now on, and remember where "now" was
                    off = os.path.getsize(self.queue) if os.path.exists(self.queue) else 0
                    open(self.offset, "w").write(str(off))
                if os.path.exists(self.queue) and os.path.getsize(self.queue) < off:
                    off = 0  # queue file recreated
                if os.path.exists(self.queue) and os.path.getsize(self.queue) > off:
                    with open(self.queue, "rb") as f:
                        f.seek(off)
                        # complete lines only; the last part is an unfinished line, or empty
                        batch = [b.decode() + "\n" for b in f.read().split(b"\n")[:-1]]
                    evs = [json.loads(line) for line in batch]
                    paired = set()  # expunges already replayed by a provider MOVE
                    for i, line in enumerate(batch):
                        ev = evs[i]
                        if i in paired:
                            pass
                        elif any(json.loads(p).get("mailbox") == ev.get("mailbox", "") for p in pending):
                            pending.append(line)  # keep this folder's actions in order
                        else:
                            later = [(j, evs[j]) for j in range(i + 1, len(batch)) if j not in paired]
                            moved = self.provider_move(ev, later, accs, remotes)
                            if moved:
                                paired.add(moved[1])
                                self.log("replay", ev.get("event"), ev.get("mailbox"), ev.get("uid"), "->", moved[0])
                            elif (time.time() - (ev.get("at") or 0) < PAIR_WAIT
                                  and self.upload_candidate(ev, accs) is not None):
                                break  # may be half of a move whose expunge is not written yet: next round
                            else:
                                try:
                                    try_one(line, accs)
                                except Wait as w:
                                    self.log("replay waits for mbsync's pairing:", w)
                                    pending.append(line)
                                except Exception as e:
                                    for x in remotes.values():
                                        x.close()
                                    self.log("replay FAILED", line.strip(), "->", repr(e))
                                    open(self.failed, "a").write(line)
                        off += len(line.encode())
                        open(self.offset, "w").write(str(off))
                if pending and time.time() - last_retry > 30:
                    kept, blocked = [], set()
                    for line in pending:
                        box = json.loads(line).get("mailbox", "")
                        if box in blocked:
                            kept.append(line)
                            continue
                        try:
                            try_one(line, accs)
                        except Wait:
                            kept.append(line)
                            blocked.add(box)
                        except Exception as e:
                            self.log("replay FAILED (pending)", line.strip(), "->", repr(e))
                            open(self.failed, "a").write(line)
                    pending, last_retry = kept, time.time()
                with open(self.pending_file, "w") as pf:
                    pf.writelines(pending)
                self.pull_now()
                for x in remotes.values():
                    if x.m is not None and time.time() - x.last > 120:
                        x.close()
            except Exception as e:
                self.log("replay loop error:", repr(e))
            time.sleep(2)

    # --------------------------------------------------------------- loop ---

    def stop_worker(self, slug):
        old = self.workers.pop(slug)
        old.stop = True
        old.wake.set()
        if old.proc is not None and old.proc.poll() is None:
            old.proc.terminate()  # mbsync keeps its state consistent on SIGTERM
        old.join(timeout=60)
        return old

    def stop(self):
        self.stopped = True
        for slug in list(self.workers):
            self.stop_worker(slug)
        self.log("no longer in the registry: mirroring stopped (the mail stays on disk)")

    def tick(self):
        accs = self.load_accounts()
        sig = {s: (a["email"], a["imap_host"], a["imap_port"], a["user"], a["pass"], a.get("imap_security")) for s, a in accs.items()}
        if sig != self.seen:
            for slug in list(self.workers):
                if slug not in accs or sig[slug] != (self.seen or {}).get(slug):
                    old = self.stop_worker(slug)
                    if slug not in accs:
                        self.forget(slug, old.a["email"])
            for slug, a in accs.items():
                if slug not in self.workers:
                    self.write_status(slug, ok=True, running=True, messages=self.count_local(a["email"]), last="starting")
                    self.workers[slug] = Worker(self, a)
                    self.workers[slug].start()
                    self.log("mirroring", a["email"])
            self.seen = sig
            self.refresh_views()
        in_views = {s: a.get("in_views") is not False for s, a in accs.items()}
        if in_views != self.seen_views:  # only the views change: no worker restarts
            if self.seen_views is not None:
                self.refresh_views()
            self.seen_views = in_views
        try:
            t = os.path.getmtime(f"{self.accounts}/.sync-now")  # touched by the page on save
        except OSError:
            t = 0
        if t > self.nudge:
            if self.nudge:
                for w in self.workers.values():
                    w.wake.set()
            self.nudge = t
        self.push.check_test()


# ------------------------------------------------------------------- push ---

PUSH_TEXTS = {  # the webmail writes its user's language into .push.json; these are the fallback
    "new_many": "{n} new messages",
    "hidden_one": "New message on {account}",
    "hidden_many": "{n} new messages on {account}",
    "no_subject": "(no subject)",
    "test_title": "MailHub",
    "test_body": "Test notification: notifications work on this device.",
}
PUSH_SUMMARY_OVER = 3  # more new messages than this in one sync: one notification for them all
HEADER_PARSER = email.parser.BytesHeaderParser(policy=email.policy.default)


class Push:
    """Web Push to one user's devices (the webmail's Settings → Notifications).

    The webmail writes /accounts/<user>/.push.json (devices: endpoint + keys; show_content;
    muted account slugs; texts in the user's language) and .push-test.json (a test request);
    this writes /state/<user>/push-status.json (per device: last delivery, `gone` once the
    push service says the subscription is no more; the test results by nonce) and
    push-hwm.json (per account, the highest INBOX UID already considered)."""

    def __init__(self, mb):
        self.mb = mb
        self.conf_file, self.test_file = f"{mb.accounts}/.push.json", f"{mb.accounts}/.push-test.json"
        self.status_file, self.hwm_file = f"{mb.state}/push-status.json", f"{mb.state}/push-hwm.json"
        self.lock = threading.Lock()
        self.conf, self.conf_key = {}, None
        self.test_seen = None

    def read_json(self, path):
        try:
            with open(path) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def write_json(self, path, data):
        tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)

    def config(self):
        try:
            st = os.stat(self.conf_file)
            key = (st.st_mtime_ns, st.st_size)
        except OSError:
            key = None
        if key != self.conf_key:
            self.conf, self.conf_key = (self.read_json(self.conf_file) if key else {}), key
        return self.conf

    def text(self, name, **kw):
        t = self.config().get("texts") or {}
        s = t.get(name) if isinstance(t.get(name), str) else PUSH_TEXTS[name]
        try:
            return s.format(**kw)
        except (KeyError, IndexError, ValueError):
            return PUSH_TEXTS[name].format(**kw)

    def muted(self, a):
        m = self.config().get("muted")
        if isinstance(m, list):
            return a["slug"] in m
        return a.get("in_views") is False  # never chosen: like the Merged views

    def devices(self):
        """The devices to send to: well-formed, and not reported gone since last (re)subscribed."""
        gone = {i: d.get("gone") for i, d in (self.read_json(self.status_file).get("devices") or {}).items()}
        out = []
        for d in self.config().get("devices") or []:
            if not isinstance(d, dict) or not all(isinstance(d.get(k), str) for k in ("id", "endpoint", "p256dh", "auth")):
                continue
            if gone.get(d["id"]) and gone[d["id"]] == d.get("updated", d.get("added")):
                continue
            out.append(d)
        return out

    def deliver(self, payload, devices, ttl=86400, urgency="normal"):
        """Send to each device; record the outcome per device. Returns {id: result}."""
        results = {}
        for d in devices:
            status, text = webpush.send(VAPID, d, payload, ttl=ttl, urgency=urgency)
            ok = status in (200, 201, 202)
            results[d["id"]] = {"ok": ok, "status": status, **({} if ok else {"error": text[:200]})}
            if not ok:
                self.mb.log("push to", d.get("label") or d["id"], "failed:", status, text[:120])
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.lock:
            st = self.read_json(self.status_file)
            devs = st.setdefault("devices", {})
            for d in devices:
                r, e = results[d["id"]], devs.setdefault(d["id"], {})
                if r["ok"]:
                    e.update(last_ok=now)
                    e.pop("gone", None)
                    e.pop("error", None)
                else:
                    e.update(last_error=now, error=f"{r['status']} {r.get('error', '')}".strip())
                    if r["status"] in (404, 410):
                        e["gone"] = d.get("updated", d.get("added")) or now
            known = {d.get("id") for d in self.config().get("devices") or [] if isinstance(d, dict)}
            st["devices"] = {i: e for i, e in devs.items() if i in known}
            self.write_json(self.status_file, st)
        return results

    def check_test(self):
        """A test request from the page (.push-test.json, {nonce, device}): answered once."""
        try:
            t = os.path.getmtime(self.test_file)
        except OSError:
            return
        if t == self.test_seen:
            return
        self.test_seen = t
        req = self.read_json(self.test_file)
        nonce = req.get("nonce")
        if not isinstance(nonce, str) or (self.read_json(self.status_file).get("test") or {}).get("nonce") == nonce:
            return
        devices = [d for d in self.devices() if req.get("device") in (None, "all", d["id"])]
        threading.Thread(target=self.run_test, args=(nonce, devices), daemon=True).start()

    def run_test(self, nonce, devices):
        payload = {"title": self.text("test_title"), "body": self.text("test_body"), "tag": "mailhub-test",
                   "url": "?_task=settings&_action=plugin.mailhub_push"}
        results = self.deliver(payload, devices, ttl=120, urgency="high") if devices and VAPID else {}
        with self.lock:
            st = self.read_json(self.status_file)
            st["test"] = {"nonce": nonce, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "results": results, **({} if VAPID else {"error": "no VAPID key"})}
            self.write_json(self.status_file, st)
        self.mb.log("test notification:", sum(r["ok"] for r in results.values()), "of", len(results), "delivered")

    # ------------------------------------------------------------ new mail ---

    def hwm(self):
        return self.read_json(self.hwm_file)

    def set_hwm(self, slug, uid):
        with self.lock:
            h = self.hwm()
            h[slug] = uid
            self.write_json(self.hwm_file, h)

    def forget(self, slug):
        with self.lock:
            h = self.hwm()
            if h.pop(slug, None) is not None:
                self.write_json(self.hwm_file, h)

    def new_mail(self, a, first):
        """After a sync: the INBOX messages above the account's high-water mark, still
        unread, become a notification. The first download and the first sync since
        this existed only set the mark."""
        inbox = f"{self.mb.live}/{a['email']}/INBOX"
        found = []  # (uid, path, seen)
        for sub in ("new", "cur"):
            try:
                names = os.listdir(f"{inbox}/{sub}")
            except OSError:
                continue
            for fn in names:
                m = NEAR_UID.search(fn)
                if m:
                    flags = fn.split(":2,", 1)[1] if ":2," in fn else ""
                    found.append((int(m.group(1)), f"{inbox}/{sub}/{fn}", "S" in flags))
        top = max((u for u, _, _ in found), default=0)
        mark = self.hwm().get(a["slug"])
        if first or not isinstance(mark, int) or top < mark:  # no mark yet, or the folder was rebuilt
            if mark != top:
                self.set_hwm(a["slug"], top)
            return
        new = sorted((f for f in found if f[0] > mark and not f[2]), key=lambda f: f[0])
        if top != mark:
            self.set_hwm(a["slug"], top)
        if not new or self.muted(a) or VAPID is None:
            return
        devices = self.devices()
        if devices:
            threading.Thread(target=self.notify, args=(a, new, devices), daemon=True).start()

    def notify(self, a, new, devices):
        show = self.config().get("show_content") is not False
        account = a["email"]
        several_accounts = len(self.mb.workers) > 1
        base = {"tag": f"mailhub-{a['slug']}", "account": account, "url": "?_task=mail"}
        if not show:
            n = len(new)
            payloads = [dict(base, title="MailHub", body=(self.text("hidden_one", account=account) if n == 1
                                                         else self.text("hidden_many", n=n, account=account)))]
        else:
            heads = [self.headers(p) for _, p, _ in new]
            if len(heads) > PUSH_SUMMARY_OVER:
                senders = []
                for s, _ in heads:
                    if s not in senders:
                        senders.append(s)
                body = ", ".join(senders[:4]) + ("…" if len(senders) > 4 else "")
                payloads = [dict(base, title=self.text("new_many", n=len(heads)) + (f" · {account}" if several_accounts else ""),
                                 body=body)]
            else:
                payloads = [dict(base, tag=f"mailhub-{a['slug']}-{uid}", title=s,
                                 body=subj + (f"\n{account}" if several_accounts else ""))
                            for (uid, _, _), (s, subj) in zip(new, heads)]
        for p in payloads:
            self.deliver(p, devices)
        self.mb.log(a["email"], len(new), "new: notified", len(devices), "device(s)")

    def headers(self, path):
        """(sender, subject) of a Maildir message, decoded; the file's headers only."""
        try:
            with open(path, "rb") as f:
                h = HEADER_PARSER.parse(f)
            sender, subject = "", str(h.get("subject") or "").strip()
            frm = h.get("from")
            if frm is not None:
                addrs = getattr(frm, "addresses", ())
                sender = (addrs[0].display_name or addrs[0].addr_spec) if addrs else str(frm)
            return (sender.strip()[:80] or "?", subject[:160] or self.text("no_subject"))
        except Exception:
            return ("?", self.text("no_subject"))


def prefix_of(a):
    return f"Live/{a['email']}/"


class Worker(threading.Thread):
    """Pulls one account in a loop; woken early when its account file changes."""

    def __init__(self, mb, a):
        super().__init__(daemon=True)
        self.mb, self.a, self.wake, self.stop, self.proc = mb, a, threading.Event(), False, None
        # set by the IDLE watcher: the next run pulls the INBOX only (new mail is there)
        self.inbox_only = False

    def run(self):
        if IDLE_ON:
            IdleWatcher(self).start()
        while not self.stop:
            box, self.inbox_only = ("INBOX" if self.inbox_only else None), False
            self.sync_once(box)
            self.wake.wait(INTERVAL)
            self.wake.clear()

    def sync_once(self, box=None):
        mb, a, slug = self.mb, self.a, self.a["slug"]
        started, done = time.time(), threading.Event()
        # first download until mbsync has completed a run of the INBOX (its state file)
        first = not os.path.exists(f"{mb.live}/{a['email']}/INBOX/.mbsyncstate")

        def progress():
            tick = 0
            while not done.wait(15):
                n = mb.count_local(a["email"])
                mb.write_status(slug, ok=True, running=True, messages=n, first=first,
                                last=(f"first download, {n:,} messages so far" if first else f"{n:,} messages here"))
                # Folders appear while a (long, first) sync runs: list them in the
                # views and subscribe them now, not only once the sync is over.
                if tick % 4 == 0:
                    mb.refresh_views()
                tick += 1
        threading.Thread(target=progress, daemon=True).start()
        try:
            r = mb.run_mbsync(a, box=box, worker=self)
        except Exception as e:
            r = subprocess.CompletedProcess([], 1, "", repr(e))
        done.set()
        if self.stop:
            return
        n = mb.count_local(a["email"])
        out = (r.stdout + r.stderr).strip().splitlines()
        m = re.search(r"Near: \+(\d+) \*(\d+) #\d+ -(\d+)", r.stdout)
        if r.returncode == 0:
            changes = (f"{int(m.group(1)):,} new, {int(m.group(2)):,} changed, {int(m.group(3)):,} removed" if m else "up to date")
            mb.write_status(slug, ok=True, running=False, messages=n, seconds=round(time.time() - started),
                            last=f"{n:,} messages here; this sync: {changes}")
            if first or (m and int(m.group(1)) > 0):
                threading.Thread(target=mb.warm_index, args=(a,), daemon=True).start()
            try:
                mb.push.new_mail(a, first)
            except Exception as e:
                mb.log(slug, "new-mail notification:", repr(e))
        else:
            err = next((l for l in reversed(out) if l.strip()), f"mbsync exit {r.returncode}")
            mb.write_status(slug, ok=False, running=False, messages=n, last=err[:300])
            mb.log(slug, "sync failed:", err)
        mb.refresh_views()


class Wait(Exception):
    """mbsync has not paired this message yet (its sync is running)."""


def near_uid(path):
    m = re.search(r",U=(\d+)", os.path.basename(path))
    return int(m.group(1)) if m else None


NEAR_UID = re.compile(r",U=(\d+)")


def connect(a, timeout=60):
    """An IMAP session at the account's provider, logged in."""
    if a.get("imap_security", "ssl") == "ssl":
        m = imaplib.IMAP4_SSL(a["imap_host"], int(a["imap_port"]), ssl_context=ssl.create_default_context(), timeout=timeout)
    else:
        m = imaplib.IMAP4(a["imap_host"], int(a["imap_port"]), timeout=timeout)
        if a.get("imap_security") == "tls":
            m.starttls(ssl_context=ssl.create_default_context())
    m.login(a["user"], a["pass"])
    return m


class Remote:
    def __init__(self, a):
        self.a, self.m, self.last = a, None, 0

    def get(self):
        if self.m is not None and time.time() - self.last > 120:
            self.close()
        if self.m is None:
            self.m = connect(self.a)
        self.last = time.time()
        return self.m

    def close(self):
        try:
            self.m and self.m.logout()
        except Exception:
            pass
        self.m = None


class IdleWatcher(threading.Thread):
    """IMAP IDLE on the provider's INBOX: new mail there wakes the account's worker
    for an INBOX-only pull at once, instead of at the next MAILHUB_SYNC_INTERVAL.
    One connection per account; a server without IDLE just leaves the polling."""

    def __init__(self, worker):
        super().__init__(daemon=True)
        self.w = worker

    def log(self, *a):
        self.w.mb.log(self.w.a["slug"], "IDLE:", *a)

    def run(self):
        backoff, logged = 30, False
        while not self.w.stop:
            m = None
            try:
                m = connect(self.w.a)
                if "IDLE" not in m.capabilities:
                    typ, data = m.capability()
                    if b"IDLE" not in b" ".join(data or []).upper().split():
                        self.log("not offered by the server; polling every", INTERVAL, "s")
                        return
                typ, _ = m.select("INBOX", readonly=True)
                if typ != "OK":
                    raise RuntimeError("SELECT INBOX refused")
                if logged:
                    self.log("connected again")
                backoff, logged = 30, False
                self.idle(m)
            except Exception as e:
                if self.w.stop:
                    break
                if not logged:
                    self.log("connection lost:", repr(e)[:200], f"(retrying, every {backoff} s at first)")
                    logged = True
                self.sleep(backoff)
                backoff = min(backoff * 2, 600)
            finally:
                if m is not None:
                    try:
                        m.shutdown()
                    except Exception:
                        pass

    def sleep(self, seconds):
        end = time.time() + seconds
        while not self.w.stop and time.time() < end:
            time.sleep(min(5, end - time.time()))

    def idle(self, m):
        """IDLE until stopped, re-issued every IDLE_RENEW seconds. Reads the socket itself
        (with select) rather than through imaplib's buffered file, which a timeout breaks."""
        sock = m.sock
        buf = b""

        def lines(deadline):
            nonlocal buf
            while True:
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    yield line
                if self.w.stop or time.time() >= deadline:
                    return
                pending = sock.pending() if hasattr(sock, "pending") else 0
                if not pending:
                    r, _, _ = select.select([sock], [], [], min(5, max(0.1, deadline - time.time())))
                    if not r:
                        continue
                chunk = sock.recv(65536)
                if not chunk:
                    raise ConnectionError("closed by the server")
                buf += chunk

        while not self.w.stop:
            tag = m._new_tag().decode()
            sock.sendall(f"{tag} IDLE\r\n".encode())
            started = False
            for line in lines(time.time() + 30):
                if line.startswith(b"+"):
                    started = True
                    break
                if line.startswith(tag.encode()):
                    raise RuntimeError("IDLE refused: " + line.decode("utf-8", "replace")[:100])
            if not started:
                raise TimeoutError("no answer to IDLE")
            for line in lines(time.time() + IDLE_RENEW):
                u = line.upper()
                if u.startswith(b"* BYE"):
                    raise ConnectionError(line.decode("utf-8", "replace")[:100])
                if u.startswith(b"* ") and (u.endswith(b" EXISTS") or u.endswith(b" RECENT")):
                    self.w.inbox_only = True
                    self.w.wake.set()
            sock.sendall(b"DONE\r\n")
            for line in lines(time.time() + 30):
                if line.startswith(tag.encode()):
                    break
            else:
                if not self.w.stop:
                    raise TimeoutError("no answer to DONE")


# ------------------------------------------------------------------- main ---

def migrate_single_user():
    """Before 0.5.0: /accounts/<slug>.json, /state/status/ and /state/run/, all the
    owner's. Moved under admin/ (the owner's mailbox itself, /srv/vmail/admin, is
    where it was)."""
    legacy = [fn for fn in os.listdir(ACCOUNTS) if os.path.isfile(os.path.join(ACCOUNTS, fn))] if os.path.isdir(ACCOUNTS) else []
    if legacy:
        dest = f"{ACCOUNTS}/{OWNER}"
        makedirs(dest, 0o700, WEB_UID)
        for fn in legacy:
            os.replace(os.path.join(ACCOUNTS, fn), os.path.join(dest, fn))
        log("moved", len(legacy), "account files to", dest, "(one user before 0.5.0)")
    for sub in ("status", "run"):
        src = f"{STATE}/{sub}"
        if os.path.isdir(src):
            dest = f"{STATE}/{OWNER}/{sub}"
            os.makedirs(f"{STATE}/{OWNER}", exist_ok=True)
            if os.path.exists(dest):
                shutil.rmtree(src)  # regenerated on the next sync anyway
            else:
                os.replace(src, dest)
            log("moved", src, "to", dest)


def main():
    if not MASTER_PASSWORD:
        log("MAILHUB_MASTER_PASSWORD is not set: only the owner's folders can be subscribed")
    migrate_single_user()
    global VAPID
    subject = PUSH_SUBJECT if PUSH_SUBJECT.startswith(("https://", "mailto:")) else ""
    if not subject:
        log("MAILHUB_PUSH_SUBJECT is not an https: or mailto: URL: push services may refuse the notifications")
    try:
        VAPID = webpush.Vapid.load_or_create(PUSH_DIR, subject or "mailto:postmaster@localhost")
    except Exception as e:
        log("no Web Push (VAPID key):", repr(e))
    mailboxes, prov = {}, Provisioner()
    while True:
        try:
            users = load_users()
            prov.run(users)
            for name in sorted(set(users) - set(mailboxes)):
                mb = Mailbox(name)
                mb.setup()
                mailboxes[name] = mb
                log("mailbox", name, "mirrored")
            for name in sorted(set(mailboxes) - set(users)):
                mailboxes.pop(name).stop()
            for mb in mailboxes.values():
                try:
                    mb.tick()
                except Exception as e:
                    mb.log("loop error:", repr(e))
        except Exception as e:
            log("main loop error:", repr(e))
        open(f"{STATE}/.alive", "w").close()
        time.sleep(3)


if __name__ == "__main__":
    main()
