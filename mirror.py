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

  users    The device logins (IMAPS, CalDAV/CardDAV): /srv/vmail/.mailhub-passwd, the
           passwd-file Dovecot checks, rendered from the registry's hashes plus the
           owner's MAILHUB_PASSWORD; and each registry user's Baïkal account (user,
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
import base64, hashlib, imaplib, json, os, re, shutil, sqlite3, ssl, subprocess, threading, time

OWNER = "admin"
OWNER_PASSWORD = os.environ.get("MAILHUB_PASSWORD", "")
MASTER_PASSWORD = os.environ.get("MAILHUB_MASTER_PASSWORD", "")
MASTER_NAME = "mailhub-mirror"
IMAP_HOST = os.environ.get("MAILHUB_IMAP_HOST", "mailhub-imap")
IMAP_PORT = int(os.environ.get("MAILHUB_IMAP_PORT", "31143"))
INTERVAL = int(os.environ.get("MAILHUB_SYNC_INTERVAL", "120"))
VMAIL = int(os.environ.get("MAILHUB_VMAIL_UID", "1000"))
WEB_UID = int(os.environ.get("MAILHUB_WEB_UID", "33"))  # the webmail's www-data
ACCOUNTS = "/accounts"
STATE = "/state"
USERS = "/users"
VMAIL_ROOT = "/srv/vmail"
PASSWD = f"{VMAIL_ROOT}/.mailhub-passwd"
BAIKAL_DB = os.environ.get("MAILHUB_BAIKAL_DB", "/baikal/db/db.sqlite")
BAIKAL_REALM = "BaikalDAV"
# a local user name: also a Dovecot home (/srv/vmail/<name>) and a Baïkal principal
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")

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
        if sig == self.seen_passwd and os.path.exists(PASSWD):
            return
        if self.owner_hash is None and OWNER_PASSWORD:
            self.owner_hash = ssha512(OWNER_PASSWORD)
        lines = [f"{OWNER}:{self.owner_hash}"] if self.owner_hash else []
        for n, u in sorted(users.items()):
            h = u.get("device_hash", "")
            if n != OWNER and re.fullmatch(r"\{SSHA512\}[A-Za-z0-9+/=]+", h):
                lines.append(f"{n}:{h}")
        atomic_write(PASSWD, "".join(l + "\n" for l in lines), 0o600, VMAIL)
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
        self.workers = {}
        self.seen, self.seen_views, self.nudge = None, None, 0
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
                if fn == base or fn.startswith(base + ":"):
                    return os.path.join(d, fn)
        return None

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
            if near_uid(path) is not None:
                return "skip (already a mirrored message)"
            info = os.path.basename(path).split(":2,", 1)
            flags = [MAILDIR_FLAG[c] for c in (info[1] if len(info) > 1 else "") if c in MAILDIR_FLAG]
            data = open(path, "rb").read()
            typ, d = r.get().append(q(box), "(" + " ".join(flags) + ")", imaplib.Time2Internaldate(os.path.getmtime(path)), data)
            if typ != "OK":
                raise RuntimeError(f"APPEND {typ} {d}")
            os.remove(path)  # the provider's copy comes back with the next pull, paired by mbsync
            self.run_mbsync(a, box)
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

    def replay_loop(self):
        remotes, pending, last_retry = {}, [], 0
        if os.path.exists(self.pending_file):
            pending = open(self.pending_file).read().splitlines(True)

        def try_one(line, accs):
            ev = json.loads(line)
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
                    with open(self.queue) as f:
                        f.seek(off)
                        for line in f:
                            if not line.endswith("\n"):
                                break
                            off += len(line.encode())
                            box = json.loads(line).get("mailbox", "")
                            if any(json.loads(p).get("mailbox") == box for p in pending):
                                pending.append(line)  # keep this folder's actions in order
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


def prefix_of(a):
    return f"Live/{a['email']}/"


class Worker(threading.Thread):
    """Pulls one account in a loop; woken early when its account file changes."""

    def __init__(self, mb, a):
        super().__init__(daemon=True)
        self.mb, self.a, self.wake, self.stop, self.proc = mb, a, threading.Event(), False, None

    def run(self):
        while not self.stop:
            self.sync_once()
            self.wake.wait(INTERVAL)
            self.wake.clear()

    def sync_once(self):
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
            r = mb.run_mbsync(a, worker=self)
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


class Remote:
    def __init__(self, a):
        self.a, self.m, self.last = a, None, 0

    def get(self):
        if self.m is not None and time.time() - self.last > 120:
            self.close()
        if self.m is None:
            a = self.a
            if a.get("imap_security", "ssl") == "ssl":
                self.m = imaplib.IMAP4_SSL(a["imap_host"], int(a["imap_port"]), ssl_context=ssl.create_default_context())
            else:
                self.m = imaplib.IMAP4(a["imap_host"], int(a["imap_port"]))
                if a.get("imap_security") == "tls":
                    self.m.starttls(ssl_context=ssl.create_default_context())
            self.m.login(a["user"], a["pass"])
        self.last = time.time()
        return self.m

    def close(self):
        try:
            self.m and self.m.logout()
        except Exception:
            pass
        self.m = None


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
