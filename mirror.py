"""MailHub mirror: every provider mailbox as a local copy, the provider staying the truth.

For each account file the Mail accounts page writes (/accounts/<slug>.json):

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
  views    Virtual/All inboxes, Unread and Flagged (Dovecot virtual folders) are
           rewritten from the accounts and folders that exist, and new Live/ and
           Virtual/ folders are subscribed (the webmail lists subscribed folders).
  status   /state/status/<slug>.json for the Mail accounts page, with the download
           progress while a sync runs.

An account removed from the page stops syncing and its local copy is deleted (only
this server's copy; nothing is deleted at the provider).

Runs as root to read the webmail's private account files; mbsync runs as the
mailbox's owner (MAILHUB_VMAIL_UID) and every file it creates belongs to it.
"""
import imaplib, json, os, re, shutil, ssl, subprocess, threading, time

USER = os.environ.get("MAILHUB_USER", "admin")
PASSWORD = os.environ.get("MAILHUB_PASSWORD", "")
IMAP_HOST = os.environ.get("MAILHUB_IMAP_HOST", "mailhub-imap")
IMAP_PORT = int(os.environ.get("MAILHUB_IMAP_PORT", "31143"))
INTERVAL = int(os.environ.get("MAILHUB_SYNC_INTERVAL", "120"))
VMAIL = int(os.environ.get("MAILHUB_VMAIL_UID", "1000"))
ACCOUNTS = "/accounts"
STATE = "/state"
HOME = f"/srv/vmail/{USER}"
LIVE, LIVE_INDEX, LIVE_CONTROL = f"{HOME}/live", f"{HOME}/live-index", f"{HOME}/live-control"
QDIR = f"{HOME}/live-queue"
QUEUE, OFFSET, PENDING, FAILED = (f"{QDIR}/events.jsonl", f"{QDIR}/offset", f"{QDIR}/pending.jsonl", f"{QDIR}/failed.jsonl")
VIRTUAL = f"{HOME}/virtual"
RUN = f"{STATE}/run"  # generated mbsync configs and password files, owned by VMAIL, 0700

SYSTEM_FLAGS = {"\\Seen", "\\Flagged", "\\Answered", "\\Draft", "\\Deleted"}
MAILDIR_FLAG = {"D": "\\Draft", "F": "\\Flagged", "R": "\\Answered", "S": "\\Seen", "T": "\\Deleted"}
# left out of the Unread and Flagged views (compared case-insensitively, last path part)
NOT_IN_VIEWS = {"trash", "deleted items", "deleted messages", "bin", "junk", "spam", "bulk mail",
                "drafts", "sent", "sent items", "sent messages", "sent mail", "all mail", "important", "starred"}
# Gmail's label views would download every message again
GMAIL_SKIP = ["[Gmail]/All Mail", "[Gmail]/Important", "[Gmail]/Starred", "[Google Mail]/All Mail",
              "[Google Mail]/Important", "[Google Mail]/Starred"]


def log(*a):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), *a, flush=True)


def own(path):
    os.chown(path, VMAIL, VMAIL)


def makedirs(path, mode=0o700):
    os.makedirs(path, mode=mode, exist_ok=True)
    own(path)


def q(name):
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------- accounts ---

def load_accounts():
    accs = {}
    for fn in sorted(os.listdir(ACCOUNTS)) if os.path.isdir(ACCOUNTS) else []:
        if not fn.endswith(".json"):
            continue
        try:
            a = json.load(open(os.path.join(ACCOUNTS, fn)))
            a["slug"] = fn[:-5]
            if not re.fullmatch(r"[a-z0-9._-]+", a["slug"]) or "@" not in a.get("email", "") or "/" in a["email"]:
                raise ValueError("bad slug or address")
            accs[a["slug"]] = a
        except Exception as e:
            log("skipping account file", fn, repr(e))
    return accs


def prefix_of(a):
    return f"Live/{a['email']}/"


def write_status(slug, **s):
    s.setdefault("at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    d = f"{STATE}/status"
    os.makedirs(d, exist_ok=True)
    tmp = f"{d}/.{slug}.tmp"
    with open(tmp, "w") as f:
        json.dump(dict(account=slug, **s), f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, f"{d}/{slug}.json")


def mbsync_config(a):
    """Write the account's mbsync config (pull only) and password file; return the config path."""
    makedirs(RUN)
    passfile, conf = f"{RUN}/{a['slug']}.pass", f"{RUN}/{a['slug']}.mbsyncrc"
    with open(passfile, "w") as f:
        f.write(a["pass"])
    os.chmod(passfile, 0o600)
    own(passfile)
    root = f"{LIVE}/{a['email']}"
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


def count_local(email):
    n = 0
    for dirpath, dirnames, filenames in os.walk(f"{LIVE}/{email}"):
        if os.path.basename(dirpath) in ("cur", "new"):
            n += len(filenames)
    return n


def run_mbsync(a, box=None, worker=None):
    conf = mbsync_config(a)
    target = a["slug"] + (f":{box}" if box else "")
    p = subprocess.Popen(["mbsync", "-c", conf, target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         user=VMAIL, group=VMAIL, env={"HOME": RUN, "PATH": "/usr/bin:/bin"})
    if worker is not None:
        worker.proc = p
    out, err = p.communicate()
    return subprocess.CompletedProcess(p.args, p.returncode, out, err)


class Worker(threading.Thread):
    """Pulls one account in a loop; woken early when its account file changes."""

    def __init__(self, a):
        super().__init__(daemon=True)
        self.a, self.wake, self.stop, self.proc = a, threading.Event(), False, None

    def run(self):
        while not self.stop:
            self.sync_once()
            self.wake.wait(INTERVAL)
            self.wake.clear()

    def sync_once(self):
        a, slug = self.a, self.a["slug"]
        started, done = time.time(), threading.Event()
        # first download until mbsync has completed a run of the INBOX (its state file)
        first = not os.path.exists(f"{LIVE}/{a['email']}/INBOX/.mbsyncstate")

        def progress():
            tick = 0
            while not done.wait(15):
                n = count_local(a["email"])
                write_status(slug, ok=True, running=True, messages=n, first=first,
                             last=(f"first download, {n:,} messages so far" if first else f"{n:,} messages here"))
                # Folders appear while a (long, first) sync runs: list them in the
                # views and subscribe them now, not only once the sync is over.
                if tick % 4 == 0:
                    refresh_views()
                tick += 1
        threading.Thread(target=progress, daemon=True).start()
        try:
            r = run_mbsync(a, worker=self)
        except Exception as e:
            r = subprocess.CompletedProcess([], 1, "", repr(e))
        done.set()
        if self.stop:
            return
        n = count_local(a["email"])
        out = (r.stdout + r.stderr).strip().splitlines()
        m = re.search(r"Near: \+(\d+) \*(\d+) #\d+ -(\d+)", r.stdout)
        if r.returncode == 0:
            changes = (f"{int(m.group(1)):,} new, {int(m.group(2)):,} changed, {int(m.group(3)):,} removed" if m else "up to date")
            write_status(slug, ok=True, running=False, messages=n, seconds=round(time.time() - started),
                         last=f"{n:,} messages here; this sync: {changes}")
            if first or (m and int(m.group(1)) > 0):
                threading.Thread(target=warm_index, args=(a,), daemon=True).start()
        else:
            err = next((l for l in reversed(out) if l.strip()), f"mbsync exit {r.returncode}")
            write_status(slug, ok=False, running=False, messages=n, last=err[:300])
            log(slug, "sync failed:", err)
        refresh_views()


def warm_index(a):
    """Have Dovecot full-text index the account's new mail now. mbsync writes Maildir
    files directly, so nothing is indexed on arrival; without this the first search
    in a big new mailbox would index it all while the user waits (and other searches
    answer INUSE meanwhile). A search triggers the indexing (fts_search_add_missing)
    and the indexer goes on with it after the search gives up."""
    if not PASSWORD:
        return
    try:
        m = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
        m.login(USER, PASSWORD)
        for f in live_folders(a["email"]):
            if m.select(q(prefix_of(a) + f), readonly=True)[0] == "OK":
                m.search(None, "BODY", '"mailhub-index-warm-up"')  # NO [INUSE] is fine
        m.logout()
        log(a["slug"], "full-text indexing started")
    except Exception as e:
        log(a["slug"], "full-text warm-up:", repr(e))


# ------------------------------------------------------------------ views ---

def live_folders(email):
    """Folder names (relative to the account) of the local copy: dirs holding cur/."""
    root, out = f"{LIVE}/{email}", []
    for dirpath, dirnames, filenames in os.walk(root):
        if "cur" in dirnames and dirpath != root:
            out.append(os.path.relpath(dirpath, root))
        for skip in ("cur", "new", "tmp"):
            if skip in dirnames:
                dirnames.remove(skip)
    return sorted(out)


VIEWS_LOCK = threading.Lock()


def refresh_views():
    with VIEWS_LOCK:
        accs = load_accounts()
        inboxes, rest, with_sent = ["INBOX"], ["INBOX"], ["INBOX"]
        for a in accs.values():
            folders = live_folders(a["email"])
            for f in folders:
                name = prefix_of(a) + f
                base = f.split("/")[-1].lower()
                if f == "INBOX":
                    inboxes.append(name)
                if base not in NOT_IN_VIEWS:
                    rest.append(name)
                if base not in NOT_IN_VIEWS or base in ("sent", "sent items", "sent messages", "sent mail"):
                    with_sent.append(name)
        views = {"All inboxes": (inboxes, "all"), "Unread": (rest, "unseen"), "Flagged": (with_sent, "flagged")}
        makedirs(VIRTUAL, 0o700)
        for view, (boxes, rule) in views.items():
            d = f"{VIRTUAL}/{view}"
            makedirs(d)
            text = "\n".join(boxes) + f"\n  {rule}\n"
            path = f"{d}/dovecot-virtual"
            if not os.path.exists(path) or open(path).read() != text:
                with open(path, "w") as f:
                    f.write(text)
                own(path)
                log("view", view, "now covers", len(boxes), "folders")
        subscribe_all()


def subscribe_all():
    if not PASSWORD:
        return
    try:
        m = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
        m.login(USER, PASSWORD)
        names = set()
        for pat in ("Live/*", "Virtual/*"):
            for line in m.list('""', pat)[1] or []:
                if line and b"\\Noselect" not in line:
                    names.add(line.decode().rsplit(' "/" ', 1)[-1].strip('"'))
        subscribed = set(l.decode().rsplit(' "/" ', 1)[-1].strip('"') for l in (m.lsub('""', "*")[1] or []) if l)
        for n in sorted(names - subscribed):
            m.subscribe(q(n))
            log("subscribed", n)
        m.logout()
    except Exception as e:
        log("subscribe failed:", repr(e))


def forget(slug, email):
    """An account removed from the page: delete this server's copy (never the provider's)."""
    for d in (f"{LIVE}/{email}", f"{LIVE_INDEX}/{email}", f"{LIVE_CONTROL}/{email}"):
        if email and os.path.isdir(d) and os.path.realpath(d).startswith(HOME + "/live"):
            shutil.rmtree(d)
    for f in (f"{RUN}/{slug}.pass", f"{RUN}/{slug}.mbsyncrc", f"{STATE}/status/{slug}.json"):
        if os.path.exists(f):
            os.remove(f)
    log("removed", email, "(local copy deleted; nothing changed at the provider)")


# ----------------------------------------------------------------- replay ---

class Wait(Exception):
    """mbsync has not paired this message yet (its sync is running)."""


def far_of_near(a, box, near):
    try:
        with open(f"{LIVE}/{a['email']}/{box}/.mbsyncstate") as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0].isdigit() and p[1] == str(near):
                    return int(p[0])
    except FileNotFoundError:
        raise Wait(box)
    raise Wait(f"{box} near {near}")


def near_uid(path):
    m = re.search(r",U=(\d+)", os.path.basename(path))
    return int(m.group(1)) if m else None


def local_file(a, box, uid):
    ul = f"{LIVE_CONTROL}/{a['email']}/{box}/dovecot-uidlist"
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
        d = f"{LIVE}/{a['email']}/{box}/{sub}"
        for fn in os.listdir(d):
            if fn == base or fn.startswith(base + ":"):
                return os.path.join(d, fn)
    return None


SNAP = {}  # (email, box, dovecot uid) -> mbsync near uid, so an expunge can be resolved


def snapshot(accs):
    for a in accs.values():
        root = f"{LIVE_CONTROL}/{a['email']}"
        for dirpath, dirnames, filenames in os.walk(root):
            if "dovecot-uidlist" not in filenames:
                continue
            box = os.path.relpath(dirpath, root)
            try:
                with open(os.path.join(dirpath, "dovecot-uidlist")) as f:
                    for line in f:
                        p = line.rstrip("\n").split(" ", 1)
                        if len(p) > 1 and p[0].isdigit():
                            m = re.search(r",U=(\d+)", p[1])
                            if m:
                                SNAP[(a["email"], box, int(p[0]))] = int(m.group(1))
            except FileNotFoundError:
                pass


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


def apply(ev, accs, remotes, workers):
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
            path = local_file(a, box, uid)
        except FileNotFoundError:
            path = None
        n = near_uid(path) if path else SNAP.get((a["email"], box, uid))
        if n is None:
            return "skip (local-only message)"
        fu = far_of_near(a, box, n)
        m = r.get()
        m.select(q(box))
        typ, d = m.uid("STORE", str(fu), "+FLAGS.SILENT" if kind == "FlagsSet" else "-FLAGS.SILENT", "(" + " ".join(flags) + ")")
        return f"{kind} {flags} on provider UID {fu}: {typ}"

    if kind in ("MessageAppend", "MessageNew"):
        path = local_file(a, box, uid)
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
        run_mbsync(a, box)
        return f"APPEND to {box} ({len(data)} bytes): {typ}"

    if kind == "MessageExpunge":
        n = SNAP.get((a["email"], box, uid))
        if n is None:
            return "skip (local-only or unknown message)"
        fu = far_of_near(a, box, n)
        m = r.get()
        m.select(q(box))
        m.uid("STORE", str(fu), "+FLAGS.SILENT", "(\\Deleted)")
        typ, d = m.uid("EXPUNGE", str(fu))  # UIDPLUS: this message only
        SNAP.pop((a["email"], box, uid), None)
        return f"EXPUNGE provider UID {fu} in {box}: {typ}"

    if kind == "MailboxCreate":
        typ, d = r.get().create(q(box))
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


def replay_loop(workers):
    remotes, pending, last_retry = {}, [], 0
    if os.path.exists(PENDING):
        pending = open(PENDING).read().splitlines(True)

    def try_one(line, accs):
        ev = json.loads(line)
        res = apply(ev, accs, remotes, workers)
        if res is not None:
            log("replay", ev.get("event"), ev.get("mailbox"), ev.get("uid"), "->", res)

    while True:
        try:
            accs = load_accounts()
            snapshot(accs)
            try:
                off = int(open(OFFSET).read())
            except (FileNotFoundError, ValueError):
                # first start: replay from now on, and remember where "now" was
                off = os.path.getsize(QUEUE) if os.path.exists(QUEUE) else 0
                open(OFFSET, "w").write(str(off))
            if os.path.exists(QUEUE) and os.path.getsize(QUEUE) < off:
                off = 0  # queue file recreated
            if os.path.exists(QUEUE) and os.path.getsize(QUEUE) > off:
                with open(QUEUE) as f:
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
                                log("replay waits for mbsync's pairing:", w)
                                pending.append(line)
                            except Exception as e:
                                for x in remotes.values():
                                    x.close()
                                log("replay FAILED", line.strip(), "->", repr(e))
                                open(FAILED, "a").write(line)
                        open(OFFSET, "w").write(str(off))
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
                        log("replay FAILED (pending)", line.strip(), "->", repr(e))
                        open(FAILED, "a").write(line)
                pending, last_retry = kept, time.time()
            with open(PENDING, "w") as pf:
                pf.writelines(pending)
            for x in remotes.values():
                if x.m is not None and time.time() - x.last > 120:
                    x.close()
        except Exception as e:
            log("replay loop error:", repr(e))
        time.sleep(2)


# ------------------------------------------------------------------- main ---

def main():
    for d in (HOME, LIVE, LIVE_INDEX, LIVE_CONTROL, QDIR, VIRTUAL):
        makedirs(d)
    if not os.path.exists(QUEUE):
        open(QUEUE, "a").close()
    for f in (QUEUE,):
        own(f)
        os.chmod(f, 0o600)
    os.makedirs(f"{STATE}/status", exist_ok=True)
    os.chmod(f"{STATE}/status", 0o755)
    workers = {}
    threading.Thread(target=replay_loop, args=(workers,), daemon=True).start()
    refresh_views()
    seen, nudge = None, 0
    while True:
        accs = load_accounts()
        sig = {s: (a["email"], a["imap_host"], a["imap_port"], a["user"], a["pass"], a.get("imap_security")) for s, a in accs.items()}
        if sig != seen:
            for slug in list(workers):
                if slug not in accs or sig[slug] != (seen or {}).get(slug):
                    old = workers.pop(slug)
                    old.stop = True
                    old.wake.set()
                    if old.proc is not None and old.proc.poll() is None:
                        old.proc.terminate()  # mbsync keeps its state consistent on SIGTERM
                    old.join(timeout=60)
                    if slug not in accs:
                        forget(slug, old.a["email"])
            for slug, a in accs.items():
                if slug not in workers:
                    write_status(slug, ok=True, running=True, messages=count_local(a["email"]), last="starting")
                    workers[slug] = Worker(a)
                    workers[slug].start()
                    log("mirroring", a["email"])
            seen = sig
            refresh_views()
        try:
            t = os.path.getmtime(f"{ACCOUNTS}/.sync-now")  # touched by the page on save
        except OSError:
            t = 0
        if t > nudge:
            if nudge:
                for w in workers.values():
                    w.wake.set()
            nudge = t
        open(f"{STATE}/.alive", "w").close()
        time.sleep(3)


if __name__ == "__main__":
    main()
