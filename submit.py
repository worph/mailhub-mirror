"""MailHub submit: one SMTP login for mail apps, each address sent through its own provider.

A phone or desktop mail app sets up MailHub as one account: IMAPS 993 and this SMTP server on
the same host, with the same device login. Every address the user connected in Settings → Mail
accounts can then send from that account, each through its provider's own SMTP, with that
account's login (the account file the webmail writes: /accounts/<user>/<slug>.json).

  listen   465 implicit TLS (RFC 8314) and 587 STARTTLS (required before AUTH), inside the
           container on 31465 / 31587. The certificate is IMAPS's (/tls, renewed by Maison,
           which restarts this service). AUTH PLAIN and LOGIN only, after TLS.
  login    The device login, checked here against the password file mailhub-mirror renders
           for Dovecot (a copy in /submit/passwd: `name:{SSHA512}…`). Dovecot is never asked,
           so its master login (accepted from the app's private network) cannot be reached
           through this port, and its per-IP slowdown cannot fall on every user at once. A
           PLAIN authorization id other than the user itself is refused, and so is any user
           name that isn't a local one (no `*`, `/`, `@`). Failed logins back off per client IP.
  sender   MAIL FROM must be one of the logged-in user's addresses (the `email` of an account
           file of theirs), and the message's From: header that same single address: anything
           else is 550 5.7.1. The provider is chosen from that address only.
  relay    Synchronous, nothing queued or stored. At MAIL FROM the provider is connected and
           logged in; each RCPT gets the provider's own answer; at the end of DATA the
           provider's reply is the client's: 2xx and 5xx kept, 4xx / timeout / connection
           error -> 4xx. Every reply text names the account ("[addr] …"), so the mail app's
           error says which one failed. Sent copies are the client's business (its local Sent,
           as for the webmail).
  limits   MAILHUB_SUBMIT_DAILY_RCPT recipients per user per rolling 24 h (500), messages up
           to MAILHUB_SUBMIT_MAX_SIZE bytes (25 MB, Gmail's limit), the provider transaction
           at most UPSTREAM_BUDGET s (under Thunderbird's 100 s).
  log      One line per message: user, account, recipients, size, provider code. Never the
           subject or the body; never a password.

Runs as root to read the webmail's private account files (read-only mounts).
"""
import asyncio, base64, collections, email.parser, email.policy, email.utils, hashlib, hmac, json, os, re, smtplib, socket, ssl, threading, time

import warnings

from aiosmtpd.smtp import SMTP, AuthResult, LoginPassword, MISSING

# aiosmtpd's own noise: it sets its deprecated Session.login_data itself, and it can't tell that a
# connection on 465 is TLS from the first byte (it only counts STARTTLS), so it warns on every one
warnings.filterwarnings("ignore", message="Session.login_data is deprecated")
warnings.filterwarnings("ignore", message="Requiring AUTH while not requiring TLS")

ACCOUNTS = os.environ.get("MAILHUB_ACCOUNTS_DIR", "/accounts")
PASSWD = os.environ.get("MAILHUB_SUBMIT_PASSWD", "/submit/passwd")
CERT = os.environ.get("MAILHUB_TLS_CERT", "/tls/cert.pem")
KEY = os.environ.get("MAILHUB_TLS_KEY", "/tls/key.pem")
HOSTNAME = os.environ.get("APP_TLS_HOST", "") or socket.getfqdn()
PORT_TLS = int(os.environ.get("MAILHUB_SUBMIT_PORT_TLS", "31465"))
PORT_STARTTLS = int(os.environ.get("MAILHUB_SUBMIT_PORT_STARTTLS", "31587"))
MAX_SIZE = int(os.environ.get("MAILHUB_SUBMIT_MAX_SIZE", str(25 * 1024 * 1024)))
DAILY_RCPT = int(os.environ.get("MAILHUB_SUBMIT_DAILY_RCPT", "500"))
CONNECT_TIMEOUT = float(os.environ.get("MAILHUB_SUBMIT_CONNECT_TIMEOUT", "20"))
UPSTREAM_BUDGET = float(os.environ.get("MAILHUB_SUBMIT_BUDGET", "90"))
# failed logins per client IP: FAIL_MAX within FAIL_WINDOW s -> refused for 2^n min (n = lockouts), capped
FAIL_MAX, FAIL_WINDOW, LOCK_CAP = 5, 600, 900

# a local user name (mirror.py's NAME_RE): also a Dovecot home and a Baïkal principal
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
SLUG_RE = re.compile(r"[a-z0-9._-]+")


def log(*a):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------------ login ---

class Passwords:
    """The device logins: the passwd-file mailhub-mirror renders, re-read when it changes."""

    def __init__(self, path=PASSWD):
        self.path, self.seen, self.hashes = path, None, {}

    def _load(self):
        try:
            st = os.stat(self.path)
        except OSError:
            self.seen, self.hashes = None, {}
            return
        sig = (st.st_ino, st.st_mtime_ns, st.st_size)
        if sig == self.seen:
            return
        hashes = {}
        try:
            with open(self.path) as f:
                for line in f:
                    name, _, h = line.strip().partition(":")
                    if NAME_RE.fullmatch(name) and h.startswith("{SSHA512}"):
                        hashes[name] = h
        except OSError as e:
            log("device logins unreadable:", repr(e))
            self.seen, self.hashes = None, {}
            return
        self.seen, self.hashes = sig, hashes

    def check(self, name, password):
        self._load()
        h = self.hashes.get(name)
        if not h:
            # same work as a real check: no timing difference for an unknown name
            hmac.compare_digest(hashlib.sha512(password + b"x" * 8).digest(), b"\0" * 64)
            return False
        try:
            raw = base64.b64decode(h[len("{SSHA512}"):], validate=True)
        except Exception:
            return False
        digest, salt = raw[:64], raw[64:]
        return len(digest) == 64 and hmac.compare_digest(hashlib.sha512(password + salt).digest(), digest)


class Backoff:
    """Failed logins per client IP: after FAIL_MAX within FAIL_WINDOW s, every login from that IP
    is refused (unchecked) for 2^n minutes, n counting the lockouts, up to LOCK_CAP s."""

    def __init__(self):
        self.fails = collections.defaultdict(collections.deque)
        self.locked = {}  # ip -> (until, lockouts)

    def blocked(self, ip, now=None):
        now = now or time.monotonic()
        until, _ = self.locked.get(ip, (0, 0))
        return now < until

    def failed(self, ip, now=None):
        now = now or time.monotonic()
        q = self.fails[ip]
        q.append(now)
        while q and q[0] < now - FAIL_WINDOW:
            q.popleft()
        if len(q) >= FAIL_MAX:
            _, n = self.locked.get(ip, (0, 0))
            self.locked[ip] = (now + min(60 * 2 ** n, LOCK_CAP), n + 1)
            q.clear()

    def succeeded(self, ip):
        self.fails.pop(ip, None)


class DailyCap:
    """Recipients per user over a rolling 24 h (in memory: a restart starts again)."""

    def __init__(self, limit=DAILY_RCPT):
        self.limit, self.sent, self.lock = limit, collections.defaultdict(collections.deque), threading.Lock()

    def take(self, user, now=None):
        now = now or time.time()
        with self.lock:
            q = self.sent[user]
            while q and q[0] < now - 86400:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def give_back(self, user):
        with self.lock:
            if self.sent[user]:
                self.sent[user].pop()


# --------------------------------------------------------------- accounts ---

def user_accounts(user, root=ACCOUNTS):
    """{address (lower case): account} from the user's account files, as mailhub-mirror loads them."""
    d = os.path.join(root, user)
    accs = {}
    for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not fn.endswith(".json") or fn.startswith("."):
            continue
        try:
            with open(os.path.join(d, fn)) as f:
                a = json.load(f)
            a["slug"] = fn[:-5]
            addr = a.get("email", "").strip().lower()
            if not SLUG_RE.fullmatch(a["slug"]) or "@" not in addr or "/" in addr:
                raise ValueError("bad slug or address")
            accs[addr] = a
        except Exception as e:
            log(f"[{user}] skipping account file", fn, repr(e))
    return accs


def credentials(account):
    """The provider login for an account: (user, secret). One place, so a token flow (OAuth)
    can replace the password later without touching the relay."""
    return account.get("user") or account["email"], account.get("pass", "")


def has_smtp(account):
    return bool(account.get("smtp_host")) and int(account.get("smtp_port") or 0) > 0


# --------------------------------------------------------------- upstream ---

class Upstream:
    """One SMTP transaction at the provider (blocking smtplib; called from an executor)."""

    def __init__(self, account):
        self.account, self.smtp = account, None

    def open(self, timeout=CONNECT_TIMEOUT):
        a = self.account
        host, port, sec = a["smtp_host"], int(a["smtp_port"]), a.get("smtp_security", "ssl")
        ctx = ssl.create_default_context()
        if sec == "ssl":
            s = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            s = smtplib.SMTP(host, port, timeout=timeout)
        self.smtp = s
        s.ehlo(HOSTNAME)
        if sec == "tls":
            s.starttls(context=ctx)
            s.ehlo(HOSTNAME)
        user, secret = credentials(a)
        if s.has_extn("auth"):
            s.login(user, secret)
        elif sec != "none":
            raise smtplib.SMTPNotSupportedError("the provider offers no AUTH")

    def mail(self, address, body8bit):
        opts = ["BODY=8BITMIME"] if body8bit and self.smtp.has_extn("8bitmime") else []
        return self.smtp.mail(address, opts)

    def rcpt(self, address):
        return self.smtp.rcpt(address)

    def data(self, content):
        return self.smtp.data(content)

    def rset(self):
        try:
            self.smtp.rset()
        except Exception:
            self.close()

    def abort(self):
        """Cut the connection at once (a stalled provider, an error): no QUIT, and a thread still
        blocked on this socket is woken by the close."""
        s, self.smtp = self.smtp, None
        sock = getattr(s, "sock", None) if s else None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def close(self):
        s, self.smtp = self.smtp, None
        if s is None:
            return
        try:
            s.quit()
        except Exception:
            try:
                s.close()
            except Exception:
                pass


def reply(addr, code, text):
    """The provider's answer for the client: 2xx/5xx kept, anything else (4xx, odd codes) 4xx;
    the account named first, the provider's text kept on one line."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    text = " ".join(str(text).split()) or "no reply text"
    if 200 <= code < 300 or 500 <= code < 600:
        out = code
    else:
        out = 451 if not 400 <= code < 500 else code
    return f"{out} [{addr}] {text}"


def failure(addr, e):
    """An exception at the provider as the client's reply."""
    if isinstance(e, smtplib.SMTPAuthenticationError):
        return reply(addr, 535 if 500 <= e.smtp_code < 600 else e.smtp_code,
                     "the provider refused this account's password; change it in Mail accounts: "
                     + (e.smtp_error.decode("utf-8", "replace") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)))
    if isinstance(e, smtplib.SMTPResponseException):
        return reply(addr, e.smtp_code, e.smtp_error)
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        code, text = next(iter(e.recipients.values()))
        return reply(addr, code, text)
    if isinstance(e, (asyncio.TimeoutError, TimeoutError, socket.timeout)):
        return f"451 4.4.2 [{addr}] the provider did not answer in time"
    return f"451 4.4.1 [{addr}] could not reach the provider ({type(e).__name__})"


# ---------------------------------------------------------------- server ---

class Submit(SMTP):
    """aiosmtpd's server with PLAIN's authorization id checked (aiosmtpd drops it) and the
    provider connection closed when the client goes away."""

    async def auth_PLAIN(self, _, args):
        if len(args) == 1:
            raw = await self.challenge_auth("")
            if raw is MISSING:
                return AuthResult(success=False)
        else:
            try:
                raw = base64.b64decode(args[1].encode(), validate=True)
            except Exception:
                await self.push("501 5.5.2 Can't decode base64")
                return AuthResult(success=False, handled=True)
        parts = raw.split(b"\0")
        if len(parts) != 3:
            await self.push("501 5.5.2 Can't split auth value")
            return AuthResult(success=False, handled=True)
        authzid, login, password = parts
        if authzid and authzid != login:
            # acting as another user (Dovecot's master-login form): never, whatever the password
            ip = self.session.peer[0] if self.session.peer else "?"
            self.event_handler.backoff.failed(ip)
            log(f"auth refused ip={ip} user={login.decode('utf-8', 'replace')!r}: authorization id given")
            return AuthResult(success=False, handled=False, message="535 5.7.8 Authentication credentials invalid")
        return self._authenticate("PLAIN", LoginPassword(login, password))

    def connection_lost(self, error):
        up = getattr(self.session, "upstream", None) if self.session else None
        if up is not None:
            self.session.upstream = None
            self.loop.run_in_executor(None, up.close)
        super().connection_lost(error)


class Relay:
    """The login check (aiosmtpd `authenticator`) and the MAIL / RCPT / DATA / RSET hooks."""

    def __init__(self, passwords=None, backoff=None, cap=None, accounts_root=ACCOUNTS, budget=UPSTREAM_BUDGET):
        self.passwords = passwords or Passwords()
        self.backoff = backoff or Backoff()
        self.cap = cap or DailyCap()
        self.accounts_root = accounts_root
        self.budget = budget

    # --- login

    def __call__(self, server, session, envelope, mechanism, auth_data):
        ip = session.peer[0] if session.peer else "?"
        fail = AuthResult(success=False, handled=False)
        if not isinstance(auth_data, LoginPassword):
            return fail
        name = auth_data.login.decode("utf-8", "replace")
        if self.backoff.blocked(ip):
            log(f"auth refused ip={ip} user={name!r} (backing off)")
            return fail
        if NAME_RE.fullmatch(name) and self.passwords.check(name, auth_data.password):
            self.backoff.succeeded(ip)
            return AuthResult(success=True, auth_data=auth_data)
        self.backoff.failed(ip)
        log(f"auth failed ip={ip} user={name!r}")
        return fail

    # --- helpers

    @staticmethod
    def user(session):
        data = session.auth_data
        return data.login.decode() if isinstance(data, LoginPassword) else None

    async def run(self, fn, *a, timeout=None):
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(loop.run_in_executor(None, fn, *a), timeout or self.budget)

    @staticmethod
    def later(up):
        """QUIT the provider in the background: the client's reply doesn't wait for it."""
        if up is not None:
            asyncio.get_running_loop().run_in_executor(None, up.close)

    def drop(self, session):
        up = getattr(session, "upstream", None)
        session.upstream = None
        self.later(up)

    # --- MAIL: the sender is one of the user's addresses; its provider is connected

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        user = self.user(session)
        addr = (address or "").strip().lower()
        self.drop(session)
        session.account = None
        if not addr:
            return "550 5.7.1 a sender address is required"
        account = user_accounts(user, self.accounts_root).get(addr)
        if account is None:
            log(f"[{user}] refused sender {addr}: not one of this user's mail accounts")
            return f"550 5.7.1 {address} is not one of your mail accounts in MailHub"
        if not has_smtp(account):
            return f"550 5.7.0 [{address}] no SMTP server known for this account: open Mail accounts and save it again"
        up = Upstream(account)
        try:
            await self.run(up.open, timeout=CONNECT_TIMEOUT + 10)
            code, text = await self.run(up.mail, account["email"], "BODY=8BITMIME" in mail_options)
        except Exception as e:
            up.abort()
            log(f"[{user}] {addr}: provider refused or unreachable: {type(e).__name__}")
            return failure(account["email"], e)
        if code != 250:
            self.later(up)
            return reply(account["email"], code, text)
        session.upstream, session.account = up, account
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return f"250 2.1.0 [{account['email']}] sender ok"

    # --- RCPT: the provider's own answer, within the daily cap

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        up, account = getattr(session, "upstream", None), getattr(session, "account", None)
        if up is None or account is None:
            return "503 5.5.1 MAIL first"
        user = self.user(session)
        if not self.cap.take(user):
            log(f"[{user}] daily recipient cap reached ({self.cap.limit})")
            return f"452 4.5.3 [{account['email']}] MailHub's daily sending limit ({self.cap.limit} recipients) is reached; try later"
        try:
            code, text = await self.run(up.rcpt, address)
        except Exception as e:
            self.cap.give_back(user)
            session.upstream = None
            up.abort()
            return failure(account["email"], e)
        if code not in (250, 251):
            self.cap.give_back(user)
            return reply(account["email"], code, text)
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return f"250 2.1.5 [{account['email']}] recipient ok"

    # --- DATA: From: is the sender; the provider's reply is the client's

    async def handle_DATA(self, server, session, envelope):
        up, account = getattr(session, "upstream", None), getattr(session, "account", None)
        user = self.user(session)
        if up is None or account is None:
            return "503 5.5.1 MAIL first"
        addr = account["email"]
        content = envelope.original_content or b""
        session.upstream = None  # one message per provider connection
        if not self.from_ok(content, addr):
            self.later(up)
            log(f"[{user}] refused message: From: is not {addr}")
            return f"550 5.7.1 [{addr}] the From: header must be {addr}, the address this message is sent as"
        try:
            code, text = await self.run(up.data, content)
        except smtplib.SMTPDataError as e:
            code, text = e.smtp_code, e.smtp_error
        except Exception as e:
            up.abort()
            log(f"[{user}] account={addr} rcpts={len(envelope.rcpt_tos)} size={len(content)} result={type(e).__name__}")
            return failure(addr, e)
        self.later(up)
        log(f"[{user}] account={addr} rcpts={len(envelope.rcpt_tos)} size={len(content)} code={code}")
        return reply(addr, code, text)

    @staticmethod
    def from_ok(content, addr):
        """The message's From: is exactly one address, `addr` (case-insensitive)."""
        headers = email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(content)
        values = headers.get_all("From") or []
        if len(values) != 1:
            return False
        found = [a for _, a in email.utils.getaddresses(values) if a]
        return len(found) == 1 and found[0].strip().lower() == addr.strip().lower()

    async def handle_RSET(self, server, session, envelope):
        self.drop(session)
        session.account = None
        return "250 2.0.0 OK"


# ------------------------------------------------------------------ main ---

def tls_context(cert=CERT, key=KEY):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def factory(relay, ctx, implicit, loop):
    common = dict(hostname=HOSTNAME, ident="MailHub", data_size_limit=MAX_SIZE, auth_required=True,
                  authenticator=relay, auth_exclude_mechanism=[], loop=loop)
    if implicit:
        # the whole connection is TLS: aiosmtpd only sees STARTTLS as "TLS", so its check is off here
        return lambda: Submit(relay, auth_require_tls=False, **common)
    return lambda: Submit(relay, tls_context=ctx, require_starttls=True, auth_require_tls=True, **common)


async def serve(relay, ctx, host="0.0.0.0", port_tls=PORT_TLS, port_starttls=PORT_STARTTLS):
    loop = asyncio.get_running_loop()
    servers = [
        await loop.create_server(factory(relay, ctx, True, loop), host, port_tls, ssl=ctx),
        await loop.create_server(factory(relay, ctx, False, loop), host, port_starttls),
    ]
    log(f"listening: {port_tls} (TLS), {port_starttls} (STARTTLS) as {HOSTNAME}")
    return servers


async def main():
    servers = await serve(Relay(), tls_context())
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
