"""submit.py against a fake provider (aiosmtpd, in-process): logins, the sender check, the
provider's replies, the limits. Runs in the image (aiosmtpd and cryptography are there):

    docker build -t mailhub-mirror . && \
    docker run --rm -v "$PWD/tests:/tests:ro" --entrypoint python3 mailhub-mirror -m unittest discover -s /tests -v
"""
import asyncio, base64, datetime, hashlib, json, os, smtplib, ssl, sys, tempfile, threading, time, unittest

sys.path.insert(0, os.environ.get("MAILHUB_SUBMIT_SRC", "/usr/local/bin"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import submit  # noqa: E402
from aiosmtpd.smtp import SMTP, AuthResult  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

ADMIN_PW, BOB_PW = "admin-device-pw", "bob-device-pw"


def ssha512(pw):
    salt = os.urandom(8)
    return "{SSHA512}" + base64.b64encode(hashlib.sha512(pw.encode() + salt).digest() + salt).decode()


def self_signed(d):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mailhub.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    with open(f"{d}/cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(f"{d}/key.pem", "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return f"{d}/cert.pem", f"{d}/key.pem"


class Provider:
    """The fake provider. By recipient: refuse@ -> 550 at RCPT, later@ -> 451 at RCPT.
    By subject: data-refuse -> 554 at DATA, data-later -> 451, stall -> no answer for 5 s."""

    def __init__(self):
        self.got, self.logins = [], []

    async def handle_RCPT(self, server, session, envelope, address, options):
        if address.startswith("refuse@"):
            return "550 5.1.1 no such user here"
        if address.startswith("later@"):
            return "451 4.3.0 try again later"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        body = envelope.original_content
        if b"Subject: data-refuse" in body:
            return "554 5.7.1 message refused by policy"
        if b"Subject: data-later" in body:
            return "451 4.7.0 sending limit, try later"
        if b"Subject: stall" in body:
            await asyncio.sleep(5)
        self.got.append((session.auth_data.login, envelope.mail_from, list(envelope.rcpt_tos), body))
        return "250 2.0.0 queued as 42"

    def auth(self, server, session, envelope, mechanism, data):
        self.logins.append((data.login, data.password))
        return AuthResult(success=data.password != b"wrong", handled=False, auth_data=data)


class Loop:
    """An asyncio loop in a thread, for the servers."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()

    def run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)


def msg(frm, to="dest@example.org", subject="hello", extra=""):
    return (f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\n{extra}"
            "Message-ID: <1@mailhub.test>\r\n\r\nbody\r\n").encode()


class SubmitTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert, cls.key = self_signed(cls.tmp)
        cls.L = Loop()

        cls.provider = Provider()

        async def start_provider():
            loop = asyncio.get_running_loop()
            srv = await loop.create_server(
                lambda: SMTP(cls.provider, authenticator=cls.provider.auth, auth_require_tls=False, loop=loop),
                "127.0.0.1", 0)
            return srv.sockets[0].getsockname()[1]
        cls.pport = cls.L.run(start_provider())

        # device logins and account files
        os.makedirs(f"{cls.tmp}/submit")
        with open(f"{cls.tmp}/submit/passwd", "w") as f:
            f.write(f"admin:{ssha512(ADMIN_PW)}\nbob:{ssha512(BOB_PW)}\n")
        acc = f"{cls.tmp}/accounts"
        smtp = {"smtp_host": "127.0.0.1", "smtp_port": cls.pport, "smtp_security": "none"}
        cls.write(f"{acc}/admin/alice_at_a.test.json", {"email": "alice@a.test", "user": "alice@a.test", "pass": "alice-app-pw", **smtp})
        cls.write(f"{acc}/admin/contact_at_b.test.json", {"email": "contact@b.test", "user": "contact@b.test", "pass": "x"})
        cls.write(f"{acc}/admin/wrong_at_a.test.json", {"email": "wrong@a.test", "user": "wrong@a.test", "pass": "wrong", **smtp})
        cls.write(f"{acc}/admin/.push.json", {"email": "push@a.test"})
        cls.write(f"{acc}/bob/bob_at_c.test.json", {"email": "bob@c.test", "user": "bob@c.test", "pass": "bob-app-pw", **smtp})

        cls.relay = submit.Relay(passwords=submit.Passwords(f"{cls.tmp}/submit/passwd"), accounts_root=acc, budget=2)
        ctx = submit.tls_context(cls.cert, cls.key)

        async def start_relay():
            servers = await submit.serve(cls.relay, ctx, "127.0.0.1", 0, 0)
            return [s.sockets[0].getsockname()[1] for s in servers]
        cls.port_tls, cls.port_starttls = cls.L.run(start_relay())

    @staticmethod
    def write(path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f)

    def setUp(self):
        self.relay.backoff = submit.Backoff()
        self.relay.cap = submit.DailyCap()
        self.provider.got.clear()
        self.provider.logins.clear()

    # --- clients

    @staticmethod
    def ctx():
        c = ssl.create_default_context()
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        return c

    def tls(self):
        return smtplib.SMTP_SSL("127.0.0.1", self.port_tls, context=self.ctx(), timeout=10)

    def starttls(self):
        s = smtplib.SMTP("127.0.0.1", self.port_starttls, timeout=10)
        s.starttls(context=self.ctx())
        return s

    def logged_in(self, user="admin", pw=ADMIN_PW):
        s = self.tls()
        s.login(user, pw)
        return s

    def plain(self, s, authzid, user, pw):
        s.ehlo()
        return s.docmd("AUTH", "PLAIN " + base64.b64encode(f"{authzid}\0{user}\0{pw}".encode()).decode())

    # --- 1. logins: the device login only, never anyone else's

    def test_login_device_password(self):
        s = self.tls()
        self.assertEqual(s.login("admin", ADMIN_PW)[0], 235)
        s.quit()

    def test_login_starttls_port(self):
        s = self.starttls()
        self.assertEqual(s.login("bob", BOB_PW)[0], 235)
        s.quit()

    def test_starttls_port_refuses_auth_before_tls(self):
        s = smtplib.SMTP("127.0.0.1", self.port_starttls, timeout=10)
        s.ehlo()
        code, _ = s.docmd("AUTH", "PLAIN " + base64.b64encode(f"\0admin\0{ADMIN_PW}".encode()).decode())
        self.assertNotEqual(code, 235)
        code, _ = s.docmd("MAIL", "FROM:<alice@a.test>")
        self.assertGreaterEqual(code, 500)
        s.close()

    def test_login_wrong_password(self):
        with self.assertRaises(smtplib.SMTPAuthenticationError):
            self.tls().login("admin", "nope")

    def test_login_authzid_other_user_refused(self):
        # bob's own password, acting as admin: Dovecot's master-login form
        self.assertEqual(self.plain(self.tls(), "admin", "bob", BOB_PW)[0], 535)

    def test_login_authzid_self_allowed(self):
        self.assertEqual(self.plain(self.tls(), "admin", "admin", ADMIN_PW)[0], 235)

    def test_login_master_syntax_refused(self):
        for name in ("admin*mailhub-mirror", "admin/x", "admin@mailhub", "*admin", "ADMIN"):
            with self.subTest(name=name):
                with self.assertRaises(smtplib.SMTPAuthenticationError):
                    self.tls().login(name, ADMIN_PW)

    def test_mail_needs_login(self):
        s = self.tls()
        s.ehlo()
        self.assertGreaterEqual(s.docmd("MAIL", "FROM:<alice@a.test>")[0], 500)

    def test_backoff(self):
        for _ in range(submit.FAIL_MAX):
            with self.assertRaises(smtplib.SMTPAuthenticationError):
                self.tls().login("admin", "nope")
        # now even the right password is refused from this IP
        with self.assertRaises(smtplib.SMTPAuthenticationError):
            self.tls().login("admin", ADMIN_PW)

    def test_one_wrong_password_counts_once(self):
        # smtplib tries PLAIN, then LOGIN: two refusals, one failure for the backoff
        with self.assertRaises(smtplib.SMTPAuthenticationError):
            self.tls().login("admin", "nope")
        self.assertEqual(len(self.relay.backoff.fails["127.0.0.1"]), 1)

    def test_connection_closed_after_failed_logins(self):
        s = self.tls()
        s.ehlo()
        for _ in range(submit.CONN_FAILS):
            self.assertEqual(self.plain(s, "", "admin", "nope")[0], 535)
        # the relay sent 421 after the second refusal and hung up: no third guess here
        try:
            code = s.noop()[0]
        except (smtplib.SMTPServerDisconnected, ConnectionError, ssl.SSLError):
            code = 421
        self.assertEqual(code, 421)
        s.close()

    def test_backoff_grows(self):
        b, t = submit.Backoff(), 1000.0
        for _ in range(submit.FAIL_MAX):
            b.failed("1.2.3.4", t)
        self.assertTrue(b.blocked("1.2.3.4", t + 59))
        self.assertFalse(b.blocked("1.2.3.4", t + 61))
        for _ in range(submit.FAIL_MAX):
            b.failed("1.2.3.4", t + 100)
        self.assertTrue(b.blocked("1.2.3.4", t + 100 + 119))
        self.assertFalse(b.blocked("5.6.7.8", t + 100))

    # --- 2. no open relay

    def test_send_ok(self):
        s = self.logged_in()
        refused = s.sendmail("alice@a.test", ["dest@example.org", "other@example.org"], msg("Alice <alice@a.test>"))
        s.quit()
        self.assertEqual(refused, {})
        login, mail_from, rcpts, body = self.provider.got[-1]
        self.assertEqual(login, b"alice@a.test")  # the account's own provider login
        self.assertEqual(mail_from, "alice@a.test")
        self.assertEqual(rcpts, ["dest@example.org", "other@example.org"])
        self.assertIn(b"Subject: hello", body)

    def test_sender_case_insensitive(self):
        s = self.logged_in()
        self.assertEqual(s.sendmail("Alice@A.test", ["dest@example.org"], msg("ALICE@a.test")), {})

    def test_foreign_sender_refused(self):
        s = self.logged_in()
        with self.assertRaises(smtplib.SMTPSenderRefused) as e:
            s.sendmail("ceo@bank.example", ["dest@example.org"], msg("ceo@bank.example"))
        self.assertEqual(e.exception.smtp_code, 550)
        self.assertEqual(self.provider.logins, [])  # no provider touched

    def test_other_users_address_refused(self):
        s = self.logged_in()  # admin
        with self.assertRaises(smtplib.SMTPSenderRefused) as e:
            s.sendmail("bob@c.test", ["dest@example.org"], msg("bob@c.test"))
        self.assertEqual(e.exception.smtp_code, 550)

    def test_dotfile_not_an_account(self):
        s = self.logged_in()
        with self.assertRaises(smtplib.SMTPSenderRefused):
            s.sendmail("push@a.test", ["dest@example.org"], msg("push@a.test"))

    def test_from_header_must_match(self):
        s = self.logged_in()
        for frm in ("contact@b.test", "ceo@bank.example", "alice@a.test, ceo@bank.example"):
            with self.subTest(frm=frm):
                with self.assertRaises(smtplib.SMTPDataError) as e:
                    s.sendmail("alice@a.test", ["dest@example.org"], msg(frm))
                self.assertEqual(e.exception.smtp_code, 550)
        self.assertEqual(self.provider.got, [])

    def test_two_from_headers_refused(self):
        s = self.logged_in()
        with self.assertRaises(smtplib.SMTPDataError):
            s.sendmail("alice@a.test", ["dest@example.org"], msg("alice@a.test", extra="From: ceo@bank.example\r\n"))

    def test_missing_from_refused(self):
        s = self.logged_in()
        with self.assertRaises(smtplib.SMTPDataError):
            s.sendmail("alice@a.test", ["dest@example.org"], b"To: dest@example.org\r\nSubject: x\r\n\r\nbody\r\n")

    def test_null_sender_refused(self):
        s = self.logged_in()
        s.ehlo()
        self.assertGreaterEqual(s.docmd("MAIL", "FROM:<>")[0], 500)

    def test_account_without_smtp(self):
        s = self.logged_in()
        with self.assertRaises(smtplib.SMTPSenderRefused) as e:
            s.sendmail("contact@b.test", ["dest@example.org"], msg("contact@b.test"))
        self.assertEqual(e.exception.smtp_code, 550)
        self.assertIn(b"save it again", e.exception.smtp_error)

    # --- 3. the provider's replies

    def test_provider_refuses_one_recipient(self):
        s = self.logged_in()
        refused = s.sendmail("alice@a.test", ["dest@example.org", "refuse@example.org"], msg("alice@a.test"))
        self.assertEqual(list(refused), ["refuse@example.org"])
        self.assertEqual(refused["refuse@example.org"][0], 550)
        self.assertIn(b"[alice@a.test]", refused["refuse@example.org"][1])
        self.assertEqual(self.provider.got[-1][2], ["dest@example.org"])

    def test_provider_tempfails_recipient(self):
        s = self.logged_in()
        refused = s.sendmail("alice@a.test", ["dest@example.org", "later@example.org"], msg("alice@a.test"))
        self.assertEqual(refused["later@example.org"][0], 451)

    def test_provider_refuses_data(self):
        s = self.logged_in()
        with self.assertRaises(smtplib.SMTPDataError) as e:
            s.sendmail("alice@a.test", ["dest@example.org"], msg("alice@a.test", subject="data-refuse"))
        self.assertEqual(e.exception.smtp_code, 554)
        self.assertIn(b"[alice@a.test]", e.exception.smtp_error)

    def test_provider_tempfails_data(self):
        s = self.logged_in()
        with self.assertRaises(smtplib.SMTPDataError) as e:
            s.sendmail("alice@a.test", ["dest@example.org"], msg("alice@a.test", subject="data-later"))
        self.assertEqual(e.exception.smtp_code, 451)

    def test_provider_stalls(self):
        s = self.logged_in()
        t = time.monotonic()
        with self.assertRaises(smtplib.SMTPDataError) as e:
            s.sendmail("alice@a.test", ["dest@example.org"], msg("alice@a.test", subject="stall"))
        self.assertEqual(e.exception.smtp_code, 451)
        self.assertLess(time.monotonic() - t, 4.5)  # the budget (2 s here), not the provider

    def test_provider_refuses_password(self):
        s = self.logged_in()
        with self.assertRaises(smtplib.SMTPSenderRefused) as e:
            s.sendmail("wrong@a.test", ["dest@example.org"], msg("wrong@a.test"))
        self.assertEqual(e.exception.smtp_code, 535)
        self.assertIn(b"Mail accounts", e.exception.smtp_error)

    def test_two_messages_one_session(self):
        s = self.logged_in()
        s.sendmail("alice@a.test", ["dest@example.org"], msg("alice@a.test"))
        s.sendmail("alice@a.test", ["dest2@example.org"], msg("alice@a.test"))
        s.quit()
        self.assertEqual([g[2] for g in self.provider.got], [["dest@example.org"], ["dest2@example.org"]])

    # --- 4. limits

    def test_daily_cap(self):
        self.relay.cap = submit.DailyCap(2)
        s = self.logged_in()
        refused = s.sendmail("alice@a.test", ["a@example.org", "b@example.org", "c@example.org"], msg("alice@a.test"))
        self.assertEqual(refused["c@example.org"][0], 452)
        # refused recipients don't count
        self.relay.cap = submit.DailyCap(1)
        s.sendmail("alice@a.test", ["refuse@example.org", "a@example.org"], msg("alice@a.test"))
        self.assertEqual(self.provider.got[-1][2], ["a@example.org"])

    def test_size_advertised(self):
        s = self.logged_in()
        s.ehlo()
        self.assertEqual(int(s.esmtp_features["size"]), submit.MAX_SIZE)


if __name__ == "__main__":
    unittest.main()
