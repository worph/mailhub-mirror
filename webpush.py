"""Web Push (RFC 8030) with VAPID (RFC 8292) and aes128gcm payload encryption (RFC 8291).

Just what mailhub-mirror needs to notify a browser subscription, on `cryptography`
and the standard library: a server keypair kept on disk, one encrypted POST per
notification. The push service (FCM, Mozilla, Apple) only relays the ciphertext.
"""
import base64, hashlib, hmac, json, os, struct, time, urllib.error, urllib.parse, urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RECORD_SIZE = 4096


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text):
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def raw_public(key):
    """A P-256 public key as the 65-byte uncompressed point."""
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def hkdf(salt, ikm, info, length):
    """HKDF-SHA256 with a single expand block (length <= 32), as RFC 8291 uses it."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


class Vapid:
    """The application server's keypair: generated once, the private key never leaves `dir`."""

    def __init__(self, key, subject):
        self.key, self.subject = key, subject
        self.public = b64u(raw_public(key))

    @classmethod
    def load_or_create(cls, dir, subject, uid=0):
        """`dir`/vapid.json (0600, the private key) and `dir`/vapid-public.txt (0644,
        what browsers subscribe with; the webmail reads it)."""
        os.makedirs(dir, exist_ok=True)
        os.chmod(dir, 0o755)
        priv = os.path.join(dir, "vapid.json")
        try:
            with open(priv) as f:
                d = int.from_bytes(unb64u(json.load(f)["d"]), "big")
            key = ec.derive_private_key(d, ec.SECP256R1())
        except (OSError, ValueError, KeyError):
            key = ec.generate_private_key(ec.SECP256R1())
            d = key.private_numbers().private_value.to_bytes(32, "big")
            tmp = priv + ".tmp"
            with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                json.dump({"d": b64u(d), "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f)
            os.replace(tmp, priv)
        v = cls(key, subject)
        pub = os.path.join(dir, "vapid-public.txt")
        try:
            current = open(pub).read().strip()
        except OSError:
            current = None
        if current != v.public:
            tmp = pub + ".tmp"
            with open(tmp, "w") as f:
                f.write(v.public + "\n")
            os.chmod(tmp, 0o644)
            os.replace(tmp, pub)
        return v

    def authorization(self, endpoint):
        """The `Authorization: vapid t=<JWT>, k=<key>` header for this push service."""
        u = urllib.parse.urlsplit(endpoint)
        header = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
        claims = b64u(json.dumps({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 12 * 3600,
                                  "sub": self.subject}, separators=(",", ":")).encode())
        signing_input = f"{header}.{claims}".encode()
        r, s = decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        sig = b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return f"vapid t={header}.{claims}.{sig}, k={self.public}"


def encrypt(payload, p256dh, auth, salt=None, server_key=None):
    """RFC 8291: the body of an aes128gcm push message to the subscription (p256dh, auth)."""
    ua_public = unb64u(p256dh)
    auth_secret = unb64u(auth)
    server_key = server_key or ec.generate_private_key(ec.SECP256R1())
    as_public = raw_public(server_key)
    shared = server_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public))
    ikm = hkdf(auth_secret, shared, b"WebPush: info\x00" + ua_public + as_public, 32)
    salt = salt or os.urandom(16)
    cek = hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    data = payload if isinstance(payload, bytes) else payload.encode()
    if len(data) > RECORD_SIZE - 17 - 86:
        raise ValueError("push payload too large")
    body = AESGCM(cek).encrypt(nonce, data + b"\x02", None)  # 0x02: last (only) record
    return salt + struct.pack("!IB", RECORD_SIZE, len(as_public)) + as_public + body


def send(vapid, sub, payload, ttl=86400, urgency="normal", timeout=20):
    """POST one notification. Returns (status, text): 201/202 delivered to the push service,
    404/410 the subscription is gone, anything else an error worth showing."""
    endpoint = sub["endpoint"]
    if urllib.parse.urlsplit(endpoint).scheme != "https":
        return 0, "endpoint is not https"
    body = encrypt(json.dumps(payload, separators=(",", ":")), sub["p256dh"], sub["auth"])
    req = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Authorization": vapid.authorization(endpoint),
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        "TTL": str(int(ttl)),
        "Urgency": urgency,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, ""
    except urllib.error.HTTPError as e:
        try:
            text = e.read(300).decode("utf-8", "replace").strip()
        except Exception:
            text = ""
        return e.code, text or e.reason
    except Exception as e:
        return 0, repr(e)[:300]
