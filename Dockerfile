# MailHub mirror: each provider mailbox pulled into a local Maildir with mbsync
# (pull only), IMAP actions on it replayed at the provider, combined views kept
# up to date. See mirror.py. The same image runs mailhub-submit (submit.py: one SMTP login
# for mail apps, each address sent through its own provider) under its own entrypoint.
FROM alpine:3.22
ARG ISYNC_VERSION=1.5.1-r0
ARG PY3_CRYPTOGRAPHY_VERSION=44.0.3-r0
ARG PY3_AIOSMTPD_VERSION=1.4.6-r0
RUN apk add --no-cache "isync=${ISYNC_VERSION}" python3 "py3-cryptography=${PY3_CRYPTOGRAPHY_VERSION}" \
    "py3-aiosmtpd=${PY3_AIOSMTPD_VERSION}" ca-certificates tini
COPY mirror.py webpush.py submit.py /usr/local/bin/
# Root to read the webmail's private account files (uid 33, 0700); mbsync itself
# runs as the mailbox owner (MAILHUB_VMAIL_UID, Dovecot's vmail).
ENTRYPOINT ["/sbin/tini", "--", "python3", "-u", "/usr/local/bin/mirror.py"]
