"""
SMTPExfilConfig -- mwcp parser for SMTP exfiltration credential extraction.

Many commodity RATs and stealers exfiltrate via hardcoded SMTP credentials.
Common families: Agent Tesla, HawkEye, Formbook, Netwire, LokiBot.

Config typically appears as:
  - SMTP host (smtp.*, mail.*, or any domain) near a port number (25/465/587/2525)
  - Username (email address) near the host
  - Password (plaintext or base64) adjacent to the username

Detection strategy:
  1. Find SMTP host indicators (smtp., mail. prefixes or known SMTP ports)
  2. Extract username/email and password from proximity context
  3. Require at least host + password to emit (host alone is too noisy)

Credentials are IMMEDIATELY ACTIONABLE for incident response:
  - Can be used to log into the attacker's mailbox and recover exfiltrated data
  - Provides attribution (email account registration info)

Staged by Build-OfflineToolkit.ps1 -IncludeMWCP.
"""

import re
import mwcp
from mwcp.metadata import C2Address, Password, DecodedString

# SMTP host patterns: smtp.*, mail.*, must start at a word boundary (not inside an email @-address).
# Negative lookbehind ensures we don't match the domain portion of user@mail.example.com.
_SMTP_HOST_RE = re.compile(
    rb'(?<![a-zA-Z0-9@])(?:smtp|mail)\.[a-zA-Z0-9\.\-]{3,100}',
    re.IGNORECASE
)
# Common SMTP port numbers (including submission variants)
_SMTP_PORTS = {25, 465, 587, 2525, 26, 2526}
# SMTP port number appearing as bytes (with possible delimiters)
_PORT_RE = re.compile(
    rb'(?:\b|[\x00:;,\s])(' + b'|'.join(str(p).encode() for p in sorted(_SMTP_PORTS)) + rb')(?:\b|[\x00:;,\s])'
)

# Email address (username) pattern
_EMAIL_RE = re.compile(
    rb'[a-zA-Z0-9][a-zA-Z0-9\.\+\-\_]{0,63}@[a-zA-Z0-9\.\-]{3,100}\.[a-zA-Z]{2,10}',
    re.IGNORECASE
)

# Password heuristic: a non-whitespace, non-null string of 4-64 chars following
# common password field delimiters. In .NET resources these often appear as raw
# strings near the email address.
_PASS_LABEL_RE = re.compile(
    rb'(?:password|pass|pwd|secret|key|cred)["\s:=\x00]{0,8}([^\x00\r\n"\'<>\s]{4,64})',
    re.IGNORECASE
)
# Bare password-length strings adjacent to email addresses (no label)
_BARE_PASS_RE = re.compile(
    rb'[A-Za-z0-9!@#\$%\^&\*\(\)\-_=\+\[\]\{\}\|;:,./<>\?]{6,64}'
)

# Context window around SMTP host to search for credentials
_CONTEXT_WINDOW = 512


def _clean(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def _find_smtp_hosts(data: bytes) -> list:
    """Return list of (offset, host_str) for all SMTP host matches."""
    results = []
    for m in _SMTP_HOST_RE.finditer(data):
        host = _clean(m.group(0))
        if host:
            results.append((m.start(), host))
    return results


def _find_port_near(data: bytes, offset: int) -> str | None:
    """Find an SMTP port number within context window of the given offset."""
    lo = max(0, offset - _CONTEXT_WINDOW)
    hi = min(len(data), offset + _CONTEXT_WINDOW)
    ctx = data[lo:hi]
    for m in _PORT_RE.finditer(ctx):
        try:
            p = int(_clean(m.group(1)))
            if p in _SMTP_PORTS:
                return str(p)
        except ValueError:
            continue
    return None


def _find_email_near(data: bytes, offset: int) -> str | None:
    """Find an email address (username) within context window of the given offset."""
    lo = max(0, offset - _CONTEXT_WINDOW)
    hi = min(len(data), offset + _CONTEXT_WINDOW)
    ctx = data[lo:hi]
    m = _EMAIL_RE.search(ctx)
    if m:
        return _clean(m.group(0))
    return None


def _find_password_near(data: bytes, offset: int, email: str | None) -> str | None:
    """Find a password in the context window. Prefer labelled passwords, fall back to
    bare strings that appear after the email address."""
    lo = max(0, offset - _CONTEXT_WINDOW)
    hi = min(len(data), offset + _CONTEXT_WINDOW)
    ctx = data[lo:hi]

    # Labelled password
    for m in _PASS_LABEL_RE.finditer(ctx):
        val = _clean(m.group(1))
        if val and val not in ('smtp', 'mail', 'email', 'password', 'pass'):
            return val

    # Bare string after email in context -- only if email was found
    if email:
        email_b = email.encode('utf-8', 'ignore')
        email_pos = ctx.find(email_b)
        if email_pos != -1:
            after = ctx[email_pos + len(email_b):]
            # Skip delimiters
            after = after.lstrip(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\r\n\t :;,|')
            m = _BARE_PASS_RE.match(after)
            if m:
                val = _clean(m.group(0))
                # Must not look like a domain or URL
                if val and '.' not in val and val not in ('smtp', 'mail', 'email'):
                    return val

    return None


class SMTPExfilConfig(mwcp.Parser):
    """Extract hardcoded SMTP exfiltration credentials from PE or carved regions."""

    DESCRIPTION = "SMTP Exfiltration Credential Extractor"

    @classmethod
    def identify(cls, file_object) -> bool:
        data = file_object.data or b''
        if len(data) < 32:
            return False
        # Run on PE files, UNKNOWN (carved), and scripts that may contain stager SMTP configs
        is_pe = data[:2] == b'MZ'
        # Quick check: does the file contain any SMTP indicator?
        has_smtp = (b'smtp.' in data.lower() or b'mail.' in data.lower() or
                    b'587' in data or b'465' in data)
        return is_pe or has_smtp

    def run(self):
        data = self.file_object.data
        if not data:
            return

        seen = set()

        smtp_hosts = _find_smtp_hosts(data)
        if not smtp_hosts:
            return

        for offset, host in smtp_hosts:
            port    = _find_port_near(data, offset) or '587'
            email   = _find_email_near(data, offset)
            password = _find_password_near(data, offset, email)

            # Require at least a password to be worth reporting
            if not password:
                continue

            c2 = f'{host}:{port}'
            if c2 not in seen:
                seen.add(c2)
                self.report.add(C2Address(c2))

            if password not in seen:
                seen.add(password)
                self.report.add(Password(password))

            # Build credential summary for analyst
            parts = [f'[SMTPExfil] host={host}:{port}']
            if email:
                parts.append(f'user={email}')
            parts.append(f'pass={password}')
            tag = ' | '.join(parts)

            if tag not in seen:
                seen.add(tag)
                self.report.add(DecodedString(tag))

            # Emit email address separately as a decoded string (pivotable IOC)
            if email:
                email_tag = f'[SMTPExfil-User] {email}'
                if email_tag not in seen:
                    seen.add(email_tag)
                    self.report.add(DecodedString(email_tag))
