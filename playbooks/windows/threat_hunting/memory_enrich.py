#!/usr/bin/env python3
"""
memory_enrich.py - per-true-positive memory footprint extractor (eradication scope).

The YARA pivot identifies WHICH processes are true positives; this gathers, for each of
those PIDs, EVERYTHING the implant touched that the memory image still holds, so eradication
can be complete and nothing is missed:

    handles   -> dropped files, registry persistence (Run/Services/IFEO), mutexes (implant
                 locks), named pipes / ALPC (C2 IPC)
    modules   -> loaded DLLs + injected/unbacked executable regions
    network   -> C2 endpoints to block
    lineage   -> parent + child processes (the rest of the foothold)
    region    -> the injected exec region carved to _region_<pid>_<addr>.bin, with C2-config
                 IOCs (IPs / domains / URLs) recovered from it for offline capa/CyberChef
    first-seen -> the process create time (from the main thread's ftCreateTime) - the RAM anchor
                 that gets correlated against USB device first-connect times to test the entry vector

Output: Memory_Enrichment_<ts>.json - a per-PID dossier plus a rolled-up eradication IOC bundle;
Memory_Enrichment.md; the memory-derived chain + a first-seen correlation timeline appended to
Attack_Graph.md; and Timeline_Correlation.md. Only ELEVATES/collects - it never suppresses a finding.

Usage: memory_enrich.py <image> <out_dir> <pid>[,<pid>...]
       memory_enrich.py --correlate <out_dir>   # re-join RAM<->USB first-seen (no image; run after
                                                 # collecting USB history live on the affected host)
"""
import sys, os, re, json, glob, gzip, bisect
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ---------------------------------------------------------------- pure helpers
# (no vmm dependency - unit-tested directly)

# Registry paths that are genuine autostart/injection persistence VECTORS. A handle alone shows
# only that a key was opened, not its value - so flag ONLY high-signal autostart locations a normal
# process would not touch, and require a SPECIFIC image subkey for IFEO / a binary value for a
# Service. This deliberately excludes the IFEO root (every process's loader opens it) and generic
# Service config keys (a service host legitimately holds hundreds) to avoid an FP flood. Actual
# persistence VALUES are corroborated by the dedicated persistence snapshot (it reads the values).
_PERSIST_KEY_RE = re.compile(
    r"(?i)("
    r"CurrentVersion\\Run(Once|Services|ServicesOnce)?(\\|$)|"
    r"\\Policies\\Explorer\\Run(\\|$)|"
    r"CurrentVersion\\Winlogon(\\|$)|"
    r"\\(AppInit_DLLs|AppCertDLLs)\b|"
    r"Image File Execution Options\\[^\\]+\.(exe|dll|com|scr)|"   # a specific image's IFEO entry
    r"Services\\[^\\]+\\(ImagePath|ServiceDll)(\\|$)|"
    r"Services\\[^\\]+\\Parameters\\ServiceDll)")

# A normal Windows mutant/event name has recognisable structure (a known prefix or a
# colon-delimited form). An implant lock is typically a bare high-entropy token.
# SM0:PID:session:NAME -- not blanket-suppressed; NAME component evaluated separately.
# WilStaging is intentionally NOT in this list: state-sponsored APT groups use
# WilStaging-named mutexes as a Windows camouflage technique. Evaluate by NAME.
# WilError IS in this list (documented WIL error-tracking mutex, not an APT signal).
# SmartScreen* mutexes are Windows security component synchronization objects.
_KNOWN_OBJ_PREFIX = re.compile(
    r"(?i)^(Local\\|Global\\|Session\\|__|Microsoft|Windows|WilError|SmartScreen|"
    r"DBWin|MSCTF|RotHint|UrlZones|\{|OLE|\[)")
_HEX_TOKEN = re.compile(r"^[0-9A-Fa-f]{6,}$")

# SM0:PID:session:NAME mutexes -- evaluate the NAME component, not the full string.
# Known-good SM0 name components: WilError_N (WIL error tracking, always legitimate).
# WilStaging is NOT known-good -- used as APT camouflage.
_SM0_RE = re.compile(r"^SM0:\d+:\d+:(.+)$", re.IGNORECASE)
_SM0_KNOWN_NAMES = re.compile(r"(?i)^WilError_\d+$")

_TEMP_FILE_RE = re.compile(
    r"(?i)\\(Temp|Tmp|AppData\\Local\\Temp|ProgramData|Users\\Public|Windows\\Temp)\\")

# C2 indicators recovered from memory. URLs include mining-pool (stratum) and other non-web C2
# schemes - a miner's `stratum+tcp://pool:port` is a C2 endpoint just like an http beacon.
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# URL path restricted to printable RFC3986 chars so a match stops at the binary that follows in memory
_URL_RE = re.compile(
    r"(?i)\b(?:https?|ftp|stratum\+(?:tcp|udp|ssl)|tcp|ws|wss)://"
    r"[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]*)?")
_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|ru|cn|io|co|xyz|top|club|online|site|tk|pw|cc|su|me)\b")
# Loopback / link-local / obviously-internal noise to drop from C2 candidates.
_BENIGN_IP_RE = re.compile(r"^(0\.|127\.|169\.254\.|255\.|224\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
# Microsoft / OS / common-platform domains that are not C2 (suffix match).
_BENIGN_DOMAIN_RE = re.compile(
    r"(?i)("
    r"microsoft\.com|microsoftonline\.com|windows\.com|windows\.net|windowsupdate\.com|"
    r"msftncsi\.com|msftconnecttest\.com|office\.com|office\.net|live\.com|live\.net|skype\.com|"
    r"skype\.net|teams\.microsoft\.com|msedge\.net|sfx\.ms|bing\.com|msn\.com|azureedge\.net|"
    r"azure\.com|digicert\.com|verisign\.com|entrust\.net|sectigo\.com|globalsign\.com|"
    r"google\.com|googleapis\.com|gstatic\.com|gvt1\.com|gvt2\.com|mozilla\.org|mozilla\.com|"
    r"cloudflare\.com|akamai\.net|akamaiedge\.net|w3\.org|schemas\.microsoft\.com|apple\.com)$")


# Real-looking-domain check - STRUCTURAL ONLY (we never resolve DNS). A host is "confident" when its
# last label is a recognised TLD - any 2-letter ccTLD (every ccTLD is exactly 2 letters, so that rule
# is complete), or one of the common gTLDs below - AND every label is RFC-1035 shaped.
# NOTE: this gTLD set is deliberately a COMMON subset, not the full ~1450-entry IANA list. So a real
# domain on an uncommon gTLD (e.g. `.ninja`) will NOT match here - which is exactly why a non-matching
# host is moved to `unverified` ("not resolvable - verify"), NOT deleted. We never assert it as an IOC,
# and never invent one; the analyst (or a later IANA-list check) confirms it. The aim is a clean,
# high-confidence `domains` list plus a transparent `unverified` bucket - no silent suppression.
_GTLD = frozenset((
    "com net org info biz xyz top club online site app dev cloud shop store tech space website "
    "live news blog page link click work fun icu vip pro name mobi asia tel pub win bid loan men "
    "date stream download racing party review trade science gdn ren xin wang ltd group team today "
    "email host run cyou sbs world life fund money company center systems solutions services "
    "digital network media monster pics photos cc su pw tk ninja guru ws me tv io co").split())
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")


def _valid_tld(tld):
    """A TLD is plausible if it is any 2-letter ccTLD (all ccTLDs are 2 letters) or a known gTLD."""
    tld = str(tld).lower()
    return (len(tld) == 2 and tld.isalpha()) or tld in _GTLD


def _valid_host(h):
    """True when h is structurally a real domain: >=2 RFC-1035 labels and a valid TLD. No DNS."""
    h = str(h or "").strip().rstrip(".").lower()
    if not h or len(h) > 253 or "." not in h:
        return False
    labels = h.split(".")
    return len(labels) >= 2 and _valid_tld(labels[-1]) and all(_LABEL_RE.match(l) for l in labels)


def _url_host_ok(h):
    """Lenient gate for KEEPING a URL (not for deriving a domain): a valid IP, or a dotted host with
    non-empty labels. Drops only the clearly-truncated junk (`http://micr`, `http://mtsvc9`)."""
    if _IPV4_RE.fullmatch(str(h)):
        return True
    labels = str(h).split(".")
    return len(labels) >= 2 and all(labels)


# ----------------------------------------------------------- offline geolocation
# Country-of-origin for a recovered IP, looked up in a LOCAL DB (db-ip.com Country Lite, a keyless,
# CC-BY, GeoLite2-equivalent staged by Build-OfflineToolkit.ps1 -IncludeGeoIP). 100% OFFLINE - never a
# DNS / whois / API call. Ties an IOC to real infrastructure (e.g. an OVH/France node that matches an
# active threat-intel campaign) so attribution starts before any external lookup.
_GEOIP_DIR = Path(__file__).resolve().parent.parent.parent.parent / "tools" / "geoip"
_GEO = {"loaded": False, "starts": [], "ends": [], "ccs": []}
_CC_NAME = {
    "US": "United States", "KR": "South Korea", "RU": "Russia", "FR": "France", "CN": "China",
    "DE": "Germany", "NL": "Netherlands", "GB": "United Kingdom", "JP": "Japan", "IN": "India",
    "BR": "Brazil", "CA": "Canada", "UA": "Ukraine", "RO": "Romania", "TR": "Turkey", "IR": "Iran",
    "HK": "Hong Kong", "SG": "Singapore", "VN": "Vietnam", "ID": "Indonesia", "PL": "Poland",
    "IT": "Italy", "ES": "Spain", "SE": "Sweden", "CH": "Switzerland", "AU": "Australia",
    "TW": "Taiwan", "KP": "North Korea", "BG": "Bulgaria", "MD": "Moldova", "SC": "Seychelles",
    "PA": "Panama", "BZ": "Belize", "VG": "British Virgin Islands", "AE": "United Arab Emirates",
}


def _ip_to_int(ip):
    parts = str(ip).split(".")
    if len(parts) != 4:
        return None
    try:
        octs = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octs):
        return None
    return (octs[0] << 24) | (octs[1] << 16) | (octs[2] << 8) | octs[3]


def _load_geoip():
    """Lazy-load the IPv4 ranges from tools/geoip/dbip-country-lite.csv[.gz] into sorted arrays."""
    if _GEO["loaded"]:
        return
    _GEO["loaded"] = True
    src = None
    for cand in (_GEOIP_DIR / "dbip-country-lite.csv.gz", _GEOIP_DIR / "dbip-country-lite.csv"):
        if cand.is_file():
            src = cand
            break
    if not src:
        return
    opener = gzip.open if str(src).endswith(".gz") else open
    starts, ends, ccs = [], [], []
    try:
        with opener(src, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                p = line.rstrip("\n").split(",")
                if len(p) < 3 or ":" in p[0]:          # IPv4 rows only
                    continue
                s, e = _ip_to_int(p[0]), _ip_to_int(p[1])
                if s is None or e is None:
                    continue
                starts.append(s); ends.append(e); ccs.append(p[2].strip().upper())
    except Exception:
        return
    _GEO["starts"], _GEO["ends"], _GEO["ccs"] = starts, ends, ccs


def country_of_ip(ip):
    """OFFLINE ISO-3166 country code for an IPv4 (None if no DB / no match / unallocated). No network."""
    _load_geoip()
    starts = _GEO["starts"]
    if not starts:
        return None
    n = _ip_to_int(ip)
    if n is None:
        return None
    i = bisect.bisect_right(starts, n) - 1
    if 0 <= i < len(starts) and starts[i] <= n <= _GEO["ends"][i]:
        cc = _GEO["ccs"][i]
        return cc if (cc and cc != "ZZ") else None
    return None


def geo_label(ip):
    """'KR (South Korea)' / 'FR (France)' / 'XX' / '' for an IP, fully offline."""
    cc = country_of_ip(ip)
    if not cc:
        return ""
    name = _CC_NAME.get(cc)
    return f"{cc} ({name})" if name else cc


def defang(s):
    """Render an IOC inert for reports: hxxp / [:]// / [.] so it can't be clicked or executed
    and on-host AV won't quarantine the report. The machine-readable IOCs.json stays un-defanged
    because Invoke-Eradication needs real hosts to block."""
    s = str(s)
    s = s.replace("http", "hxxp").replace("://", "[:]//")
    s = re.sub(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", r"\1[.]\2[.]\3[.]\4", s)
    s = re.sub(r"(?i)\b([a-z0-9-]+)\.((?:[a-z0-9-]+\.)*[a-z]{2,})\b",
               lambda m: m.group(0).replace(".", "[.]"), s)
    return s


def region_is_injected(vad_type, protection):
    """An injected/unbacked executable region: NOT an Image/File/Mapped-backed VAD AND executable.
    'Mapped' sections are file-section views (CreateFileMapping); treating them as unbacked would
    flag legitimate RX mapped files as injected. Consistent with the YARA worker's _addr_context."""
    t = str(vad_type or "").strip().lower()
    backed = t.startswith("image") or t.startswith("file") or t.startswith("mapped")
    return (not backed) and ("x" in str(protection or "").lower())


def classify_handle(htype, tag):
    """Map a handle (type, tag) to an eradication category + a cleaned name. Returns
    (category, name, suspicious) where category in file/registry/mutex/pipe/section/event/other."""
    htype = str(htype or "").strip()
    tag = str(tag or "").strip()
    if not tag:
        return ("other", "", False)
    if htype == "File":
        name = tag if tag.startswith("\\") else "\\" + tag
        return ("file", name, bool(_TEMP_FILE_RE.search(name)))
    if htype == "Key":
        # MemProcFS prefixes registry tags with "[hive:offset] " - strip it.
        name = re.sub(r"^\[[^\]]*\]\s*", "", tag)
        return ("registry", name, bool(_PERSIST_KEY_RE.search(name)))
    if htype == "Mutant":
        return ("mutex", tag, is_suspicious_object_name(tag))
    if htype == "ALPC Port" or (htype == "File" and "\\pipe\\" in tag.lower()):
        return ("pipe", tag, False)
    if htype == "Section":
        return ("section", tag, is_suspicious_object_name(tag))
    if htype == "Event":
        return ("event", tag, False)
    return ("other", tag, False)


def is_suspicious_object_name(name):
    """Classify a mutex/event name as suspicious (likely implant-created) or benign.

    Classification layers (research-validated):
    1. SM0:PID:session:NAME format -- evaluate the NAME component via known-good list.
       WilError_* = known WIL error tracking (benign). WilStaging_* = NOT known-good:
       state-sponsored APT groups use WilStaging-named mutexes as a Windows camouflage technique.
    2. Known-good prefix match -- Windows system objects have recognisable prefixes (Global\\,
       Local\\, Microsoft*, SmartScreen*, etc.). Hexacorn 'clean list' corroborates these.
    3. Bare hex token (e.g. '1BA6BD98D9') -- highest-confidence malware signal per SANS/Unit42.
    4. Undelimited long string (e.g. 'x9pv45dxghk') -- heuristic; requires process attribution
       to confirm. Some legitimate Windows DLLs (winipcsecproc.dll) produce these names (Hexacorn).
       Flagged suspicious here because enrichment runs over confirmed-TP PIDs; analyst verifies.

    DC3-MWCP adds a DEFINITIVE layer on top: mwcp_mutexes in the dossier are confirmed
    malware-created via family-specific binary parsing and bypass this heuristic entirely."""
    name = str(name or "").strip()
    if not name:
        return False
    # Layer 1: SM0:PID:session:NAME -- evaluate the name component, not the full string
    sm0_m = _SM0_RE.match(name)
    if sm0_m:
        name_component = sm0_m.group(1)
        return not bool(_SM0_KNOWN_NAMES.match(name_component))
    # Layer 2: known-good Windows prefix → not suspicious
    if _KNOWN_OBJ_PREFIX.search(name):
        return False
    # Layer 3: bare hex token → high-confidence malware lock
    if _HEX_TOKEN.match(name):
        return True
    # Layer 4: undelimited long string → heuristic, needs process attribution to confirm
    return (len(name) >= 8 and ":" not in name and "\\" not in name
            and "-" not in name and " " not in name)


# Higher-order threat IOCs an implant leaves in memory beyond plain C2 - each pattern is specific
# enough to stay quiet on benign data (the standing FP-resistance rule).
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9][A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_ONION_RE = re.compile(r"\b(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion\b")
_XMR_RE = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b")                  # Monero address (fixed len)
_AWS_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b")
_TELEGRAM_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")              # bot API token
_DISCORD_RE = re.compile(r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]{20,}")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
# printable-only so the match stops at the binary that follows the config in memory
_MINER_RE = re.compile(
    r"(?i)stratum\+(?:tcp|udp|ssl)://[A-Za-z0-9._:\-/?=&%]+(?:[ \t]+-[A-Za-z][ \t]+[A-Za-z0-9._:\-/?=&%]+){0,5}")
_HOST_OF_RE = re.compile(r"(?i)^[a-z+]+://([A-Za-z0-9._\-]+)")
# Memory has no string delimiters, so the greedy URL host regex over-reads into the NEXT string when
# they run together: `office.net` + `Xfoo` -> host `office.netXfoo`. A lowercase TLD label immediately
# followed by an UPPERCASE letter is a camelCase/run-on concatenation artifact - a real URL ends its
# TLD with `/ : ? #` or end-of-string. Cut there. This RECOVERS the true host (office.netX ->
# office.net, foo.comBar -> foo.com) without inventing one: an all-lowercase run-on (foo.community)
# has no boundary signal, so it is left intact and just fails the TLD check below - we never fabricate
# foo.com out of foo.community. NB: we deliberately do NOT treat a following digit run as a boundary -
# that wrongly cuts legitimate hosts whose label has digits (ip.aq138.com would mis-trim to ip.aq).
_OVERCAPTURE_RE = re.compile(r"\.[a-z]{2,24}(?=[A-Z])")


def _host_of(url):
    """Host (no scheme/port) from a url/stratum string, lowercased, with run-on over-capture trimmed."""
    m = _HOST_OF_RE.match(url)
    if not m:
        return ""
    h = m.group(1)
    cut = _OVERCAPTURE_RE.search(h)        # trim a TLD-then-uppercase/digit-run concatenation
    if cut:
        h = h[:cut.end()]
    return h.lower()


def _memblob(data):
    """ASCII + UTF-16LE (both alignments) view of a region, so wide-char strings are caught."""
    try:
        return (data.decode("latin-1", "ignore") + "\n" +
                data.decode("utf-16-le", "ignore") + "\n" + data[1:].decode("utf-16-le", "ignore"))
    except Exception:
        return ""


def extract_c2_iocs(data, bare_domains=True):
    """Recover C2 indicators (IPs / domains / URLs, incl. stratum/onion/ws schemes) from carved bytes
    - ASCII + UTF-16LE. Domains/IPs are always derived from the host of any matched URL (structured,
    high-confidence). `bare_domains` additionally scrapes free-standing FQDNs/IPs from the blob - use
    it on small config-bearing regions, but NOT on a big heap where every `x.com` substring is noise."""
    if not data:
        return {"ips": [], "domains": [], "urls": [], "unverified": []}
    blob = _memblob(data)
    domains, ips, unverified = set(), set(), set()
    # URLs are kept only when their host isn't benign infrastructure; the host seeds domains/ips.
    # A host that does NOT pass the TLD gate is NOT dropped - it is recorded under `unverified`
    # ("captured, but not a recognised TLD - verify; may be an over-capture or an uncommon TLD") so
    # nothing is silently suppressed. The `domains` list stays high-confidence/actionable.
    urls = []
    for u in sorted(set(_URL_RE.findall(blob))):
        h = _host_of(u)
        if not h or _BENIGN_DOMAIN_RE.search(h):
            continue
        urls.append(u)
        if _IPV4_RE.fullmatch(h):
            ips.add(h)
        elif _valid_host(h):                 # structured + recognised TLD -> confident domain IOC
            domains.add(h)
        else:                                # kept, not dropped: surfaced as "not resolvable - verify"
            unverified.add(h)
    if bare_domains:
        # bare FQDNs only (NOT bare IPs - those collide with crypto OIDs / version numbers like 2.5.4.3)
        domains |= set(_DOMAIN_RE.findall(blob))
    ips = sorted({m for m in ips if m and not _BENIGN_IP_RE.match(m)})
    # Confident domains: structurally valid + recognised TLD. A bare-scraped string with an unrecognised
    # TLD is moved to `unverified` (kept, labelled), never deleted.
    clean, maybe = set(), set(unverified)
    for d in domains:
        d = str(d).lower()
        if not d or _BENIGN_DOMAIN_RE.search(d) or d.isupper():
            continue
        (clean if _valid_host(d) else maybe).add(d)
    return {"ips": ips[:50], "domains": sorted(clean)[:50], "urls": urls[:50],
            "unverified": sorted(maybe)[:50]}


def extract_threat_iocs(data, bare_domains=False):
    """Full memory-IOC sweep: C2 network + exfil channels (Telegram/Discord), Tor, crypto (Monero +
    miner command line), and credential theft (AWS keys, private-key blocks). Returns a structured,
    de-duplicated, FP-filtered bundle. `bare_domains` only for small config regions. Plain email
    addresses are deliberately NOT collected - they are mostly victim PII, not adversary IOCs; the
    real exfil indicators are the Telegram/Discord channels below."""
    out = {"ips": [], "domains": [], "urls": [], "unverified": [], "onion": [], "xmr": [],
           "aws_keys": [], "telegram_tokens": [], "discord_webhooks": [], "miner_configs": [],
           "private_keys": 0}
    if not data:
        return out
    blob = _memblob(data)
    net = extract_c2_iocs(data, bare_domains=bare_domains)
    out["ips"], out["domains"], out["urls"] = net["ips"], net["domains"], net["urls"]
    out["unverified"] = net.get("unverified", [])
    out["onion"] = sorted(set(_ONION_RE.findall(blob)))[:50]
    out["xmr"] = sorted(set(_XMR_RE.findall(blob)))[:20]
    out["aws_keys"] = sorted(set(_AWS_RE.findall(blob)))[:20]
    out["telegram_tokens"] = sorted(set(_TELEGRAM_RE.findall(blob)))[:20]
    out["discord_webhooks"] = sorted(set(_DISCORD_RE.findall(blob)))[:20]
    out["miner_configs"] = sorted({re.sub(r"\s+", " ", m).strip() for m in _MINER_RE.findall(blob)})[:20]
    out["private_keys"] = len(_PRIVKEY_RE.findall(blob))
    # crypto wallets: Monero (specific length) + the `-u <wallet>` from any miner command line
    # (the worker suffix after a '.' is dropped - the address is the part before it)
    wallets = set(out["xmr"])
    for m in out["miner_configs"]:
        wm = re.search(r"(?i)-u[=\s]+([A-Za-z0-9]{20,})", m)
        if wm:
            wallets.add(wm.group(1))
    out["wallets"] = sorted(wallets)[:20]
    return out


# Encoded blobs worth handing to CyberChef: base64 runs, long hex, and bare high-entropy tokens.
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{24,}={0,2})|(?:[A-Za-z0-9_-]{24,})")    # std + url-safe
_HEX_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:,-]?){16,}")    # >=16 hex bytes (no spaces - don't span tokens)


def _shannon(s):
    """Byte-entropy of a string - high entropy distinguishes packed/encoded data from plain text."""
    if not s:
        return 0.0
    from math import log2
    n = len(s)
    counts = {c: s.count(c) for c in set(s)}
    return -sum((v / n) * log2(v / n) for v in counts.values())


def _looks_encoded(s):
    """Discriminate a real base64/encoded blob from a plain identifier run (DLL lists, api-ms-win-*
    names, dotted paths). Encoded binary is high-entropy with mixed case+digits or base64 specials;
    dash/underscore-heavy or mostly-lowercase 'wordy' strings are rejected."""
    n = len(s)
    if n < 24 or _shannon(s) < 4.0:
        return False
    if (s.count("-") + s.count("_")) / n > 0.06:          # api-ms-win-* / GUID-dashy identifiers
        return False
    special = any(c in "+/=" for c in s)
    low = sum(c.islower() for c in s)
    if low / n > 0.72 and not special:                    # mostly-lowercase => readable text
        return False
    up = sum(c.isupper() for c in s)
    dg = sum(c.isdigit() for c in s)
    return special or (up >= 2 and dg >= 1)               # real b64 of binary mixes case + digits


_GUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$")
_SID_NUMRUN_RE = re.compile(r"^\d{4,}-\d{4,}(?:-\d{4,})*$")           # decimal-dashed SID/handle runs


def extract_decode_candidates(data, limit=15):
    """Pull the strings an analyst would want to DECODE (not decode them here): base64 blobs and long
    hex, from both ASCII and UTF-16LE. The report hands these to CyberChef. De-noised so concatenated
    DLL/API-name runs, plain text, and benign Windows GUIDs/SIDs are NOT offered as candidates."""
    if not data:
        return []
    try:
        text = data.decode("latin-1", "ignore") + "\n" + data.decode("utf-16-le", "ignore")
    except Exception:
        return []
    out, seen = [], set()
    # hex BEFORE base64: a pure-hex run is also valid base64 chars, but is more usefully typed as hex
    for kind, rx in (("hex", _HEX_RE), ("base64", _B64_RE)):
        for m in rx.findall(text):
            v = m.strip()
            if len(v) < 24 or v in seen:
                continue
            if _GUID_RE.match(v) or _SID_NUMRUN_RE.match(v):    # benign Windows GUID/SID, not payload
                continue
            if kind == "base64" and not _looks_encoded(v):
                continue
            seen.add(v)
            out.append({"type": kind, "len": len(v), "value": v[:256]})
            if len(out) >= limit:
                return out
    return out


_THREAT_CATS = ("ips", "domains", "urls", "unverified", "onion", "xmr", "wallets", "aws_keys",
                "telegram_tokens", "discord_webhooks", "miner_configs")


# Bot-config "DNA" - the format strings an HTTP bot/worm carries: beacon URI templates with printf
# specifiers, custom User-Agents, and self-spreading (USB-worm) markers. High-signal config evidence.
_BEACON_RE = re.compile(rb"(?i)/[\w.\-]{1,40}\.(?:php|asp|aspx|cgi|jsp|html?)\?[\w=%&.\-/]*%[sdux][\w=%&.\-/]*")
_UA_RE = re.compile(rb"(?i)user-agent:\s?[\x20-\x7e]{6,90}")
_BOTPARAM_RE = re.compile(rb"(?i)\b(?:bid|botid|uid|campaign|uptime|rnd)=%?(?:08x|[sdux]|\w{0,4})")
_USB_RE = re.compile(rb"(?i)autorun\.inf|infected %s|\\recycler\\|attrib\s+-s\s+-h|%temp%\\%s|xcopy\s+/")


def extract_config_artifacts(data):
    """Recover bot/implant CONFIG DNA from a region: HTTP beacon URI templates, custom User-Agents,
    bot parameters, and USB-worm self-spread markers. Returns a set of (kind, value) - high-signal
    config evidence to surface when a YARA hit pivots to a deeper region dive."""
    out = set()
    for m in _BEACON_RE.findall(data)[:12]:
        out.add(("beacon_uri", m.decode("latin-1", "ignore")[:110]))
    for m in _UA_RE.findall(data)[:6]:
        out.add(("user_agent", m.decode("latin-1", "ignore")[:110]))
    if _BOTPARAM_RE.search(data):
        params = sorted({m.decode("latin-1", "ignore")[:40] for m in _BOTPARAM_RE.findall(data)})[:8]
        # findall returns groups; re-scan for full tokens
        toks = sorted({m.group(0).decode("latin-1", "ignore") for m in _BOTPARAM_RE.finditer(data)})[:8]
        if toks:
            out.add(("bot_params", ", ".join(toks)))
    if _USB_RE.search(data):
        out.add(("self_spread", "USB-worm markers (autorun.inf / recycler drop / attrib -s -h / xcopy)"))
    return out


def rollup_iocs(dossiers):
    """Aggregate every per-PID footprint into one eradication IOC bundle: files to delete, registry
    keys to remove, mutexes, the full memory-IOC sweep (C2 + exfil + crypto + credentials), and the
    related (parent/child) PIDs."""
    files, keys, mutexes, pids = set(), set(), set(), set()
    agg = {c: set() for c in _THREAT_CATS}
    privkeys = 0
    for d in dossiers:
        pids.add(d["pid"])
        for h in d.get("handles", []):
            if h["category"] == "file" and h["suspicious"]:
                files.add(h["name"])
            elif h["category"] == "registry" and h["suspicious"]:
                keys.add(h["name"])
            elif h["category"] == "mutex" and h["suspicious"]:
                mutexes.add(h["name"])
        # DC3-MWCP confirmed malware-created mutex names -- definitive, bypass heuristic gate
        for mx in d.get("mwcp_mutexes", []):
            if mx:
                mutexes.add(f"[mwcp-confirmed] {mx}")
        for rel in d.get("lineage", {}).get("children", []) + \
                ([d["lineage"]["parent"]] if d.get("lineage", {}).get("parent") else []):
            if rel.get("pid"):
                pids.add(rel["pid"])
        ti = d.get("threat_iocs", {})
        for c in _THREAT_CATS:
            agg[c].update(ti.get(c, []))
        privkeys += ti.get("private_keys", 0)
        for n in d.get("network", []):              # live sockets from netscan
            if n.get("dst_ip"):
                agg["ips"].add(n["dst_ip"])
    out = {
        "files_to_remove": sorted(files),
        "registry_keys_to_remove": sorted(keys),
        "mutexes": sorted(mutexes),
        "implicated_pids": sorted(pids),
        "private_key_blocks": privkeys,
    }
    # c2_* names kept for back-compat; the rest carry the broader sweep
    out["c2_ips"] = sorted(agg["ips"]); out["c2_domains"] = sorted(agg["domains"])
    out["c2_urls"] = sorted(agg["urls"])
    for c in ("unverified", "onion", "xmr", "wallets", "aws_keys", "telegram_tokens", "discord_webhooks", "miner_configs"):
        out[c] = sorted(agg[c])
    return out


# ----------------------------------------------------------------------- capa
def find_capa():
    """capa standalone, staged by Build-OfflineToolkit -IncludeCapa (tools/capa/) or on PATH."""
    import shutil
    cand = os.path.join(str(Path(__file__).resolve().parent.parent.parent.parent / "tools" / "capa"),
                        "capa.exe")
    return cand if os.path.isfile(cand) else (shutil.which("capa") or shutil.which("capa.exe"))


def parse_capa_json(text):
    """Extract capability names + ATT&CK ids from `capa -j` output, tolerant of schema variance."""
    try:
        doc = json.loads(text)
    except Exception:
        return {"capabilities": [], "attack": []}
    rules = doc.get("rules", {}) if isinstance(doc, dict) else {}
    caps, att = [], set()
    for name, r in (rules.items() if isinstance(rules, dict) else []):
        meta = r.get("meta", {}) if isinstance(r, dict) else {}
        caps.append(meta.get("name", name))
        for a in (meta.get("attack") or meta.get("att&ck") or []):
            if isinstance(a, dict):
                tid = a.get("id") or a.get("technique")
                if tid:
                    att.add(tid)
            else:
                m = re.search(r"T\d{4}(?:\.\d{3})?", str(a))
                if m:
                    att.add(m.group(0))
    return {"capabilities": sorted(set(caps)), "attack": sorted(att)}


def run_capa(capa_exe, region_path, fmt="sc64"):
    """Run capa over a carved shellcode region. Returns capabilities/ATT&CK, or empty on any error."""
    import subprocess
    try:
        r = subprocess.run([capa_exe, "-f", fmt, "-j", "--no-progress", region_path],
                           capture_output=True, text=True, timeout=300)
        if r.stdout.strip():
            return parse_capa_json(r.stdout)
    except Exception:
        pass
    return {"capabilities": [], "attack": []}


# ---------------------------------------------------------------------- FLOSS
def find_floss():
    """FLOSS standalone, staged by Build-OfflineToolkit -IncludeFloss (tools/floss/) or on PATH."""
    import shutil
    cand = os.path.join(str(Path(__file__).resolve().parent.parent.parent.parent / "tools" / "floss"),
                        "floss.exe")
    return cand if os.path.isfile(cand) else (shutil.which("floss") or shutil.which("floss.exe"))


def parse_floss_json(text):
    """Pull the DEOBFUSCATED strings (decoded/stack/tight) from `floss -j` - these are what plain
    `strings`/capa miss. Static strings are just a count (already covered by the IOC sweep)."""
    try:
        d = json.loads(text)
    except Exception:
        return {"decoded": [], "stack": [], "tight": [], "static_count": 0}
    st = d.get("strings", {}) if isinstance(d, dict) else {}

    def vals(bucket):
        return [(s.get("string") if isinstance(s, dict) else str(s))
                for s in (st.get(bucket) or []) if (s.get("string") if isinstance(s, dict) else s)]
    return {"decoded": vals("decoded_strings"), "stack": vals("stack_strings"),
            "tight": vals("tight_strings"), "static_count": len(st.get("static_strings") or [])}


def run_floss(floss_exe, region_path, fmt="sc64"):
    """Run FLOSS over a carved shellcode region. Returns deobfuscated strings, or empty on error."""
    import subprocess
    try:
        r = subprocess.run([floss_exe, "-f", fmt, "-j", "--quiet", region_path],
                           capture_output=True, text=True, timeout=600)
        if r.stdout.strip():
            return parse_floss_json(r.stdout)
    except Exception:
        pass
    return {"decoded": [], "stack": [], "tight": [], "static_count": 0}


# ---------------------------------------------------------------------- DC3-MWCP
def find_mwcp():
    """DC3-MWCP staged by Build-OfflineToolkit -IncludeMWCP (tools/mwcp/lib/) or installed globally.
    Returns (python_exe, mwcp_lib_path) or (None, None) if not available."""
    import shutil
    lib_path = str(Path(__file__).resolve().parent.parent.parent.parent / "tools" / "mwcp" / "lib")
    if os.path.isdir(lib_path):
        py = shutil.which("python") or shutil.which("python3") or shutil.which("py")
        return (py, lib_path) if py else (None, None)
    # Fall back: check if mwcp is installed globally
    py = shutil.which("python") or shutil.which("python3")
    if py:
        import subprocess
        r = subprocess.run([py, "-c", "import mwcp; print(mwcp.__version__)"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return (py, None)
    return (None, None)


def run_mwcp(python_exe, lib_path, region_path, existing_iocs=None, out_dir=None):
    """Run DC3-MWCP against a carved region binary using mwcp_scan.py.

    mwcp_scan.py API requirements (mwcp 3.16.1):
      - Parsers MUST be registered in parser_config.yml (else mwcp silently rejects them)
      - file_object.data (NOT .file_data) for binary content in parser run()
      - Extraction via report.as_dict()['metadata'] -- report.get(meta.Class) is unreliable
      - Returns JSON array; single-region call → use result_list[0]
      - File-type detection selects parsers: GenericMutex, GenericC2, PowerShellDecoder, LNKParser
      - Tailing log appended to <out_dir>/mwcp_scan_log.txt for audit trail

    Results tagged: mwcp-verified (overlap with sweep = confidence upgrade),
    mwcp_new_iocs (new IOCs from binary not in sweep)."""
    import subprocess
    if existing_iocs is None:
        existing_iocs = {}

    # mwcp_scan.py lives alongside this file in the threat_hunting directory
    scanner = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mwcp_scan.py")
    if not os.path.isfile(scanner):
        return {}

    # Signature: mwcp_scan.py <lib_path> <out_dir|-> <file_path>
    # Returns JSON array ([{...}]) -- take first element for this single-file call.
    cmd = [python_exe, scanner, lib_path, out_dir or '-', region_path]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode == 0 and r.stdout.strip():
            result_list = json.loads(r.stdout.strip())
            # mwcp_scan.py always returns a list; single-region call → take first entry
            merged = result_list[0] if isinstance(result_list, list) and result_list else {}
            # Tag results: mwcp is a VERIFICATION layer on top of the IOC sweep.
            # When mwcp finds the same IOC the sweep already found -> mark as mwcp-verified
            # (confidence upgrade). When mwcp finds NEW IOCs -> add them.
            # Both cases appear in the report -- overlap is corroboration, not duplication.
            existing_all = set(existing_iocs.get("ips", [])) | \
                           set(existing_iocs.get("domains", [])) | \
                           set(existing_iocs.get("urls", []))
            verified, new_finds = [], []
            for a in merged.get("address", []):
                if a in existing_all:
                    verified.append(a)
                else:
                    new_finds.append(a)
            merged["mwcp_verified_iocs"] = verified    # already in sweep, now also confirmed by binary
            merged["mwcp_new_iocs"]      = new_finds   # not in sweep, newly found by mwcp
            merged["address"]            = new_finds   # only promote truly new ones to IOC set
            return {k: list(dict.fromkeys(v)) for k, v in merged.items()}
    except Exception:
        pass
    return {}


# --------------------------------------------------------- time / correlation
# "First seen" anchors. From RAM we take each implant process's create time (= when it first ran
# on the host); from the USB collector we take each device's first-connect time. Putting both on
# one UTC timeline tells us whether a removable device was present BEFORE the implant first ran
# (entry-vector candidate) or only AFTER (introduced post-infection, not the source).

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# vmmpyc surfaces the thread struct ftCreateTime under one of these dict keys (version-dependent).
_THREAD_CREATE_KEYS = ("time-create", "create-time", "createtime", "ftcreatetime", "ft-create")


def filetime_to_dt(ft):
    """Windows FILETIME (100ns ticks since 1601-01-01 UTC) -> aware UTC datetime, or None if invalid."""
    try:
        ft = int(ft)
    except (TypeError, ValueError):
        return None
    if ft <= 0 or ft > 0x7FFFFFFFFFFFFFFF:
        return None
    dt = _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    return dt if 1980 <= dt.year <= 2200 else None


def coerce_dt(val):
    """Best-effort convert any time value (vmmpyc thread time, .NET /Date(ms)/, ISO/locale string,
    FILETIME or unix int) into an aware UTC datetime. None on anything unparseable."""
    if val is None or val == "" or val == 0:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, (int, float)):
        v = int(val)
        if v <= 0:
            return None
        if v > 10 ** 16:                       # FILETIME (100ns since 1601) ~ 1.3e17 for current dates
            return filetime_to_dt(v)
        if v > 10 ** 11:                       # unix milliseconds
            return datetime.fromtimestamp(v / 1000, tz=timezone.utc)
        return datetime.fromtimestamp(v, tz=timezone.utc)          # unix seconds
    s = str(val).strip()
    if not s:
        return None
    m = re.search(r"/Date\((\d+)", s)          # .NET JSON date: /Date(<unix-ms UTC>)/
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC", "%m/%d/%Y %H:%M:%S",
                "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


def _fmt(dt):
    """Aware datetime -> 'YYYY-MM-DD HH:MM:SS UTC' label (None -> '')."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""


def thread_create_dt(t):
    """Create time of one vmmpyc thread dict, trying the known key variants (case-insensitive)."""
    low = {str(k).lower(): v for k, v in (t.items() if hasattr(t, "items") else [])}
    for k in _THREAD_CREATE_KEYS:
        if low.get(k):
            dt = coerce_dt(low[k])
            if dt:
                return dt
    return None


def earliest_thread_create(threads):
    """Process create time = earliest (main) thread create time. Returns 'YYYY-MM-DD HH:MM:SS UTC' or None.
    The first thread is created at process creation, so the minimum thread create time is the process
    create time - a reliable RAM 'first seen' for the implant."""
    times = [dt for dt in (thread_create_dt(t) for t in (threads or [])) if dt]
    return _fmt(min(times)) if times else None


def load_usb_devices(usb_bundle):
    """Flatten a USB_Forensics_*.json bundle into [{vendor, product, serial, first_connect(dt),
    suspicion, verdict}], earliest first. Tolerant of missing fields."""
    out = []
    for d in (usb_bundle.get("usb_devices") or []):
        out.append({
            "vendor": d.get("Vendor", ""), "product": d.get("Product", ""),
            "serial": d.get("Serial", ""), "suspicion": d.get("Suspicion", ""),
            "verdict": d.get("Verdict", ""), "first_connect": coerce_dt(d.get("FirstConnect")),
        })
    out.sort(key=lambda x: (x["first_connect"] is None, x["first_connect"] or _FILETIME_EPOCH))
    return out


def _vector_verdict(usb_dt, ram_dt):
    """Verdict for one USB device vs the RAM implant first-seen reference. Mirrors the PowerShell
    Get-VectorVerdict thresholds so both reports agree: connected <=24h BEFORE -> entry-vector
    candidate; longer before -> weak possible; AFTER -> introduced post-infection (not the source)."""
    if not usb_dt or not ram_dt:
        return ("UNKNOWN", None)
    delta_h = round((ram_dt - usb_dt).total_seconds() / 3600.0, 1)   # +ve: USB connected before implant
    if delta_h >= 0:
        if delta_h <= 24:
            return (f"ENTRY-VECTOR CANDIDATE - connected {delta_h}h BEFORE implant first ran", delta_h)
        return (f"possible (weak) - connected {delta_h}h before implant first ran", delta_h)
    return (f"LIKELY NOT SOURCE - connected {abs(delta_h)}h AFTER implant first ran (post-infection)", delta_h)


def implant_anchor(dossier):
    """The best 'implant first ran' time for a PID, as (datetime, basis). Prefer the injected-thread
    create time (true code-execution start inside a host process); fall back to process create time
    (which for an injected implant is only the host process's start - flagged as lower confidence)."""
    t = coerce_dt(dossier.get("injected_thread_first_seen"))
    if t:
        return t, "injected-thread"
    return coerce_dt(dossier.get("create_time")), "process-create"


def has_injection_evidence(dossier):
    """True if the PID actually carries injected code (an injected/unbacked exec region, an off-module
    thread, or a captured injected-thread time). A PID flagged only by a name/string YARA match - with
    NO region or thread - has no reliable execution-time signal: its process-create is just boot, so it
    must NOT anchor the infection timeline (the svchost-flagged-at-boot trap)."""
    return bool(dossier.get("injected_thread_first_seen")
                or dossier.get("injected_regions")
                or dossier.get("shellcode_threads"))


def correlate_first_seen(dossiers, usb_devices, tp_events=None):
    """Join RAM implant first-seen with USB device connect times and all confirmed TP artifact events.
    Returns a dict: {ram_first_seen, ram_pid, ram_name, ram_basis, per_pid:[...],
    devices:[{...delta_hours, verdict}], tp_events:[...], summary}.
    tp_events is an ordered list of confirmed TP artifacts across all scan outputs."""
    per_pid = []
    for d in dossiers:
        dt, basis = implant_anchor(d)
        if dt:
            per_pid.append({"pid": d.get("pid"), "name": d.get("name"), "first_seen": _fmt(dt),
                            "basis": basis, "evidence": has_injection_evidence(d), "_dt": dt})
    per_pid.sort(key=lambda x: x["_dt"])
    # Anchor on the EARLIEST process that actually carries injection evidence; only if none do, fall
    # back to the earliest process-create overall (flagged low confidence - it is just boot/session).
    evidence_pids = [p for p in per_pid if p["evidence"]]
    ram = (evidence_pids[0] if evidence_pids else (per_pid[0] if per_pid else None))
    ram_dt = ram["_dt"] if ram else None
    devices = []
    for dev in usb_devices:
        verdict, delta = _vector_verdict(dev.get("first_connect"), ram_dt)
        devices.append({
            "vendor": dev.get("vendor", ""), "product": dev.get("product", ""),
            "serial": dev.get("serial", ""), "suspicion": dev.get("suspicion", ""),
            "first_connect": _fmt(dev.get("first_connect")), "delta_hours": delta, "verdict": verdict,
        })
    candidates = [x for x in devices if x["delta_hours"] is not None and x["delta_hours"] >= 0]
    strong = [x for x in candidates if x["delta_hours"] <= 24]      # tight pre-execution drop window
    # A process-create anchor on a long-running host process (svchost/lsass/services) is the host's
    # BOOT/start, not the injection time - call that out so the timeline isn't over-trusted.
    caveat = ""
    if ram and not ram["evidence"]:
        caveat = (f" [LOW CONFIDENCE: no PID carries injection evidence (region/thread); anchored on "
                  f"PID {ram['pid']} {ram['name']} process-create, which is just boot/session start - "
                  "not an infection time. Anchor on payload first-execution (Prefetch) or dropped-file "
                  "MAC times instead.]")
    elif ram and ram["basis"] == "process-create":
        caveat = (f" [MODERATE CONFIDENCE: anchored on PID {ram['pid']} {ram['name']} process-create "
                  "(it carries injected regions but no dedicated injected thread). Process-create is the "
                  "host/session start, so this is an UPPER BOUND on the injection time, not the exact "
                  "moment; corroborate with payload Prefetch / dropped-file MAC times.]")
    if not ram:
        summary = "No RAM first-seen captured (no thread create times) - cannot place implant on timeline."
    elif not usb_devices:
        summary = (f"Implant first ran {ram['first_seen']} ({ram['basis']}, PID {ram['pid']} "
                   f"{ram['name']}); no USB device history present to correlate.{caveat}")
    elif strong:
        c = min(strong, key=lambda x: x["delta_hours"])
        summary = (f"Implant first ran {ram['first_seen']} ({ram['basis']}, PID {ram['pid']} "
                   f"{ram['name']}); {c['vendor']} {c['product']} connected {c['delta_hours']}h "
                   f"earlier (within the 24h pre-execution window) - USB is a viable entry vector.{caveat}")
    elif candidates:
        c = min(candidates, key=lambda x: x["delta_hours"])
        summary = (f"Implant first ran {ram['first_seen']} ({ram['basis']}, PID {ram['pid']} "
                   f"{ram['name']}); nearest device {c['vendor']} {c['product']} connected "
                   f"{c['delta_hours']}h earlier - only a WEAK temporal link (>24h before), not a tight "
                   f"pre-execution drop. Favor a non-USB vector unless payload Prefetch / dropped-file "
                   f"MAC times tighten the infection time.{caveat}")
    else:
        summary = (f"Implant first ran {ram['first_seen']} ({ram['basis']}, PID {ram['pid']} "
                   f"{ram['name']}); every USB device connected AFTER - none is the entry vector "
                   f"(point to a non-USB vector: download / fake-update / malvertising).{caveat}")
    for x in per_pid:
        x.pop("_dt", None)
    return {"ram_first_seen": ram["first_seen"] if ram else None,
            "ram_pid": ram["pid"] if ram else None, "ram_name": ram["name"] if ram else None,
            "ram_basis": ram["basis"] if ram else None,
            "per_pid": per_pid, "devices": devices, "summary": summary,
            "tp_events": tp_events or []}


# ------------------------------------------------------------- live extraction
def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def enrich_pid(vmm, p, pid_map, nets_by_pid, carve_dir, size_cap=16 * 1024 * 1024,
               capa_exe=None, floss_exe=None, mwcp_py=None, mwcp_lib=None, out_dir=None):
    """Build one PID's full memory footprint and carve its injected exec regions."""
    pid, name = p.pid, p.name
    mods = _safe(lambda: p.module_list(), [])
    mod_ranges = []
    for m in mods:
        b, sz = _safe(lambda: m.base, 0), _safe(lambda: m.image_size, 0)
        if b:
            mod_ranges.append((b, b + sz, _safe(lambda: m.fullname, "") or _safe(lambda: m.name, "")))

    # handles -> categorised footprint
    handles = []
    for h in _safe(lambda: p.maps.handle(), []):
        cat, nm, susp = classify_handle(h.get("type"), h.get("tag"))
        if cat == "other" or not nm:
            continue
        handles.append({"category": cat, "type": h.get("type", ""), "name": nm, "suspicious": susp})

    # threat IOCs accumulate across every region we read (exec + data)
    threat = {k: [] for k in _THREAT_CATS}
    threat["private_keys"] = 0
    # mwcp-confirmed mutexes: DEFINITIVE malware-created names extracted from carved binaries
    # by DC3-MWCP family-specific parsers. Separate from handle-based mutex classification.
    mwcp_mutexes: list = []

    def _accumulate(data, bare):
        found = extract_threat_iocs(data, bare_domains=bare)
        for k in threat:
            if k == "private_keys":
                threat[k] += found.get(k, 0)
            else:
                threat[k] = sorted(set(threat[k]) | set(found.get(k, [])))

    # injected exec regions -> carve + sweep for IOCs/config
    regions = []
    for v in _safe(lambda: p.maps.vad(), []):
        if not region_is_injected(v.get("type"), v.get("protection")):
            continue
        start, end = int(v["start"]), int(v["end"])
        size = min(end - start + 1, size_cap)   # vmmpyc 'end' is inclusive
        backed = any(b <= start < e for b, e, _ in mod_ranges)
        rec = {"start": hex(start), "end": hex(end), "size": end - start + 1,
               "protection": str(v.get("protection", "")), "backed": backed, "carved_to": None}
        data = _safe(lambda: p.memory.read(start, size), b"")
        if data:
            # We EXTRACT INFORMATION from the region; we do NOT copy the live malware binary out to
            # disk. capa/FLOSS need a file, so write a TEMP copy, analyze it, then delete it - no
            # raw implant code is left behind (the dossier keeps the results, not the bytes).
            _accumulate(data, bare=True)        # small injected region - config lives here
            rec["decode_candidates"] = extract_decode_candidates(data)
            rec["analyzed"] = "in-memory (region bytes not retained on disk)"
            tmpf = None
            try:
                if capa_exe or floss_exe:
                    import tempfile
                    try:
                        # temp carve in the OS temp dir (NEVER the toolkit/output tree) for static
                        # tools only; deleted in `finally` so a crash can't leave live malware behind
                        tf = tempfile.NamedTemporaryFile(prefix=f"_reg_{pid}_", suffix=".bin", delete=False)
                        tf.write(data); tf.close(); tmpf = tf.name
                    except OSError:
                        tmpf = None
                if capa_exe and tmpf:
                    rec["capa"] = run_capa(capa_exe, tmpf)
                if floss_exe and tmpf:
                    rec["floss"] = run_floss(floss_exe, tmpf)
                    deob = "\n".join(rec["floss"]["decoded"] + rec["floss"]["stack"] + rec["floss"]["tight"])
                    if deob:
                        _accumulate(deob.encode("utf-8", "ignore"), bare=True)
                if mwcp_py and tmpf:
                    # Pass the existing IOC sweep results so mwcp can tag overlaps as verified
                    current_iocs = {"ips": list(threat["ips"]), "domains": list(threat["domains"]),
                                    "urls": list(threat["urls"])}
                    mwcp_result = run_mwcp(mwcp_py, mwcp_lib, tmpf,
                                            existing_iocs=current_iocs, out_dir=out_dir)
                    rec["mwcp"] = mwcp_result
                    # mwcp-confirmed mutexes: DEFINITIVE malware-created names from binary parsing.
                    for mx in mwcp_result.get("mutex", []):
                        if mx and mx not in mwcp_mutexes:
                            mwcp_mutexes.append(mx)
                    # mwcp-confirmed C2 addresses → merge into IOC sweep
                    for addr in mwcp_result.get("address", []):
                        if addr:
                            _accumulate(addr.encode("utf-8", "ignore"), bare=True)
            finally:
                if tmpf:
                    try:
                        os.unlink(tmpf)         # always delete the temp carve - leave no live binary
                    except OSError:
                        pass
        regions.append(rec)

    # The implant's config/IOCs and encoded blobs usually live in private DATA regions, not the exec
    # region - sweep private committed regions for IOCs + decode candidates. Bounded so a large heap
    # can't blow up runtime: a capped slice of up to N private regions.
    # Scan ALL private readable regions (the config can be in any of them) up to a byte budget, so a
    # huge heap can't blow up runtime but we still cover the whole working set on a normal process.
    # A C2 config can sit MANY MB deep inside a region (real case: a bot config at +2.4MB in a 16MB
    # region - a shallow 1MB read missed it). So read private regions in FULL up to a generous cap,
    # but only run the expensive IOC/config regex on regions that actually contain config markers
    # (a fast substring pre-filter) so the deep read stays cheap on benign heap.
    decode_candidates, total_read, budget = [], 0, 1024 * 1024 * 1024
    config_artifacts = set()
    _MARKERS = (b"://", b"stratum", b"-----BEGIN", b"AKIA", b"/api/webhooks", b".php?", b".onion",
                b"autorun", b"user-agent")
    for v in _safe(lambda: p.maps.vad(), []):
        if total_read >= budget:
            break
        vtype, prot = str(v.get("type", "")).strip().lower(), str(v.get("protection", ""))
        backed = vtype.startswith("image") or vtype.startswith("file")
        if backed or "r" not in prot.lower():           # private, readable (an empty read is skipped)
            continue
        start, end = int(v["start"]), int(v["end"])
        data = _safe(lambda: p.memory.read(start, min(end - start + 1, 32 * 1024 * 1024)), b"")
        if not data:
            continue
        total_read += len(data)
        low = data.lower()
        if any(mk in low for mk in _MARKERS):           # only deep-scan regions that look like config
            _accumulate(data, bare=False)               # structured (URL-host) domains only on heap
            config_artifacts |= extract_config_artifacts(data)
        if len(decode_candidates) < 25:                 # decode candidates from the region head (cheap)
            for c in extract_decode_candidates(data[:1024 * 1024], limit=8):
                c["region"] = hex(start)
                decode_candidates.append(c)

    # threads: read once -> (a) process create time = earliest thread create time; (b) shellcode
    # threads whose start is outside every loaded module, WITH their own create time. For an injected
    # implant living inside a host process (e.g. svchost), the PROCESS create time is just the host's
    # boot/start - the real "implant first ran" is when the off-module (injected) thread was created.
    all_threads = _safe(lambda: p.maps.thread(), [])
    create_time = earliest_thread_create(all_threads)
    threads, inj_create = [], []
    for t in all_threads:
        sa = t.get("va-win32start") or t.get("va-start") or 0
        if sa and not any(b <= sa < e for b, e, _ in mod_ranges):
            ct = thread_create_dt(t)
            threads.append({"tid": t.get("tid"), "start": hex(int(sa)), "off_module": True,
                            "create_time": _fmt(ct) if ct else None})
            if ct:
                inj_create.append(ct)
    injected_first_seen = _fmt(min(inj_create)) if inj_create else None

    # lineage
    parent = pid_map.get(p.ppid)
    children = [{"pid": c.pid, "name": c.name} for c in pid_map.values() if c.ppid == pid]
    lineage = {"parent": {"pid": parent.pid, "name": parent.name} if parent else None,
               "children": children}

    network = nets_by_pid.get(pid, [])
    return {
        "pid": pid, "name": name, "cmdline": _safe(lambda: p.cmdline or "", ""),
        "create_time": create_time,                 # process create (host start for an injected implant)
        "injected_thread_first_seen": injected_first_seen,   # injected-thread create = implant first ran
        "handles": handles, "modules_loaded": len(mod_ranges),
        "injected_regions": regions, "shellcode_threads": threads,
        "decode_candidates": decode_candidates,
        "config_artifacts": sorted(f"[{k}] {v}" for k, v in config_artifacts),
        "lineage": lineage, "network": network,
        "c2": {"ips": threat["ips"], "domains": threat["domains"], "urls": threat["urls"]},
        "threat_iocs": threat,
        "mwcp_mutexes": mwcp_mutexes,   # DC3-MWCP confirmed malware-created mutex names
    }


def _mm(label):
    """Sanitise a label for a mermaid node (no quotes/pipes/backslashes; <br/> for line breaks)."""
    s = str(label).replace("\\", "/").replace('"', "'").replace("|", "/")
    return s.replace("\n", "<br/>")


def build_attack_chain_mermaid(bundle):
    """Render the full discovered/correlated chain for the true positives as a mermaid flowchart:
    parent → implant PID (with its named rules) → the affected files, registry persistence, mutex,
    injected/carved regions, and C2 it touched. Data-driven from the per-PID dossiers."""
    L = ["```mermaid", "flowchart TD"]
    # Match the existing Attack_Graph.md scheme: dark fills, light strokes, white text. C2 reuses the
    # graph's exact c2 style; the rest map to the same ATT&CK-tactic palette generate_reports uses.
    cls = ["classDef implant fill:#7f1d1d,stroke:#fca5a5,color:#fff,stroke-width:3px;",
           "classDef file fill:#9a3412,stroke:#fdba74,color:#fff;",
           "classDef reg fill:#92400e,stroke:#fcd34d,color:#fff;",
           "classDef mutex fill:#155e75,stroke:#67e8f9,color:#fff;",
           "classDef c2 fill:#991b1b,stroke:#fde047,color:#fff,stroke-width:3px;",
           "classDef inj fill:#5b21b6,stroke:#c4b5fd,color:#fff;",
           "classDef proc fill:#374151,stroke:#9ca3af,color:#fff;"]
    edges, nodes, classed = [], [], []
    for d in bundle.get("dossiers", []):
        pid = d["pid"]
        ip = f"P{pid}"
        # implant node labelled with the process, its RAM first-seen time, and its YARA rules.
        # Prefer the injected-thread time (true implant start) over the host process create time.
        rule_txt = _mm(", ".join(d.get("rules", []))) if d.get("rules") else ""
        fs = d.get("injected_thread_first_seen") or d.get("create_time")
        seen_txt = f'<br/>first seen {_mm(fs)}' if fs else ""
        nodes.append(f'{ip}["PID {pid} {_mm(d["name"])}' + seen_txt
                     + (f'<br/>{rule_txt}' if rule_txt else "") + '"]')
        classed.append(f"class {ip} implant;")
        par = d.get("lineage", {}).get("parent")
        if par:
            pn = f"PP{par['pid']}"
            nodes.append(f'{pn}["PID {par["pid"]} {_mm(par["name"])} (parent)"]')
            classed.append(f"class {pn} proc;")
            edges.append(f"{pn} --> {ip}")
        for c in d.get("lineage", {}).get("children", []):
            cn = f"PC{c['pid']}"
            nodes.append(f'{cn}["PID {c["pid"]} {_mm(c["name"])} (child)"]')
            classed.append(f"class {cn} proc;")
            edges.append(f"{ip} -->|spawned| {cn}")
        susp = [h for h in d.get("handles", []) if h.get("suspicious")]
        for i, h in enumerate(susp):
            nid = f"{ip}H{i}"
            cat = h["category"]
            kind = {"file": "file", "registry": "reg", "mutex": "mutex"}.get(cat, "proc")
            verb = {"file": "dropped", "registry": "persistence", "mutex": "lock"}.get(cat, "touched")
            label = os.path.basename(h["name"]) if cat == "file" else h["name"]   # basename: no PII path
            nodes.append(f'{nid}["{_mm(label[:70])}"]')
            classed.append(f"class {nid} {kind};")
            edges.append(f"{ip} -->|{verb}| {nid}")
        for i, r in enumerate(d.get("injected_regions", [])):
            nid = f"{ip}R{i}"
            nodes.append(f'{nid}["injected {r["protection"]} {r["start"]}"]')
            classed.append(f"class {nid} inj;")
            edges.append(f"{ip} -->|injected code| {nid}")
        for i, n in enumerate(d.get("network", [])):
            if not n.get("dst_ip"):
                continue
            nid = f"{ip}N{i}"
            nodes.append(f'{nid}["{_mm(n["dst_ip"])}:{n.get("dst_port","")}"]')
            classed.append(f"class {nid} c2;")
            edges.append(f"{ip} -->|C2| {nid}")
        for i, host in enumerate(d.get("c2", {}).get("domains", [])):    # per-PID, not the global set
            nid = f"{ip}D{i}"
            nodes.append(f'{nid}["{_mm(host)}"]')
            classed.append(f"class {nid} c2;")
            edges.append(f"{ip} -->|C2 recovered| {nid}")
    L += ["    " + n for n in nodes] + ["    " + e for e in edges]
    L += ["    " + c for c in cls] + ["    " + c for c in classed]
    L.append("```")
    return "\n".join(L)


_CHAIN_START = "<!-- MEM-CHAIN-START -->"
_CHAIN_END = "<!-- MEM-CHAIN-END -->"


def append_attack_chain(out_dir, bundle):
    """Add (idempotently) a detailed memory-derived chain to Attack_Graph.md. Replaces any prior
    chain block so re-runs don't duplicate. Only when there is at least one true-positive footprint."""
    if not bundle.get("dossiers"):
        return None
    graph_path = os.path.join(out_dir, "Attack_Graph.md")
    section = (f"\n{_CHAIN_START}\n\n## Memory-derived attack chain (discovered · correlated · "
               f"corroborated)\n\nFull footprint of the true-positive implant(s) recovered from the "
               f"memory image - parent lineage, injected/carved regions, dropped files, registry "
               f"persistence, implant mutex, and C2.\n\n"
               f"{build_attack_chain_mermaid(bundle)}\n\n{_CHAIN_END}\n")
    existing = ""
    if os.path.isfile(graph_path):
        with open(graph_path, "r", encoding="utf-8-sig") as fh:
            existing = fh.read()
        if _CHAIN_START in existing:
            existing = re.sub(re.escape(_CHAIN_START) + r".*?" + re.escape(_CHAIN_END),
                              "", existing, flags=re.S).rstrip() + "\n"
    with open(graph_path, "w", encoding="utf-8") as fh:
        fh.write(existing + section)
    return graph_path


_CORR_START = "<!-- TIMELINE-CORR-START -->"
_CORR_END = "<!-- TIMELINE-CORR-END -->"


def build_correlation_mermaid(corr):
    """Attack chain timeline: confirmed TP artifacts clustered by ATT&CK phase, ordered chronologically.
    Each phase is a subgraph node cluster; arrows show phase progression with time deltas."""
    tp_events = corr.get("tp_events", [])
    devices   = corr.get("devices", [])

    # Group events by ATT&CK phase, preserving chronological order within each phase
    _PHASE_ORDER = ["Execution", "Defense Evasion", "Persistence",
                    "Command & Control", "Credential Access", "Collection", "Exfiltration", "Impact"]
    by_phase = {}
    for e in tp_events:
        ph = e.get("phase", "Other")
        by_phase.setdefault(ph, []).append(e)

    L = ["```mermaid", "flowchart TD",
         "    classDef phase fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0,rx:8;",
         "    classDef artifact fill:#1e293b,stroke:#64748b,color:#cbd5e1;",
         "    classDef usb fill:#155e75,stroke:#67e8f9,color:#fff;",
         "    classDef c2 fill:#7f1d1d,stroke:#fca5a5,color:#fff;"]

    prev_node = None
    node_idx  = 0

    # USB entry vector (if any candidate)
    usb_candidates = [d for d in devices if d.get("delta_hours") is not None and d["delta_hours"] >= 0]
    if usb_candidates:
        best = min(usb_candidates, key=lambda d: d["delta_hours"])
        unode = f"USB0"
        fc = best.get("first_connect") or "unknown"
        L.append(f'    {unode}["Entry vector candidate<br/>USB: {_mm(best["vendor"])} {_mm(best["product"])}'
                 f'<br/>connected {_mm(fc)}"]')
        L.append(f"    class {unode} usb;")
        prev_node = unode

    # Phase clusters
    for phase in _PHASE_ORDER:
        events_in_phase = by_phase.get(phase, [])
        if not events_in_phase:
            continue
        # Earliest event in phase as the phase anchor
        earliest = events_in_phase[0]
        ph_node  = f"P{node_idx}"
        node_idx += 1
        ts_short = (earliest.get("timestamp") or "")[:16]  # YYYY-MM-DD HH:MM
        # Summarise up to 3 artifact types in this phase
        types = list(dict.fromkeys(e.get("type", "") for e in events_in_phase))[:3]
        type_summary = "<br/>".join(_mm(t[:40]) for t in types)
        label = f"{_mm(phase)}<br/>{_mm(ts_short)}<br/>{type_summary}"
        L.append(f'    {ph_node}["{label}"]')
        L.append(f"    class {ph_node} phase;")
        if prev_node:
            L.append(f"    {prev_node} --> {ph_node}")
        prev_node = ph_node

    # C2 endpoints recovered
    iocs = (corr.get("ram_first_seen") or "")
    c2_events = [e for e in tp_events if e.get("phase") == "Command & Control"]
    if c2_events and corr.get("ram_first_seen"):
        c2node = f"P{node_idx}"
        node_idx += 1
        c2_ts = c2_events[0].get("timestamp", corr["ram_first_seen"])[:16]
        L.append(f'    {c2node}["C2 confirmed<br/>{_mm(c2_ts)}<br/>IOCs recovered from RAM"]')
        L.append(f"    class {c2node} c2;")
        if prev_node and prev_node != c2node:
            pass  # already included in phase flow

    # If no TP events, fall back to simple USB→RAM flow
    if not tp_events and corr.get("ram_first_seen"):
        ref = (f'Implant first ran {_mm(corr["ram_first_seen"])}<br/>PID {corr["ram_pid"]} '
               f'{_mm(corr["ram_name"])}')
        L.append(f'    RAM["{ref}"]')
        L.append("    class RAM phase;")
        if prev_node:
            L.append(f"    {prev_node} --> RAM")

    L.append("```")
    return "\n".join(L)


def build_correlation_section(corr):
    """The full confirmed-TP attack timeline (artifact chain + USB correlation + Mermaid diagram)."""
    L = [_CORR_START, "",
         "## Confirmed TP Attack Timeline", "",
         "All confirmed true-positive artifacts ordered by earliest known timestamp. "
         "Only findings with positive injection/execution evidence are included. "
         "YARA-only name/string matches without corroborating memory evidence are excluded.", "",
         f"**Assessment:** {corr.get('summary', '')}", ""]

    # TP artifact timeline (all sources, chronological)
    tp_events = corr.get("tp_events", [])
    if tp_events:
        L += ["### Confirmed TP Artifact Chain (chronological)", "",
              "| Timestamp (UTC) | Phase | Type | PID | Description |",
              "|---|---|---|---|---|"]
        for e in tp_events:
            pid_s = str(e.get("pid") or "")
            L.append(f"| {e.get('timestamp', '')} | {e.get('phase', '')} | {e.get('type', '')} "
                     f"| {pid_s} | {e.get('description', '')[:120]} |")
        L.append("")

    # Per-PID RAM first-seen (enrichment anchor)
    if corr.get("per_pid"):
        L += ["### RAM First-Seen by Confirmed TP PID", "",
              "| PID | Process | First ran (UTC) | Basis | Injection evidence |", "|---|---|---|---|---|"]
        for p in corr["per_pid"]:
            note = "injected-thread create (implant start)" if p["basis"] == "injected-thread" \
                   else "process create (host/session start — upper bound)"
            ev = "yes (region/thread)" if p.get("evidence") else "NO — name/string match only (boot time)"
            L.append(f"| {p['pid']} | {p['name']} | {p['first_seen']} | {note} | {ev} |")
        L.append("")

    # USB correlation
    if corr.get("devices"):
        L += ["### Entry Vector Correlation (USB <-> Implant First-Seen)", "",
              "| USB device | Serial | First connect | vs implant | Verdict |",
              "|---|---|---|---|---|"]
        for d in corr["devices"]:
            delta = ("" if d["delta_hours"] is None
                     else (f"{d['delta_hours']}h before" if d["delta_hours"] >= 0
                           else f"{abs(d['delta_hours'])}h after"))
            L.append(f"| {d['vendor']} {d['product']} | `{d['serial']}` | {d['first_connect'] or 'unknown'} "
                     f"| {delta} | {d['verdict']} |")
        L.append("")

    L += [build_correlation_mermaid(corr), "", _CORR_END, ""]
    return "\n".join(L)


def append_correlation(out_dir, corr):
    """Idempotently add/replace the first-seen correlation block in Attack_Graph.md."""
    graph_path = os.path.join(out_dir, "Attack_Graph.md")
    section = "\n" + build_correlation_section(corr)
    existing = ""
    if os.path.isfile(graph_path):
        with open(graph_path, "r", encoding="utf-8-sig") as fh:
            existing = fh.read()
        if _CORR_START in existing:
            existing = re.sub(re.escape(_CORR_START) + r".*?" + re.escape(_CORR_END),
                              "", existing, flags=re.S).rstrip() + "\n"
    with open(graph_path, "w", encoding="utf-8") as fh:
        fh.write(existing + section)
    return graph_path


def _newest(out_dir, pattern):
    files = glob.glob(os.path.join(out_dir, pattern))
    return max(files, key=os.path.getmtime) if files else None


def _load_json(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except Exception:
        return None


# ATT&CK phase classification for confirmed TP finding types.
_TP_PHASE = {
    "Shellcode Thread (Memory)":                    "Execution",
    "Injected Memory Region":                       "Defense Evasion",
    "Dormant Beacon Candidate (Memory)":            "Command & Control",
    "Thread-Pool Injection / Ekko Pattern (Memory)":"Defense Evasion",
    "Process Hollowing Indicator (Memory)":         "Defense Evasion",
    "Process Ghosting (Deleted Image)":             "Defense Evasion",
    "Manual-map PE Injection (Memory)":             "Defense Evasion",
    "Module Stomping (Memory)":                     "Defense Evasion",
    "Direct Syscall Execution":                     "Defense Evasion",
    "ETW-TI Provider Disabled":                     "Defense Evasion",
    "YARA Match (Memory)":                          "Execution",
    "Known Offensive Tool (Memory)":                "Execution",
    "Suspicious Scheduled Task":                    "Persistence",
    "WMI Persistence":                              "Persistence",
    "AppCertDLLs Injection":                        "Persistence",
    "Accessibility Feature Hijack":                 "Persistence",
    "IFEO Debugger Hijack":                         "Persistence",
    "BootExecute Persistence":                      "Persistence",
    "Active Setup Persistence":                     "Persistence",
    "Suspicious Print Monitor DLL":                 "Persistence",
    "Suspicious Service":                           "Persistence",
    "VSS Deletion":                                 "Impact",
    "Recovery Disable":                             "Impact",
    "Archive Staging":                              "Collection",
    "SMTP Exfiltration":                            "Exfiltration",
    "Raw File Transfer":                            "Exfiltration",
    "DoH Beacon":                                   "Command & Control",
    "Suspicious Outbound Connection":               "Command & Control",
    "Suspicious BITS Job":                          "Command & Control",
    "Credential Hive Dump":                         "Credential Access",
    "Browser Credential Access":                    "Credential Access",
    "LSASS Memory Dump":                            "Credential Access",
    "Credential Vault Access":                      "Credential Access",
    "LOLBin Execution":                             "Execution",
    "WSL Suspicious Execution":                     "Defense Evasion",
    "WSL Parent Spawn":                             "Defense Evasion",
}

# Finding types that are confirmed TP only when severity is High or Critical.
# Medium/Low instances need corroboration and are NOT confirmed TPs for the timeline.
_TP_SEVERITY_GATE = {
    "YARA Match (Memory)",               # Medium = data region hit, not exec evidence
    "Dormant Beacon Candidate (Memory)", # Medium = entropy alone, needs AdjAnonExec corroboration
    "Shellcode Thread (Memory)",         # Medium = vad=image (needs corroboration); only High = anon_exec
}


def _collect_tp_events(out_dir, dossiers, tp_pids=None):
    """Aggregate confirmed true-positive artifact events from all scan outputs in `out_dir`.
    Returns a list of dicts: {timestamp (str), phase (str), type (str), pid, name, description}.
    Only confirmed TPs are included -- no YARA-only Medium matches, no FP-cleared findings.

    Sources (in priority order for timestamp accuracy):
    1. Enrichment dossiers  -- injected-thread first-seen (most accurate attack time)
    2. Memory_Findings JSON -- detection timestamps for confirmed TP finding types
    3. IOCs.json            -- C2 IP/domain recovery = at least one confirmed C2 contact
    """
    tp_pids = set(tp_pids or [])
    events  = []

    # 1. Enrichment dossiers -- inject time is the best attack anchor.
    for d in dossiers:
        pid  = d.get("pid")
        name = d.get("name", "?")
        t, basis = implant_anchor(d)
        if t and has_injection_evidence(d):
            phase = "Execution (injection)"
            desc  = f"PID {pid} ({name}) first carried injected code -- {basis} create time"
            events.append({"timestamp": _fmt(t), "phase": "Execution", "type": "Implant First Seen",
                           "pid": pid, "name": name, "description": desc, "_dt": t})
        # C2 contact first-seen: recovered IPs/domains = the implant called home at least once
        if d.get("recovered_iocs", {}).get("ips") or d.get("recovered_iocs", {}).get("domains"):
            ioc_t = t  # best we can do: anchor on the same PID's first-seen time
            if ioc_t:
                c2 = (d["recovered_iocs"].get("ips", []) + d["recovered_iocs"].get("domains", []))[:3]
                events.append({"timestamp": _fmt(ioc_t), "phase": "Command & Control",
                               "type": "C2 Infrastructure Recovery",
                               "pid": pid, "name": name,
                               "description": f"C2 IOCs recovered from PID {pid} ({name}): {', '.join(c2)}",
                               "_dt": ioc_t})

    # 2. Memory_Findings -- filter to confirmed TP types at High/Critical severity.
    mf_path = _newest(out_dir, "Memory_Findings_*.json")
    if mf_path:
        mf = _load_json(mf_path) or []
        for f in mf:
            sev  = f.get("Severity", "")
            ftyp = f.get("Type", "")
            tgt  = f.get("Target", "")
            det  = f.get("Details", "")
            ts   = f.get("Timestamp", "")
            if ftyp in _TP_SEVERITY_GATE and sev not in ("High", "Critical"):
                continue  # skip Medium/Low for these uncertain types
            if ftyp not in _TP_PHASE:
                continue  # not a confirmed-TP finding type
            # Only include if from a TP PID (enriched) or if finding itself is from a high-conf type
            pid_in_target = None
            import re as _re
            m = _re.search(r"PID\s+(\d+)", tgt)
            if m:
                pid_in_target = int(m.group(1))
            if tp_pids and pid_in_target and pid_in_target not in tp_pids:
                continue  # finding is from a non-TP PID
            phase = _TP_PHASE.get(ftyp, "Other")
            dt_v  = coerce_dt(ts)
            events.append({"timestamp": ts, "phase": phase, "type": ftyp,
                           "pid": pid_in_target, "name": tgt[:60],
                           "description": det[:120], "_dt": dt_v or coerce_dt("2000-01-01")})

    # Deduplicate: one entry per (type, pid) keeping earliest timestamp.
    seen_keys: dict = {}
    deduped = []
    for e in sorted(events, key=lambda x: x["_dt"] or coerce_dt("2000-01-01")):
        key = (e.get("type", ""), e.get("pid"))
        if key not in seen_keys:
            seen_keys[key] = True
            deduped.append(e)
    # Strip internal sort key
    for e in deduped:
        e.pop("_dt", None)
    return deduped


def correlate_from_dir(out_dir):
    """Standalone join (no memory image needed): read the newest Memory_Enrichment_*.json and
    USB_Forensics_*.json already in `out_dir`, correlate first-seen times, write Timeline_Correlation.md
    and patch the Attack_Graph first-seen block. Run this AFTER collecting USB history on the host."""
    enr = _load_json(_newest(out_dir, "Memory_Enrichment_*.json"))
    if not enr:
        print("[!] no Memory_Enrichment_*.json in", out_dir, "- run the enrichment first")
        return None
    dossiers = enr.get("dossiers", [])
    tp_pids  = {d["pid"] for d in dossiers}
    usb      = _load_json(_newest(out_dir, "USB_Forensics_*.json"))
    devices  = load_usb_devices(usb) if usb else []
    tp_events = _collect_tp_events(out_dir, dossiers, tp_pids)
    corr = correlate_first_seen(dossiers, devices, tp_events=tp_events)
    with open(os.path.join(out_dir, "Timeline_Correlation.md"), "w", encoding="utf-8") as fh:
        fh.write("# Confirmed TP Attack Timeline\n\n" + build_correlation_section(corr))
    append_correlation(out_dir, corr)
    if not usb:
        print("[i] no USB_Forensics_*.json yet - correlation shows RAM first-seen only.")
    print(f"[+] {corr['summary']}")
    return corr


def build_enrichment_md(bundle):
    """Analyst work sheet for the true positives: footprint per PID, capa capabilities on the carved
    shellcode, and the encoded blobs to **decode in CyberChef** (we extract the strings; the analyst
    decodes - encodings vary per case: base64, hex, gzip/zlib, single/rolling XOR, RC4, custom)."""
    L, a = [], lambda s="": L.append(s)
    a(f"# Memory Enrichment - Eradication Scope - {bundle.get('image','')}")
    a(""); a(f"Generated: {bundle.get('generated','')} · True positives: "
             f"{', '.join(str(p) for p in bundle.get('true_positive_pids', []))}"); a("")
    _IOC_LABELS = [("urls", "C2 / URLs"), ("domains", "Domains"), ("ips", "IPs"),
                   ("miner_configs", "Miner command lines"), ("wallets", "Crypto wallets"),
                   ("xmr", "Monero wallets"), ("onion", "Tor (.onion)"),
                   ("telegram_tokens", "Telegram bot tokens"), ("discord_webhooks", "Discord webhooks"),
                   ("aws_keys", "AWS keys"),
                   ("unverified", "Unverified hosts (captured; TLD not recognized - not resolved, verify)")]
    for d in bundle.get("dossiers", []):
        a(f"## PID {d['pid']} ({d['name']})")
        if d.get("injected_thread_first_seen"):
            a(f"_First ran in RAM (injected-thread create = implant start): "
              f"**{d['injected_thread_first_seen']}**_  ")
        if d.get("create_time"):
            a(f"_Process create time (host start{' - injected, so this is the host process boot, not the implant' if d.get('injected_thread_first_seen') else ''}): {d['create_time']}_")
        a("")
        # DC3-MWCP confirmed mutexes get their own section -- these are definitively malware-created
        mwcp_mx = d.get("mwcp_mutexes", [])
        if mwcp_mx:
            a("**DC3-MWCP CONFIRMED malware-created mutex names (from binary parsing):**")
            for mx in mwcp_mx:
                a(f"- `{mx}` _(mwcp-confirmed: this mutex was created by the malware binary)_")
            a("")
        susp = [h for h in d.get("handles", []) if h.get("suspicious")]
        if susp:
            a("**Suspicious handles (eradication artifacts):**")
            for h in susp:
                a(f"- `{h['category']}` {h['name']}")
            a("")
        ti = d.get("threat_iocs", {})
        ioc_lines = [(key, label, ti.get(key, [])) for key, label in _IOC_LABELS if ti.get(key)]
        if ioc_lines or ti.get("private_keys"):
            a("**Recovered IOCs (from process memory; defanged here, live in IOCs.json):**")
            for key, label, vals in ioc_lines:
                for v in vals:
                    # IPs get an OFFLINE country-of-origin tag (db-ip Lite; no network) so each IOC is
                    # tied to real infrastructure at a glance.
                    geo = f"  [{geo_label(v)}]" if key == "ips" and geo_label(v) else ""
                    a(f"- **{label}:** `{defang(v)}`{geo}")
            if ti.get("private_keys"):
                a(f"- **Private-key blocks in memory:** {ti['private_keys']}")
            a("")
        cfg = d.get("config_artifacts", [])
        if cfg:
            a("**Bot/implant config DNA recovered (beacon templates, UA, self-spread):**")
            for art in cfg:
                a(f"- {defang(art)}")
            a("")
        for r in d.get("injected_regions", []):
            a(f"### Injected region {r['start']} ({r['protection']}) - "
              "analyzed in-memory, bytes not retained"); a("")
            cap = r.get("capa")
            if cap is None:
                a("- capa: not staged (stage with `Build-OfflineToolkit.ps1 -IncludeCapa` "
                  "to auto-analyze injected regions)")
            elif cap.get("capabilities"):
                a(f"- **capa capabilities:** {', '.join(cap['capabilities'][:20])}")
                if cap.get("attack"):
                    a(f"- **capa ATT&CK:** {', '.join(cap['attack'])}")
            else:
                a("- capa: ran, no capabilities matched (region may be data, packed, or non-code)")
            fl = r.get("floss")
            if fl:
                deob = (fl.get("decoded", []) + fl.get("stack", []) + fl.get("tight", []))
                if deob:
                    a(f"- **FLOSS deobfuscated strings ({len(deob)}):** "
                      + ", ".join(f"`{s}`" for s in deob[:25]))
                else:
                    a(f"- FLOSS: no obfuscated strings recovered ({fl.get('static_count', 0)} static)")
            mw = r.get("mwcp")
            if mw is None:
                a("- mwcp: not staged (stage with `Build-OfflineToolkit.ps1 -IncludeMWCP` "
                  "to extract malware family config — mutex names, C2, credentials)")
            elif (mw.get("mutex") or mw.get("address") or mw.get("filename") or mw.get("password")
                  or mw.get("mwcp_verified_iocs") or mw.get("mwcp_new_iocs")):
                if mw.get("mutex"):
                    a(f"- **mwcp CONFIRMED mutexes (extracted from binary):** "
                      + ", ".join(f"`{m}`" for m in mw["mutex"]))
                if mw.get("mwcp_verified_iocs"):
                    a(f"- **mwcp VERIFIED (binary config confirms sweep IOCs):** "
                      + ", ".join(f"`{defang(x)}`" for x in mw["mwcp_verified_iocs"][:10]))
                if mw.get("mwcp_new_iocs"):
                    a(f"- **mwcp NEW C2 (not in region sweep, from binary config):** "
                      + ", ".join(f"`{defang(x)}`" for x in mw["mwcp_new_iocs"][:10]))
                if mw.get("address"):
                    a(f"- **mwcp additional C2:** "
                      + ", ".join(f"`{defang(x)}`" for x in mw["address"][:10]))
                if mw.get("filename"):
                    a(f"- **mwcp dropped filenames:** "
                      + ", ".join(f"`{x}`" for x in mw["filename"][:10]))
                if mw.get("password"):
                    a(f"- **mwcp passwords/keys:** "
                      + ", ".join(f"`{x}`" for x in mw["password"][:5]))
            else:
                a("- mwcp: ran, no family parser matched (unknown family or packed)")
            a("")
        cands = d.get("decode_candidates", [])
        if cands:
            a("**Decode candidates - paste into CyberChef** (start with the *Magic* recipe, then "
              "From Base64 / From Hex / Gunzip / XOR Brute Force / RC4 as the data suggests):")
            for c in cands:
                reg = f" @ {c['region']}" if c.get("region") else ""
                a(f"- ({c['type']}, {c['len']} chars{reg}) `{c['value']}`")
            a("")
    a("> CyberChef: https://gchq.github.io/CyberChef/ - *Magic* auto-detects most encodings/layers; "
      "for keyed ciphers supply the key recovered from the region strings above.")
    a("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Phase 1C retrospective fix: benign-infrastructure allowlist.
# memory_enrich.py's IOC sweep recovers ALL domains present in scanned process
# memory, including cert-authority OCSP/CRL endpoints, vendor CDN domains, and
# XML namespace URIs. Without filtering, merge_into_iocs() promotes them into
# c2_endpoints[], causing Invoke-Eradication to sinkhole legitimate infra.
# ---------------------------------------------------------------------------

_BENIGN_DOMAIN_SUFFIXES = (
    # Microsoft / Windows
    ".microsoft.com", ".windows.com", ".windowsupdate.com", ".microsoftonline.com",
    ".msocsp.com",  # Microsoft OCSP responder
    ".azure.com", ".azureedge.net", ".live.com", ".live.net", ".office.com", ".sharepoint.com",
    # Google / YouTube
    ".google.com", ".googleapis.com", ".gstatic.com", ".youtube.com", ".googlevideo.com",
    # Adobe (confirmed FP pattern from MAIN-SYS investigation)
    ".adobe.com", ".acrobat.com", ".adobelogin.com", ".adobe.io", ".adobedtm.com",
    # Certificate authorities — OCSP / CRL infrastructure
    ".digicert.com", ".verisign.com", ".entrust.net", ".globalsign.com",
    ".identrust.com", ".sectigo.com", ".comodo.com", ".letsencrypt.org",
    # Government / military CA endpoints (DISA)
    "disa.mil", ".disa.mil",
    # Taiwanese ISP CA (common in enterprise cert chains)
    ".hinet.net",
    # Content / standards namespaces that appear in Office/PDF metadata
    ".openxmlformats.org", ".w3.org", ".iptc.org", ".purl.org",
    # Developer tools commonly in working memory
    ".github.com", ".githubusercontent.com", ".gitforwindows.org",
    # Apple
    ".apple.com", ".icloud.com",
    # CDNs
    ".cloudfront.net", ".akamaiedge.net", ".akamaitechnologies.com",
    ".fastly.net", ".cloudflare.com",
    # Mozilla
    ".mozilla.org", ".firefox.com",
)

_BENIGN_DOMAIN_EXACT = frozenset({
    "ocsp.us", "gitforwindows.org", "iptc.org", "purl.org",
})


def _is_benign_domain(host: str) -> bool:
    """Return True if *host* is known-good infrastructure that must never be
    promoted to c2_endpoints[].  Used by merge_into_iocs to prevent FP PIDs
    from contaminating the eradication IOC set."""
    h = host.lower().rstrip(".")
    if h in _BENIGN_DOMAIN_EXACT:
        return True
    return any(h == s.lstrip(".") or h.endswith(s) for s in _BENIGN_DOMAIN_SUFFIXES)


def _is_valid_ioc_host(host: str) -> bool:
    """Return True if host is a structurally valid IP or domain that can be acted on.
    Filters out extraction artifacts like '***', empty strings, or truncated fragments
    that the IOC sweep occasionally emits from malformed netscan records."""
    if not host or len(host) < 3:
        return False
    if _ip_to_int(host) is not None:
        return True   # valid IPv4
    return _valid_host(host)  # valid-looking domain (TLD check)


def merge_into_iocs(out_dir, bundle):
    """Feed the eradication scope into IOCs.json so Invoke-Eradication acts on it: recovered C2
    (ips/domains) is folded into c2_endpoints (the firewall keeps it blocked after restore), and a
    `memory_eradication` block carries the files/keys/mutexes/implicated-PIDs to remove. Eradication
    stays analyst-gated - this only populates the indicator set, it deletes nothing."""
    iocs_path = os.path.join(out_dir, "IOCs.json")
    if not os.path.isfile(iocs_path):
        return None
    try:
        with open(iocs_path, "r", encoding="utf-8-sig") as fh:
            ioc = json.load(fh)
    except Exception:
        return None
    erad = bundle.get("eradication_iocs", {})
    # REPLACE prior memory-sourced endpoints so re-runs don't accumulate stale FPs; keep others.
    ioc["c2_endpoints"] = [c for c in ioc.get("c2_endpoints", []) if c.get("source") != "memory"]
    have = {(c.get("host"), c.get("port")) for c in ioc["c2_endpoints"]}
    for host in erad.get("c2_ips", []) + erad.get("c2_domains", []):
        if not _is_valid_ioc_host(host):
            continue  # drop extraction artifacts (***,  truncated fragments, etc.)
        if _is_benign_domain(host):
            continue  # Phase 1C: skip allowlisted infrastructure (cert CAs, vendor CDNs, etc.)
        if (host, 0) not in have:
            ioc["c2_endpoints"].append({"host": host, "port": 0, "sanctioned": False,
                                        "session_id": None, "instance_id": None, "source": "memory",
                                        "country": (country_of_ip(host) if _ip_to_int(host) is not None else None)})
            have.add((host, 0))
    ioc["memory_eradication"] = erad
    with open(iocs_path, "w", encoding="utf-8") as fh:
        json.dump(ioc, fh, indent=2)
    return iocs_path


def _open_vmm(image):
    mpc = str(Path(__file__).resolve().parent.parent.parent.parent / "tools" / "memprocfs")
    os.add_dll_directory(mpc)
    sys.path.insert(0, mpc)
    for z in glob.glob(os.path.join(mpc, "python", "python3*.zip")):
        sys.path.insert(0, z)
    import vmmpyc
    return vmmpyc.Vmm(["-device", image, "-disable-symbolserver", "-disable-python"])


def run(image, out_dir, pids):
    vmm = _open_vmm(image)
    pid_map = {p.pid: p for p in vmm.process_list()}
    nets_by_pid = {}
    for c in _safe(lambda: vmm.maps.net(), []):
        nets_by_pid.setdefault(c.get("pid"), []).append({
            "state": c.get("state", ""), "dst_ip": c.get("dst-ip", ""),
            "dst_port": c.get("dst-port", ""), "src_port": c.get("src-port", "")})
    carve_dir = out_dir
    os.makedirs(carve_dir, exist_ok=True)
    capa_exe, floss_exe = find_capa(), find_floss()
    mwcp_py, mwcp_lib   = find_mwcp()
    print(f"[*] capa:  {capa_exe or 'not staged'}")
    print(f"[*] floss: {floss_exe or 'not staged'}")
    print(f"[*] mwcp:  {'python -m mwcp (lib: ' + str(mwcp_lib) + ')' if mwcp_py else 'not staged -- run: .\\Build-OfflineToolkit.ps1 -IncludeMWCP'}")
    dossiers = []
    for pid in pids:
        p = pid_map.get(pid)
        if not p:
            print(f"[!] PID {pid} not in image - skipping")
            continue
        print(f"[*] enriching PID {pid} ({p.name}) ...")
        dossiers.append(enrich_pid(vmm, p, pid_map, nets_by_pid, carve_dir,
                                   capa_exe=capa_exe, floss_exe=floss_exe,
                                   mwcp_py=mwcp_py, mwcp_lib=mwcp_lib,
                                   out_dir=out_dir))

    # attach the YARA rules the pivot matched per PID (so the attack-chain implant node names them)
    tp_path = os.path.join(out_dir, "YARA_Pivot_TP.json")
    if os.path.isfile(tp_path):
        try:
            with open(tp_path, "r", encoding="utf-8-sig") as fh:
                rules_by_pid = {int(t["pid"]): t.get("rules", []) for t in json.load(fh)}
            for d in dossiers:
                d["rules"] = rules_by_pid.get(d["pid"], [])
        except Exception:
            pass

    bundle = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
              "image": os.path.basename(image), "true_positive_pids": pids,
              "dossiers": dossiers, "eradication_iocs": rollup_iocs(dossiers)}
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(out_dir, f"Memory_Enrichment_{ts}.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    print(f"[+] {out}")
    md_path = os.path.join(out_dir, "Memory_Enrichment.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(build_enrichment_md(bundle))
    print(f"[+] {md_path}")
    if merge_into_iocs(out_dir, bundle):
        print(f"[+] eradication IOCs merged into IOCs.json")
    if append_attack_chain(out_dir, bundle):
        print(f"[+] memory-derived attack chain added to Attack_Graph.md")
    # First-seen correlation: tie the RAM implant create time(s) to any USB history already collected.
    # If USB history is gathered later (live on the host), re-run with --correlate to refresh this.
    usb       = _load_json(_newest(out_dir, "USB_Forensics_*.json"))
    tp_pids   = {d["pid"] for d in dossiers}
    tp_events = _collect_tp_events(out_dir, dossiers, tp_pids)
    corr = correlate_first_seen(dossiers, load_usb_devices(usb) if usb else [], tp_events=tp_events)
    with open(os.path.join(out_dir, "Timeline_Correlation.md"), "w", encoding="utf-8") as fh:
        fh.write("# Confirmed TP Attack Timeline\n\n" + build_correlation_section(corr))
    append_correlation(out_dir, corr)
    print(f"[+] first-seen correlation: {corr['summary']}")
    return out


def main():
    # --correlate <out_dir>: re-join existing Memory_Enrichment + USB_Forensics JSON into the
    # first-seen timeline WITHOUT re-opening the image. Run after collecting USB history on the host.
    if len(sys.argv) >= 3 and sys.argv[1] == "--correlate":
        return 0 if correlate_from_dir(sys.argv[2]) is not None else 1
    if len(sys.argv) < 4:
        print("usage: memory_enrich.py <image> <out_dir> <pid>[,<pid>...]")
        print("       memory_enrich.py --correlate <out_dir>   (re-join RAM<->USB first-seen, no image)")
        return 2
    image, out_dir = sys.argv[1], sys.argv[2]
    pids = [int(x) for x in sys.argv[3].split(",") if x.strip()]
    run(image, out_dir, pids)
    return 0


if __name__ == "__main__":
    sys.exit(main())
