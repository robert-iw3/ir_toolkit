#!/usr/bin/env python3
"""
memory_enrich.py - Linux memory IOC enrichment ("dynamically scan strings in memory").

The Linux counterpart of the Windows playbooks/windows/threat_hunting/memory_enrich.py IOC core.
After the YARA worker CARVES true-positive regions (anon+exec injected code, or any hit with
--carve / IR_CARVE_ANY) to tools/binja/data/<incident>/*.bin, this scans those regions' STRINGS
(ASCII + UTF-16LE) and recovers the adversary IOCs the implant left in memory:

    network   -> C2 IPs / domains / URLs (incl. stratum/ws/tcp schemes), Tor .onion
    exfil     -> Telegram bot tokens, Discord webhooks
    crypto    -> Monero addresses + miner command lines / wallets
    creds     -> AWS keys, private-key blocks

Output: Memory_Enrichment_<stamp>.json (per-region dossier + rolled-up IOC bundle) + .md, and
common-schema FINDINGS that merge into Memory_Findings -> Combined_Findings -> adjudication ->
IOCs.json + the incident report's "Memory forensics & YARA" / C2 sections. Only ELEVATES - it
never suppresses a finding. FP-resistant: benign OS/CDN hosts + RFC1918/loopback IPs are dropped.

Usage:
  memory_enrich.py --carve-dir tools/binja/data/<incident> --out-dir reports/<host> [--stamp S]
  memory_enrich.py --region path/to/pidNNN_proc_0xADDR.bin   # one region, print IOCs (no write)
"""
import argparse
import datetime
import glob
import json
import os
import re
import sys

# ---- IOC core (mirrors the Windows memory_enrich.py pure helpers; stdlib-only) ----------------
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL_RE = re.compile(
    r"(?i)\b(?:https?|ftp|stratum\+(?:tcp|udp|ssl)|tcp|ws|wss)://"
    r"[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]*)?")
_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|ru|cn|io|co|xyz|top|club|online|site|tk|pw|cc|su|me)\b")
_BENIGN_IP_RE = re.compile(r"^(0\.|127\.|169\.254\.|255\.|224\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
_BENIGN_DOMAIN_RE = re.compile(
    r"(?i)("
    r"microsoft\.com|microsoftonline\.com|windows\.com|windows\.net|windowsupdate\.com|"
    r"ubuntu\.com|canonical\.com|debian\.org|kernel\.org|launchpad\.net|archlinux\.org|"
    r"fedoraproject\.org|redhat\.com|python\.org|pypi\.org|gnu\.org|freedesktop\.org|"
    r"google\.com|googleapis\.com|gstatic\.com|gvt1\.com|gvt2\.com|mozilla\.org|mozilla\.com|"
    r"nvidia\.com|gnome\.org|x\.org|systemd\.io|openssl\.org|sourceforge\.net|"
    r"cloudflare\.com|akamai\.net|akamaiedge\.net|w3\.org|digicert\.com|letsencrypt\.org|apple\.com)$")
_ONION_RE = re.compile(r"\b(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion\b")
_XMR_RE = re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b")
_AWS_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b")
_TELEGRAM_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")
_DISCORD_RE = re.compile(r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]{20,}")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_MINER_RE = re.compile(
    r"(?i)stratum\+(?:tcp|udp|ssl)://[A-Za-z0-9._:\-/?=&%]+(?:[ \t]+-[A-Za-z][ \t]+[A-Za-z0-9._:\-/?=&%]+){0,5}")
_HOST_OF_RE = re.compile(r"(?i)^[a-z+]+://([A-Za-z0-9._\-]+)")
# Real-looking-domain check - STRUCTURAL ONLY (no DNS). "Confident" = last label is a recognised TLD
# (any 2-letter ccTLD, which is a complete rule, OR a common gTLD below) and every label is RFC-1035
# shaped. The gTLD set is a COMMON subset, not the full IANA list; a host that does not match is moved
# to `unverified` ("not resolvable - verify"), never deleted and never asserted as an IOC.
_GTLD = frozenset((
    "com net org info biz xyz top club online site app dev cloud shop store tech space website "
    "live news blog page link click work fun icu vip pro name mobi asia tel pub win bid loan men "
    "date stream download racing party review trade science gdn ren xin wang ltd group team today "
    "email host run cyou sbs world life fund money company center systems solutions services "
    "digital network media monster pics photos cc su pw tk ninja guru ws me tv io co").split())
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")
# A lowercase TLD label immediately followed by an UPPERCASE letter is a run-on concatenation artifact
# (memory has no delimiters); cut there to recover the real host (office.netX -> office.net). Never
# fabricates: an all-lowercase run-on has no boundary and just fails the TLD check.
_OVERCAPTURE_RE = re.compile(r"\.[a-z]{2,24}(?=[A-Z])")


def _valid_tld(tld):
    tld = str(tld).lower()
    return (len(tld) == 2 and tld.isalpha()) or tld in _GTLD


def _valid_host(h):
    """True when h is structurally a real domain: >=2 RFC-1035 labels and a recognised TLD. No DNS."""
    h = str(h or "").strip().rstrip(".").lower()
    if not h or len(h) > 253 or "." not in h:
        return False
    labels = h.split(".")
    return len(labels) >= 2 and _valid_tld(labels[-1]) and all(_LABEL_RE.match(l) for l in labels)


def _url_host_ok(h):
    if _IPV4_RE.fullmatch(str(h)):
        return True
    labels = str(h).split(".")
    return len(labels) >= 2 and all(labels)


def defang(s):
    s = str(s).replace("http", "hxxp").replace("://", "[:]//")
    s = re.sub(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", r"\1[.]\2[.]\3[.]\4", s)
    s = re.sub(r"(?i)\b([a-z0-9-]+)\.((?:[a-z0-9-]+\.)*[a-z]{2,})\b",
               lambda m: m.group(0).replace(".", "[.]"), s)
    return s


def _host_of(url):
    m = _HOST_OF_RE.match(url)
    if not m:
        return ""
    h = m.group(1)
    cut = _OVERCAPTURE_RE.search(h)        # trim a TLD-then-uppercase run-on concatenation
    if cut:
        h = h[:cut.end()]
    return h.lower()


def _memblob(data):
    """ASCII + UTF-16LE (both alignments) view, so wide-char strings are caught too."""
    try:
        return (data.decode("latin-1", "ignore") + "\n" +
                data.decode("utf-16-le", "ignore") + "\n" + data[1:].decode("utf-16-le", "ignore"))
    except Exception:
        return ""


def extract_c2_iocs(data, bare_domains=True):
    if not data:
        return {"ips": [], "domains": [], "urls": [], "unverified": []}
    blob = _memblob(data)
    domains, ips, unverified, urls = set(), set(), set(), []
    for u in sorted(set(_URL_RE.findall(blob))):
        h = _host_of(u)
        if not h or _BENIGN_DOMAIN_RE.search(h):
            continue
        urls.append(u)
        if _IPV4_RE.fullmatch(h):
            ips.add(h)
        elif _valid_host(h):                 # structured + recognised TLD -> confident domain IOC
            domains.add(h)
        else:                                # kept, not dropped: "not resolvable - verify"
            unverified.add(h)
    if bare_domains:
        domains |= set(_DOMAIN_RE.findall(blob))
    ips = sorted({m for m in ips if m and not _BENIGN_IP_RE.match(m)})
    clean, maybe = set(), set(unverified)
    for d in domains:
        d = str(d).lower()
        if not d or _BENIGN_DOMAIN_RE.search(d) or d.isupper():
            continue
        (clean if _valid_host(d) else maybe).add(d)
    return {"ips": ips[:50], "domains": sorted(clean)[:50], "urls": urls[:50],
            "unverified": sorted(maybe)[:50]}


def extract_threat_iocs(data, bare_domains=True):
    """Full memory-IOC sweep: C2 + Tor + crypto + exfil channels + credential material. Structured,
    de-duplicated, FP-filtered. Plain emails are NOT collected (mostly victim PII)."""
    out = {"ips": [], "domains": [], "urls": [], "unverified": [], "onion": [], "xmr": [],
           "aws_keys": [], "telegram_tokens": [], "discord_webhooks": [], "miner_configs": [],
           "wallets": [], "private_keys": 0}
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
    wallets = set(out["xmr"])
    for m in out["miner_configs"]:
        wm = re.search(r"(?i)-u[=\s]+([A-Za-z0-9]{20,})", m)
        if wm:
            wallets.add(wm.group(1))
    out["wallets"] = sorted(wallets)[:20]
    return out


def has_iocs(iocs):
    return bool(iocs["ips"] or iocs["domains"] or iocs["urls"] or iocs["onion"] or iocs["xmr"] or
                iocs["aws_keys"] or iocs["telegram_tokens"] or iocs["discord_webhooks"] or
                iocs["miner_configs"] or iocs["wallets"] or iocs["private_keys"])


# ---- capa + FLOSS (Linux) on carved regions ---------------------------------------------------
# capa identifies CAPABILITIES + ATT&CK in a carved shellcode region; FLOSS recovers DEOBFUSCATED
# strings (decoded/stack/tight) that plain `strings`/the IOC sweep miss - so an implant's encoded
# C2 config is recovered. Both are OPTIONAL: staged by Build-OfflineToolkit-Linux.sh
# (--include-capa / --include-floss -> tools/capa/capa, tools/floss/floss) or found on PATH.
import shutil

_TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))), "tools")


def find_capa():
    cand = os.path.join(_TOOLS, "capa", "capa")
    return cand if os.path.isfile(cand) else shutil.which("capa")


def find_floss():
    cand = os.path.join(_TOOLS, "floss", "floss")
    return cand if os.path.isfile(cand) else shutil.which("floss")


def parse_capa_json(text):
    """Capability names + ATT&CK ids from `capa -j`, tolerant of schema variance."""
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


def parse_floss_json(text):
    """DEOBFUSCATED strings (decoded/stack/tight) from `floss -j` - what plain strings/capa miss."""
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


def run_capa(capa_exe, region_path, fmt="sc64"):
    if not capa_exe:
        return {"capabilities": [], "attack": []}
    try:
        r = __import__("subprocess").run([capa_exe, "-f", fmt, "-j", region_path],
                                         capture_output=True, text=True, timeout=300)
        if r.stdout.strip():
            return parse_capa_json(r.stdout)
    except Exception:
        pass
    return {"capabilities": [], "attack": []}


def run_floss(floss_exe, region_path, fmt="sc64"):
    if not floss_exe:
        return {"decoded": [], "stack": [], "tight": [], "static_count": 0}
    try:
        r = __import__("subprocess").run([floss_exe, "-f", fmt, "-j", "--quiet", region_path],
                                         capture_output=True, text=True, timeout=600)
        if r.stdout.strip():
            return parse_floss_json(r.stdout)
    except Exception:
        pass
    return {"decoded": [], "stack": [], "tight": [], "static_count": 0}


# ---- Linux driver: scan carved regions -> dossiers + findings ---------------------------------
def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(sev, ftype, target, details, mitre):
    return {"Timestamp": _now(), "Severity": sev, "Type": ftype, "Target": target,
            "Details": details, "MITRE": mitre, "Source": "memory_enrich"}


def enrich_region(bin_path):
    """Scan one carved region -> {pid, process, region, perms, iocs}. Reads the JSON sidecar for
    attribution; bare_domains is enabled (carved regions are small config-bearing slices)."""
    meta = {}
    side = bin_path[:-4] + ".json" if bin_path.endswith(".bin") else bin_path + ".json"
    if os.path.isfile(side):
        try:
            meta = json.load(open(side, encoding="utf-8"))
        except Exception:
            meta = {}
    try:
        with open(bin_path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    iocs = extract_threat_iocs(data, bare_domains=True)
    # capa (capabilities/ATT&CK) + FLOSS (deobfuscated strings) over the region, if staged. FLOSS
    # recovers encoded C2 config plain strings miss, so IOC-sweep its decoded output and merge in.
    capa = run_capa(find_capa(), bin_path)
    floss = run_floss(find_floss(), bin_path)
    deob = "\n".join(floss["decoded"] + floss["stack"] + floss["tight"])
    if deob.strip():
        di = extract_threat_iocs(deob.encode("utf-8", "ignore"), bare_domains=True)
        for k in ("ips", "domains", "urls", "onion", "xmr", "aws_keys", "telegram_tokens",
                  "discord_webhooks", "miner_configs", "wallets"):
            iocs[k] = sorted(set(iocs[k]) | set(di[k]))[:50]
        iocs["private_keys"] += di["private_keys"]
    return {"region_file": os.path.basename(bin_path),
            "pid": str(meta.get("pid", "")), "process": meta.get("process", ""),
            "base_address": meta.get("base_address", ""), "region": meta.get("region", ""),
            "perms": meta.get("perms", ""), "matched_rules": meta.get("matched_rules", []),
            "iocs": iocs, "capa": capa, "floss_deobfuscated": len(floss["decoded"])}


def dossiers_to_findings(dossiers):
    """Common-schema findings from recovered IOCs. C2/exfil/crypto/creds each map to a high-signal
    type the adjudicator + IOCs.json + report already understand. Never suppresses."""
    out = []
    for d in dossiers:
        where = f"PID {d['pid']} ({d['process']})" if d["pid"] else d["region_file"]
        i = d["iocs"]
        for ip in i["ips"]:
            out.append(_finding("High", "C2 Endpoint (memory)", ip,
                                f"C2 IP {ip} recovered from {where} memory region {d['base_address']}.",
                                "T1071 (Application Layer Protocol)"))
        for dom in i["domains"]:
            out.append(_finding("High", "C2 Endpoint (memory)", dom,
                                f"C2 domain {dom} recovered from {where}.", "T1071"))
        for onion in i["onion"]:
            out.append(_finding("High", "Tor C2 (memory)", onion,
                                f"Tor hidden-service {onion} recovered from {where}.",
                                "T1090.003 (Multi-hop Proxy: Tor)"))
        for mc in i["miner_configs"]:
            out.append(_finding("High", "Cryptominer C2 (memory)", _host_of(mc) or mc[:60],
                                f"Miner config recovered from {where}: {mc[:160]}",
                                "T1496 (Resource Hijacking)"))
        for w in i["wallets"]:
            out.append(_finding("Medium", "Cryptominer Wallet (memory)", w,
                                f"Crypto wallet {w} recovered from {where}.", "T1496"))
        for t in i["telegram_tokens"]:
            out.append(_finding("High", "Exfiltration Channel (memory)", "Telegram bot",
                                f"Telegram bot token recovered from {where}: {t[:14]}…",
                                "T1567 (Exfiltration Over Web Service)"))
        for w in i["discord_webhooks"]:
            out.append(_finding("High", "Exfiltration Channel (memory)", "Discord webhook",
                                f"Discord webhook recovered from {where}.", "T1567"))
        for k in i["aws_keys"]:
            out.append(_finding("High", "Cloud Credential in Memory", k,
                                f"AWS access key {k} recovered from {where}.",
                                "T1552 (Unsecured Credentials)"))
        if i["private_keys"]:
            out.append(_finding("Medium", "Private Key Material (memory)", where,
                                f"{i['private_keys']} private-key block(s) recovered from {where}.",
                                "T1552.004 (Private Keys)"))
        # capa: one summary finding per region (capabilities + ATT&CK) — context for the YARA hit,
        # not a per-capability flood.
        capa = d.get("capa") or {}
        if capa.get("capabilities"):
            mitre = ", ".join(capa["attack"][:8]) or "T1059"
            out.append(_finding("Medium", "Memory Capabilities (capa)", where,
                                f"capa identified {len(capa['capabilities'])} capability(ies) in "
                                f"{where}: {', '.join(capa['capabilities'][:10])}.", mitre))
    return out


def _notable(d):
    """Keep a region's dossier if it carries IOCs OR capa capabilities (capa flags behaviour even
    when no network IOC is present, e.g. anti-analysis / injection / encryption)."""
    return has_iocs(d["iocs"]) or bool((d.get("capa") or {}).get("capabilities"))


def enrich(carve_dir, out_dir, stamp, quiet=False):
    """Scan every carved region in carve_dir -> dossiers + findings + Memory_Enrichment_<stamp>.{json,md}.
    Returns (findings, dossiers_with_iocs)."""
    bins = sorted(glob.glob(os.path.join(carve_dir, "**", "*.bin"), recursive=True))
    dossiers = []
    for b in bins:
        d = enrich_region(b)
        if d and _notable(d):
            dossiers.append(d)
    findings = dossiers_to_findings(dossiers)

    # rolled-up IOC bundle (de-duplicated across regions)
    roll = {k: sorted({v for d in dossiers for v in d["iocs"][k]})
            for k in ("ips", "domains", "urls", "onion", "xmr", "aws_keys",
                      "telegram_tokens", "discord_webhooks", "wallets")}
    roll["private_keys"] = sum(d["iocs"]["private_keys"] for d in dossiers)
    doc = {"stamp": stamp, "carve_dir": carve_dir, "regions_scanned": len(bins),
           "regions_with_iocs": len(dossiers), "ioc_bundle": roll, "dossiers": dossiers}
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, f"Memory_Enrichment_{stamp}.json"), "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        with open(os.path.join(out_dir, f"Memory_Enrichment_{stamp}.md"), "w", encoding="utf-8") as fh:
            fh.write(_render_md(doc))
    if not quiet:
        print(f"[enrich] {len(bins)} region(s) scanned, {len(dossiers)} with IOC(s) -> "
              f"{len(findings)} finding(s)", file=sys.stderr)
    return findings, dossiers


def _render_md(doc):
    L = [f"# Memory IOC Enrichment — {doc['stamp']}", "",
         f"Scanned **{doc['regions_scanned']}** carved region(s); "
         f"**{doc['regions_with_iocs']}** held adversary IOCs. IOCs are **defanged** below; the "
         f"machine-readable list is in `Memory_Enrichment_{doc['stamp']}.json` / `IOCs.json`.", ""]
    b = doc["ioc_bundle"]
    for label, key in (("C2 IPs", "ips"), ("C2 domains", "domains"), ("URLs", "urls"),
                       ("Tor .onion", "onion"), ("Monero addresses", "xmr"),
                       ("Miner wallets", "wallets"), ("AWS keys", "aws_keys"),
                       ("Telegram tokens", "telegram_tokens"), ("Discord webhooks", "discord_webhooks")):
        if b.get(key):
            L.append(f"- **{label}:** " + ", ".join(f"`{defang(x)}`" for x in b[key]))
    if b.get("private_keys"):
        L.append(f"- **Private-key blocks:** {b['private_keys']}")
    L += ["", "## Per-region attribution", "",
          "| Region | PID (process) | region/perms | rules | IOCs |", "|---|---|---|---|---|"]
    for d in doc["dossiers"]:
        i = d["iocs"]
        n = (len(i["ips"]) + len(i["domains"]) + len(i["urls"]) + len(i["onion"]) +
             len(i["wallets"]) + len(i["aws_keys"]) + len(i["telegram_tokens"]) +
             len(i["discord_webhooks"]) + i["private_keys"])
        L.append(f"| `{d['region_file']}` | {d['pid']} ({d['process']}) | "
                 f"{d['region']}/{d['perms']} | {', '.join(d['matched_rules'][:2])} | {n} |")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Linux memory IOC enrichment (scan strings in carved regions)")
    ap.add_argument("--carve-dir", help="dir of carved *.bin regions (tools/binja/data/<incident>)")
    ap.add_argument("--out-dir", help="write Memory_Enrichment + merge findings here (report folder)")
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--region", help="scan ONE region file and print its IOCs (no write)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.region:
        d = enrich_region(args.region)
        print(json.dumps(d["iocs"] if d else {}, indent=2))
        return 0
    if not args.carve_dir:
        ap.error("--carve-dir or --region required")
    findings, _ = enrich(args.carve_dir, args.out_dir, args.stamp, quiet=args.quiet)
    if args.out_dir and findings:
        # merge into a Memory_Findings file so it flows into Combined_Findings -> adjudication -> reports
        path = os.path.join(args.out_dir, f"Memory_Findings_enrich_{args.stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        if not args.quiet:
            print(f"[enrich] {len(findings)} finding(s) -> {os.path.basename(path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
