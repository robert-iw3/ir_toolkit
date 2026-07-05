"""
Phase 1 retrospective gap fixes — memory_enrich.py unit tests.

Phase 1C — IOC allowlist filter in merge_into_iocs:
  - _is_benign_domain() helper correctly classifies known-good infrastructure
  - merge_into_iocs() does NOT promote benign domains to c2_endpoints
  - merge_into_iocs() DOES promote confirmed adversary IOCs
  - Mixed input: only adversary IOCs make it through
  - Re-run idempotency: benign domains already in c2_endpoints from a previous
    (unfixed) run are removed on the next merge pass
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "playbooks", "windows", "threat_hunting"))
import memory_enrich as me


# ---------------------------------------------------------------------------
# _is_benign_domain — classification helper
# ---------------------------------------------------------------------------

def test_is_benign_adobe_domains():
    for d in ("www.adobe.com", "aepxlg.adobe.com", "oobe.adobe.com",
              "lcs-robs.adobe.io", "api2.acrobat.com", "assets.adobedtm.com",
              "delegated.adobelogin.com", "comments.adobe.io"):
        assert me._is_benign_domain(d), f"Adobe domain wrongly flagged as adversary: {d}"


def test_is_benign_cert_ocsp_crl():
    for d in ("ocsp.digicert.com", "ocsp.entrust.net", "ocsp.verisign.com",
              "crl.disa.mil", "ocsp.disa.mil", "ocsp.eca.hinet.net",
              "eca.hinet.net"):
        assert me._is_benign_domain(d), f"Cert authority domain wrongly flagged: {d}"


def test_is_benign_microsoft_infra():
    for d in ("update.microsoft.com", "ocsp.msocsp.com", "schemas.openxmlformats.org",
              "www.youtube.com", "d.docs.live.net"):
        assert me._is_benign_domain(d), f"Microsoft/Google infra wrongly flagged: {d}"


def test_is_benign_standards_bodies():
    for d in ("ns.adobe.com", "iptc.org", "purl.org", "gitforwindows.org"):
        assert me._is_benign_domain(d), f"Standards/tools domain wrongly flagged: {d}"


def test_is_not_benign_adversary_domains():
    for d in ("evil-c2.ru", "badactor.top", "gate.malware.xyz",
              "beacon.attacker.net", "xcnpool.1gh.com", "fhu77e.co"):
        assert not me._is_benign_domain(d), f"Adversary domain wrongly cleared: {d}"


def test_is_not_benign_dga_looking():
    for d in ("a4f7bx.biz", "jkq9z.info", "randomjunk.click"):
        assert not me._is_benign_domain(d), f"DGA-like domain wrongly cleared: {d}"


# ---------------------------------------------------------------------------
# merge_into_iocs — integration with IOCs.json
# ---------------------------------------------------------------------------

def _make_iocs_file(path, existing_endpoints=None):
    iocs = {
        "incident_id": "TEST",
        "hostname": "TEST-HOST",
        "generated_utc": "2026-06-28T00:00:00Z",
        "c2_endpoints": existing_endpoints or [],
        "file_hashes_sha256": [],
        "remote_access_tools": [],
        "attack_techniques": [],
    }
    with open(path, "w") as f:
        json.dump(iocs, f)


def _make_bundle(c2_ips=None, c2_domains=None):
    return {
        "eradication_iocs": {
            "c2_ips":   c2_ips    or [],
            "c2_domains": c2_domains or [],
            "files_to_remove": [],
            "registry_keys_to_remove": [],
            "mutexes": [],
            "implicated_pids": [],
            "private_key_blocks": 0,
            "c2_urls": [],
        }
    }


def test_merge_benign_domains_not_promoted():
    """Benign Adobe/cert domains must NOT appear in c2_endpoints after merge."""
    benign = [
        "www.adobe.com", "oobe.adobe.com", "ocsp.digicert.com",
        "crl.disa.mil", "iptc.org", "www.youtube.com",
    ]
    with tempfile.TemporaryDirectory() as d:
        iocs_path = os.path.join(d, "IOCs.json")
        _make_iocs_file(iocs_path)
        bundle = _make_bundle(c2_domains=benign)
        me.merge_into_iocs(d, bundle)
        with open(iocs_path) as f:
            result = json.load(f)
        hosts = [e["host"] for e in result["c2_endpoints"]]
        for bad in benign:
            assert bad not in hosts, (
                f"Benign domain '{bad}' was promoted to c2_endpoints — "
                "allowlist filter not applied in merge_into_iocs"
            )


def test_merge_adversary_domain_is_promoted():
    """A confirmed adversary domain must still reach c2_endpoints."""
    with tempfile.TemporaryDirectory() as d:
        iocs_path = os.path.join(d, "IOCs.json")
        _make_iocs_file(iocs_path)
        bundle = _make_bundle(c2_domains=["evil-c2.ru"])
        me.merge_into_iocs(d, bundle)
        with open(iocs_path) as f:
            result = json.load(f)
        hosts = [e["host"] for e in result["c2_endpoints"]]
        assert "evil-c2.ru" in hosts, (
            "Adversary domain 'evil-c2.ru' was filtered out — "
            "allowlist must not block real IOCs"
        )


def test_merge_adversary_ip_is_promoted():
    """Adversary IPs (non-private) must still reach c2_endpoints."""
    with tempfile.TemporaryDirectory() as d:
        iocs_path = os.path.join(d, "IOCs.json")
        _make_iocs_file(iocs_path)
        bundle = _make_bundle(c2_ips=["198.51.100.44"])
        me.merge_into_iocs(d, bundle)
        with open(iocs_path) as f:
            result = json.load(f)
        hosts = [e["host"] for e in result["c2_endpoints"]]
        assert "198.51.100.44" in hosts, "Adversary IP not promoted to c2_endpoints"


def test_merge_mixed_input_only_adversary_passes():
    """With both benign and adversary IOCs in the bundle, only adversary ones
    must appear in c2_endpoints."""
    benign = ["www.adobe.com", "ocsp.digicert.com", "www.youtube.com"]
    adversary_d = "evil-c2.ru"
    adversary_ip = "198.51.100.44"
    with tempfile.TemporaryDirectory() as d:
        iocs_path = os.path.join(d, "IOCs.json")
        _make_iocs_file(iocs_path)
        bundle = _make_bundle(
            c2_ips=[adversary_ip],
            c2_domains=benign + [adversary_d],
        )
        me.merge_into_iocs(d, bundle)
        with open(iocs_path) as f:
            result = json.load(f)
        hosts = [e["host"] for e in result["c2_endpoints"]]
        assert adversary_d in hosts, "Adversary domain missing from c2_endpoints"
        assert adversary_ip in hosts, "Adversary IP missing from c2_endpoints"
        for b in benign:
            assert b not in hosts, f"Benign domain '{b}' leaked into c2_endpoints"


def test_merge_rerun_removes_previously_promoted_benign():
    """If a previous (unfixed) run already placed benign domains in c2_endpoints,
    a re-run with the fixed merge_into_iocs must clean them out."""
    pre_contamination = [
        {"host": "www.adobe.com", "port": 0, "sanctioned": False,
         "session_id": None, "instance_id": None, "source": "memory", "country": None},
        {"host": "evil-c2.ru",    "port": 0, "sanctioned": False,
         "session_id": None, "instance_id": None, "source": "memory", "country": None},
    ]
    with tempfile.TemporaryDirectory() as d:
        iocs_path = os.path.join(d, "IOCs.json")
        _make_iocs_file(iocs_path, existing_endpoints=pre_contamination)
        # re-run merge with the same (now correctly filtered) bundle
        bundle = _make_bundle(c2_domains=["www.adobe.com", "evil-c2.ru"])
        me.merge_into_iocs(d, bundle)
        with open(iocs_path) as f:
            result = json.load(f)
        hosts = [e["host"] for e in result["c2_endpoints"]]
        assert "www.adobe.com" not in hosts, (
            "www.adobe.com still in c2_endpoints after re-run — "
            "merge_into_iocs must evict previously-promoted benign domains"
        )
        assert "evil-c2.ru" in hosts, "evil-c2.ru must remain after re-run"


def test_merge_extraction_artifacts_not_promoted():
    """Malformed extraction artifacts ('***', truncated fragments, empty strings) must
    NOT appear in c2_endpoints even though they are not benign infrastructure.
    Discovered via live validation: netscan occasionally emits '***' for
    redacted/null connection records."""
    artifacts = ["***", "", "ch", "crl.", "http", "xx"]
    with tempfile.TemporaryDirectory() as d:
        iocs_path = os.path.join(d, "IOCs.json")
        _make_iocs_file(iocs_path)
        bundle = _make_bundle(c2_ips=artifacts)
        me.merge_into_iocs(d, bundle)
        with open(iocs_path) as f:
            result = json.load(f)
        hosts = [e["host"] for e in result["c2_endpoints"]]
        for art in artifacts:
            assert art not in hosts, (
                f"Extraction artifact '{art}' was promoted to c2_endpoints — "
                "_is_valid_ioc_host must filter malformed extraction results"
            )


def test_merge_idempotent_adversary_not_duplicated():
    """Running merge twice with the same adversary domain must not duplicate it
    in c2_endpoints."""
    with tempfile.TemporaryDirectory() as d:
        iocs_path = os.path.join(d, "IOCs.json")
        _make_iocs_file(iocs_path)
        bundle = _make_bundle(c2_domains=["evil-c2.ru"])
        me.merge_into_iocs(d, bundle)
        me.merge_into_iocs(d, bundle)  # second run
        with open(iocs_path) as f:
            result = json.load(f)
        hosts = [e["host"] for e in result["c2_endpoints"]]
        assert hosts.count("evil-c2.ru") == 1, (
            f"'evil-c2.ru' appears {hosts.count('evil-c2.ru')} times — "
            "merge must be idempotent"
        )


# ---------------------------------------------------------------------------
# Phase 1D — own-module-namespace domain filter + mwcp hex-junk mutex filter
#
# Discovered via live validation on a fresh host (FLUSH): a legitimate .NET
# MSIX app's memory yielded 'system.io', 'system.net', 'microsoft.windows.sdk.net'
# as structurally-valid-looking "domains" (real TLD, valid RFC-1035 labels) --
# purely because .NET namespace strings coincidentally share domain syntax.
# Shape alone can't distinguish these from real domains; cross-referencing
# against the process's OWN loaded module list (ground truth already collected
# for that exact process) can. Separately, mwcp's mutex parser over the same
# process's memory returned 'fffffff', '0123456789abcdef', '110101' tagged
# "CONFIRMED malware-created" -- the existing _HEX_TOKEN shape check already
# used to gate handle-based mutex classification was never applied to mwcp's
# own results, which bypassed that gate on the assumption family-specific
# parsing is always reliable. It is not.
# ---------------------------------------------------------------------------

def test_module_namespace_basenames_strips_path_and_extension():
    mod_ranges = [
        (0x1000, 0x2000, r"C:\Program Files\WindowsApps\Foo\System.Runtime.dll"),
        (0x2000, 0x3000, r"C:\Program Files\WindowsApps\Foo\Newtonsoft.Json.dll"),
        (0x3000, 0x4000, ""),  # missing fullname must not crash
    ]
    names = me._module_namespace_basenames(mod_ranges)
    assert "system.runtime" in names
    assert "newtonsoft.json" in names


def test_own_module_namespace_exact_match():
    basenames = {"system.runtime", "newtonsoft.json"}
    assert me._is_own_module_namespace("system.runtime", basenames)
    assert me._is_own_module_namespace("System.Runtime", basenames)  # case-insensitive


def test_own_module_namespace_prefix_match():
    """Domain scraping can stop early at a coincidental TLD-shaped segment --
    'system.io' inside 'System.IO.Abstractions.Wrappers.dll' -- so a prefix
    match against the fuller module name must also be caught."""
    basenames = {"testableio.system.io.abstractions.wrappers"}
    assert me._is_own_module_namespace("testableio.system.io", basenames)


def test_own_module_namespace_rejects_real_external_domain():
    """A real external domain that happens to share no relation to any loaded
    module must NOT be filtered -- this is not a blanket 'looks like a namespace'
    heuristic, it is a direct match against this process's own modules only."""
    basenames = {"system.runtime", "newtonsoft.json", "microsoft.winui"}
    assert not me._is_own_module_namespace("evil-c2-panel.example.net", basenames)
    assert not me._is_own_module_namespace("easyauth.edgebrowser.microsoft-falcon.io", basenames)


def test_own_module_namespace_empty_basenames_never_matches():
    assert not me._is_own_module_namespace("system.io", set())
    assert not me._is_own_module_namespace("", {"system.io"})


def test_hex_token_matches_confirmed_live_junk_mutexes():
    """The exact strings mwcp reported as 'CONFIRMED malware-created' on a live
    host with zero other corroboration -- all must match the existing hex-shape
    gate that was bypassed for mwcp results specifically."""
    for junk in ("fffffff", "ffffff", "0123456789abcdef", "110101", "Cd7C41a"):
        assert me._HEX_TOKEN.match(junk), (
            f"{junk!r} must match the hex-junk shape -- this is the exact string "
            "recovered live and wrongly tagged CONFIRMED"
        )


def test_hex_token_does_not_match_plausible_real_mutex():
    for name in ("Global\\WmiSync_7d3f", "MyAppSingleInstanceMutex", "WilStaging_02"):
        assert not me._HEX_TOKEN.match(name), \
            f"A plausible real mutex name {name!r} must not be caught by the hex-junk gate"
