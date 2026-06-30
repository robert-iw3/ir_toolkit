"""Section 36 - memory enrichment (eradication scope): pure helpers that classify a true
positive's memory footprint and roll it up into eradication IOCs. No vmm dependency."""
import json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "playbooks", "windows", "threat_hunting"))
import memory_enrich as me


# -- injected-region detection (Private/Pf + exec, NOT Image/File-backed) -------
def test_region_injected_private_exec():
    # real-world capture shape: Private VADs have a BLANK type, exec shows as 'p-rwx-'
    assert me.region_is_injected("     ", "p-rwx-") is True
    assert me.region_is_injected("Pf   ", "p-rwx-") is True


def test_region_not_injected_when_image_backed_or_non_exec():
    assert me.region_is_injected("Image", "---wxc") is False   # backed code, not injected
    assert me.region_is_injected("     ", "p-rw--") is False    # private but not executable
    assert me.region_is_injected("File ", "--r---") is False


# -- handle classification ------------------------------------------------------
def test_classify_registry_strips_hive_prefix():
    cat, name, _ = me.classify_handle(
        "Key", "[ffff8d07d2be3000:02e18840] SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options")
    assert cat == "registry"
    assert name.startswith("SOFTWARE")          # the [hive:offset] prefix is stripped


def test_classify_registry_ifeo_root_not_flagged_specific_image_is():
    # the IFEO ROOT handle is opened by every process's loader -> NOT persistence
    _, _, root = me.classify_handle("Key", "[h:o] SOFTWARE\\...\\CurrentVersion\\Image File Execution Options")
    assert root is False
    # a SPECIFIC image's IFEO entry (the Debugger-hijack vector) IS flagged
    _, _, img = me.classify_handle("Key", "[h:o] SOFTWARE\\...\\Image File Execution Options\\target.exe")
    assert img is True


def test_classify_registry_run_key_yes_service_config_no():
    # classic autostart Run key -> persistence
    _, _, run_susp = me.classify_handle("Key", "[h:o] SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
    assert run_susp is True
    # a service host's normal config handles must NOT flood the eradication list (the FP we fixed)
    for legit in ("SYSTEM\\ControlSet001\\Services\\SharedAccess\\Epoch",
                  "SYSTEM\\ControlSet001\\Services\\mpssvc\\Parameters\\AppCs",
                  "SYSTEM\\ControlSet001\\Services\\WinSock2\\Parameters\\Protocol_Catalog9",
                  "SYSTEM\\ControlSet001\\Control\\Nls\\Sorting"):
        assert me.classify_handle("Key", "[h:o] " + legit)[2] is False
    # but a service pointing at a binary (ImagePath/ServiceDll) IS persistence
    assert me.classify_handle("Key", "[h:o] SYSTEM\\...\\Services\\evilsvc\\ImagePath")[2] is True


def test_classify_mutex_implant_lock_vs_normal():
    # bare high-entropy token = implant lock candidate
    assert me.classify_handle("Mutant", "1BA6BD98D9") == ("mutex", "1BA6BD98D9", True)
    # WilStaging: state-sponsored APT groups use SM0:*:WilStaging_* as a Windows camouflage
    # technique. Should be suspicious: True regardless of which PID holds it.
    assert me.classify_handle("Mutant", "SM0:13680:304:WilStaging_02")[2] is True
    assert me.classify_handle("Mutant", "SM0:740:304:WilStaging_02")[2] is True
    # WilError: documented WIL error-tracking mutex, NOT an APT signal -> not suspicious
    assert me.classify_handle("Mutant", "SM0:1204:120:WilError_03")[2] is False
    # SmartScreen*: Windows security component sync object -> not suspicious
    assert me.classify_handle("Mutant", "SmartScreenLocalDatadownloadCache66cac7fd6401c1bb0e14283fe7cadb7e")[2] is False
    # Plain Windows utility names
    assert me.classify_handle("Mutant", "DBWinMutex")[2] is False


def test_classify_file_temp_drop_flagged():
    # a normal system DLL path is not a drop; a Temp/Public path is
    cat, name, susp = me.classify_handle("File", "\\HarddiskVolume3\\Windows\\System32\\kernel32.dll")
    assert cat == "file" and susp is False
    assert me.classify_handle("File", "\\HarddiskVolume3\\Windows\\Temp\\x.dll")[2] is True
    assert me.classify_handle("File", "\\HarddiskVolume3\\Users\\Public\\evil.exe")[2] is True


# -- C2 IOC recovery from carved bytes -----------------------------------------
def test_extract_c2_iocs_ascii():
    # IPs come from a URL host (bare-number scraping is OFF — it collides with crypto OIDs)
    out = me.extract_c2_iocs(b"config: http://203.0.113.9:8080/gate evil-c2.top https://bad.example/x")
    assert "203.0.113.9" in out["ips"]
    assert "evil-c2.top" in out["domains"]
    assert any("bad.example" in u for u in out["urls"])


def test_extract_c2_iocs_no_bare_ip_scrape():
    # crypto OIDs / version numbers look like IPs — bare numbers must NOT be captured as IPs
    out = me.extract_c2_iocs(b"oid 2.5.4.3 sha 1.3.14.3.2.26 version 5.1.0.0")
    assert out["ips"] == []


def test_extract_c2_iocs_wide_char():
    # RedLeaves-style wide-char config string must be recovered (UTF-16LE)
    out = me.extract_c2_iocs("portal.evil-c2.club".encode("utf-16-le"))
    assert any("evil-c2.club" in d for d in out["domains"])


def test_valid_host_structural_tld_gate():
    # real, resolvable-looking domains pass (2-letter ccTLD or known gTLD)
    for good in ("flashupd.com", "fhu77e.co", "1drv.ms", "xcnpool.1gh.com",
                 "pyairunner-dev.azurewebsites.net", "en.aa.com"):
        assert me._valid_host(good), good
    # regex over-capture noise is rejected WITHOUT resolving anything:
    for bad in ("kipesoftin", "mtsvc9", "micr",            # no TLD at all
                "office.netx", "uol.conhecaa", "wmd9e.a3i1",  # bogus TLD
                "mysafesavings.commicrosoft", "ithink."):     # concatenation / truncation
        assert not me._valid_host(bad), bad


def test_overcapture_recovered_at_boundary_and_unverified_kept():
    # mirrors a real-world capture: a clean dropper URL + adjacent run-on/over-captured hosts. Nothing is
    # dropped: a TLD-then-uppercase concatenation is RECOVERED at the boundary; an unrecognised/no-TLD
    # host is KEPT under `unverified` (labelled "not resolvable - verify"), never asserted as a domain.
    blob = (b"http://fhu77e.co/get http://evil-drop.comMicrosoft https://badpanel.netX "
            b"https://micr http://staging.zip flashupd.com")
    out = me.extract_c2_iocs(blob)
    assert "fhu77e.co" in out["domains"] and "flashupd.com" in out["domains"]   # real domains kept
    assert "evil-drop.com" in out["domains"]                                    # recovered from comMicrosoft
    assert "badpanel.net" in out["domains"]                                     # recovered from netX
    assert not any("microsoft" in d or "netx" in d for d in out["domains"])     # the run-on tail is gone
    assert "micr" in out["unverified"]                # no-TLD fragment: kept + labelled, not an IOC
    assert "staging.zip" in out["unverified"]         # real but uncommon TLD: kept, not silently dropped
    assert "micr" not in out["domains"] and "staging.zip" not in out["domains"]
    assert all(me._valid_host(d) for d in out["domains"])                       # every domain is real-looking


def test_offline_geo_lookup():
    # inject a tiny fixture so the test is deterministic and DB-independent (no network either)
    orig = dict(me._GEO)
    try:
        me._GEO.update(loaded=True,
            starts=[me._ip_to_int("1.0.0.0"), me._ip_to_int("78.140.220.0"), me._ip_to_int("94.23.0.0")],
            ends=[me._ip_to_int("1.255.255.255"), me._ip_to_int("78.140.220.255"), me._ip_to_int("94.23.255.255")],
            ccs=["KR", "RU", "CZ"])
        assert me.country_of_ip("1.234.66.143") == "KR"
        assert me.country_of_ip("78.140.220.175") == "RU"
        assert me.country_of_ip("94.23.172.164") == "CZ"
        assert me.country_of_ip("8.8.8.8") is None          # outside the fixture ranges
        assert me.country_of_ip("not.an.ip") is None
        assert me.geo_label("1.234.66.143") == "KR (South Korea)"
    finally:
        me._GEO.clear(); me._GEO.update(orig)               # restore (don't poison real lookups)


def test_host_with_digit_label_not_mistrimmed():
    # a legit host whose label has digits after a short ccTLD-looking part must NOT be cut: the
    # boundary trim keys on a following UPPERCASE letter only, never on digits (ip.aq138.com stays whole)
    out = me.extract_c2_iocs(b"beacon http://ip.aq138.com/get and http://xcnpool.1gh.com/x")
    assert "ip.aq138.com" in out["domains"]            # NOT mis-trimmed to ip.aq
    assert "ip.aq" not in out["domains"]
    assert "xcnpool.1gh.com" in out["domains"]


def test_extract_c2_iocs_drops_benign_noise():
    blob = b"127.0.0.1 10.0.0.5 update.microsoft.com 192.168.1.1 windowsupdate.com"
    out = me.extract_c2_iocs(blob)
    assert out["ips"] == []                       # loopback/private dropped
    assert out["domains"] == []                   # MS/OS domains dropped


def test_extract_c2_iocs_captures_stratum_pool():
    # mining pool C2 is a real C2 endpoint — the scheme + host must be recovered
    out = me.extract_c2_iocs(b"stratum+tcp://xcnpool.1gh.com:7333 -u WALLET.worker -p x")
    assert any("xcnpool.1gh.com" in u for u in out["urls"])     # stratum URL
    assert "xcnpool.1gh.com" in out["domains"]                  # and the bare domain


# -- full threat-IOC sweep (beyond C2) -----------------------------------------
def test_extract_threat_iocs_miner_and_exfil_and_creds():
    blob = (b"stratum+tcp://xcnpool.1gh.com:7333 -u CJJkVzjx8GNtX4z395bDY4GFWL6Ehdf8kJ -p x\n"
            b"exfil via https://canary.discord.com/api/webhooks/123456789/"
            b"abcdefghijklmnopqrstuvwxyz012345\n"
            b"bottoken 123456789:AAEhBOweik6ad9r_QXLxj0jXImnv6jJ7abc\n"
            b"AKIAIOSFODNN7EXAMPLE\n"
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"http://abcdefghij234567.onion/panel")
    out = me.extract_threat_iocs(blob)
    assert any("xcnpool.1gh.com" in m for m in out["miner_configs"])
    assert "xcnpool.1gh.com" in out["domains"]              # pool host derived from the stratum URL
    assert "CJJkVzjx8GNtX4z395bDY4GFWL6Ehdf8kJ" in out["wallets"]   # -u wallet pulled from the config
    assert out["discord_webhooks"] and out["telegram_tokens"]
    assert "AKIAIOSFODNN7EXAMPLE" in out["aws_keys"]
    assert out["private_keys"] == 1
    assert any(".onion" in o for o in out["onion"])
    assert "emails" not in out                              # victim PII is NOT collected


def test_extract_config_artifacts_bot_dna():
    blob = (b"GET /bad.php?w=%u&i=%s HTTP/1.0\r\n"
            b"user-agent: opera/6 (windows nt %u.%u; u; langid=%x)\r\n"
            b"up?bid=%08x&os=%d&uptime=%d&rnd=%d\r\n"
            b"autorun.inf  attrib -s -h %cd%\\x & xcopy /f /s")
    arts = dict(me.extract_config_artifacts(blob))
    assert any("bad.php?w=%u" in v for v in arts.values())          # beacon URI template
    assert any("opera/6" in v for v in arts.values())               # custom user-agent
    assert any("bid=" in v for v in arts.values())                  # bot params
    assert "self_spread" in arts                                    # USB-worm markers


def test_extract_config_artifacts_quiet_on_benign():
    assert me.extract_config_artifacts(b"normal text, no beacon, no autorun here") == set()


def test_defang_makes_iocs_inert():
    assert me.defang("http://flashupd.com/mp3/in") == "hxxp[:]//flashupd[.]com/mp3/in"
    assert me.defang("78.140.220.175") == "78[.]140[.]220[.]175"
    assert "[.]" in me.defang("ip.aq138.com")


def test_extract_threat_iocs_quiet_on_benign():
    out = me.extract_threat_iocs(b"normal program text, kernel32.dll, C:/Windows/System32")
    assert all(out[k] == [] for k in ("miner_configs", "onion", "xmr", "aws_keys",
                                      "telegram_tokens", "discord_webhooks"))
    assert out["private_keys"] == 0


# -- rollup into an eradication bundle ------------------------------------------
def test_rollup_iocs_aggregates_footprint():
    dossiers = [{
        "pid": 13680,
        "handles": [
            {"category": "registry", "name": "SOFTWARE\\...\\Image File Execution Options", "suspicious": True},
            {"category": "mutex", "name": "1BA6BD98D9", "suspicious": True},
            {"category": "file", "name": "\\Windows\\Temp\\x.dll", "suspicious": True},
            {"category": "registry", "name": "SYSTEM\\...\\Nls", "suspicious": False},
        ],
        "lineage": {"parent": {"pid": 1204, "name": "svchost.exe"}, "children": [{"pid": 9000, "name": "cmd.exe"}]},
        "network": [{"dst_ip": "203.0.113.9"}],
        "threat_iocs": {"ips": ["198.51.100.7"], "domains": ["evil.top"], "urls": [],
                        "xmr": ["48aaaa"], "miner_configs": ["stratum+tcp://pool.bad:7333 -u w"],
                        "emails": [], "onion": [], "aws_keys": [], "telegram_tokens": [],
                        "discord_webhooks": [], "private_keys": 2},
    }]
    b = me.rollup_iocs(dossiers)
    assert b["registry_keys_to_remove"] == ["SOFTWARE\\...\\Image File Execution Options"]
    assert b["mutexes"] == ["1BA6BD98D9"]
    assert "\\Windows\\Temp\\x.dll" in b["files_to_remove"]
    assert "203.0.113.9" in b["c2_ips"] and "198.51.100.7" in b["c2_ips"]
    assert "evil.top" in b["c2_domains"]
    assert b["xmr"] == ["48aaaa"] and b["miner_configs"][0].startswith("stratum")
    assert b["private_key_blocks"] == 2
    # parent + child + self are all implicated for eradication
    assert set(b["implicated_pids"]) == {1204, 9000, 13680}


def test_merge_into_iocs_feeds_eradication(tmp_path):
    """Recovered C2 folds into c2_endpoints (so the firewall keeps it blocked) and the
    files/keys/mutexes land in a memory_eradication block. Eradication is gated elsewhere."""
    iocs = {"incident_id": "T", "hostname": "H", "c2_endpoints": [
        {"host": "relay.sanctioned.test", "port": 443, "sanctioned": True}]}
    (tmp_path / "IOCs.json").write_text(json.dumps(iocs))
    bundle = {"eradication_iocs": {
        "files_to_remove": ["\\Windows\\Temp\\x.dll"], "registry_keys_to_remove": [],
        "mutexes": ["1BA6BD98D9"], "c2_ips": ["203.0.113.9"], "c2_domains": ["evil.top"],
        "c2_urls": [], "implicated_pids": [1204, 13680]}}
    out = me.merge_into_iocs(str(tmp_path), bundle)
    assert out is not None
    merged = json.load(open(tmp_path / "IOCs.json", encoding="utf-8-sig"))
    hosts = {c["host"] for c in merged["c2_endpoints"]}
    assert "203.0.113.9" in hosts and "evil.top" in hosts        # memory C2 now blockable
    assert "relay.sanctioned.test" in hosts                       # existing entry preserved
    assert merged["memory_eradication"]["mutexes"] == ["1BA6BD98D9"]
    assert "\\Windows\\Temp\\x.dll" in merged["memory_eradication"]["files_to_remove"]


def test_merge_into_iocs_no_file_is_safe(tmp_path):
    assert me.merge_into_iocs(str(tmp_path), {"eradication_iocs": {}}) is None


# -- detailed attack-chain mermaid ----------------------------------------------
def _chain_bundle():
    return {"dossiers": [{
        "pid": 13680, "name": "ShellExperienceHost.exe", "rules": ["REDLEAVES_CoreImplant", "LOLBin_BITS_Drop"],
        "handles": [
            {"category": "file", "name": "\\Windows\\Temp\\x.dll", "suspicious": True},
            {"category": "registry", "name": "...\\IFEO\\target.exe", "suspicious": True},
            {"category": "mutex", "name": "1BA6BD98D9", "suspicious": True},
            {"category": "file", "name": "\\Windows\\System32\\ok.dll", "suspicious": False},
        ],
        "injected_regions": [{"start": "0x1f0000", "protection": "p-rwx-", "carved_to": "_region_13680_1f0000.bin"}],
        "network": [{"dst_ip": "203.0.113.9", "dst_port": 443}],
        "c2": {"ips": [], "domains": ["evil.top"], "urls": []},
        "lineage": {"parent": {"pid": 1204, "name": "svchost.exe"}, "children": [{"pid": 9000, "name": "cmd.exe"}]},
    }], "eradication_iocs": {"c2_domains": ["evil.top"]}}


def test_attack_chain_mermaid_shows_full_chain():
    mm = me.build_attack_chain_mermaid(_chain_bundle())
    assert mm.startswith("```mermaid") and "flowchart TD" in mm
    assert "PID 13680" in mm and "REDLEAVES_CoreImplant" in mm     # implant + rule
    assert "PID 1204" in mm and "parent" in mm                     # lineage up
    assert "cmd.exe" in mm and "spawned" in mm                     # lineage down
    assert "x.dll" in mm and "dropped" in mm                       # affected file (basename, no PII path)
    assert "IFEO/target.exe" in mm and "persistence" in mm        # registry persistence
    assert "1BA6BD98D9" in mm and "lock" in mm                     # mutex
    assert "injected p-rwx-" in mm and "injected code" in mm      # injected region node + edge
    assert "203.0.113.9" in mm and "evil.top" in mm               # C2 (live + recovered)
    assert "ok.dll" not in mm                                      # benign handle not drawn


def test_attack_chain_mermaid_edge_labels_valid():
    """Mermaid edge labels (|...|) must contain no parentheses/pipes/brackets — those break the parser."""
    mm = me.build_attack_chain_mermaid(_chain_bundle())
    import re as _re
    for lbl in _re.findall(r"-->\|([^|]*)\|", mm):
        assert not any(ch in lbl for ch in "()[]{}"), f"bad edge label: {lbl!r}"


# -- decode candidates (for CyberChef) + capa parsing --------------------------
def test_extract_decode_candidates_finds_base64_and_hex():
    import base64
    b64 = base64.b64encode(bytes((i * 37 + 11) & 0xff for i in range(120))).decode()  # high-entropy b64
    hexblob = "deadbeefcafe0011223344556677889900aabbccddee"     # long hex run
    data = (f"junk text here {b64} more {hexblob} tail").encode()
    cands = me.extract_decode_candidates(data)
    kinds = {c["type"] for c in cands}
    assert "base64" in kinds and "hex" in kinds
    assert any(b64[:20] in c["value"] for c in cands)


def test_extract_decode_candidates_skips_plain_text():
    # an English sentence / path is not an encoded blob -> not offered as base64
    data = b"this is just a normal english sentence with several words in it and a path C:/Windows"
    cands = me.extract_decode_candidates(data)
    assert all(c["type"] != "base64" for c in cands)


def test_extract_decode_candidates_skips_guids_and_sids():
    data = (b"090B42FF-7B26-4416-99B6-CB17896CF07C "
            b"df9d8cd0-1501-11d1-8c7a-00c04fc297eb "
            b"98566239-1598046694-2988170848-1001")
    cands = me.extract_decode_candidates(data)
    assert cands == []          # canonical GUIDs + decimal SID runs are benign, not decode targets


def test_extract_decode_candidates_skips_dll_name_runs():
    # concatenated api-ms-win-* / DLL-name runs are NOT encoded blobs (the real-data FP we fixed)
    data = (b"api-ms-win-appmodel-lifecyclepolicy-l1-1-0api-ms-win-core-com-l1-1-1"
            b"dllapi-ms-onecoreuap-print-render-l1-1-0kernel32.dll")
    cands = me.extract_decode_candidates(data)
    assert all(c["type"] != "base64" for c in cands)


def test_parse_capa_json_extracts_capabilities_and_attack():
    sample = json.dumps({"rules": {
        "encrypt data via RC4": {"meta": {"name": "encrypt data via RC4",
                                          "attack": [{"id": "T1573.001", "technique": "Encrypted Channel"}]}},
        "create TCP socket": {"meta": {"name": "create TCP socket", "attack": ["[T1095] Non-App Layer"]}},
    }})
    out = me.parse_capa_json(sample)
    assert "encrypt data via RC4" in out["capabilities"]
    assert "T1573.001" in out["attack"] and "T1095" in out["attack"]


def test_parse_capa_json_bad_input_is_safe():
    assert me.parse_capa_json("not json") == {"capabilities": [], "attack": []}


def test_parse_floss_json_extracts_deobfuscated():
    sample = json.dumps({"strings": {
        "static_strings": [{"string": "kernel32.dll"}, {"string": "x"}],
        "stack_strings": [{"string": "evil-c2.top"}],
        "tight_strings": [{"string": "stratum+tcp://pool.bad:7333"}],
        "decoded_strings": [{"string": "RC4_decoded_config"}]}})
    out = me.parse_floss_json(sample)
    assert out["decoded"] == ["RC4_decoded_config"]
    assert out["stack"] == ["evil-c2.top"] and out["tight"] == ["stratum+tcp://pool.bad:7333"]
    assert out["static_count"] == 2


def test_parse_floss_json_bad_input_is_safe():
    assert me.parse_floss_json("nope") == {"decoded": [], "stack": [], "tight": [], "static_count": 0}


def test_enrichment_md_lists_candidates_and_cyberchef():
    bundle = {"image": "mem.aff4", "generated": "2026-06-24", "true_positive_pids": [13680],
              "dossiers": [{"pid": 13680, "name": "evil.exe",
                            "handles": [{"category": "mutex", "name": "ABC123", "suspicious": True}],
                            "injected_regions": [{"start": "0x1f0000", "protection": "p-rwx-",
                                                  "carved_to": "_region_13680_1f0000.bin",
                                                  "capa": {"capabilities": ["encrypt data via RC4"], "attack": ["T1573.001"]}}],
                            "decode_candidates": [{"type": "base64", "len": 40, "value": "QUJD...", "region": "0x2a0000"}],
                            "lineage": {"parent": None, "children": []}}]}
    md = me.build_enrichment_md(bundle)
    assert "encrypt data via RC4" in md and "T1573.001" in md     # capa surfaced
    assert "CyberChef" in md and "Decode candidates" in md         # instruction present
    assert "QUJD..." in md                                         # the blob to decode is listed


def test_enrichment_md_capa_states():
    """capa message distinguishes not-staged vs ran-but-empty."""
    base = {"image": "m", "generated": "t", "true_positive_pids": [1], "decode_candidates": []}
    not_staged = dict(base, dossiers=[{"pid": 1, "name": "a", "handles": [], "decode_candidates": [],
        "injected_regions": [{"start": "0x1", "protection": "p-rwx-", "carved_to": "r.bin"}], "lineage": {}}])
    assert "not staged" in me.build_enrichment_md(not_staged)
    ran_empty = dict(base, dossiers=[{"pid": 1, "name": "a", "handles": [], "decode_candidates": [],
        "injected_regions": [{"start": "0x1", "protection": "p-rwx-", "carved_to": "r.bin",
                              "capa": {"capabilities": [], "attack": []}}], "lineage": {}}])
    assert "no capabilities matched" in me.build_enrichment_md(ran_empty)


def test_append_attack_chain_idempotent(tmp_path):
    (tmp_path / "Attack_Graph.md").write_text("# Attack Graph\n\noriginal content\n", encoding="utf-8")
    me.append_attack_chain(str(tmp_path), _chain_bundle())
    me.append_attack_chain(str(tmp_path), _chain_bundle())     # second run must not duplicate
    txt = (tmp_path / "Attack_Graph.md").read_text(encoding="utf-8")
    assert "original content" in txt                            # base graph preserved
    assert txt.count(me._CHAIN_START) == 1                     # exactly one chain block
    assert "Memory-derived attack chain" in txt


# -- first-seen time parsing + RAM<->USB correlation ---------------------------
def test_filetime_to_dt_roundtrip():
    import datetime as _dt
    # FILETIME for 2026-06-19 14:32:05 UTC -> back to that instant
    epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
    target = _dt.datetime(2026, 6, 19, 14, 32, 5, tzinfo=_dt.timezone.utc)
    ft = int((target - epoch).total_seconds() * 10_000_000)
    got = me.filetime_to_dt(ft)
    assert got is not None and got.strftime("%Y-%m-%d %H:%M:%S") == "2026-06-19 14:32:05"
    assert me.filetime_to_dt(0) is None and me.filetime_to_dt("x") is None


def test_coerce_dt_handles_every_source_form():
    # .NET /Date(ms)/ from the USB JSON (unix ms UTC)
    assert me.coerce_dt("/Date(1781795528158)/").year == 2026
    # ISO string, locale string, unix-ms int, and FILETIME int all parse to aware UTC
    for v in ("2026-06-19 14:32:05", "2026-06-19T14:32:05Z", "06/19/2026 14:32:05", 1781795528158):
        dt = me.coerce_dt(v)
        assert dt is not None and dt.tzinfo is not None
    assert me.coerce_dt(None) is None and me.coerce_dt("") is None and me.coerce_dt("garbage") is None


def test_earliest_thread_create_is_process_first_seen():
    # main thread (earliest create) defines the process create time, across vmmpyc key variants
    threads = [
        {"tid": 5, "time-create": "2026-06-19 14:40:00"},
        {"tid": 1, "time-create": "2026-06-19 14:32:05"},     # earliest -> the answer
        {"tid": 9, "time-create": None},
    ]
    assert me.earliest_thread_create(threads) == "2026-06-19 14:32:05 UTC"
    assert me.earliest_thread_create([{"tid": 1, "createtime": 0}]) is None   # no usable time
    assert me.earliest_thread_create([]) is None


def test_load_usb_devices_flattens_and_sorts():
    bundle = {"usb_devices": [
        {"Vendor": "SAMSUNG", "Product": "FLASH", "Serial": "S2", "FirstConnect": "/Date(1781795528158)/"},
        {"Vendor": "VENDORC", "Product": "CODE", "Serial": "S1", "FirstConnect": "/Date(1770307252478)/",
         "Suspicion": "placeholder/no-name"},
    ]}
    devs = me.load_usb_devices(bundle)
    assert [d["vendor"] for d in devs] == ["VENDORC", "SAMSUNG"]     # earliest first
    assert all(d["first_connect"] is not None for d in devs)


def test_correlate_first_seen_entry_vector_candidate():
    dossiers = [{"pid": 13680, "name": "evil.exe", "create_time": "2026-06-19 14:32:05 UTC"}]
    # device connected 4h BEFORE the implant first ran -> entry-vector candidate
    usb = [{"vendor": "VENDORC", "product": "CODE", "serial": "S1", "suspicion": "placeholder",
            "first_connect": me.coerce_dt("2026-06-19 10:30:00")}]
    corr = me.correlate_first_seen(dossiers, usb)
    assert corr["ram_first_seen"] == "2026-06-19 14:32:05 UTC" and corr["ram_pid"] == 13680
    d = corr["devices"][0]
    assert "ENTRY-VECTOR CANDIDATE" in d["verdict"] and d["delta_hours"] > 0
    assert "entry vector" in corr["summary"]


def test_implant_anchor_prefers_injected_thread_over_process_create():
    # injected implant inside svchost: process create is host boot; injected-thread is the real start
    inj = {"pid": 3464, "name": "svchost.exe", "create_time": "2026-06-18 19:20:44 UTC",
           "injected_thread_first_seen": "2026-06-19 18:40:00 UTC"}
    dt, basis = me.implant_anchor(inj)
    assert basis == "injected-thread" and dt.strftime("%Y-%m-%d %H:%M") == "2026-06-19 18:40"
    # no injected-thread time -> fall back to process create, flagged lower confidence
    dt2, basis2 = me.implant_anchor({"pid": 1, "name": "a", "create_time": "2026-06-18 19:20:44 UTC"})
    assert basis2 == "process-create"


def test_correlate_uses_injection_time_and_flags_boot_anchor():
    # svchost process-create (06-18) would falsely pre-date the USB; the injected-thread time (06-19)
    # is the real anchor and flips the SAMSUNG verdict to post-infection.
    dossiers = [{"pid": 3464, "name": "svchost.exe", "create_time": "2026-06-18 19:20:44 UTC",
                 "injected_thread_first_seen": "2026-06-19 18:40:00 UTC"}]
    usb = [{"vendor": "SAMSUNG", "product": "FLASH", "serial": "S", "suspicion": "",
            "first_connect": me.coerce_dt("2026-06-18 15:12:08")}]
    corr = me.correlate_first_seen(dossiers, usb)
    assert corr["ram_basis"] == "injected-thread"
    assert corr["ram_first_seen"] == "2026-06-19 18:40:00 UTC"      # injection time, not boot
    # boot anchor (06-18 19:20) would read 4h-before = strong candidate; injection anchor (06-19 18:40)
    # widens the gap to >24h -> only a WEAK match (the anchor choice materially changes the verdict)
    assert "possible (weak)" in corr["devices"][0]["verdict"]
    assert round(corr["devices"][0]["delta_hours"]) == 28


def test_has_injection_evidence_distinguishes_real_implant_from_string_match():
    assert me.has_injection_evidence({"injected_regions": [{"start": "0x1"}]}) is True
    assert me.has_injection_evidence({"shellcode_threads": [{"tid": 9}]}) is True
    assert me.has_injection_evidence({"injected_thread_first_seen": "2026-06-19 18:40:00 UTC"}) is True
    # flagged by a name/string YARA match only -> no execution-time signal
    assert me.has_injection_evidence({"create_time": "2026-06-18 19:20:44 UTC",
                                      "injected_regions": [], "shellcode_threads": []}) is False


def test_correlate_anchors_on_injection_evidence_not_boot_svchost():
    # real-world capture shape: svchost flagged at BOOT (06-18, no region/thread) must NOT anchor; the
    # injected-region-bearing ShellExperienceHost (06-19 session start) is the right anchor.
    dossiers = [
        {"pid": 3464, "name": "svchost.exe", "create_time": "2026-06-18 19:20:44 UTC",
         "injected_regions": [], "shellcode_threads": []},                         # boot, no evidence
        {"pid": 13680, "name": "ShellExperienceHost.exe", "create_time": "2026-06-19 18:26:36 UTC",
         "injected_regions": [{"start": "0x241dcfd0000"}], "shellcode_threads": []},  # evidence
    ]
    usb = [{"vendor": "SAMSUNG", "product": "FLASH", "serial": "S", "suspicion": "",
            "first_connect": me.coerce_dt("2026-06-18 15:12:08")}]
    corr = me.correlate_first_seen(dossiers, usb)
    assert corr["ram_pid"] == 13680                                  # NOT the boot-time svchost
    assert corr["ram_first_seen"] == "2026-06-19 18:26:36 UTC"
    assert "MODERATE CONFIDENCE" in corr["summary"] and "UPPER BOUND" in corr["summary"]
    assert "possible (weak)" in corr["devices"][0]["verdict"]        # ~27h before, not a tight 4h hit

    # if NO pid has evidence, it falls back to earliest boot with a strong low-confidence warning
    no_ev = me.correlate_first_seen(
        [{"pid": 3464, "name": "svchost.exe", "create_time": "2026-06-18 19:20:44 UTC",
          "injected_regions": [], "shellcode_threads": []}], usb)
    assert no_ev["ram_pid"] == 3464 and "LOW CONFIDENCE" in no_ev["summary"]
    assert "Prefetch" in no_ev["summary"]
    # when only process-create is available, the summary must carry the low-confidence caveat
    boot_only = me.correlate_first_seen(
        [{"pid": 3464, "name": "svchost.exe", "create_time": "2026-06-18 19:20:44 UTC"}], usb)
    assert "LOW CONFIDENCE" in boot_only["summary"] and boot_only["ram_basis"] == "process-create"


def test_correlate_first_seen_post_infection_not_source():
    dossiers = [{"pid": 13680, "name": "evil.exe", "create_time": "2026-06-19 14:32:05 UTC"}]
    usb = [{"vendor": "KINGSTON", "product": "DT", "serial": "K", "suspicion": "",
            "first_connect": me.coerce_dt("2026-06-19 20:00:00")}]    # connected AFTER
    corr = me.correlate_first_seen(dossiers, usb)
    assert "LIKELY NOT SOURCE" in corr["devices"][0]["verdict"]
    assert corr["devices"][0]["delta_hours"] < 0
    assert "non-USB" in corr["summary"]


def test_correlate_first_seen_no_usb_and_no_ram():
    only_ram = me.correlate_first_seen(
        [{"pid": 1, "name": "a", "create_time": "2026-06-19 14:32:05 UTC"}], [])
    assert only_ram["ram_first_seen"] and "no USB" in only_ram["summary"]
    no_ram = me.correlate_first_seen([{"pid": 1, "name": "a", "create_time": None}], [])
    assert no_ram["ram_first_seen"] is None and "No RAM first-seen" in no_ram["summary"]


def test_correlation_mermaid_edge_labels_valid():
    import re as _re
    dossiers = [{"pid": 13680, "name": "evil.exe", "create_time": "2026-06-19 14:32:05 UTC"}]
    usb = [{"vendor": "VENDORC", "product": "CODE", "serial": "S1", "suspicion": "placeholder",
            "first_connect": me.coerce_dt("2026-06-19 10:30:00")}]
    mm = me.build_correlation_mermaid(me.correlate_first_seen(dossiers, usb))
    # After Phase 5 timeline refactor: flowchart TD, attack chain clusters by ATT&CK phase
    assert mm.startswith("```mermaid") and "flowchart TD" in mm
    for lbl in _re.findall(r'-->\|"?([^|"]*)"?\|', mm):
        assert not any(ch in lbl for ch in "()[]{}<>"), f"bad edge label: {lbl!r}"


def test_append_correlation_idempotent(tmp_path):
    (tmp_path / "Attack_Graph.md").write_text("# Attack Graph\n\noriginal content\n", encoding="utf-8")
    corr = me.correlate_first_seen(
        [{"pid": 1, "name": "evil.exe", "create_time": "2026-06-19 14:32:05 UTC"}],
        [{"vendor": "V", "product": "P", "serial": "S", "suspicion": "",
          "first_connect": me.coerce_dt("2026-06-19 10:00:00")}])
    me.append_correlation(str(tmp_path), corr)
    me.append_correlation(str(tmp_path), corr)
    txt = (tmp_path / "Attack_Graph.md").read_text(encoding="utf-8")
    assert "original content" in txt
    assert txt.count(me._CORR_START) == 1                       # exactly one correlation block
    # After Phase 5 timeline refactor: heading is now "Confirmed TP Attack Timeline"
    assert "Confirmed TP Attack Timeline" in txt or "First-seen" in txt or "RAM First-Seen" in txt


def test_correlate_from_dir_joins_existing_json(tmp_path):
    """The --correlate path: read existing enrichment + USB JSON, write timeline, patch graph."""
    (tmp_path / "Memory_Enrichment_20260624.json").write_text(json.dumps(
        {"dossiers": [{"pid": 13680, "name": "evil.exe", "create_time": "2026-06-19 14:32:05 UTC"}]}))
    (tmp_path / "USB_Forensics_HOST_20260624.json").write_text(json.dumps(
        {"usb_devices": [{"Vendor": "VENDORC", "Product": "CODE", "Serial": "S1",
                          "FirstConnect": "/Date(1750329000000)/", "Suspicion": "placeholder"}]}))
    (tmp_path / "Attack_Graph.md").write_text("# Attack Graph\n\nbase\n", encoding="utf-8")
    corr = me.correlate_from_dir(str(tmp_path))
    assert corr is not None and corr["ram_pid"] == 13680
    assert (tmp_path / "Timeline_Correlation.md").exists()
    assert me._CORR_START in (tmp_path / "Attack_Graph.md").read_text(encoding="utf-8")
