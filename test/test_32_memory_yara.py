"""YARA trust/verify helpers for the Windows memory scan (memory_yara.py).

memory_forensic.py runs vmmpyc at import, so its YARA logic is factored into a
vmmpyc-free module (memory_yara) that we can unit-test here. Covers: rule
collection, noise/severity classification, the self-test canary, rule validation
via yarac64, and the post-scan trust verdict.
"""
import os
import sys
import shutil

import pytest

from conftest import WIN_HUNT

sys.path.insert(0, WIN_HUNT)
import memory_yara as my  # noqa: E402

TOOLS = os.path.join(os.path.dirname(os.path.dirname(WIN_HUNT)), "..", "tools")
YARAC = os.path.join(TOOLS, "yarac64.exe")
RULES = os.path.join(TOOLS, "yara_rules")
_have_yarac = os.path.isfile(YARAC)


# -- rule collection ----------------------------------------------------------
@pytest.mark.skipif(not os.path.isdir(RULES), reason="staged rules not present")
def test_collect_rule_files_finds_staged_rules():
    files = my.collect_rule_files(RULES)
    assert len(files) > 1000
    assert all(f.lower().endswith((".yar", ".yara")) for f in files)


def test_collect_rule_files_missing_dir_returns_empty():
    assert my.collect_rule_files(os.path.join(os.sep, "no", "such", "dir")) == []


# -- noise + severity classification -----------------------------------------
@pytest.mark.parametrize("name", ["generic_test", "PUA_thing", "with_suffix", "debug_x"])
def test_noise_rules_suppressed(name):
    assert my.is_noise_rule(name) is True


@pytest.mark.parametrize("name", ["Cobalt_Strike_Beacon", "Mimikatz", "APT_Implant"])
def test_real_rules_not_noise(name):
    assert my.is_noise_rule(name) is False


@pytest.mark.parametrize("name", ["CobaltStrike_x", "win_meterpreter", "generic_shellcode",
                                  "Mimikatz_creds", "process_inject"])
def test_high_signal_rules_are_critical(name):
    assert my.severity_for_rule(name) == "Critical"


def test_other_rules_are_high():
    assert my.severity_for_rule("Suspicious_Office_Macro") == "High"


# -- canary -------------------------------------------------------------------
def test_canary_source_matches_dos_stub():
    src = my.canary_rule_source()
    assert my.CANARY_RULE_NAME in src
    assert "This program cannot be run in DOS mode" in src


@pytest.mark.skipif(not _have_yarac, reason="yarac64.exe not staged")
def test_canary_rule_compiles(tmp_path):
    rule = tmp_path / "canary.yar"
    rule.write_text(my.canary_rule_source(), encoding="utf-8")
    good, failed = my.validate_rule_files([str(rule)], YARAC)
    assert failed == []
    assert str(rule) in good


# -- rule validation (chunk + bisect) ----------------------------------------
@pytest.mark.skipif(not _have_yarac, reason="yarac64.exe not staged")
def test_validate_separates_good_and_broken(tmp_path):
    good_rule = tmp_path / "good.yar"
    good_rule.write_text('rule G { strings: $a = "abc" condition: $a }', encoding="utf-8")
    bad_rule = tmp_path / "bad.yar"
    bad_rule.write_text("rule B { this is not valid yara", encoding="utf-8")

    good, failed = my.validate_rule_files([str(good_rule), str(bad_rule)], YARAC)
    assert str(good_rule) in good
    assert any(bad_rule.name in os.path.basename(f) for f in failed)
    assert str(good_rule) not in failed


# -- windows-only rule filtering ----------------------------------------------
@pytest.mark.parametrize("name,expected", [
    ("Windows_Trojan_CobaltStrike.yar", True),
    ("Linux_Trojan_Gafgyt.yar", False),
    ("MacOS_Backdoor_X.yara", False),
    ("macos_evil.yar", False),
    ("Multi_Generic_Threat.yar", True),
    ("gen_mimikatz.yar", True),
    ("apt_equation.yar", True),
    ("webshell.yar", True),
])
def test_is_windows_rule(name, expected):
    assert my.is_windows_rule(name) is expected


def test_is_windows_rule_path_based():
    assert my.is_windows_rule(os.path.join("rules", "linux", "foo.yar")) is False
    assert my.is_windows_rule(os.path.join("rules", "windows", "foo.yar")) is True


def test_filter_windows_rules_excludes_non_windows():
    files = [os.path.join("a", "Windows_X.yar"), os.path.join("b", "Linux_Y.yar"),
             os.path.join("c", "MacOS_Z.yar"), os.path.join("d", "gen_w.yar")]
    out = my.filter_windows_rules(files)
    assert os.path.join("a", "Windows_X.yar") in out
    assert os.path.join("d", "gen_w.yar") in out
    assert os.path.join("b", "Linux_Y.yar") not in out
    assert os.path.join("c", "MacOS_Z.yar") not in out


# -- single compiled ruleset (.yac) -------------------------------------------
@pytest.mark.skipif(not _have_yarac, reason="yarac64.exe not staged")
def test_compile_ruleset_builds_single_yac(tmp_path):
    (tmp_path / "a.yar").write_text('rule A { strings: $a="x" condition: $a }', encoding="utf-8")
    (tmp_path / "b.yar").write_text('rule B { strings: $b="y" condition: $b }', encoding="utf-8")
    out = tmp_path / "out.yac"
    yac, n_ok, n_fail = my.compile_ruleset(
        [str(tmp_path / "a.yar"), str(tmp_path / "b.yar")], YARAC, str(out))
    assert yac == str(out) and os.path.isfile(yac)
    assert n_ok == 2 and n_fail == 0


@pytest.mark.skipif(not _have_yarac, reason="yarac64.exe not staged")
def test_compile_ruleset_drops_broken_and_keeps_good(tmp_path):
    (tmp_path / "g.yar").write_text('rule G { strings: $a="x" condition: $a }', encoding="utf-8")
    (tmp_path / "b.yar").write_text("rule B { not valid yara", encoding="utf-8")
    out = tmp_path / "o.yac"
    yac, n_ok, n_fail = my.compile_ruleset(
        [str(tmp_path / "g.yar"), str(tmp_path / "b.yar")], YARAC, str(out))
    assert yac is not None and os.path.isfile(yac)
    assert n_ok == 1 and n_fail == 1


@pytest.mark.skipif(not _have_yarac, reason="yarac64.exe not staged")
def test_compile_ruleset_all_broken_returns_none(tmp_path):
    (tmp_path / "b.yar").write_text("rule B { not valid yara", encoding="utf-8")
    out = tmp_path / "o.yac"
    yac, n_ok, n_fail = my.compile_ruleset([str(tmp_path / "b.yar")], YARAC, str(out))
    assert yac is None and n_ok == 0 and n_fail == 1


def test_compile_ruleset_empty_returns_none():
    yac, n_ok, n_fail = my.compile_ruleset([], "yarac64.exe", "out.yac")
    assert yac is None and n_ok == 0 and n_fail == 0


# -- post-scan trust verdict --------------------------------------------------
def test_trust_verdict_canary_fired_is_trusted():
    v = my.yara_trust_verdict(procs_scanned=50, canary_hits=12, scan_errors=0)
    assert v["trusted"] is True


def test_trust_verdict_no_canary_despite_scans_is_untrusted():
    # Scanned real processes but the canary (present in every PE) never matched
    # -> the engine is not actually inspecting memory.
    v = my.yara_trust_verdict(procs_scanned=50, canary_hits=0, scan_errors=0)
    assert v["trusted"] is False
    assert "canary" in v["message"].lower()


def test_trust_verdict_nothing_scanned_is_neutral():
    v = my.yara_trust_verdict(procs_scanned=0, canary_hits=0, scan_errors=0)
    assert v["trusted"] is True  # nothing to scan -> not a failure


def test_trust_verdict_reports_scan_errors():
    v = my.yara_trust_verdict(procs_scanned=50, canary_hits=5, scan_errors=7)
    assert v["scan_errors"] == 7


# -- VAD-context enrichment (parity with Linux _vma_context) ------------------
@pytest.mark.parametrize("prot,expected", [
    ("PAGE_EXECUTE_READWRITE", "rwx"),
    ("PAGE_EXECUTE_READ", "r-x"),
    ("PAGE_READWRITE", "rw-"),
    ("PAGE_READONLY", "r--"),
    ("PAGE_EXECUTE_WRITECOPY", "rwx"),
    ("", "---"),
    # MemProcFS VAD char form
    ("p-rw--", "rw-"),
    ("p-r---", "r--"),
    ("---wxc", "-wx"),
    ("p-rwx-", "rwx"),
])
def test_normalize_perms(prot, expected):
    assert my.normalize_perms(prot) == expected


@pytest.mark.parametrize("vtype,path,expected", [
    ("Private", "", "anon"),
    ("", "", "anon"),
    ("Image", r"C:\Windows\System32\ntdll.dll", "file"),
    ("Mapped", r"C:\pagefile.sys", "file"),
    ("Private", r"C:\x.dll", "file"),   # any backing path => file
])
def test_vad_region(vtype, path, expected):
    assert my.vad_region(vtype, path) == expected


def test_classify_anon_exec_escalates_to_critical():
    # injected/unbacked executable memory = injected code => Critical (the real signal)
    assert my.classify_yara_hit(region="anon", perms="rwx", base_severity="High") == "Critical"
    assert my.classify_yara_hit(region="anon", perms="r-x", base_severity="High") == "Critical"


def test_classify_file_backed_keeps_severity():
    # a rule grazing a loaded DLL: keep severity, never downgrade (could be trojanised)
    assert my.classify_yara_hit(region="file", perms="r-x", base_severity="High") == "High"
    assert my.classify_yara_hit(region="anon", perms="rw-", base_severity="High") == "High"  # no exec


def test_hit_context_note():
    assert "injected" in my.hit_context_note("anon", "rwx", "").lower()
    note = my.hit_context_note("file", "r-x", r"C:\Windows\System32\SecHealthUI.dll")
    assert "verify" in note.lower() and "SecHealthUI" in note


# -- crash-resilient worker orchestration -------------------------------------
# The scan runs in a subprocess so a native MemProcFS segfault on a pathological
# process (e.g. dwm.exe) can't kill the whole analysis; the parent restarts with
# the crashing PID skipped. These pure helpers drive that loop.
def test_parse_worker_jsonl_counts():
    lines = [
        '{"t":"start","pid":100}',
        '{"t":"result","pid":100,"name":"svchost.exe","canary":true,'
        '"hits":[{"rule":"RuleA","region":"anon","perms":"p-rwx-","path":"","strings":["$a"],"n":3}]}',
        '{"t":"start","pid":200}',
        '{"t":"result","pid":200,"name":"x.exe","canary":true,"hits":[]}',
        '{"t":"start","pid":1516}',          # dwm started but never finished (crashed)
        'garbage line that is not json',
    ]
    s = my.parse_worker_jsonl(lines)
    assert s["canary_hits"] == 2
    assert s["started_pids"] == {100, 200, 1516}
    assert s["finished_pids"] == {100, 200}
    assert s["done"] is False
    rules = {h["rule"] for (_pid, _name, hits) in s["finished"] for h in hits}
    assert "RuleA" in rules


def test_parse_worker_jsonl_done():
    s = my.parse_worker_jsonl(['{"t":"start","pid":1}',
                               '{"t":"result","pid":1,"name":"a","canary":true,"hits":[]}',
                               '{"t":"done"}'])
    assert s["done"] is True


def test_crashing_pid_identifies_unfinished():
    assert my.crashing_pid({1, 2, 1516}, {1, 2}) == 1516


def test_crashing_pid_none_when_all_finished():
    assert my.crashing_pid({1, 2}, {1, 2}) is None


def test_crashing_pid_excludes_already_skipped():
    # Parent passes finished|skip so a stale 'start' for an earlier crasher (4512,
    # already skipped) isn't re-flagged; the NEW crasher (5000) is found instead.
    started = {1, 2, 4512, 5000}
    finished = {1, 2}
    skip = {4512}
    assert my.crashing_pid(started, finished | skip) == 5000


# -- packaging regression: embeddable Python lacks the script dir on sys.path --
def test_memory_forensic_adds_script_dir_to_syspath():
    # The bundled embeddable Python does not add the script's own directory to
    # sys.path, so memory_forensic.py must do it explicitly or `import memory_yara`
    # fails at runtime (only reproduces with the staged bundle, not dev Python).
    src = open(os.path.join(WIN_HUNT, "memory_forensic.py"), encoding="utf-8").read()
    assert "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))" in src
    # And the import must be guarded so a YARA failure can't crash the whole scan.
    assert "import memory_yara as myara" in src
    assert "myara = None" in src



# -- duplicate rule-name dedup (vendor feeds ship colliding rule ids) ----------
def test_dedupe_rule_files_drops_duplicate_rule_name(tmp_path):
    a = tmp_path / "a.yar"; a.write_text('rule DupName { condition: true }', encoding="utf-8")
    b = tmp_path / "b.yar"; b.write_text('rule DupName { condition: false }', encoding="utf-8")
    c = tmp_path / "c.yar"; c.write_text('rule Unique { condition: true }', encoding="utf-8")
    kept, dropped = my.dedupe_rule_files([str(a), str(b), str(c)])
    assert str(a) in kept and str(c) in kept
    assert str(b) in dropped and str(c) not in dropped


# -- abuse.ch excluded from MEMORY scanning (file-oriented feed) ----------------
def test_exclude_memory_noise_drops_abusech():
    files = [
        os.path.join("tools", "yara_rules", "abusech", "Luckyware.yar"),
        os.path.join("tools", "yara_rules", "elastic", "Windows_Trojan_REDLEAVES.yar"),
        os.path.join("tools", "yara_rules", "neo23x0", "gen_x.yar"),
    ]
    out = my.exclude_memory_noise(files)
    assert not any("abusech" in f for f in out)
    assert any("REDLEAVES" in f for f in out)
    assert len(out) == 2
