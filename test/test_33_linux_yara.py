"""Linux YARA rule compilation (linux_yara.py) — the fix for the silent-failure bug.

vol3's --yara-file compiles rule SOURCE with no externals declared, so any rule referencing
filename/filepath (or a Windows-PE construct) fails the whole compile -> vol scans with no rules
-> 0 matches (a false "clean"). linux_yara compiles the rules ourselves: externals declared,
non-Linux rules dropped, bad rules isolated, + an ELF canary to prove the engine read memory.
"""
import os
import sys

import pytest
from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import linux_yara as ly      # noqa: E402

try:
    import yara              # noqa: F401
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


def test_externals_declared():
    # the externals community rules reference must be present (this is what fixes the compile)
    assert {"filename", "filepath", "extension", "filetype", "owner"} <= set(ly.LINUX_EXTERNALS)


def test_filter_drops_non_linux_rules_by_content(tmp_path):
    # filter is by RULE CONTENT (module import), not filename
    pe = tmp_path / "generic_packer.yar"          # innocent name, but PE-bound -> dropped
    pe.write_text('import "pe"\nrule p { condition: pe.is_pe }')
    macho = tmp_path / "x.yar"
    macho.write_text('import "macho"\nrule m { condition: true }')
    generic = tmp_path / "windows_sounding_name.yar"   # scary name, but generic strings -> KEPT
    generic.write_text('rule g { strings: $a = "evil" condition: $a }')
    elf = tmp_path / "y.yar"
    elf.write_text('import "elf"\nrule e { condition: elf.type == elf.ET_EXEC }')
    kept = ly.filter_linux_rules([str(pe), str(macho), str(generic), str(elf)])
    assert str(generic) in kept and str(elf) in kept       # generic + ELF kept
    assert str(pe) not in kept and str(macho) not in kept  # PE + macho dropped (by content)


def test_canary_and_severity():
    assert ly.CANARY_RULE_NAME in ly.canary_rule_source()
    assert "7f 45 4c 46" in ly.canary_rule_source()           # ELF magic
    assert ly.severity_for_rule("Cobalt_Strike") == "Critical"
    assert ly.severity_for_rule("Some_Generic_Pe") == "High"


def test_trust_verdict():
    assert ly.yara_trust_verdict(5, 3)["trusted"] is True
    bad = ly.yara_trust_verdict(0, 0)
    assert bad["trusted"] is False and "did not" in bad["message"].lower()


@pytest.mark.skipif(not HAVE_YARA, reason="yara-python not installed")
def test_compile_with_externals_succeeds(tmp_path):
    # a rule that references the `filename` external — would FAIL the old (no-externals) path,
    # MUST compile here because linux_yara declares the externals.
    d = tmp_path / "rules"
    d.mkdir()
    (d / "ext_rule.yar").write_text(
        'rule uses_ext { condition: filename matches /evil/ }')
    (d / "linux_x.yar").write_text('rule lx { strings: $a = "x" condition: $a }')
    (d / "pe_only.yar").write_text('import "pe"\nrule po { condition: pe.is_pe }')  # content-dropped
    out = tmp_path / "rules.yarc"
    compiled, n, failed = ly.compile_ruleset(str(d), str(out), include_generic=True)
    assert compiled and os.path.exists(str(out)) and failed == 0
    # the PE-bound rule is filtered out by content -> 2 source files compiled, not 3
    assert n == 2
    loaded = yara.load(str(out))
    names = [r.identifier for r in loaded]
    assert ly.CANARY_RULE_NAME in names and "uses_ext" in names


def test_select_rules_strict_vs_broad(tmp_path):
    (tmp_path / "lin.yar").write_text('rule l { strings: $a="/proc/self/maps" condition: $a }')
    (tmp_path / "gen.yar").write_text('rule g { strings: $a="zxqv_marker" condition: $a }')
    (tmp_path / "win.yar").write_text('rule w { strings: $a="kernel32.dll" condition: $a }')
    files = [str(tmp_path / f) for f in ("lin.yar", "gen.yar", "win.yar")]
    assert ly.select_rules(files, include_generic=False) == [str(tmp_path / "lin.yar")]   # linux only
    broad = set(ly.select_rules(files, include_generic=True))
    assert str(tmp_path / "lin.yar") in broad and str(tmp_path / "gen.yar") in broad
    assert str(tmp_path / "win.yar") not in broad                                          # windows dropped


@pytest.mark.skipif(not HAVE_YARA, reason="yara-python not installed")
def test_native_scan_finds_match_and_canary(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "m.yar").write_text('rule MALWARE_X { strings: $s="EVILSIG/proc/self/maps" condition: $s }')
    out = tmp_path / "r.yarc"
    ly.compile_ruleset(str(d), str(out))                       # linux (rule has /proc)
    img = tmp_path / "mem.bin"
    img.write_bytes(b"\x7fELF" + b"\x00" * 100 + b"EVILSIG/proc/self/maps" + b"\x00" * 50)
    jsonl = tmp_path / "_yara_results.jsonl"
    rows, timed_out = ly.scan_image(str(out), str(img), timeout=60,
                                    results_jsonl=str(jsonl), log=False)
    rules = {r["Rule"] for r in rows}
    assert "MALWARE_X" in rules                                # the planted signature fired
    assert ly.CANARY_RULE_NAME in rules                         # ELF canary proves engine read bytes
    assert not timed_out
    hit = next(r for r in rows if r["Rule"] == "MALWARE_X")
    assert hit["Value"]                                         # hex snippet of the matched bytes
    # ROLLING LOG: the match was APPENDED to the JSONL during the scan (parity with Windows)
    import json as _j
    lines = [_j.loads(x) for x in open(str(jsonl)) if x.strip()]
    types = [r["t"] for r in lines]
    assert types[0] == "start" and types[-1] == "done"
    assert any(r["t"] == "match" and r["rule"] == "MALWARE_X" for r in lines)


@pytest.mark.skipif(not HAVE_YARA, reason="yara-python not installed")
def test_bad_rule_is_isolated_not_fatal(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "good.yar").write_text('rule g { strings: $a = "x" condition: $a }')
    (d / "broken.yar").write_text('rule b { this is not valid yara }')
    out = tmp_path / "r.yarc"
    compiled, n, failed = ly.compile_ruleset(str(d), str(out), include_generic=True)
    assert compiled and n == 1 and failed == 1     # good kept, broken isolated, set still usable
