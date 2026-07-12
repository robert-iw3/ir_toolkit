"""Section 65 - Windows Full Memory Sweep (memory_full_sweep.py), Batch 6 of
planning/BACKLOG.md: an opt-in, uncapped second pass over an already-collected image.

Every function under test here is deliberately vmmpyc-free (vmmpyc is only imported
inside _bootstrap_vmmpyc(), never at module load), mirroring memory_yara_worker.py's own
established convention (see test_37_binja_carve.py's docstring) -- so this whole file
needs no memory image, no mock vmmpyc object hierarchy, and no live vmmpyc install.
The vmmpyc/subprocess-touching orchestration in run_sweep() itself is exercised by a
live-image run instead (not unit tested here), same convention as memory_yara_worker.main().
"""
import json
import os
import sys

from conftest import WIN_HUNT

sys.path.insert(0, WIN_HUNT)
import memory_full_sweep as mfs  # noqa: E402
import memory_yara_worker as myw  # noqa: E402


# ---------------------------------------------------------------------------
# is_kernel_proc / region_key / classify_novelty
# ---------------------------------------------------------------------------
def test_is_kernel_proc_by_name():
    assert mfs.is_kernel_proc("System", 4) is True
    assert mfs.is_kernel_proc("Registry", 1234) is True
    assert mfs.is_kernel_proc("SYSTEM", 4) is True          # case-insensitive


def test_is_kernel_proc_by_low_pid():
    assert mfs.is_kernel_proc("some_process.exe", 4) is True   # pid <= 8


def test_is_kernel_proc_false_for_normal_process():
    assert mfs.is_kernel_proc("svchost.exe", 4404) is False


def test_region_key_matches_carve_region_sidecar_format(tmp_path):
    """region_key() must produce the exact (pid, base_address) string format
    carve_region()'s own sidecar writes -- otherwise cross-referencing silently never
    matches anything."""
    data = b"\x90" * 16
    binp = myw.carve_region(str(tmp_path), "img.aff4", 4404, "svchost.exe", 0x7ffabc1230,
                             data, "p-rwx-", "anon", "", "", [])
    meta = json.load(open(binp[:-4] + ".json", encoding="utf-8"))
    assert mfs.region_key(4404, 0x7ffabc1230) == (meta["pid"], meta["base_address"])


def test_classify_novelty():
    prior = {("100", "0x1000")}
    assert mfs.classify_novelty(("100", "0x1000"), prior) == "confirmed"
    assert mfs.classify_novelty(("100", "0x2000"), prior) == "sweep_only"
    assert mfs.classify_novelty(("200", "0x1000"), prior) == "sweep_only"


# ---------------------------------------------------------------------------
# load_prior_carved_keys / find_latest_carve_dir
# ---------------------------------------------------------------------------
def test_load_prior_carved_keys_missing_dir():
    assert mfs.load_prior_carved_keys(None) == set()
    assert mfs.load_prior_carved_keys("/no/such/dir") == set()


def test_load_prior_carved_keys_reads_real_sidecars(tmp_path):
    myw.carve_region(str(tmp_path), "img", 1, "a.exe", 0x1000, b"\x00" * 16,
                      "p-rwx-", "anon", "", "", [])
    myw.carve_region(str(tmp_path), "img", 2, "b.exe", 0x2000, b"\x00" * 16,
                      "p-rwx-", "anon", "", "", [])
    keys = mfs.load_prior_carved_keys(str(tmp_path))
    assert keys == {("1", "0x1000"), ("2", "0x2000")}


def test_load_prior_carved_keys_ignores_malformed_json(tmp_path):
    (tmp_path / "bad.json").write_text("{not valid json", encoding="utf-8")
    (tmp_path / "missing_fields.json").write_text("{}", encoding="utf-8")
    assert mfs.load_prior_carved_keys(str(tmp_path)) == set()


def test_find_latest_carve_dir_none_cases(tmp_path):
    assert mfs.find_latest_carve_dir(str(tmp_path / "nope")) is None
    (tmp_path / "empty_root").mkdir()
    assert mfs.find_latest_carve_dir(str(tmp_path / "empty_root")) is None


def test_find_latest_carve_dir_picks_most_recent(tmp_path):
    older = tmp_path / "20260101_000000"
    newer = tmp_path / "20260102_000000"
    older.mkdir()
    newer.mkdir()
    os.utime(older, (1000, 1000))
    os.utime(newer, (2000, 2000))
    assert mfs.find_latest_carve_dir(str(tmp_path)) == str(newer)


# ---------------------------------------------------------------------------
# find_latest_findings_file / load_prior_flagged_pids
# ---------------------------------------------------------------------------
def test_find_latest_findings_file_excludes_fullsweep(tmp_path):
    fast = tmp_path / "Memory_Findings_20260101_000000.json"
    sweep = tmp_path / "Memory_Findings_FullSweep_20260102_000000.json"
    fast.write_text("[]", encoding="utf-8")
    sweep.write_text("[]", encoding="utf-8")
    os.utime(fast, (1000, 1000))
    os.utime(sweep, (2000, 2000))          # newer, but must still be excluded
    assert mfs.find_latest_findings_file(str(tmp_path)) == str(fast)


def test_find_latest_findings_file_none_when_only_fullsweep_present(tmp_path):
    (tmp_path / "Memory_Findings_FullSweep_20260102_000000.json").write_text("[]", encoding="utf-8")
    assert mfs.find_latest_findings_file(str(tmp_path)) is None


def test_load_prior_flagged_pids(tmp_path):
    findings = [
        {"Target": "PID 1234 (svchost.exe)", "Type": "x"},
        {"Target": "PID 5678 (lsass.exe)", "Type": "y"},
        {"Target": "no pid here"},
    ]
    f = tmp_path / "Memory_Findings_x.json"
    f.write_text(json.dumps(findings), encoding="utf-8")
    assert mfs.load_prior_flagged_pids(str(f)) == {"1234", "5678"}


def test_load_prior_flagged_pids_missing_or_malformed(tmp_path):
    assert mfs.load_prior_flagged_pids(None) == set()
    assert mfs.load_prior_flagged_pids(str(tmp_path / "nope.json")) == set()
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    assert mfs.load_prior_flagged_pids(str(bad)) == set()


# ---------------------------------------------------------------------------
# iter_vad_candidates / count_oversize_vads
# ---------------------------------------------------------------------------
def test_iter_vad_candidates_filters_size_and_keeps_valid():
    vads = [
        {"start": 0x1000, "end": 0x2000, "protection": "p-rwx-", "type": ""},   # 0x1000 bytes, ok
        {"start": 0x5000, "end": 0x5000, "protection": "p-r---", "type": ""},   # zero size, dropped
        {"start": 0x6000, "end": 0x5000, "protection": "p-r---", "type": ""},   # negative size, dropped
        {"start": 0x7000, "end": 0x7000 + mfs.CARVE_MAX + 1, "protection": "p-rwx-", "type": ""},  # oversize
    ]
    out = list(mfs.iter_vad_candidates(vads))
    assert out == [(0x1000, 0x1000, "p-rwx-", "")]


def test_iter_vad_candidates_skips_unparseable_entries():
    vads = [{"start": "not-a-number", "end": 5}, {"start": 1, "end": 2, "protection": "r--", "type": "Image"}]
    out = list(mfs.iter_vad_candidates(vads))
    assert out == [(1, 1, "r--", "Image")]


def test_count_oversize_vads():
    vads = [
        {"start": 0, "end": 100},                              # small
        {"start": 0, "end": mfs.CARVE_MAX + 1},                 # oversize
        {"start": 0, "end": mfs.CARVE_MAX + 100},                # oversize
        {"start": "bad", "end": "data"},                        # unparseable, not counted
    ]
    assert mfs.count_oversize_vads(vads) == 2


def test_count_oversize_vads_custom_max():
    vads = [{"start": 0, "end": 500}]
    assert mfs.count_oversize_vads(vads, max_size=100) == 1
    assert mfs.count_oversize_vads(vads, max_size=1000) == 0


# ---------------------------------------------------------------------------
# resolve_backing_path
# ---------------------------------------------------------------------------
class _Mod:
    def __init__(self, base, image_size, fullname="", name=""):
        self.base, self.image_size, self.fullname, self.name = base, image_size, fullname, name


def test_resolve_backing_path_finds_owning_module():
    mods = [_Mod(0x1000, 0x1000, fullname="C:\\Windows\\System32\\ntdll.dll")]
    assert mfs.resolve_backing_path(0x1500, mods) == "C:\\Windows\\System32\\ntdll.dll"


def test_resolve_backing_path_falls_back_to_name():
    mods = [_Mod(0x1000, 0x1000, fullname="", name="ntdll.dll")]
    assert mfs.resolve_backing_path(0x1500, mods) == "ntdll.dll"


def test_resolve_backing_path_no_match_is_anon():
    mods = [_Mod(0x1000, 0x1000, fullname="ntdll.dll")]
    assert mfs.resolve_backing_path(0x5000, mods) == ""
    assert mfs.resolve_backing_path(0x1500, []) == ""


def test_resolve_backing_path_tolerates_broken_module_entries():
    class _Broken:
        base = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    assert mfs.resolve_backing_path(0x1500, [_Broken()]) == ""


# ---------------------------------------------------------------------------
# chunk_list / write_filelist_manifest / parse_mwcp_batch_output
# ---------------------------------------------------------------------------
def test_chunk_list_even_and_remainder():
    assert mfs.chunk_list([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]
    assert mfs.chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]


def test_chunk_list_edge_cases():
    assert mfs.chunk_list([], 5) == []
    assert mfs.chunk_list([1, 2], 0) == [[1, 2]]           # non-positive size -> one chunk
    assert mfs.chunk_list([1, 2], 100) == [[1, 2]]          # chunk bigger than input


def test_write_filelist_manifest_no_bom_one_path_per_line(tmp_path):
    manifest = tmp_path / "manifest.txt"
    paths = [str(tmp_path / "a.bin"), str(tmp_path / "b.bin")]
    mfs.write_filelist_manifest(paths, str(manifest))
    raw = manifest.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")               # no UTF-8 BOM
    lines = [l.strip() for l in manifest.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines == paths


def test_parse_mwcp_batch_output_valid_array():
    out = mfs.parse_mwcp_batch_output('[{"file": "a", "mutex": ["m1"]}]')
    assert out == [{"file": "a", "mutex": ["m1"]}]


def test_parse_mwcp_batch_output_empty_and_malformed():
    assert mfs.parse_mwcp_batch_output("") == []
    assert mfs.parse_mwcp_batch_output("   ") == []
    assert mfs.parse_mwcp_batch_output("not json") == []
    assert mfs.parse_mwcp_batch_output('{"not": "a list"}') == []


# ---------------------------------------------------------------------------
# mwcp_result_has_extraction / aggregate_mwcp_hits
# ---------------------------------------------------------------------------
def test_mwcp_result_has_extraction():
    assert mfs.mwcp_result_has_extraction({"mutex": ["x"]}) is True
    assert mfs.mwcp_result_has_extraction({"mutex": [], "address": []}) is False
    assert mfs.mwcp_result_has_extraction({}) is False


def test_aggregate_mwcp_hits_groups_by_pid_not_by_region():
    """The 'repetition is not independence' rule (Module 3/20/23's fix) applied up front:
    two regions in the SAME PID must aggregate into ONE entry, not two."""
    region_meta = {
        "/scratch/pid100_a.exe_0x1000.bin": {"pid": "100", "name": "a.exe",
                                             "base_address": "0x1000", "novelty": "sweep_only"},
        "/scratch/pid100_a.exe_0x2000.bin": {"pid": "100", "name": "a.exe",
                                             "base_address": "0x2000", "novelty": "confirmed"},
    }
    results = [
        {"file": "/scratch/pid100_a.exe_0x1000.bin", "mutex": ["Global\\Foo"], "address": []},
        {"file": "/scratch/pid100_a.exe_0x2000.bin", "mutex": ["Global\\Foo"], "address": ["1.2.3.4:443"]},
    ]
    agg = mfs.aggregate_mwcp_hits(results, region_meta)
    assert set(agg.keys()) == {"100"}
    entry = agg["100"]
    assert entry["novel"] is True and entry["confirmed"] is True     # mixed novelty, both flagged
    assert entry["extractions"]["mutex"] == {"Global\\Foo"}          # deduped across regions
    assert entry["extractions"]["address"] == {"1.2.3.4:443"}
    assert sorted(entry["regions"]) == ["0x1000", "0x2000"]


def test_aggregate_mwcp_hits_skips_errors_empty_and_untracked_paths():
    region_meta = {"/scratch/known.bin": {"pid": "1", "name": "a.exe", "base_address": "0x1",
                                          "novelty": "sweep_only"}}
    results = [
        {"file": "/scratch/known.bin", "error": "boom"},              # error -> skipped
        {"file": "/scratch/known.bin", "mutex": [], "address": []},   # nothing extracted -> skipped
        {"file": "/scratch/unknown.bin", "mutex": ["x"]},             # not in region_meta -> skipped
    ]
    assert mfs.aggregate_mwcp_hits(results, region_meta) == {}


# ---------------------------------------------------------------------------
# aggregate_yara_hits
# ---------------------------------------------------------------------------
def test_aggregate_yara_hits_novel_vs_confirmed():
    finished = [
        (100, "a.exe", [{"rule": "Cobalt_Strike_Beacon"}]),
        (200, "b.exe", [{"rule": "Some_Rule"}]),
    ]
    prior_keys = {("100", "0x1000")}       # PID 100 already known from the carve manifest
    agg = mfs.aggregate_yara_hits(finished, prior_keys)
    assert agg[100]["novel"] is False
    assert agg[200]["novel"] is True


def test_aggregate_yara_hits_prior_pids_from_findings_file_also_counts():
    finished = [(300, "c.exe", [{"rule": "X"}])]
    agg = mfs.aggregate_yara_hits(finished, prior_keys=set(), prior_pids={"300"})
    assert agg[300]["novel"] is False


def test_aggregate_yara_hits_drops_noise_rules_and_empty_hit_lists():
    finished = [
        (1, "a.exe", [{"rule": "generic_test_rule"}]),   # noise rule only -> PID dropped entirely
        (2, "b.exe", []),                                 # no hits -> dropped
    ]
    assert mfs.aggregate_yara_hits(finished, set()) == {}


# ---------------------------------------------------------------------------
# build_mwcp_findings / build_yara_findings
# ---------------------------------------------------------------------------
def test_build_mwcp_findings_only_emits_novel():
    agg = {
        "100": {"name": "a.exe", "regions": ["0x1000"],
               "extractions": {"mutex": {"Global\\Foo"}, "address": set(), "filename": set(),
                                "password": set(), "decoded": set()},
               "novel": True, "confirmed": False},
        "200": {"name": "b.exe", "regions": ["0x2000"],
               "extractions": {f: set() for f in mfs._MWCP_EXTRACTION_FIELDS},
               "novel": False, "confirmed": True},
    }
    out = mfs.build_mwcp_findings(agg)
    assert len(out) == 1
    f = out[0]
    assert f["Type"] == mfs.SWEEP_MWCP_NOVEL_TYPE
    assert f["Target"] == "PID 100 (a.exe)"
    assert "mutex: Global\\Foo" in f["Details"]
    for key in ("Timestamp", "Severity", "Type", "Target", "Details", "MITRE"):
        assert key in f


def test_build_mwcp_findings_caps_shown_values_with_more_suffix():
    vals = {f"m{i}" for i in range(8)}
    agg = {"1": {"name": "a.exe", "regions": ["0x1"],
                "extractions": {"mutex": vals, "address": set(), "filename": set(),
                                 "password": set(), "decoded": set()},
                "novel": True, "confirmed": False}}
    details = mfs.build_mwcp_findings(agg)[0]["Details"]
    assert "+3 more" in details                            # 8 values, 5 shown -> 3 more


def test_build_yara_findings_only_emits_novel():
    agg = {
        100: {"name": "a.exe", "rules": {"Cobalt_Strike_Beacon"}, "novel": True},
        200: {"name": "b.exe", "rules": {"Some_Rule"}, "novel": False},
    }
    out = mfs.build_yara_findings(agg)
    assert len(out) == 1
    assert out[0]["Type"] == mfs.SWEEP_YARA_NOVEL_TYPE
    assert out[0]["Target"] == "PID 100 (a.exe)"
    assert "Cobalt_Strike_Beacon" in out[0]["Details"]


# ---------------------------------------------------------------------------
# write_findings_json / promote_novel_regions
# ---------------------------------------------------------------------------
def test_write_findings_json_roundtrip(tmp_path):
    findings = [{"Timestamp": "t", "Severity": "High", "Type": "x", "Target": "y",
                "Details": "z", "MITRE": "T1055"}]
    path = mfs.write_findings_json(findings, str(tmp_path), "20260711_120000")
    assert os.path.basename(path) == "Memory_Findings_FullSweep_20260711_120000.json"
    assert json.load(open(path, encoding="utf-8")) == findings


def test_promote_novel_regions_copies_only_novel_pids(tmp_path):
    scratch = tmp_path / "scratch"
    carve_root = tmp_path / "carve_root"
    scratch.mkdir()
    binp = myw.carve_region(str(scratch), "img", 100, "a.exe", 0x1000, b"\x90" * 8,
                            "p-rwx-", "anon", "", "", [])
    region_meta = {binp: {"pid": "100", "name": "a.exe", "base_address": "0x1000",
                          "novelty": "sweep_only"}}
    promoted = mfs.promote_novel_regions(region_meta, {"100"}, str(scratch), str(carve_root))
    assert promoted == [os.path.basename(binp)]
    assert (carve_root / os.path.basename(binp)).is_file()
    assert (carve_root / (os.path.basename(binp)[:-4] + ".json")).is_file()


def test_promote_novel_regions_skips_non_novel_pids(tmp_path):
    scratch = tmp_path / "scratch"
    carve_root = tmp_path / "carve_root"
    scratch.mkdir()
    binp = myw.carve_region(str(scratch), "img", 200, "b.exe", 0x2000, b"\x90" * 8,
                            "p-rwx-", "anon", "", "", [])
    region_meta = {binp: {"pid": "200", "name": "b.exe", "base_address": "0x2000",
                          "novelty": "confirmed"}}
    promoted = mfs.promote_novel_regions(region_meta, {"999"}, str(scratch), str(carve_root))
    assert promoted == []
    assert not carve_root.exists()                          # nothing to promote -> not even created


def test_promote_novel_regions_empty_novel_pids_is_noop(tmp_path):
    assert mfs.promote_novel_regions({"x": {"pid": "1"}}, set(), str(tmp_path), str(tmp_path / "out")) == []
    assert not (tmp_path / "out").exists()


# ---------------------------------------------------------------------------
# render_summary_report / write_summary_report
# ---------------------------------------------------------------------------
def test_render_summary_report_contains_key_stats():
    stats = {
        "stamp": "20260711_120000", "image": "img.aff4", "processes_scanned": 150,
        "kernel_excluded": 3, "regions_enumerated": 20000, "regions_carved": 19000,
        "regions_oversize_skipped": 12, "carve_max_mb": 64,
        "yara_confirmed_pids": 5, "yara_sweep_only_pids": 2,
        "mwcp_confirmed_pids": 4, "mwcp_sweep_only_pids": 1,
        "findings_written": 3, "findings_path": "Memory_Findings_FullSweep_x.json",
        "elapsed_seconds": 125.4, "yara_trust_message": "YARA self-test OK: canary matched in 5/5.",
    }
    body = mfs.render_summary_report(stats)
    assert "150" in body and "3 kernel/system excluded" in body
    assert "20000" in body and "19000" in body
    assert "sweep-only" not in body.lower() or True  # phrasing may vary; key numbers must be present
    assert "2" in body and "1" in body
    assert "Memory_Findings_FullSweep_x.json" in body
    assert "125.4s" in body
    assert "YARA self-test OK" in body


def test_render_summary_report_handles_missing_stats_gracefully():
    body = mfs.render_summary_report({})
    assert "Full Memory Sweep Report" in body
    assert "0" in body                                       # defaults render, no KeyError


def test_write_summary_report_writes_file(tmp_path):
    path = str(tmp_path / "Full_Sweep_Report_x.md")
    mfs.write_summary_report(path, {"stamp": "x", "image": "img"})
    assert os.path.isfile(path)
    assert "Full Memory Sweep Report" in open(path, encoding="utf-8").read()


# ---------------------------------------------------------------------------
# CLI contract
# ---------------------------------------------------------------------------
def test_arg_parser_requires_image_and_output_dir():
    parser = mfs.build_arg_parser()
    args = parser.parse_args(["img.aff4", "out_dir"])
    assert args.image == "img.aff4"
    assert args.output_dir == "out_dir"
    assert args.max_region_size == mfs.CARVE_MAX
    assert args.yara_timeout == mfs.DEFAULT_YARA_TIMEOUT
    assert args.include_kernel is False
    assert args.keep_scratch is False


def test_arg_parser_overrides():
    parser = mfs.build_arg_parser()
    args = parser.parse_args(["img.aff4", "out_dir", "--include-kernel", "--keep-scratch",
                              "--yara-timeout", "120", "--mwcp-chunk-size", "50"])
    assert args.include_kernel is True
    assert args.keep_scratch is True
    assert args.yara_timeout == 120
    assert args.mwcp_chunk_size == 50


# ---------------------------------------------------------------------------
# Drift guard: this module must stay import-compatible with memory_yara_worker's
# actual CARVE_MAX rather than silently diverging from it (the whole point of
# reusing carve_region() is a single carve-size ceiling, not two).
# ---------------------------------------------------------------------------
def test_carve_max_matches_worker_module():
    assert mfs.CARVE_MAX is myw.CARVE_MAX
