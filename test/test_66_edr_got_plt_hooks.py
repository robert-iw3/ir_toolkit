"""Live-host GOT/PLT hook detector (edr_hunt.check_got_plt_hooks).

A userland rootkit (Symbiote, jynx/libprocesshider-class, a malicious LD_PRELOAD object)
redirects a library function's GOT slot to attacker code. Detection walks a sensitive
process's PLT relocation table and reads the LIVE pointer each slot currently holds.

Two layers tested:
  1. Pure ELF parsing (_elf_header/_elf_program_headers/_elf_plt_relocations/
     _elf_defined_symbols/_elf_load_bias) against both a hand-built, genuinely parseable
     ELF64 fixture and (where available) the host's real libc, cross-checked against
     readelf's own PLT relocation count during development.
  2. Classification logic (_got_plt_scan_pid) with /proc reads mocked but ELF parsing
     real -- reads an actual synthetic .so from disk, only the "live" pointer values and
     /proc/<pid>/maps table are controlled.

The most important case here (test_clean_process_produces_zero_findings /
test_self_plt_stub_is_clean_not_verify) is a real bug caught before landing: the first
version of this check flagged ~440 findings against a single clean python3 process. Every
target address landed in the SCANNED LIBRARY'S OWN .plt section -- the universal signature
of an unresolved lazy-bound slot (most of a process's imports are simply never called),
confirmed against readelf's section table on /usr/bin/python3.13. Fixed by treating "target
lands back in the object whose PLT table is being walked" as clean, not just "target lands
in the confirmed definer".
"""
import os
import struct
import sys
from unittest.mock import patch

import pytest

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import edr_hunt as h  # noqa: E402

_REAL_LIBC_CANDIDATES = [
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib64/libc.so.6",
]
_real_libc = next((p for p in _REAL_LIBC_CANDIDATES if os.path.isfile(p)), None)
needs_real_libc = pytest.mark.skipif(_real_libc is None, reason="no real libc.so.6 found")


# ---------------------------------------------------------------------------
# Synthetic ELF64 fixture: a minimal, genuinely parseable shared object with a real
# PT_LOAD + PT_DYNAMIC pair and a real .rela.plt entry -- not a byte-soup approximation.
# ---------------------------------------------------------------------------
def _build_elf64_with_plt(defined_in_lib, plt_symbol, plt_got_vaddr):
    """One PT_LOAD covering the whole file (vaddr == file offset, identity-mapped for
    simplicity) and one PT_DYNAMIC segment whose .dynamic table points at a real
    dynsym/dynstr/rela.plt triplet. `defined_in_lib` are symbols this object EXPORTS
    (st_shndx=1); `plt_symbol` is the one imported symbol bound via the single
    .rela.plt (R_X86_64_JUMP_SLOT) entry, whose GOT slot sits at `plt_got_vaddr`."""
    E_HDR_SIZE, PHDR_SIZE, N_PHDRS = 64, 56, 2
    phdr_table_off = E_HDR_SIZE
    dynsym_off = phdr_table_off + PHDR_SIZE * N_PHDRS

    dynstr = b"\x00"
    name_off = {}
    for n in list(defined_in_lib) + [plt_symbol]:
        name_off[n] = len(dynstr)
        dynstr += n.encode() + b"\x00"

    def sym(name, shndx):
        return struct.pack("<IBBHQQ", name_off[name], 0x10, 0, shndx, 0, 0)

    dynsym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)          # index 0: reserved null entry
    sym_index = {}
    idx = 1
    for n in defined_in_lib:
        dynsym += sym(n, 1)                                    # shndx != 0 -> defined
        sym_index[n] = idx
        idx += 1
    dynsym += sym(plt_symbol, 0)                                # SHN_UNDEF -> imported via PLT
    sym_index[plt_symbol] = idx

    dynstr_off = dynsym_off + len(dynsym)
    rela_off = dynstr_off + len(dynstr)
    rela = struct.pack("<QQq", plt_got_vaddr, (sym_index[plt_symbol] << 32) | 7, 0)
    dynamic_off = rela_off + len(rela)

    def dyn(tag, val):
        return struct.pack("<qQ", tag, val)

    dynamic = (dyn(6, dynsym_off) + dyn(11, 24) + dyn(5, dynstr_off) + dyn(10, len(dynstr))
               + dyn(23, rela_off) + dyn(2, len(rela)) + dyn(0, 0))
    file_end = dynamic_off + len(dynamic)

    load_phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, file_end, file_end, 0x1000)
    dyn_phdr = struct.pack("<IIQQQQQQ", 2, 6, dynamic_off, dynamic_off, dynamic_off,
                           len(dynamic), len(dynamic), 8)

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = e_ident + struct.pack("<HHIQQQIHHHHHH",
        3, 0x3e, 1, 0, phdr_table_off, 0, 0, E_HDR_SIZE, PHDR_SIZE, N_PHDRS, 0, 0, 0)

    data = header + load_phdr + dyn_phdr + dynsym + dynstr + rela + dynamic
    assert len(data) == file_end
    return data


def _parse(data):
    hdr = h._elf_header(data)
    phdrs = h._elf_program_headers(data, hdr)
    return hdr, phdrs


# ---------------------------------------------------------------------------
# Pure ELF parsing
# ---------------------------------------------------------------------------
def test_elf_header_rejects_non_elf():
    assert h._elf_header(os.urandom(200)) is None
    assert h._elf_header(b"") is None
    assert h._elf_header(b"\x7fELF" + os.urandom(10)) is None


def test_synthetic_plt_relocation_roundtrip():
    data = _build_elf64_with_plt(["local_helper"], "target_func", 0x3000)
    hdr, phdrs = _parse(data)
    assert hdr["is64"] is True
    relocs = h._elf_plt_relocations(data, hdr, phdrs)
    assert relocs == [("target_func", 0x3000)]


def test_synthetic_defined_symbols_excludes_the_plt_import():
    data = _build_elf64_with_plt(["local_helper", "other_export"], "target_func", 0x3000)
    hdr, phdrs = _parse(data)
    defined = h._elf_defined_symbols(data, hdr, phdrs)
    assert defined == {"local_helper", "other_export"}
    assert "target_func" not in defined              # imported, not defined by this object


def test_elf_load_bias_identity_and_offset():
    data = _build_elf64_with_plt([], "f", 0x100)
    hdr, phdrs = _parse(data)
    assert h._elf_load_bias([0x555000], phdrs) == 0x555000     # PT_LOAD vaddr=0
    assert h._elf_load_bias([], phdrs) is None
    assert h._elf_load_bias([0x555000], []) is None


def test_dynamic_tags_missing_pt_dynamic_returns_none():
    assert h._elf_dynamic_tags(b"\x00" * 200, {"is64": True}, []) is None


@needs_real_libc
def test_plt_relocations_against_real_libc_matches_readelf_shape():
    """Ground truth: readelf -r on this host's libc.so.6 shows exactly the JUMP_SLOT
    (symbol-bound) entries this parser should return, plus a larger number of
    R_X86_64_IRELATIVE entries (sym index 0, no name) it correctly excludes."""
    data = open(_real_libc, "rb").read()
    hdr, phdrs = _parse(data)
    assert hdr is not None and hdr["is64"] is True
    defined = h._elf_defined_symbols(data, hdr, phdrs)
    assert "malloc" in defined and "printf" in defined
    relocs = h._elf_plt_relocations(data, hdr, phdrs)
    assert len(relocs) > 0
    names = {n for n, _ in relocs}
    assert "realloc" in names or "calloc" in names    # stable across modern glibc builds
    assert all(n for n, _ in relocs)                  # no empty/IRELATIVE names leaked through


@needs_real_libc
def test_load_bias_and_reloc_addresses_are_real_vaddrs():
    """The relocation offsets returned are genuine link-time virtual addresses (small,
    well within the mapped object's size), not garbage -- sanity bound, not a specific
    value, since exact offsets are glibc-build-specific."""
    data = open(_real_libc, "rb").read()
    hdr, phdrs = _parse(data)
    relocs = h._elf_plt_relocations(data, hdr, phdrs)
    for _, vaddr in relocs:
        assert 0 <= vaddr < len(data) * 4             # generous bound, catches gross misparse


# ---------------------------------------------------------------------------
# Live /proc helpers (real self-process, no mocking needed)
# ---------------------------------------------------------------------------
def test_read_maps_objects_parses_real_proc_self():
    maps = h._read_maps_objects(str(os.getpid()))
    assert "ANON" in maps
    py = next((p for p in maps if "python3" in os.path.basename(p)), None)
    assert py is not None
    assert all(e["end"] > e["start"] for e in maps[py])


def test_read_maps_objects_missing_pid_returns_empty():
    assert h._read_maps_objects("999999999") == {}


def test_read_proc_mem_u64_out_of_range_returns_none():
    assert h._read_proc_mem_u64(str(os.getpid()), 0xFFFFFFFFFFFF0000) is None


def test_pid_uid0_matches_real_self():
    assert h._pid_uid0(str(os.getpid())) == (os.geteuid() == 0)


def test_pid_uid0_missing_pid_is_false():
    assert h._pid_uid0("999999999") is False


# ---------------------------------------------------------------------------
# check_got_plt_hooks / _got_plt_scan_pid classification -- real ELF parsing against
# synthetic .so files on disk, mocked /proc/<pid>/maps + /proc/<pid>/mem.
# ---------------------------------------------------------------------------
_TARGET_GOT_VADDR = 0x3000
_TARGET_BASE = 0x500000
_DEFINER_BASE = 0x600000
_OTHER_BASE = 0x700000
_TARGET_SLOT_LIVE = _TARGET_BASE + _TARGET_GOT_VADDR


def _scan(tmp_path, evil_target_live_value, evil_target_readable=True):
    target_path = str(tmp_path / "libtarget.so")
    definer_path = str(tmp_path / "libreal.so")
    other_path = str(tmp_path / "libother.so")

    target_data = _build_elf64_with_plt([], "evil_target", _TARGET_GOT_VADDR)
    definer_data = _build_elf64_with_plt(["evil_target"], "dummy_import", 0x3000)
    other_data = _build_elf64_with_plt(["unrelated_symbol"], "dummy_import2", 0x3000)
    open(target_path, "wb").write(target_data)
    open(definer_path, "wb").write(definer_data)
    open(other_path, "wb").write(other_data)

    maps = {
        target_path: [{"start": _TARGET_BASE, "end": _TARGET_BASE + len(target_data) + 0x10000,
                       "perms": "r-xp"}],
        definer_path: [{"start": _DEFINER_BASE, "end": _DEFINER_BASE + len(definer_data) + 0x10000,
                        "perms": "r-xp"}],
        other_path: [{"start": _OTHER_BASE, "end": _OTHER_BASE + len(other_data) + 0x10000,
                     "perms": "r-xp"}],
        "ANON": [
            {"start": 0x800000, "end": 0x801000, "perms": "rwxp"},   # anon + exec
            {"start": 0x900000, "end": 0x901000, "perms": "rw-p"},   # anon, not exec
        ],
    }

    def fake_mem(pid, addr):
        if addr == _TARGET_SLOT_LIVE:
            return None if not evil_target_readable else evil_target_live_value
        # definer/other libraries' own placeholder PLT slots resolve cleanly (self-PLT)
        # so they never contribute unrelated findings to these tests.
        if addr == _DEFINER_BASE + 0x3000:
            return _DEFINER_BASE + 5
        if addr == _OTHER_BASE + 0x3000:
            return _OTHER_BASE + 5
        return None

    h.FINDINGS.clear()
    with patch.object(h, "_read_maps_objects", return_value=maps), \
         patch.object(h, "_read_proc_mem_u64", side_effect=fake_mem):
        h._got_plt_scan_pid("4242", "target-proc")
    return [f for f in h.FINDINGS if "evil_target" in f["Details"]]


def test_clean_via_confirmed_definer_produces_no_finding(tmp_path):
    findings = _scan(tmp_path, evil_target_live_value=_DEFINER_BASE + 5)
    assert findings == []


def test_self_plt_stub_is_clean_not_verify(tmp_path):
    """The bug this check shipped with, caught before landing: an unresolved
    lazy-bound slot points back at its OWN object's .plt stub, not the real definer.
    That must be silent, not a 'verify' finding -- see module docstring."""
    findings = _scan(tmp_path, evil_target_live_value=_TARGET_BASE + 5)
    assert findings == []


def test_anon_exec_target_is_critical(tmp_path):
    findings = _scan(tmp_path, evil_target_live_value=0x800500)      # inside the anon+exec range
    assert len(findings) == 1
    f = findings[0]
    assert f["Severity"] == "Critical"
    assert f["Type"] == "GOT/PLT Overwrite (memory)"
    assert "evil_target" in f["Details"]
    assert "T1574.001" in f["MITRE"]


def test_anon_non_exec_target_is_skipped(tmp_path):
    findings = _scan(tmp_path, evil_target_live_value=0x900500)      # anon, no exec bit
    assert findings == []


def test_wrong_library_target_is_medium_verify(tmp_path):
    findings = _scan(tmp_path, evil_target_live_value=_OTHER_BASE + 5)
    assert len(findings) == 1
    f = findings[0]
    assert f["Severity"] == "Medium"
    assert f["Type"] == "GOT Entry Relocation (verify)"
    assert "evil_target" in f["Details"]
    assert "confirmed definer" in f["Details"] or "libreal.so" in f["Details"]


def test_unreadable_slot_is_skipped_not_flagged(tmp_path):
    findings = _scan(tmp_path, evil_target_live_value=0, evil_target_readable=False)
    assert findings == []


def test_target_resolves_to_no_known_mapping_is_skipped(tmp_path):
    findings = _scan(tmp_path, evil_target_live_value=0xDEADBEEF000)   # not in any mapped range
    assert findings == []


# ---------------------------------------------------------------------------
# check_got_plt_hooks scoping: sensitive-process selection + unprivileged note
# ---------------------------------------------------------------------------
def _run_check(pids, exes, uid0=None, trust=None, geteuid=1000):
    uid0 = uid0 or {}
    trust = trust or {}
    h.FINDINGS.clear()
    scanned = []
    with patch.object(h, "proc_pids", return_value=list(pids)), \
         patch.object(h, "exe_of", side_effect=lambda p: exes.get(p)), \
         patch.object(h, "comm", side_effect=lambda p: f"comm-{p}"), \
         patch.object(h, "_pid_uid0", side_effect=lambda p: uid0.get(p, False)), \
         patch.object(h, "_pid_exe_trust", side_effect=lambda p: trust.get(p)), \
         patch.object(h, "_got_plt_scan_pid", side_effect=lambda p, c: scanned.append(p)), \
         patch.object(os, "geteuid", return_value=geteuid, create=True):
        h.check_got_plt_hooks()
    return scanned, h.FINDINGS


def test_trusted_cred_exe_is_scanned():
    scanned, _ = _run_check(["1"], {"1": "/usr/sbin/sshd"})
    assert scanned == ["1"]


def test_uid0_with_untrusted_exe_is_scanned():
    scanned, _ = _run_check(["1"], {"1": "/tmp/.evil/backdoor"},
                            uid0={"1": True}, trust={"1": "binary under a world-writable path"})
    assert scanned == ["1"]


def test_uid0_with_trusted_exe_is_not_scanned():
    scanned, _ = _run_check(["1"], {"1": "/usr/bin/bash"}, uid0={"1": True}, trust={"1": None})
    assert scanned == []


def test_ordinary_process_is_not_scanned():
    scanned, _ = _run_check(["1"], {"1": "/usr/bin/firefox"})
    assert scanned == []


def test_unprivileged_run_emits_coverage_gap_note():
    _, findings = _run_check([], {}, geteuid=1000)
    assert any(f["Type"] == "GOT/PLT Hook Check Reduced Coverage" for f in findings)


def test_root_run_emits_no_coverage_gap_note():
    _, findings = _run_check([], {}, geteuid=0)
    assert not any(f["Type"] == "GOT/PLT Hook Check Reduced Coverage" for f in findings)


def test_one_pathological_pid_does_not_abort_the_whole_check():
    def boom(p, c):
        raise RuntimeError("malformed ELF")
    h.FINDINGS.clear()
    with patch.object(h, "proc_pids", return_value=["1", "2"]), \
         patch.object(h, "exe_of", side_effect=lambda p: "/usr/sbin/sshd"), \
         patch.object(h, "comm", return_value="sshd"), \
         patch.object(h, "_got_plt_scan_pid", side_effect=boom), \
         patch.object(os, "geteuid", return_value=0, create=True):
        h.check_got_plt_hooks()          # must not raise


# ---------------------------------------------------------------------------
# main() wiring
# ---------------------------------------------------------------------------
def test_check_got_plt_hooks_registered_in_main():
    import inspect
    src = inspect.getsource(h.main)
    assert "check_got_plt_hooks" in src
