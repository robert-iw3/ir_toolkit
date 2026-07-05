"""Batch 4 item 10 -- Module 20 syscall SSN/target decoding.

memory_forensic.py loads vmmpyc at import so it cannot be unit-imported (same
constraint as the rest of this file's tests). _decode_syscall_at, however, is pure
byte-manipulation with no vmmpyc dependency -- extract its source text (plus the
three module-level byte constants it needs) and exec() it into an isolated
namespace for genuine behavioral testing, rather than settling for structural-only
regex assertions. _build_ssn_table DOES need a live vmm/module object, so it gets
structural assertions only (behavioral coverage comes from the live FLUSH
verification instead).
"""
import re

from conftest import WIN_HUNT
import os

SCRIPT = os.path.join(WIN_HUNT, "memory_forensic.py")


def _src():
    with open(SCRIPT, encoding="utf-8") as f:
        return f.read()


def _extract_decode_syscall_at():
    """Pull _MOV_EAX/_SYSCALL_BYTES/_CLEAN_PREFIX constants + the _decode_syscall_at
    function body out of the source text and exec() them in isolation."""
    src = _src()
    consts = re.search(
        r"^_CLEAN_PREFIX.*\n_SYSCALL_BYTES.*\n_MOV_EAX.*$", src, re.MULTILINE
    )
    assert consts, "Byte constants not found"
    func = re.search(
        r"^def _decode_syscall_at\(.*?\n(?:.*\n)*?    return name, ssn, target\n",
        src, re.MULTILINE
    )
    assert func, "_decode_syscall_at function body not found"
    ns = {}
    exec(consts.group(0) + "\n\n" + func.group(0), ns)
    return ns["_decode_syscall_at"]


def _stub_bytes(ssn: int, prefix_bytes: bytes = None) -> bytes:
    """Build a clean 'mov r10,rcx; mov eax,SSN; syscall' stub (10 bytes)."""
    prefix = prefix_bytes or bytes([0x4C, 0x8B, 0xD1])
    return prefix + bytes([0xB8]) + ssn.to_bytes(4, 'little') + bytes([0x0F, 0x05])


class TestDecodeSyscallAt:

    def test_decodes_known_ssn_to_name(self):
        decode = _extract_decode_syscall_at()
        stub = _stub_bytes(0x18)
        # syscall opcode is the last 2 bytes of the 10-byte stub
        syscall_off = len(stub) - 2
        name, ssn, target = decode(stub, syscall_off, {0x18: 'NtWriteVirtualMemory'})
        assert ssn == 0x18
        assert name == 'NtWriteVirtualMemory'

    def test_unresolved_ssn_returns_none_name_not_a_guess(self):
        decode = _extract_decode_syscall_at()
        stub = _stub_bytes(0x9999)
        syscall_off = len(stub) - 2
        name, ssn, target = decode(stub, syscall_off, {})
        assert ssn == 0x9999
        assert name is None, "Must not fabricate a name for an unresolved SSN"

    def test_no_mov_eax_before_syscall_returns_none_ssn(self):
        """A bare 0x0F 0x05 with unrelated bytes before it (no mov eax,imm32) must
        not produce a fabricated SSN."""
        decode = _extract_decode_syscall_at()
        data = bytes([0x90, 0x90, 0x90, 0x90, 0x90]) + bytes([0x0F, 0x05])
        name, ssn, target = decode(data, 5, {})
        assert ssn is None
        assert name is None

    def test_self_pseudo_handle_imm32_confirms_self_target(self):
        """mov rcx,-1 (48 C7 C1 FFFFFFFF) immediately before the stub is
        GetCurrentProcess()'s documented pseudo-handle -- confirmed self."""
        decode = _extract_decode_syscall_at()
        rcx_load = bytes([0x48, 0xC7, 0xC1]) + (-1).to_bytes(4, 'little', signed=True)
        stub = _stub_bytes(0x18)
        data = rcx_load + stub
        syscall_off = len(data) - 2
        name, ssn, target = decode(data, syscall_off, {0x18: 'NtWriteVirtualMemory'})
        assert target == 'self'

    def test_self_pseudo_handle_imm64_confirms_self_target(self):
        decode = _extract_decode_syscall_at()
        rcx_load = bytes([0x48, 0xB9]) + (-1).to_bytes(8, 'little', signed=True)
        stub = _stub_bytes(0x18)
        data = rcx_load + stub
        syscall_off = len(data) - 2
        name, ssn, target = decode(data, syscall_off, {0x18: 'NtWriteVirtualMemory'})
        assert target == 'self'

    def test_non_immediate_or_absent_rcx_load_stays_undetermined(self):
        """No decodable immediate handle load before the stub -- must stay honestly
        'undetermined', never guessed as 'cross-process' or 'self'."""
        decode = _extract_decode_syscall_at()
        stub = _stub_bytes(0x18)
        # 32 bytes of unrelated filler, no recognizable immediate RCX load pattern
        data = bytes([0x90] * 32) + stub
        syscall_off = len(data) - 2
        name, ssn, target = decode(data, syscall_off, {0x18: 'NtWriteVirtualMemory'})
        assert target == 'undetermined'

    def test_non_self_immediate_handle_value_stays_undetermined(self):
        """An immediate RCX load that is NOT -1 (some other numeric value) must NOT
        be asserted as 'cross-process' -- a real handle value can't be resolved to
        'definitely a different process' from static bytes alone without a deeper
        handle-table cross-reference (deliberately out of scope this round)."""
        decode = _extract_decode_syscall_at()
        rcx_load = bytes([0x48, 0xC7, 0xC1]) + (1234).to_bytes(4, 'little', signed=True)
        stub = _stub_bytes(0x18)
        data = rcx_load + stub
        syscall_off = len(data) - 2
        name, ssn, target = decode(data, syscall_off, {0x18: 'NtWriteVirtualMemory'})
        assert target == 'undetermined', (
            "A non-(-1) immediate handle value must not be asserted as cross-process "
            "-- that requires handle-table correlation, not a guess from the byte value"
        )

    def test_syscall_too_close_to_buffer_start_returns_none(self):
        """Not enough preceding bytes for a full stub -- must not read out of bounds
        or fabricate a result."""
        decode = _extract_decode_syscall_at()
        data = bytes([0x0F, 0x05])
        name, ssn, target = decode(data, 0, {})
        assert ssn is None


# ---------------------------------------------------------------------------
# _build_ssn_table -- behavioral tests via mock vmmpyc-shaped objects (module_list/
# memory.read/maps.eat are simple enough to fake without a live image)
# ---------------------------------------------------------------------------

def _extract_build_ssn_table():
    src = _src()
    consts = re.search(r"^_CLEAN_PREFIX.*\n_SYSCALL_BYTES.*\n_MOV_EAX.*$", src, re.MULTILINE)
    assert consts, "Byte constants not found"
    func = re.search(r"^def _build_ssn_table\(procs\):.*?\n    return \{\}\n", src, re.MULTILINE | re.DOTALL)
    assert func, "_build_ssn_table function body not found"
    ns = {}
    exec(consts.group(0) + "\n\n" + func.group(0), ns)
    return ns["_build_ssn_table"]


class _FakeModule:
    def __init__(self, name, base, data):
        self.name = name
        self.base = base
        self.image_size = len(data)
        self._data = data
        self._eat = {'e': [{'fn': 'NtWriteVirtualMemory', 'va': base}]}

    class _Maps:
        def __init__(self, eat):
            self._eat = eat
        def eat(self):
            return self._eat

    @property
    def maps(self):
        return self._Maps(self._eat)


class _FakeMemory:
    def __init__(self, data):
        self._data = data
    def read(self, addr, size):
        return self._data[:size]


class _FakeProc:
    def __init__(self, module):
        self._module = module
        self.memory = _FakeMemory(module._data)
    def module_list(self):
        return [self._module]


def test_ssn_table_handles_modern_stub_with_syscall_vs_int2e_check():
    """Real bug caught live against a Windows 11 24H2 (build 26100) image: modern
    ntdll inserts a 'test byte [SharedUserData+0x308],1; jnz +N' compatibility check
    (~10 bytes) between 'mov eax,SSN' and the actual 'syscall' opcode -- the syscall
    is NOT at a fixed offset immediately after mov-eax. A fixed-offset assumption
    resolved ZERO syscalls on this real image; must scan forward for the syscall
    opcode within a bounded window instead."""
    build_ssn_table = _extract_build_ssn_table()
    # Exact real bytes read from NtWriteVirtualMemory's stub on the real FLUSH image:
    # mov r10,rcx; mov eax,0x3a; test byte[SharedUserData+0x308],1; jnz+3; syscall; ret; int 2e; ret
    # Padded with trailing NOPs -- the real ntdll buffer is 1.5MB+ so the forward-scan
    # window never runs off the end in production; this minimal fixture needs padding
    # to satisfy the same bounds check.
    modern_stub = bytes.fromhex('4c8bd1b83a000000f604250803fe7f0175030f05c3cd2ec3') + bytes([0x90] * 16)
    module = _FakeModule('ntdll.dll', base=0x7ffc86840000, data=modern_stub)
    proc = _FakeProc(module)
    table = build_ssn_table([proc])
    assert table.get(0x3a) == 'NtWriteVirtualMemory', (
        f"Must resolve SSN 0x3a for the modern (test+jnz-guarded) stub shape, got: {table}"
    )


def test_ssn_table_handles_simple_stub_with_no_compat_check():
    """Older/simpler stub shape (syscall immediately after mov eax, no compat
    check) must also resolve correctly -- the forward scan must not assume the
    check is always present."""
    build_ssn_table = _extract_build_ssn_table()
    simple_stub = bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]) + bytes([0x90] * 24)
    module = _FakeModule('ntdll.dll', base=0x7ffc86840000, data=simple_stub)
    proc = _FakeProc(module)
    table = build_ssn_table([proc])
    assert table.get(0x3a) == 'NtWriteVirtualMemory'


def test_ssn_table_rejects_hooked_stub_no_clean_prefix():
    """A prefix that doesn't match the clean 'mov r10,rcx' pattern (e.g. hooked)
    must not produce a fabricated SSN entry."""
    build_ssn_table = _extract_build_ssn_table()
    hooked_stub = (bytes([0xE9, 0x00, 0x00, 0x00, 0x00])
                   + bytes([0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05]) + bytes([0x90] * 20))
    module = _FakeModule('ntdll.dll', base=0x7ffc86840000, data=hooked_stub)
    proc = _FakeProc(module)
    table = build_ssn_table([proc])
    assert 0x3a not in table


def test_ssn_table_derived_live_from_image_ntdll_not_hardcoded():
    """Must resolve SSNs from THIS image's own ntdll export table (maps.eat()),
    never a hardcoded per-Windows-build reference table that could go stale."""
    src = _src()
    m = re.search(r"def _build_ssn_table.*?(?=\ndef )", src, re.DOTALL)
    assert m, "_build_ssn_table not found"
    body = m.group(0)
    assert '.maps.eat()' in body
    assert "startswith('Nt')" in body


def test_ssn_table_validates_clean_stub_before_trusting_an_export():
    """Must verify the clean 'mov r10,rcx; mov eax,SSN; syscall' pattern at each
    exported address before extracting an SSN -- never trust an address blindly."""
    src = _src()
    m = re.search(r"def _build_ssn_table.*?(?=\ndef )", src, re.DOTALL)
    assert m, "_build_ssn_table not found"
    body = m.group(0)
    assert '_CLEAN_PREFIX' in body
    assert '_SYSCALL_BYTES' in body


def test_module20_decode_is_bounded_per_region():
    """Decoding must be capped per region (bounded work), not exhaustive over every
    syscall occurrence -- the same volume-safety discipline as the rest of Module 20."""
    src = _src()
    assert '_SSN_DECODE_LIMIT' in src


def test_module20_ssn_table_built_once_before_the_process_loop():
    """The SSN table must be built ONCE (ntdll's content is identical across every
    process that maps it), not rebuilt per-process or per-region."""
    src = _src()
    m20 = re.search(r"=== 20\. Direct syscall detection.*?for p in procs:", src, re.DOTALL)
    assert m20, "Module 20 header not found"
    assert '_build_ssn_table(procs)' in m20.group(0)
