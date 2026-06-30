"""
Shared pytest fixtures and mock vmmpyc objects for memory detection unit tests.

No vmmpyc DLL or image required -- all vmmpyc surfaces are replaced with simple
dataclasses / dicts that match the API shape used in each phase script.
"""
import os, sys
import pytest

# Make phase scripts importable without vmmpyc.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ---------------------------------------------------------------------------
# Mock vmmpyc object hierarchy
# ---------------------------------------------------------------------------
class MockMemory:
    """Simulates p.memory with a fixed byte buffer per address range."""

    def __init__(self, regions: dict = None):
        # regions: {base_addr: bytes}
        self._regions = regions or {}

    def read(self, addr: int, size: int) -> bytes:
        for base, data in self._regions.items():
            if base <= addr < base + len(data):
                off = addr - base
                return data[off: off + size]
        return b'\x00' * size


class MockMaps:
    """Simulates p.maps with injectable VAD, thread, and net lists."""

    def __init__(self, vads=None, threads=None, net=None, kdriver=None, memory=None):
        self._vads    = vads    or []
        self._threads = threads or []
        self._net     = net     or []
        self._kdriver = kdriver or []
        self.memory   = memory or MockMemory()

    def vad(self):
        return list(self._vads)

    def thread(self):
        return list(self._threads)

    def net(self):
        return list(self._net)

    def kdriver(self):
        return list(self._kdriver)


class MockModule:
    """Simulates a vmmpyc module object."""

    def __init__(self, name: str, base: int, image_size: int, path: str = ''):
        self.name       = name
        self.base       = base
        self.image_size = image_size
        self.path       = path
        self.fullname   = path


class MockToken:
    """Simulates p.token."""

    def __init__(self, user_sid='', integrity_level=0x2000, privileges_enabled=0):
        self.user_sid           = user_sid
        self.integrity_level    = integrity_level
        self.privileges_enabled = privileges_enabled

    def get(self, key, default=None):
        return getattr(self, key, default)


class MockProcess:
    """Simulates a vmmpyc process object."""

    def __init__(
        self,
        pid: int,
        name: str,
        ppid: int = 4,
        cmdline: str = '',
        pathuser: str = '',
        pathkernel: str = '',
        vads: list = None,
        threads: list = None,
        modules: list = None,
        mem_regions: dict = None,
        token=None,
        peb: int = None,
        create_time=None,
        state: str = '',
    ):
        self.pid        = pid
        self.name       = name
        self.ppid       = ppid
        self.cmdline    = cmdline
        self.pathuser   = pathuser
        self.pathkernel = pathkernel
        _mem            = MockMemory(mem_regions or {})
        self.maps       = MockMaps(vads=vads, threads=threads, memory=_mem)
        self._modules   = modules or []
        self.memory     = _mem
        self.token      = token
        self.peb        = peb
        self.create_time = create_time
        self.state      = state

    def module_list(self):
        return list(self._modules)


class MockVmm:
    """Simulates the top-level vmmpyc.Vmm object."""

    def __init__(self, net=None, kdriver=None, kernel_attrs=None):
        self.maps   = MockMaps(net=net, kdriver=kdriver)
        self._katts = kernel_attrs or {}

    @property
    def kernel(self):
        return type('K', (), self._katts)()


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def findings():
    """Return a fresh findings list and an add() callable."""
    result = []

    def add(severity, ftype, target, details, mitre):
        result.append({
            'Severity': severity,
            'Type':     ftype,
            'Target':   target,
            'Details':  details,
            'MITRE':    mitre,
        })

    return result, add


@pytest.fixture
def silent_log():
    """A log function that discards output (keeps test stdout clean)."""
    def _log(msg, lvl='INFO'):
        pass
    return _log


@pytest.fixture
def noisy_log(capsys):
    """A log function that prints (useful for debugging failing tests)."""
    def _log(msg, lvl='INFO'):
        print(f'[{lvl}] {msg}')
    return _log


def make_system_proc(name='system', pid=4):
    """Quick helper: build a process that is_system_proc() returns True for."""
    return MockProcess(pid=pid, name=name)


def make_user_proc(pid, name, ppid=4, **kwargs):
    """Quick helper: build a regular user-mode process."""
    return MockProcess(pid=pid, name=name, ppid=ppid, **kwargs)
