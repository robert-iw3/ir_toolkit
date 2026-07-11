"""
test_63_mwcp_parser_performance.py -- QA performance gate for every IR_Toolkit
mwcp parser's identify().

Origin: a live KIMBAP verification sweep against 271 real carved memory
regions (up to 34MB each) hung for 2+ hours at ~100% CPU. Bisection found 8
parsers with pathological identify() cost against large inputs -- root
causes were (?i) case-folding across multi-MB buffers, an O(n^2) nested-loop
cluster check, a brute-force XOR loop re-decoding the same bytes per offset
instead of once per key, and a backtracking-prone repeated-group regex.
All were fixed (see QakBotConfig/EmotedConfig/RansomwareIndicators/
HTMLSmugglingDetector/MacroPackConfig/AntiAnalysisStrings). This test exists
so the NEXT parser with the same class of bug fails CI instead of hanging a
real investigation.

Every parser's identify() must complete within _TIME_BUDGET_SECONDS against
a 10MB adversarial stress file (dense base64 runs, thousands of
extension-shaped tokens, mixed-case text) -- see generate_perf_stress_file.py
for exactly what shapes are exercised and why.
"""

import importlib
import os
import pkgutil
import subprocess
import sys
import time

import pytest

_HERE     = os.path.dirname(os.path.abspath(__file__))
_ROOT     = os.path.dirname(_HERE)
_WIN_HUNT = os.path.join(_ROOT, 'playbooks', 'windows', 'threat_hunting')
_PARSERS  = os.path.join(_WIN_HUNT, 'mwcp_parsers')
_MWCP_LIB = os.path.join(_ROOT, 'tools', 'mwcp', 'lib')
_LAB      = os.path.join(_HERE, 'windows', 'lab_mwcp')
_GENERATE = os.path.join(_LAB, 'generate_perf_stress_file.py')
_STRESS_FILE = os.path.join(_LAB, 'samples', 'perf_stress.bin')

_TIME_BUDGET_SECONDS = 3.0

_mwcp_ok = os.path.isdir(_MWCP_LIB)
for _p in (_MWCP_LIB, _PARSERS):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

_CATEGORY_DIRS = [
    'generic', 'c2_frameworks', 'stagers', 'rats', 'stealers', 'ransomware',
    'lol_fileless', 'delivery', 'cloud_saas', 'specialized',
]


@pytest.fixture(scope='session', autouse=True)
def stress_file():
    if not os.path.exists(_STRESS_FILE):
        subprocess.run([sys.executable, _GENERATE], check=True, timeout=60)


class _FO:
    def __init__(self, data: bytes):
        self.data = data
        self.name = 'perf_stress.bin'


def _discover_parser_classes():
    """Import every module in each category subfolder and return
    (module_path, ClassName, class_object) for every mwcp.Parser subclass
    found -- dynamic discovery means a newly-added parser is automatically
    covered without editing this file."""
    found = []
    for category in _CATEGORY_DIRS:
        cat_dir = os.path.join(_PARSERS, category)
        if not os.path.isdir(cat_dir):
            continue
        for _finder, mod_name, _is_pkg in pkgutil.iter_modules([cat_dir]):
            if mod_name.startswith('_'):
                continue
            module_path = f'{category}.{mod_name}'
            try:
                mod = importlib.import_module(module_path)
            except ImportError:
                continue
            cls = getattr(mod, mod_name, None)
            if cls is None or not hasattr(cls, 'identify'):
                continue
            found.append((module_path, mod_name, cls))
    return found


_PARSER_CLASSES = _discover_parser_classes() if _mwcp_ok else []

needs_mwcp = pytest.mark.skipif(not _mwcp_ok, reason='mwcp not staged in tools/')


@needs_mwcp
@pytest.mark.parametrize(
    'module_path,class_name,cls', _PARSER_CLASSES,
    ids=[f'{m}.{c}' for m, c, _ in _PARSER_CLASSES])
def test_identify_completes_within_budget(module_path, class_name, cls, stress_file):
    with open(_STRESS_FILE, 'rb') as f:
        data = f.read()

    t0 = time.time()
    try:
        cls.identify(_FO(data))
    except Exception as e:
        pytest.fail(f'{class_name}.identify() raised on the perf stress file: {e}')
    elapsed = time.time() - t0

    assert elapsed < _TIME_BUDGET_SECONDS, (
        f'{class_name}.identify() took {elapsed:.2f}s against a 10MB stress file '
        f'(budget: {_TIME_BUDGET_SECONDS}s) -- likely a pathological regex/algorithm; '
        f'see this file\'s module docstring for the class of bug to look for '
        f'((?i) case-folding over large buffers, O(n^2) nested loops, brute-force '
        f'per-offset re-decoding, backtracking-prone repeated-group regexes).')


@needs_mwcp
def test_discovered_at_least_the_known_parser_count():
    """Sanity check that dynamic discovery is actually finding parsers, not
    silently returning an empty (vacuously-passing) list."""
    assert len(_PARSER_CLASSES) >= 45, (
        f'Only discovered {len(_PARSER_CLASSES)} parser classes -- expected 45+. '
        f'Dynamic discovery may be broken (check _CATEGORY_DIRS / import errors).')
