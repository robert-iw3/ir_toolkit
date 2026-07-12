"""Third-party tooling is accounted for in the offline-toolkit builders (Windows + Linux).

Platform-agnostic: both builder scripts exist (pure filesystem check, no execution). See
test_17_offline_toolkit_windows.py / _linux.py for the per-platform builder content/execution
checks.
"""
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_PS1 = os.path.join(_ROOT, "Build-OfflineToolkit.ps1")
BUILD_SH = os.path.join(_ROOT, "Build-OfflineToolkit-Linux.sh")


def test_both_builders_exist():
    assert os.path.isfile(BUILD_PS1), "Windows offline-toolkit builder missing"
    assert os.path.isfile(BUILD_SH), "Linux offline-toolkit builder missing"
