"""P1-5 - Windows synthetic adjudication conforms to the canonical schema."""
import sys

from conftest import REPORTING, newest

sys.path.insert(0, REPORTING)
import finding_schema as fs   # noqa: E402


def test_windows_synthetic_conforms(windows_collection):
    adj = newest(windows_collection, "Adjudication_*.json")
    assert fs.validate_file(adj) == []
