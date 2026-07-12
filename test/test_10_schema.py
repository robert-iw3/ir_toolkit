"""P1-5 - the canonical findings schema/validator itself (platform-agnostic). See
test_10_schema_{windows,linux,cloud}.py for the per-platform adjudicator-output conformance
checks."""
import sys

from conftest import REPORTING

sys.path.insert(0, REPORTING)
import finding_schema as fs   # noqa: E402


def test_verdict_ladder_is_canonical():
    assert fs.VERDICTS[0] == "False Positive"
    assert fs.VERDICTS[-1] == "True Positive"
    assert fs.VERDICT_RANK["Likely True Positive"] > fs.VERDICT_RANK["Indeterminate"]


def test_validator_flags_missing_fields():
    errs = fs.validate([{"Target": "x"}])           # no Type, no Verdict
    assert any("Type" in e for e in errs)
    assert any("Verdict" in e for e in errs)


def test_validator_flags_bad_verdict():
    errs = fs.validate([{"Type": "t", "Target": "x", "Verdict": "Maybe"}])
    assert any("not in the canonical ladder" in e for e in errs)
