from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class VerdictLabel(str, Enum):
    TRUE_POSITIVE  = 'TRUE_POSITIVE'   # 3+ independent positive dimensions
    FALSE_POSITIVE = 'FALSE_POSITIVE'  # all checked dimensions negative
    NOISE_CLOSED   = 'NOISE_CLOSED'    # ML + structural rules: certain background noise
    UNDETERMINED   = 'UNDETERMINED'    # mixed signal; needs more evidence


# Minimum number of independent positive dimensions required for a TP verdict.
# From investigation guide: "A verified TP requires positive answers on at least
# three independent dimensions."
TP_DIMENSION_THRESHOLD = 3


@dataclass
class Dimension:
    name: str           # e.g. 'Module13_CV_UNIFORM', 'Module5_ShellcodeThread'
    positive: bool      # True = supports TP; False = supports benign/FP
    rationale: str      # human-readable evidence statement
    source_module: int  # which memory_forensic module contributed this


@dataclass
class Verdict:
    pid: int
    process: str
    label: VerdictLabel
    dimensions: List[Dimension]
    positive_count: int
    negative_count: int
    rationale: str
    noise_score: Optional[float] = None   # IsolationForest score when ML ran
    findings: List[dict] = field(default_factory=list)

    @property
    def is_tp(self) -> bool:
        return self.label == VerdictLabel.TRUE_POSITIVE

    @property
    def is_closed(self) -> bool:
        return self.label in (VerdictLabel.FALSE_POSITIVE, VerdictLabel.NOISE_CLOSED)
