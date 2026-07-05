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
# three independent dimensions." This remains the aggregate floor for every dimension
# still at the Tier 2 default (see Tier below) -- migrating a module to a real tier
# changes ITS dimensions' weight, never this floor, so un-migrated modules see zero
# behavior change. Tier 1 is a pure additive shortcut on top of this (see engine.py);
# it can only ADD new TP verdicts (a genuine structurally-unforgeable fact that used to
# be diluted into an UNDETERMINED dimension count), never remove one.
TP_DIMENSION_THRESHOLD = 3


class Tier(int, Enum):
    """Evidentiary strength of a Dimension (planning/CURRENT-STATE-AND-OPEN-ITEMS.md
    §4 design note -- "the tiered evidence model"). Replaces treating every dimension
    as equally strong, which let a weak signal repeated N times out-vote one strong
    signal (the root cause of the Module 3/20 volume-driven-TP bugs).

    INVALID (0)            -- category error (shared-VAD-address, hex-token "mutex",
                               own-module-namespace "domain"): excluded before scoring
                               entirely. Not a benign-vs-malicious judgment.
    DEFINITIVE (1)         -- single positive settles it: a structurally unforgeable
                               fact (e.g. a cross-process handle with VM_WRITE/
                               CREATE_THREAD held by another process -- Module 23).
    STRONG_BEHAVIORAL (2)  -- a real observed action, needs >=1 independent
                               corroborating item from a genuinely different mechanism.
                               DEFAULT for every dimension not yet explicitly migrated.
    WEAK_STRUCTURAL (3)    -- capability without demonstrated use (anon-exec region
                               exists but nothing runs there, syscalls present but
                               untargeted). Can NEVER reach TP regardless of count --
                               its only role is flagging that more Tier-2 evidence
                               (enrichment, handle-walk, repeat capture) is needed.
    """
    INVALID = 0
    DEFINITIVE = 1
    STRONG_BEHAVIORAL = 2
    WEAK_STRUCTURAL = 3


@dataclass
class Dimension:
    name: str           # e.g. 'Module13_CV_UNIFORM', 'Module5_ShellcodeThread'
    positive: bool      # True = supports TP; False = supports benign/FP
    rationale: str      # human-readable evidence statement
    source_module: int  # which memory_forensic module contributed this
    tier: int = Tier.STRONG_BEHAVIORAL    # evidentiary strength; see Tier above
    mechanism_id: Optional[str] = None    # groups dimensions asserting the SAME underlying
                                          # detection mechanism, so a future independence
                                          # check can tell "2 corroborating mechanisms" apart
                                          # from "the same mechanism counted twice"


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
