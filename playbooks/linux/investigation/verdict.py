from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class VerdictLabel(str, Enum):
    TRUE_POSITIVE  = 'TRUE_POSITIVE'   # Tier 1 positive, or 3+ independent Tier 1/2 positives
    FALSE_POSITIVE = 'FALSE_POSITIVE'  # all checked dimensions negative
    NOISE_CLOSED   = 'NOISE_CLOSED'    # deterministic rules (+ optional ML): certain background
    UNDETERMINED   = 'UNDETERMINED'    # mixed signal; needs more evidence


# Minimum number of independent positive dimensions required for a TP verdict.
# Same aggregate floor as the Windows engine: "a verified TP requires positive
# answers on at least three independent dimensions." Tier 1 is an additive
# shortcut on top of it; Tier 3 positives never count toward it.
TP_DIMENSION_THRESHOLD = 3

# Pseudo-PID for host-scope findings (kernel integrity, persistence files,
# accounts/SSH, SUID sweep, anti-forensics) that have no owning process.
HOST_SCOPE_PID = 0
HOST_SCOPE_NAME = '[host/kernel]'


class Tier(int, Enum):
    """Evidentiary strength of a Dimension (mirrors the Windows engine's tiered
    evidence model -- see playbooks/windows/investigation/verdict.py). Unlike the
    Windows engine (where no module has migrated off the Tier 2 default yet),
    the Linux engine uses Tier 1 and Tier 3 from day one:

    INVALID (0)            -- category error; excluded before scoring entirely.
    DEFINITIVE (1)         -- single positive settles it: structurally unforgeable
                              on Linux (a kernel module present in memory structures
                              but unlinked from /proc/modules; a second uid-0 line
                              in /etc/passwd; modprobe_path pointing at a writable
                              file). These cannot be produced by any benign
                              mechanism the playbooks document.
    STRONG_BEHAVIORAL (2)  -- a real observed action; needs >=1 independent
                              corroborating item from a different mechanism.
                              DEFAULT for dimensions not explicitly tagged.
    WEAK_STRUCTURAL (3)    -- capability without demonstrated use (io_uring in
                              use, pinned eBPF objects, LD_PRELOAD set to a benign
                              path, posture-only container findings, '(verify)'
                              severity findings). Can NEVER alone reach TP.
    """
    INVALID = 0
    DEFINITIVE = 1
    STRONG_BEHAVIORAL = 2
    WEAK_STRUCTURAL = 3


@dataclass
class Dimension:
    name: str           # e.g. 'M1_MemfdExec', 'M20_HiddenKernelModule'
    positive: bool      # True = supports TP; False = supports benign/FP
    rationale: str      # human-readable evidence statement
    source_module: int  # which investigation module contributed this
    tier: int = Tier.STRONG_BEHAVIORAL    # evidentiary strength; see Tier above
    mechanism_id: Optional[str] = None    # groups dimensions asserting the SAME underlying
                                          # detection mechanism (independence bookkeeping)


@dataclass
class Verdict:
    pid: int            # HOST_SCOPE_PID (0) = host/kernel-scope verdict
    process: str
    label: VerdictLabel
    dimensions: List[Dimension]
    positive_count: int
    negative_count: int
    rationale: str
    noise_score: Optional[float] = None   # anomaly score when the noise filter ran
    findings: List[dict] = field(default_factory=list)

    @property
    def is_tp(self) -> bool:
        return self.label == VerdictLabel.TRUE_POSITIVE

    @property
    def is_closed(self) -> bool:
        return self.label in (VerdictLabel.FALSE_POSITIVE, VerdictLabel.NOISE_CLOSED)

    @property
    def is_host_scope(self) -> bool:
        return self.pid == HOST_SCOPE_PID
