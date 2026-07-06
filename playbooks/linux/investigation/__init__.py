# Investigation engine: memory/EDR + multi-source correlation (Linux).
#
# Single-source:
#   from playbooks.linux.investigation import investigate
#   verdicts = investigate(findings)      # findings = EDR_Report/Memory_Findings/Combined_Findings
#
# Multi-source QA layer:
#   from playbooks.linux.investigation import correlate
#   verdicts = correlate(findings, journal_events, container_findings, c2_config_hits)
#
from .engine import investigate
from .correlator import correlate, CorrelationVerdict, CrossSourceSignal
from .verdict import Verdict, VerdictLabel, Dimension, Tier, HOST_SCOPE_PID, HOST_SCOPE_NAME
from .process_tree import ProcessNode
from .chain_builder import build_chains, AttackChain, ChainEvent
from .ttp_patterns import match_patterns, TTPMatch

__all__ = [
    'investigate', 'correlate',
    'Verdict', 'VerdictLabel', 'Dimension', 'Tier', 'HOST_SCOPE_PID', 'HOST_SCOPE_NAME',
    'CorrelationVerdict', 'CrossSourceSignal',
    'ProcessNode', 'build_chains', 'AttackChain', 'ChainEvent',
    'match_patterns', 'TTPMatch',
]
