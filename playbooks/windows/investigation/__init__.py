# Investigation engine: memory + multi-source correlation.
#
# Single-source (memory only):
#   from playbooks.windows.investigation import investigate
#   verdicts = investigate(findings)          # findings = Memory_Findings_*.json
#
# Multi-source QA layer:
#   from playbooks.windows.investigation import correlate
#   verdicts = correlate(findings, mwcp_hits, edr_events, event_logs)
#
from .engine import investigate
from .correlator import correlate, CorrelationVerdict, CrossSourceSignal
from .verdict import Verdict, VerdictLabel, Dimension, Tier
from .process_tree import ProcessNode
from .chain_builder import build_chains, AttackChain, ChainEvent
from .ttp_patterns import match_patterns, TTPMatch

__all__ = [
    'investigate', 'correlate',
    'Verdict', 'VerdictLabel', 'Dimension', 'Tier',
    'CorrelationVerdict', 'CrossSourceSignal',
    'ProcessNode', 'build_chains', 'AttackChain', 'ChainEvent',
    'match_patterns', 'TTPMatch',
]
