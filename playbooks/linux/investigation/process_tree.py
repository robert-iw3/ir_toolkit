"""Process lineage graph for chain-of-events reconstruction (Linux).

Builds a pid -> ProcessNode map from whichever source is available:

  ProcessTree_*.json    -- a dedicated snapshot, if the collection stack ever
                          emits one (ps -eo pid,ppid,comm,args,lstart-shaped).
                          Preferred: covers every process, not just adjudicated ones.
  Adjudication_*.json   -- partial fallback: adjudicate.py's enrich() already
                          sets ParentPid/ParentName/CommandLine/Owner as real
                          top-level fields (not embedded in free text like the
                          Windows engine's fallback), so this is more complete
                          than the Windows equivalent tends to be in practice.

Lineage queries (ancestors/descendants) power the chain builder: given a
suspicious PID, walk up to find what spawned it and down to find what it spawned.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ProcessNode:
    pid: int
    name: str = ''
    ppid: int = 0
    parent_name: str = ''
    path: str = ''
    command_line: str = ''
    owner: str = ''

    def label(self) -> str:
        return f'{self.name or "?"} (PID {self.pid})'


def load_from_snapshot(entries: List[dict]) -> Dict[int, ProcessNode]:
    """Build tree from a ps-shaped snapshot (ProcessTree_*.json)."""
    tree: Dict[int, ProcessNode] = {}
    for e in entries:
        pid = e.get('pid', 0) or e.get('PID', 0)
        if not pid:
            continue
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        tree[pid] = ProcessNode(
            pid=pid,
            name=e.get('comm', '') or e.get('Comm', '') or e.get('name', ''),
            ppid=int(e.get('ppid', 0) or e.get('PPid', 0) or 0),
            path=e.get('exe', '') or e.get('path', '') or '',
            command_line=e.get('cmdline', '') or e.get('args', '') or '',
            owner=str(e.get('uid', '') or e.get('owner', '') or ''),
        )
    for node in tree.values():
        parent = tree.get(node.ppid)
        if parent:
            node.parent_name = parent.name
    return tree


_PID_TARGET_RE = re.compile(r'PID:?\s*(\d+)\s*(?:\(([^)]+)\))?')


def load_from_adjudication(entries: List[dict]) -> Dict[int, ProcessNode]:
    """Build a partial tree from adjudicate.py's enriched output. Unlike the
    Windows fallback (which regex-parses ParentPid out of free text),
    adjudicate.py's enrich() already writes ParentPid/ParentName/CommandLine/
    Owner as real fields via /proc reads at adjudication time."""
    tree: Dict[int, ProcessNode] = {}
    for e in entries:
        pid = e.get('Pid')
        if not pid:
            m = _PID_TARGET_RE.search(e.get('Target', '') or '')
            pid = m.group(1) if m else None
        if not pid:
            continue
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue

        ppid = e.get('ParentPid')
        try:
            ppid = int(ppid) if ppid else 0
        except (TypeError, ValueError):
            ppid = 0

        node = tree.get(pid) or ProcessNode(pid=pid)
        target_m = _PID_TARGET_RE.search(e.get('Target', '') or '')
        name_from_target = target_m.group(2) if target_m and target_m.group(2) else ''
        if not name_from_target:
            comm_m = re.search(r'comm=(\S+)', e.get('Details', '') or '')
            name_from_target = comm_m.group(1) if comm_m else ''
        node.name = node.name or name_from_target
        if ppid:
            node.ppid = ppid
        node.parent_name = node.parent_name or (e.get('ParentName') or '')
        node.path = node.path or (e.get('SubjectPath') or '')
        node.command_line = node.command_line or (e.get('CommandLine') or '')
        node.owner = node.owner or (e.get('Owner') or '')
        tree[pid] = node
    return tree


def ancestors(tree: Dict[int, ProcessNode], pid: int, max_depth: int = 16) -> List[ProcessNode]:
    """Walk parent links from pid upward. Cycle-safe (PID reuse can loop)."""
    chain: List[ProcessNode] = []
    seen = {pid}
    node = tree.get(pid)
    while node and node.ppid and len(chain) < max_depth:
        parent = tree.get(node.ppid)
        if parent is None or parent.pid in seen:
            if node.ppid not in seen and (node.parent_name or node.ppid):
                chain.append(ProcessNode(pid=node.ppid, name=node.parent_name))
            break
        chain.append(parent)
        seen.add(parent.pid)
        node = parent
    return chain


def descendants(tree: Dict[int, ProcessNode], pid: int, max_depth: int = 16) -> List[ProcessNode]:
    """Breadth-first walk of child links from pid downward."""
    children_of: Dict[int, List[ProcessNode]] = {}
    for node in tree.values():
        if node.ppid:
            children_of.setdefault(node.ppid, []).append(node)

    out: List[ProcessNode] = []
    seen = {pid}
    frontier = [pid]
    depth = 0
    while frontier and depth < max_depth:
        next_frontier: List[int] = []
        for p in frontier:
            for child in children_of.get(p, []):
                if child.pid in seen:
                    continue
                seen.add(child.pid)
                out.append(child)
                next_frontier.append(child.pid)
        frontier = next_frontier
        depth += 1
    return out
