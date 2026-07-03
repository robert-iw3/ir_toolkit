"""Process lineage graph for chain-of-events reconstruction.

Builds a pid -> ProcessNode map from whichever source is available:

  ProcessTree_*.json   -- dedicated snapshot (Win32_Process: ProcessId,
                          ParentProcessId, Name, ExecutablePath, CommandLine,
                          CreationDate). Preferred: covers every process.
  Adjudication_*.json  -- partial fallback: ParentPid/ParentName/StartTime are
                          only present for adjudicated targets.

Lineage queries (ancestors / descendants) power the chain builder: given a
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
    start_time: str = ''

    def label(self) -> str:
        return f'{self.name or "?"} (PID {self.pid})'


def load_from_snapshot(entries: List[dict]) -> Dict[int, ProcessNode]:
    """Build tree from a Win32_Process snapshot (ProcessTree_*.json)."""
    tree: Dict[int, ProcessNode] = {}
    for e in entries:
        pid = e.get('ProcessId', 0) or e.get('pid', 0)
        if not pid:
            continue
        tree[pid] = ProcessNode(
            pid=pid,
            name=e.get('Name', '') or e.get('name', ''),
            ppid=e.get('ParentProcessId', 0) or e.get('ppid', 0),
            path=e.get('ExecutablePath', '') or e.get('path', '') or '',
            command_line=e.get('CommandLine', '') or e.get('cmd', '') or '',
            start_time=str(e.get('CreationDate', '') or e.get('start_time', '') or ''),
        )
    # Resolve parent names now that all nodes exist
    for node in tree.values():
        parent = tree.get(node.ppid)
        if parent:
            node.parent_name = parent.name
    return tree


def load_from_adjudication(entries: List[dict]) -> Dict[int, ProcessNode]:
    """Build a partial tree from adjudication entries (ParentPid/ParentName)."""
    tree: Dict[int, ProcessNode] = {}
    for e in entries:
        target = e.get('Target', '')
        m = re.match(r'PID\s+(\d+)\s+\(([^)]+)\)', target)
        if not m:
            continue
        pid, name = int(m.group(1)), m.group(2)
        ppid = e.get('ParentPid', 0) or 0
        try:
            ppid = int(ppid)
        except (TypeError, ValueError):
            ppid = 0
        node = tree.get(pid) or ProcessNode(pid=pid)
        node.name = node.name or name
        if ppid:
            node.ppid = ppid
        node.parent_name  = node.parent_name  or (e.get('ParentName', '') or '')
        node.path         = node.path         or (e.get('SubjectPath', '') or '')
        node.command_line = node.command_line or (e.get('CommandLine', '') or '')
        node.start_time   = node.start_time   or (e.get('StartTime', '') or '')
        tree[pid] = node
    return tree


def ancestors(tree: Dict[int, ProcessNode], pid: int,
              max_depth: int = 16) -> List[ProcessNode]:
    """Walk parent links from pid upward. Cycle-safe (PID reuse can loop)."""
    chain: List[ProcessNode] = []
    seen = {pid}
    node = tree.get(pid)
    while node and node.ppid and len(chain) < max_depth:
        parent = tree.get(node.ppid)
        if parent is None or parent.pid in seen:
            # Parent unknown to the tree -- record what the child knows about it
            if node.ppid not in seen and (node.parent_name or node.ppid):
                chain.append(ProcessNode(pid=node.ppid, name=node.parent_name))
            break
        chain.append(parent)
        seen.add(parent.pid)
        node = parent
    return chain


def descendants(tree: Dict[int, ProcessNode], pid: int,
                max_depth: int = 16) -> List[ProcessNode]:
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
