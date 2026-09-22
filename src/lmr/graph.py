"""
Lateral Movement Attack Graph Engine.
Constructs a directed multigraph (MultiDiGraph) using NetworkX from detection findings.
Computes pivot metrics, identifies 'Patient Zero' and high-value target hubs,
and exports adjacency structures for visualization.
"""

from typing import Iterable, Dict, Any, List, Tuple
import networkx as nx
from lmr.schema import DetectionFinding

def build_attack_graph(findings: Iterable[DetectionFinding]) -> nx.MultiDiGraph:
    """
    Constructs a directed multigraph representing lateral movement vectors.
    Nodes = Hosts (IPs).
    Edges = Lateral movement techniques with metadata.
    """
    g = nx.MultiDiGraph()

    for f in findings:
        src = str(f.src_ip)
        dst = str(f.dst_ip)

        # Initialize node metadata
        if not g.has_node(src):
            g.add_node(src, label=src, role="source")
        if not g.has_node(dst):
            g.add_node(dst, label=dst, role="target")

        # Edge attributes store forensic evidence
        g.add_edge(
            src,
            dst,
            rule_id=f.rule_id,
            title=f.title,
            attack_ids=",".join(f.attack_ids),
            confidence=f.confidence,
            evidence_uids=",".join(f.evidence_uids),
            reason=f.reason,
        )

    return g

def analyze_graph_metrics(g: nx.MultiDiGraph) -> Dict[str, Any]:
    """
    Analyzes graph topology to identify threat actor pivot hubs and entry points.
    Returns:
        patient_zero_candidates: Nodes with out-degree > 0 and in-degree == 0.
        target_hubs: Nodes with the highest in-degree (frequently targeted systems).
        total_pivots: Total lateral edges observed.
    """
    if g.number_of_nodes() == 0:
        return {
            "patient_zero_candidates": [],
            "target_hubs": [],
            "total_pivots": 0,
            "total_hosts": 0,
        }

    in_degrees = dict(g.in_degree())
    out_degrees = dict(g.out_degree())

    # Patient Zero: Hosts initiating lateral movement without prior observed compromise
    patient_zero = [
        node for node in g.nodes()
        if out_degrees.get(node, 0) > 0 and in_degrees.get(node, 0) == 0
    ]

    # Target Hubs: Hosts receiving multiple lateral connections
    sorted_targets = sorted(
        [(node, deg) for node, deg in in_degrees.items() if deg > 0],
        key=lambda x: x[1],
        reverse=True,
    )

    return {
        "patient_zero_candidates": sorted(patient_zero),
        "target_hubs": [t[0] for t in sorted_targets[:5]],
        "total_pivots": g.number_of_edges(),
        "total_hosts": g.number_of_nodes(),
    }

def export_graph_json(g: nx.MultiDiGraph) -> Dict[str, Any]:
    """Serializes the graph into a lightweight node/link dictionary for UI visualization."""
    return nx.node_link_data(g)