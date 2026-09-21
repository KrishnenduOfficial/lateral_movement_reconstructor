"""
Attack path graph builder.

Converts individual detection findings into a directed multigraph, 
allowing analysts to see the entire chain of lateral movement.
"""

import networkx as nx
from typing import List
from lmr.schema import DetectionFinding


def build_attack_graph(findings: List[DetectionFinding]) -> nx.MultiDiGraph:
    """
    Builds a directed multigraph from a list of detection findings.
    
    Nodes represent IP addresses (hosts).
    Edges represent lateral movement techniques observed between those hosts.
    We use a MultiDiGraph because multiple different attacks (e.g., PsExec and RDP)
    can occur between the same two hosts.
    """
    graph = nx.MultiDiGraph()

    for finding in findings:
        # Add the nodes (hosts) if they don't exist yet
        if not graph.has_node(finding.src_ip):
            graph.add_node(finding.src_ip, role="unknown")
            
        if not graph.has_node(finding.dst_ip):
            graph.add_node(finding.dst_ip, role="unknown")

        # Add a directional edge (the attack) from source to destination
        graph.add_edge(
            finding.src_ip,
            finding.dst_ip,
            rule_id=finding.rule_id,
            title=finding.title,
            confidence=finding.confidence,
            attack_ids=",".join(finding.attack_ids),
        )

    return graph