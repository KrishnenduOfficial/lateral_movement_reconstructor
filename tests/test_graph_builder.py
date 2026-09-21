"""
Unit tests for the attack graph builder.
"""

from lmr.schema import DetectionFinding
from lmr.graph.builder import build_attack_graph


def test_build_attack_graph_chain() -> None:
    """Validates that a multi-hop attack creates the correct nodes and edges."""
    findings = [
        DetectionFinding(
            rule_id="F-001", title="PsExec", attack_ids=["T1021.002"],
            confidence="High", src_ip="10.0.0.5", dst_ip="10.0.0.20",
            evidence_uids=["C1"], reason="Step 1"
        ),
        DetectionFinding(
            rule_id="F-001", title="PsExec", attack_ids=["T1021.002"],
            confidence="High", src_ip="10.0.0.20", dst_ip="10.0.0.50",
            evidence_uids=["C2"], reason="Step 2"
        )
    ]
    
    graph = build_attack_graph(findings)
    
    assert len(graph.nodes) == 3
    assert len(graph.edges) == 2
    assert graph.has_node("10.0.0.20")