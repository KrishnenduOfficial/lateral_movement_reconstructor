"""
Tests for root-level graph.py (Attack Graph Construction & Metrics).
"""

from pathlib import Path
import networkx as nx
from lmr.schema import DetectionFinding
from lmr.graph import build_attack_graph, analyze_graph_metrics, export_graph_json

def sample_findings():
    return [
        DetectionFinding(
            rule_id="LMR-SSH-001",
            title="SSH Lateral Movement",
            attack_ids=["T1021.004"],
            confidence="High",
            src_ip="10.0.0.5",
            dst_ip="10.0.0.10",
            evidence_uids=["UID_SSH_1"],
            reason="SSH Pivot",
        ),
        DetectionFinding(
            rule_id="LMR-SMB-001",
            title="SMB Admin Share Lateral Movement",
            attack_ids=["T1021.002"],
            confidence="High",
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            evidence_uids=["UID_SMB_1"],
            reason="C$ Mounted",
        ),
    ]

def test_attack_graph_topology():
    findings = sample_findings()
    graph = build_attack_graph(findings)

    assert graph.number_of_nodes() == 3
    assert graph.number_of_edges() == 2

    metrics = analyze_graph_metrics(graph)
    assert metrics["patient_zero_candidates"] == ["10.0.0.5"]
    assert metrics["total_pivots"] == 2

def test_graph_serialization():
    graph = build_attack_graph(sample_findings())
    data = export_graph_json(graph)
    assert "nodes" in data
    assert "links" in data
    assert len(data["nodes"]) == 3