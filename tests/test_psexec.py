"""
Unit tests for the PsExec detection rule.
"""

from lmr.schema import LmrEvent
from lmr.detections.psexec import detect_psexec


def test_detect_psexec_success() -> None:
    """Validates that a matching sequence of SMB and DCE/RPC events triggers a finding."""
    # Create fake events that mimic a PsExec attack
    mock_events = [
        LmrEvent(
            ts=100.0, uid="C1", src_ip="10.0.0.5", dst_ip="10.0.0.20",
            service="smb_mapping", action="Share Mapped", detail="\\\\10.0.0.20\\ADMIN$"
        ),
        LmrEvent(
            ts=101.0, uid="C2", src_ip="10.0.0.5", dst_ip="10.0.0.20",
            service="dce_rpc", action="CreateServiceW", detail="svcctl"
        ),
        # Add some unrelated noise to ensure the rule ignores it
        LmrEvent(
            ts=102.0, uid="C3", src_ip="192.168.1.1", dst_ip="8.8.8.8",
            service="dns", action="Query", detail="google.com"
        )
    ]

    findings = list(detect_psexec(mock_events))
    
    assert len(findings) == 1
    assert findings[0].rule_id == "F-001"
    assert findings[0].evidence_uids == ["C1", "C2"]
    assert "T1021.002" in findings[0].attack_ids


def test_detect_psexec_incomplete() -> None:
    """Validates that mapping a share WITHOUT service creation does not trigger a finding."""
    mock_events = [
        LmrEvent(
            ts=100.0, uid="C1", src_ip="10.0.0.5", dst_ip="10.0.0.20",
            service="smb_mapping", action="Share Mapped", detail="\\\\10.0.0.20\\ADMIN$"
        )
    ]
    
    findings = list(detect_psexec(mock_events))
    
    assert len(findings) == 0